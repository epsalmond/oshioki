//! Persistent relay and browser application for sudo approval.

mod db;

use anyhow::{Context as _, Result, bail};
use async_nats::jetstream::{
    self, AckKind,
    consumer::{AckPolicy, PullConsumer, pull},
};
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use db::{InsertResult, RequestLifecycle, Store};
use futures::StreamExt as _;
use protocol::{
    ActivationV1, ApproveV1, DecisionV1, DenyV1, EnrollmentIntentV1, EnrollmentSubmissionV1,
    RequestEnvelopeV1, SealedDeviceBodyV1,
};
use serde::Serialize;
use serde_json::json;
use std::{
    path::{Path as FsPath, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::Duration,
};
use tracing::{error, info, warn};

const REQUEST_STREAM: &str = "SUDO_APPROVE";
const REQUEST_CONSUMER: &str = "sudo-approve-server-v1";
const MAX_HTTP_BODY: usize = 3 * 1024 * 1024;

#[derive(Clone)]
struct AppState {
    store: Arc<Store>,
    nats: async_nats::Client,
    dist_root: Arc<PathBuf>,
    consumer_last_ok: Arc<AtomicI64>,
    outbox_last_ok: Arc<AtomicI64>,
    origin: Arc<String>,
    ntfy_url: Option<Arc<String>>,
}

#[derive(Debug)]
struct ApiError(StatusCode);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": "request rejected"}))).into_response()
    }
}

#[derive(Serialize)]
struct RequestResponse {
    sealed: SealedDeviceBodyV1,
    expires_at: i64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive(
                "management_plane_sudo_approve_server=info"
                    .parse()
                    .expect("valid directive"),
            ),
        )
        .init();
    let database_path = required_env("SUDO_APPROVE_STATE_PATH")?;
    let listen = std::env::var("SUDO_APPROVE_LISTEN").unwrap_or_else(|_| "127.0.0.1:8443".into());
    let dist_root = std::env::var("SUDO_APPROVE_DARWIN_DIST")
        .unwrap_or_else(|_| "/opt/sudo-approve/dist/v1/darwin-arm64".into());
    let origin = required_env("SUDO_APPROVE_ORIGIN")?;
    let runtime_config = protocol::HookConfigV1 {
        version: 1,
        origin: origin.clone(),
        rp_id: required_env("SUDO_APPROVE_RP_ID")?,
        server_base_url: origin,
    };
    runtime_config
        .validate()
        .context("validate server origin and RP ID")?;
    info!(origin=%runtime_config.origin, rp_id=%runtime_config.rp_id, "validated server WebAuthn configuration");
    let store = Arc::new(Store::open(FsPath::new(&database_path))?);
    store.ready()?;
    let state = AppState {
        store,
        nats: connect_nats().await?,
        dist_root: Arc::new(PathBuf::from(dist_root)),
        consumer_last_ok: Arc::new(AtomicI64::new(0)),
        outbox_last_ok: Arc::new(AtomicI64::new(now())),
        origin: Arc::new(runtime_config.origin),
        ntfy_url: std::env::var("SUDO_APPROVE_NTFY_URL").ok().map(Arc::new),
    };
    spawn_workers(&state);
    let app = Router::new()
        .route("/r/:id", get(request_page))
        .route("/enroll/:id", get(enrollment_page))
        .route("/assets/app.js", get(app_js))
        .route("/assets/app.css", get(app_css))
        .route("/assets/libsodium.js", get(libsodium_js))
        .route("/api/v1/requests/:id", get(get_request))
        .route("/api/v1/requests/:id/approve", post(approve_request))
        .route("/api/v1/requests/:id/deny", post(deny_request))
        .route(
            "/api/v1/enrollments/:id/submission",
            post(submit_enrollment),
        )
        .route("/api/v1/enrollments/:id/status", get(enrollment_status))
        .route("/api/v1/devices/:fingerprint", get(get_device))
        .route("/healthz", get(health))
        .route("/dist/v1/darwin-arm64/*path", get(dist_file))
        .layer(DefaultBodyLimit::max(MAX_HTTP_BODY))
        .layer(middleware::from_fn(security_headers))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    info!(listen, "sudo approval server listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn spawn_workers(state: &AppState) {
    let request_state = state.clone();
    tokio::spawn(async move {
        loop {
            if let Err(error) = request_consumer(request_state.clone()).await {
                error!(%error, "request consumer stopped");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    });
    let enrollment_state = state.clone();
    tokio::spawn(async move {
        loop {
            if let Err(error) = enrollment_consumer(enrollment_state.clone()).await {
                error!(%error, "enrollment consumer stopped");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    });
    let outbox_state = state.clone();
    tokio::spawn(async move { outbox_worker(outbox_state).await });
    let cleanup_store = state.store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Err(error) = cleanup_store.cleanup(now()) {
                warn!(%error, "cleanup failed");
            }
        }
    });
}

async fn request_consumer(state: AppState) -> Result<()> {
    let stream = jetstream::new(state.nats.clone())
        .get_stream(REQUEST_STREAM)
        .await
        .context("open request stream")?;
    let consumer: PullConsumer = stream
        .get_or_create_consumer(
            REQUEST_CONSUMER,
            pull::Config {
                durable_name: Some(REQUEST_CONSUMER.into()),
                filter_subject: "sudo.request.>".into(),
                ack_policy: AckPolicy::Explicit,
                ..Default::default()
            },
        )
        .await
        .context("open durable request consumer")?;
    state.consumer_last_ok.store(now(), Ordering::Relaxed);
    let mut messages = consumer.messages().await?;
    loop {
        let result = match tokio::time::timeout(Duration::from_secs(10), messages.next()).await {
            Ok(Some(result)) => result,
            Ok(None) => bail!("request consumer stream closed"),
            Err(_) => {
                state.consumer_last_ok.store(now(), Ordering::Relaxed);
                continue;
            }
        };
        let message = result?;
        let raw = message.payload.as_ref();
        if raw.len() > protocol::v1::MAX_ENVELOPE_BYTES {
            warn!(bytes = raw.len(), "terminating oversized request envelope");
            message
                .ack_with(AckKind::Term)
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            state.consumer_last_ok.store(now(), Ordering::Relaxed);
            continue;
        }
        let envelope = match serde_json::from_slice::<RequestEnvelopeV1>(raw) {
            Ok(value) => value,
            Err(error) => {
                warn!(%error, "terminating malformed request envelope");
                message
                    .ack_with(AckKind::Term)
                    .await
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                state.consumer_last_ok.store(now(), Ordering::Relaxed);
                continue;
            }
        };
        match state.store.ingest_request(raw, &envelope, now()) {
            Ok(result @ (InsertResult::Inserted | InsertResult::Identical)) => {
                if result == InsertResult::Inserted {
                    queue_notification(&state, &envelope)?;
                }
                message
                    .double_ack()
                    .await
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            }
            Ok(InsertResult::Conflict) => {
                warn!(request_id=%envelope.request_id, "terminating conflicting request id reuse");
                message
                    .ack_with(AckKind::Term)
                    .await
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            }
            Err(error) => {
                warn!(%error, "terminating invalid or expired request");
                message
                    .ack_with(AckKind::Term)
                    .await
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            }
        }
        state.consumer_last_ok.store(now(), Ordering::Relaxed);
    }
}

async fn enrollment_consumer(state: AppState) -> Result<()> {
    let mut intents = state.nats.subscribe("sudo.enrollment.intent").await?;
    let mut activations = state.nats.subscribe("sudo.enrollment.activation.>").await?;
    let mut revocations = state.nats.subscribe("sudo.device.revoke.>").await?;
    loop {
        tokio::select! {
            Some(message) = intents.next() => match serde_json::from_slice::<EnrollmentIntentV1>(&message.payload) {
                Ok(intent) => {
                    let outcome = (|| -> Result<()> {
                        intent.validate()?;
                        let hash = protocol::decode_base64url(&intent.secret_hash)?;
                        if let InsertResult::Conflict = state.store.create_enrollment(&intent.enrollment_id, &hash, intent.expires_at, &intent.reply_subject)? { warn!(enrollment_id=%intent.enrollment_id, "conflicting enrollment intent"); }
                        Ok(())
                    })();
                    if let Err(error) = outcome { warn!(%error, "invalid enrollment intent"); }
                }
                Err(error) => warn!(%error, "invalid enrollment intent"),
            },
            Some(message) = activations.next() => match serde_json::from_slice::<ActivationV1>(&message.payload) {
                Ok(activation) if activation.version == 1 && !activation.enrollment_id.is_empty() => {
                    if let Err(error) = state.store.activate_enrollment(&activation.enrollment_id, &activation.device) { warn!(%error, "invalid enrollment activation"); }
                },
                Ok(_) => warn!("invalid enrollment activation"),
                Err(error) => warn!(%error, "invalid enrollment activation"),
            },
            Some(message) = revocations.next() => {
                if let Some(fingerprint) = message.subject.strip_prefix("sudo.device.revoke.") {
                    match state.store.set_device_active(fingerprint, false) {
                        Ok(false) => warn!(%fingerprint, "revocation named unknown device"),
                        Err(error) => { warn!(%error, %fingerprint, "revocation persistence failed"); continue; }
                        Ok(true) => {}
                    }
                    state.nats.publish(format!("sudo.device.revoked.{fingerprint}"), Vec::new().into()).await?;
                    state.nats.flush().await?;
                }
            },
            else => bail!("enrollment subscription closed"),
        }
    }
}

async fn outbox_worker(state: AppState) {
    let http = reqwest::Client::new();
    let mut interval = tokio::time::interval(Duration::from_millis(250));
    loop {
        interval.tick().await;
        match state.store.pending_outbox(32) {
            Ok(items) => {
                let mut healthy = true;
                for item in items {
                    if item.kind == "ntfy" {
                        let result = http
                            .post(&item.subject)
                            .header("content-type", "application/json")
                            .body(item.payload.clone())
                            .send()
                            .await;
                        if !matches!(result, Ok(response) if response.status().is_success()) {
                            warn!(outbox_id = item.id, "ntfy delivery failed");
                            healthy = false;
                            break;
                        }
                    } else {
                        if let Err(error) =
                            state.nats.publish(item.subject, item.payload.into()).await
                        {
                            warn!(%error, outbox_id=item.id, "outbox publish failed");
                            healthy = false;
                            break;
                        }
                        if let Err(error) = state.nats.flush().await {
                            warn!(%error, outbox_id=item.id, "outbox flush failed");
                            healthy = false;
                            break;
                        }
                    }
                    if let Err(error) = state.store.mark_outbox_sent(item.id) {
                        warn!(%error, outbox_id=item.id, "outbox mark-sent failed");
                        healthy = false;
                        break;
                    }
                }
                if healthy {
                    state.outbox_last_ok.store(now(), Ordering::Relaxed);
                }
            }
            Err(error) => warn!(%error, "outbox read failed"),
        }
    }
}

fn queue_notification(state: &AppState, envelope: &RequestEnvelopeV1) -> Result<()> {
    let Some(endpoint) = &state.ntfy_url else {
        return Ok(());
    };
    let payload = serde_json::to_vec(&json!({
        "title": format!("sudo on {}", envelope.host),
        "message": format!("{} requested sudo ({})", envelope.user, envelope.request_id),
        "click": format!("{}/r/{}", state.origin, envelope.request_id),
    }))?;
    state
        .store
        .queue_notification(&envelope.request_id, endpoint, &payload)
}

async fn request_page(Path(_id): Path<String>) -> Response {
    html(include_str!("../web/request.html"))
}
async fn enrollment_page(Path(_id): Path<String>) -> Response {
    html(include_str!("../web/enroll.html"))
}
async fn app_js() -> Response {
    asset(
        "application/javascript",
        include_bytes!("../web/app.js"),
        false,
    )
}
async fn app_css() -> Response {
    asset("text/css", include_bytes!("../web/app.css"), false)
}
async fn libsodium_js() -> Response {
    asset(
        "application/javascript",
        include_bytes!("../web/vendor/libsodium.js"),
        false,
    )
}

async fn get_request(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<RequestResponse>, ApiError> {
    require_pending(&state, &id)?;
    let token = bearer_token(&headers)?;
    let request = state
        .store
        .sealed_request_for_token(&id, token.as_bytes(), now())
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(ApiError(StatusCode::UNAUTHORIZED))?;
    let sealed = serde_json::from_str(&request.body_json)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(RequestResponse {
        sealed,
        expires_at: request.expires_at,
    }))
}

async fn approve_request(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(approval): Json<ApproveV1>,
) -> Result<StatusCode, ApiError> {
    approval
        .validate_shape()
        .map_err(|_| ApiError(StatusCode::CONFLICT))?;
    authorize_request(&state, &id, &headers, &approval.device_fingerprint)?;
    if approval.request_id != id {
        return Err(ApiError(StatusCode::CONFLICT));
    }
    let fingerprint = approval.device_fingerprint.clone();
    queue_decision(&state, &id, &fingerprint, &DecisionV1::Approve(approval))
}
async fn deny_request(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(denial): Json<DenyV1>,
) -> Result<StatusCode, ApiError> {
    denial
        .validate_shape()
        .map_err(|_| ApiError(StatusCode::CONFLICT))?;
    authorize_request(&state, &id, &headers, &denial.device_fingerprint)?;
    if denial.request_id != id {
        return Err(ApiError(StatusCode::CONFLICT));
    }
    let fingerprint = denial.device_fingerprint.clone();
    queue_decision(&state, &id, &fingerprint, &DecisionV1::Deny(denial))
}
fn authorize_request(
    state: &AppState,
    id: &str,
    headers: &HeaderMap,
    fingerprint: &str,
) -> Result<(), ApiError> {
    require_pending(state, id)?;
    let token = bearer_token(headers)?;
    let request = state
        .store
        .sealed_request_for_token(id, token.as_bytes(), now())
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(ApiError(StatusCode::UNAUTHORIZED))?;
    let sealed: SealedDeviceBodyV1 = serde_json::from_str(&request.body_json)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?;
    if sealed.device_fingerprint != fingerprint {
        return Err(ApiError(StatusCode::UNAUTHORIZED));
    }
    Ok(())
}
fn require_pending(state: &AppState, id: &str) -> Result<(), ApiError> {
    match state
        .store
        .request_lifecycle(id, now())
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?
    {
        Some(RequestLifecycle::Pending) => Ok(()),
        Some(RequestLifecycle::Gone) => Err(ApiError(StatusCode::GONE)),
        None => Err(ApiError(StatusCode::NOT_FOUND)),
    }
}
fn queue_decision(
    state: &AppState,
    id: &str,
    fingerprint: &str,
    decision: &DecisionV1,
) -> Result<StatusCode, ApiError> {
    match state.store.queue_decision(id, fingerprint, decision, now()) {
        Ok(InsertResult::Inserted | InsertResult::Identical) => Ok(StatusCode::ACCEPTED),
        Ok(InsertResult::Conflict) => Err(ApiError(StatusCode::GONE)),
        Err(error) if error.to_string().contains("expired") => Err(ApiError(StatusCode::GONE)),
        Err(error) if error.to_string().contains("unknown") => Err(ApiError(StatusCode::NOT_FOUND)),
        Err(_) => Err(ApiError(StatusCode::CONFLICT)),
    }
}

async fn submit_enrollment(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(submission): Json<EnrollmentSubmissionV1>,
) -> Result<StatusCode, ApiError> {
    if submission.enrollment_id != id {
        return Err(ApiError(StatusCode::CONFLICT));
    }
    submission
        .validate_shape()
        .map_err(|_| ApiError(StatusCode::CONFLICT))?;
    match state.store.submit_enrollment(&id, &submission, now()) {
        Ok(InsertResult::Inserted | InsertResult::Identical) => Ok(StatusCode::ACCEPTED),
        Ok(InsertResult::Conflict) => Err(ApiError(StatusCode::CONFLICT)),
        Err(error) if error.to_string().contains("expired") => Err(ApiError(StatusCode::GONE)),
        Err(error) if error.to_string().contains("unknown") => Err(ApiError(StatusCode::NOT_FOUND)),
        Err(_) => Err(ApiError(StatusCode::INTERNAL_SERVER_ERROR)),
    }
}
async fn enrollment_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<db::EnrollmentView>, ApiError> {
    state
        .store
        .enrollment_status(&id, now())
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?
        .map(Json)
        .ok_or(ApiError(StatusCode::NOT_FOUND))
}
async fn get_device(
    State(state): State<AppState>,
    Path(fingerprint): Path<String>,
) -> Result<Json<protocol::DevicePublicRecordV1>, ApiError> {
    state
        .store
        .active_device(&fingerprint)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?
        .map(Json)
        .ok_or(ApiError(StatusCode::NOT_FOUND))
}
async fn health(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .store
        .ready()
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE))?;
    let current = now();
    let consumer_age = current - state.consumer_last_ok.load(Ordering::Relaxed);
    let outbox_age = current - state.outbox_last_ok.load(Ordering::Relaxed);
    if consumer_age > 30 || outbox_age > 30 {
        return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE));
    }
    Ok(Json(
        json!({"status":"ok","consumer_age_seconds":consumer_age,"outbox_age_seconds":outbox_age}),
    ))
}
async fn dist_file(
    State(state): State<AppState>,
    Path(path): Path<String>,
) -> Result<Response, ApiError> {
    if path.is_empty()
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(ApiError(StatusCode::NOT_FOUND));
    }
    let root = tokio::fs::canonicalize(state.dist_root.as_ref())
        .await
        .map_err(|_| ApiError(StatusCode::NOT_FOUND))?;
    let file = tokio::fs::canonicalize(root.join(&path))
        .await
        .map_err(|_| ApiError(StatusCode::NOT_FOUND))?;
    if !file.starts_with(&root) {
        return Err(ApiError(StatusCode::NOT_FOUND));
    }
    let bytes = tokio::fs::read(file)
        .await
        .map_err(|_| ApiError(StatusCode::NOT_FOUND))?;
    Ok(asset(
        if FsPath::new(&path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
        {
            "application/json"
        } else {
            "application/octet-stream"
        },
        &bytes,
        true,
    ))
}

fn html(body: &'static str) -> Response {
    asset("text/html; charset=utf-8", body.as_bytes(), false)
}
fn asset(content_type: &str, body: &[u8], immutable: bool) -> Response {
    let mut response = Response::new(Body::from(body.to_vec()));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type).expect("static content type"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if immutable {
            "public, max-age=31536000, immutable"
        } else {
            "no-store"
        }),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("content-security-policy", HeaderValue::from_static("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"));
    response
}
async fn security_headers(request: axum::extract::Request, next: Next) -> Response {
    let is_api = request.uri().path().starts_with("/api/");
    let mut response = next.run(request).await;
    if is_api && response.status().is_client_error() {
        let status = response.status();
        response = (status, Json(json!({"error": "request rejected"}))).into_response();
    }
    let headers = response.headers_mut();
    if !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("content-security-policy", HeaderValue::from_static("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"));
    response
}
fn bearer_token(headers: &HeaderMap) -> Result<String, ApiError> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| value.len() >= 32)
        .map(ToOwned::to_owned)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED))
}
async fn connect_nats() -> Result<async_nats::Client> {
    async_nats::ConnectOptions::new()
        .user_and_password(required_env("NATS_USER")?, required_env("NATS_PASS")?)
        .connect(required_env("NATS_URL")?)
        .await
        .context("connect to NATS")
}
fn required_env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} not set"))
}
fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}
