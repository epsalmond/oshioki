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
use oshioki_protocol::{
    ALLOW_PLAINTEXT_NATS_ENV, ActivationV1, ApproveV1, DecisionV1, DenyV1, EnrollmentIntentV1,
    EnrollmentSubmissionV1, RequestEnvelopeV1, SealedDeviceBodyV1, allow_plaintext_nats,
    check_nats_url, nats_url_is_tls,
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
use tokio::sync::Semaphore;
use tokio_util::io::ReaderStream;
use tracing::{error, info, warn};

const REQUEST_STREAM: &str = "OSHIOKI";
const REQUEST_CONSUMER: &str = "oshioki-server-v1";
const MAX_HTTP_BODY: usize = 3 * 1024 * 1024;

/// Largest servable Darwin artifact. Release tarballs are tens of megabytes,
/// so this is headroom, not a fit: anything bigger is not ours to serve,
/// and refusing it before reading a byte keeps one request from eating the
/// server's memory.
const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

/// How many artifact streams run at once; the rest get 503. Streaming bounds
/// each response to its buffer, and this bounds their count (and open files).
const MAX_CONCURRENT_ARTIFACTS: usize = 8;

#[derive(Clone)]
struct AppState {
    store: Arc<Store>,
    nats: async_nats::Client,
    dist_root: Arc<PathBuf>,
    artifact_permits: Arc<Semaphore>,
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
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("oshioki_server=info".parse().expect("valid directive")),
        )
        .init();
    let database_path = required_env("OSHIOKI_STATE_PATH")?;
    let listen = std::env::var("OSHIOKI_LISTEN").unwrap_or_else(|_| "127.0.0.1:8443".into());
    let dist_root = std::env::var("OSHIOKI_DARWIN_DIST")
        .unwrap_or_else(|_| "/opt/oshioki/dist/v1/darwin-arm64".into());
    let origin = required_env("OSHIOKI_ORIGIN")?;
    let runtime_config = oshioki_protocol::HookConfigV1 {
        version: 1,
        origin: origin.clone(),
        rp_id: required_env("OSHIOKI_RP_ID")?,
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
        artifact_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_ARTIFACTS)),
        consumer_last_ok: Arc::new(AtomicI64::new(0)),
        outbox_last_ok: Arc::new(AtomicI64::new(now())),
        origin: Arc::new(runtime_config.origin),
        ntfy_url: std::env::var("OSHIOKI_NTFY_URL").ok().map(Arc::new),
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
    let verdict_state = state.clone();
    tokio::spawn(async move { verdict_worker(verdict_state).await });
    let notification_state = state.clone();
    tokio::spawn(async move { notification_worker(notification_state).await });
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
                filter_subject: "oshioki.request.>".into(),
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
        if raw.len() > oshioki_protocol::v1::MAX_ENVELOPE_BYTES {
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
    let mut intents = state.nats.subscribe("oshioki.enrollment.intent").await?;
    let mut submissions = state
        .nats
        .subscribe("oshioki.enrollment.submission.>")
        .await?;
    let mut activations = state
        .nats
        .subscribe("oshioki.enrollment.activation.>")
        .await?;
    let mut revocations = state.nats.subscribe("oshioki.device.revoke.>").await?;
    loop {
        tokio::select! {
            Some(message) = intents.next() => match serde_json::from_slice::<EnrollmentIntentV1>(&message.payload) {
                Ok(intent) => {
                    let outcome = (|| -> Result<()> {
                        intent.validate()?;
                        if intent.expires_at <= now() || intent.expires_at > now() + 300 {
                            bail!("invalid enrollment intent expiry");
                        }
                        let hash = oshioki_protocol::decode_base64url(&intent.secret_hash)?;
                        if let InsertResult::Conflict = state.store.create_enrollment(&intent.enrollment_id, &hash, intent.expires_at, &intent.reply_subject)? { warn!(enrollment_id=%intent.enrollment_id, "conflicting enrollment intent"); }
                        Ok(())
                    })();
                    if let Err(error) = outcome { warn!(%error, "invalid enrollment intent"); }
                }
                Err(error) => warn!(%error, "invalid enrollment intent"),
            },
            Some(message) = submissions.next() => match serde_json::from_slice::<EnrollmentSubmissionV1>(&message.payload) {
                // Native devices publish here; the hook reads the same
                // subject, and the stored submission is what a later
                // activation is bound to. Storage verifies nothing: the
                // hook's cryptographic check is what admits a device, and
                // first-wins keeps a later forgery from displacing it.
                Ok(submission) => {
                    match state.store.submit_enrollment(submission.enrollment_id(), &submission, now()) {
                        Err(error) => warn!(%error, "invalid enrollment submission"),
                        Ok(InsertResult::Conflict) => warn!(enrollment_id=%submission.enrollment_id(), "conflicting enrollment submission"),
                        Ok(_) => {}
                    }
                }
                Err(error) => warn!(%error, "invalid enrollment submission"),
            },
            Some(message) = activations.next() => match serde_json::from_slice::<ActivationV1>(&message.payload) {
                Ok(activation) if activation.version == 1 && !activation.enrollment_id.is_empty() => {
                    // No acknowledgement goes back on NATS: the hook confirms
                    // the enrollment by reading the device back over HTTPS,
                    // which is the only answer that says what this server
                    // actually stored. The hook restates the activation while
                    // the read-back says the record is missing, so an
                    // activation that arrives before its submission is stored
                    // heals on the next pass instead of failing the enroll.
                    if let Err(error) = state.store.activate_enrollment(&activation.enrollment_id, &activation.device, now()) {
                        warn!(%error, "invalid enrollment activation");
                    }
                },
                Ok(_) => warn!("invalid enrollment activation"),
                Err(error) => warn!(%error, "invalid enrollment activation"),
            },
            Some(message) = revocations.next() => {
                if let Some(fingerprint) = message.subject.strip_prefix("oshioki.device.revoke.") {
                    match state.store.set_device_active(fingerprint, false) {
                        Ok(false) => warn!(%fingerprint, "revocation named unknown device"),
                        Err(error) => { warn!(%error, %fingerprint, "revocation persistence failed"); continue; }
                        Ok(true) => {}
                    }
                    state.nats.publish(format!("oshioki.device.revoked.{fingerprint}"), Vec::new().into()).await?;
                    state.nats.flush().await?;
                }
            },
            else => bail!("enrollment subscription closed"),
        }
    }
}

/// Publishes verdicts (and enrollment relays) to NATS. This lane never
/// touches a notification row, so a dead ntfy endpoint cannot delay an
/// approval: while this worker is healthy, `/healthz` is healthy.
async fn verdict_worker(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_millis(250));
    loop {
        interval.tick().await;
        match state.store.pending_verdicts(32) {
            Ok(items) => {
                let mut healthy = true;
                for item in items {
                    if let Err(error) = state.nats.publish(item.subject, item.payload.into()).await
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
            Err(error) => warn!(%error, "verdict outbox read failed"),
        }
    }
}

/// Delivers notifications on their own cadence with bounded backoff. A
/// failure here sleeps this worker only: verdicts keep flowing, and the
/// health check (driven by the verdict lane) stays green.
async fn notification_worker(state: AppState) {
    let http = reqwest::Client::new();
    let mut interval = tokio::time::interval(Duration::from_millis(250));
    let mut consecutive_failures: u32 = 0;
    loop {
        interval.tick().await;
        match state.store.pending_notifications(32) {
            Ok(items) => {
                let mut batch_clean = true;
                for item in items {
                    let result = http
                        .post(&item.subject)
                        .header("content-type", "application/json")
                        .body(item.payload.clone())
                        .send()
                        .await;
                    if !matches!(result, Ok(response) if response.status().is_success()) {
                        warn!(outbox_id = item.id, "ntfy delivery failed");
                        consecutive_failures = consecutive_failures.saturating_add(1);
                        batch_clean = false;
                        break;
                    }
                    if let Err(error) = state.store.mark_outbox_sent(item.id) {
                        warn!(%error, outbox_id=item.id, "ntfy mark-sent failed");
                        batch_clean = false;
                        break;
                    }
                }
                if batch_clean {
                    consecutive_failures = 0;
                } else {
                    // Independent exponential backoff, capped at five
                    // minutes: a dead endpoint is retried, never hammered.
                    let wait = Duration::from_secs(1 << consecutive_failures.min(8))
                        .min(Duration::from_secs(300));
                    tokio::time::sleep(wait).await;
                }
            }
            Err(error) => warn!(%error, "ntfy outbox read failed"),
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
    // Native devices publish their submission straight to NATS; the HTTP
    // path serves the browser only.
    if submission.enrollment_id() != id
        || !matches!(submission, EnrollmentSubmissionV1::Webauthn(_))
    {
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
) -> Result<Json<oshioki_protocol::DevicePublicRecordV1>, ApiError> {
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
    dist_response(state.dist_root.as_ref(), &path, &state.artifact_permits).await
}

/// Serves one Darwin artifact as a stream, so response memory stays bounded
/// no matter how large the file is. Split from the handler so tests can
/// drive it without a NATS connection.
async fn dist_response(
    root: &std::path::Path,
    path: &str,
    permits: &Arc<Semaphore>,
) -> Result<Response, ApiError> {
    // The permit lives in the stream below, not in this frame: holding it
    // past the return is what bounds concurrent downloads rather than
    // concurrent handler entries.
    let permit = permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE))?;
    if path.is_empty()
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(ApiError(StatusCode::NOT_FOUND));
    }
    let root = tokio::fs::canonicalize(root)
        .await
        .map_err(|_| ApiError(StatusCode::NOT_FOUND))?;
    let file_path = tokio::fs::canonicalize(root.join(path))
        .await
        .map_err(|_| ApiError(StatusCode::NOT_FOUND))?;
    if !file_path.starts_with(&root) {
        return Err(ApiError(StatusCode::NOT_FOUND));
    }
    let file = tokio::fs::File::open(&file_path)
        .await
        .map_err(|_| ApiError(StatusCode::NOT_FOUND))?;
    let metadata = file
        .metadata()
        .await
        .map_err(|_| ApiError(StatusCode::NOT_FOUND))?;
    if !metadata.is_file() {
        return Err(ApiError(StatusCode::NOT_FOUND));
    }
    let len = metadata.len();
    if len > MAX_ARTIFACT_BYTES {
        return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE));
    }
    // The closure captures the permit without otherwise using it, so the
    // download holds its concurrency slot until the stream is dropped.
    let stream = ReaderStream::new(file).map(move |chunk| {
        let _ = &permit;
        chunk
    });
    let mut response = Response::new(Body::from_stream(stream));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(
            if FsPath::new(path)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
            {
                "application/json"
            } else {
                "application/octet-stream"
            },
        ),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("content-security-policy", HeaderValue::from_static("default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"));
    Ok(response)
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
    headers.insert("content-security-policy", HeaderValue::from_static("default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"));
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
    headers.insert("content-security-policy", HeaderValue::from_static("default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"));
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
    let url = required_env("NATS_URL")?;
    check_nats_url(
        &url,
        allow_plaintext_nats(std::env::var(ALLOW_PLAINTEXT_NATS_ENV).ok().as_deref()),
    )
    .context("invalid NATS_URL")?;
    // A tls:// URL must stay TLS past the first server: the cluster
    // advertises more addresses on reconnect as bare host:port, which parse
    // as plaintext, so the options flag carries the requirement with them.
    let mut options = async_nats::ConnectOptions::new()
        .user_and_password(required_env("NATS_USER")?, required_env("NATS_PASS")?);
    if nats_url_is_tls(&url) {
        options = options.require_tls(true);
    }
    options.connect(url).await.context("connect to NATS")
}
fn required_env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} not set"))
}
fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dist_root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("oshioki-dist-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn permits() -> Arc<Semaphore> {
        Arc::new(Semaphore::new(MAX_CONCURRENT_ARTIFACTS))
    }

    async fn status(root: &std::path::Path, path: &str, permits: &Arc<Semaphore>) -> StatusCode {
        match dist_response(root, path, permits).await {
            Ok(response) => response.status(),
            Err(error) => error.0,
        }
    }

    /// Traversal shapes never reach the filesystem as themselves: empty,
    /// dot, and dot-dot components are rejected before canonicalization,
    /// and anything escaping the root is rejected after it.
    #[tokio::test]
    async fn traversal_attempts_are_not_found() {
        let dir = dist_root("traversal");
        std::fs::write(dir.join("manifest.json"), b"{}").unwrap();
        let permits = permits();
        for path in [
            "",
            ".",
            "..",
            "../manifest.json",
            "a/../../manifest.json",
            "a//manifest.json",
            "a/./manifest.json",
            "/manifest.json",
        ] {
            assert_eq!(
                status(&dir, path, &permits).await,
                StatusCode::NOT_FOUND,
                "{path}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Missing files and directories are 404 without a body read.
    #[tokio::test]
    async fn missing_and_directories_are_not_found() {
        let dir = dist_root("missing");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        let permits = permits();
        assert_eq!(
            status(&dir, "nope.tar.gz", &permits).await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(status(&dir, "sub", &permits).await, StatusCode::NOT_FOUND);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A symlink is resolved before the root check: pointing outside stays
    /// outside, pointing inside serves the target's bytes.
    #[cfg(unix)]
    #[tokio::test]
    async fn symlinks_resolve_before_the_root_check() {
        let dir = dist_root("symlink");
        let outside = dist_root("symlink-outside");
        std::fs::write(outside.join("secret"), b"secret").unwrap();
        std::fs::write(dir.join("real.tar.gz"), b"real").unwrap();
        std::os::unix::fs::symlink(outside.join("secret"), dir.join("evil")).unwrap();
        std::os::unix::fs::symlink(dir.join("real.tar.gz"), dir.join("alias.tar.gz")).unwrap();
        let permits = permits();
        assert_eq!(status(&dir, "evil", &permits).await, StatusCode::NOT_FOUND);
        let response = dist_response(&dir, "alias.tar.gz", &permits).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), b"real");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// The size cap is enforced from metadata before a byte is read (sparse
    /// files, so the over-limit case costs no I/O), and a file exactly at
    /// the cap serves with its length announced.
    #[tokio::test]
    async fn artifacts_over_the_cap_are_rejected() {
        let dir = dist_root("oversize");
        let big = std::fs::File::create(dir.join("big.tar.gz")).unwrap();
        big.set_len(MAX_ARTIFACT_BYTES + 1).unwrap();
        let exact = std::fs::File::create(dir.join("exact.tar.gz")).unwrap();
        exact.set_len(MAX_ARTIFACT_BYTES).unwrap();
        let permits = permits();
        assert_eq!(
            status(&dir, "big.tar.gz", &permits).await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let response = dist_response(&dir, "exact.tar.gz", &permits).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_LENGTH).unwrap(),
            &HeaderValue::from(MAX_ARTIFACT_BYTES)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Small files stream their exact bytes with the content type the
    /// extension implies and an explicit length.
    #[tokio::test]
    async fn small_files_stream_verbatim() {
        let dir = dist_root("small");
        std::fs::write(dir.join("manifest.json"), br#"{"v":1}"#).unwrap();
        std::fs::write(dir.join("agent.tar.gz"), b"\x1f\x8bBinary").unwrap();
        let permits = permits();
        let json = dist_response(&dir, "manifest.json", &permits)
            .await
            .unwrap();
        assert_eq!(json.status(), StatusCode::OK);
        assert_eq!(
            json.headers().get(header::CONTENT_TYPE).unwrap(),
            &HeaderValue::from_static("application/json")
        );
        let body = axum::body::to_bytes(json.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), br#"{"v":1}"#);
        let tar = dist_response(&dir, "agent.tar.gz", &permits).await.unwrap();
        assert_eq!(
            tar.headers().get(header::CONTENT_TYPE).unwrap(),
            &HeaderValue::from_static("application/octet-stream")
        );
        assert_eq!(
            tar.headers().get(header::CONTENT_LENGTH).unwrap(),
            &HeaderValue::from_static("8")
        );
        let body = axum::body::to_bytes(tar.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), b"\x1f\x8bBinary");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Many simultaneous downloads all complete: over-limit requests shed
    /// with 503 and retry, so this also proves permits are released rather
    /// than leaked — a leak would stall here past the timeout instead.
    #[tokio::test]
    async fn concurrent_downloads_all_complete() {
        let dir = dist_root("concurrent");
        std::fs::write(dir.join("agent.tar.gz"), b"payload").unwrap();
        let dir = Arc::new(dir);
        let permits = permits();
        let downloads = (0..4 * MAX_CONCURRENT_ARTIFACTS).map(|_| {
            let dir = Arc::clone(&dir);
            let permits = Arc::clone(&permits);
            tokio::spawn(async move {
                for _ in 0..1000 {
                    match dist_response(&dir, "agent.tar.gz", &permits).await {
                        Ok(response) => {
                            assert_eq!(response.status(), StatusCode::OK);
                            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                                .await
                                .unwrap();
                            assert_eq!(body.as_ref(), b"payload");
                            return;
                        }
                        Err(error) => {
                            assert_eq!(error.0, StatusCode::SERVICE_UNAVAILABLE);
                            tokio::task::yield_now().await;
                        }
                    }
                }
                panic!("a download never won a permit");
            })
        });
        let outstanding: Vec<_> = downloads.collect();
        tokio::time::timeout(Duration::from_secs(30), async {
            for download in outstanding {
                download.await.unwrap();
            }
        })
        .await
        .expect("downloads stalled: permits leak");
        let _ = std::fs::remove_dir_all(dir.as_ref());
    }

    /// Past the concurrency limit the handler sheds load with 503 instead
    /// of queueing unbounded work, and recovers when a slot frees.
    #[tokio::test]
    async fn downloads_past_the_limit_get_503() {
        let dir = dist_root("limit");
        std::fs::write(dir.join("agent.tar.gz"), b"payload").unwrap();
        let permits = permits();
        let held: Vec<_> = (0..MAX_CONCURRENT_ARTIFACTS)
            .map(|_| permits.clone().try_acquire_owned().unwrap())
            .collect();
        assert_eq!(
            status(&dir, "agent.tar.gz", &permits).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        drop(held);
        assert_eq!(status(&dir, "agent.tar.gz", &permits).await, StatusCode::OK);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
