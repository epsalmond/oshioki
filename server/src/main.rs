//! Persistent relay and browser application for sudo approval.

mod db;

use anyhow::{Context as _, Result, bail};
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
    AUTH_ENVELOPE_TYPE, ActivationV1, AliveV1, ApproveV1, AuthApproveWebauthnV1, AuthDecisionV1,
    AuthEnvelopeV1, DecisionV1, DenyV1, EnrollmentIntentV1, EnrollmentSubmissionV1,
    RequestEnvelopeV1, SealedDeviceBodyV1,
};
use oshioki_transport::{Ack, JetStreamMessage, NatsTransport, ServerTransport};
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

/// Every path the authentication lane serves. The router is built from this
/// list and from nothing else, so the lane's route table is this array: a
/// test asserting that none of these is a refusal is a check on the router
/// itself rather than on the text of this file.
///
/// There is no denial route and there must never be one. Cancelling in the
/// browser sends nothing at all, and sudo asks for a password at the host's
/// deadline; a route that could record a "no" would turn a request nobody
/// read into a failure nobody chose.
const AUTH_ROUTES: [&str; 4] = [
    "/api/v1/auth/:id",
    "/api/v1/auth/:id/ack",
    "/api/v1/auth/:id/authenticate-webauthn",
    "/api/v1/auth/:id/verdict",
];

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
    transport: Arc<dyn ServerTransport>,
    dist_root: Arc<PathBuf>,
    artifact_permits: Arc<Semaphore>,
    consumer_last_ok: Arc<AtomicI64>,
    outbox_last_ok: Arc<AtomicI64>,
    origin: Arc<String>,
    rp_id: Arc<String>,
    ntfy_url: Option<Arc<String>>,
}

#[derive(Debug)]
struct ApiError(StatusCode);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": "request rejected"}))).into_response()
    }
}

#[derive(Debug, Serialize)]
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
        transport: transport_from_env().await?,
        dist_root: Arc::new(PathBuf::from(dist_root)),
        artifact_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_ARTIFACTS)),
        consumer_last_ok: Arc::new(AtomicI64::new(0)),
        outbox_last_ok: Arc::new(AtomicI64::new(now())),
        origin: Arc::new(runtime_config.origin),
        rp_id: Arc::new(runtime_config.rp_id),
        ntfy_url: std::env::var("OSHIOKI_NTFY_URL").ok().map(Arc::new),
    };
    spawn_workers(&state);
    let app = Router::new()
        .route("/r/:id", get(request_page))
        .route("/a/:id", get(authentication_page))
        .route("/enroll/:id", get(enrollment_page))
        .route("/assets/app.js", get(app_js))
        .route("/assets/app.css", get(app_css))
        .route("/assets/libsodium.js", get(libsodium_js))
        .route("/api/v1/requests/:id", get(get_request))
        .route("/api/v1/requests/:id/ack", post(acknowledge_request))
        .route("/api/v1/requests/:id/approve", post(approve_request))
        .route("/api/v1/requests/:id/deny", post(deny_request))
        .route("/api/v1/requests/:id/verdict", get(recorded_verdict))
        .route(AUTH_ROUTES[0], get(get_auth_request))
        .route(AUTH_ROUTES[1], post(acknowledge_auth_request))
        .route(AUTH_ROUTES[2], post(authenticate_webauthn))
        .route(AUTH_ROUTES[3], get(recorded_auth_verdict))
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
    let mut batches = state.transport.requests().await?;
    state.consumer_last_ok.store(now(), Ordering::Relaxed);
    loop {
        let batch = match tokio::time::timeout(Duration::from_secs(10), batches.next()).await {
            Ok(Some(batch)) => batch,
            Ok(None) => bail!("request consumer stream closed"),
            Err(_) => {
                state.consumer_last_ok.store(now(), Ordering::Relaxed);
                continue;
            }
        };
        for message in batch? {
            // Payload and acknowledgement split apart: the ack closure is
            // single-use, and every arm below consumes it exactly once.
            let JetStreamMessage { payload, ack } = message;
            let raw = payload.as_slice();
            if raw.len() > oshioki_protocol::v1::MAX_ENVELOPE_BYTES {
                warn!(bytes = raw.len(), "terminating oversized request envelope");
                ack(Ack::Term).await?;
                state.consumer_last_ok.store(now(), Ordering::Relaxed);
                continue;
            }
            // The lane is decided by the envelope's own `type` tag, not by
            // the subject it arrived on. The legacy command envelope carries
            // no tag at all, so it routes exactly as it always has; a tag
            // this build does not implement is terminated rather than
            // guessed at, and never reaches the command decoder.
            match envelope_type(raw) {
                None => {}
                Some(message_type) if message_type == AUTH_ENVELOPE_TYPE => {
                    ingest_auth_envelope(&state, raw, ack).await?;
                    state.consumer_last_ok.store(now(), Ordering::Relaxed);
                    continue;
                }
                Some(message_type) => {
                    warn!(%message_type, "terminating envelope of an unknown type");
                    ack(Ack::Term).await?;
                    state.consumer_last_ok.store(now(), Ordering::Relaxed);
                    continue;
                }
            }
            let envelope = match serde_json::from_slice::<RequestEnvelopeV1>(raw) {
                Ok(value) => value,
                Err(error) => {
                    warn!(%error, "terminating malformed request envelope");
                    ack(Ack::Term).await?;
                    state.consumer_last_ok.store(now(), Ordering::Relaxed);
                    continue;
                }
            };
            match state.store.ingest_request(raw, &envelope, now()) {
                Ok(result @ (InsertResult::Inserted | InsertResult::Identical)) => {
                    if result == InsertResult::Inserted {
                        queue_notification(&state, &envelope)?;
                    }
                    ack(Ack::Ok).await?;
                }
                Ok(InsertResult::Conflict) => {
                    warn!(request_id=%envelope.request_id, "terminating conflicting request id reuse");
                    ack(Ack::Term).await?;
                }
                Err(error) => {
                    warn!(%error, "terminating invalid or expired request");
                    ack(Ack::Term).await?;
                }
            }
            state.consumer_last_ok.store(now(), Ordering::Relaxed);
        }
    }
}

/// Reads only an envelope's `type` tag, so one delivery can be routed before
/// anything decides how to parse the rest of it. `None` covers both an
/// untagged legacy envelope and a payload that is not JSON at all; the
/// command decode is what reports the latter, as it always has.
fn envelope_type(raw: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct EnvelopeTypeV1 {
        #[serde(rename = "type")]
        message_type: Option<String>,
    }
    serde_json::from_slice::<EnvelopeTypeV1>(raw)
        .ok()
        .and_then(|envelope| envelope.message_type)
}

/// Stores one contextual sudo authentication envelope, with the same
/// acknowledgement contract the command lane uses: stored or already stored
/// is an Ack, and anything undecodable, conflicting, or expired is a Term so
/// it never redelivers.
async fn ingest_auth_envelope(
    state: &AppState,
    raw: &[u8],
    ack: oshioki_transport::AckFn,
) -> Result<()> {
    let envelope = match serde_json::from_slice::<AuthEnvelopeV1>(raw) {
        Ok(value) => value,
        Err(error) => {
            warn!(%error, "terminating malformed authentication envelope");
            ack(Ack::Term).await?;
            return Ok(());
        }
    };
    match state.store.ingest_auth_request(raw, &envelope, now()) {
        Ok(result @ (InsertResult::Inserted | InsertResult::Identical)) => {
            if result == InsertResult::Inserted {
                queue_auth_notification(state, &envelope)?;
            }
            ack(Ack::Ok).await?;
        }
        Ok(InsertResult::Conflict) => {
            warn!(request_id=%envelope.request_id, "terminating conflicting authentication request id reuse");
            ack(Ack::Term).await?;
        }
        Err(error) => {
            warn!(%error, "terminating invalid or expired authentication request");
            ack(Ack::Term).await?;
        }
    }
    Ok(())
}

async fn enrollment_consumer(state: AppState) -> Result<()> {
    let mut intents = state
        .transport
        .subscribe("oshioki.enrollment.intent")
        .await?;
    let mut submissions = state
        .transport
        .subscribe("oshioki.enrollment.submission.>")
        .await?;
    let mut activations = state
        .transport
        .subscribe("oshioki.enrollment.activation.>")
        .await?;
    let mut revocations = state.transport.subscribe("oshioki.device.revoke.>").await?;
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
                handle_revocation(&state, message.subject).await?;
            },
            else => bail!("enrollment subscription closed"),
        }
    }
}

/// One revocation delivery: strip the subject prefix, deactivate the device,
/// then publish the confirmation. Publishing after the store write is the
/// contract — a confirmation says the revocation persisted.
async fn handle_revocation(state: &AppState, subject: String) -> Result<()> {
    if let Some(fingerprint) = subject.strip_prefix("oshioki.device.revoke.") {
        match state.store.set_device_active(fingerprint, false) {
            Ok(false) => warn!(%fingerprint, "revocation named unknown device"),
            Err(error) => {
                warn!(%error, %fingerprint, "revocation persistence failed");
                return Ok(());
            }
            Ok(true) => {}
        }
        state
            .transport
            .publish(format!("oshioki.device.revoked.{fingerprint}"), Vec::new())
            .await?;
    }
    Ok(())
}

/// Publishes verdicts, browser delivery receipts, and enrollment relays to
/// NATS. This lane never touches a notification row, so a dead ntfy endpoint
/// cannot delay an approval: while this worker is healthy, `/healthz` is
/// healthy.
async fn verdict_worker(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_millis(250));
    loop {
        interval.tick().await;
        match state.store.pending_verdicts(32) {
            Ok(items) => {
                let mut healthy = true;
                for item in items {
                    // The transport publishes then flushes; a flush failure
                    // surfaces here as a publish failure, preserving the
                    // observable contract.
                    if let Err(error) = state.transport.publish(item.subject, item.payload).await {
                        warn!(%error, outbox_id=item.id, "outbox publish failed");
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

/// The authentication lane's notification. It names the host and the
/// request, and nothing about the account or the invocation: that context is
/// inside the sealed body, and a push notification is not a place to put it.
fn queue_auth_notification(state: &AppState, envelope: &AuthEnvelopeV1) -> Result<()> {
    let Some(endpoint) = &state.ntfy_url else {
        return Ok(());
    };
    let payload = serde_json::to_vec(&json!({
        "title": format!("sudo authentication on {}", envelope.host),
        "message": format!("sudo is asking for authentication ({})", envelope.request_id),
        "click": format!("{}/a/{}", state.origin, envelope.request_id),
    }))?;
    state
        .store
        .queue_notification(&envelope.request_id, endpoint, &payload)
}

async fn request_page(Path(_id): Path<String>) -> Response {
    html(include_str!("../web/request.html"))
}
/// The authentication lane has its own page at its own path. Keeping it off
/// `/r/:id` is the simplest thing that leaves every existing request page
/// byte-for-byte what it was, and makes a link to the wrong lane a plain
/// 404 rather than a page that renders the wrong question.
async fn authentication_page(Path(_id): Path<String>) -> Response {
    html(include_str!("../web/auth.html"))
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

/// Relays an explicit browser liveness acknowledgement. The server does not
/// acknowledge a request when it ingests one, because that would claim that a
/// browser received it before any browser did. The browser posts this message
/// after it has authenticated, fetched, decrypted, and checked the request.
async fn acknowledge_request(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(acknowledgement): Json<AliveV1>,
) -> Result<StatusCode, ApiError> {
    acknowledgement
        .validate(&id)
        .map_err(|_| ApiError(StatusCode::CONFLICT))?;
    require_pending(&state, &id)?;
    let token = bearer_token(&headers)?;
    state
        .store
        .sealed_request_for_token(&id, token.as_bytes(), now())
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(ApiError(StatusCode::UNAUTHORIZED))?;
    let payload = serde_json::to_vec(&acknowledgement)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?;
    state
        .transport
        .publish(format!("oshioki.ack.{id}"), payload)
        .await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE))?;
    Ok(StatusCode::ACCEPTED)
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

/// The sealed authentication body for the browser profile holding this API
/// token. Deliberately a separate path from `/api/v1/requests/:id`: an
/// authentication id is unknown to that route and a command request id is
/// unknown to this one, so a client aimed at the wrong lane is told so.
async fn get_auth_request(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<RequestResponse>, ApiError> {
    require_pending_auth(&state, &id)?;
    let token = bearer_token(&headers)?;
    let request = state
        .store
        .sealed_auth_request_for_token(&id, token.as_bytes(), now())
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(ApiError(StatusCode::UNAUTHORIZED))?;
    let sealed = serde_json::from_str(&request.body_json)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(RequestResponse {
        sealed,
        expires_at: request.expires_at,
    }))
}

/// Relays the browser's liveness acknowledgement for an authentication, on
/// the same `oshioki.ack.<id>` subject the hook already waits on.
async fn acknowledge_auth_request(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(acknowledgement): Json<AliveV1>,
) -> Result<StatusCode, ApiError> {
    acknowledgement
        .validate(&id)
        .map_err(|_| ApiError(StatusCode::CONFLICT))?;
    require_pending_auth(&state, &id)?;
    let token = bearer_token(&headers)?;
    state
        .store
        .sealed_auth_request_for_token(&id, token.as_bytes(), now())
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(ApiError(StatusCode::UNAUTHORIZED))?;
    let payload = serde_json::to_vec(&acknowledgement)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?;
    state
        .transport
        .publish(format!("oshioki.ack.{id}"), payload)
        .await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE))?;
    Ok(StatusCode::ACCEPTED)
}

/// Queues one `WebAuthn` authentication assertion for the hook.
///
/// This is the only decision route on the lane. There is no denial
/// counterpart and there must never be one: cancelling in the browser sends
/// nothing, and the host then asks for a password. The server verifies no
/// signature here, exactly as it verifies none for a command approval — the
/// hook checks the assertion against its own pinned registry.
async fn authenticate_webauthn(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(approval): Json<AuthApproveWebauthnV1>,
) -> Result<StatusCode, ApiError> {
    approval
        .validate_shape()
        .map_err(|_| ApiError(StatusCode::CONFLICT))?;
    authorize_auth_request(&state, &id, &headers, &approval.device_fingerprint)?;
    if approval.request_id != id {
        return Err(ApiError(StatusCode::CONFLICT));
    }
    let fingerprint = approval.device_fingerprint.clone();
    match state.store.queue_auth_decision(
        &id,
        &fingerprint,
        &AuthDecisionV1::AuthenticateWebauthn(approval),
        now(),
    ) {
        Ok(InsertResult::Inserted | InsertResult::Identical) => Ok(StatusCode::ACCEPTED),
        Ok(InsertResult::Conflict) => Err(ApiError(StatusCode::GONE)),
        Err(error) if error.to_string().contains("expired") => Err(ApiError(StatusCode::GONE)),
        Err(error) if error.to_string().contains("unknown") => Err(ApiError(StatusCode::NOT_FOUND)),
        Err(_) => Err(ApiError(StatusCode::CONFLICT)),
    }
}

/// The server's recorded assertion for an authentication request, in its own
/// lane: a command verdict is never readable here, nor this one there.
///
/// Follow-ups deferred out of this slice, recorded here so they are not
/// lost (none of them is a behaviour change made in this pass):
///
/// * This route is unauthenticated, for parity with
///   `/api/v1/requests/:id/verdict`: a verdict is an outcome, not a secret,
///   and the payload was already published on NATS. Whether either route
///   should require a token is one decision for both lanes together.
/// * Decision-to-status mapping in `queue_decision` and
///   `authenticate_webauthn` dispatches on `error.to_string().contains(...)`.
///   That is the existing command-lane pattern, carried over deliberately so
///   the two stay identical; a typed store error would be better and belongs
///   to both lanes at once.
/// * `SubmittedAuthContextV1::agent_label` is signed and carried but shown
///   nowhere — neither the browser page nor the agent's terminal prompt
///   renders it. The hook does not populate it yet, so displaying it is work
///   for whichever slice starts to.
async fn recorded_auth_verdict(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    match state
        .store
        .recorded_auth_verdict(&id)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?
    {
        Some(payload) => Ok(asset("application/json", &payload, false)),
        None => Err(ApiError(StatusCode::NOT_FOUND)),
    }
}

fn authorize_auth_request(
    state: &AppState,
    id: &str,
    headers: &HeaderMap,
    fingerprint: &str,
) -> Result<(), ApiError> {
    require_pending_auth(state, id)?;
    let token = bearer_token(headers)?;
    let request = state
        .store
        .sealed_auth_request_for_token(id, token.as_bytes(), now())
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(ApiError(StatusCode::UNAUTHORIZED))?;
    let sealed: SealedDeviceBodyV1 = serde_json::from_str(&request.body_json)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?;
    if sealed.device_fingerprint != fingerprint {
        return Err(ApiError(StatusCode::UNAUTHORIZED));
    }
    Ok(())
}

fn require_pending_auth(state: &AppState, id: &str) -> Result<(), ApiError> {
    match state
        .store
        .auth_request_lifecycle(id, now())
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?
    {
        Some(RequestLifecycle::Pending) => Ok(()),
        Some(RequestLifecycle::Gone) => Err(ApiError(StatusCode::GONE)),
        None => Err(ApiError(StatusCode::NOT_FOUND)),
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
/// The server's recorded verdict for a request, if its authenticated API
/// accepted one. Public like the NATS verdict stream itself: hooks fetch it
/// to confirm relayed browser denials they cannot verify by signature.
/// Verdicts are outcomes, not secrets — the payload was already published.
async fn recorded_verdict(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    match state
        .store
        .recorded_verdict(&id)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?
    {
        Some(payload) => Ok(asset("application/json", &payload, false)),
        None => Err(ApiError(StatusCode::NOT_FOUND)),
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
    Ok(Json(json!({
        "status":"ok",
        "consumer_age_seconds":consumer_age,
        "outbox_age_seconds":outbox_age,
        "origin":state.origin.as_str(),
        "rp_id":state.rp_id.as_str(),
    })))
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
/// Selects the server transport named by `OSHIOKI_TRANSPORT`. Absent or
/// empty means `nats`, the only backend; anything else fails closed before
/// the listener binds — an unknown transport must never silently use NATS.
async fn transport_from_env() -> Result<Arc<dyn ServerTransport>> {
    match std::env::var("OSHIOKI_TRANSPORT").as_deref() {
        Err(_) | Ok("" | "nats") => Ok(Arc::new(NatsTransport::from_env().await?)),
        Ok(other) => bail!("unsupported transport: {other}"),
    }
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
    use sha2::Digest as _;

    fn dist_root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("oshioki-dist-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn permits() -> Arc<Semaphore> {
        Arc::new(Semaphore::new(MAX_CONCURRENT_ARTIFACTS))
    }

    fn health_state(name: &str, consumer_age: i64, outbox_age: i64) -> (PathBuf, AppState) {
        let dir =
            std::env::temp_dir().join(format!("oshioki-health-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Arc::new(Store::open(&dir.join("state.sqlite3")).unwrap());
        store.ready().unwrap();
        let transport = oshioki_transport::MockTransport::new();
        let current = now();
        (
            dir,
            AppState {
                store,
                transport: Arc::new(transport),
                dist_root: Arc::new(PathBuf::from("/nonexistent")),
                artifact_permits: Arc::new(Semaphore::new(1)),
                consumer_last_ok: Arc::new(AtomicI64::new(current - consumer_age)),
                outbox_last_ok: Arc::new(AtomicI64::new(current - outbox_age)),
                origin: Arc::new("https://sudo.test:8443".into()),
                rp_id: Arc::new("sudo.test".into()),
                ntfy_url: None,
            },
        )
    }

    #[tokio::test]
    async fn health_reports_public_webauthn_configuration() {
        let (dir, state) = health_state("metadata", 0, 0);
        let Json(body) = health(State(state)).await.unwrap();
        assert_eq!(body["status"], "ok");
        assert_eq!(body["origin"], "https://sudo.test:8443");
        assert_eq!(body["rp_id"], "sudo.test");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn health_rejects_stale_workers() {
        let (dir, state) = health_state("stale", 31, 0);
        let error = health(State(state)).await.unwrap_err();
        assert_eq!(error.0, StatusCode::SERVICE_UNAVAILABLE);
        let _ = std::fs::remove_dir_all(dir);
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

    /// The verdict worker publishes every outbox row through the transport
    /// and marks it sent, so the publish ordering survives the seam: a
    /// duplicate publish in the recording would mean commit-before-ack
    /// flipped.
    #[tokio::test]
    async fn mock_transport_drives_verdict_worker() {
        let dir =
            std::env::temp_dir().join(format!("oshioki-server-verdict-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Arc::new(Store::open(&dir.join("state.sqlite3")).unwrap());
        store.ready().unwrap();
        let device = test_device();
        store.put_device(&device).unwrap();
        let request_now = now();
        let envelope = RequestEnvelopeV1 {
            version: 1,
            request_id: "req-1".into(),
            host: "nas".into(),
            user: "eric".into(),
            issued_at: request_now,
            expires_at: request_now + oshioki_protocol::MAX_REQUEST_LIFETIME_SECS,
            sealed: vec![SealedDeviceBodyV1 {
                device_fingerprint: device.fingerprint.clone(),
                ephemeral_pub: oshioki_protocol::v1::encode_base64url(&[4; 32]),
                nonce: oshioki_protocol::v1::encode_base64url(&[5; 12]),
                ciphertext: oshioki_protocol::v1::encode_base64url(&[6; 32]),
            }],
        };
        let raw = serde_json::to_vec(&envelope).unwrap();
        store.ingest_request(&raw, &envelope, now()).unwrap();
        let decision = DecisionV1::Deny(DenyV1 {
            version: 1,
            request_id: "req-1".into(),
            device_fingerprint: device.fingerprint.clone(),
            signature: None,
        });
        store
            .queue_decision("req-1", &device.fingerprint, &decision, now())
            .unwrap();
        let transport = oshioki_transport::MockTransport::new();
        let state = AppState {
            store: Arc::clone(&store),
            transport: Arc::new(transport.clone()),
            dist_root: Arc::new(PathBuf::from("/nonexistent")),
            artifact_permits: Arc::new(Semaphore::new(1)),
            consumer_last_ok: Arc::new(AtomicI64::new(0)),
            outbox_last_ok: Arc::new(AtomicI64::new(0)),
            origin: Arc::new("https://sudo.test".into()),
            rp_id: Arc::new("sudo.test".into()),
            ntfy_url: None,
        };
        let worker = tokio::spawn(verdict_worker(state));
        let store_check = Arc::clone(&store);
        let transport_check = transport.clone();
        tokio::time::timeout(Duration::from_secs(2), async move {
            loop {
                if !transport_check.published().is_empty()
                    && store_check
                        .pending_verdicts(32)
                        .is_ok_and(|items| items.is_empty())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("verdict worker never drained the outbox");
        worker.abort();
        let published = transport.published();
        assert_eq!(
            published.len(),
            2,
            "duplicate publish means commit-before-ack flipped"
        );
        assert_eq!(published[0].0, "oshioki.delivery.req-1");
        let delivery: oshioki_protocol::DeliveryV1 =
            serde_json::from_slice(&published[0].1).unwrap();
        delivery.validate("req-1").unwrap();
        assert_eq!(published[1].0, "oshioki.verdict.req-1");
        assert_eq!(published[1].1, serde_json::to_vec(&decision).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A revocation delivery deactivates the device and confirms on the
    /// subject verbatim: the store transition comes first, then exactly one
    /// confirmation on `oshioki.device.revoked.<fingerprint>`.
    #[tokio::test]
    async fn mock_transport_drives_revocation() {
        let dir =
            std::env::temp_dir().join(format!("oshioki-server-revoke-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir.join("state.sqlite3")).unwrap();
        store.ready().unwrap();
        let device = test_device();
        store.put_device(&device).unwrap();
        let transport = oshioki_transport::MockTransport::new();
        let state = AppState {
            store: Arc::new(store),
            transport: Arc::new(transport.clone()),
            dist_root: Arc::new(PathBuf::from("/nonexistent")),
            artifact_permits: Arc::new(Semaphore::new(1)),
            consumer_last_ok: Arc::new(AtomicI64::new(0)),
            outbox_last_ok: Arc::new(AtomicI64::new(0)),
            origin: Arc::new("https://sudo.test".into()),
            rp_id: Arc::new("sudo.test".into()),
            ntfy_url: None,
        };
        handle_revocation(
            &state,
            format!("oshioki.device.revoke.{}", device.fingerprint),
        )
        .await
        .unwrap();
        assert!(
            state
                .store
                .active_device(&device.fingerprint)
                .unwrap()
                .is_none()
        );
        let last = transport
            .published()
            .last()
            .map(|(subject, _)| subject.clone());
        assert_eq!(
            last,
            Some(format!("oshioki.device.revoked.{}", device.fingerprint))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The request consumer double-acks identifiable requests and term-
    /// rejects oversized, malformed, or conflicting envelopes through the
    /// transport seam, preserving the store contract: the request row lands
    /// before the ack.
    #[tokio::test]
    async fn mock_transport_drives_request_consumer() {
        async fn wait_for(rx: &std::sync::mpsc::Receiver<()>, what: &str) {
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if rx.try_recv().is_ok() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("{what} never fired"));
        }
        let dir =
            std::env::temp_dir().join(format!("oshioki-server-consume-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Arc::new(Store::open(&dir.join("state.sqlite3")).unwrap());
        store.ready().unwrap();
        let device = test_device();
        store.put_device(&device).unwrap();
        let request_now = now();
        let valid_envelope = RequestEnvelopeV1 {
            version: 1,
            request_id: "req-consume".into(),
            host: "nas".into(),
            user: "eric".into(),
            issued_at: request_now,
            expires_at: request_now + oshioki_protocol::MAX_REQUEST_LIFETIME_SECS,
            sealed: vec![SealedDeviceBodyV1 {
                device_fingerprint: device.fingerprint.clone(),
                ephemeral_pub: oshioki_protocol::v1::encode_base64url(&[4; 32]),
                nonce: oshioki_protocol::v1::encode_base64url(&[5; 12]),
                ciphertext: oshioki_protocol::v1::encode_base64url(&[6; 32]),
            }],
        };
        let valid_raw = serde_json::to_vec(&valid_envelope).unwrap();
        // A conflicting reuse of the same request id with a different payload
        // must term the redelivery, never double-commit.
        let mut conflict = valid_envelope.clone();
        conflict.user = "zed".into();
        let conflict_raw = serde_json::to_vec(&conflict).unwrap();
        let (ack_tx, ack_rx) = std::sync::mpsc::channel::<()>();
        let (term_tx, term_rx) = std::sync::mpsc::channel::<()>();
        let transport = oshioki_transport::MockTransport::new();
        // Oversized envelopes are terminated on length alone, before any
        // parse: a redelivery would only cost the same bytes again.
        transport.push_request(oshioki_transport::mock::JetStreamMessageStub {
            payload: vec![b'x'; oshioki_protocol::v1::MAX_ENVELOPE_BYTES + 1],
            on_term: Some(term_tx.clone()),
            on_ack: None,
        });
        transport.push_request(oshioki_transport::mock::JetStreamMessageStub {
            payload: b"not json".to_vec(),
            on_term: Some(term_tx.clone()),
            on_ack: None,
        });
        transport.push_request(oshioki_transport::mock::JetStreamMessageStub {
            payload: valid_raw.clone(),
            on_term: None,
            on_ack: Some(ack_tx),
        });
        transport.push_request(oshioki_transport::mock::JetStreamMessageStub {
            payload: conflict_raw,
            on_term: Some(term_tx),
            on_ack: None,
        });
        let state = AppState {
            store: Arc::clone(&store),
            transport: Arc::new(transport),
            dist_root: Arc::new(PathBuf::from("/nonexistent")),
            artifact_permits: Arc::new(Semaphore::new(1)),
            consumer_last_ok: Arc::new(AtomicI64::new(0)),
            outbox_last_ok: Arc::new(AtomicI64::new(0)),
            origin: Arc::new("https://sudo.test".into()),
            rp_id: Arc::new("sudo.test".into()),
            ntfy_url: None,
        };
        let worker = tokio::spawn(request_consumer(state));
        // Oversized → term; malformed → term; valid → ack; conflict → term.
        // Poll without blocking so the single-threaded runtime keeps driving
        // the worker.
        wait_for(&term_rx, "oversized envelope term").await;
        wait_for(&term_rx, "malformed envelope term").await;
        wait_for(&ack_rx, "valid request ack").await;
        wait_for(&term_rx, "conflicting request term").await;
        worker.abort();
        // The valid request committed before the ack: the row is pending.
        assert!(
            store
                .request_lifecycle("req-consume", now())
                .unwrap()
                .is_some()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn auth_test_state(
        name: &str,
    ) -> (PathBuf, AppState, oshioki_transport::MockTransport, String) {
        let dir =
            std::env::temp_dir().join(format!("oshioki-server-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Arc::new(Store::open(&dir.join("state.sqlite3")).unwrap());
        store.ready().unwrap();
        let token = "browser-token-012345678901234567890".to_owned();
        let mut device = test_device();
        device.api_token_hash =
            oshioki_protocol::encode_base64url(&sha2::Sha256::digest(token.as_bytes()));
        store.put_device(&device).unwrap();
        let transport = oshioki_transport::MockTransport::new();
        let state = AppState {
            store,
            transport: Arc::new(transport.clone()),
            dist_root: Arc::new(PathBuf::from("/nonexistent")),
            artifact_permits: Arc::new(Semaphore::new(1)),
            consumer_last_ok: Arc::new(AtomicI64::new(0)),
            outbox_last_ok: Arc::new(AtomicI64::new(0)),
            origin: Arc::new("https://sudo.test".into()),
            rp_id: Arc::new("sudo.test".into()),
            ntfy_url: None,
        };
        (dir, state, transport, token)
    }

    fn auth_envelope(id: &str, fingerprint: &str) -> AuthEnvelopeV1 {
        let issued_at = now() - 1;
        AuthEnvelopeV1 {
            message_type: AUTH_ENVELOPE_TYPE.into(),
            version: oshioki_protocol::AUTH_WIRE_VERSION,
            request_id: id.into(),
            host: "nas".into(),
            issued_at,
            expires_at: issued_at + 75,
            sealed: vec![SealedDeviceBodyV1 {
                device_fingerprint: fingerprint.to_owned(),
                ephemeral_pub: oshioki_protocol::encode_base64url(&[4; 32]),
                nonce: oshioki_protocol::encode_base64url(&[5; 12]),
                ciphertext: oshioki_protocol::encode_base64url(&[6; 32]),
            }],
        }
    }

    fn command_envelope(id: &str, fingerprint: &str) -> RequestEnvelopeV1 {
        let issued_at = now() - 1;
        RequestEnvelopeV1 {
            version: oshioki_protocol::VERSION_V1,
            request_id: id.into(),
            host: "nas".into(),
            user: "eric".into(),
            issued_at,
            expires_at: issued_at + oshioki_protocol::MAX_REQUEST_LIFETIME_SECS - 1,
            sealed: vec![SealedDeviceBodyV1 {
                device_fingerprint: fingerprint.to_owned(),
                ephemeral_pub: oshioki_protocol::encode_base64url(&[4; 32]),
                nonce: oshioki_protocol::encode_base64url(&[5; 12]),
                ciphertext: oshioki_protocol::encode_base64url(&[6; 32]),
            }],
        }
    }

    fn webauthn_assertion(id: &str, fingerprint: &str) -> AuthApproveWebauthnV1 {
        AuthApproveWebauthnV1 {
            version: oshioki_protocol::AUTH_WIRE_VERSION,
            request_id: id.into(),
            device_fingerprint: fingerprint.to_owned(),
            credential_id: oshioki_protocol::encode_base64url(&[1; 16]),
            authenticator_data: oshioki_protocol::encode_base64url(&[7; 37]),
            client_data_json: oshioki_protocol::encode_base64url(b"{\"type\":\"webauthn.get\"}"),
            signature: oshioki_protocol::encode_base64url(&[8; 70]),
        }
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers
    }

    /// One authentication, from the durable stream to the verdict the hook
    /// reads back: it is stored in its own lane, served to the browser
    /// profile that owns it, acknowledged, and answered with a `WebAuthn`
    /// assertion queued on the verdict subject for this request id.
    #[tokio::test]
    async fn an_authentication_runs_from_ingest_to_verdict() {
        let (dir, state, transport, token) = auth_test_state("auth-lane");
        let device = test_device();
        let envelope = auth_envelope("auth-request", &device.fingerprint);
        let raw = serde_json::to_vec(&envelope).unwrap();
        assert_eq!(
            state
                .store
                .ingest_auth_request(&raw, &envelope, now())
                .unwrap(),
            InsertResult::Inserted
        );
        // A redelivery of the same bytes changes nothing.
        assert_eq!(
            state
                .store
                .ingest_auth_request(&raw, &envelope, now())
                .unwrap(),
            InsertResult::Identical
        );

        let Json(served) = get_auth_request(
            State(state.clone()),
            Path("auth-request".into()),
            bearer(&token),
        )
        .await
        .unwrap();
        assert_eq!(served.sealed.device_fingerprint, device.fingerprint);
        assert_eq!(served.expires_at, envelope.expires_at);

        let ack = AliveV1::for_request("auth-request");
        assert_eq!(
            acknowledge_auth_request(
                State(state.clone()),
                Path("auth-request".into()),
                bearer(&token),
                Json(ack.clone()),
            )
            .await
            .unwrap(),
            StatusCode::ACCEPTED
        );
        assert_eq!(
            transport.published(),
            vec![(
                "oshioki.ack.auth-request".to_owned(),
                serde_json::to_vec(&ack).unwrap()
            )]
        );

        let assertion = webauthn_assertion("auth-request", &device.fingerprint);
        assert_eq!(
            authenticate_webauthn(
                State(state.clone()),
                Path("auth-request".into()),
                bearer(&token),
                Json(assertion.clone()),
            )
            .await
            .unwrap(),
            StatusCode::ACCEPTED
        );
        let queued = state
            .store
            .pending_verdicts(8)
            .unwrap()
            .into_iter()
            .find(|item| item.subject == "oshioki.verdict.auth-request")
            .expect("the assertion was queued on this request's verdict subject");
        let decision: AuthDecisionV1 = serde_json::from_slice(&queued.payload).unwrap();
        assert_eq!(
            decision,
            AuthDecisionV1::AuthenticateWebauthn(assertion.clone())
        );

        let recorded = state
            .store
            .recorded_auth_verdict("auth-request")
            .unwrap()
            .expect("the assertion is readable back on its own lane");
        assert_eq!(recorded, queued.payload);
        // Lane isolation both ways: the command verdict route knows nothing
        // about this id, and the authentication route nothing about a
        // command one.
        assert!(
            state
                .store
                .recorded_verdict("auth-request")
                .unwrap()
                .is_none()
        );

        // The request is answered: a second, different assertion is refused.
        let mut replacement = assertion;
        replacement.signature = oshioki_protocol::encode_base64url(&[9; 70]);
        assert_eq!(
            authenticate_webauthn(
                State(state),
                Path("auth-request".into()),
                bearer(&token),
                Json(replacement),
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::GONE
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The durable consumer decides the lane from the envelope, not the
    /// subject: a command envelope and an authentication envelope both
    /// store and Ack, each in its own table.
    #[tokio::test]
    async fn the_consumer_stores_each_envelope_in_its_own_lane() {
        async fn wait_for(rx: &std::sync::mpsc::Receiver<()>, what: &str) {
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if rx.try_recv().is_ok() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("{what} never fired"));
        }
        let dir = std::env::temp_dir().join(format!(
            "oshioki-server-consumer-lanes-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Arc::new(Store::open(&dir.join("state.sqlite3")).unwrap());
        store.ready().unwrap();
        let device = test_device();
        let transport = oshioki_transport::MockTransport::new();
        let (command_tx, command_rx) = std::sync::mpsc::channel();
        let (auth_tx, auth_rx) = std::sync::mpsc::channel();
        let (term_tx, term_rx) = std::sync::mpsc::channel();
        transport.push_request(oshioki_transport::mock::JetStreamMessageStub {
            payload: serde_json::to_vec(&command_envelope("cmd-1", &device.fingerprint)).unwrap(),
            on_term: None,
            on_ack: Some(command_tx),
        });
        transport.push_request(oshioki_transport::mock::JetStreamMessageStub {
            payload: serde_json::to_vec(&auth_envelope("auth-1", &device.fingerprint)).unwrap(),
            on_term: None,
            on_ack: Some(auth_tx),
        });
        // An authentication envelope that does not decode is terminated, not
        // retried forever and not fed to the command decoder.
        transport.push_request(oshioki_transport::mock::JetStreamMessageStub {
            payload: serde_json::to_vec(&serde_json::json!({
                "type": AUTH_ENVELOPE_TYPE,
                "version": 2,
                "request_id": "auth-broken",
            }))
            .unwrap(),
            on_term: Some(term_tx),
            on_ack: None,
        });
        // A type this build does not implement is terminated as well. It
        // must never reach the command decoder: a tagged envelope that
        // happens to carry the command lane's fields would otherwise be
        // stored as a command approval request.
        let (unknown_tx, unknown_rx) = std::sync::mpsc::channel();
        let mut disguised =
            serde_json::to_value(command_envelope("cmd-disguised", &device.fingerprint)).unwrap();
        disguised["type"] = serde_json::json!("sudo_something_else");
        transport.push_request(oshioki_transport::mock::JetStreamMessageStub {
            payload: serde_json::to_vec(&disguised).unwrap(),
            on_term: Some(unknown_tx),
            on_ack: None,
        });
        let state = AppState {
            store: Arc::clone(&store),
            transport: Arc::new(transport),
            dist_root: Arc::new(PathBuf::from("/nonexistent")),
            artifact_permits: Arc::new(Semaphore::new(1)),
            consumer_last_ok: Arc::new(AtomicI64::new(0)),
            outbox_last_ok: Arc::new(AtomicI64::new(0)),
            origin: Arc::new("https://sudo.test".into()),
            rp_id: Arc::new("sudo.test".into()),
            ntfy_url: None,
        };
        let worker = tokio::spawn(request_consumer(state));
        wait_for(&command_rx, "command envelope ack").await;
        wait_for(&auth_rx, "authentication envelope ack").await;
        wait_for(&term_rx, "malformed authentication envelope term").await;
        wait_for(&unknown_rx, "unknown envelope type term").await;
        worker.abort();
        assert!(store.request_lifecycle("cmd-1", now()).unwrap().is_some());
        assert!(
            store
                .auth_request_lifecycle("cmd-1", now())
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .auth_request_lifecycle("auth-1", now())
                .unwrap()
                .is_some()
        );
        assert!(store.request_lifecycle("auth-1", now()).unwrap().is_none());
        // The disguised envelope was stored by neither lane.
        assert!(
            store
                .request_lifecycle("cmd-disguised", now())
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .auth_request_lifecycle("cmd-disguised", now())
                .unwrap()
                .is_none()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Neither lane answers for the other. A command approval or denial
    /// aimed at an authentication id, and an assertion aimed at a command
    /// id, are both refused before anything is stored or published.
    #[tokio::test]
    async fn a_decision_aimed_at_the_wrong_lane_is_refused() {
        let (dir, state, transport, token) = auth_test_state("cross-lane");
        let device = test_device();
        let auth = auth_envelope("auth-cross", &device.fingerprint);
        state
            .store
            .ingest_auth_request(&serde_json::to_vec(&auth).unwrap(), &auth, now())
            .unwrap();
        let command = command_envelope("cmd-cross", &device.fingerprint);
        state
            .store
            .ingest_request(&serde_json::to_vec(&command).unwrap(), &command, now())
            .unwrap();

        let approval = ApproveV1 {
            version: oshioki_protocol::VERSION_V1,
            request_id: "auth-cross".into(),
            device_fingerprint: device.fingerprint.clone(),
            credential_id: oshioki_protocol::encode_base64url(&[1; 16]),
            authenticator_data: oshioki_protocol::encode_base64url(&[7; 37]),
            client_data_json: oshioki_protocol::encode_base64url(b"{\"type\":\"webauthn.get\"}"),
            signature: oshioki_protocol::encode_base64url(&[8; 70]),
        };
        assert_eq!(
            approve_request(
                State(state.clone()),
                Path("auth-cross".into()),
                bearer(&token),
                Json(approval),
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::NOT_FOUND
        );
        let denial = DenyV1 {
            version: oshioki_protocol::VERSION_V1,
            request_id: "auth-cross".into(),
            device_fingerprint: device.fingerprint.clone(),
            signature: None,
        };
        assert_eq!(
            deny_request(
                State(state.clone()),
                Path("auth-cross".into()),
                bearer(&token),
                Json(denial),
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get_auth_request(
                State(state.clone()),
                Path("cmd-cross".into()),
                bearer(&token),
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get_request(
                State(state.clone()),
                Path("auth-cross".into()),
                bearer(&token),
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::NOT_FOUND
        );
        // Nothing above queued a verdict or published anything. (Ingest
        // queues a browser delivery receipt on each lane; that is not a
        // verdict and is expected here.)
        assert!(transport.published().is_empty());
        assert!(
            state
                .store
                .pending_verdicts(8)
                .unwrap()
                .iter()
                .all(|item| !item.subject.starts_with("oshioki.verdict."))
        );
        assert!(
            state
                .store
                .auth_request_lifecycle("auth-cross", now())
                .unwrap()
                .is_some()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The mirror of the case above: an authentication assertion may not be
    /// posted against a command request id, nor against an authentication id
    /// other than its own.
    #[tokio::test]
    async fn an_assertion_aimed_at_the_wrong_request_is_refused() {
        let (dir, state, transport, token) = auth_test_state("assertion-cross");
        let device = test_device();
        let auth = auth_envelope("auth-target", &device.fingerprint);
        state
            .store
            .ingest_auth_request(&serde_json::to_vec(&auth).unwrap(), &auth, now())
            .unwrap();
        let command = command_envelope("cmd-target", &device.fingerprint);
        state
            .store
            .ingest_request(&serde_json::to_vec(&command).unwrap(), &command, now())
            .unwrap();
        assert_eq!(
            authenticate_webauthn(
                State(state.clone()),
                Path("cmd-target".into()),
                bearer(&token),
                Json(webauthn_assertion("cmd-target", &device.fingerprint)),
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            authenticate_webauthn(
                State(state.clone()),
                Path("auth-target".into()),
                bearer(&token),
                Json(webauthn_assertion("auth-other", &device.fingerprint)),
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::CONFLICT
        );
        assert!(transport.published().is_empty());
        assert!(
            state
                .store
                .pending_verdicts(8)
                .unwrap()
                .iter()
                .all(|item| !item.subject.starts_with("oshioki.verdict."))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// There is no refusal on the authentication lane, and there must never
    /// be one: cancelling in the browser sends nothing and the host asks for
    /// a password. The wire type has no `Deny` variant at all, so this guards
    /// the three places that could still grow one — the lane's route table,
    /// a hand-registered route that bypassed it, and a button on the page.
    #[test]
    fn the_authentication_lane_has_no_denial() {
        // The router registers these and nothing else, so this is the lane's
        // complete route table.
        assert_eq!(AUTH_ROUTES.len(), 4);
        let prefix = concat!("/api/v1/", "auth/");
        for route in AUTH_ROUTES {
            assert!(route.starts_with(prefix), "{route}");
            for forbidden in ["deny", "refuse", "reject", "approve"] {
                assert!(!route.contains(forbidden), "{route}");
            }
        }
        assert!(AUTH_ROUTES.contains(&"/api/v1/auth/:id/authenticate-webauthn"));
        // And nothing registers a lane path outside that table: every line
        // of this file naming one is checked, so a hand-added `.route(...)`
        // in any form is caught too. The needle is split above so this test's
        // own source cannot match itself.
        for line in include_str!("main.rs").lines() {
            if !line.contains(prefix) {
                continue;
            }
            for forbidden in ["deny", "refuse", "reject", "approve"] {
                assert!(!line.contains(forbidden), "{line}");
            }
        }
        let page = include_str!("../web/auth.html");
        assert!(page.contains("id=\"authenticate\""));
        assert!(!page.to_lowercase().contains("deny"));
    }

    fn test_device() -> oshioki_protocol::DevicePublicRecordV1 {
        let credential_id = vec![1; 16];
        let signing = p256::ecdsa::SigningKey::from_bytes((&[2; 32]).into()).unwrap();
        let point = signing.verifying_key().to_encoded_point(false);
        let cose = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Integer(2.into()),
            ),
            (
                ciborium::Value::Integer(3.into()),
                ciborium::Value::Integer((-7).into()),
            ),
            (
                ciborium::Value::Integer((-1).into()),
                ciborium::Value::Integer(1.into()),
            ),
            (
                ciborium::Value::Integer((-2).into()),
                ciborium::Value::Bytes(point.x().unwrap().to_vec()),
            ),
            (
                ciborium::Value::Integer((-3).into()),
                ciborium::Value::Bytes(point.y().unwrap().to_vec()),
            ),
        ]);
        let mut credential_public_key = Vec::new();
        ciborium::ser::into_writer(&cose, &mut credential_public_key).unwrap();
        let box_public_key = vec![3; 32];
        let fingerprint = oshioki_protocol::device_fingerprint(
            &credential_id,
            &credential_public_key,
            &box_public_key,
        );
        oshioki_protocol::DevicePublicRecordV1 {
            version: 1,
            kind: oshioki_protocol::DeviceKindV1::Webauthn,
            fingerprint,
            credential_id: oshioki_protocol::v1::encode_base64url(&credential_id),
            credential_public_key: oshioki_protocol::v1::encode_base64url(&credential_public_key),
            box_public_key: oshioki_protocol::v1::encode_base64url(&box_public_key),
            label: "test".into(),
            api_token_hash: oshioki_protocol::v1::encode_base64url(&[9; 32]),
            sign_count: 0,
            active: true,
        }
    }

    /// Browser liveness is an explicit authenticated message. Ingesting a
    /// request alone publishes nothing, a wrong token cannot publish, and a
    /// valid browser post is forwarded byte-for-byte on the ack subject.
    #[tokio::test]
    async fn browser_ack_requires_authenticated_pending_request() {
        let dir =
            std::env::temp_dir().join(format!("oshioki-server-browser-ack-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Arc::new(Store::open(&dir.join("state.sqlite3")).unwrap());
        store.ready().unwrap();
        let token = "browser-token-012345678901234567890";
        let mut device = test_device();
        device.api_token_hash =
            oshioki_protocol::encode_base64url(&sha2::Sha256::digest(token.as_bytes()));
        store.put_device(&device).unwrap();
        let request_now = now();
        let request = RequestEnvelopeV1 {
            version: oshioki_protocol::VERSION_V1,
            request_id: "browser-ack-request".into(),
            host: "nas".into(),
            user: "eric".into(),
            issued_at: request_now - 1,
            expires_at: request_now + oshioki_protocol::MAX_REQUEST_LIFETIME_SECS - 1,
            sealed: vec![SealedDeviceBodyV1 {
                device_fingerprint: device.fingerprint.clone(),
                ephemeral_pub: oshioki_protocol::encode_base64url(&[4; 32]),
                nonce: oshioki_protocol::encode_base64url(&[5; 12]),
                ciphertext: oshioki_protocol::encode_base64url(&[6; 32]),
            }],
        };
        let raw = serde_json::to_vec(&request).unwrap();
        store.ingest_request(&raw, &request, request_now).unwrap();
        let transport = oshioki_transport::MockTransport::new();
        let state = AppState {
            store,
            transport: Arc::new(transport.clone()),
            dist_root: Arc::new(PathBuf::from("/nonexistent")),
            artifact_permits: Arc::new(Semaphore::new(1)),
            consumer_last_ok: Arc::new(AtomicI64::new(0)),
            outbox_last_ok: Arc::new(AtomicI64::new(0)),
            origin: Arc::new("https://sudo.test".into()),
            rp_id: Arc::new("sudo.test".into()),
            ntfy_url: None,
        };
        assert!(transport.published().is_empty());

        let ack = AliveV1::for_request(&request.request_id);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        let response = acknowledge_request(
            State(state.clone()),
            Path(request.request_id.clone()),
            headers.clone(),
            Json(ack.clone()),
        )
        .await
        .unwrap();
        assert_eq!(response, StatusCode::ACCEPTED);
        assert_eq!(
            transport.published(),
            vec![(
                format!("oshioki.ack.{}", request.request_id),
                serde_json::to_vec(&ack).unwrap()
            )]
        );

        let bad = acknowledge_request(
            State(state.clone()),
            Path(request.request_id.clone()),
            {
                let mut bad_headers = HeaderMap::new();
                bad_headers.insert(
                    header::AUTHORIZATION,
                    HeaderValue::from_static("Bearer wrong-token-012345678901234567890"),
                );
                bad_headers
            },
            Json(ack.clone()),
        )
        .await
        .unwrap_err();
        assert_eq!(bad.0, StatusCode::UNAUTHORIZED);
        assert_eq!(transport.published().len(), 1);

        let mismatch = acknowledge_request(
            State(state),
            Path("other-request".into()),
            headers,
            Json(ack),
        )
        .await
        .unwrap_err();
        assert_eq!(mismatch.0, StatusCode::CONFLICT);
        assert_eq!(transport.published().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
