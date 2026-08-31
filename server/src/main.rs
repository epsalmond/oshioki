//! `management-plane-sudo-approve-server` — the approval service.
//!
//! The server runs behind Traefik. It serves the HTTPS approval and
//! enrollment pages, maintains the NATS consumer on `SUDO_APPROVE`, and
//! publishes requests to enrolled devices as browser-page payloads.

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Html,
    routing::{get, post},
};
use futures::StreamExt;
use serde_json::json;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use protocol::Verdict;

/// Server state shared by handlers.
#[derive(Clone)]
struct AppState {
    nats: Arc<async_nats::Client>,
    pending: PendingMap,
    /// Shared bearer token required on the approval API endpoints
    /// (`/api/pending`, `/assertion/:id`). Loaded once from the
    /// `SUDO_APPROVE_API_TOKEN` env var at startup; empty disables the
    /// server with a clear error (fail closed).
    api_token: String,
}

/// Pending requests awaiting verdicts.
type PendingMap = Arc<Mutex<std::collections::HashMap<String, Pending>>>;

/// One pending approval.
#[derive(Debug, Clone)]
struct Pending {
    id: String,
    host: String,
    user: String,
    command: String,
    expiry: i64,
    envelope_body_json: String,
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("management_plane_sudo_approve_server=info".parse().unwrap()),
        )
        .init();

    let nats_url = std::env::var("NATS_URL").expect("NATS_URL not set");
    let nats_user = std::env::var("NATS_USER").expect("NATS_USER not set");
    let nats_pass = std::env::var("NATS_PASS").expect("NATS_PASS not set");
    let api_token = std::env::var("SUDO_APPROVE_API_TOKEN")
        .expect("SUDO_APPROVE_API_TOKEN not set — refusing to start unauthenticated");
    assert!(
        api_token.len() >= 16,
        "SUDO_APPROVE_API_TOKEN too short (want >= 16 chars)"
    );

    info!(nats_url, "starting");

    let nats = Arc::new(
        async_nats::ConnectOptions::new()
            .user_and_password(nats_user, nats_pass)
            .connect(&nats_url)
            .await
            .expect("connect to NATS"),
    );

    let pending: PendingMap = Arc::new(Mutex::new(std::collections::HashMap::new()));

    // Spawn NATS consumer.
    {
        let nats2 = nats.clone();
        let pending2 = pending.clone();
        tokio::spawn(async move {
            if let Err(e) = consumer_task(nats2, pending2).await {
                warn!(error = %e, "consumer task failed");
            }
        });
    }

    // Build HTTP routes.
    let state = AppState {
        nats,
        pending: pending.clone(),
        api_token,
    };
    let app = Router::new()
        .route("/", get(handle_approval_page))
        .route("/enroll/:token", get(handle_enroll_page))
        .route("/api/pending", get(handle_api_pending))
        .route("/assertion/:id", post(handle_assertion))
        .with_state(state);

    info!("listening on 8443");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8443").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

/// The approval page.
async fn handle_approval_page() -> Html<&'static str> {
    Html(APPROVAL_HTML)
}

/// The enrollment page.
async fn handle_enroll_page(Path(_token): Path<String>) -> Html<&'static str> {
    Html(ENROLL_HTML)
}

/// Return pending requests as JSON.
async fn handle_api_pending(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_auth(&state, &headers)?;
    let pending = state.pending.lock().await;

    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_secs(),
    )
    .expect("Unix timestamp fits i64");

    let mut list = Vec::new();

    for p in pending.values() {
        if now < p.expiry {
            list.push(json!({
                "id": p.id,
                "host": p.host,
                "user": p.user,
                "command": p.command,
                "expiry": p.expiry,
                "expiry_human": format!("{}s", p.expiry - now),
                "body": p.envelope_body_json,
            }));
        }
    }

    Ok(Json(json!({
        "requests": list
    })))
}

/// Handle a signed verdict (`WebAuthn` assertion).
async fn handle_assertion(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(verdict): Json<Verdict>,
) -> Result<(), StatusCode> {
    check_auth(&state, &headers)?;
    // Hold the lock across the entire operation to avoid the double-lock pattern.
    let pending = state.pending.lock().await;

    if !pending.contains_key(&id) {
        warn!(id, "assertion for unknown request");
        return Err(StatusCode::NOT_FOUND);
    }

    // Serialize the verdict before dropping the lock.
    let payload = serde_json::to_vec(&verdict).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Drop the lock before the async NATS call.
    drop(pending);

    state
        .nats
        .publish(format!("sudo.verdict.{id}"), payload.into())
        .await
        .map_err(|e| {
            warn!(error = %e, id, "failed to publish verdict");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    debug!(id, "published verdict to NATS");

    // Remove from pending after successful publish.
    state.pending.lock().await.remove(&id);

    Ok(())
}

// ---------------------------------------------------------------------------
// Authentication — shared bearer token on approval endpoints
// ---------------------------------------------------------------------------

/// Check the Authorization header against the shared API token.
///
/// This is a simple boundary to prevent unauthenticated access to
/// `/api/pending` and `/assertion/:id`. The token is loaded from the
/// `SUDO_APPROVE_API_TOKEN` environment variable at startup.
fn check_auth(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let Some(header) = headers.get("Authorization") else {
        warn!("missing Authorization header on protected endpoint");
        return Err(StatusCode::UNAUTHORIZED);
    };
    let Ok(auth) = header.to_str() else {
        warn!("invalid utf-8 in Authorization header");
        return Err(StatusCode::UNAUTHORIZED);
    };

    let Some((scheme, token)) = auth.split_once(' ') else {
        warn!("missing bearer token in Authorization");
        return Err(StatusCode::UNAUTHORIZED);
    };

    if scheme != "Bearer" {
        warn!(scheme, "unexpected auth scheme");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token = token.trim();
    if token.is_empty() {
        warn!("empty bearer token");
        return Err(StatusCode::UNAUTHORIZED);
    }

    if token != state.api_token {
        warn!("invalid bearer token");
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// NATS consumer — just queue requests
// ---------------------------------------------------------------------------

async fn consumer_task(nats: Arc<async_nats::Client>, pending: PendingMap) -> Result<()> {
    let mut sub = nats.subscribe("sudo.request.>").await?;
    info!("consuming sudo.request.>");

    while let Some(msg) = sub.next().await {
        match serde_json::from_slice::<serde_json::Value>(&msg.payload) {
            Ok(req) => {
                let id = req["header"]["id"].as_str().unwrap_or("").to_string();
                let host = req["header"]["host"].as_str().unwrap_or("").to_string();
                let user = req["header"]["user"].as_str().unwrap_or("").to_string();
                let ts = req["header"]["ts"].as_i64().unwrap_or(0);
                let sealed = req["sealed"][0]["ciphertext"].as_str().unwrap_or("");

                if id.is_empty() {
                    warn!("missing request id");
                    continue;
                }

                let expiry = ts + 90;

                let entry = Pending {
                    id: id.clone(),
                    host,
                    user,
                    command: format!("(exp: {}s)", ts + 90),
                    expiry,
                    envelope_body_json: sealed.to_string(),
                };

                debug!(id, "queued request");
                pending.lock().await.insert(id, entry);
            }
            Err(e) => {
                warn!(error = %e, "bad request payload");
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// HTML pages
// ---------------------------------------------------------------------------

const APPROVAL_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
  <title>Approve sudo</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: system-ui, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; }
    h1 { color: #333; }
    .request { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 4px; }
    .command { font-family: monospace; }
    button { background: #007bff; color: white; border: none; padding: 10px 20px; cursor: pointer; }
    button:hover { background: #0056b3; }
  </style>
</head>
<body>
  <h1>Pending sudo requests</h1>
  <div id="requests">Loading…</div>
  <script>
    async function load() {
      const res = await fetch('/api/pending');
      const data = await res.json();
      document.getElementById('requests').innerHTML = data.requests.map(r => `
        <div class="request">
          <strong>#${r.id.slice(0,8)}</strong> on ${r.host}<br/>
          user: ${r.user}<br/>
          command: <span class="command">${r.command}</span><br/>
          expires: ${r.expiry_human}<br/>
          <button onclick="approve('${r.id}')">Approve</button>
        </div>
      `).join('');
    }

    async function approve(id) {
      const credential = await navigator.credentials.create({
        publicKey: {
          rp: { name: "sudo" },
          user: { id: new Uint8Array(16), name: "sudo", displayName: "sudo" },
          challenge: new TextEncoder().encode("approve"),
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          authenticatorSelection: { userVerification: "required" }
        }
      });
      alert("credential ceremony not wired: see WebAuthn handler");
    }

    setInterval(load, 2000);
    load();
  </script>
</body>
</html>"#;

const ENROLL_HTML: &str = r#"<!DOCTYPE html>
<html>
<head><title>Enroll</title></head>
<body>
  <h1>Enroll this device</h1>
  <p>Enroll a Touch ID / Face ID credential for sudo approval.</p>
  <button onclick="enroll()">Enroll</button>
  <script>
    async function enroll() {
      const credential = await navigator.credentials.create({
        publicKey: {
          rp: { name: "sudo" },
          user: { id: new Uint8Array(16), name: "sudo-approve", displayName: "sudo" },
          challenge: new TextEncoder().encode("enroll"),
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          authenticatorSelection: { userVerification: "required" }
        }
      });
      alert("enrollment ceremony not wired");
    }
  </script>
</body>
</html>"#;
