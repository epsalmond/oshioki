//! Root-owned sudo approval hook and operator CLI.

use anyhow::{Context as _, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand};
use futures::StreamExt as _;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::{self, BufRead as _, Write as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
use tracing::{info, warn};
use uuid::Uuid;

use oshioki_protocol::{
    ActivationV1, DecisionV1, DeviceKindV1, DevicePublicRecordV1, DeviceRegistryV1,
    EnrollmentIntentV1, EnrollmentSubmissionV1, HookConfigV1, RequestEnvelopeV1, RequestV1,
    VERSION_V1, verify_approval_v1, verify_enrollment_v1, verify_native_approval_v1,
    verify_native_enrollment_v1,
};

const DEFAULT_CONFIG_DIR: &str = "/etc/oshioki";
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(90);
const ENROLLMENT_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Parser)]
#[command(name = "oshioki", about = "sudo approval hook")]
struct Cli {
    #[command(subcommand)]
    verb: Verb,
}

#[derive(Subcommand)]
enum Verb {
    Check,
    Enroll {
        #[arg(long, allow_hyphen_values = true)]
        resume: Option<String>,
    },
    Revoke {
        #[arg(allow_hyphen_values = true)]
        fingerprint: String,
    },
    Pin {
        #[arg(allow_hyphen_values = true)]
        fingerprint: String,
    },
    Status,
    Test,
    Watch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EnrollmentStateV1 {
    version: u8,
    enrollment_id: String,
    secret: String,
    expires_at: i64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("oshioki=info".parse().expect("valid directive")),
        )
        .with_writer(io::stdout)
        .init();
    let result = match Cli::parse().verb {
        Verb::Check => cmd_check().await,
        Verb::Enroll { resume } => cmd_enroll(resume.as_deref()).await,
        Verb::Revoke { fingerprint } => cmd_revoke(&fingerprint).await,
        Verb::Pin { fingerprint } => cmd_pin(&fingerprint).await,
        Verb::Status => cmd_status(),
        Verb::Test => cmd_test().await,
        Verb::Watch => cmd_watch().await,
    };
    if let Err(error) = result {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
    Ok(())
}

async fn cmd_check() -> Result<()> {
    let request = build_request(&parse_sudo_stdin()?)?;
    execute_request_at(request, APPROVAL_TIMEOUT, check_config_dir(), false).await
}

async fn execute_request(request: RequestV1, timeout: Duration) -> Result<()> {
    let directory = config_dir();
    execute_request_at(request, timeout, &directory, true).await
}

async fn execute_request_at(
    request: RequestV1,
    timeout: Duration,
    directory: &Path,
    announce_url: bool,
) -> Result<()> {
    let raw_request = request.raw_json()?;
    let mut registry = load_registry_from(directory)?;
    let active = registry
        .devices
        .iter()
        .filter(|device| device.active)
        .cloned()
        .collect::<Vec<_>>();
    if active.is_empty() {
        bail!("no active approval devices");
    }
    let envelope = seal_request(&request, &raw_request, &active)?;
    let payload = serde_json::to_vec(&envelope)?;
    if payload.len() > oshioki_protocol::v1::MAX_ENVELOPE_BYTES {
        bail!("request envelope exceeds 3 MiB");
    }
    let nats = connect_nats_from(directory).await?;
    if announce_url {
        let config = load_hook_config_from(directory)?;
        println!(
            "Approval URL (expires in {} seconds):\n  {}",
            timeout.as_secs(),
            approval_url(&config.server_base_url, &request.request_id)
        );
        io::stdout().flush()?;
    }
    let decision = request_decision(
        &nats,
        &format!("oshioki.request.{}", request.host),
        &format!("oshioki.verdict.{}", request.request_id),
        payload,
        timeout,
    )
    .await?;
    apply_decision(
        decision,
        &request,
        &raw_request,
        &active,
        &mut registry,
        directory,
    )
}

/// Applies one decision to a request. Invalid decisions fail closed.
fn apply_decision(
    decision: DecisionV1,
    request: &RequestV1,
    raw_request: &[u8],
    active: &[DevicePublicRecordV1],
    registry: &mut DeviceRegistryV1,
    directory: &Path,
) -> Result<()> {
    match decision {
        DecisionV1::Deny(denial) => {
            denial.validate_shape().context("validate deny decision")?;
            if denial.version != VERSION_V1 || denial.request_id != request.request_id {
                bail!("malformed deny decision");
            }
            if !active
                .iter()
                .any(|device| device.fingerprint == denial.device_fingerprint)
            {
                bail!("deny from unpinned device");
            }
            bail!("request explicitly denied");
        }
        DecisionV1::Approve(approval) => {
            approval
                .validate_shape()
                .context("validate approval decision")?;
            if approval.request_id != request.request_id {
                bail!("approval request id mismatch");
            }
            let device = active
                .iter()
                .find(|device| {
                    device.kind == DeviceKindV1::Webauthn
                        && device.fingerprint == approval.device_fingerprint
                        && device.credential_id == approval.credential_id
                })
                .context("approval does not name one exact pinned credential")?;
            let outcome = verify_approval_v1(
                &approval,
                raw_request,
                device,
                &load_hook_config_from(directory)?,
            )
            .context("approval verification failed")?;
            if outcome.counter_regressed {
                warn!(fingerprint=%device.fingerprint, stored=device.sign_count, observed=outcome.observed_sign_count, "authenticator signature counter regressed");
            }
            if outcome.observed_sign_count > device.sign_count {
                if let Some(stored) = registry
                    .devices
                    .iter_mut()
                    .find(|stored| stored.fingerprint == device.fingerprint)
                {
                    stored.sign_count = outcome.observed_sign_count;
                }
                write_registry_to(directory, registry)?;
            }
            info!(request_id=%request.request_id, fingerprint=%device.fingerprint, "sudo request approved");
            Ok(())
        }
        DecisionV1::ApproveNative(approval) => {
            approval
                .validate_shape()
                .context("validate native approval decision")?;
            if approval.request_id != request.request_id {
                bail!("approval request id mismatch");
            }
            let device = active
                .iter()
                .find(|device| {
                    device.kind == DeviceKindV1::SecureEnclave
                        && device.fingerprint == approval.device_fingerprint
                })
                .context("native approval does not name one pinned secure-enclave device")?;
            verify_native_approval_v1(&approval, raw_request, device)
                .context("native approval verification failed")?;
            info!(request_id=%request.request_id, fingerprint=%device.fingerprint, kind="secure-enclave", "sudo request approved");
            Ok(())
        }
    }
}

fn approval_url(server_base_url: &str, request_id: &str) -> String {
    format!("{server_base_url}/r/{request_id}")
}

async fn request_decision(
    nats: &async_nats::Client,
    request_subject: &str,
    decision_subject: &str,
    payload: Vec<u8>,
    timeout: Duration,
) -> Result<DecisionV1> {
    let mut stage = "subscribing to decision";
    tokio::time::timeout(timeout, async {
        let mut subscription = nats
            .subscribe(decision_subject.to_owned())
            .await
            .context("subscribe decision")?;
        stage = "confirming decision subscription readiness";
        nats.flush().await.context("flush decision subscription")?;
        stage = "publishing approval request";
        nats.publish(request_subject.to_owned(), payload.into())
            .await
            .context("publish request")?;
        stage = "waiting for decision";
        let message = subscription
            .next()
            .await
            .context("decision stream closed")?;
        serde_json::from_slice(&message.payload).context("decode decision")
    })
    .await
    .with_context(|| {
        format!(
            "sudo decision deadline exceeded after {}ms while {stage}",
            timeout.as_millis()
        )
    })?
}

async fn cmd_enroll(resume: Option<&str>) -> Result<()> {
    let config = load_hook_config()?;
    let state = if let Some(id) = resume {
        load_enrollment_state(id)?
    } else {
        create_enrollment_state()?
    };
    let state_path = enrollment_path(&state.enrollment_id)?;
    prune_expired_enrollment_states(&state.enrollment_id);
    if state.expires_at <= now() {
        remove_enrollment_state(&state_path);
        bail!("enrollment expired");
    }
    let secret_bytes: [u8; 32] = oshioki_protocol::decode_base64url(&state.secret)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid enrollment secret"))?;
    let nats = connect_nats().await?;
    let reply_subject = format!("oshioki.enrollment.submission.{}", state.enrollment_id);
    let mut subscription = nats
        .subscribe(reply_subject.clone())
        .await
        .context("subscribe enrollment submission")?;
    nats.flush()
        .await
        .context("flush enrollment subscription")?;
    let intent = EnrollmentIntentV1 {
        version: VERSION_V1,
        enrollment_id: state.enrollment_id.clone(),
        secret_hash: URL_SAFE_NO_PAD.encode(Sha256::digest(secret_bytes)),
        expires_at: state.expires_at,
        reply_subject,
    };
    nats.publish(
        "oshioki.enrollment.intent",
        serde_json::to_vec(&intent)?.into(),
    )
    .await?;
    nats.flush().await?;
    let enrollment_url = format!(
        "{}/enroll/{}#{}",
        config.server_base_url, state.enrollment_id, state.secret
    );
    println!(
        "Enrollment URL (expires in five minutes):\n  {enrollment_url}\nNative agent:\n  oshioki-agent pair '{enrollment_url}'"
    );
    let remaining = u64::try_from(state.expires_at - now()).context("enrollment expiry")?;
    let message = tokio::time::timeout(
        Duration::from_secs(remaining.min(ENROLLMENT_TIMEOUT.as_secs())),
        subscription.next(),
    )
    .await
    .context("enrollment timeout")?
    .context("enrollment stream closed")?;
    let submission: EnrollmentSubmissionV1 =
        serde_json::from_slice(&message.payload).context("decode enrollment submission")?;
    if submission.enrollment_id() != state.enrollment_id {
        bail!("enrollment id mismatch");
    }
    let device = match &submission {
        EnrollmentSubmissionV1::Webauthn(submission) => {
            verify_enrollment_v1(submission, &secret_bytes, &config).context("verify enrollment")?
        }
        EnrollmentSubmissionV1::SecureEnclave(submission) => {
            verify_native_enrollment_v1(submission, &secret_bytes)
                .context("verify native enrollment")?
        }
    };
    let mut registry = load_registry()?;
    if registry.devices.iter().any(|stored| {
        stored.credential_id == device.credential_id && stored.fingerprint != device.fingerprint
    }) {
        bail!("credential id is already enrolled under another record");
    }
    registry
        .devices
        .retain(|stored| stored.fingerprint != device.fingerprint);
    registry.devices.push(device.clone());
    registry.validate()?;
    write_registry(&registry)?;
    let activation = ActivationV1 {
        version: VERSION_V1,
        enrollment_id: state.enrollment_id.clone(),
        device: device.clone(),
    };
    nats.publish(
        format!("oshioki.enrollment.activation.{}", state.enrollment_id),
        serde_json::to_vec(&activation)?.into(),
    )
    .await?;
    nats.flush().await?;
    remove_enrollment_state(&state_path);
    println!("Device enrolled: {} ({})", device.fingerprint, device.label);
    Ok(())
}

async fn cmd_revoke(fingerprint: &str) -> Result<()> {
    let mut registry = load_registry()?;
    let original = registry.devices.len();
    if !registry
        .devices
        .iter()
        .any(|device| device.fingerprint == fingerprint)
    {
        bail!("unknown device fingerprint");
    }
    let nats = connect_nats().await?;
    let confirmation_subject = format!("oshioki.device.revoked.{fingerprint}");
    let mut confirmation = nats.subscribe(confirmation_subject).await?;
    nats.flush().await?;
    nats.publish(
        format!("oshioki.device.revoke.{fingerprint}"),
        Vec::new().into(),
    )
    .await?;
    nats.flush().await?;
    tokio::time::timeout(Duration::from_secs(15), confirmation.next())
        .await
        .context("server revocation confirmation timeout")?
        .context("server revocation confirmation stream closed")?;
    registry
        .devices
        .retain(|device| device.fingerprint != fingerprint);
    debug_assert!(registry.devices.len() < original);
    write_registry(&registry)?;
    println!("Device revoked: {fingerprint}");
    Ok(())
}

async fn cmd_pin(expected: &str) -> Result<()> {
    let config = load_hook_config()?;
    let body = http_get(&format!(
        "{}/api/v1/devices/{expected}",
        config.server_base_url
    ))
    .await?;
    let device: DevicePublicRecordV1 =
        serde_json::from_slice(&body).context("decode device record")?;
    device.validate()?;
    if device.fingerprint != expected {
        bail!("server device fingerprint mismatch");
    }
    println!(
        "Fingerprint: {}\nLabel: {}\nCredential: {}",
        device.fingerprint, device.label, device.credential_id
    );
    print!("Type the full fingerprint to confirm: ");
    io::stdout().flush()?;
    let mut confirmation = String::new();
    io::stdin().lock().read_line(&mut confirmation)?;
    if confirmation.trim() != device.fingerprint {
        bail!("fingerprint confirmation mismatch");
    }
    let mut registry = load_registry()?;
    registry
        .devices
        .retain(|stored| stored.fingerprint != device.fingerprint);
    registry.devices.push(device);
    registry.validate()?;
    write_registry(&registry)?;
    println!("Device pinned: {expected}");
    Ok(())
}

fn cmd_status() -> Result<()> {
    let registry = load_registry()?;
    println!("Enrolled devices ({}):", registry.devices.len());
    for device in registry.devices {
        let kind = match device.kind {
            DeviceKindV1::Webauthn => "webauthn",
            DeviceKindV1::SecureEnclave => "secure-enclave",
        };
        println!(
            "  {}  {}  kind={kind}  active={}",
            device.fingerprint, device.label, device.active
        );
    }
    Ok(())
}

async fn cmd_test() -> Result<()> {
    execute_request(build_synthetic_request(), APPROVAL_TIMEOUT).await
}

async fn cmd_watch() -> Result<()> {
    let config = load_hook_config()?;
    let nats = connect_nats().await?;
    let mut subscription = nats.subscribe("oshioki.request.>").await?;
    while let Some(message) = subscription.next().await {
        let envelope: RequestEnvelopeV1 = match serde_json::from_slice(&message.payload) {
            Ok(value) => value,
            Err(error) => {
                warn!(%error, "ignoring malformed request");
                continue;
            }
        };
        envelope.validate()?;
        let url = approval_url(&config.server_base_url, &envelope.request_id);
        let opener = std::env::var("OSHIOKI_OPENER").unwrap_or_else(|_| "/usr/bin/open".into());
        let status = opener_command(&opener, &url)
            .status()
            .context("launch approval URL")?;
        if !status.success() {
            warn!(%status, "approval URL opener failed");
        }
    }
    bail!("request subscription closed")
}

fn opener_command(opener: &str, url: &str) -> Command {
    let mut command = Command::new(opener);
    command.arg(url);
    command
}

fn build_request(values: &HashMap<String, String>) -> Result<RequestV1> {
    let issued_at = now();
    let mut nonce = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let command = values
        .get("info.command")
        .cloned()
        .context("missing info.command")?;
    let argv = values
        .keys()
        .filter_map(|key| key.strip_prefix("argv.")?.parse::<u32>().ok())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .filter_map(|index| values.get(&format!("argv.{index}")).cloned())
        .collect();
    let request = RequestV1 {
        version: VERSION_V1,
        request_id: Uuid::new_v4().to_string(),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        host: hostname(),
        user: values
            .get("info.user")
            .cloned()
            .unwrap_or_else(|| "unknown".into()),
        uid: values
            .get("info.uid")
            .and_then(|value| value.parse().ok())
            .unwrap_or(u32::MAX),
        runas_uid: values
            .get("info.runas_uid")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        cwd: values
            .get("info.cwd")
            .cloned()
            .unwrap_or_else(|| "/".into()),
        tty: values
            .get("info.tty")
            .cloned()
            .filter(|value| !value.is_empty()),
        command,
        argv,
        pid_chain: pid_chain(),
        issued_at,
        expires_at: issued_at + 90,
    };
    request.validate()?;
    Ok(request)
}

fn build_synthetic_request() -> RequestV1 {
    let issued_at = now();
    let mut nonce = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    RequestV1 {
        version: VERSION_V1,
        request_id: Uuid::new_v4().to_string(),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        host: hostname(),
        user: std::env::var("USER").unwrap_or_else(|_| "unknown".into()),
        uid: nix::unistd::getuid().as_raw(),
        runas_uid: 0,
        cwd: std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .display()
            .to_string(),
        tty: std::env::var("SSH_TTY").ok(),
        command: "/usr/bin/true".into(),
        argv: vec!["/usr/bin/true".into()],
        pid_chain: pid_chain(),
        issued_at,
        expires_at: issued_at + 90,
    }
}

fn seal_request(
    request: &RequestV1,
    raw: &[u8],
    devices: &[DevicePublicRecordV1],
) -> Result<RequestEnvelopeV1> {
    if devices.len() > oshioki_protocol::v1::MAX_DEVICES {
        bail!("more than eight active devices");
    }
    let envelope = RequestEnvelopeV1 {
        version: VERSION_V1,
        request_id: request.request_id.clone(),
        host: request.host.clone(),
        user: request.user.clone(),
        issued_at: request.issued_at,
        expires_at: request.expires_at,
        sealed: devices
            .iter()
            .map(|device| oshioki_protocol::seal_v1(raw, device))
            .collect::<Result<Vec<_>, _>>()?,
    };
    envelope.validate()?;
    Ok(envelope)
}

fn parse_sudo_stdin() -> Result<HashMap<String, String>> {
    let mut values = HashMap::new();
    for line in io::stdin().lock().lines() {
        let line = line?;
        if let Some((key, value)) = line.split_once('=') {
            values.insert(key.to_owned(), value.to_owned());
        }
    }
    if values.is_empty() {
        bail!("stdin empty; expected sudo plugin payload");
    }
    Ok(values)
}

fn config_dir() -> PathBuf {
    std::env::var_os("OSHIOKI_CONFIG_DIR")
        .map_or_else(|| PathBuf::from(DEFAULT_CONFIG_DIR), PathBuf::from)
}
fn check_config_dir() -> &'static Path {
    Path::new(DEFAULT_CONFIG_DIR)
}
fn load_hook_config() -> Result<HookConfigV1> {
    load_hook_config_from(&config_dir())
}
fn load_hook_config_from(directory: &Path) -> Result<HookConfigV1> {
    let config: HookConfigV1 = read_json(&directory.join("hook.json"))?;
    config.validate()?;
    Ok(config)
}
fn load_registry() -> Result<DeviceRegistryV1> {
    load_registry_from(&config_dir())
}
fn load_registry_from(directory: &Path) -> Result<DeviceRegistryV1> {
    let path = directory.join("devices.json");
    if !path.exists() {
        return Ok(DeviceRegistryV1 {
            version: VERSION_V1,
            devices: Vec::new(),
        });
    }
    let registry: DeviceRegistryV1 = read_json(&path)?;
    registry.validate()?;
    Ok(registry)
}
fn write_registry(registry: &DeviceRegistryV1) -> Result<()> {
    write_registry_to(&config_dir(), registry)
}
fn write_registry_to(directory: &Path, registry: &DeviceRegistryV1) -> Result<()> {
    registry.validate()?;
    atomic_write_json(&directory.join("devices.json"), registry, 0o600)
}

fn create_enrollment_state() -> Result<EnrollmentStateV1> {
    let mut secret = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    let state = EnrollmentStateV1 {
        version: VERSION_V1,
        enrollment_id: Uuid::new_v4().to_string(),
        secret: URL_SAFE_NO_PAD.encode(secret),
        expires_at: now() + 300,
    };
    atomic_write_json(&enrollment_path(&state.enrollment_id)?, &state, 0o600)?;
    Ok(state)
}
fn load_enrollment_state(id: &str) -> Result<EnrollmentStateV1> {
    let state: EnrollmentStateV1 = read_json(&enrollment_path(id)?)?;
    if state.version != VERSION_V1 || state.enrollment_id != id {
        bail!("invalid enrollment state");
    }
    Ok(state)
}
fn enrollment_path(id: &str) -> Result<PathBuf> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        bail!("invalid enrollment id");
    }
    Ok(config_dir().join("enrollments").join(format!("{id}.json")))
}

fn remove_enrollment_state(path: &Path) {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => {
            warn!(path=%path.display(), %error, "failed to remove enrollment state");
        }
        _ => {}
    }
}

fn prune_expired_enrollment_states(current_id: &str) {
    let directory = config_dir().join("enrollments");
    let Ok(entries) = fs::read_dir(&directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(state) = read_json::<EnrollmentStateV1>(&path) else {
            continue;
        };
        if state.enrollment_id != current_id && state.expires_at <= now() {
            remove_enrollment_state(&path);
        }
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}
fn atomic_write_json<T: Serialize>(path: &Path, value: &T, mode: u32) -> Result<()> {
    let parent = path.parent().context("state file has no parent")?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .context("invalid state filename")?,
        Uuid::new_v4()
    ));
    let result = (|| -> Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true).mode(mode);
        let mut file = options.open(&temporary)?;
        serde_json::to_writer_pretty(&mut file, value)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

async fn connect_nats() -> Result<async_nats::Client> {
    connect_nats_from(&config_dir()).await
}
async fn connect_nats_from(directory: &Path) -> Result<async_nats::Client> {
    let env = read_env_file(&directory.join("config.env"))?;
    async_nats::ConnectOptions::new()
        .user_and_password(
            env.get("NATS_USER").context("NATS_USER not set")?.clone(),
            env.get("NATS_PASS").context("NATS_PASS not set")?.clone(),
        )
        .connect(env.get("NATS_URL").context("NATS_URL not set")?)
        .await
        .context("connect to NATS")
}
fn read_env_file(path: &Path) -> Result<HashMap<String, String>> {
    let content = fs::read_to_string(path)?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect())
}

async fn http_get(url: &str) -> Result<Vec<u8>> {
    let output = tokio::process::Command::new("/usr/bin/curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "15",
            url,
        ])
        .output()
        .await?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        bail!("device lookup failed: {}", detail.trim());
    }
    if output.stdout.len() > 256 * 1024 {
        bail!("device response too large");
    }
    Ok(output.stdout)
}
fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}
fn hostname() -> String {
    Command::new("/usr/bin/uname")
        .arg("-n")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "localhost".into())
}

fn pid_chain() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        pid_chain_linux()
    }
    #[cfg(target_os = "macos")]
    {
        pid_chain_darwin()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Vec::new()
    }
}
#[cfg(target_os = "linux")]
fn pid_chain_linux() -> Vec<String> {
    let mut chain = Vec::new();
    let mut pid = std::process::id();
    for _ in 0..5 {
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
            break;
        };
        let (Some(open), Some(close)) = (stat.find('('), stat.rfind(')')) else {
            break;
        };
        let fields = stat[close + 1..].split_whitespace().collect::<Vec<_>>();
        chain.push(format!("{pid}:{}", &stat[open + 1..close]));
        let Some(parent) = fields.get(1).and_then(|value| value.parse::<u32>().ok()) else {
            break;
        };
        if parent <= 1 {
            break;
        }
        pid = parent;
    }
    chain
}
#[cfg(target_os = "macos")]
fn pid_chain_darwin() -> Vec<String> {
    let mut chain = Vec::new();
    let mut pid = std::process::id();
    for _ in 0..5 {
        let Ok(output) = Command::new("/bin/ps")
            .args(["-o", "ppid=,comm=", "-p", &pid.to_string()])
            .output()
        else {
            break;
        };
        if !output.status.success() {
            break;
        }
        let value = String::from_utf8_lossy(&output.stdout);
        let mut fields = value.split_whitespace();
        let Some(parent) = fields.next().and_then(|value| value.parse::<u32>().ok()) else {
            break;
        };
        let Some(command) = fields.next() else { break };
        chain.push(format!("{pid}:{command}"));
        if parent <= 1 {
            break;
        }
        pid = parent;
    }
    chain
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use std::collections::BTreeMap;
    #[test]
    fn fingerprint_arguments_may_start_with_a_hyphen() {
        for verb in ["revoke", "pin"] {
            let cli = Cli::try_parse_from(["oshioki", verb, "-8lGYGvNFgwWqSSFS3yv1Q"]).unwrap();
            let (Verb::Revoke { fingerprint } | Verb::Pin { fingerprint }) = cli.verb else {
                panic!("unexpected verb")
            };
            assert_eq!(fingerprint, "-8lGYGvNFgwWqSSFS3yv1Q");
        }
        let cli = Cli::try_parse_from(["oshioki", "enroll", "--resume", "-abc"]).unwrap();
        assert!(matches!(cli.verb, Verb::Enroll { resume: Some(ref r) } if r == "-abc"));
    }
    #[test]
    fn request_bytes_are_retained_in_every_sealed_body() {
        let request = build_synthetic_request();
        let raw = request.raw_json().unwrap();
        let credential = vec![1; 8];
        let signing = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
        let point = signing.verifying_key().to_encoded_point(false);
        let mut cose = BTreeMap::new();
        cose.insert(serde_cbor::Value::Integer(1), serde_cbor::Value::Integer(2));
        cose.insert(
            serde_cbor::Value::Integer(3),
            serde_cbor::Value::Integer(-7),
        );
        cose.insert(
            serde_cbor::Value::Integer(-1),
            serde_cbor::Value::Integer(1),
        );
        cose.insert(
            serde_cbor::Value::Integer(-2),
            serde_cbor::Value::Bytes(point.x().unwrap().to_vec()),
        );
        cose.insert(
            serde_cbor::Value::Integer(-3),
            serde_cbor::Value::Bytes(point.y().unwrap().to_vec()),
        );
        let public = serde_cbor::to_vec(&serde_cbor::Value::Map(cose)).unwrap();
        let secret = x25519_dalek::StaticSecret::from([4; 32]);
        let box_public = x25519_dalek::PublicKey::from(&secret);
        let fingerprint =
            oshioki_protocol::device_fingerprint(&credential, &public, box_public.as_bytes());
        let device = DevicePublicRecordV1 {
            version: 1,
            kind: DeviceKindV1::Webauthn,
            fingerprint,
            credential_id: URL_SAFE_NO_PAD.encode(&credential),
            credential_public_key: URL_SAFE_NO_PAD.encode(&public),
            box_public_key: URL_SAFE_NO_PAD.encode(box_public.as_bytes()),
            label: "test".into(),
            api_token_hash: URL_SAFE_NO_PAD.encode([3; 32]),
            sign_count: 0,
            active: true,
        };
        let envelope = seal_request(&request, &raw, &[device]).unwrap();
        assert_eq!(envelope.request_id, request.request_id);
        assert_eq!(envelope.sealed.len(), 1);
    }
    #[test]
    fn approval_url_uses_the_configured_origin_and_request_id() {
        assert_eq!(
            approval_url(
                "https://host.example.ts.net:8443",
                "67767d61-bcea-4e2d-8f28-32270c34eb6d"
            ),
            "https://host.example.ts.net:8443/r/67767d61-bcea-4e2d-8f28-32270c34eb6d"
        );
    }
    #[test]
    fn atomic_registry_round_trip() {
        let root = std::env::temp_dir().join(format!("oshioki-hook-test-{}", Uuid::new_v4()));
        let path = root.join("devices.json");
        let registry = DeviceRegistryV1 {
            version: 1,
            devices: Vec::new(),
        };
        atomic_write_json(&path, &registry, 0o600).unwrap();
        assert_eq!(read_json::<DeviceRegistryV1>(&path).unwrap(), registry);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn check_uses_the_root_owned_config_directory() {
        assert_eq!(check_config_dir(), Path::new("/etc/oshioki"));
    }

    #[test]
    fn opener_keeps_the_url_in_one_argument() {
        let command = opener_command("/usr/bin/open", "https://sudo.example/r/id?value=a b;false");
        assert_eq!(command.get_program(), "/usr/bin/open");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["https://sudo.example/r/id?value=a b;false"]
        );
    }
}
