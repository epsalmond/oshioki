//! `management-plane-sudo-approve` — the hook sudo runs.
//!
//! Verbs: check, enroll, pin, status, test, watch.
//!
//! When the sudo approval plugin (`approval_exec`) accepts a command it forks
//! this binary with `check`. stdin carries `command_info`, `run_argv`, and
//! `user_info` as newline-separated `key=value` pairs (the sudo plugin
//! format). We build a `protocol::Request`, seal it per enrolled device,
//! publish to NATS, and wait up to 90 s for a signed verdict.
//!
//! Every failure path exits 1 (fail closed).

// This binary runs as root via sudo's approval plugin. Lints are inherited
// from the workspace. `nix::unistd::getuid` provides the only uid lookup
// without unsafe blocks.

use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use futures::StreamExt as _;

use anyhow::{Context, Result, bail};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use clap::{Parser, Subcommand};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use uuid::Uuid;

use protocol::{Request, Verdict};

// ---------------------------------------------------------------------------
// Config paths
// ---------------------------------------------------------------------------

/// Directory that holds all hook configuration.
const CONFIG_DIR: &str = "/etc/management-plane/sudo-approve";
/// NATS credentials file (`NATS_URL=`, `NATS_USER=`, `NATS_PASS=`).
const NATS_ENV: &str = "/etc/management-plane/sudo-approve/config.env";
/// Enrolled devices.
const DEVICES_JSON: &str = "/etc/management-plane/sudo-approve/devices.json";

// ---------------------------------------------------------------------------
// Types local to the hook (serialisation formats shared with the server)
// ---------------------------------------------------------------------------

/// A device enrolled for sudo approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    /// X25519 public key for sealed-box encryption (raw bytes, hex-encoded).
    pub box_pub: String,
    /// P-256 COSE public key from `WebAuthn` (base64-encoded).
    pub credential_pub: String,
    /// `WebAuthn` credential ID (base64-encoded).
    pub credential_id: String,
}

/// Payload published to `sudo.request.<host>` — cleartext header + sealed
/// bodies, one per device.
#[derive(Debug, Serialize)]
struct SealedEnvelope {
    /// Cleartext routing header.
    header: Header,
    /// Sealed body, one per enrolled device.
    sealed: Vec<SealedBody>,
}

#[derive(Debug, Serialize)]
struct Header {
    id: String,
    host: String,
    user: String,
    ts: i64,
}

#[derive(Debug, Serialize)]
struct SealedBody {
    /// Ephemeral X25519 public key (raw, hex).
    ephemeral_pub: String,
    /// ChaCha20-Poly1305 nonce (12 bytes, hex).
    nonce: String,
    /// Ciphertext (hex).
    ciphertext: String,
    /// Which device this body is sealed to (fingerprint = `box_pub` hex prefix).
    device_fingerprint: String,
}

/// Device record received from the enrollment relay.
#[derive(Debug, Deserialize)]
struct EnrollDeviceRecord {
    box_pub: String,
    credential_pub: String,
    credential_id: String,
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// The sudo approval hook.
#[derive(Parser)]
#[command(name = "management-plane-sudo-approve", about = "sudo approval hook")]
struct Cli {
    #[command(subcommand)]
    verb: Verb,
}

#[derive(Subcommand)]
enum Verb {
    /// Check a pending sudo command (invoked by the approval plugin).
    Check,
    /// Enroll a new device by printing a one-time URL.
    Enroll,
    /// Pin a device on a second host after fingerprint confirmation.
    Pin { fingerprint: String },
    /// List enrolled devices.
    Status,
    /// Dry-run: show what the approval page would display.
    Test,
    /// Watch for incoming requests (used by macOS `LaunchAgent`).
    Watch,
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("management_plane_sudo_approve=info".parse().unwrap()),
        )
        .with_writer(io::stdout)
        .init();

    let cli = Cli::parse();

    let code = match cli.verb {
        Verb::Check => cmd_check().await,
        Verb::Enroll => cmd_enroll().await,
        Verb::Pin { fingerprint } => cmd_pin(&fingerprint).await,
        Verb::Status => cmd_status(),
        Verb::Test => cmd_test(),
        Verb::Watch => cmd_watch().await,
    };

    match code {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// check — the critical path
// ---------------------------------------------------------------------------

async fn cmd_check() -> Result<()> {
    let kv = parse_sudo_stdin()?;
    debug!(?kv, "parsed sudo stdin");

    let request = build_request(&kv)?;
    info!(id = %request.id, host = %request.host, user = %request.user, "request built");

    let nats = connect_nats().await?;
    let devices = load_devices()?;

    if devices.is_empty() {
        bail!("no devices enrolled — denying");
    }

    // Seal per device and publish.
    let envelope = seal_request(&request, &devices)?;
    let payload = serde_json::to_vec(&envelope).context("serialize envelope")?;
    let request_subject = format!("sudo.request.{}", request.host);
    let verdict_subject = format!("sudo.verdict.{}", request.id);
    let verdict = request_verdict(
        &nats,
        &request_subject,
        &verdict_subject,
        payload,
        tokio::time::Duration::from_secs(90),
    )
    .await?;

    // protocol::verify is implemented in parallel; if not yet present, the
    // hook fails closed. We verify against each enrolled device — the first
    // valid signature wins.
    let devices = load_devices()?;
    let mut verified = false;

    for dev in &devices {
        let credential_pub = base64::engine::general_purpose::STANDARD
            .decode(&dev.credential_pub)
            .context("decode credential_pub base64")?;

        match protocol::verify::verify(&verdict, &request, &credential_pub) {
            Ok(()) => {
                info!(id = %request.id, "verdict valid — approve");
                verified = true;
                break;
            }
            Err(e) => {
                debug!(id = %request.id, "device {} verify failed: {e}",
                    fingerprint(&dev.box_pub));
            }
        }
    }

    if !verified {
        bail!("verdict verification failed for all devices");
    }

    info!(id = %request.id, "check approved");
    Ok(())
}

async fn request_verdict(
    nats: &async_nats::Client,
    request_subject: &str,
    verdict_subject: &str,
    payload: Vec<u8>,
    timeout: tokio::time::Duration,
) -> Result<Verdict> {
    let mut deadline_stage = "subscribing to verdict";
    let result = tokio::time::timeout(timeout, async {
        let mut sub = nats
            .subscribe(verdict_subject.to_string())
            .await
            .context("subscribe verdict")?;
        deadline_stage = "confirming verdict subscription readiness";
        nats.flush()
            .await
            .context("confirm verdict subscription readiness")?;

        deadline_stage = "publishing approval request";
        nats.publish(request_subject.to_string(), payload.into())
            .await
            .context("publish request")?;
        info!(subject = request_subject, "published request");

        deadline_stage = "waiting for verdict";
        let msg = sub.next().await.context("verdict stream closed")?;
        let verdict: Verdict =
            serde_json::from_slice(&msg.payload).context("deserialize verdict")?;
        Ok(verdict)
    })
    .await;

    result.with_context(|| {
        format!(
            "sudo verdict deadline exceeded after {}ms while {deadline_stage}",
            timeout.as_millis(),
        )
    })?
}

// ---------------------------------------------------------------------------
// enroll
// ---------------------------------------------------------------------------

async fn cmd_enroll() -> Result<()> {
    let token = generate_token();
    let url = format!("https://sudo.internal.psalmond.com/enroll/{token}");
    println!("Enrollment URL (one-time):");
    println!("  {url}");
    println!();
    println!("Waiting for device…");

    let nats = connect_nats().await?;
    let subject = format!("sudo.enroll.{token}");
    let mut sub = nats.subscribe(subject).await.context("subscribe enroll")?;

    let timeout = tokio::time::Duration::from_secs(300); // 5 min for the human
    let msg = tokio::time::timeout(timeout, sub.next())
        .await
        .context("enrollment timeout")?
        .context("enroll stream closed")?;

    let record: EnrollDeviceRecord =
        serde_json::from_slice(&msg.payload).context("deserialize device record")?;

    let device = DeviceRecord {
        box_pub: record.box_pub,
        credential_pub: record.credential_pub,
        credential_id: record.credential_id,
    };

    let fp = fingerprint(&device.box_pub);
    append_device(&device)?;

    println!("Device enrolled.");
    println!("  fingerprint: {fp}");
    println!(
        "  box_pub:     {}…",
        &device.box_pub[..16.min(device.box_pub.len())]
    );
    println!(
        "  cred_pub:    {}…",
        credential_pub_prefix(&device.credential_pub)
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// pin
// ---------------------------------------------------------------------------

async fn cmd_pin(expected_fp: &str) -> Result<()> {
    println!("Fetching device record from server…");

    let url = format!("https://sudo.internal.psalmond.com/enroll/{expected_fp}");
    let body = http_get(&url).await?;

    let record: EnrollDeviceRecord =
        serde_json::from_slice(&body).context("deserialize device record")?;

    let device = DeviceRecord {
        box_pub: record.box_pub,
        credential_pub: record.credential_pub,
        credential_id: record.credential_id,
    };

    let actual_fp = fingerprint(&device.box_pub);

    println!("Server returned fingerprint: {actual_fp}");
    println!("Expected:                  {expected_fp}");
    println!();
    print!("Type the fingerprint to confirm: ");
    io::stdout().flush()?;

    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    let typed = line.trim();

    if typed != actual_fp {
        bail!(
            "fingerprint mismatch — not pinning. Actual fingerprint returned by server: {actual_fp}"
        );
    }

    append_device(&device)?;
    println!("Device pinned: {actual_fp}");
    Ok(())
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

fn cmd_status() -> Result<()> {
    let devices = load_devices()?;
    println!("Enrolled devices ({}):", devices.len());
    for (i, d) in devices.iter().enumerate() {
        let fp = fingerprint(&d.box_pub);
        let bp = &d.box_pub[..16.min(d.box_pub.len())];
        let cp = credential_pub_prefix(&d.credential_pub);
        println!("  [{i}] fingerprint={fp}  box_pub={bp}…  cred_pub={cp}…");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// test
// ---------------------------------------------------------------------------

fn cmd_test() -> Result<()> {
    let request = build_dry_request();
    let devices = load_devices()?;

    if devices.is_empty() {
        bail!("no devices enrolled");
    }

    let envelope = seal_request(&request, &devices)?;

    println!("=== Approval page would show ===");
    println!("  id:       {}", request.id);
    println!("  host:     {}", request.host);
    println!("  user:     {}", request.user);
    println!("  uid:      {}", request.uid);
    println!("  runas_uid:{}", request.runas_uid);
    println!("  cwd:      {}", request.cwd);
    if let Some(ref t) = request.tty {
        println!("  tty:      {t}");
    }
    println!("  command:  {}", request.command);
    println!("  argv:     {:?}", request.argv);
    if !request.pid_chain.is_empty() {
        println!("  pid_chain:");
        for p in &request.pid_chain {
            println!("    - {p}");
        }
    }
    println!("  ts:       {}", request.ts);
    println!("  expiry:   {}", request.expiry);
    println!();
    println!("Sealed bodies: {} device(s)", envelope.sealed.len());
    for s in &envelope.sealed {
        println!(
            "  device={} ephemeral={}…  nonce={}…  ct_len={}",
            s.device_fingerprint,
            &s.ephemeral_pub[..16.min(s.ephemeral_pub.len())],
            s.nonce,
            s.ciphertext.len() / 2,
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// watch
// ---------------------------------------------------------------------------

async fn cmd_watch() -> Result<()> {
    let nats = connect_nats().await?;
    let mut sub = nats
        .subscribe("sudo.request.>")
        .await
        .context("subscribe requests")?;

    info!("watching for sudo requests…");

    while let Some(msg) = sub.next().await {
        match serde_json::from_slice::<serde_json::Value>(&msg.payload) {
            Ok(v) => println!("{}", serde_json::to_string_pretty(&v)?),
            Err(e) => warn!("bad request payload: {e}"),
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Parse sudo plugin stdin into a key-value map.
///
/// The format is newline-separated `key=value` pairs covering
/// `command_info`, `run_argv`, and `user_info` sections.
fn parse_sudo_stdin() -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    let stdin = io::stdin();
    let lock = stdin.lock();

    for line in lock.lines() {
        let line = line.context("read stdin line")?;
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }

    if map.is_empty() {
        bail!("stdin empty — expected sudo plugin format");
    }
    Ok(map)
}

/// Build a `protocol::Request` from parsed sudo stdin.
fn build_request(kv: &HashMap<String, String>) -> Result<Request> {
    let now = now_unix();

    let id = Uuid::new_v4().to_string();
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);

    let host = hostname();
    // Lookup with the info. prefix — sudo ships command_info env vars with
    // bare names but the plugin payload prefixes them with `info.`.
    let user = kv
        .get("info.user")
        .cloned()
        .unwrap_or_else(|| "unknown".into());
    let uid: u32 = kv
        .get("info.uid")
        .and_then(|v| v.parse().ok())
        .unwrap_or(u32::MAX);
    let runas_uid: u32 = kv
        .get("info.runas_uid")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let command = kv
        .get("info.command")
        .cloned()
        .context("missing `info.command` in stdin")?;
    let cwd = kv.get("info.cwd").cloned().unwrap_or_else(|| "/".into());
    let tty = kv.get("info.tty").cloned().filter(|s| !s.is_empty());

    // Positional argv encoding: argv.1=arg1 argv.2=arg2 ...
    // Cannot collide with kv pairs — a dedicated namespace.
    let argv = kv
        .keys()
        .filter_map(|k| k.strip_prefix("argv."))
        .filter_map(|idx| idx.parse::<u32>().ok())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|idx| kv.get(&format!("argv.{idx}")).cloned().unwrap())
        .collect();

    let pid_chain = pid_chain();

    Ok(Request {
        id,
        nonce,
        host,
        user,
        uid,
        runas_uid,
        cwd,
        tty,
        command,
        argv,
        pid_chain,
        ts: now,
        expiry: now + 90,
    })
}

/// Build a synthetic dry request for `test`.
fn build_dry_request() -> Request {
    let now = now_unix();
    let host = hostname();
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);

    Request {
        id: Uuid::new_v4().to_string(),
        nonce,
        host,
        user: whoami(),
        uid: current_uid(),
        runas_uid: 0,
        cwd: std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .display()
            .to_string(),
        tty: std::env::var("SSH_TTY").ok().or(std::env::var("TTY").ok()),
        command: "/usr/bin/true".into(),
        argv: vec!["/usr/bin/true".into()],
        pid_chain: pid_chain(),
        ts: now,
        expiry: now + 90,
    }
}

/// Encrypt the request for every enrolled device (sealed boxes).
fn seal_request(request: &Request, devices: &[DeviceRecord]) -> Result<SealedEnvelope> {
    let body_json = serde_json::to_vec(request).context("serialize request")?;
    let mut sealed = Vec::with_capacity(devices.len());

    for dev in devices {
        sealed.push(seal_one(&body_json, dev)?);
    }

    Ok(SealedEnvelope {
        header: Header {
            id: request.id.clone(),
            host: request.host.clone(),
            user: request.user.clone(),
            ts: request.ts,
        },
        sealed,
    })
}

/// Encrypt for a single device.
fn seal_one(plaintext: &[u8], dev: &DeviceRecord) -> Result<SealedBody> {
    let peer_pub_raw = hex::decode(&dev.box_pub).context("decode device box_pub hex")?;
    let peer_pub: [u8; 32] = peer_pub_raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("box_pub wrong length"))?;

    let ephemeral_secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
    let ephemeral_pub = x25519_dalek::PublicKey::from(&ephemeral_secret);

    let shared = ephemeral_secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer_pub));

    let cipher = ChaCha20Poly1305::new(shared.as_bytes().into());
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = ChaChaNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("chacha20poly1305 encrypt: {e}"))?;

    Ok(SealedBody {
        ephemeral_pub: hex::encode(ephemeral_pub.as_bytes()),
        nonce: hex::encode(&nonce_bytes),
        ciphertext: hex::encode(&ciphertext),
        device_fingerprint: fingerprint(&dev.box_pub),
    })
}

/// Connect to NATS from the env file.
async fn connect_nats() -> Result<async_nats::Client> {
    let env = read_env_file(NATS_ENV)?;

    let url = env.get("NATS_URL").context("NATS_URL not set")?;
    let user = env.get("NATS_USER").context("NATS_USER not set")?;
    let pass = env.get("NATS_PASS").context("NATS_PASS not set")?;

    let client = async_nats::ConnectOptions::new()
        .user_and_password(user.clone(), pass.clone())
        .connect(url)
        .await
        .context("connect to NATS")?;

    Ok(client)
}

/// Load enrolled devices from disk.
fn load_devices() -> Result<Vec<DeviceRecord>> {
    let path = Path::new(DEVICES_JSON);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read_to_string(path).context("read devices.json")?;
    let devices: Vec<DeviceRecord> = serde_json::from_str(&data).context("parse devices.json")?;
    Ok(devices)
}

/// Append a device to the devices file (create dir + file if needed).
fn append_device(device: &DeviceRecord) -> Result<()> {
    let dir = Path::new(CONFIG_DIR);
    fs::create_dir_all(dir).context("create config dir")?;

    // Set permissions on the directory itself.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o750)).context("chmod config dir")?;
    }

    let mut devices = load_devices()?;
    devices.push(device.clone());
    let json = serde_json::to_string_pretty(&devices).context("serialize devices")?;
    fs::write(DEVICES_JSON, json).context("write devices.json")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(DEVICES_JSON, fs::Permissions::from_mode(0o600))
            .context("chmod devices.json")?;
    }

    Ok(())
}

/// Fingerprint: first 8 bytes of the hex-encoded `box_pub`.
fn fingerprint(box_pub: &str) -> String {
    if box_pub.len() >= 16 {
        box_pub[..16].to_string()
    } else {
        box_pub.to_string()
    }
}

/// Truncate a base64 credential pub for display.
fn credential_pub_prefix(cred: &str) -> &str {
    &cred[..12.min(cred.len())]
}

/// 64-hex random enrollment token.
fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(&bytes)
}

/// HTTP GET via `reqwest`-style blocking inside tokio. For v1 we shell out to
/// `curl` to avoid adding a TLS dependency to the hook. The tailnet + stepca
/// is the trust root.
async fn http_get(url: &str) -> Result<Vec<u8>> {
    // Use absolute paths — root's PATH is attacker-influenceable if we
    // shell out improperly.
    let output = tokio::process::Command::new("/usr/local/bin/curl")
        .arg("-sf")
        .arg("--max-time")
        .arg("15")
        .arg("--cacert")
        .arg("/etc/ssl/certs/")
        .arg("--capath")
        .arg("/etc/ssl/certs/")
        .arg(url)
        .output()
        .await
        .context("curl fetch device record")?;

    if !output.status.success() {
        bail!("HTTP GET {url} failed: {}", output.status);
    }
    Ok(output.stdout)
}

/// Current Unix timestamp.
fn now_unix() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock skew")
            .as_secs(),
    )
    .expect("Unix timestamp fits i64")
}

/// Hostname.
fn hostname() -> String {
    // Use the POSIX uname command if hostname is not available. This
    // eliminates the subprocess risk of spawning arbitrary "hostname"
    // binaries found on PATH.
    match std::process::Command::new("/usr/bin/uname")
        .arg("-n")
        .output()
    {
        Ok(output) => {
            if output.status.success() {
                String::from_utf8_lossy(&output.stdout).trim().to_string()
            } else {
                "localhost".into()
            }
        }
        Err(e) => {
            tracing::debug!(error = %e, "uname -n failed, using localhost");
            "localhost".into()
        }
    }
}

/// Current uid (Linux / macOS). Safe wrapper via `nix`.
fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        nix::unistd::getuid().as_raw()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Current username.
fn whoami() -> String {
    std::env::var("USER").unwrap_or_else(|_| "unknown".into())
}

/// Walk /proc up to 5 ancestors (Linux) or `ps -o ppid=,comm=` on Darwin.
///
/// Returns entries as `pid:comm`, nearest first, capped at 5.
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
    let mut current_pid = std::process::id();

    for _ in 0..5 {
        let stat_path = format!("/proc/{current_pid}/stat");
        let Ok(stat) = fs::read_to_string(&stat_path) else {
            break;
        };
        let Some(comm) = extract_proc_comm(&stat) else {
            break;
        };
        chain.push(format!("{current_pid}:{comm}"));

        match extract_proc_ppid(&stat) {
            Some(parent_pid) if parent_pid > 1 => current_pid = parent_pid,
            _ => break,
        }
    }

    chain
}

/// Extract `comm` from `/proc/[pid]/stat` — the field between the last `)`
/// and the end.
#[cfg(target_os = "linux")]
fn extract_proc_comm(stat: &str) -> Option<String> {
    // comm is the field between the first `(` and the last `)`.
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let comm = &stat[open + 1..close];
    Some(comm.to_string())
}

/// Extract `ppid` from `/proc/[pid]/stat`.
#[cfg(target_os = "linux")]
fn extract_proc_ppid(stat: &str) -> Option<u32> {
    let close = stat.rfind(')')?;
    let rest = &stat[close + 1..];
    let parts: Vec<&str> = rest.split_whitespace().collect();
    // Field 3 is state, field 4 is ppid (1-indexed from the full field list).
    parts.get(2)?.parse::<u32>().ok()
}

#[cfg(target_os = "macos")]
fn pid_chain_darwin() -> Vec<String> {
    let mut chain = Vec::new();
    let mut pid = std::process::id().to_string();

    for _ in 0..5 {
        let output = match std::process::Command::new("ps")
            .arg("-o")
            .arg("ppid=,comm=")
            .arg("-p")
            .arg(&pid)
            .output()
        {
            Ok(o) => o,
            Err(_) => break,
        };

        if !output.status.success() {
            break;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let line = stdout.trim();
        if line.is_empty() {
            break;
        }

        // Parse "  ppid command" from ps output.
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            break;
        }

        let ppid: u32 = match parts[0].parse() {
            Ok(v) => v,
            Err(_) => break,
        };
        let comm = parts[1];

        chain.push(format!("{pid}:{comm}"));

        if ppid <= 1 {
            break;
        }
        pid = ppid.to_string();
    }

    chain
}

/// Read a `KEY=value` env file into a map.
fn read_env_file(path: &str) -> Result<HashMap<String, String>> {
    let content = fs::read_to_string(path).with_context(|| format!("read {path}"))?;
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    Ok(map)
}

// ---------------------------------------------------------------------------
// hex (tiny inline hex module to avoid adding the `hex` crate)
// ---------------------------------------------------------------------------

mod hex {
    use std::fmt::Write;

    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    pub fn decode(hex: &str) -> Result<Vec<u8>, HexError> {
        if hex.len() % 2 != 0 {
            return Err(HexError::OddLength);
        }
        let mut out = Vec::with_capacity(hex.len() / 2);
        for chunk in hex.as_bytes().chunks(2) {
            let hi = val(chunk[0])?;
            let lo = val(chunk[1])?;
            out.push(hi << 4 | lo);
        }
        Ok(out)
    }

    fn val(c: u8) -> Result<u8, HexError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(HexError::InvalidChar),
        }
    }

    #[derive(Debug)]
    pub enum HexError {
        OddLength,
        InvalidChar,
    }

    impl std::fmt::Display for HexError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::OddLength => write!(f, "odd-length hex string"),
                Self::InvalidChar => write!(f, "invalid hex character"),
            }
        }
    }

    impl std::error::Error for HexError {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeMap;
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;

    fn signed_verdict(request: &Request) -> (Verdict, Vec<u8>) {
        let signing_key = SigningKey::from_bytes((&[1_u8; 32]).into()).unwrap();
        let canonical_json = serde_json::to_string(request).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(canonical_json.as_bytes());
        hasher.update(b"approve");
        let challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://sudo.internal.psalmond.com"}}"#
        );

        let mut hasher = Sha256::new();
        hasher.update(b"sudo.internal.psalmond.com");
        let mut authenticator_data = hasher.finalize().to_vec();
        authenticator_data.push(0b101);
        authenticator_data.extend_from_slice(&[0, 0, 0, 1]);

        let mut hasher = Sha256::new();
        hasher.update(client_data_json.as_bytes());
        let mut signed_message = authenticator_data.clone();
        signed_message.extend_from_slice(&hasher.finalize());
        let signature: Signature = signing_key.sign(&signed_message);

        let public_key = signing_key.verifying_key().to_encoded_point(false);
        let mut cose = BTreeMap::new();
        cose.insert(
            serde_cbor::Value::Integer(-2),
            serde_cbor::Value::Bytes(public_key.x().unwrap().to_vec()),
        );
        cose.insert(
            serde_cbor::Value::Integer(-3),
            serde_cbor::Value::Bytes(public_key.y().unwrap().to_vec()),
        );

        (
            Verdict {
                id: request.id.clone(),
                credential_id: vec![1, 2, 3],
                authenticator_data,
                client_data_json,
                signature: signature.to_der().as_bytes().to_vec(),
            },
            serde_cbor::to_vec(&serde_cbor::Value::Map(cose)).unwrap(),
        )
    }

    async fn run_readiness_broker(
        listener: TcpListener,
        request_subject: &str,
        verdict_subject: &str,
        verdict_payload: &[u8],
    ) -> std::io::Result<()> {
        let (stream, _) = listener.accept().await?;
        let (reader, mut writer) = TcpStream::into_split(stream);
        let mut reader = BufReader::new(reader);
        writer
            .write_all(
                b"INFO {\"server_id\":\"test\",\"version\":\"2.10.0\",\"proto\":1,\"host\":\"127.0.0.1\",\"port\":4222,\"max_payload\":1048576}\r\n",
            )
            .await?;

        let mut verdict_sid = None;
        let mut subscription_ready = false;
        let mut line = String::new();

        loop {
            line.clear();
            if reader.read_line(&mut line).await? == 0 {
                return Ok(());
            }

            let fields = line.split_whitespace().collect::<Vec<_>>();
            match fields.as_slice() {
                ["PING"] => {
                    writer.write_all(b"PONG\r\n").await?;
                }
                ["SUB", subject, sid] if *subject == verdict_subject => {
                    verdict_sid = Some((*sid).to_string());
                    subscription_ready = true;
                }
                ["PUB", subject, size] => {
                    let size = size.parse::<usize>().map_err(std::io::Error::other)?;
                    let mut payload_and_terminator = vec![0; size + 2];
                    reader.read_exact(&mut payload_and_terminator).await?;

                    if *subject == request_subject && subscription_ready {
                        let sid = verdict_sid
                            .as_deref()
                            .expect("ready subscription has a sid");
                        writer
                            .write_all(
                                format!(
                                    "MSG {verdict_subject} {sid} {}\r\n",
                                    verdict_payload.len()
                                )
                                .as_bytes(),
                            )
                            .await?;
                        writer.write_all(verdict_payload).await?;
                        writer.write_all(b"\r\n").await?;
                        return Ok(());
                    }
                }
                _ => {}
            }
        }
    }

    async fn run_stalled_reconnect_broker(
        listener: TcpListener,
        subscription_accepted: oneshot::Sender<()>,
        reconnect_ping_stalled: oneshot::Sender<()>,
    ) -> std::io::Result<()> {
        let (stream, _) = listener.accept().await?;
        let (reader, mut writer) = TcpStream::into_split(stream);
        let mut reader = BufReader::new(reader);
        writer
            .write_all(
                b"INFO {\"server_id\":\"test\",\"version\":\"2.10.0\",\"proto\":1,\"host\":\"127.0.0.1\",\"port\":4222,\"max_payload\":1048576}\r\n",
            )
            .await?;

        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).await? == 0 {
                return Ok(());
            }
            match line.split_whitespace().next() {
                Some("PING") => writer.write_all(b"PONG\r\n").await?,
                Some("SUB") => {
                    let _ = subscription_accepted.send(());
                    break;
                }
                _ => {}
            }
        }

        loop {
            line.clear();
            if reader.read_line(&mut line).await? == 0 {
                break;
            }
        }

        let (stream, _) = listener.accept().await?;
        let (reader, mut writer) = TcpStream::into_split(stream);
        let mut reader = BufReader::new(reader);
        writer
            .write_all(
                b"INFO {\"server_id\":\"test-reconnect\",\"version\":\"2.10.0\",\"proto\":1,\"host\":\"127.0.0.1\",\"port\":4222,\"max_payload\":1048576}\r\n",
            )
            .await?;
        let mut reconnect_ping_stalled = Some(reconnect_ping_stalled);

        loop {
            line.clear();
            if reader.read_line(&mut line).await? == 0 {
                return Ok(());
            }
            if line.split_whitespace().next() == Some("PING") {
                let _ = reconnect_ping_stalled
                    .take()
                    .expect("reconnect PING should arrive once")
                    .send(());
                std::future::pending::<()>().await;
            }
        }
    }

    #[tokio::test]
    async fn immediate_verdict_waits_for_subscription_readiness() {
        let request_subject = "sudo.request.test-host";
        let verdict_subject = "sudo.verdict.test-id";
        let request = Request {
            id: "test-id".to_string(),
            nonce: [0; 16],
            host: "test-host".to_string(),
            user: "eric".to_string(),
            uid: 1000,
            runas_uid: 0,
            cwd: "/home/eric".to_string(),
            tty: Some("/dev/pts/0".to_string()),
            command: "/usr/bin/true".to_string(),
            argv: vec!["/usr/bin/true".to_string()],
            pid_chain: vec![],
            ts: now_unix(),
            expiry: now_unix() + 60,
        };
        let (expected, credential_pub) = signed_verdict(&request);
        let verdict_payload = serde_json::to_vec(&expected).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let broker = tokio::spawn(async move {
            run_readiness_broker(listener, request_subject, verdict_subject, &verdict_payload).await
        });
        let nats = async_nats::connect(format!("nats://{address}"))
            .await
            .unwrap();

        let received = request_verdict(
            &nats,
            request_subject,
            verdict_subject,
            serde_json::to_vec(&request).unwrap(),
            tokio::time::Duration::from_millis(250),
        )
        .await
        .expect("an immediate verdict should arrive after subscription readiness");

        assert_eq!(received, expected);
        protocol::verify::verify(&received, &request, &credential_pub)
            .expect("the immediate verdict should be cryptographically valid");
        broker.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn readiness_stall_respects_the_supplied_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (subscription_accepted_tx, subscription_accepted_rx) = oneshot::channel();
        let (reconnect_ping_stalled_tx, reconnect_ping_stalled_rx) = oneshot::channel();
        let broker = tokio::spawn(run_stalled_reconnect_broker(
            listener,
            subscription_accepted_tx,
            reconnect_ping_stalled_tx,
        ));
        let nats = async_nats::ConnectOptions::new()
            .reconnect_delay_callback(|_| tokio::time::Duration::ZERO)
            .connect(format!("nats://{address}"))
            .await
            .unwrap();

        let _priming_subscription = nats.subscribe("sudo.verdict.priming").await.unwrap();
        nats.flush().await.unwrap();
        subscription_accepted_rx.await.unwrap();
        nats.force_reconnect().await.unwrap();
        tokio::time::timeout(
            tokio::time::Duration::from_secs(1),
            reconnect_ping_stalled_rx,
        )
        .await
        .expect("broker should receive the reconnect readiness PING")
        .unwrap();

        let deadline = tokio::time::Duration::from_millis(100);
        let started = tokio::time::Instant::now();
        let result = tokio::time::timeout(
            tokio::time::Duration::from_millis(500),
            request_verdict(
                &nats,
                "sudo.request.test-host",
                "sudo.verdict.test-id",
                b"request".to_vec(),
                deadline,
            ),
        )
        .await
        .expect("request_verdict should enforce its supplied deadline")
        .expect_err("a stalled subscription readiness check must fail closed");

        assert!(
            started.elapsed() < tokio::time::Duration::from_millis(250),
            "request_verdict exceeded the supplied deadline by too much"
        );
        assert!(
            format!("{result:#}").contains("sudo verdict deadline exceeded"),
            "deadline failure should retain useful context: {result:#}"
        );
        assert!(
            format!("{result:#}").contains("confirming verdict subscription readiness"),
            "deadline failure should identify the stalled stage: {result:#}"
        );
        broker.abort();
    }
}
