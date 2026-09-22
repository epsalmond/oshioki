//! The relay is a separate opt-in companion to the approval agent.

use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::Write as _,
    os::unix::{
        fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
        process::CommandExt as _,
    },
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail, ensure};
use clap::{Parser, Subcommand};
use futures::StreamExt as _;
use oshioki_agent::BrowserRelaySigner;
use oshioki_browser_relay::{
    Action, MAX_LIFETIME, Message, approval_challenge, google_callback_port, sign, verify,
};
use oshioki_protocol::{decode_base64url, encode_base64url};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Verifier as _};
use serde::Deserialize;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, UnixListener, UnixStream},
    process::{Child, Command},
    time::{Instant, timeout, timeout_at},
};

#[derive(Parser)]
#[command(about = "Opt-in Google browser ceremony relay (separate from sudo approval)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a private signing key; print only its public key for peer pinning.
    Keygen { path: PathBuf },
    /// Run gcloud auth login with a browser launcher bridged to the Mac.
    Login {
        #[arg(long)]
        config: PathBuf,
    },
    /// Run the account-bound ceremony on this Mac without NATS or SSH.
    LocalLogin {
        #[arg(long)]
        config: PathBuf,
    },
    /// Receive ceremonies and open the default browser (macOS only).
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    #[command(hide = true)]
    Capture { url: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    nats_url: String,
    /// UUID used only for routing; signatures authenticate the two peers.
    lane: String,
    private_key: PathBuf,
    peer_public_key: String,
    /// Account selected for the headless credential reuse/refresh path.
    #[serde(default)]
    google_account: Option<String>,
    /// Mac Oshioki credential public key, pinned on the NAS.
    #[serde(default)]
    approval_public_key: Option<String>,
    /// Mac agent identity file used to show the Oshioki Touch ID prompt.
    #[serde(default)]
    approval_identity: Option<PathBuf>,
    /// Trusted local configuration, never copied from the message.
    ssh_destination: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
struct LocalConfig {
    google_account: String,
    approval_identity: PathBuf,
    approval_public_key: String,
    #[serde(default = "default_local_label")]
    local_label: String,
}

fn default_local_label() -> String {
    "this Mac".into()
}

fn validate_account(account: &str) -> Result<()> {
    ensure!(
        !account.is_empty()
            && account.len() <= 320
            && account.is_ascii()
            && !account.bytes().any(|byte| byte.is_ascii_control()),
        "invalid configured Google account"
    );
    Ok(())
}

fn verify_browser_approval(
    message: &Message,
    lane: &str,
    nonce: &str,
    account: &str,
    public_key: &VerifyingKey,
    signature: &str,
) -> Result<()> {
    let signature = Signature::from_der(&decode_base64url(signature)?)?;
    public_key.verify(
        &oshioki_protocol::browser_relay_signature_payload(&approval_challenge(
            lane,
            &message.attempt,
            message.expires,
            nonce,
            account,
        )),
        &signature,
    )?;
    Ok(())
}

struct Peer {
    client: async_nats::Client,
    signing: SigningKey,
    verifying: VerifyingKey,
    subject: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StartupStage {
    BeforeSubscriptionFlush,
    BeforeProbeFlush,
}

#[cfg(test)]
type StartupFault = Arc<dyn Fn(StartupStage, &Message) + Send + Sync>;

#[derive(Default)]
struct StartupHooks {
    #[cfg(test)]
    fault: Option<StartupFault>,
    #[cfg(test)]
    gcloud: Option<PathBuf>,
}

impl StartupHooks {
    fn at(&self, stage: StartupStage, attempt: &Message) {
        let _ = (self, stage, attempt);
        #[cfg(test)]
        if let Some(fault) = &self.fault {
            fault(stage, attempt);
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn authorize_account(
    peer: &Peer,
    sub: &mut async_nats::Subscriber,
    attempt: &Message,
    nonce: &str,
    account: &str,
    config: &Config,
) -> Result<()> {
    validate_account(account)?;
    let approval_public_key = config
        .approval_public_key
        .as_deref()
        .context("approval_public_key is required with google_account")?;
    let approval_public_key =
        VerifyingKey::from_sec1_bytes(&decode_base64url(approval_public_key)?)?;
    peer.send(
        &peer.subject,
        attempt,
        Action::Authorize {
            nonce: nonce.to_owned(),
            account: account.to_owned(),
        },
    )
    .await?;
    let authorized = timeout(Duration::from_secs(30), peer.receive(sub, attempt)).await??;
    let Action::Authorized {
        nonce: authorized_nonce,
        signature,
    } = authorized.action
    else {
        bail!("Mac relay did not authorize the configured Google account")
    };
    ensure!(nonce == authorized_nonce, "stale Mac authorization");
    verify_browser_approval(
        attempt,
        &config.lane,
        nonce,
        account,
        &approval_public_key,
        &signature,
    )
    .context("verify Mac Oshioki approval")?;
    Ok(())
}

fn nats_options(url: &str) -> Result<async_nats::ConnectOptions> {
    let parsed = url::Url::parse(url).context("parse NATS URL")?;
    let mut options =
        async_nats::ConnectOptions::new().require_tls(oshioki_protocol::nats_url_is_tls(url));
    if parsed.username().is_empty() {
        ensure!(
            parsed.password().is_none(),
            "NATS URL password requires a username"
        );
    } else {
        let username = percent_encoding::percent_decode_str(parsed.username())
            .decode_utf8()
            .context("decode NATS username")?
            .into_owned();
        let password = parsed
            .password()
            .map(|password| {
                percent_encoding::percent_decode_str(password)
                    .decode_utf8()
                    .context("decode NATS password")
                    .map(std::borrow::Cow::into_owned)
            })
            .transpose()?
            .unwrap_or_default();
        options = options.user_and_password(username, password);
    }
    Ok(options)
}

fn private_read(path: &Path) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.permissions().mode().trailing_zeros() >= 6,
        "configuration and keys must be regular private files (chmod 600)"
    );
    std::fs::read(path).context("read private file")
}

async fn connect(config: &Config) -> Result<Peer> {
    ensure!(
        uuid::Uuid::parse_str(&config.lane).is_ok_and(|id| id.to_string() == config.lane),
        "lane must be a canonical UUID"
    );
    oshioki_protocol::check_nats_url(&config.nats_url, false)?;
    let secret = private_read(&config.private_key)?;
    let signing = SigningKey::from_slice(&decode_base64url(std::str::from_utf8(&secret)?.trim())?)?;
    let verifying = VerifyingKey::from_sec1_bytes(&decode_base64url(&config.peer_public_key)?)?;
    let client = nats_options(&config.nats_url)
        .context("configure relay NATS authentication")?
        .connect(&config.nats_url)
        .await
        .context("connect to relay NATS")?;
    Ok(Peer {
        client,
        signing,
        verifying,
        subject: format!("oshioki.browser.v1.{}", config.lane),
    })
}

impl Peer {
    async fn send(&self, subject: &str, template: &Message, action: Action) -> Result<()> {
        let mut message = template.clone();
        message.action = action;
        self.client
            .publish(subject.to_owned(), sign(&message, &self.signing)?.into())
            .await?;
        self.client.flush().await?;
        Ok(())
    }

    async fn receive(
        &self,
        sub: &mut async_nats::Subscriber,
        attempt: &Message,
    ) -> Result<Message> {
        while let Some(frame) = sub.next().await {
            if let Ok(message) = verify(&frame.payload, &self.verifying, now()) {
                if message.attempt == attempt.attempt && message.expires == attempt.expires {
                    return Ok(message);
                }
            }
        }
        bail!("relay subscription ended")
    }
}

/// The wrapper owns gcloud's entire process group, including its launcher.
///
/// Keep the process-group ID captured at spawn time. Tokio clears `Child::id`
/// after reaping the leader, so deriving a group ID during `Drop` would either
/// miss still-running launcher children or risk signaling a reused process ID.
struct ProcessGroup {
    child: Child,
    anchor: Child,
    pgid: nix::unistd::Pid,
}

impl ProcessGroup {
    fn spawn(mut command: Command) -> Result<Self> {
        // Keep a process in the group independently of gcloud. If gcloud
        // exits and Tokio reaps it before cleanup runs, the group ID remains
        // owned by this anchor and can still be signaled without risking a
        // later PID reuse.
        let mut anchor = Command::new("/bin/sleep");
        anchor.arg("360").kill_on_drop(true);
        anchor.as_std_mut().process_group(0);
        let anchor = anchor
            .spawn()
            .context("start gcloud process-group anchor")?;
        let id = anchor
            .id()
            .context("process-group anchor exited before setup")?;
        let pgid = nix::unistd::Pid::from_raw(i32::try_from(id)?);
        command.as_std_mut().process_group(pgid.as_raw());
        let child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let _ = nix::sys::signal::killpg(pgid, nix::sys::signal::Signal::SIGKILL);
                return Err(error).context("start gcloud");
            }
        };
        Ok(Self {
            child,
            anchor,
            pgid,
        })
    }

    async fn terminate(&mut self) {
        // `id()` is Some only while Tokio still owns an unreaped leader. The
        // anchor also keeps the recorded process group alive after the leader
        // is reaped, so launcher descendants are included in either case.
        if self.child.id().is_some() || self.anchor.id().is_some() {
            let _ = nix::sys::signal::killpg(self.pgid, nix::sys::signal::Signal::SIGKILL);
        }
        let _ = self.child.wait().await;
        let _ = self.anchor.wait().await;
    }
}

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        // This is a last-resort synchronous fallback. Normal error paths call
        // terminate() so both processes are reaped. The anchor keeps this
        // process-group ID owned until then, so it is safe to signal while it
        // is still live even if gcloud itself has already been reaped.
        if self.child.id().is_some() || self.anchor.id().is_some() {
            let _ = nix::sys::signal::killpg(self.pgid, nix::sys::signal::Signal::SIGKILL);
            let _ = self.child.start_kill();
            let _ = self.anchor.start_kill();
        }
    }
}

struct SocketDir(PathBuf);
impl Drop for SocketDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0.join("capture"));
        let _ = std::fs::remove_dir(&self.0);
    }
}

async fn interrupted() -> Result<()> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result?,
        _ = term.recv() => {},
    }
    bail!("ceremony interrupted")
}

async fn capture(url: &str) -> Result<()> {
    google_callback_port(url)?;
    let mut socket = UnixStream::connect(std::env::var("OSHIOKI_BROWSER_SOCKET")?).await?;
    socket.write_all(url.as_bytes()).await?;
    socket.shutdown().await?;
    let mut ready = [0];
    socket.read_exact(&mut ready).await?;
    ensure!(ready == [1], "Mac browser relay refused request");
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn login(config: Config) -> Result<()> {
    login_with_lifetime(
        config,
        Duration::from_secs(MAX_LIFETIME),
        StartupHooks::default(),
    )
    .await
}

fn ceremony_deadline(lifetime: Duration) -> Result<(Instant, u64)> {
    ensure!(!lifetime.is_zero(), "ceremony lifetime must be nonzero");
    Ok((
        Instant::now() + lifetime,
        now().saturating_add(lifetime.as_secs().max(1)),
    ))
}

#[allow(clippy::too_many_lines)]
async fn login_with_lifetime(
    config: Config,
    lifetime: Duration,
    startup_hooks: StartupHooks,
) -> Result<()> {
    let (deadline, expires) = ceremony_deadline(lifetime)?;
    let attempt = Message {
        version: 1,
        attempt: uuid::Uuid::new_v4().to_string(),
        expires,
        action: Action::Probe,
    };

    // This deadline starts before connecting. Once a NATS client has connected,
    // async-nats may otherwise keep a flush pending while its connection task
    // retries forever. Dropping the peer on every setup error closes that task
    // before any browser, callback listener, or process group is created.
    let connect_deadline = deadline.min(Instant::now() + Duration::from_secs(10));
    let peer = match timeout_at(connect_deadline, connect(&config)).await {
        Ok(result) => result?,
        Err(_) => bail!("NATS connection exceeded setup deadline"),
    };
    let (mut sub, offer) =
        match timeout_at(deadline, startup(&peer, &attempt, deadline, &startup_hooks)).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                drop(peer);
                return Err(error);
            }
            Err(_) => {
                drop(peer);
                return Err(anyhow::anyhow!("NATS setup exceeded ceremony deadline"));
            }
        };
    let Action::Offer { nonce } = offer.action else {
        bail!("Mac relay unavailable")
    };
    let account = config.google_account.as_deref();
    ensure!(
        account.is_some() == config.approval_public_key.is_some(),
        "google_account and approval_public_key must be configured together"
    );
    if let Some(account) = account {
        let authorization = timeout_at(
            deadline,
            authorize_account(&peer, &mut sub, &attempt, &nonce, account, &config),
        )
        .await;
        if let Err(error) = match authorization {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!("NATS ceremony deadline expired")),
        } {
            let _ = timeout(Duration::from_secs(2), async {
                peer.send(&peer.subject, &attempt, Action::Stop).await?;
                ensure!(
                    peer.receive(&mut sub, &attempt).await?.action == Action::Closed,
                    "Mac relay did not confirm authorization cleanup"
                );
                anyhow::Ok(())
            })
            .await;
            return Err(error);
        }
    }
    ensure!(
        Instant::now() < deadline,
        "browser ceremony expired before launcher setup"
    );
    let dir = SocketDir(PathBuf::from(format!(
        "/tmp/oshioki-browser-{}",
        attempt.attempt
    )));
    std::fs::DirBuilder::new().mode(0o700).create(&dir.0)?;
    let listener = UnixListener::bind(dir.0.join("capture"))?;
    let executable = std::env::current_exe()?;
    let executable = executable
        .to_str()
        .context("executable path is not UTF-8")?;
    ensure!(
        !executable.contains([':', '\'', '\n']),
        "unsupported executable path for Python BROWSER"
    );
    #[cfg(test)]
    let gcloud = startup_hooks
        .gcloud
        .as_deref()
        .unwrap_or_else(|| Path::new("gcloud"));
    #[cfg(not(test))]
    let gcloud = Path::new("gcloud");
    let mut command = Command::new(gcloud);
    command.args(["auth", "login"]);
    if let Some(account) = account {
        command.arg(account);
    } else {
        command.arg("--force");
    }
    command
        .arg("--launch-browser")
        .env("BROWSER", format!("'{executable}' capture %s"))
        .env("CLOUDSDK_CORE_DISABLE_PROMPTS", "true")
        .env("CLOUDSDK_AUTH_DISABLE_CODE_VERIFIER", "false")
        // gcloud checks DISPLAY even with a custom BROWSER on Linux. The
        // launcher uses our socket only; no X server is contacted.
        .env("DISPLAY", "oshioki-browser-relay")
        .env("OSHIOKI_BROWSER_SOCKET", dir.0.join("capture"))
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let mut child = ProcessGroup::spawn(command)?;
    let outcome = tokio::select! {
        result = timeout_at(deadline, login_attempt(&peer, &attempt, nonce, &mut sub, &listener, &mut child.child, account.is_some())) => result.context("Google browser ceremony expired").and_then(std::convert::identity),
        result = interrupted() => result.map(|()| LoginAttempt::Browser),
    };
    // Do this before waiting for NATS cleanup. A failed or interrupted login
    // must not leave gcloud able to finish OAuth in the background. The same
    // cleanup removes the process-group anchor after a successful login.
    child.terminate().await;
    let mut outcome = outcome;
    if matches!(&outcome, Ok(LoginAttempt::Headless))
        && let Some(account) = account
        && let Err(error) = validate_headless_account(account).await
    {
        outcome = Err(error);
    }
    // Stop contains no Google callback, authorization code, or token. It is
    // sent on success AND failure. A lost stop still expires on the Mac.
    let stopped = timeout(Duration::from_secs(2), async {
        peer.send(&peer.subject, &attempt, Action::Stop).await?;
        ensure!(
            peer.receive(&mut sub, &attempt).await?.action == Action::Closed,
            "Mac relay did not confirm cleanup"
        );
        anyhow::Ok(())
    })
    .await;
    outcome?;
    stopped.context("Mac cleanup confirmation timed out")?
}

async fn startup(
    peer: &Peer,
    attempt: &Message,
    deadline: Instant,
    hooks: &StartupHooks,
) -> Result<(async_nats::Subscriber, Message)> {
    let reply = format!("{}.reply.{}", peer.subject, attempt.attempt);
    let mut sub = peer.client.subscribe(reply).await?;
    hooks.at(StartupStage::BeforeSubscriptionFlush, attempt);
    peer.client.flush().await?;

    let mut probe = attempt.clone();
    probe.action = Action::Probe;
    peer.client
        .publish(peer.subject.clone(), sign(&probe, &peer.signing)?.into())
        .await?;
    hooks.at(StartupStage::BeforeProbeFlush, attempt);
    peer.client.flush().await?;

    let offer = timeout_at(deadline, peer.receive(&mut sub, attempt))
        .await
        .context("Mac relay offer timed out")??;
    Ok((sub, offer))
}

#[cfg(target_os = "macos")]
async fn local_login(config: LocalConfig) -> Result<()> {
    validate_account(&config.google_account)?;
    ensure!(
        !config.local_label.is_empty(),
        "local_label cannot be empty"
    );
    let approval_public_key =
        VerifyingKey::from_sec1_bytes(&decode_base64url(&config.approval_public_key)?)?;
    let signer = load_approval_signer(Some(&config.approval_identity))
        .await?
        .context("local approval identity was not loaded")?;
    let deadline = Instant::now() + Duration::from_secs(MAX_LIFETIME);
    let attempt = Message {
        version: 1,
        attempt: uuid::Uuid::new_v4().to_string(),
        expires: now() + MAX_LIFETIME,
        action: Action::Probe,
    };
    let nonce = uuid::Uuid::new_v4().to_string();
    let signature = tokio::select! {
        result = timeout_at(deadline, browser_authorize(
            &signer,
            &attempt,
            "local",
            &nonce,
            &config.google_account,
            &config.local_label,
        )) => result.context("local Oshioki approval timed out")??,
        result = interrupted() => return result,
    }
    .context("local Oshioki approval was denied or expired")?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    run_local_after_approval(
        &config.google_account,
        Path::new("gcloud"),
        verify_browser_approval(
            &attempt,
            "local",
            &nonce,
            &config.google_account,
            &approval_public_key,
            &encode_base64url(&signature),
        ),
        Some(remaining),
    )
    .await
}

#[cfg(not(target_os = "macos"))]
#[allow(clippy::unused_async)]
async fn local_login(_config: LocalConfig) -> Result<()> {
    bail!("local browser ceremony requires macOS")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LoginAttempt {
    Headless,
    Browser,
}

async fn login_attempt(
    peer: &Peer,
    attempt: &Message,
    nonce: String,
    sub: &mut async_nats::Subscriber,
    listener: &UnixListener,
    child: &mut Child,
    allow_headless: bool,
) -> Result<LoginAttempt> {
    let (mut socket, _) = tokio::select! {
        accepted = listener.accept() => accepted?,
        status = child.wait() => {
            let status = status?;
            ensure!(status.success(), "Google sign-in failed or was denied");
            ensure!(allow_headless, "gcloud exited without a browser ceremony");
            return Ok(LoginAttempt::Headless);
        },
    };
    let mut bytes = Vec::new();
    (&mut socket).take(8193).read_to_end(&mut bytes).await?;
    let url = String::from_utf8(bytes)?;
    google_callback_port(&url)?;
    peer.send(&peer.subject, attempt, Action::Start { nonce, url })
        .await?;
    let ready = timeout(Duration::from_secs(15), peer.receive(sub, attempt)).await??;
    ensure!(
        ready.action == Action::Ready,
        "Mac failed to start the browser ceremony"
    );
    socket.write_all(&[1]).await?;
    socket.shutdown().await?;
    eprintln!(
        "Complete Google's sign-in in the Mac browser. Password, consent, or CAPTCHA requirements must be completed there; the relay will not retry them."
    );
    tokio::select! {
        status = child.wait() => ensure!(status?.success(), "Google sign-in failed or was denied"),
        _ = peer.receive(sub, attempt) => bail!("Mac browser relay ended before gcloud completed"),
    }
    Ok(LoginAttempt::Browser)
}

async fn validate_headless_account(account: &str) -> Result<()> {
    validate_headless_account_with(account, Path::new("gcloud")).await
}

async fn validate_headless_account_with(account: &str, executable: &Path) -> Result<()> {
    let output = timeout(
        Duration::from_secs(15),
        Command::new(executable)
            .args([
                "auth",
                "print-access-token",
                "--account",
                account,
                "--quiet",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("headless Google credential check timed out")??;
    ensure!(
        output.status.success() && !output.stdout.is_empty(),
        "configured Google credentials could not produce an access token"
    );
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
async fn run_local_after_approval(
    account: &str,
    executable: &Path,
    approval: Result<()>,
    limit: Option<Duration>,
) -> Result<()> {
    approval?;
    match limit {
        Some(limit) => run_local_gcloud_with_timeout(account, executable, limit).await,
        None => run_local_gcloud(account, executable).await,
    }
}

#[cfg(any(target_os = "macos", test))]
async fn run_local_gcloud(account: &str, executable: &Path) -> Result<()> {
    run_local_gcloud_until(
        account,
        executable,
        Instant::now() + Duration::from_secs(MAX_LIFETIME),
        None,
    )
    .await
}

#[cfg(any(target_os = "macos", test))]
async fn run_local_gcloud_with_timeout(
    account: &str,
    executable: &Path,
    limit: Duration,
) -> Result<()> {
    run_local_gcloud_until(account, executable, Instant::now() + limit, None).await
}

#[cfg(test)]
async fn run_local_gcloud_with_timeout_and_browser(
    account: &str,
    executable: &Path,
    limit: Duration,
    browser: &Path,
) -> Result<()> {
    run_local_gcloud_until(account, executable, Instant::now() + limit, Some(browser)).await
}

#[cfg(any(target_os = "macos", test))]
async fn run_local_gcloud_until(
    account: &str,
    executable: &Path,
    deadline: Instant,
    browser: Option<&Path>,
) -> Result<()> {
    ensure!(
        Instant::now() < deadline,
        "local ceremony expired before gcloud start"
    );
    let mut command = Command::new(executable);
    command
        .args(["auth", "login", account, "--launch-browser"])
        .env("CLOUDSDK_CORE_DISABLE_PROMPTS", "true")
        .env("CLOUDSDK_AUTH_DISABLE_CODE_VERIFIER", "false")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    if let Some(browser) = browser {
        command.env("BROWSER", browser);
    }
    let mut child = ProcessGroup::spawn(command)?;
    let outcome = timeout_at(deadline, async {
        tokio::select! {
            status = child.child.wait() => {
                ensure!(status?.success(), "Google sign-in failed or was denied");
                anyhow::Ok(())
            }
            result = interrupted() => result,
        }
    })
    .await
    .context("local Google sign-in timed out");
    child.terminate().await;
    outcome??;
    tokio::select! {
        result = timeout_at(deadline, validate_headless_account_with(account, executable)) => {
            result.context("local credential check timed out")?
        }
        result = interrupted() => result,
    }
}

#[cfg(target_os = "macos")]
async fn load_approval_signer(path: Option<&Path>) -> Result<Option<Arc<BrowserRelaySigner>>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let path = path.to_owned();
    let signer = timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(move || BrowserRelaySigner::load(&path)),
    )
    .await
    .context("load Mac approval identity timed out")??
    .context("load Mac approval identity")?;
    Ok(Some(Arc::new(signer)))
}

#[cfg(not(target_os = "macos"))]
#[allow(clippy::unused_async)]
async fn load_approval_signer(path: Option<&Path>) -> Result<Option<Arc<BrowserRelaySigner>>> {
    ensure!(path.is_none(), "browser relay approval requires macOS");
    Ok(None)
}

async fn serve(config: Config) -> Result<()> {
    ensure!(
        cfg!(target_os = "macos"),
        "browser ceremony receiver requires macOS"
    );
    let destination = config
        .ssh_destination
        .as_deref()
        .context("ssh_destination is required on Mac")?;
    ensure!(
        !destination.starts_with('-')
            && !destination.is_empty()
            && destination
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"@._-".contains(&b)),
        "invalid configured SSH destination"
    );
    ensure!(
        config.google_account.is_some() == config.approval_identity.is_some(),
        "google_account and approval_identity must be configured together on Mac"
    );
    let approval_signer = load_approval_signer(config.approval_identity.as_deref()).await?;
    let peer = connect(&config).await?;
    let mut sub = peer.client.subscribe(peer.subject.clone()).await?;
    peer.client.flush().await?;
    let mut seen = HashMap::<String, u64>::new();
    let programs = Programs::default();
    eprintln!("Browser ceremony receiver ready");
    loop {
        let frame = tokio::select! {
            frame = sub.next() => frame.context("relay subscription ended")?,
            result = interrupted() => return result,
        };
        let Ok(attempt) = verify(&frame.payload, &peer.verifying, now()) else {
            continue;
        };
        if attempt.action != Action::Probe {
            continue;
        }
        seen.retain(|_, expires| *expires > now());
        if seen.contains_key(&attempt.attempt) || seen.len() >= 128 {
            continue;
        }
        seen.insert(attempt.attempt.clone(), attempt.expires);
        let reply = format!("{}.reply.{}", peer.subject, attempt.attempt);
        let deadline = Instant::now() + Duration::from_secs(attempt.expires.saturating_sub(now()));
        let result = tokio::select! {
            result = timeout_at(deadline, serve_attempt(&peer, &attempt, &reply, &mut sub, &config.lane, config.google_account.as_deref(), destination, &programs, approval_signer.as_ref())) => result.context("ceremony expired").and_then(std::convert::identity),
            result = interrupted() => return result,
        };
        // Diagnostics deliberately exclude URLs, NATS frames, and callback bytes.
        eprintln!(
            "Browser ceremony {}",
            if result.is_ok() {
                "closed"
            } else {
                "failed or expired"
            }
        );
        if result.is_ok() {
            let _ = timeout(
                Duration::from_secs(2),
                peer.send(&reply, &attempt, Action::Closed),
            )
            .await;
        } else {
            let _ = timeout(Duration::from_secs(2), async {
                peer.send(&reply, &attempt, Action::Failed).await?;
                ensure!(
                    peer.receive(&mut sub, &attempt).await?.action == Action::Stop,
                    "expected Stop after failed ceremony"
                );
                peer.send(&reply, &attempt, Action::Closed).await
            })
            .await;
        }
    }
}

struct Programs {
    browser: PathBuf,
    ssh: PathBuf,
}

#[cfg(target_os = "macos")]
mod native_approval {
    use std::sync::Arc;

    use anyhow::{Context as _, Result};
    use oshioki_agent::{
        BrowserRelaySigner,
        touchid::{AttemptError, Outcome, PromptCancel, ScreenLock, TouchIdPrompt},
    };
    use oshioki_browser_relay::{Message, approval_challenge};
    use oshioki_enclave::SignError;

    struct Screen;

    impl ScreenLock for Screen {
        fn is_locked(&self) -> bool {
            oshioki_enclave::screen_is_locked()
        }
    }

    struct Canceller(Arc<BrowserRelaySigner>);

    impl PromptCancel for Canceller {
        fn begin(&self) -> u64 {
            self.0.begin_prompt()
        }

        fn cancel(&self, attempt: u64) {
            self.0.cancel_prompt(attempt);
        }
    }

    pub async fn authorize(
        signer: &Arc<BrowserRelaySigner>,
        attempt: &Message,
        lane: &str,
        nonce: &str,
        account: &str,
        destination: &str,
    ) -> Result<Option<Vec<u8>>> {
        let prompt = TouchIdPrompt::new(Box::new(Screen), Arc::new(Canceller(Arc::clone(signer))));
        let challenge = approval_challenge(lane, &attempt.attempt, attempt.expires, nonce, account);
        let reason = format!("authorize gcloud for {account} via {destination}");
        let signer = Arc::clone(signer);
        let sign = move || {
            signer
                .sign_browser_relay(&challenge, &reason)
                .map_err(classify)
        };
        let expires = i64::try_from(attempt.expires).context("ceremony expiry is too large")?;
        match prompt.ask(&attempt.attempt, expires, sign).await? {
            Outcome::Approved(signature) => Ok(Some(signature)),
            Outcome::Denied | Outcome::Expired => Ok(None),
        }
    }

    fn classify(error: anyhow::Error) -> AttemptError {
        if matches!(error.downcast_ref::<SignError>(), Some(SignError::Canceled)) {
            AttemptError::Canceled
        } else {
            AttemptError::Failed(error)
        }
    }
}

#[cfg(target_os = "macos")]
async fn browser_authorize(
    signer: &Arc<BrowserRelaySigner>,
    attempt: &Message,
    lane: &str,
    nonce: &str,
    account: &str,
    destination: &str,
) -> Result<Option<Vec<u8>>> {
    native_approval::authorize(signer, attempt, lane, nonce, account, destination).await
}

#[cfg(not(target_os = "macos"))]
#[allow(clippy::unused_async)]
async fn browser_authorize(
    _signer: &Arc<BrowserRelaySigner>,
    _attempt: &Message,
    _lane: &str,
    _nonce: &str,
    _account: &str,
    _destination: &str,
) -> Result<Option<Vec<u8>>> {
    bail!("browser relay approval requires macOS")
}

impl Default for Programs {
    fn default() -> Self {
        Self {
            browser: "/usr/bin/open".into(),
            ssh: "/usr/bin/ssh".into(),
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn serve_attempt(
    peer: &Peer,
    attempt: &Message,
    reply: &str,
    sub: &mut async_nats::Subscriber,
    lane: &str,
    expected_account: Option<&str>,
    destination: &str,
    programs: &Programs,
    approval_signer: Option<&Arc<BrowserRelaySigner>>,
) -> Result<()> {
    // A fresh receiver nonce prevents a captured Start from working after
    // restart, even when its signed wall-clock expiry has not passed.
    let nonce = uuid::Uuid::new_v4().to_string();
    peer.send(
        reply,
        attempt,
        Action::Offer {
            nonce: nonce.clone(),
        },
    )
    .await?;
    let first = timeout(Duration::from_secs(30), peer.receive(sub, attempt)).await??;
    let url = match first.action {
        Action::Authorize {
            nonce: offered,
            account,
        } => {
            ensure!(nonce == offered, "stale receiver nonce");
            validate_account(&account)?;
            ensure!(
                expected_account == Some(account.as_str()),
                "Google account does not match Mac configuration"
            );
            let Some(signer) = approval_signer else {
                bail!("Mac Oshioki approval identity is not configured")
            };
            let authorization = tokio::select! {
                result = timeout(
                    Duration::from_secs(30),
                    browser_authorize(signer, attempt, lane, &offered, &account, destination),
                ) => result.context("Oshioki authorization timed out")??,
                message = peer.receive(sub, attempt) => {
                    ensure!(message?.action == Action::Stop, "unexpected ceremony control message");
                    return Ok(())
                }
            };
            let Some(signature) = authorization else {
                bail!("Oshioki approval was denied or expired")
            };
            peer.send(
                reply,
                attempt,
                Action::Authorized {
                    nonce: offered,
                    signature: encode_base64url(&signature),
                },
            )
            .await?;
            let next = timeout(Duration::from_secs(30), peer.receive(sub, attempt)).await??;
            match next.action {
                Action::Start {
                    nonce: offered,
                    url,
                } => {
                    ensure!(nonce == offered, "stale receiver nonce");
                    url
                }
                Action::Stop => return Ok(()),
                _ => bail!("ceremony cancelled before browser start"),
            }
        }
        Action::Start {
            nonce: offered,
            url,
        } => {
            ensure!(
                approval_signer.is_none(),
                "configured Mac approval requires an Authorize action"
            );
            ensure!(nonce == offered, "stale receiver nonce");
            url
        }
        _ => bail!("ceremony cancelled before start"),
    };
    let port = google_callback_port(&url)?;
    // These listeners live in this process, not in an orphanable ssh -L.
    // Binding both families prevents localhost from reaching a different
    // process over IPv6. A collision on either address aborts before open.
    let ipv4 = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    let ipv6 = TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, port)).await?;
    let mut browser = Command::new(&programs.browser)
        .arg(&url)
        .kill_on_drop(true)
        .spawn()?;
    ensure!(
        timeout(Duration::from_secs(5), browser.wait())
            .await??
            .success(),
        "default browser could not be opened"
    );
    peer.send(reply, attempt, Action::Ready).await?;
    let mut connections = futures::stream::FuturesUnordered::new();
    loop {
        tokio::select! {
            message = peer.receive(sub, attempt) => {
                ensure!(message?.action == Action::Stop, "unexpected ceremony control message");
                return Ok(());
            },
            accepted = ipv4.accept(), if connections.len() < 8 => {
                let (stream, _) = accepted?;
                connections.push(forward(stream, destination.to_owned(), port, programs.ssh.clone()));
            },
            accepted = ipv6.accept(), if connections.len() < 8 => {
                let (stream, _) = accepted?;
                connections.push(forward(stream, destination.to_owned(), port, programs.ssh.clone()));
            },
            result = connections.next(), if !connections.is_empty() => {
                result.context("missing forward result")??;
            },
        }
    }
}

async fn forward(
    stream: tokio::net::TcpStream,
    destination: String,
    port: u16,
    executable: PathBuf,
) -> Result<()> {
    let mut ssh = Command::new(executable)
        .args([
            "-T",
            "-oBatchMode=yes",
            "-oStrictHostKeyChecking=yes",
            "-oExitOnForwardFailure=yes",
            "-oConnectTimeout=5",
            "-oConnectionAttempts=1",
            "-oServerAliveInterval=5",
            "-oServerAliveCountMax=1",
            "-oControlMaster=no",
            "-oForkAfterAuthentication=no",
            "-oControlPath=none",
            "-oPermitLocalCommand=no",
            "-oClearAllForwardings=yes",
            "-W",
        ])
        .arg(format!("localhost:{port}"))
        .arg(destination)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut input = ssh.stdin.take().context("ssh stdin")?;
    let mut output = ssh.stdout.take().context("ssh stdout")?;
    let (mut read, mut write) = tokio::io::split(stream);
    let mut to_ssh = Some(Box::pin(async move {
        tokio::io::copy(&mut read, &mut input).await?;
        input.shutdown().await
    }));
    let mut from_ssh = Some(Box::pin(async move {
        tokio::io::copy(&mut output, &mut write).await?;
        write.shutdown().await
    }));
    let mut wait = Box::pin(ssh.wait());

    // SSH can exit while the browser keeps its request socket open. Observe
    // the child independently of the browser-to-SSH copy so that failure is
    // reported promptly. If the child exits first, drain stdout completely
    // before returning; the final OAuth response may already be buffered.
    let result = tokio::select! {
        result = to_ssh.as_mut().expect("upload future missing") => {
            async {
                result.map_err(anyhow::Error::from)?;
                drop(to_ssh.take());
                // Keep reading while waiting for SSH. A large callback can
                // fill stdout and block SSH before it exits.
                let (status, ()) = tokio::try_join!(
                    &mut wait,
                    from_ssh.as_mut().expect("download future missing")
                )?;
                Ok(status.success())
            }
            .await
        },
        result = from_ssh.as_mut().expect("download future missing") => {
            async {
                result.map_err(anyhow::Error::from)?;
                // The download is complete; release the upload half before
                // waiting for an SSH process that may be waiting for EOF.
                drop(to_ssh.take());
                Ok((&mut wait).await?.success())
            }
            .await
        },
        status = &mut wait => {
            match status {
                Err(error) => Err(error.into()),
                Ok(status) => {
                    drop(to_ssh.take());
                    match from_ssh.as_mut().expect("download future missing").await {
                        Ok(()) => Ok(status.success()),
                        Err(error) => Err(error.into()),
                    }
                }
            }
        },
    };
    match result {
        Ok(true) => Ok(()),
        Ok(false) => bail!("SSH callback forward failed"),
        Err(error) => {
            // Reap a child on copy errors. `kill_on_drop` is retained as a
            // fallback for cancellation, but explicit cleanup avoids leaving
            // a zombie when a pipe fails first.
            drop(wait);
            drop(to_ssh.take());
            drop(from_ssh.take());
            let _ = ssh.kill().await;
            Err(error)
        }
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        // Some library errors contain their input URL. Keep user-visible
        // errors categorical; never dump signed payloads or credentials.
        let _ = error;
        eprintln!(
            "Browser ceremony failed. Check private configuration, pinned keys, NATS/SSH reachability, port availability, and Google's browser prompt."
        );
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    match Cli::parse().command {
        Commands::Keygen { path } => {
            let key = SigningKey::random(&mut rand::rngs::OsRng);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            writeln!(file, "{}", encode_base64url(&key.to_bytes()))?;
            file.sync_all()?;
            println!(
                "{}",
                encode_base64url(key.verifying_key().to_encoded_point(false).as_bytes())
            );
            Ok(())
        }
        Commands::Capture { url } => timeout(Duration::from_secs(30), capture(&url)).await?,
        Commands::Login { config } => login(serde_json::from_slice(&private_read(&config)?)?).await,
        Commands::LocalLogin { config } => {
            local_login(serde_json::from_slice(&private_read(&config)?)?).await
        }
        Commands::Serve { config } => serve(serde_json::from_slice(&private_read(&config)?)?).await,
    }
}

#[cfg(test)]
mod tests;
