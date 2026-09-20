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
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail, ensure};
use clap::{Parser, Subcommand};
use futures::StreamExt as _;
use oshioki_browser_relay::{Action, MAX_LIFETIME, Message, google_callback_port, sign, verify};
use oshioki_protocol::{decode_base64url, encode_base64url};
use p256::ecdsa::{SigningKey, VerifyingKey};
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
    /// Trusted local configuration, never copied from the message.
    ssh_destination: Option<String>,
}

struct Peer {
    client: async_nats::Client,
    signing: SigningKey,
    verifying: VerifyingKey,
    subject: String,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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

async fn login(config: Config) -> Result<()> {
    let peer = timeout(Duration::from_secs(10), connect(&config)).await??;
    let attempt = Message {
        version: 1,
        attempt: uuid::Uuid::new_v4().to_string(),
        expires: now() + MAX_LIFETIME,
        action: Action::Probe,
    };
    let reply = format!("{}.reply.{}", peer.subject, attempt.attempt);
    let mut sub = peer.client.subscribe(reply).await?;
    peer.client.flush().await?;
    peer.send(&peer.subject, &attempt, Action::Probe).await?;
    let offer = timeout(Duration::from_secs(10), peer.receive(&mut sub, &attempt)).await??;
    let Action::Offer { nonce } = offer.action else {
        bail!("Mac relay unavailable")
    };
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
    let mut command = Command::new("gcloud");
    command
        .args(["auth", "login", "--force", "--launch-browser"])
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
    let deadline = Instant::now() + Duration::from_secs(attempt.expires.saturating_sub(now()));
    let outcome = tokio::select! {
        result = timeout_at(deadline, login_attempt(&peer, &attempt, nonce, &mut sub, &listener, &mut child.child)) => result.context("Google browser ceremony expired").and_then(std::convert::identity),
        result = interrupted() => result,
    };
    // Do this before waiting for NATS cleanup. A failed or interrupted login
    // must not leave gcloud able to finish OAuth in the background. The same
    // cleanup removes the process-group anchor after a successful login.
    child.terminate().await;
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

async fn login_attempt(
    peer: &Peer,
    attempt: &Message,
    nonce: String,
    sub: &mut async_nats::Subscriber,
    listener: &UnixListener,
    child: &mut Child,
) -> Result<()> {
    let (mut socket, _) = tokio::select! {
        accepted = listener.accept() => accepted?,
        status = child.wait() => { let _ = status?; bail!("gcloud exited without a browser ceremony"); },
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
    Ok(())
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
            result = timeout_at(deadline, serve_attempt(&peer, &attempt, &reply, &mut sub, destination, &programs)) => result.context("ceremony expired").and_then(std::convert::identity),
            result = interrupted() => return result,
        };
        let action = if result.is_ok() {
            Action::Closed
        } else {
            Action::Failed
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
        let _ = timeout(Duration::from_secs(2), peer.send(&reply, &attempt, action)).await;
    }
}

struct Programs {
    browser: PathBuf,
    ssh: PathBuf,
}

impl Default for Programs {
    fn default() -> Self {
        Self {
            browser: "/usr/bin/open".into(),
            ssh: "/usr/bin/ssh".into(),
        }
    }
}

async fn serve_attempt(
    peer: &Peer,
    attempt: &Message,
    reply: &str,
    sub: &mut async_nats::Subscriber,
    destination: &str,
    programs: &Programs,
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
    let start = timeout(Duration::from_secs(15), peer.receive(sub, attempt)).await??;
    let Action::Start {
        nonce: offered,
        url,
    } = start.action
    else {
        bail!("ceremony cancelled before start")
    };
    ensure!(nonce == offered, "stale receiver nonce");
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
        Commands::Serve { config } => serve(serde_json::from_slice(&private_read(&config)?)?).await,
    }
}

#[cfg(test)]
mod tests;
