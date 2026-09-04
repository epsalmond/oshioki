//! `oshioki-agent`: pairs a native device with a host and answers sudo
//! requests over NATS and a local Unix socket. NATS is optional at runtime:
//! without it the agent answers socket requests only.
//!
//! This binary is the Linux and test build of the macOS agent (#9). It uses
//! a software P-256 key and a terminal prompt. macOS adds the Secure Enclave
//! backend and a native prompt on top of the same library.

use std::{
    future::Future,
    io::{self, BufRead, IsTerminal as _, Write as _},
    os::unix::fs::{FileTypeExt as _, PermissionsExt as _},
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
#[cfg(feature = "unattended")]
use clap::ValueEnum;
use clap::{Parser, Subcommand};
use futures::StreamExt as _;
use oshioki_agent::{Identity, OpenedRequest, SignerKind, parse_enrollment_url, remaining_until};
use oshioki_protocol::{
    ALLOW_PLAINTEXT_NATS_ENV, ActivationV1, DecisionV1, RequestEnvelopeV1, allow_plaintext_nats,
    check_nats_url, escape_for_terminal, nats_url_is_tls,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{Mutex, mpsc, oneshot};
use tracing::{info, warn};

const PAIR_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Parser)]
#[command(name = "oshioki-agent", version, about)]
struct Cli {
    /// Directory holding the agent identity (default: `$OSHIOKI_AGENT_STATE`,
    /// then ~/.config/oshioki).
    #[arg(long, global = true)]
    state: Option<PathBuf>,
    #[command(subcommand)]
    verb: Verb,
}

#[derive(Subcommand)]
enum Verb {
    /// Enroll this device with a host using the URL printed by `oshioki enroll`.
    Pair {
        #[arg(allow_hyphen_values = true)]
        enrollment_url: String,
        /// Label shown on the host's device list.
        #[arg(long)]
        label: String,
        /// Where the signing key lives. Defaults to the Secure Enclave on
        /// macOS and to a software key everywhere else. Ignored when this
        /// device already has an identity, unless it disagrees with it.
        #[arg(long, value_enum)]
        signer: Option<SignerArg>,
        /// Replace an existing identity. The device gets a new fingerprint,
        /// so the host's old record for it should be revoked.
        #[arg(long)]
        force: bool,
    },
    /// Watch for requests and decide them.
    Run {
        /// Decide every request without asking. For tests only.
        #[cfg(feature = "unattended")]
        #[arg(long, value_enum)]
        auto: Option<Auto>,
    },
    /// Print this device's fingerprint.
    Show,
}

#[cfg(feature = "unattended")]
#[derive(Clone, Copy, ValueEnum)]
enum Auto {
    Approve,
    Deny,
}

/// The `--signer` choices. Not every one works on every machine: only a Mac
/// has a Secure Enclave.
#[derive(Clone, Copy, clap::ValueEnum)]
enum SignerArg {
    Software,
    Enclave,
}

/// A Mac signs with the enclave unless told otherwise, so pairing on a Mac
/// gets Touch ID with no flag to remember.
const DEFAULT_SIGNER: SignerKind = if cfg!(target_os = "macos") {
    SignerKind::Enclave
} else {
    SignerKind::Software
};

fn signer_kind(flag: Option<SignerArg>) -> SignerKind {
    match flag {
        Some(SignerArg::Software) => SignerKind::Software,
        Some(SignerArg::Enclave) => SignerKind::Enclave,
        None => DEFAULT_SIGNER,
    }
}

/// Whether `--signer` was given, so a mismatch with an existing identity can
/// be an error rather than a flag that did nothing.
fn requested_signer_kind(flag: Option<SignerArg>) -> Option<SignerKind> {
    flag.map(|flag| signer_kind(Some(flag)))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(io::stderr)
        .init();
    let cli = Cli::parse();
    let identity_path = state_dir(cli.state)?.join("agent.json");
    match cli.verb {
        Verb::Pair {
            enrollment_url,
            label,
            signer,
            force,
        } => {
            cmd_pair(
                &identity_path,
                &enrollment_url,
                &label,
                Pairing {
                    requested: requested_signer_kind(signer),
                    default: signer_kind(signer),
                    force,
                },
            )
            .await
        }
        #[cfg(feature = "unattended")]
        Verb::Run { auto } => cmd_run(&identity_path, auto).await,
        #[cfg(not(feature = "unattended"))]
        Verb::Run {} => cmd_run(&identity_path).await,
        Verb::Show => {
            let identity = Identity::load(&identity_path)?;
            println!("{}", identity.fingerprint());
            println!("signer: {}", identity.signer_kind());
            Ok(())
        }
    }
}

fn state_dir(flag: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(dir) = flag {
        return Ok(dir);
    }
    if let Some(dir) = std::env::var_os("OSHIOKI_AGENT_STATE") {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config").join("oshioki"))
}

/// Loads the identity, creating one on first use. One identity serves every
/// host this device pairs with.
/// What `pair` was told about the signing key.
struct Pairing {
    /// The `--signer` value, if one was given.
    requested: Option<SignerKind>,
    /// What to create when there is no identity yet.
    default: SignerKind,
    /// Replace an existing identity rather than reuse it.
    force: bool,
}

fn load_or_create(path: &std::path::Path, pairing: &Pairing) -> Result<Identity> {
    if path.exists() && !pairing.force {
        // One identity serves every host this device pairs with, so an
        // existing one is reused rather than replaced. A --signer that
        // disagrees with it cannot be honoured and must not look like it was.
        let identity = Identity::load(path)?;
        let existing = identity.signer_kind();
        if let Some(requested) = pairing.requested {
            if requested != existing {
                bail!(
                    "this device already has an identity with a {existing} signing key, and \
                     --signer {requested} cannot change it; drop the flag to pair this host \
                     with the existing key, or pass --force to replace the identity, which \
                     gives the device a new fingerprint and needs the host's old record \
                     revoked"
                );
            }
        }
        info!(
            fingerprint = %identity.fingerprint(),
            signer = %existing,
            "pairing with this device's existing identity"
        );
        return Ok(identity);
    }
    if path.exists() {
        warn!(path=%path.display(), "replacing this device's identity");
        std::fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
    }
    let identity = Identity::generate_to(path, pairing.requested.unwrap_or(pairing.default))?;
    info!(
        path = %path.display(),
        fingerprint = %identity.fingerprint(),
        signer = %identity.signer_kind(),
        "created device identity"
    );
    Ok(identity)
}

async fn cmd_pair(
    identity_path: &std::path::Path,
    url: &str,
    label: &str,
    pairing: Pairing,
) -> Result<()> {
    let (enrollment_id, secret) = parse_enrollment_url(url)?;
    let identity = load_or_create(identity_path, &pairing)?;
    let submission = identity.enrollment_submission(&enrollment_id, &secret, label)?;
    let nats = connect_nats().await?;
    let mut activations = nats
        .subscribe(format!("oshioki.enrollment.activation.{enrollment_id}"))
        .await
        .context("subscribe activation")?;
    nats.flush().await?;
    nats.publish(
        format!("oshioki.enrollment.submission.{enrollment_id}"),
        serde_json::to_vec(&oshioki_protocol::EnrollmentSubmissionV1::SecureEnclave(
            submission,
        ))?
        .into(),
    )
    .await
    .context("publish submission")?;
    nats.flush().await?;
    let message = tokio::time::timeout(PAIR_TIMEOUT, activations.next())
        .await
        .context("no activation before the enrollment expired")?
        .context("activation stream closed")?;
    let activation: ActivationV1 =
        serde_json::from_slice(&message.payload).context("decode activation")?;
    if activation.enrollment_id != enrollment_id
        || activation.device.fingerprint != identity.fingerprint()
    {
        bail!("activation names another device");
    }
    activation.device.validate().context("activated record")?;
    println!(
        "Paired: {} ({})",
        activation.device.fingerprint,
        escape_for_terminal(&activation.device.label)
    );
    Ok(())
}

async fn cmd_run(
    identity_path: &std::path::Path,
    #[cfg(feature = "unattended")] auto: Option<Auto>,
) -> Result<()> {
    let identity = Arc::new(Identity::load(identity_path)?);
    // Bind before subscribing so a second instance fails fast instead of
    // double-prompting behind the first one.
    let socket_path = socket_path(identity_path, std::env::var_os("OSHIOKI_AGENT_SOCKET"))?;
    let socket = bind_socket(&socket_path)?;
    info!(
        path = %socket_path.display(),
        fingerprint = %identity.fingerprint(),
        "agent socket listening"
    );
    // NATS is the network transport; the socket above is the local one. When
    // the network is down the agent still answers socket requests, and
    // rejoining NATS needs a restart.
    let mut requests = subscribe_requests(&identity).await?;
    #[cfg(feature = "unattended")]
    let auto = auto.map(|auto| match auto {
        Auto::Approve => true,
        Auto::Deny => false,
    });
    #[cfg(not(feature = "unattended"))]
    let auto: Option<bool> = None;
    // A terminal prompt with no stdin behind it answers nothing, and the hook
    // waits out its full deadline on every request. Say so and stop instead.
    // Nothing else here reads stdin, so nothing else waits on it.
    let mut stdin_closed: Pin<Box<dyn Future<Output = ()> + Send>> =
        Box::pin(std::future::pending());
    let decider = if let Some(decider) = auto
        .map(Decider::Auto)
        .or_else(|| native_decider(&identity))
    {
        decider
    } else {
        let (prompter, closed) = Prompter::from_stdin();
        stdin_closed = Box::pin(async move {
            let _ = closed.await;
        });
        Decider::Prompt(prompter)
    };
    let decider = Arc::new(decider);
    tokio::spawn(serve_socket(
        socket,
        Arc::clone(&identity),
        Arc::clone(&decider),
    ));
    loop {
        let message = tokio::select! {
            () = &mut stdin_closed => bail!(
                "stdin is closed, so no approval prompt can be answered and every request \
                 would wait out its deadline; run the agent on a terminal"
            ),
            message = async {
                match requests.as_mut() {
                    Some((_, subscription)) => subscription.next().await,
                    None => std::future::pending().await,
                }
            } => message.context("request stream closed")?,
        };
        let envelope: RequestEnvelopeV1 = match serde_json::from_slice(&message.payload) {
            Ok(envelope) => envelope,
            Err(error) => {
                warn!(error = %escape_for_terminal(&error.to_string()), "ignoring malformed request");
                continue;
            }
        };
        let opened = match identity.open_request(&envelope) {
            Ok(Some(opened)) => opened,
            Ok(None) => continue,
            Err(error) => {
                warn!(
                    request_id = %escape_for_terminal(&envelope.request_id),
                    error = %escape_for_terminal(&error.to_string()),
                    "ignoring request"
                );
                continue;
            }
        };
        let identity = Arc::clone(&identity);
        let nats = requests.as_ref().map(|(nats, _)| nats.clone());
        let decider = Arc::clone(&decider);
        tokio::spawn(async move {
            let verdict = decide(&identity, &decider, &opened).await;
            let result = match verdict {
                Ok(Some(decision)) => {
                    if let Some(nats) = nats {
                        publish(&nats, &opened.request, decision).await
                    } else {
                        Ok(())
                    }
                }
                Ok(None) => Ok(()),
                Err(error) => Err(error),
            };
            if let Err(error) = result {
                warn!(
                    request_id = %escape_for_terminal(&opened.request.request_id),
                    error = %escape_for_terminal(&error.to_string()),
                    "decision failed"
                );
            }
        });
    }
}

/// Connect NATS and subscribe to requests, or return `None` when the network
/// is down so the agent answers socket requests only.
async fn subscribe_requests(
    identity: &Identity,
) -> Result<Option<(async_nats::Client, async_nats::Subscriber)>> {
    let nats = match connect_nats().await {
        Ok(nats) => nats,
        Err(error) => {
            warn!(
                error = %escape_for_terminal(&format!("{error:#}")),
                "NATS is unreachable; answering socket requests only until restart"
            );
            return Ok(None);
        }
    };
    let requests = nats
        .subscribe("oshioki.request.>")
        .await
        .context("subscribe requests")?;
    nats.flush().await?;
    info!(fingerprint=%identity.fingerprint(), "watching for requests");
    Ok(Some((nats, requests)))
}

/// Answer one opened request. `Ok(None)` means no verdict was produced —
/// the request expired, nobody answered the prompt, or the Touch ID sheet
/// was dismissed — and the caller must not publish anything. Delivery (NATS
/// or socket) is the caller's job, so every transport shares this decider.
async fn decide(
    identity: &Arc<Identity>,
    decider: &Decider,
    opened: &OpenedRequest,
) -> Result<Option<DecisionV1>> {
    let request = &opened.request;
    if request.expires_at <= now() {
        bail!("request already expired");
    }
    let approve = match decider {
        #[cfg(target_os = "macos")]
        Decider::TouchId(prompt) => {
            // The signature is the approval here, so this path builds the
            // whole decision rather than answering yes or no.
            let Some(decision) = mac::decide(prompt, identity, opened).await? else {
                return Ok(None);
            };
            return Ok(Some(decision));
        }
        Decider::Auto(answer) => *answer,
        Decider::Prompt(prompter) => {
            let summary = format!(
                "sudo on {}: {} (uid {}) wants to run as {}: {} {}\n  cwd: {}\n  callers: {}\n{}",
                escape_for_terminal(&request.host),
                escape_for_terminal(&request.user),
                request.uid,
                runas_label(request.runas_uid),
                escape_for_terminal(&request.command),
                escape_for_terminal(&quote_argv(&request.argv)),
                escape_for_terminal(&request.cwd),
                escape_for_terminal(&request.pid_chain.join(" <- ")),
                format_env(request),
            );
            // No answer means no signed verdict: the hook fails closed when
            // the deadline passes, and a Deny nobody typed would be a lie
            // about a request nobody read.
            let Some(answer) = prompter
                .ask(&request.request_id, &summary, request.expires_at)
                .await?
            else {
                info!(
                    request_id = %escape_for_terminal(&request.request_id),
                    host = %escape_for_terminal(&request.host),
                    "request expired unanswered"
                );
                return Ok(None);
            };
            answer
        }
    };
    let decision = if approve {
        identity.approve(opened, &approval_reason(request))?
    } else {
        identity.deny(&request.request_id)
    };
    Ok(Some(decision))
}

/// The prompt a Mac holding an enclave key uses: the Touch ID sheet itself.
#[cfg(target_os = "macos")]
fn native_decider(identity: &Arc<Identity>) -> Option<Decider> {
    if identity.signer_kind() != SignerKind::Enclave {
        return None;
    }
    info!("approvals are the Touch ID sheet; nothing is read from stdin");
    Some(Decider::TouchId(
        oshioki_agent::touchid::TouchIdPrompt::new(
            Box::new(mac::Screen),
            Arc::new(mac::Canceller(Arc::clone(identity))),
        ),
    ))
}

/// Only a Mac has a native prompt, and only for an enclave key.
#[cfg(not(target_os = "macos"))]
fn native_decider(_identity: &Arc<Identity>) -> Option<Decider> {
    None
}

/// Publishes one decision and says so in the log.
async fn publish(
    nats: &async_nats::Client,
    request: &oshioki_protocol::RequestV1,
    decision: DecisionV1,
) -> Result<()> {
    nats.publish(
        format!("oshioki.verdict.{}", request.request_id),
        serde_json::to_vec(&decision)?.into(),
    )
    .await
    .context("publish decision")?;
    nats.flush().await?;
    let verb = match decision {
        DecisionV1::ApproveNative(_) => "approved",
        DecisionV1::Approve(_) => unreachable!("agent never builds WebAuthn approvals"),
        DecisionV1::Deny(_) => "denied",
    };
    info!(
        request_id = %escape_for_terminal(&request.request_id),
        host = %escape_for_terminal(&request.host),
        verb,
        "decision published"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Local socket — the hook's network-free fast path
// ---------------------------------------------------------------------------

/// File name of the agent socket inside the agent state directory, unless
/// `OSHIOKI_AGENT_SOCKET` overrides it.
const AGENT_SOCKET_NAME: &str = "agent.sock";

/// Resolve the socket path: explicit override first, then the state dir next
/// to the identity. The override is a parameter (rather than read here) so
/// tests do not mutate the process environment.
fn socket_path(
    identity_path: &std::path::Path,
    override_path: Option<std::ffi::OsString>,
) -> Result<PathBuf> {
    if let Some(path) = override_path {
        if path.is_empty() {
            bail!("OSHIOKI_AGENT_SOCKET is set but empty");
        }
        return Ok(PathBuf::from(path));
    }
    identity_path
        .parent()
        .context("identity path has no parent directory")
        .map(|parent| parent.join(AGENT_SOCKET_NAME))
}

/// Bind the agent socket, clearing a stale file left by a dead agent. A
/// live agent on the path is a second instance, which must not silently
/// double-prompt behind the first one, so that case is an error. Anything
/// that is not a socket file is never deleted.
fn bind_socket(path: &std::path::Path) -> Result<tokio::net::UnixListener> {
    if let Ok(listener) = tokio::net::UnixListener::bind(path) {
        restrict_socket(path)?;
        return Ok(listener);
    }
    if !std::fs::symlink_metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .file_type()
        .is_socket()
    {
        bail!("socket path {} exists and is not a socket", path.display());
    }
    // The path is a socket file. If someone answers there, they own it.
    if std::os::unix::net::UnixStream::connect(path).is_ok() {
        bail!("another agent is already listening on {}", path.display());
    }
    std::fs::remove_file(path)
        .with_context(|| format!("remove stale socket {}", path.display()))?;
    let listener =
        tokio::net::UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))?;
    restrict_socket(path)?;
    Ok(listener)
}

/// Owner-only permissions on the socket file. The state directory already
/// gates access, but a socket that outlives a permissive umask should not
/// stay world-accessible.
fn restrict_socket(path: &std::path::Path) -> Result<()> {
    let mut permissions = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions)
        .with_context(|| format!("chmod {}", path.display()))?;
    Ok(())
}

/// Accept hook connections forever. One failing accept must not kill the
/// listener, so errors are logged with a breather instead of propagated.
async fn serve_socket(
    listener: tokio::net::UnixListener,
    identity: Arc<Identity>,
    decider: Arc<Decider>,
) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                warn!(
                    error = %escape_for_terminal(&error.to_string()),
                    "agent socket accept failed"
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let identity = Arc::clone(&identity);
        let decider = Arc::clone(&decider);
        tokio::spawn(async move {
            if let Err(error) = handle_socket(stream, &identity, &decider).await {
                warn!(
                    error = %escape_for_terminal(&error.to_string()),
                    "socket request failed"
                );
            }
        });
    }
}

/// Answer one hook connection: one framed envelope in, one framed verdict
/// out. Hanging up without a verdict means this agent is not answering, and
/// the hook falls back to NATS, where another agent may.
async fn handle_socket(
    stream: tokio::net::UnixStream,
    identity: &Arc<Identity>,
    decider: &Decider,
) -> Result<()> {
    let (mut reader, mut writer) = stream.into_split();
    let Some(bytes) = read_frame(&mut reader).await? else {
        return Ok(());
    };
    let envelope: RequestEnvelopeV1 =
        serde_json::from_slice(&bytes).context("decode socket envelope")?;
    let opened = match identity.open_request(&envelope) {
        Ok(Some(opened)) => opened,
        Ok(None) => return Ok(()),
        Err(error) => {
            warn!(
                request_id = %escape_for_terminal(&envelope.request_id),
                error = %escape_for_terminal(&error.to_string()),
                "ignoring socket request"
            );
            return Ok(());
        }
    };
    let Some(decision) = decide(identity, decider, &opened).await? else {
        return Ok(());
    };
    let frame = oshioki_protocol::socket_v1::encode_frame(&serde_json::to_vec(&decision)?)?;
    writer
        .write_all(&frame)
        .await
        .context("write socket verdict")?;
    info!(
        request_id = %escape_for_terminal(&opened.request.request_id),
        "socket decision answered"
    );
    Ok(())
}

/// Read one length-delimited frame. A peer that hangs up before delivering
/// one has not answered.
async fn read_frame(reader: &mut tokio::net::unix::OwnedReadHalf) -> Result<Option<Vec<u8>>> {
    let mut prefix = [0u8; oshioki_protocol::socket_v1::FRAME_LEN_BYTES];
    match reader.read_exact(&mut prefix).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let len = oshioki_protocol::socket_v1::decode_frame_len(prefix)?;
    let mut payload = vec![0u8; len];
    match reader.read_exact(&mut payload).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    Ok(Some(payload))
}

/// Renders argv so the boundaries between arguments are visible.
///
/// Joined with plain spaces, `["/tmp/a b"]` and `["/tmp/a", "b"]` render
/// identically, and the operator approves the wrong one of the two. Every
/// argument that is not plainly printable, including the empty one, is
/// wrapped in shell single quotes instead.
fn quote_argv(argv: &[String]) -> String {
    argv.iter()
        .map(|argument| quote_argument(argument))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Single-quotes one argument unless every byte of it is unambiguous.
///
/// The escape is the shell's own: a single quote ends the quoted run, adds a
/// backslash-escaped quote, and opens the next run.
fn quote_argument(argument: &str) -> String {
    let plain = !argument.is_empty()
        && argument
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "@%+=:,./-_".contains(character));
    if plain {
        argument.to_owned()
    } else {
        format!("'{}'", argument.replace('\'', r"'\''"))
    }
}

/// Names the account the command would run as.
///
/// The target is what the approval actually grants, so the prompt always
/// shows it, including sudo's default of root. The name is derived from the
/// number rather than resolved on this device: the account lives on the
/// requesting host, whose passwd file this device cannot read, and only uid 0
/// means the same thing everywhere.
fn runas_label(runas_uid: u32) -> String {
    if runas_uid == 0 {
        "root (uid 0)".to_owned()
    } else {
        format!("uid {runas_uid}")
    }
}

/// Where a verdict comes from: the Touch ID sheet on a Mac holding an enclave
/// key, the terminal otherwise, or a fixed answer when the `unattended`
/// feature's `--auto` flag was given.
enum Decider {
    Auto(bool),
    Prompt(Prompter),
    #[cfg(target_os = "macos")]
    TouchId(oshioki_agent::touchid::TouchIdPrompt),
}

/// What the operator is being asked to allow, in the second person.
///
/// The Touch ID sheet reads "Oshioki is trying to `<this>`. Touch ID to allow
/// this", and it is one line on somebody's screen. It carries the arguments,
/// rendered exactly as the terminal prompt renders them: `rm` and `rm -rf /`
/// are different requests and must not read the same. The working directory
/// and the caller process chain go to the log instead, where there is room.
fn approval_reason(request: &oshioki_protocol::RequestV1) -> String {
    // Truncate before escaping. escape_for_terminal turns one byte into a
    // multi-character sequence, and a cut through the middle of one would put
    // half an escape on the sheet.
    let command = truncate(
        &format!("{} {}", request.command, quote_argv(&request.argv)),
        MAX_COMMAND_CHARS,
    );
    // The sheet has room for one line, so a request carrying environment
    // only announces how much: the count tells the approver something is
    // bound beyond the command, and the signature binds the values.
    let env = if request.env.is_empty() {
        String::new()
    } else {
        format!(" (+{} env)", request.env.len())
    };
    format!(
        "run {} as {} on {}{}",
        escape_for_terminal(command.trim_end()),
        runas_label(request.runas_uid),
        escape_for_terminal(&truncate(&request.host, MAX_HOST_CHARS)),
        env,
    )
}

/// The bound environment as approver-visible lines, empty when the request
/// carries none. Terminal prompts show these; the Touch ID sheet only has
/// room for a count (see [`approval_reason`]).
///
/// Both dimensions are bounded: values are attacker-controlled and can be
/// kilobytes each, and lines print after the command block just before the
/// prompt, so an unbounded environment would scroll the command off the
/// approver's screen. Truncation is display-only; the signature still binds
/// the whole values.
fn format_env(request: &oshioki_protocol::RequestV1) -> String {
    use std::fmt::Write as _;
    let mut shown = String::new();
    for entry in request.env.iter().take(MAX_ENV_LINES_SHOWN) {
        // Truncate before escaping, as in approval_reason: escaping turns
        // one byte into several characters, and a cut through the middle of
        // one would put half an escape on the screen.
        let _ = writeln!(
            shown,
            "  env {}={}",
            escape_for_terminal(&truncate(&entry.name, MAX_ENV_NAME_CHARS)),
            escape_for_terminal(&truncate(&entry.value, MAX_ENV_VALUE_CHARS))
        );
    }
    if request.env.len() > MAX_ENV_LINES_SHOWN {
        let _ = writeln!(
            shown,
            "  ... ({} more)",
            request.env.len() - MAX_ENV_LINES_SHOWN
        );
    }
    shown
}

/// How much of one environment name the terminal prompt shows. Allowlisted
/// names are short; this only caps a hostile one.
const MAX_ENV_NAME_CHARS: usize = 64;

/// How much of one environment value the terminal prompt shows. Enough to
/// recognize a PATH, not enough to fill a screen.
const MAX_ENV_VALUE_CHARS: usize = 128;

/// How many bound variables the terminal prompt lists before summarizing
/// the rest.
const MAX_ENV_LINES_SHOWN: usize = 10;

/// How much of the command line the sheet gets. Past this it is not a sentence
/// anybody reads before touching the sensor.
const MAX_COMMAND_CHARS: usize = 100;

/// How much of the host name the sheet gets. Long enough for any real name.
const MAX_HOST_CHARS: usize = 64;

/// Shortens to `limit` characters, marking that it was shortened.
fn truncate(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_owned();
    }
    let kept: String = text.chars().take(limit.saturating_sub(3)).collect();
    format!("{kept}...")
}

/// The terminal prompt, serialized across concurrent requests.
///
/// Stdin is read by one long-lived task feeding a channel. A reader started
/// per prompt would outlive a timed-out prompt and swallow the answer meant
/// for the next one.
struct Prompter {
    lines: Mutex<mpsc::Receiver<String>>,
}

impl Prompter {
    /// Reads lines from stdin. The returned receiver fires when the reader
    /// reaches end of file, which with a closed stdin happens at startup.
    fn from_stdin() -> (Self, oneshot::Receiver<()>) {
        Self::from_reader(io::BufReader::new(io::stdin()))
    }

    fn from_reader(reader: impl BufRead + Send + 'static) -> (Self, oneshot::Receiver<()>) {
        let (sender, receiver) = mpsc::channel(8);
        let (closed_sender, closed_receiver) = oneshot::channel();
        std::thread::spawn(move || {
            for line in reader.lines() {
                let Ok(line) = line else { break };
                if sender.blocking_send(line).is_err() {
                    return;
                }
            }
            let _ = closed_sender.send(());
        });
        (Self::new(receiver), closed_receiver)
    }

    fn new(lines: mpsc::Receiver<String>) -> Self {
        Self {
            lines: Mutex::new(lines),
        }
    }

    /// Asks the terminal about one request. Any answer other than `y` denies.
    ///
    /// Returns `None` when `expires_at` passes first, either while queued
    /// behind another prompt or while waiting for an answer: the request is
    /// dead by then and the caller must not sign anything for it. Lines typed
    /// before the prompt appeared are discarded, so a stale answer never
    /// decides a later request.
    async fn ask(&self, request_id: &str, summary: &str, expires_at: i64) -> Result<Option<bool>> {
        let mut lines = self.lines.lock().await;
        let Some(remaining) = remaining_until(expires_at) else {
            return Ok(None);
        };
        while lines.try_recv().is_ok() {}
        print!(
            "{}",
            prompt_output(request_id, summary, io::stdout().is_terminal())
        );
        io::stdout().flush()?;
        match tokio::time::timeout(remaining, lines.recv()).await {
            Ok(Some(answer)) => Ok(Some(answer.trim().eq_ignore_ascii_case("y"))),
            Ok(None) => bail!("stdin closed"),
            Err(_) => {
                println!("\nrequest expired before it was answered");
                Ok(None)
            }
        }
    }
}

/// What one terminal prompt may print. Stdout backs the persistent agent log
/// when launchd runs the agent, so the request summary — user, command,
/// arguments, directory, callers — is only rendered to a live terminal.
/// Anywhere else the opaque request id is all that is printed: an operator
/// answering there is approving blind, and the log must not carry the
/// request to make it readable.
fn prompt_output(request_id: &str, summary: &str, stdout_is_terminal: bool) -> String {
    if stdout_is_terminal {
        format!("{summary}Approve? [y/N] ")
    } else {
        format!(
            "request {} needs an answer, but stdout is not a terminal: \
             no request details are shown here\nApprove? [y/N] ",
            escape_for_terminal(request_id)
        )
    }
}

async fn connect_nats() -> Result<async_nats::Client> {
    let url = std::env::var("NATS_URL").context("NATS_URL is not set")?;
    let mut options = async_nats::ConnectOptions::new();
    // Half a credential is a misconfiguration, not a request for an anonymous
    // connection; the hook and the server both require the pair.
    match (std::env::var("NATS_USER"), std::env::var("NATS_PASS")) {
        (Ok(user), Ok(pass)) => options = options.user_and_password(user, pass),
        (Err(_), Err(_)) => {}
        _ => bail!("set both NATS_USER and NATS_PASS, or neither"),
    }
    check_nats_url(
        &url,
        allow_plaintext_nats(std::env::var(ALLOW_PLAINTEXT_NATS_ENV).ok().as_deref()),
    )
    .context("invalid NATS_URL")?;
    // A tls:// URL must stay TLS past the first server: the cluster
    // advertises more addresses on reconnect as bare host:port, which parse
    // as plaintext, so the options flag carries the requirement with them.
    if nats_url_is_tls(&url) {
        options = options.require_tls(true);
    }
    options.connect(&url).await.context("connect to NATS")
}

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// The Touch ID sheet, and the two macOS facts the prompt needs: whether the
/// screen is locked, and how to tear a sheet down at a deadline.
#[cfg(target_os = "macos")]
mod mac {
    use std::sync::Arc;

    use anyhow::Result;
    use oshioki_agent::{
        Identity, OpenedRequest,
        touchid::{AttemptError, Outcome, PromptCancel, ScreenLock, TouchIdPrompt},
    };
    use oshioki_enclave::SignError;
    use oshioki_protocol::{DecisionV1, escape_for_terminal};
    use tracing::{error, info};

    use super::approval_reason;

    /// The login session's lock state, read fresh each time it is asked for.
    pub struct Screen;

    impl ScreenLock for Screen {
        fn is_locked(&self) -> bool {
            oshioki_enclave::screen_is_locked()
        }
    }

    /// Dismisses the sheet the agent's own signing key is showing.
    pub struct Canceller(pub Arc<Identity>);

    impl PromptCancel for Canceller {
        fn begin(&self) -> u64 {
            self.0.begin_prompt()
        }
        fn cancel(&self, attempt: u64) {
            self.0.cancel_prompt(attempt);
        }
    }

    /// Asks for one request with a Touch ID sheet.
    ///
    /// Returns the decision to publish, or `None` when there is nothing to
    /// publish: the deadline passed with no answer, or the enclave refused and
    /// the operator has been told to re-pair.
    pub async fn decide(
        prompt: &TouchIdPrompt,
        identity: &Arc<Identity>,
        opened: &OpenedRequest,
    ) -> Result<Option<DecisionV1>> {
        let request = &opened.request;
        let reason = approval_reason(request);
        // The sheet has room for one line, so the reason is shown there and
        // only there: stdout and stderr both back the persistent agent log
        // under launchd, and the command line can carry credentials. The log
        // gets the opaque request id, nothing that identifies the request.
        info!(
            request_id = %escape_for_terminal(&request.request_id),
            "asking for Touch ID"
        );
        let sign = {
            let (identity, opened, reason) = (Arc::clone(identity), opened.clone(), reason.clone());
            move || identity.approve(&opened, &reason).map_err(classify)
        };
        match prompt
            .ask(&request.request_id, request.expires_at, sign)
            .await
        {
            Ok(Outcome::Approved(decision)) => Ok(Some(decision)),
            Ok(Outcome::Denied) => Ok(Some(identity.deny(&request.request_id))),
            Ok(Outcome::Expired) => {
                info!(
                    request_id = %escape_for_terminal(&request.request_id),
                    host = %escape_for_terminal(&request.host),
                    "request expired unanswered"
                );
                Ok(None)
            }
            Err(error) => {
                // Not a verdict: the key is unusable, not refused. Biometry
                // re-enrollment invalidates it permanently, and a new key means
                // a new fingerprint for the host to pin.
                error!(
                    request_id = %escape_for_terminal(&request.request_id),
                    error = %escape_for_terminal(&format!("{error:#}")),
                    "the Secure Enclave would not sign; re-pair with `oshioki-agent pair`"
                );
                Ok(None)
            }
        }
    }

    /// A dismissed sheet is an answer; anything else is a broken key.
    fn classify(error: anyhow::Error) -> AttemptError {
        if matches!(error.downcast_ref::<SignError>(), Some(SignError::Canceled)) {
            AttemptError::Canceled
        } else {
            AttemptError::Failed(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Decider, MAX_ENV_LINES_SHOWN, Pairing, Prompter, approval_reason, bind_socket, decide,
        format_env, load_or_create, now, prompt_output, quote_argv, runas_label, socket_path,
        truncate,
    };
    use oshioki_agent::SignerKind;
    use oshioki_protocol::{
        EnvEntryV1, RequestEnvelopeV1, RequestV1, VERSION_V1, encode_base64url,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::sync::mpsc;

    fn request_for_reason() -> RequestV1 {
        RequestV1 {
            version: VERSION_V1,
            request_id: "req-1".into(),
            nonce: encode_base64url(&[1; 16]),
            host: "host.example".into(),
            user: "eric".into(),
            uid: 1000,
            runas_uid: 0,
            cwd: "/home/eric".into(),
            tty: None,
            command: "/usr/bin/apt".into(),
            argv: vec!["apt".into(), "update".into()],
            pid_chain: vec![],
            env: vec![],
            issued_at: 1_000,
            expires_at: 1_090,
        }
    }

    /// One argument holding a space and two arguments are different requests,
    /// so they must not render as the same line.
    #[test]
    fn argument_boundaries_survive_rendering() {
        assert_ne!(
            quote_argv(&["/tmp/a b".to_owned()]),
            quote_argv(&["/tmp/a".to_owned(), "b".to_owned()])
        );
        assert_eq!(quote_argv(&["/tmp/a b".to_owned()]), "'/tmp/a b'");
        assert_eq!(
            quote_argv(&["/tmp/a".to_owned(), "b".to_owned()]),
            "/tmp/a b"
        );
        // An empty argument is a real argument and has to be visible.
        assert_eq!(
            quote_argv(&["rm".to_owned(), String::new(), "-rf".to_owned()]),
            "rm '' -rf"
        );
        // The shell's own escape for a quote inside a quoted run.
        assert_eq!(quote_argv(&["it's".to_owned()]), r"'it'\''s'");
        // Anything not plainly printable is quoted, quotation marks included.
        assert_eq!(quote_argv(&["a\"b".to_owned()]), "'a\"b'");
        assert_eq!(quote_argv(&["a\tb".to_owned()]), "'a\tb'");
        assert_eq!(
            quote_argv(&["-rf".to_owned(), "/var/log".to_owned()]),
            "-rf /var/log"
        );
        assert_eq!(quote_argv(&[]), "");
    }

    /// The prompt names the target account for every request, including the
    /// root default that sudo leaves implicit.
    #[test]
    fn target_account_is_always_named() {
        assert_eq!(runas_label(0), "root (uid 0)");
        assert_eq!(runas_label(1000), "uid 1000");
    }

    /// The Touch ID sheet gets one sentence: what would run, as whom, where.
    /// The arguments are in it, because `rm` and `rm -rf /` are different
    /// requests and one fingerprint answers only one of them.
    #[test]
    fn the_sheet_reason_names_the_command_the_account_and_the_host() {
        let mut request = request_for_reason();
        assert_eq!(
            approval_reason(&request),
            "run /usr/bin/apt apt update as root (uid 0) on host.example"
        );
        request.runas_uid = 1000;
        assert!(approval_reason(&request).contains("as uid 1000"));

        let mut dangerous = request_for_reason();
        dangerous.command = "/bin/rm".into();
        dangerous.argv = vec!["rm".into()];
        let mut worse = dangerous.clone();
        worse.argv = vec!["rm".into(), "-rf".into(), "/".into()];
        assert_ne!(approval_reason(&dangerous), approval_reason(&worse));
        assert!(approval_reason(&worse).contains("rm -rf /"));

        // A command with no arguments must not trail a space onto the sheet.
        let mut bare = request_for_reason();
        bare.argv = vec![];
        assert_eq!(
            approval_reason(&bare),
            "run /usr/bin/apt as root (uid 0) on host.example"
        );
    }

    /// The terminal summary shows the bound environment line by line, while
    /// an empty environment shows nothing; the sheet reason only announces
    /// the count, because one line cannot hold the values.
    #[test]
    fn summary_shows_the_bound_environment() {
        let mut request = request_for_reason();
        assert!(!format_env(&request).contains("env "));
        assert!(!approval_reason(&request).contains("env)"));
        request.env = vec![
            EnvEntryV1 {
                name: "LD_PRELOAD".into(),
                value: "/tmp/evil.so".into(),
            },
            EnvEntryV1 {
                name: "PATH".into(),
                value: "/tmp/bin:/usr/bin".into(),
            },
        ];
        let shown = format_env(&request);
        assert!(shown.contains("  env LD_PRELOAD=/tmp/evil.so\n"), "{shown}");
        assert!(shown.contains("  env PATH=/tmp/bin:/usr/bin\n"), "{shown}");
        let reason = approval_reason(&request);
        assert!(reason.ends_with(" (+2 env)"), "{reason}");
    }

    /// A hostile environment cannot scroll the command off the screen: long
    /// values are cut and the list is capped with a count of what is hidden.
    #[test]
    fn a_hostile_environment_stays_bounded() {
        let mut request = request_for_reason();
        request.env = (0..64)
            .map(|n| EnvEntryV1 {
                name: format!("PATH{n}"),
                value: "x".repeat(1024),
            })
            .collect();
        let shown = format_env(&request);
        assert_eq!(shown.lines().count(), MAX_ENV_LINES_SHOWN + 1, "{shown}");
        assert!(shown.ends_with("  ... (54 more)\n"), "{shown}");
        assert!(shown.contains("..."), "{shown}");
        assert!(!shown.contains(&"x".repeat(129)), "{shown}");
        // The count still announces the binding on the one-line sheet.
        assert!(approval_reason(&request).ends_with(" (+64 env)"));
    }

    /// Same command, different environments: the signatures differ, because
    /// the signature covers the raw request bytes and the environment is
    /// part of them.
    #[test]
    fn approvals_differ_by_environment() {
        let dir = std::env::temp_dir().join(format!("oshioki-env-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pairing = Pairing {
            requested: None,
            default: SignerKind::Software,
            force: false,
        };
        let identity = load_or_create(&dir.join("agent.json"), &pairing).unwrap();
        let sign = |env: Vec<EnvEntryV1>| {
            let mut request = request_for_reason();
            request.env = env;
            let raw = request.raw_json().unwrap();
            let opened = oshioki_agent::OpenedRequest { request, raw };
            match identity
                .approve(&opened, &approval_reason(&opened.request))
                .unwrap()
            {
                oshioki_protocol::DecisionV1::ApproveNative(approval) => approval.signature,
                other => panic!("expected an approval, got {other:?}"),
            }
        };
        let bare = sign(vec![]);
        let one = sign(vec![EnvEntryV1 {
            name: "PATH".into(),
            value: "/a".into(),
        }]);
        let other = sign(vec![EnvEntryV1 {
            name: "PATH".into(),
            value: "/b".into(),
        }]);
        assert_ne!(bare, one);
        assert_ne!(one, other);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A command line long enough to fill the screen is cut, and says so.
    #[test]
    fn a_long_reason_is_cut_rather_than_wrapped() {
        assert_eq!(truncate("abcdef", 6), "abcdef");
        assert_eq!(truncate("abcdefg", 6), "abc...");
        let mut request = request_for_reason();
        request.command = "/usr/bin/".to_owned() + &"x".repeat(400);
        let reason = approval_reason(&request);
        assert!(reason.contains("..."));
        assert!(reason.chars().count() < 200, "{reason}");
    }

    /// Cutting the rendered command before escaping keeps whole escape
    /// sequences on the sheet. Cutting after would leave half of one.
    #[test]
    fn truncation_never_splits_an_escape_sequence() {
        let mut request = request_for_reason();
        request.command = "/usr/bin/x".to_owned();
        request.argv = vec!["x".to_owned(), "\u{1b}[31m".repeat(60)];
        let reason = approval_reason(&request);
        assert!(
            !reason.contains('\u{1b}'),
            "an escape byte reached the sheet"
        );
        // Every rendered escape is whole: `\u{` then four hex digits and `}`.
        let mut rest = reason.as_str();
        let mut rendered = 0;
        while let Some(at) = rest.find("\\u{") {
            let tail = &rest[at + 3..];
            let (digits, closer) = tail.split_at(tail.len().min(4));
            assert!(
                digits.chars().count() == 4 && digits.chars().all(|c| c.is_ascii_hexdigit()),
                "a cut landed inside an escape: {reason}"
            );
            assert!(
                closer.starts_with('}'),
                "a cut landed inside an escape: {reason}"
            );
            rendered += 1;
            rest = &tail[4..];
        }
        assert!(rendered > 0, "{reason}");
    }

    /// One identity serves every host, so a second `pair` reuses it. A
    /// `--signer` that disagrees with it cannot be honoured, and a flag that
    /// quietly does nothing is worse than a refusal.
    #[test]
    fn pairing_reuses_an_identity_and_refuses_to_pretend_otherwise() {
        let dir = std::env::temp_dir().join(format!("oshioki-pair-{}", std::process::id()));
        let path = dir.join("agent.json");
        let _ = std::fs::remove_dir_all(&dir);
        let pairing = |requested, force| Pairing {
            requested,
            default: SignerKind::Software,
            force,
        };

        let created = load_or_create(&path, &pairing(None, false)).unwrap();
        let reused = load_or_create(&path, &pairing(None, false)).unwrap();
        assert_eq!(created.fingerprint(), reused.fingerprint());
        let asked_for_the_same = load_or_create(&path, &pairing(Some(SignerKind::Software), false));
        assert_eq!(
            asked_for_the_same.unwrap().fingerprint(),
            created.fingerprint()
        );

        let Err(error) = load_or_create(&path, &pairing(Some(SignerKind::Enclave), false)) else {
            panic!("a mismatched --signer was accepted");
        };
        let error = error.to_string();
        assert!(error.contains("software"), "{error}");
        assert!(error.contains("--force"), "{error}");

        // --force replaces the identity, so the device is a new one and the
        // host's old record for it is stale.
        let replaced = load_or_create(&path, &pairing(None, true)).unwrap();
        assert_ne!(replaced.fingerprint(), created.fingerprint());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An answer typed before the prompt appeared belongs to whatever the
    /// operator was looking at then, not to this request.
    #[tokio::test]
    async fn discards_answers_typed_before_the_prompt() {
        let (sender, receiver) = mpsc::channel(8);
        let prompter = Prompter::new(receiver);
        sender.send("y".into()).await.unwrap();
        let typed = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            sender.send("n".into()).await.unwrap();
            sender
        });
        assert_eq!(
            prompter
                .ask("req-test", "summary\n", now() + 30)
                .await
                .unwrap(),
            Some(false)
        );
        drop(typed.await.unwrap());
    }

    /// A request whose deadline passed while it queued behind another prompt
    /// is never shown and never answered, so nothing gets signed for it.
    #[tokio::test]
    async fn skips_an_expired_request_without_reading_stdin() {
        let (sender, receiver) = mpsc::channel(8);
        let prompter = Prompter::new(receiver);
        sender.send("y".into()).await.unwrap();
        assert_eq!(
            prompter
                .ask("req-test", "summary\n", now() - 1)
                .await
                .unwrap(),
            None
        );
        // The queued line is still there: no answer was consumed.
        assert_eq!(
            prompter.lines.lock().await.try_recv().unwrap(),
            "y".to_owned()
        );
    }

    /// A closed stdin is reported at once, not one hung request at a time.
    #[tokio::test]
    async fn reports_a_reader_that_cannot_answer() {
        let (prompter, closed) = Prompter::from_reader(std::io::empty());
        closed.await.unwrap();
        assert!(
            prompter
                .ask("req-test", "summary\n", now() + 30)
                .await
                .is_err()
        );
    }

    /// The prompt stops at the expiry instant itself. Whole-second
    /// arithmetic let it wait most of a second past a dead request and sign
    /// for it.
    #[tokio::test]
    async fn prompt_stops_at_the_exact_deadline() {
        let (sender, receiver) = mpsc::channel(8);
        let prompter = Prompter::new(receiver);
        let expires_at = now() + 1;
        assert_eq!(
            prompter
                .ask("req-test", "summary\n", expires_at)
                .await
                .unwrap(),
            None
        );
        let overshoot = time::OffsetDateTime::now_utc()
            - time::OffsetDateTime::from_unix_timestamp(expires_at).unwrap();
        assert!(
            overshoot < time::Duration::milliseconds(250),
            "waited {overshoot} past the deadline"
        );
        drop(sender);
    }

    /// Waiting out the deadline is silence, not a denial.
    #[tokio::test]
    async fn unanswered_prompt_yields_no_verdict() {
        let (sender, receiver) = mpsc::channel(8);
        let prompter = Prompter::new(receiver);
        assert_eq!(
            prompter
                .ask("req-test", "summary\n", now() + 1)
                .await
                .unwrap(),
            None
        );
        drop(sender);
    }

    fn socket_test_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "oshioki-agent-socket-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn socket_defaults_to_the_state_dir() {
        let dir = socket_test_dir("default");
        let path = socket_path(&dir.join("agent.json"), None).unwrap();
        assert_eq!(path, dir.join("agent.sock"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn socket_override_wins_over_the_state_dir() {
        let dir = socket_test_dir("override");
        let path = socket_path(
            &dir.join("agent.json"),
            Some(std::ffi::OsString::from("/tmp/custom-agent.sock")),
        )
        .unwrap();
        assert_eq!(path, std::path::PathBuf::from("/tmp/custom-agent.sock"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_socket_override_is_an_error() {
        let dir = socket_test_dir("empty");
        assert!(socket_path(&dir.join("agent.json"), Some(std::ffi::OsString::new())).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn stale_socket_file_is_reclaimed() {
        let dir = socket_test_dir("stale");
        let path = dir.join("agent.sock");
        {
            let _dead = tokio::net::UnixListener::bind(&path).unwrap();
        }
        let listener = bind_socket(&path).unwrap();
        drop(listener);
        assert!(path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn live_socket_refuses_a_second_agent() {
        let dir = socket_test_dir("live");
        let path = dir.join("agent.sock");
        let _first = bind_socket(&path).unwrap();
        let second = bind_socket(&path);
        assert!(second.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn regular_file_is_never_deleted_as_a_socket() {
        let dir = socket_test_dir("regular");
        let path = dir.join("agent.sock");
        std::fs::write(&path, "not a socket").unwrap();
        assert!(bind_socket(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"not a socket");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A sealed request for this test's own identity, the way the hook seals
    /// one envelope per active device.
    #[cfg(feature = "unattended")]
    fn sealed_envelope_for(
        identity: &oshioki_agent::Identity,
        request: &oshioki_protocol::RequestV1,
    ) -> Vec<u8> {
        use oshioki_protocol::RequestEnvelopeV1;
        let raw = request.raw_json().unwrap();
        let sealed = oshioki_protocol::seal_v1(&raw, &identity.device_record("test")).unwrap();
        let envelope = RequestEnvelopeV1 {
            version: oshioki_protocol::VERSION_V1,
            request_id: request.request_id.clone(),
            host: request.host.clone(),
            user: request.user.clone(),
            issued_at: request.issued_at,
            expires_at: request.expires_at,
            sealed: vec![sealed],
        };
        envelope.validate().unwrap();
        serde_json::to_vec(&envelope).unwrap()
    }

    /// Drive `handle_socket` with one connected pair: frame in, verdict out.
    /// `Auto` needs the `unattended` feature, so this whole happy-path test
    /// only exists in the E2E build, like `run --auto` itself.
    #[cfg(feature = "unattended")]
    async fn socket_verdict(
        identity: std::sync::Arc<oshioki_agent::Identity>,
        approve: bool,
        envelope: &[u8],
    ) -> oshioki_protocol::DecisionV1 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut hook_side, agent_side) = tokio::net::UnixStream::pair().unwrap();
        let serve = tokio::spawn(async move {
            let decider = super::Decider::Auto(approve);
            super::handle_socket(agent_side, &identity, &decider).await
        });
        let frame = oshioki_protocol::socket_v1::encode_frame(envelope).unwrap();
        hook_side.write_all(&frame).await.unwrap();
        let mut prefix = [0u8; oshioki_protocol::socket_v1::FRAME_LEN_BYTES];
        hook_side.read_exact(&mut prefix).await.unwrap();
        let len = usize::try_from(u32::from_be_bytes(prefix)).unwrap();
        let mut verdict = vec![0u8; len];
        hook_side.read_exact(&mut verdict).await.unwrap();
        serve.await.unwrap().unwrap();
        serde_json::from_slice(&verdict).unwrap()
    }

    /// The full local loop with an auto-approving agent: the sealed envelope
    /// comes back as a signed native approval for the same request.
    #[cfg(feature = "unattended")]
    #[tokio::test]
    async fn socket_auto_approve_returns_a_signed_verdict() {
        let dir = socket_test_dir("happy");
        let identity = oshioki_agent::Identity::generate_to(
            &dir.join("agent.json"),
            oshioki_agent::SignerKind::Software,
        )
        .unwrap();
        let mut request = request_for_reason();
        request.issued_at = now();
        request.expires_at = now() + 60;
        let envelope = sealed_envelope_for(&identity, &request);
        let identity = std::sync::Arc::new(identity);
        match socket_verdict(identity.clone(), true, &envelope).await {
            oshioki_protocol::DecisionV1::ApproveNative(approval) => {
                assert_eq!(approval.request_id, request.request_id);
                assert_eq!(approval.device_fingerprint, identity.fingerprint());
            }
            other => panic!("expected a native approval, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Auto-deny travels the same path back as an explicit denial.
    #[cfg(feature = "unattended")]
    #[tokio::test]
    async fn socket_auto_deny_returns_a_denial() {
        let dir = socket_test_dir("deny");
        let identity = oshioki_agent::Identity::generate_to(
            &dir.join("agent.json"),
            oshioki_agent::SignerKind::Software,
        )
        .unwrap();
        let mut request = request_for_reason();
        request.issued_at = now();
        request.expires_at = now() + 60;
        let envelope = sealed_envelope_for(&identity, &request);
        let identity = std::sync::Arc::new(identity);
        match socket_verdict(identity.clone(), false, &envelope).await {
            oshioki_protocol::DecisionV1::Deny(denial) => {
                assert_eq!(denial.request_id, request.request_id);
            }
            other => panic!("expected a denial, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The prompt renders the request to a live terminal only. Stdout backs
    /// the persistent agent log under launchd, so anywhere else the summary
    /// stays out and the opaque request id is all that is printed.
    #[test]
    fn prompt_hides_the_request_without_a_terminal() {
        let summary = "sudo on host: user runs /bin/secret --token abc\n  cwd: /tmp\n";
        let shown = prompt_output("req-1", summary, true);
        assert!(shown.contains(summary), "{shown}");
        let hidden = prompt_output("req-1", summary, false);
        assert!(hidden.contains("req-1"), "{hidden}");
        assert!(!hidden.contains("/bin/secret"), "{hidden}");
        assert!(!hidden.contains("--token abc"), "{hidden}");
    }

    /// Marker that request-shaped tracing tests hunt for. Plain ASCII so the
    /// terminal escaping passes it through visibly: if it reached the log,
    /// this test would see it.
    const LOG_PROBE: &str = "OQ-LOGPROBE-7f3a9c";

    /// A request carrying the marker in every field the log must never see:
    /// command, arguments, working directory, user, and process chain.
    fn request_for_log_probe() -> RequestV1 {
        RequestV1 {
            version: VERSION_V1,
            request_id: "req-logprobe-1".into(),
            nonce: encode_base64url(&[7; 16]),
            host: "host.example".into(),
            user: format!("user-{LOG_PROBE}"),
            uid: 1000,
            runas_uid: 0,
            cwd: format!("/tmp/{LOG_PROBE}"),
            tty: None,
            command: format!("/tmp/{LOG_PROBE}/do"),
            argv: vec!["do".into(), format!("--token={LOG_PROBE}")],
            pid_chain: vec![format!("{LOG_PROBE}:4242")],
            env: vec![],
            issued_at: now(),
            expires_at: now() + 60,
        }
    }

    /// Seal one envelope the way the hook seals one per active device.
    /// Unlike `sealed_envelope_for` this is not gated on `unattended`: seal
    /// and open work with a software key in every build.
    fn sealed_envelope_bytes(identity: &oshioki_agent::Identity, request: &RequestV1) -> Vec<u8> {
        let raw = request.raw_json().unwrap();
        let sealed = oshioki_protocol::seal_v1(&raw, &identity.device_record("test")).unwrap();
        let envelope = RequestEnvelopeV1 {
            version: VERSION_V1,
            request_id: request.request_id.clone(),
            host: request.host.clone(),
            user: request.user.clone(),
            issued_at: request.issued_at,
            expires_at: request.expires_at,
            sealed: vec![sealed],
        };
        envelope.validate().unwrap();
        serde_json::to_vec(&envelope).unwrap()
    }

    /// Tracing events captured into memory, so the test can prove request
    /// plaintext never reaches the log while the agent decides.
    #[derive(Clone, Default)]
    struct CapturedLogs(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl CapturedLogs {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    struct CapturedGuard<'a>(std::sync::MutexGuard<'a, Vec<u8>>);

    impl std::io::Write for CapturedGuard<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
        type Writer = CapturedGuard<'a>;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedGuard(self.0.lock().unwrap())
        }
    }

    /// A terminal prompter with a canned answer, so `decide` runs without a
    /// keyboard. The answer arrives after the prompt appears: lines already
    /// queued are stale input and `ask` discards them.
    fn canned_prompter(answer: &str) -> (Prompter, tokio::task::JoinHandle<mpsc::Sender<String>>) {
        let (sender, receiver) = mpsc::channel(8);
        let answer = answer.to_owned();
        let delivery = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            sender.send(answer).await.unwrap();
            sender
        });
        (Prompter::new(receiver), delivery)
    }

    #[cfg(target_os = "macos")]
    struct UnlockedScreen;

    #[cfg(target_os = "macos")]
    impl oshioki_agent::touchid::ScreenLock for UnlockedScreen {
        fn is_locked(&self) -> bool {
            false
        }
    }

    #[cfg(target_os = "macos")]
    struct NoopCanceller;

    #[cfg(target_os = "macos")]
    impl oshioki_agent::touchid::PromptCancel for NoopCanceller {
        fn begin(&self) -> u64 {
            0
        }

        fn cancel(&self, _attempt: u64) {}
    }

    /// Decrypted request details must never enter the tracing log: no
    /// command, arguments, working directory, user, or process chain. The
    /// positive controls keep this honest — the probe proves the request
    /// really carried the marker, and the request ids in the log prove the
    /// capture really saw the decision paths.
    #[tokio::test]
    async fn request_plaintext_never_reaches_the_log() {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .without_time()
            .with_writer(logs.clone())
            .finish();
        let _ = tracing::dispatcher::set_global_default(tracing::Dispatch::new(subscriber));

        let dir = socket_test_dir("logprobe");
        let identity = std::sync::Arc::new(
            oshioki_agent::Identity::generate_to(
                &dir.join("agent.json"),
                oshioki_agent::SignerKind::Software,
            )
            .unwrap(),
        );

        // The probe request really carries the marker everywhere the log
        // must not see it.
        let request = request_for_log_probe();
        let reason = approval_reason(&request);
        assert!(reason.contains(LOG_PROBE), "{reason}");

        // Terminal prompt path: answer yes to the canned prompt.
        let envelope: RequestEnvelopeV1 =
            serde_json::from_slice(&sealed_envelope_bytes(&identity, &request)).unwrap();
        let opened = identity.open_request(&envelope).unwrap().unwrap();
        let (prompter, _sender) = canned_prompter("y");
        let decision = decide(&identity, &Decider::Prompt(prompter), &opened)
            .await
            .unwrap();
        assert!(
            matches!(
                decision,
                Some(oshioki_protocol::DecisionV1::ApproveNative(_))
            ),
            "the canned yes should approve"
        );

        // Local socket path: the same request through `handle_socket`.
        let (mut hook_side, agent_side) = tokio::net::UnixStream::pair().unwrap();
        let frame =
            oshioki_protocol::socket_v1::encode_frame(&sealed_envelope_bytes(&identity, &request))
                .unwrap();
        hook_side.write_all(&frame).await.unwrap();
        let (prompter, _sender) = canned_prompter("y");
        let decider = Decider::Prompt(prompter);
        super::handle_socket(agent_side, &identity, &decider)
            .await
            .unwrap();
        let mut prefix = [0u8; oshioki_protocol::socket_v1::FRAME_LEN_BYTES];
        hook_side.read_exact(&mut prefix).await.unwrap();
        let len = usize::try_from(u32::from_be_bytes(prefix)).unwrap();
        assert!(len > 0, "the socket path should answer");

        #[cfg(target_os = "macos")]
        {
            let prompt = oshioki_agent::touchid::TouchIdPrompt::new(
                Box::new(UnlockedScreen),
                std::sync::Arc::new(NoopCanceller),
            );
            let decision = super::mac::decide(&prompt, &identity, &opened)
                .await
                .unwrap();
            assert!(
                matches!(
                    decision,
                    Some(oshioki_protocol::DecisionV1::ApproveNative(_))
                ),
                "the software key should sign behind the mocked sheet"
            );
        }

        let text = logs.text();
        assert!(
            text.contains("req-logprobe-1"),
            "the capture missed the decision paths:\n{text}"
        );
        assert!(
            !text.contains(LOG_PROBE),
            "request plaintext reached the log:\n{text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
