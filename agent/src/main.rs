//! `oshioki-agent`: pairs a native device with a host and answers sudo
//! requests over NATS and a local Unix socket. NATS is optional at runtime:
//! without it the agent answers socket requests only.
//!
//! This binary is the Linux and test build of the macOS agent (#9). It uses
//! a software P-256 key and a terminal prompt. macOS adds the Secure Enclave
//! backend and a native prompt on top of the same library.

use std::{
    collections::HashMap,
    future::Future,
    io::{self, BufRead, IsTerminal as _, Write as _},
    os::unix::fs::{FileTypeExt as _, PermissionsExt as _},
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};
#[cfg(feature = "unattended")]
use clap::ValueEnum;
use clap::{Parser, Subcommand};
use futures::StreamExt as _;
use oshioki_agent::{Identity, OpenedRequest, SignerKind, parse_enrollment_url, remaining_until};
use oshioki_protocol::{
    ALLOW_PLAINTEXT_NATS_ENV, ActivationV1, AliveV1, DecisionV1, RequestEnvelopeV1,
    allow_plaintext_nats, check_nats_url, escape_for_terminal, nats_url_is_tls,
};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tracing::{info, warn};

const PAIR_TIMEOUT: Duration = Duration::from_secs(300);
/// Maximum number of request handlers, across both transports, that may be
/// waiting on a prompt or doing request work at once. Admission is
/// nonblocking: a flood is discarded instead of queued behind Touch ID.
const MAX_IN_FLIGHT_REQUESTS: usize = 8;
/// Keep accepted request IDs for at least the complete protocol validity
/// window, while bounding memory if a publisher sends many unique IDs.
const MAX_SEEN_REQUEST_IDS: usize = 1024;
const SEEN_REQUEST_RETENTION: Duration = Duration::from_secs(
    (oshioki_protocol::MAX_REQUEST_LIFETIME_SECS + oshioki_protocol::MAX_REQUEST_ISSUANCE_SKEW_SECS)
        as u64,
);
/// A connected socket peer must deliver its complete frame promptly; without
/// this bound an idle local connection could occupy one work slot forever.
const SOCKET_FRAME_TIMEOUT: Duration = Duration::from_secs(5);

/// Shared request admission for NATS and the local socket. The semaphore
/// bounds task and prompt work; the recent-ID set prevents one request from
/// being presented twice while its first decision is in flight or shortly
/// after it completes.
#[derive(Clone)]
struct RequestAdmission {
    permits: Arc<Semaphore>,
    request_ids: Arc<StdMutex<HashMap<String, Instant>>>,
}

struct RequestPermit {
    _permit: OwnedSemaphorePermit,
    request_ids: Arc<StdMutex<HashMap<String, Instant>>>,
}

impl RequestAdmission {
    fn new() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(MAX_IN_FLIGHT_REQUESTS)),
            request_ids: Arc::new(StdMutex::new(HashMap::new())),
        }
    }

    fn reserve(&self) -> Option<RequestPermit> {
        Some(RequestPermit {
            _permit: Arc::clone(&self.permits).try_acquire_owned().ok()?,
            request_ids: Arc::clone(&self.request_ids),
        })
    }
}

impl RequestPermit {
    /// Claims an ID after the envelope is decoded. A duplicate releases its
    /// permit when this lease is dropped and never reaches request opening or
    /// a prompt. IDs remain remembered for the protocol validity window, so a
    /// sequential replay cannot raise another prompt after the first ends.
    fn claim(&self, request_id: &str) -> bool {
        let Ok(mut request_ids) = self.request_ids.lock() else {
            return false;
        };
        let now = Instant::now();
        request_ids.retain(|_, seen_at| now.duration_since(*seen_at) < SEEN_REQUEST_RETENTION);
        if request_ids.contains_key(request_id) {
            return false;
        }
        if request_ids.len() >= MAX_SEEN_REQUEST_IDS
            && let Some(oldest) = request_ids
                .iter()
                .min_by_key(|(_, seen_at)| **seen_at)
                .map(|(request_id, _)| request_id.clone())
        {
            request_ids.remove(&oldest);
        }
        request_ids.insert(request_id.to_owned(), now);
        true
    }
}

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
    /// Create this device's identity without enrolling it. For offline
    /// pairing: `device-record` reads what `init` writes.
    Init {
        /// Where the signing key lives. Defaults to the Secure Enclave on
        /// macOS and to a software key everywhere else. Ignored when this
        /// device already has an identity, unless it disagrees with it.
        #[arg(long, value_enum)]
        signer: Option<SignerArg>,
        /// Replace an existing identity. The device gets a new fingerprint,
        /// so every record pinned for the old one should be revoked.
        #[arg(long)]
        force: bool,
    },
    /// Print this device's public record for offline pairing (`oshioki
    /// pin-record`). Read-only: no NATS, no server, no prompt.
    DeviceRecord {
        /// Label shown on the host's device list.
        #[arg(long)]
        label: String,
    },
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
    // Silent by default hid a day of "NATS unreachable" from the LaunchAgent
    // log; RUST_LOG still overrides.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
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
        Verb::DeviceRecord { label } => {
            let identity = Identity::load(&identity_path)?;
            let record = identity.device_record(&label);
            record.validate().context("device record")?;
            println!("{}", serde_json::to_string_pretty(&record)?);
            Ok(())
        }
        Verb::Init { signer, force } => {
            let identity = load_or_create(
                &identity_path,
                &Pairing {
                    requested: requested_signer_kind(signer),
                    default: signer_kind(signer),
                    force,
                },
            )?;
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
    #[cfg(target_os = "macos")]
    {
        let store = oshioki_agent::secret_store::KeychainStore::oshioki();
        load_or_create_with(path, pairing, &store)
    }
    #[cfg(not(target_os = "macos"))]
    {
        if path.exists() && !pairing.force {
            return reuse_or_complain(pairing, Identity::load(path)?);
        }
        replace_identity(path, pairing, |path, kind| {
            Identity::generate_to(path, kind)
        })
    }
}

/// The macOS pairing flow, and every platform's tests, through an explicit
/// secret store. See `oshioki_agent::Identity::load_with`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn load_or_create_with(
    path: &std::path::Path,
    pairing: &Pairing,
    store: &dyn oshioki_agent::secret_store::SecretStore,
) -> Result<Identity> {
    if path.exists() && !pairing.force {
        // One identity serves every host this device pairs with, so an
        // existing one is reused rather than replaced. A --signer that
        // disagrees with it cannot be honoured and must not look like it was.
        let identity = Identity::load_with(path, store)?;
        return reuse_or_complain(pairing, identity);
    }
    replace_identity(path, pairing, |path, kind| {
        Identity::generate_to_with(path, kind, store)
    })
}

fn reuse_or_complain(pairing: &Pairing, identity: Identity) -> Result<Identity> {
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
    Ok(identity)
}

/// Replaces the identity file, cleaning up the old keychain entry first.
fn replace_identity(
    path: &std::path::Path,
    pairing: &Pairing,
    generate: impl FnOnce(&std::path::Path, SignerKind) -> Result<Identity>,
) -> Result<Identity> {
    if path.exists() {
        warn!(path=%path.display(), "replacing this device's identity");
        remove_old_secret(path);
        std::fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
    }
    let identity = generate(path, pairing.requested.unwrap_or(pairing.default))?;
    info!(
        path = %path.display(),
        fingerprint = %identity.fingerprint(),
        signer = %identity.signer_kind(),
        "created device identity"
    );
    Ok(identity)
}

/// Removes the replaced identity's keychain entry, if the file keeps only a
/// reference. Best effort: re-pairing must not fail because stale cleanup
/// did, so failures are logged and ignored.
fn remove_old_secret(path: &std::path::Path) {
    #[cfg(target_os = "macos")]
    {
        let Ok(body) = std::fs::read(path) else {
            return;
        };
        let Ok(file): Result<serde_json::Value, _> = serde_json::from_slice(&body) else {
            return;
        };
        let Some(reference) = file.get("box_secret_ref").and_then(|value| value.as_str()) else {
            return;
        };
        let store = oshioki_agent::secret_store::KeychainStore::oshioki();
        if let Err(error) = oshioki_agent::secret_store::SecretStore::remove(&store, reference) {
            warn!(path = %path.display(), error = %format!("{error:#}"), "kept the replaced identity's keychain entry");
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
    }
}

async fn cmd_pair(
    identity_path: &std::path::Path,
    url: &str,
    label: &str,
    pairing: Pairing,
) -> Result<()> {
    let (enrollment_id, secret) = parse_enrollment_url(url)?;
    let identity = load_or_create(identity_path, &pairing)?;
    let native = identity.enrollment_submission(&enrollment_id, &secret, label)?;
    let submission = match identity.signer_kind() {
        SignerKind::Software => oshioki_protocol::EnrollmentSubmissionV1::Software(native),
        SignerKind::Enclave => oshioki_protocol::EnrollmentSubmissionV1::SecureEnclave(native),
    };
    let nats = connect_nats().await?;
    let mut activations = nats
        .subscribe(format!("oshioki.enrollment.activation.{enrollment_id}"))
        .await
        .context("subscribe activation")?;
    nats.flush().await?;
    nats.publish(
        format!("oshioki.enrollment.submission.{enrollment_id}"),
        serde_json::to_vec(&submission)?.into(),
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
        || activation.device.kind != identity.device_kind()
    {
        bail!("activation names another device or assurance kind");
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
    // NATS is the network transport; the socket above is the local one. The
    // agent answers socket requests from the start and joins NATS whenever it
    // becomes reachable: after a reboot the VPN is often a minute behind.
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
    let admission = Arc::new(RequestAdmission::new());
    tokio::spawn(serve_socket(
        socket,
        Arc::clone(&identity),
        Arc::clone(&decider),
        Arc::clone(&admission),
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
        dispatch_nats_request(
            &message.payload,
            &identity,
            &decider,
            requests.as_ref().map(|(nats, _)| nats.clone()),
            &admission,
        );
    }
}

/// Decodes and admits one NATS delivery. Admission happens before opening the
/// sealed body, so capacity drops do not spend crypto work or create tasks.
fn dispatch_nats_request(
    payload: &[u8],
    identity: &Arc<Identity>,
    decider: &Arc<Decider>,
    nats: Option<async_nats::Client>,
    admission: &RequestAdmission,
) {
    let envelope: RequestEnvelopeV1 = match serde_json::from_slice(payload) {
        Ok(envelope) => envelope,
        Err(error) => {
            warn!(
                error = %escape_for_terminal(&error.to_string()),
                "ignoring malformed request"
            );
            return;
        }
    };
    let Some(permit) = admission.reserve() else {
        warn!("discarding request while agent work is at capacity");
        return;
    };
    let opened = match identity.open_request(&envelope) {
        Ok(Some(opened)) => opened,
        Ok(None) => return,
        Err(error) => {
            warn!(
                request_id = %escape_for_terminal(&envelope.request_id),
                error = %escape_for_terminal(&error.to_string()),
                "ignoring request"
            );
            return;
        }
    };
    if !permit.claim(&envelope.request_id) {
        warn!(
            request_id = %escape_for_terminal(&envelope.request_id),
            "discarding duplicate request"
        );
        return;
    }
    let identity = Arc::clone(identity);
    let decider = Arc::clone(decider);
    tokio::spawn(async move {
        let _permit = permit;
        if let Some(nats) = &nats
            && let Err(error) = publish_alive(nats, &opened.request).await
        {
            warn!(
                request_id = %escape_for_terminal(&opened.request.request_id),
                error = %escape_for_terminal(&error.to_string()),
                "native liveness acknowledgement failed; approval prompt suppressed"
            );
            return;
        }
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

/// Connect NATS and subscribe to requests, or return `None` when the network
/// is unset so the agent answers socket requests only. An unreachable NATS
/// is not an error: the client keeps connecting in the background and the
/// subscription takes effect the moment it lands.
async fn subscribe_requests(
    identity: &Identity,
) -> Result<Option<(async_nats::Client, async_nats::Subscriber)>> {
    // Unset and unreachable are different states: the first is a
    // socket-only install answering exactly what it was told to, the second
    // is a network that has not come up yet.
    let Some(url) = env_nonempty("NATS_URL") else {
        info!("NATS_URL is not set; answering socket requests only (socket-only)");
        return Ok(None);
    };
    let nats = nats_connect_options()?
        .retry_on_initial_connect()
        .max_reconnects(None)
        .reconnect_delay_callback(reconnect_delay)
        .event_callback(|event| async move {
            match event {
                async_nats::Event::Connected => info!("NATS connected; watching for requests"),
                async_nats::Event::Disconnected => {
                    warn!("NATS disconnected; reconnecting in the background");
                }
                async_nats::Event::ServerError(error) => {
                    warn!(error = %escape_for_terminal(&error.to_string()), "NATS server error");
                }
                async_nats::Event::ClientError(error) => {
                    warn!(error = %escape_for_terminal(&error.to_string()), "NATS connect failed; retrying");
                }
                other => info!(event = %other, "NATS event"),
            }
        })
        .connect(&url)
        .await
        .context("connect to NATS")?;
    let requests = nats
        .subscribe("oshioki.request.>")
        .await
        .context("subscribe requests")?;
    info!(
        fingerprint = %identity.fingerprint(),
        "NATS connection in progress; requests are answered once it is up"
    );
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
    let reason = approval_reason_for_raw(request, &opened.raw);
    let decision = if approve {
        identity.approve(opened, &reason)?
    } else {
        // An explicit refusal signs like an approval: the hook verifies the
        // denial against the pinned device, so no NATS credential suffices
        // to deny for it. Silence (timeout, dismissal) signs nothing.
        identity.deny(opened, &reason)?
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

/// Publishes a liveness acknowledgement before the decider is invoked. It
/// carries no signature and cannot authorize a request; the hook uses it only
/// to distinguish a live native agent from an unavailable transport.
async fn publish_alive(
    nats: &async_nats::Client,
    request: &oshioki_protocol::RequestV1,
) -> Result<()> {
    nats.publish(
        format!("oshioki.ack.{}", request.request_id),
        serde_json::to_vec(&AliveV1::for_request(&request.request_id))?.into(),
    )
    .await
    .context("publish daemon acknowledgement")?;
    nats.flush().await.context("flush daemon acknowledgement")?;
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
    admission: Arc<RequestAdmission>,
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
        let Some(permit) = admission.reserve() else {
            warn!("discarding socket request while agent work is at capacity");
            continue;
        };
        let identity = Arc::clone(&identity);
        let decider = Arc::clone(&decider);
        tokio::spawn(async move {
            if let Err(error) = handle_socket(stream, &identity, &decider, permit).await {
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
    permit: RequestPermit,
) -> Result<()> {
    let (mut reader, mut writer) = stream.into_split();
    let Some(bytes) = tokio::time::timeout(SOCKET_FRAME_TIMEOUT, read_frame(&mut reader))
        .await
        .context("socket frame timed out")??
    else {
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
    if !permit.claim(&envelope.request_id) {
        warn!(
            request_id = %escape_for_terminal(&envelope.request_id),
            "discarding duplicate socket request"
        );
        return Ok(());
    }
    let alive = oshioki_protocol::socket_v1::encode_frame(&serde_json::to_vec(
        &AliveV1::for_request(&opened.request.request_id),
    )?)?;
    writer
        .write_all(&alive)
        .await
        .context("write socket acknowledgement")?;
    writer
        .flush()
        .await
        .context("flush socket acknowledgement")?;
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

/// Computes the fingerprint shown in the companion review and the biometric
/// reason. The digest is over the exact bytes retained for signature
/// verification, rather than a re-serialization that could hide a mismatch.
fn request_digest(raw: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut digest = String::with_capacity(64);
    for byte in Sha256::digest(raw) {
        let _ = write!(digest, "{byte:02x}");
    }
    digest
}

/// Builds the complete read-only document shown before a native approval.
/// `raw` is JSON produced by the requesting hook, so its string escapes are
/// also the unambiguous representation of every command, argument, and
/// environment value that the signature covers.
#[cfg(any(target_os = "macos", test))]
fn full_review_document(request: &oshioki_protocol::RequestV1, raw: &[u8]) -> String {
    format!(
        "Oshioki approval review\n\nRequest ID: {}\nExact signed request SHA-256: {}\n\nThe JSON below is the complete signed request. Review every field, including every argv and env entry, before continuing to Touch ID.\n\n{}\n",
        escape_for_terminal(&request.request_id),
        request_digest(raw),
        String::from_utf8_lossy(raw),
    )
}

/// What the operator is being asked to allow after the complete companion
/// document has been reviewed. No executable input is put in this string:
/// `LocalAuthentication` may truncate a localized reason, so it must never be
/// the only place a behavior-changing field appears.
fn approval_reason_for_raw(request: &oshioki_protocol::RequestV1, raw: &[u8]) -> String {
    let digest = request_digest(raw);
    let reason = format!(
        "Approve {} [sha256:{}] after full review.",
        escape_for_terminal(&request.request_id),
        &digest[..16],
    );
    debug_assert!(reason.chars().count() <= MAX_APPROVAL_REASON_CHARS);
    reason
}

/// The request ID is bounded to 128 ASCII bytes by the protocol. Together
/// with this fixed wording and a 16-hex digest prefix, the reason stays below
/// the conservative limit used for a system-owned biometric prompt.
const MAX_APPROVAL_REASON_CHARS: usize = 96;

/// Test helper for the short reason generated from a semantically valid
/// request. Production paths use the exact retained bytes directly.
#[cfg(test)]
fn approval_reason(request: &oshioki_protocol::RequestV1) -> String {
    let raw = request.raw_json().unwrap_or_default();
    approval_reason_for_raw(request, &raw)
}

/// The complete bound environment as approver-visible lines, empty when the
/// request carries none. The terminal is scrollable, so hiding a suffix or
/// summarizing entries would let an unreviewed value affect execution.
fn format_env(request: &oshioki_protocol::RequestV1) -> String {
    use std::fmt::Write as _;
    let mut shown = String::new();
    for (index, entry) in request.env.iter().enumerate() {
        let _ = writeln!(
            shown,
            "  env[{index}] {}={}",
            escape_for_terminal(&entry.name),
            escape_for_terminal(&entry.value)
        );
    }
    shown
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

/// Reads an environment variable with empty counting as unset, so generated
/// files can carry blank values without changing the transport set.
fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// Connection options from the environment, validated up front so a
/// misconfiguration fails fast even when the connect itself is retried.
fn nats_connect_options() -> Result<async_nats::ConnectOptions> {
    let url = env_nonempty("NATS_URL").context("NATS_URL is not set")?;
    let mut options = async_nats::ConnectOptions::new();
    // Half a credential is a misconfiguration, not a request for an anonymous
    // connection; the hook and the server both require the pair.
    match (env_nonempty("NATS_USER"), env_nonempty("NATS_PASS")) {
        (Some(user), Some(pass)) => options = options.user_and_password(user, pass),
        (None, None) => {}
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
    Ok(options)
}

/// One attempt, for the pairing flow: a user waiting at a terminal wants the
/// failure now, not a background retry.
async fn connect_nats() -> Result<async_nats::Client> {
    let url = env_nonempty("NATS_URL").context("NATS_URL is not set")?;
    nats_connect_options()?
        .connect(&url)
        .await
        .context("connect to NATS")
}

/// Reconnect backoff: one second per attempt, capped at fifteen. Short
/// enough that a returning network is joined well inside the hook's
/// deadline, long enough that a laptop off the VPN does not log every
/// few seconds forever.
fn reconnect_delay(attempts: usize) -> std::time::Duration {
    std::time::Duration::from_secs(attempts.clamp(1, 15) as u64)
}

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// The Touch ID sheet, and the two macOS facts the prompt needs: whether the
/// screen is locked, and how to tear a sheet down at a deadline.
#[cfg(target_os = "macos")]
mod mac {
    use std::{
        fs::{self, OpenOptions},
        io::Write as _,
        os::unix::fs::OpenOptionsExt as _,
        path::{Path, PathBuf},
        process::{Command, Stdio},
        sync::Arc,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    use anyhow::{Context as _, Result, bail};
    use oshioki_agent::{
        Identity, OpenedRequest,
        touchid::{AttemptError, Outcome, PromptCancel, ScreenLock, TouchIdPrompt},
    };
    use oshioki_enclave::SignError;
    use oshioki_protocol::{DecisionV1, escape_for_terminal};
    use tracing::{error, info};

    use super::{approval_reason_for_raw, full_review_document, now};
    use oshioki_agent::remaining_until;

    /// The result of the review helper, before Touch ID is attempted.
    #[derive(Debug, PartialEq, Eq)]
    enum ReviewOutcome {
        Approved,
        Canceled,
        Expired,
    }

    /// The request is shown in a transient, read-only `AppKit` view rather than
    /// in `LocalAuthentication`'s one-line reason. The JXA is constant and the
    /// path is passed as data, so neither request contents nor shell syntax
    /// are interpreted by the helper.
    const REVIEW_SCRIPT: &str = r"
ObjC.import('AppKit');
ObjC.import('Foundation');

function run(argv) {
    if (argv.length !== 1) throw new Error('invalid review arguments');
    const path = $(argv[0]);
    const contents = $.NSString.stringWithContentsOfFileEncodingError(
        path, $.NSUTF8StringEncoding, null);
    if (contents === null) throw new Error('could not read the approval review');

    const alert = $.NSAlert.alloc.init;
    alert.messageText = 'Review sudo request';
    alert.informativeText = 'Read the complete signed request below. Continue only if every command, argument, and environment entry is expected.';
    alert.addButtonWithTitle('Cancel');
    alert.addButtonWithTitle('Continue to Touch ID');

    const frame = $.NSMakeRect(0, 0, 700, 420);
    const textView = $.NSTextView.alloc.initWithFrame(frame);
    textView.string = ObjC.unwrap(contents);
    textView.editable = false;
    textView.selectable = true;
    textView.richText = false;
    textView.horizontallyResizable = true;
    textView.verticallyResizable = true;
    textView.maxSize = $.NSMakeSize(100000, 100000);

    const scrollView = $.NSScrollView.alloc.initWithFrame(frame);
    scrollView.hasVerticalScroller = true;
    scrollView.hasHorizontalScroller = true;
    scrollView.autohidesScrollers = false;
    scrollView.documentView = textView;
    alert.accessoryView = scrollView;

    // A helper launched by a LaunchAgent has no activation policy, so AppKit
    // never shows its windows without one. JXA invokes zero-argument
    // methods on property access; trailing parentheses call the result.
    const app = $.NSApplication.sharedApplication;
    app.setActivationPolicy($.NSApplicationActivationPolicyAccessory);
    app.activateIgnoringOtherApps(true);
    const response = alert.runModal;
    if (response != 1001) throw new Error('approval review was canceled');
    return 0;
}
";

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
        // The permit covers both the review window and the subsequent Touch
        // ID sheet. A second native request fails closed immediately instead
        // of stacking a review dialog and consuming an admission slot.
        let Some(permit) = prompt.try_acquire() else {
            info!(
                request_id = %escape_for_terminal(&request.request_id),
                "another native approval is already under review"
            );
            return Ok(None);
        };
        // LocalAuthentication can truncate localized reasons, so the full
        // signed bytes must be inspected in the companion first. A launchd
        // agent has no terminal; failure to reach the GUI is therefore a
        // deliberate fail-closed result.
        let document = full_review_document(request, &opened.raw);
        let expires_at = request.expires_at;
        let reviewed = tokio::task::spawn_blocking(move || show_review(&document, expires_at))
            .await
            .context("the approval review thread panicked")??;
        match reviewed {
            ReviewOutcome::Approved => {}
            ReviewOutcome::Canceled => {
                info!(
                    request_id = %escape_for_terminal(&request.request_id),
                    "approval review was canceled"
                );
                return Ok(None);
            }
            ReviewOutcome::Expired => {
                info!(
                    request_id = %escape_for_terminal(&request.request_id),
                    "request expired during approval review"
                );
                return Ok(None);
            }
        }
        if request.expires_at <= now() {
            info!(
                request_id = %escape_for_terminal(&request.request_id),
                "request expired during approval review"
            );
            return Ok(None);
        }
        let reason = approval_reason_for_raw(request, &opened.raw);
        info!(
            request_id = %escape_for_terminal(&request.request_id),
            "request reviewed; asking for Touch ID"
        );
        let sign = {
            let (identity, opened, reason) = (Arc::clone(identity), opened.clone(), reason.clone());
            move || identity.approve(&opened, &reason).map_err(classify)
        };
        match prompt
            .ask_with_permit(permit, &request.request_id, request.expires_at, sign)
            .await
        {
            Ok(Outcome::Approved(decision)) => Ok(Some(decision)),
            // Dismissal carries no signature, and an unsigned denial is
            // indistinguishable from a forgery: the hook fails closed at
            // the deadline instead.
            Ok(Outcome::Denied) => Ok(None),
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

    /// Displays the exact signed request in a transient `AppKit` alert and waits
    /// for the operator to explicitly continue. The file is owner-only and
    /// is unlinked on every path; if either display or cleanup fails, approval
    /// is refused rather than leaving secrets behind or signing blindly.
    fn show_review(document: &str, expires_at: i64) -> Result<ReviewOutcome> {
        let Some(remaining) = remaining_until(expires_at) else {
            return Ok(ReviewOutcome::Expired);
        };
        show_review_with_deadline(
            document,
            Instant::now() + remaining,
            Path::new("/usr/bin/osascript"),
            &std::env::temp_dir(),
        )
    }

    /// Runs a review helper while retaining a hard deadline. Killing the
    /// child is required because aborting the blocking task would leave an
    /// interactive osascript process and its dialog behind.
    fn show_review_with_deadline(
        document: &str,
        deadline: Instant,
        helper: &Path,
        temp_dir: &Path,
    ) -> Result<ReviewOutcome> {
        let (path, file) = create_review_file_in(temp_dir)?;
        let display_result = (|| -> Result<ReviewOutcome> {
            let mut file = file;
            file.write_all(document.as_bytes())?;
            file.sync_all()?;
            drop(file);
            let path_string = path
                .to_str()
                .context("approval review path is not valid UTF-8")?;
            let mut child = Command::new(helper)
                .env_clear()
                .args(["-l", "JavaScript", "-e", REVIEW_SCRIPT, path_string])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .context("launch the approval review")?;
            loop {
                if let Some(status) = child.try_wait()? {
                    return Ok(if status.success() {
                        ReviewOutcome::Approved
                    } else {
                        ReviewOutcome::Canceled
                    });
                }
                if Instant::now() >= deadline {
                    child
                        .kill()
                        .context("terminate the expired approval review")?;
                    child.wait().context("reap the expired approval review")?;
                    return Ok(ReviewOutcome::Expired);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })();
        let cleanup_result = fs::remove_file(&path)
            .map_err(|error| anyhow::anyhow!("remove the temporary approval review: {error}"));
        cleanup_result?;
        display_result
    }

    fn create_review_file_in(temp_dir: &Path) -> Result<(PathBuf, fs::File)> {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for attempt in 0..100u8 {
            let path = temp_dir.join(format!(
                "oshioki-review-{}-{stamp}-{attempt}.txt",
                std::process::id()
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error).context("create the approval review"),
            }
        }
        bail!("could not allocate a unique approval review file")
    }

    /// A dismissed sheet is an answer; anything else is a broken key.
    fn classify(error: anyhow::Error) -> AttemptError {
        if matches!(error.downcast_ref::<SignError>(), Some(SignError::Canceled)) {
            AttemptError::Canceled
        } else {
            AttemptError::Failed(error)
        }
    }

    #[cfg(test)]
    mod tests {
        use std::{
            fs,
            os::unix::fs::PermissionsExt as _,
            path::{Path, PathBuf},
            time::{Duration, Instant},
        };

        use super::{REVIEW_SCRIPT, ReviewOutcome, show_review_with_deadline};

        fn test_dir(name: &str) -> PathBuf {
            let path = std::env::temp_dir()
                .join(format!("oshioki-review-test-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            path
        }

        fn helper(dir: &Path, name: &str, body: &str) -> PathBuf {
            let path = dir.join(name);
            fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(&path, permissions).unwrap();
            path
        }

        fn review_files(dir: &Path) -> Vec<PathBuf> {
            fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with("oshioki-review-"))
                })
                .collect()
        }

        /// The real helper receives the review path as its final argument.
        /// These non-interactive helpers inspect that file before returning,
        /// which exercises its permissions, contents, and cleanup on each
        /// exit-status path.
        #[test]
        fn review_file_lifecycle_is_fail_closed_and_owner_only() {
            let dir = test_dir("lifecycle");
            let ok = helper(
                &dir,
                "approve.sh",
                "path=\"$5\"; cat \"$path\" > \"$path.capture\"; stat -f %Lp \"$path\" > \"$path.mode\"; exit 0",
            );
            let document = "signed request with a complete environment";
            assert_eq!(
                show_review_with_deadline(
                    document,
                    Instant::now() + Duration::from_secs(5),
                    &ok,
                    &dir,
                )
                .unwrap(),
                ReviewOutcome::Approved
            );
            let capture = review_files(&dir)
                .into_iter()
                .find(|path| path.extension().is_some_and(|ext| ext == "capture"))
                .unwrap();
            assert_eq!(fs::read_to_string(&capture).unwrap(), document);
            let mode = capture.with_extension("mode");
            assert_eq!(fs::read_to_string(mode).unwrap().trim(), "600");
            assert!(review_files(&dir).iter().all(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "capture" || extension == "mode")
            }));

            let cancel = helper(
                &dir,
                "cancel.sh",
                "path=\"$5\"; cat \"$path\" > \"$path.capture\"; stat -f %Lp \"$path\" > \"$path.mode\"; exit 1",
            );
            assert_eq!(
                show_review_with_deadline(
                    document,
                    Instant::now() + Duration::from_secs(5),
                    &cancel,
                    &dir,
                )
                .unwrap(),
                ReviewOutcome::Canceled
            );
            assert!(review_files(&dir).iter().all(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "capture" || extension == "mode")
            }));

            let missing = dir.join("missing-helper");
            assert!(
                show_review_with_deadline(
                    document,
                    Instant::now() + Duration::from_secs(5),
                    &missing,
                    &dir,
                )
                .is_err()
            );
            assert!(review_files(&dir).iter().all(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "capture" || extension == "mode")
            }));
            let _ = fs::remove_dir_all(dir);
        }

        #[test]
        fn review_expiry_kills_the_helper_before_cleanup() {
            let dir = test_dir("expiry");
            let started = dir.join("helper.started");
            let helper = helper(
                &dir,
                "hang.sh",
                &format!(": > '{}'; exec /bin/sleep 60", started.display()),
            );
            let outcome = show_review_with_deadline(
                "expiring request",
                Instant::now() + Duration::from_secs(1),
                &helper,
                &dir,
            )
            .unwrap();
            assert_eq!(outcome, ReviewOutcome::Expired);
            assert!(started.exists());
            assert!(review_files(&dir).is_empty());
            let _ = fs::remove_dir_all(dir);
        }

        #[test]
        fn jxa_buttons_map_cancel_to_non_continue_and_continue_to_1001() {
            assert!(REVIEW_SCRIPT.contains("alert.addButtonWithTitle('Cancel');"));
            assert!(REVIEW_SCRIPT.contains("alert.addButtonWithTitle('Continue to Touch ID');"));
            assert!(REVIEW_SCRIPT.contains("if (response != 1001)"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Cli, Decider, MAX_APPROVAL_REASON_CHARS, MAX_IN_FLIGHT_REQUESTS, Pairing, Prompter,
        RequestAdmission, Verb, approval_reason, approval_reason_for_raw, bind_socket, decide,
        dispatch_nats_request, format_env, full_review_document, load_or_create_with, now,
        prompt_output, quote_argv, request_digest, runas_label, socket_path,
    };
    use clap::Parser as _;
    use oshioki_agent::SignerKind;
    use oshioki_agent::secret_store::MemoryStore;
    use oshioki_protocol::{
        EnvEntryV1, RequestEnvelopeV1, RequestV1, VERSION_V1, encode_base64url,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::sync::mpsc;

    #[test]
    fn request_admission_is_bounded_and_deduplicates_ids() {
        let admission = RequestAdmission::new();
        let mut leases = Vec::new();
        for index in 0..MAX_IN_FLIGHT_REQUESTS {
            let lease = admission.reserve().expect("capacity should be available");
            assert!(lease.claim(&format!("request-{index}")));
            leases.push(lease);
        }
        assert!(admission.reserve().is_none());

        drop(leases.pop());
        let duplicate = admission.reserve().expect("one slot was released");
        assert!(!duplicate.claim("request-0"));
        drop(duplicate);
        let replacement = admission.reserve().expect("duplicate released its slot");
        assert!(replacement.claim("replacement"));
    }

    #[tokio::test]
    async fn encrypted_request_flood_never_admits_more_than_the_fixed_capacity() {
        let dir = socket_test_dir("flood");
        let store = MemoryStore::new();
        let identity = std::sync::Arc::new(
            oshioki_agent::Identity::generate_to_with(
                &dir.join("agent.json"),
                oshioki_agent::SignerKind::Software,
                &store,
            )
            .unwrap(),
        );
        let (_sender, receiver) = mpsc::channel(1);
        let decider = std::sync::Arc::new(Decider::Prompt(Prompter::new(receiver)));
        let admission = std::sync::Arc::new(RequestAdmission::new());
        for index in 0..(MAX_IN_FLIGHT_REQUESTS * 4) {
            let mut request = request_for_log_probe();
            request.request_id = format!("encrypted-flood-{index}");
            request.issued_at = now();
            request.expires_at = request.issued_at + oshioki_protocol::MAX_REQUEST_LIFETIME_SECS;
            let payload = sealed_envelope_bytes(&identity, &request);
            dispatch_nats_request(&payload, &identity, &decider, None, &admission);
        }
        assert_eq!(
            admission.request_ids.lock().unwrap().len(),
            MAX_IN_FLIGHT_REQUESTS
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn invalid_and_foreign_envelopes_do_not_poison_request_id_dedupe() {
        let dir = socket_test_dir("dedupe");
        let store = MemoryStore::new();
        let identity = std::sync::Arc::new(
            oshioki_agent::Identity::generate_to_with(
                &dir.join("agent.json"),
                oshioki_agent::SignerKind::Software,
                &store,
            )
            .unwrap(),
        );
        let (_sender, receiver) = mpsc::channel(1);
        let decider = std::sync::Arc::new(Decider::Prompt(Prompter::new(receiver)));
        let admission = std::sync::Arc::new(RequestAdmission::new());
        let mut request = request_for_log_probe();
        request.request_id = "claim-after-rejection".into();
        request.issued_at = now();
        request.expires_at = request.issued_at + oshioki_protocol::MAX_REQUEST_LIFETIME_SECS;

        let mut invalid: RequestEnvelopeV1 =
            serde_json::from_slice(&sealed_envelope_bytes(&identity, &request)).unwrap();
        invalid.issued_at = now() + oshioki_protocol::MAX_REQUEST_ISSUANCE_SKEW_SECS + 1;
        invalid.expires_at = invalid.issued_at + oshioki_protocol::MAX_REQUEST_LIFETIME_SECS;
        dispatch_nats_request(
            &serde_json::to_vec(&invalid).unwrap(),
            &identity,
            &decider,
            None,
            &admission,
        );
        assert!(admission.request_ids.lock().unwrap().is_empty());

        let foreign =
            oshioki_agent::Identity::from_material([0x44; 32], [0x55; 32], [0x66; 32]).unwrap();
        dispatch_nats_request(
            &sealed_envelope_bytes(&foreign, &request),
            &identity,
            &decider,
            None,
            &admission,
        );
        assert!(admission.request_ids.lock().unwrap().is_empty());

        dispatch_nats_request(
            &sealed_envelope_bytes(&identity, &request),
            &identity,
            &decider,
            None,
            &admission,
        );
        assert_eq!(admission.request_ids.lock().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

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

    /// Touch ID receives only a short reference to the companion review. No
    /// command or environment suffix is delegated to a potentially truncated
    /// `LocalAuthentication` reason.
    #[test]
    fn the_sheet_reason_references_the_full_review_compactly() {
        let mut request = request_for_reason();
        let raw = request.raw_json().unwrap();
        let reason = approval_reason_for_raw(&request, &raw);
        assert!(reason.contains("req-1"));
        assert!(reason.contains(&request_digest(&raw)[..16]));
        assert!(!reason.contains("/usr/bin/apt"));
        assert!(reason.chars().count() <= MAX_APPROVAL_REASON_CHARS);
        request.runas_uid = 1000;
        assert_ne!(approval_reason(&request), reason);
    }

    /// The terminal summary shows the complete bound environment line by line,
    /// while an empty environment shows nothing.
    #[test]
    fn summary_shows_the_bound_environment() {
        let mut request = request_for_reason();
        assert!(!format_env(&request).contains("env "));
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
        assert!(
            shown.contains("  env[0] LD_PRELOAD=/tmp/evil.so\n"),
            "{shown}"
        );
        assert!(
            shown.contains("  env[1] PATH=/tmp/bin:/usr/bin\n"),
            "{shown}"
        );
    }

    #[test]
    fn device_record_takes_a_label() {
        let cli =
            Cli::try_parse_from(["oshioki-agent", "device-record", "--label", "mbp"]).unwrap();
        assert!(matches!(cli.verb, Verb::DeviceRecord { .. }));
    }

    #[test]
    fn init_takes_signer_and_force() {
        let cli = Cli::try_parse_from(["oshioki-agent", "init", "--signer", "software"]).unwrap();
        assert!(matches!(
            cli.verb,
            Verb::Init {
                signer: Some(_),
                force: false
            }
        ));
        let cli = Cli::try_parse_from(["oshioki-agent", "init", "--force"]).unwrap();
        assert!(matches!(
            cli.verb,
            Verb::Init {
                signer: None,
                force: true
            }
        ));
    }

    /// A hostile environment remains fully visible. It is escaped for the
    /// terminal, but no value or entry is cut or replaced by a count.
    #[test]
    fn a_hostile_environment_is_not_summarized() {
        let mut request = request_for_reason();
        request.env = (0..64)
            .map(|n| EnvEntryV1 {
                name: format!("PATH{n}"),
                value: "x".repeat(1024),
            })
            .collect();
        let shown = format_env(&request);
        assert_eq!(shown.lines().count(), 64, "{shown}");
        assert!(shown.ends_with(&format!("  env[63] PATH63={}\n", "x".repeat(1024))));
        assert!(shown.contains(&"x".repeat(1024)), "{shown}");
    }

    /// The native companion contains the exact signed bytes, including
    /// behavior-changing variables and a suffix beyond the former
    /// `LocalAuthentication` reason cut.
    #[test]
    fn full_review_keeps_bash_env_ld_preload_and_long_suffix() {
        let mut request = request_for_reason();
        request.command = "/bin/sh".into();
        request.argv = vec![
            "-c".into(),
            format!("{}{}", "x".repeat(100), ";echo malicious-suffix"),
        ];
        request.env = vec![
            EnvEntryV1 {
                name: "BASH_ENV".into(),
                value: "/tmp/attacker-init".into(),
            },
            EnvEntryV1 {
                name: "LD_PRELOAD".into(),
                value: "/tmp/evil.so".into(),
            },
        ];
        let raw = request.raw_json().unwrap();
        let document = full_review_document(&request, &raw);
        assert!(document.contains("BASH_ENV"), "{document}");
        assert!(document.contains("LD_PRELOAD"), "{document}");
        assert!(document.contains("malicious-suffix"), "{document}");
        assert!(document.contains(&request_digest(&raw)), "{document}");
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
        let store = MemoryStore::new();
        let identity = load_or_create_with(&dir.join("agent.json"), &pairing, &store).unwrap();
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

        let store = MemoryStore::new();
        let create =
            |requested, force| load_or_create_with(&path, &pairing(requested, force), &store);
        let created = create(None, false).unwrap();
        let reused = create(None, false).unwrap();
        assert_eq!(created.fingerprint(), reused.fingerprint());
        let asked_for_the_same = create(Some(SignerKind::Software), false);
        assert_eq!(
            asked_for_the_same.unwrap().fingerprint(),
            created.fingerprint()
        );

        let Err(error) = create(Some(SignerKind::Enclave), false) else {
            panic!("a mismatched --signer was accepted");
        };
        let error = error.to_string();
        assert!(error.contains("software"), "{error}");
        assert!(error.contains("--force"), "{error}");

        // --force replaces the identity, so the device is a new one and the
        // host's old record for it is stale.
        let replaced = create(None, true).unwrap();
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
            super::handle_socket(
                agent_side,
                &identity,
                &decider,
                super::RequestAdmission::new().reserve().unwrap(),
            )
            .await
        });
        let frame = oshioki_protocol::socket_v1::encode_frame(envelope).unwrap();
        hook_side.write_all(&frame).await.unwrap();
        let mut prefix = [0u8; oshioki_protocol::socket_v1::FRAME_LEN_BYTES];
        hook_side.read_exact(&mut prefix).await.unwrap();
        let len = usize::try_from(u32::from_be_bytes(prefix)).unwrap();
        let mut acknowledgement = vec![0u8; len];
        hook_side.read_exact(&mut acknowledgement).await.unwrap();
        let acknowledgement: oshioki_protocol::AliveV1 =
            serde_json::from_slice(&acknowledgement).unwrap();
        let request: oshioki_protocol::RequestEnvelopeV1 =
            serde_json::from_slice(envelope).unwrap();
        acknowledgement.validate(&request.request_id).unwrap();
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
        let identity =
            oshioki_agent::Identity::from_material([0x41; 32], [0x42; 32], [0x43; 32]).unwrap();
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
        let identity =
            oshioki_agent::Identity::from_material([0x44; 32], [0x45; 32], [0x46; 32]).unwrap();
        let mut request = request_for_reason();
        request.issued_at = now();
        request.expires_at = now() + 60;
        let envelope = sealed_envelope_for(&identity, &request);
        let identity = std::sync::Arc::new(identity);
        match socket_verdict(identity.clone(), false, &envelope).await {
            oshioki_protocol::DecisionV1::Deny(denial) => {
                assert_eq!(denial.request_id, request.request_id);
                // Auto-deny signs like an explicit refusal: the hook
                // verifies this against the pinned record.
                oshioki_protocol::verify_deny_v1(&denial, &identity.device_record("laptop"))
                    .unwrap();
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

    /// Decrypted request details must never enter the tracing log: no
    /// command, arguments, working directory, user, or process chain. The
    /// positive controls keep this honest — the probe proves the request
    /// really carried the marker, and the request ids in the log prove the
    /// capture really saw the decision paths.
    #[test]
    fn reconnect_backoff_is_bounded_on_both_ends() {
        use std::time::Duration;
        assert_eq!(super::reconnect_delay(0), Duration::from_secs(1));
        assert_eq!(super::reconnect_delay(7), Duration::from_secs(7));
        assert_eq!(super::reconnect_delay(10_000), Duration::from_secs(15));
    }

    /// After a reboot the VPN comes up a minute after the agent. The agent
    /// must not need a restart for that: connect returns at once, the
    /// subscription lands when the server does, and requests flow.
    #[tokio::test]
    async fn nats_subscription_survives_a_server_that_starts_late() {
        use futures::StreamExt as _;
        use std::process::{Command, Stdio};
        use std::time::Duration;
        let Ok(bin) = which_nats_server() else {
            eprintln!("nats-server not on PATH; skipping");
            return;
        };
        let port = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        };
        let url = format!("nats://127.0.0.1:{port}");
        let started = std::time::Instant::now();
        let client = async_nats::ConnectOptions::new()
            .retry_on_initial_connect()
            .max_reconnects(None)
            .reconnect_delay_callback(super::reconnect_delay)
            .connect(&url)
            .await
            .expect("connect returns before the server exists");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "connect blocked on an absent server"
        );
        let mut requests = client.subscribe("oshioki.request.>").await.unwrap();

        let server = Command::new(bin)
            .args(["-a", "127.0.0.1", "-p", &port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn nats-server");
        let _server = KillOnDrop(server);

        // A fail-fast publisher that waits for the server, then keeps
        // publishing until the late subscription answers.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let publisher = loop {
            if let Ok(publisher) = async_nats::connect(&url).await {
                break publisher;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "nats-server never came up"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        loop {
            publisher
                .publish("oshioki.request.test", "late".into())
                .await
                .unwrap();
            let _ = publisher.flush().await;
            match tokio::time::timeout(Duration::from_millis(300), requests.next()).await {
                Ok(Some(message)) => {
                    assert_eq!(message.payload.as_ref(), b"late");
                    break;
                }
                _ => assert!(
                    std::time::Instant::now() < deadline,
                    "subscription never took effect after the server started"
                ),
            }
        }
    }

    struct KillOnDrop(std::process::Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn which_nats_server() -> Result<std::path::PathBuf, ()> {
        let path = std::env::var_os("PATH").ok_or(())?;
        std::env::split_paths(&path)
            .map(|dir| dir.join("nats-server"))
            .find(|candidate| candidate.is_file())
            .ok_or(())
    }

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
        let store = MemoryStore::new();
        let identity = std::sync::Arc::new(
            oshioki_agent::Identity::generate_to_with(
                &dir.join("agent.json"),
                oshioki_agent::SignerKind::Software,
                &store,
            )
            .unwrap(),
        );

        // The probe request really carries the marker everywhere the log
        // must not see it.
        let request = request_for_log_probe();
        let reason = approval_reason(&request);
        assert!(!reason.contains(LOG_PROBE), "{reason}");

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
        super::handle_socket(
            agent_side,
            &identity,
            &decider,
            RequestAdmission::new().reserve().unwrap(),
        )
        .await
        .unwrap();
        let mut prefix = [0u8; oshioki_protocol::socket_v1::FRAME_LEN_BYTES];
        hook_side.read_exact(&mut prefix).await.unwrap();
        let len = usize::try_from(u32::from_be_bytes(prefix)).unwrap();
        assert!(len > 0, "the socket path should answer");

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
