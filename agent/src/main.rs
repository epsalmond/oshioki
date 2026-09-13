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
use clap::{CommandFactory as _, Parser, Subcommand};
use futures::StreamExt as _;
use oshioki_agent::{Identity, OpenedRequest, SignerKind, parse_enrollment_url, remaining_until};
use oshioki_protocol::{
    ALLOW_PLAINTEXT_NATS_ENV, AUTH_ENVELOPE_TYPE, ActivationV1, AliveV1, AuthDecisionV1,
    AuthEnvelopeV1, AuthInvocationV1, AuthRequestV1, DecisionV1, DeviceKindV1, OpenedAuthRequestV1,
    RequestEnvelopeV1, allow_plaintext_nats, check_nats_url, escape_for_terminal, nats_url_is_tls,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tracing::{info, warn};

#[path = "../../cli/terminal_logo.rs"]
mod terminal_logo;

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
#[command(
    name = "oshioki-agent",
    version,
    about = "Run a native Oshioki approval agent"
)]
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
        /// Enrollment URL printed by `oshioki enroll`.
        #[arg(value_name = "ENROLLMENT_URL", allow_hyphen_values = true)]
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
    /// Watch for sudo requests and ask for approval.
    Run {
        /// Decide every request without asking. For tests only.
        #[cfg(feature = "unattended")]
        #[arg(long, value_enum)]
        auto: Option<Auto>,
    },
    /// Print this device's fingerprint and signer.
    Show,
    /// Create a native identity.
    ///
    /// For offline pairing, `device-record` reads what `init` writes.
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
    /// Print a public device record.
    ///
    /// This is read-only. It does not contact NATS or the server.
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
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if terminal_logo::is_top_level_help(&arguments) {
        terminal_logo::maybe_print_for_arguments(&arguments);
        Cli::command().print_help()?;
        return Ok(());
    }
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

/// The merged inbound subscription: command approval and contextual sudo
/// authentication arrive on separate subject trees and are dispatched by
/// envelope type, not by the subject they came in on. The authentication
/// half is absent on a device that may never answer one.
type Lane = futures::stream::Select<async_nats::Subscriber, AuthLane>;

/// The authentication half of [`Lane`]: one subscription, or none at all on
/// a device that may never answer an authentication.
type AuthLane =
    futures::stream::Flatten<futures::stream::Iter<std::option::IntoIter<async_nats::Subscriber>>>;

fn lane(requests: async_nats::Subscriber, authentications: Option<async_nats::Subscriber>) -> Lane {
    futures::stream::select(requests, futures::stream::iter(authentications).flatten())
}

/// Reads only the envelope's `type` tag, so one delivery can be routed to a
/// lane before anything decides how to parse the rest of it.
///
/// The legacy command envelope carries no `type` field at all, so `None`
/// means the command lane and nothing else has to change to keep it working.
#[derive(serde::Deserialize)]
struct EnvelopeTypeV1 {
    #[serde(rename = "type")]
    message_type: Option<String>,
}

/// Routes one delivery to its lane. Anything carrying a `type` this agent
/// does not implement is logged and dropped: answering an envelope whose
/// meaning is unknown is exactly what must not happen.
fn dispatch_nats_request(
    payload: &[u8],
    identity: &Arc<Identity>,
    decider: &Arc<Decider>,
    nats: Option<async_nats::Client>,
    admission: &RequestAdmission,
) {
    match serde_json::from_slice::<EnvelopeTypeV1>(payload) {
        Ok(EnvelopeTypeV1 { message_type: None }) => {}
        Ok(EnvelopeTypeV1 {
            message_type: Some(message_type),
        }) => {
            if message_type == AUTH_ENVELOPE_TYPE {
                dispatch_nats_authentication(payload, identity, decider, nats, admission);
            } else {
                warn!(
                    envelope_type = %escape_for_terminal(&message_type),
                    "ignoring envelope of an unknown type"
                );
            }
            return;
        }
        Err(error) => {
            warn!(
                error = %escape_for_terminal(&error.to_string()),
                "ignoring malformed request"
            );
            return;
        }
    }
    dispatch_nats_command(payload, identity, decider, nats, admission);
}

/// Decodes and admits one NATS delivery. Admission happens before opening the
/// sealed body, so capacity drops do not spend crypto work or create tasks.
fn dispatch_nats_command(
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
            && let Err(error) = publish_alive(nats, &opened.request.request_id).await
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

/// Decodes and admits one contextual sudo authentication delivery. It mirrors
/// [`dispatch_nats_command`] with two differences that are the point of the
/// lane: a software identity never answers, and there is no denial to
/// publish — a skipped prompt publishes nothing and the host falls back to
/// asking for a password.
fn dispatch_nats_authentication(
    payload: &[u8],
    identity: &Arc<Identity>,
    decider: &Arc<Decider>,
    nats: Option<async_nats::Client>,
    admission: &RequestAdmission,
) {
    let envelope: AuthEnvelopeV1 = match serde_json::from_slice(payload) {
        Ok(envelope) => envelope,
        Err(error) => {
            warn!(
                error = %escape_for_terminal(&error.to_string()),
                "ignoring malformed authentication request"
            );
            return;
        }
    };
    // Checked before admission and before any crypto: a software key cannot
    // produce an assurance this lane accepts, so the honest answer is to say
    // nothing and let the host ask for a password.
    if !identity_may_authenticate(identity, &envelope.request_id) {
        return;
    }
    let Some(permit) = admission.reserve() else {
        warn!("discarding authentication request while agent work is at capacity");
        return;
    };
    let opened = match identity.open_auth_request(&envelope) {
        Ok(Some(opened)) => opened,
        Ok(None) => return,
        Err(error) => {
            warn!(
                request_id = %escape_for_terminal(&envelope.request_id),
                error = %escape_for_terminal(&error.to_string()),
                "ignoring authentication request"
            );
            return;
        }
    };
    if !permit.claim(&auth_dedupe_key(&envelope.request_id)) {
        warn!(
            request_id = %escape_for_terminal(&envelope.request_id),
            "discarding duplicate authentication request"
        );
        return;
    }
    let identity = Arc::clone(identity);
    let decider = Arc::clone(decider);
    tokio::spawn(async move {
        let _permit = permit;
        if let Some(nats) = &nats
            && let Err(error) = publish_alive(nats, &opened.request.request_id).await
        {
            warn!(
                request_id = %escape_for_terminal(&opened.request.request_id),
                error = %escape_for_terminal(&error.to_string()),
                "native liveness acknowledgement failed; authentication prompt suppressed"
            );
            return;
        }
        let result = match decide_authentication(&identity, &decider, &opened).await {
            Ok(Some(decision)) => match nats {
                Some(nats) => publish_authentication(&nats, &opened.request, decision).await,
                None => Ok(()),
            },
            Ok(None) => Ok(()),
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            warn!(
                request_id = %escape_for_terminal(&opened.request.request_id),
                error = %escape_for_terminal(&error.to_string()),
                "authentication decision failed"
            );
        }
    });
}

/// The dedupe key for one authentication request.
///
/// Namespaced away from the command lane's bare request id. The two lanes
/// mint ids independently, so a command envelope carrying the same id must
/// not be able to consume an authentication's one-shot claim (or the other
/// way round) and make the real request look like a replay.
fn auth_dedupe_key(request_id: &str) -> String {
    format!("auth:{request_id}")
}

/// Whether this identity's key may answer an authentication request at all.
/// Only a hardware-backed signer may; a software one is refused here, with a
/// log line, even if the envelope somehow named its fingerprint.
fn identity_may_authenticate(identity: &Identity, request_id: &str) -> bool {
    if identity.device_kind() == DeviceKindV1::SecureEnclave {
        return true;
    }
    warn!(
        request_id = %escape_for_terminal(request_id),
        "ignoring authentication request: this device holds a software key, which cannot \
         answer a sudo authentication"
    );
    false
}

/// Answers one opened authentication request. `Ok(None)` means no assertion
/// was produced — the request expired, the operator skipped the prompt, or
/// the sheet was dismissed — and the caller publishes nothing.
///
/// There is no negative answer to publish. A refusal on this lane is silence:
/// the host's PAM stack then asks for a password, which is the outcome the
/// operator wanted. A signed "no" would only add a way to turn a request
/// nobody read into a failure nobody chose.
async fn decide_authentication(
    identity: &Arc<Identity>,
    decider: &Decider,
    opened: &OpenedAuthRequestV1,
) -> Result<Option<AuthDecisionV1>> {
    let request = &opened.request;
    if request.expires_at <= now() {
        bail!("authentication request already expired");
    }
    match decider {
        #[cfg(target_os = "macos")]
        Decider::TouchId(prompt) => mac::authenticate(prompt, identity, opened).await,
        // Decision: `run --auto` does not answer this lane, in either
        // direction. The flag exists so end-to-end tests can drive the
        // command lane without a human, and its `deny` arm has no meaning
        // here at all. Auto-authenticating sudo would hand every process on
        // the host a passwordless root prompt, which is the one thing this
        // lane exists to prevent; an unattended host falls back to the
        // password path instead.
        Decider::Auto(_) => {
            warn!(
                request_id = %escape_for_terminal(&request.request_id),
                "ignoring authentication request: --auto never answers a sudo authentication"
            );
            Ok(None)
        }
        Decider::Prompt(prompter) => {
            let summary = authentication_summary(request);
            let Some(()) = prompter
                .ask_authentication(&request.request_id, &summary, request.expires_at)
                .await?
            else {
                info!(
                    request_id = %escape_for_terminal(&request.request_id),
                    host = %escape_for_terminal(&request.trusted.host),
                    "authentication request was not answered"
                );
                return Ok(None);
            };
            Ok(Some(
                identity.authenticate(opened, &authentication_reason(request))?,
            ))
        }
    }
}

/// What the operator reads before authenticating: who is being authenticated
/// for what, on which host, and the invocation that was submitted with the
/// request.
///
/// The invocation is display context, never a claim about what sudo will
/// finally run — PAM does not know that yet — so its status is shown as it
/// is, including when it is missing or cut short.
fn authentication_summary(request: &AuthRequestV1) -> String {
    let trusted = &request.trusted;
    format!(
        "Authenticate sudo on {} for {} (invoked by {}, {}, tty {})\n  invocation: {}\n",
        escape_for_terminal(&trusted.host),
        escape_for_terminal(&trusted.pam_user),
        escape_for_terminal(&invoking_user_label(request)),
        escape_for_terminal(&trusted.service),
        escape_for_terminal(trusted.tty.as_deref().unwrap_or("unknown")),
        escape_for_terminal(&invocation_label(&request.submitted.invocation)),
    )
}

/// Names the account that invoked sudo. The numeric UID is always shown: the
/// name is a host-side lookup that can fail, and the number is what PAM
/// actually captured.
fn invoking_user_label(request: &AuthRequestV1) -> String {
    match &request.trusted.invoking_user {
        Some(name) => format!("{name}, uid {}", request.trusted.invoking_uid),
        None => format!("uid {}", request.trusted.invoking_uid),
    }
}

/// Renders the submitted invocation with its status intact. "unavailable" and
/// "truncated:" are part of the text an operator reads, because a partial
/// command line presented as a whole one would be a claim this lane cannot
/// make.
fn invocation_label(invocation: &AuthInvocationV1) -> String {
    match invocation {
        AuthInvocationV1::Available { command, argv, .. } => {
            let rendered = quote_argv(argv);
            if rendered.is_empty() {
                command.clone()
            } else {
                rendered
            }
        }
        AuthInvocationV1::Truncated {
            command,
            argv,
            omitted_args,
            ..
        } => {
            let rendered = quote_argv(argv);
            let shown = if rendered.is_empty() {
                command.clone().unwrap_or_else(|| "(none)".to_owned())
            } else {
                rendered
            };
            match omitted_args {
                Some(count) => format!("truncated: {shown} (+{count} more arguments)"),
                None => format!("truncated: {shown}"),
            }
        }
        AuthInvocationV1::Unavailable => "unavailable".to_owned(),
    }
}

/// What a signer backend that asks the operator puts on screen. The same
/// character budget as the command lane's reason applies, and the same rule:
/// nothing shown here can change what is verified, which is the exact bytes.
fn authentication_reason(request: &AuthRequestV1) -> String {
    let trusted = &request.trusted;
    let head = format!(
        "authenticate sudo: {}@{}",
        escape_for_terminal(&trusted.pam_user),
        escape_for_terminal(&trusted.host)
    );
    let room = MAX_APPROVAL_REASON_CHARS.saturating_sub(head.chars().count() + 1);
    if room == 0 {
        return truncate_chars(&head, MAX_APPROVAL_REASON_CHARS);
    }
    format!(
        "{head} {}",
        truncate_chars(
            &escape_for_terminal(&invocation_label(&request.submitted.invocation)),
            room
        )
    )
}

/// Publishes one authentication assertion on the shared verdict subject the
/// hook waits on for this request id.
async fn publish_authentication(
    nats: &async_nats::Client,
    request: &AuthRequestV1,
    decision: AuthDecisionV1,
) -> Result<()> {
    nats.publish(
        format!("oshioki.verdict.{}", request.request_id),
        serde_json::to_vec(&decision)?.into(),
    )
    .await
    .context("publish authentication decision")?;
    nats.flush().await?;
    info!(
        request_id = %escape_for_terminal(&request.request_id),
        host = %escape_for_terminal(&request.trusted.host),
        pam_user = %escape_for_terminal(&request.trusted.pam_user),
        "sudo authentication published"
    );
    Ok(())
}

/// Connect NATS and subscribe to requests, or return `None` when the network
/// is unset so the agent answers socket requests only. An unreachable NATS
/// is not an error: the client keeps connecting in the background and the
/// subscription takes effect the moment it lands.
async fn subscribe_requests(identity: &Identity) -> Result<Option<(async_nats::Client, Lane)>> {
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
    // Contextual sudo authentication rides its own subject tree, so a
    // command approval and an authentication can never be confused for one
    // another by routing alone. Both streams feed the one dispatcher below,
    // which decides the lane from the envelope itself.
    //
    // A software identity does not subscribe at all: it can never produce an
    // assurance this lane accepts, so carrying every host's authentication
    // traffic to it only to refuse each one is waste. The socket path keeps
    // its refusal regardless — the hook connects to this agent by name
    // there, and silence would look like a transport fault rather than the
    // answer it is.
    let authentications = if identity.device_kind() == DeviceKindV1::SecureEnclave {
        Some(
            nats.subscribe("oshioki.auth.>")
                .await
                .context("subscribe authentications")?,
        )
    } else {
        info!("this device holds a software key; not subscribing to sudo authentications");
        None
    };
    info!(
        fingerprint = %identity.fingerprint(),
        "NATS connection in progress; requests are answered once it is up"
    );
    Ok(Some((nats, lane(requests, authentications))))
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
    let reason = approval_reason_for_raw(request);
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
async fn publish_alive(nats: &async_nats::Client, request_id: &str) -> Result<()> {
    nats.publish(
        format!("oshioki.ack.{request_id}"),
        serde_json::to_vec(&AliveV1::for_request(request_id))?.into(),
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
    // Same routing rule as the NATS lane: the envelope's own `type` decides,
    // not the transport it arrived on. The command envelope carries no type
    // tag, so nothing about the legacy path changes.
    match serde_json::from_slice::<EnvelopeTypeV1>(&bytes)
        .context("decode socket envelope")?
        .message_type
    {
        None => {}
        Some(message_type) if message_type == AUTH_ENVELOPE_TYPE => {
            return handle_socket_authentication(&bytes, identity, decider, permit, writer).await;
        }
        Some(message_type) => {
            warn!(
                envelope_type = %escape_for_terminal(&message_type),
                "ignoring socket envelope of an unknown type"
            );
            return Ok(());
        }
    }
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

/// Answers one contextual sudo authentication over the local socket: the
/// same acknowledge-then-answer shape as the command lane, with no denial
/// frame. Hanging up without an assertion means this agent is not answering,
/// and the hook falls back to NATS and then to the password path.
async fn handle_socket_authentication(
    bytes: &[u8],
    identity: &Arc<Identity>,
    decider: &Decider,
    permit: RequestPermit,
    mut writer: tokio::net::unix::OwnedWriteHalf,
) -> Result<()> {
    let envelope: AuthEnvelopeV1 =
        serde_json::from_slice(bytes).context("decode socket authentication envelope")?;
    if !identity_may_authenticate(identity, &envelope.request_id) {
        return Ok(());
    }
    let opened = match identity.open_auth_request(&envelope) {
        Ok(Some(opened)) => opened,
        Ok(None) => return Ok(()),
        Err(error) => {
            warn!(
                request_id = %escape_for_terminal(&envelope.request_id),
                error = %escape_for_terminal(&error.to_string()),
                "ignoring socket authentication request"
            );
            return Ok(());
        }
    };
    if !permit.claim(&auth_dedupe_key(&envelope.request_id)) {
        warn!(
            request_id = %escape_for_terminal(&envelope.request_id),
            "discarding duplicate socket authentication request"
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
    let Some(decision) = decide_authentication(identity, decider, &opened).await? else {
        return Ok(());
    };
    let frame = oshioki_protocol::socket_v1::encode_frame(&serde_json::to_vec(&decision)?)?;
    writer
        .write_all(&frame)
        .await
        .context("write socket authentication")?;
    info!(
        request_id = %escape_for_terminal(&opened.request.request_id),
        "socket authentication answered"
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

/// What the operator is being asked to allow, shown on the Touch ID sheet
/// itself: the companion review dialog this text once deferred to is gone
/// (#70), so the sheet is the only thing an operator reads before approving.
/// A hash and a request ID told them nothing; host, user, and the command
/// are what a person actually recognizes at a glance. Everything here still
/// comes from the signed request, so a truncated or even fully dropped
/// suffix cannot change what gets executed — the full bytes are verified
/// independently of this display string.
///
/// Format: `<session>: <user>@<host> sudo <argv...>`, with the `<session>: `
/// prefix dropped when no session name resolves, and `sudo` omitted when
/// `argv[0]` already names it. Host and user are never dropped; the argv
/// tail is truncated with "…" to fit the cap, and the session prefix is the
/// first thing dropped under pressure.
fn approval_reason_for_raw(request: &oshioki_protocol::RequestV1) -> String {
    let target = format!(
        "{}@{}",
        escape_for_terminal(&request.user),
        escape_for_terminal(&request.host)
    );
    let argv = quote_argv(&request.argv);
    let wants_sudo_prefix = !matches!(request.argv.first(), Some(first) if first == "sudo");
    let command = if argv.is_empty() {
        escape_for_terminal(&request.command)
    } else if wants_sudo_prefix {
        format!("sudo {}", escape_for_terminal(&argv))
    } else {
        escape_for_terminal(&argv)
    };
    let session = session_name_for(request);

    // The target (`<user>@<host>`) is never truncated or dropped. The
    // session prefix is the first thing dropped under pressure: the command
    // is more useful than the session label when space is tight, so the
    // session is shown only when the full command fits alongside it too —
    // never as a surviving label next to a chopped-up command.
    let target_only_room = MAX_APPROVAL_REASON_CHARS.saturating_sub(target.chars().count() + 1);
    if target_only_room == 0 {
        // The target alone overflows the cap (an implausibly long
        // user/host): show as much of it as fits rather than nothing.
        return truncate_chars(&target, MAX_APPROVAL_REASON_CHARS);
    }
    if let Some(name) = &session {
        let prefix = format!("{name}: ");
        let fixed_len = prefix.chars().count() + target.chars().count() + 1;
        if fixed_len + command.chars().count() <= MAX_APPROVAL_REASON_CHARS {
            return format!("{prefix}{target} {command}");
        }
        // The session plus the full command does not fit: drop the session
        // rather than show a truncated command next to an intact label.
    }
    format!("{target} {}", truncate_chars(&command, target_only_room))
}

/// Shrinks `value` to at most `max_chars` characters, replacing a dropped
/// tail with "…" so the operator can tell the text was cut rather than
/// reading a command that happens to end early.
fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }
    if max_chars == 0 {
        return String::new();
    }
    let keep = max_chars.saturating_sub(1);
    let mut truncated: String = value.chars().take(keep).collect();
    truncated.push('…');
    truncated
}

/// Names the session a request came from, using only fields carried on the
/// request itself — the agent never reads the requesting host's live
/// process table. First match wins:
///
/// 1. The request's `session` field, which the hook resolves on the host
///    from an `OSHIOKI_SESSION` entry in the caller's original environment
///    — see `session_label` in `hook/src/main.rs`. Absent when the hook
///    predates this field (0.1.4 and earlier), in which case the remaining
///    rules apply exactly as before.
/// 2. An `OSHIOKI_SESSION` environment entry, which a user can export in a
///    shell or terminal tab to label it (documented in `docs/configuration.md`).
///    Kept as a fallback for an old hook that bound the environment but
///    never resolved `session` itself.
/// 3. The nearest "interesting" ancestor in `pid_chain` — entries are
///    `"pid:comm"` pairs (see `pid_chain_darwin`/`pid_chain_linux` in
///    `hook/src/main.rs`), so a process name like `claude`, `codex`, or
///    `tmux` is usable directly; shells and `sudo` itself are skipped as
///    uninteresting. Rendered as `comm[pid]` (e.g. `claude[44930]`) so two
///    concurrent agent sessions on the same host are distinguishable, while
///    staying short enough for the reason's character budget.
/// 4. The tty's basename (e.g. `ttys004`), if the request carries one.
///
/// `None` when nothing resolves, in which case the reason drops the prefix
/// entirely rather than show a blank label.
fn session_name_for(request: &oshioki_protocol::RequestV1) -> Option<String> {
    if let Some(session) = request.session.as_ref().filter(|value| !value.is_empty()) {
        return Some(escape_for_terminal(session));
    }
    if let Some(entry) = request
        .env
        .iter()
        .rev()
        .find(|entry| entry.name == "OSHIOKI_SESSION" && !entry.value.is_empty())
    {
        return Some(escape_for_terminal(&entry.value));
    }
    if let Some((pid, comm)) = request.pid_chain.iter().find_map(|entry| {
        let (pid, comm) = entry.split_once(':')?;
        is_interesting_session_process(comm).then_some((pid, comm))
    }) {
        return Some(escape_for_terminal(&format!("{comm}[{pid}]")));
    }
    if let Some(tty) = &request.tty {
        if let Some(basename) = tty.rsplit('/').next().filter(|value| !value.is_empty()) {
            return Some(escape_for_terminal(basename));
        }
    }
    None
}

/// Whether a `pid_chain` process name is worth naming a session after.
/// Shells, `sudo` itself, and init/daemon wrappers say nothing a user would
/// recognize as "their" session; an agent harness or multiplexer name does.
fn is_interesting_session_process(comm: &str) -> bool {
    !matches!(
        comm,
        "sudo"
            | "sh"
            | "bash"
            | "zsh"
            | "dash"
            | "fish"
            | "login"
            | "sshd"
            | "systemd"
            | "launchd"
            | "init"
    )
}

/// The reason's cap for a system-owned biometric prompt. `LocalAuthentication`
/// wraps a long reason across lines on the sheet rather than truncating it
/// outright (confirmed on-device with a two-line reason under the previous,
/// tighter cap), so this is set with headroom for host, user, and a short
/// command rather than the bare id-and-hash the sheet used to show. Still
/// conservative pending a longer on-device check of how many lines look
/// reasonable.
const MAX_APPROVAL_REASON_CHARS: usize = 160;

/// Test helper for the short reason generated from a semantically valid
/// request. Production paths use the exact retained bytes directly.
#[cfg(test)]
fn approval_reason(request: &oshioki_protocol::RequestV1) -> String {
    approval_reason_for_raw(request)
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

    /// Asks the terminal about one sudo authentication. The only answer is
    /// the affirmative one: an empty line authenticates, and anything else —
    /// a stray word, a dismissal, the deadline — skips.
    ///
    /// `Some(())` means authenticate; `None` means publish nothing, which on
    /// this lane is how the host is told to ask for a password instead. There
    /// is deliberately no way to answer "no" here: a refusal that travelled
    /// as a message would be a way to fail an authentication the operator
    /// never saw.
    async fn ask_authentication(
        &self,
        request_id: &str,
        summary: &str,
        expires_at: i64,
    ) -> Result<Option<()>> {
        let mut lines = self.lines.lock().await;
        let Some(remaining) = remaining_until(expires_at) else {
            return Ok(None);
        };
        while lines.try_recv().is_ok() {}
        print!(
            "{}",
            authentication_prompt_output(request_id, summary, io::stdout().is_terminal())
        );
        io::stdout().flush()?;
        match tokio::time::timeout(remaining, lines.recv()).await {
            Ok(Some(answer)) => Ok(answer.trim().is_empty().then_some(())),
            Ok(None) => bail!("stdin closed"),
            Err(_) => {
                println!("\nauthentication request expired before it was answered");
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

/// What one authentication prompt may print. Same rule as the command lane:
/// the summary is rendered only to a live terminal, because stdout is the
/// persistent agent log under launchd and an authentication's context —
/// account, service, tty, invocation — does not belong in it.
fn authentication_prompt_output(
    request_id: &str,
    summary: &str,
    stdout_is_terminal: bool,
) -> String {
    if stdout_is_terminal {
        format!("{summary}[Enter to authenticate, anything else / timeout to skip] ")
    } else {
        format!(
            "authentication request {} needs an answer, but stdout is not a terminal: \
             no request details are shown here\n[Enter to authenticate, anything else / \
             timeout to skip] ",
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
    use std::sync::Arc;

    use anyhow::Result;
    use oshioki_agent::{
        Identity, OpenedRequest,
        touchid::{AttemptError, Outcome, PromptCancel, ScreenLock, TouchIdPrompt},
    };
    use oshioki_enclave::SignError;
    use oshioki_protocol::{AuthDecisionV1, DecisionV1, OpenedAuthRequestV1, escape_for_terminal};
    use tracing::{error, info};

    use super::{approval_reason_for_raw, authentication_reason};

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
        let reason = approval_reason_for_raw(request);
        let sign = {
            let (identity, opened, reason) = (Arc::clone(identity), opened.clone(), reason.clone());
            move || identity.approve(&opened, &reason).map_err(classify)
        };
        match prompt
            .ask(&request.request_id, request.expires_at, sign)
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

    /// Asks for one contextual sudo authentication with a Touch ID sheet.
    ///
    /// The same sheet, the same serialization, and the same deadline rules as
    /// a command approval — with no negative outcome to report. A dismissed
    /// sheet publishes nothing, and the host's PAM stack asks for a password.
    pub async fn authenticate(
        prompt: &TouchIdPrompt,
        identity: &Arc<Identity>,
        opened: &OpenedAuthRequestV1,
    ) -> Result<Option<AuthDecisionV1>> {
        let request = &opened.request;
        let reason = authentication_reason(request);
        let sign = {
            let (identity, opened, reason) = (Arc::clone(identity), opened.clone(), reason.clone());
            move || identity.authenticate(&opened, &reason).map_err(classify)
        };
        match prompt
            .ask(&request.request_id, request.expires_at, sign)
            .await
        {
            Ok(Outcome::Approved(decision)) => Ok(Some(decision)),
            Ok(Outcome::Denied) => Ok(None),
            Ok(Outcome::Expired) => {
                info!(
                    request_id = %escape_for_terminal(&request.request_id),
                    host = %escape_for_terminal(&request.trusted.host),
                    "authentication request expired unanswered"
                );
                Ok(None)
            }
            Err(error) => {
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
        Cli, Decider, MAX_APPROVAL_REASON_CHARS, MAX_IN_FLIGHT_REQUESTS, Pairing, Prompter,
        RequestAdmission, Verb, approval_reason, authentication_prompt_output,
        authentication_reason, authentication_summary, bind_socket, decide, decide_authentication,
        dispatch_nats_request, format_env, load_or_create_with, now, prompt_output, quote_argv,
        runas_label, socket_path,
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

    fn auth_request_for_tests() -> oshioki_protocol::AuthRequestV1 {
        oshioki_protocol::AuthRequestV1 {
            message_type: oshioki_protocol::AUTH_REQUEST_TYPE.into(),
            version: oshioki_protocol::AUTH_WIRE_VERSION,
            request_id: "auth-1".into(),
            nonce: encode_base64url(&[3; 16]),
            issued_at: now(),
            expires_at: now() + 70,
            trusted: oshioki_protocol::TrustedAuthContextV1 {
                host: "host.example".into(),
                service: "sudo".into(),
                pam_user: "root".into(),
                pam_uid: 0,
                invoking_uid: 1000,
                invoking_user: Some("eric".into()),
                tty: Some("/dev/pts/3".into()),
            },
            submitted: oshioki_protocol::SubmittedAuthContextV1 {
                session: None,
                agent_label: None,
                invocation: oshioki_protocol::AuthInvocationV1::Truncated {
                    command: None,
                    argv: vec!["apt".into(), "upgrade".into()],
                    cwd: None,
                    omitted_args: Some(2),
                },
            },
        }
    }

    fn auth_envelope_bytes(
        identity: &oshioki_agent::Identity,
        request: &oshioki_protocol::AuthRequestV1,
    ) -> Vec<u8> {
        let raw = request.raw_json().unwrap();
        let sealed = oshioki_protocol::seal_v1(&raw, &identity.device_record("test")).unwrap();
        let envelope = oshioki_protocol::AuthEnvelopeV1 {
            message_type: oshioki_protocol::AUTH_ENVELOPE_TYPE.into(),
            version: oshioki_protocol::AUTH_WIRE_VERSION,
            request_id: request.request_id.clone(),
            host: request.trusted.host.clone(),
            issued_at: request.issued_at,
            expires_at: request.expires_at,
            sealed: vec![sealed],
        };
        envelope.validate().unwrap();
        serde_json::to_vec(&envelope).unwrap()
    }

    /// A Linux agent holds a software key, so it is exactly the device that
    /// must never answer an authentication — even when the envelope was
    /// sealed to its own fingerprint. It never reaches admission, so it
    /// spends no work and claims no request id.
    #[tokio::test]
    async fn a_software_agent_never_answers_an_authentication_envelope() {
        let dir = socket_test_dir("auth-software");
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
        let payload = auth_envelope_bytes(&identity, &auth_request_for_tests());
        dispatch_nats_request(&payload, &identity, &decider, None, &admission);
        assert!(admission.request_ids.lock().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An envelope type this build does not implement is dropped, not
    /// guessed at, and the legacy lane it is not addressed to never sees it.
    #[tokio::test]
    async fn an_unknown_envelope_type_is_ignored() {
        let dir = socket_test_dir("auth-unknown");
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
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&auth_envelope_bytes(&identity, &auth_request_for_tests()))
                .unwrap();
        envelope["type"] = serde_json::json!("sudo_something_else");
        dispatch_nats_request(
            &serde_json::to_vec(&envelope).unwrap(),
            &identity,
            &decider,
            None,
            &admission,
        );
        assert!(admission.request_ids.lock().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `--auto` answers the command lane and nothing else. Auto-signing a
    /// sudo authentication would hand the host a passwordless root prompt,
    /// which is the outcome this lane exists to prevent.
    #[tokio::test]
    async fn auto_never_answers_an_authentication() {
        let identity = std::sync::Arc::new(
            oshioki_agent::Identity::from_material([0x11; 32], [0x22; 32], [0x33; 32]).unwrap(),
        );
        let request = auth_request_for_tests();
        let opened = oshioki_protocol::OpenedAuthRequestV1 {
            raw: request.raw_json().unwrap(),
            request,
        };
        for answer in [true, false] {
            assert!(
                decide_authentication(&identity, &Decider::Auto(answer), &opened)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }

    /// The only affirmative answer is an empty line. Anything else, and the
    /// deadline, publish nothing — which is how the host is told to ask for
    /// a password instead.
    #[tokio::test]
    async fn only_an_empty_line_authenticates() {
        for (answer, authenticates) in [("", true), ("y", false), ("n", false), ("no", false)] {
            let (sender, receiver) = mpsc::channel(1);
            let prompter = Prompter::new(receiver);
            // Lines typed before the prompt appeared are discarded, so the
            // answer has to arrive after the prompt is up, as at a terminal.
            let asked = tokio::spawn(async move {
                prompter
                    .ask_authentication("auth-1", "summary\n", now() + 30)
                    .await
            });
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            sender.send(answer.to_owned()).await.unwrap();
            let decided = asked.await.unwrap().unwrap();
            assert_eq!(decided.is_some(), authenticates, "{answer:?}");
        }
    }

    /// The prompt says what is being authenticated and offers exactly one
    /// action. No refusal is offered because none can be sent.
    #[test]
    fn the_authentication_prompt_offers_only_the_affirmative() {
        let summary = authentication_summary(&auth_request_for_tests());
        assert!(summary.contains("Authenticate sudo on host.example for root"));
        assert!(summary.contains("invoked by eric, uid 1000, sudo, tty /dev/pts/3"));
        assert!(summary.contains("invocation: truncated: apt upgrade (+2 more arguments)"));
        let prompt = authentication_prompt_output("auth-1", &summary, true);
        assert!(prompt.contains("[Enter to authenticate, anything else / timeout to skip]"));
        assert!(!prompt.to_lowercase().contains("deny"));
        // Off a terminal, stdout is the agent log: the context stays out of it.
        let logged = authentication_prompt_output("auth-1", &summary, false);
        assert!(!logged.contains("host.example"));
        assert!(logged.contains("auth-1"));
    }

    /// A missing invocation is shown as missing. Nothing on this lane may
    /// present partial or absent context as the command sudo will run.
    #[test]
    fn an_unavailable_invocation_is_labelled_honestly() {
        let mut request = auth_request_for_tests();
        request.submitted.invocation = oshioki_protocol::AuthInvocationV1::Unavailable;
        assert!(authentication_summary(&request).contains("invocation: unavailable"));
        assert!(authentication_reason(&request).contains("unavailable"));
        assert!(
            authentication_reason(&request).starts_with("authenticate sudo: root@host.example")
        );
        let mut anonymous = auth_request_for_tests();
        anonymous.trusted.invoking_user = None;
        anonymous.trusted.tty = None;
        let summary = authentication_summary(&anonymous);
        assert!(summary.contains("invoked by uid 1000"));
        assert!(summary.contains("tty unknown"));
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
            session: None,
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

    /// With no session name, the reason is `<user>@<host> sudo <argv>` and
    /// stays within the cap.
    #[test]
    fn reason_without_session_shows_user_host_and_command() {
        let request = request_for_reason();
        let reason = approval_reason(&request);
        assert_eq!(reason, "eric@host.example sudo apt update");
        assert!(reason.chars().count() <= MAX_APPROVAL_REASON_CHARS);
    }

    /// The request's `session` field, which the hook resolves on the host,
    /// takes priority over an `OSHIOKI_SESSION` environment entry.
    #[test]
    fn reason_prefers_request_session_field_over_env() {
        let mut request = request_for_reason();
        request.session = Some("oshioki-1b".into());
        request.env = vec![EnvEntryV1 {
            name: "OSHIOKI_SESSION".into(),
            value: "laptop-ghostty".into(),
        }];
        assert_eq!(
            approval_reason(&request),
            "oshioki-1b: eric@host.example sudo apt update"
        );
    }

    /// `OSHIOKI_SESSION` in the bound environment names the session, shown
    /// as a prefix ahead of the usual user@host/command text.
    #[test]
    fn reason_with_session_env_shows_session_prefix() {
        let mut request = request_for_reason();
        request.env = vec![EnvEntryV1 {
            name: "OSHIOKI_SESSION".into(),
            value: "laptop-ghostty".into(),
        }];
        assert_eq!(
            approval_reason(&request),
            "laptop-ghostty: eric@host.example sudo apt update"
        );
    }

    /// A later duplicate `OSHIOKI_SESSION` entry wins, matching the protocol
    /// rule that a duplicated env name's last value is the effective one.
    #[test]
    fn reason_session_env_prefers_last_duplicate() {
        let mut request = request_for_reason();
        request.env = vec![
            EnvEntryV1 {
                name: "OSHIOKI_SESSION".into(),
                value: "first".into(),
            },
            EnvEntryV1 {
                name: "OSHIOKI_SESSION".into(),
                value: "second".into(),
            },
        ];
        assert!(approval_reason(&request).starts_with("second: "));
    }

    /// Without an `OSHIOKI_SESSION` entry, the nearest interesting
    /// `pid_chain` ancestor names the session, rendered as `comm[pid]` so
    /// two concurrent agent sessions are distinguishable; shells and `sudo`
    /// itself are skipped as uninteresting.
    #[test]
    fn reason_falls_back_to_interesting_pid_chain_ancestor() {
        let mut request = request_for_reason();
        request.pid_chain = vec![
            "100:sudo".into(),
            "99:zsh".into(),
            "50:claude".into(),
            "1:launchd".into(),
        ];
        assert!(approval_reason(&request).starts_with("claude[50]: "));
    }

    /// With no session env and no interesting `pid_chain` entry, the tty
    /// basename is the last resort.
    #[test]
    fn reason_falls_back_to_tty_basename() {
        let mut request = request_for_reason();
        request.pid_chain = vec!["99:zsh".into(), "1:launchd".into()];
        request.tty = Some("/dev/ttys004".into());
        assert!(approval_reason(&request).starts_with("ttys004: "));
    }

    /// No session env, no interesting `pid_chain` ancestor, and no tty: the
    /// reason drops the prefix entirely rather than show an empty label.
    #[test]
    fn reason_drops_prefix_when_nothing_resolves() {
        let mut request = request_for_reason();
        request.pid_chain = vec!["99:zsh".into()];
        request.tty = None;
        let reason = approval_reason(&request);
        assert!(!reason.contains(':') || reason.starts_with("eric@"));
        assert_eq!(reason, "eric@host.example sudo apt update");
    }

    /// `sudo` is not repeated when the caller's argv already names it.
    #[test]
    fn reason_does_not_double_sudo() {
        let mut request = request_for_reason();
        request.argv = vec!["sudo".into(), "apt".into(), "update".into()];
        assert_eq!(
            approval_reason(&request),
            "eric@host.example sudo apt update"
        );
    }

    /// Host and user are never truncated or dropped, even when the argv is
    /// far too long to fit alongside them; the tail shrinks with "…" rather
    /// than overflowing the cap or cutting into user/host.
    #[test]
    fn reason_truncates_long_argv_without_touching_user_host() {
        let mut request = request_for_reason();
        request.command = "/usr/bin/find".into();
        request.argv = vec![
            "find".into(),
            "/".into(),
            "-name".into(),
            "*.rs".into(),
            "-exec".into(),
            "grep".into(),
            "-l".into(),
            "needle-".repeat(20),
            "{}".into(),
            "+".into(),
        ];
        let reason = approval_reason(&request);
        assert!(reason.chars().count() <= MAX_APPROVAL_REASON_CHARS);
        assert!(reason.starts_with("eric@host.example sudo "));
        assert!(reason.ends_with('…'));
    }

    /// Under the same pressure, a session-carrying request still shows the
    /// full user@host and drops the session prefix entirely rather than
    /// truncate it, since the command is more useful when space is tight.
    #[test]
    fn reason_truncation_prefers_command_over_session_name() {
        let mut request = request_for_reason();
        request.env = vec![EnvEntryV1 {
            name: "OSHIOKI_SESSION".into(),
            value: "a-very-long-session-label-that-eats-the-budget".into(),
        }];
        request.command = "/usr/bin/find".into();
        request.argv = vec![
            "find".into(),
            "/".into(),
            "-name".into(),
            "needle-".repeat(20),
        ];
        let reason = approval_reason(&request);
        assert!(reason.chars().count() <= MAX_APPROVAL_REASON_CHARS);
        assert!(reason.starts_with("eric@host.example sudo "));
        assert!(
            !reason.contains("a-very-long-session-label"),
            "the session prefix should be dropped, not truncated into noise: {reason}"
        );
        assert!(reason.ends_with('…'));
    }

    /// Changing the target account changes the reason: it is not a fixed
    /// template independent of the request.
    #[test]
    fn reason_changes_with_the_request() {
        let mut request = request_for_reason();
        let reason = approval_reason(&request);
        request.user = "otheruser".into();
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
            session: None,
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

    /// The decision paths log the request ID and host for operability, but
    /// never the reason text (shown only on the Touch ID sheet or the
    /// terminal prompt) or any other request field.
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
        // must not see it. The Touch ID reason is shown on-device rather
        // than logged (asserted below via `text`), so it legitimately
        // carries the probe now that the sheet shows user/host/command.
        let request = request_for_log_probe();
        let reason = approval_reason(&request);
        assert!(
            reason.contains(&format!("user-{LOG_PROBE}")),
            "the reason should show who asked: {reason}"
        );

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
