//! `oshioki-agent`: pairs a native device with a host and answers sudo
//! requests over NATS.
//!
//! This binary is the Linux and test build of the macOS agent (#9). It uses
//! a software P-256 key and a terminal prompt. macOS adds the Secure Enclave
//! backend and a native prompt on top of the same library.

use std::{
    future::Future,
    io::{self, BufRead, Write as _},
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
use oshioki_protocol::{ActivationV1, DecisionV1, RequestEnvelopeV1, escape_for_terminal};
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
        /// macOS and to a software key everywhere else.
        #[arg(long, value_enum)]
        signer: Option<SignerArg>,
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
        } => cmd_pair(&identity_path, &enrollment_url, &label, signer_kind(signer)).await,
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
fn load_or_create(path: &std::path::Path, kind: SignerKind) -> Result<Identity> {
    if path.exists() {
        let identity = Identity::load(path)?;
        if identity.signer_kind() != kind {
            warn!(
                signer = %identity.signer_kind(),
                "this device already has an identity; keeping its signing key"
            );
        }
        return Ok(identity);
    }
    let identity = Identity::generate_to(path, kind)?;
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
    kind: SignerKind,
) -> Result<()> {
    let (enrollment_id, secret) = parse_enrollment_url(url)?;
    let identity = load_or_create(identity_path, kind)?;
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
    let nats = connect_nats().await?;
    let mut requests = nats
        .subscribe("oshioki.request.>")
        .await
        .context("subscribe requests")?;
    nats.flush().await?;
    info!(fingerprint=%identity.fingerprint(), "watching for requests");
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
    loop {
        let message = tokio::select! {
            () = &mut stdin_closed => bail!(
                "stdin is closed, so no approval prompt can be answered and every request \
                 would wait out its deadline; run the agent on a terminal"
            ),
            message = requests.next() => message.context("request stream closed")?,
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
        let nats = nats.clone();
        let decider = Arc::clone(&decider);
        tokio::spawn(async move {
            if let Err(error) = decide(&identity, &nats, &decider, &opened).await {
                warn!(
                    request_id = %escape_for_terminal(&opened.request.request_id),
                    error = %escape_for_terminal(&error.to_string()),
                    "decision failed"
                );
            }
        });
    }
}

async fn decide(
    identity: &Arc<Identity>,
    nats: &async_nats::Client,
    decider: &Decider,
    opened: &OpenedRequest,
) -> Result<()> {
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
                return Ok(());
            };
            return publish(nats, request, decision).await;
        }
        Decider::Auto(answer) => *answer,
        Decider::Prompt(prompter) => {
            let summary = format!(
                "sudo on {}: {} (uid {}) wants to run as {}: {} {}\n  cwd: {}\n  callers: {}\n",
                escape_for_terminal(&request.host),
                escape_for_terminal(&request.user),
                request.uid,
                runas_label(request.runas_uid),
                escape_for_terminal(&request.command),
                escape_for_terminal(&quote_argv(&request.argv)),
                escape_for_terminal(&request.cwd),
                escape_for_terminal(&request.pid_chain.join(" <- ")),
            );
            // No answer means no signed verdict: the hook fails closed when
            // the deadline passes, and a Deny nobody typed would be a lie
            // about a request nobody read.
            let Some(answer) = prompter.ask(&summary, request.expires_at).await? else {
                info!(
                    request_id = %escape_for_terminal(&request.request_id),
                    host = %escape_for_terminal(&request.host),
                    "request expired unanswered"
                );
                return Ok(());
            };
            answer
        }
    };
    let decision = if approve {
        identity.approve(opened, &approval_reason(request))?
    } else {
        identity.deny(&request.request_id)
    };
    publish(nats, request, decision).await
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
/// this", and it is one line on somebody's screen. The working directory and
/// the caller process chain go to the log instead, where there is room.
fn approval_reason(request: &oshioki_protocol::RequestV1) -> String {
    let reason = format!(
        "run {} as {} on {}",
        escape_for_terminal(&request.command),
        runas_label(request.runas_uid),
        escape_for_terminal(&request.host),
    );
    truncate(&reason, MAX_REASON_CHARS)
}

/// How much of the reason the sheet gets. Past this it is not a sentence
/// anybody reads before touching the sensor.
const MAX_REASON_CHARS: usize = 120;

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
    async fn ask(&self, summary: &str, expires_at: i64) -> Result<Option<bool>> {
        let mut lines = self.lines.lock().await;
        let Some(remaining) = remaining_until(expires_at) else {
            return Ok(None);
        };
        while lines.try_recv().is_ok() {}
        print!("{summary}Approve? [y/N] ");
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
        // The sheet has room for one line, so the rest of the request is
        // logged rather than shown.
        info!(
            request_id = %escape_for_terminal(&request.request_id),
            user = %escape_for_terminal(&request.user),
            cwd = %escape_for_terminal(&request.cwd),
            callers = %escape_for_terminal(&request.pid_chain.join(" <- ")),
            reason = %escape_for_terminal(&reason),
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
    use super::{Prompter, approval_reason, now, quote_argv, runas_label, truncate};
    use oshioki_protocol::{RequestV1, VERSION_V1, encode_base64url};
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
    #[test]
    fn the_sheet_reason_names_the_command_the_account_and_the_host() {
        let mut request = request_for_reason();
        assert_eq!(
            approval_reason(&request),
            "run /usr/bin/apt as root (uid 0) on host.example"
        );
        request.runas_uid = 1000;
        assert!(approval_reason(&request).contains("as uid 1000"));
    }

    /// A command line long enough to fill the screen is cut, and says so.
    #[test]
    fn a_long_reason_is_cut_rather_than_wrapped() {
        assert_eq!(truncate("abcdef", 6), "abcdef");
        assert_eq!(truncate("abcdefg", 6), "abc...");
        let mut request = request_for_reason();
        request.command = "/usr/bin/".to_owned() + &"x".repeat(400);
        let reason = approval_reason(&request);
        assert_eq!(reason.chars().count(), 120);
        assert!(reason.ends_with("..."));
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
            prompter.ask("summary\n", now() + 30).await.unwrap(),
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
        assert_eq!(prompter.ask("summary\n", now() - 1).await.unwrap(), None);
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
        assert!(prompter.ask("summary\n", now() + 30).await.is_err());
    }

    /// The prompt stops at the expiry instant itself. Whole-second
    /// arithmetic let it wait most of a second past a dead request and sign
    /// for it.
    #[tokio::test]
    async fn prompt_stops_at_the_exact_deadline() {
        let (sender, receiver) = mpsc::channel(8);
        let prompter = Prompter::new(receiver);
        let expires_at = now() + 1;
        assert_eq!(prompter.ask("summary\n", expires_at).await.unwrap(), None);
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
        assert_eq!(prompter.ask("summary\n", now() + 1).await.unwrap(), None);
        drop(sender);
    }
}
