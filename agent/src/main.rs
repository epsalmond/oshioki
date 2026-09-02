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
use clap::{Parser, Subcommand, ValueEnum};
use futures::StreamExt as _;
use oshioki_agent::{Identity, OpenedRequest, parse_enrollment_url};
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
    },
    /// Watch for requests and decide them.
    Run {
        /// Decide every request without asking. For tests only.
        #[arg(long, value_enum)]
        auto: Option<Auto>,
    },
    /// Print this device's fingerprint.
    Show,
}

#[derive(Clone, Copy, ValueEnum)]
enum Auto {
    Approve,
    Deny,
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
        } => cmd_pair(&identity_path, &enrollment_url, &label).await,
        Verb::Run { auto } => cmd_run(&identity_path, auto).await,
        Verb::Show => {
            println!("{}", Identity::load(&identity_path)?.fingerprint());
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
fn load_or_create(path: &std::path::Path) -> Result<Identity> {
    if path.exists() {
        Identity::load(path)
    } else {
        let identity = Identity::generate_to(path)?;
        info!(path=%path.display(), fingerprint=%identity.fingerprint(), "created device identity");
        Ok(identity)
    }
}

async fn cmd_pair(identity_path: &std::path::Path, url: &str, label: &str) -> Result<()> {
    let (enrollment_id, secret) = parse_enrollment_url(url)?;
    let identity = load_or_create(identity_path)?;
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

async fn cmd_run(identity_path: &std::path::Path, auto: Option<Auto>) -> Result<()> {
    let identity = Arc::new(Identity::load(identity_path)?);
    let nats = connect_nats().await?;
    let mut requests = nats
        .subscribe("oshioki.request.>")
        .await
        .context("subscribe requests")?;
    nats.flush().await?;
    info!(fingerprint=%identity.fingerprint(), "watching for requests");
    let (decider, stdin_closed) = match auto {
        Some(Auto::Approve) => (Decider::Auto(true), None),
        Some(Auto::Deny) => (Decider::Auto(false), None),
        None => {
            let (prompter, closed) = Prompter::from_stdin();
            (Decider::Prompt(prompter), Some(closed))
        }
    };
    let decider = Arc::new(decider);
    // A prompt with no stdin behind it answers nothing, and the hook waits
    // out its full deadline on every request. Say so and stop instead.
    let mut stdin_closed: Pin<Box<dyn Future<Output = ()> + Send>> = match stdin_closed {
        Some(closed) => Box::pin(async move {
            let _ = closed.await;
        }),
        None => Box::pin(std::future::pending()),
    };
    loop {
        let message = tokio::select! {
            () = &mut stdin_closed => bail!(
                "stdin is closed, so no approval prompt can be answered and every request \
                 would wait out its deadline; run the agent on a terminal, or with --auto \
                 for unattended tests"
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
    identity: &Identity,
    nats: &async_nats::Client,
    decider: &Decider,
    opened: &OpenedRequest,
) -> Result<()> {
    let request = &opened.request;
    if request.expires_at <= now() {
        bail!("request already expired");
    }
    let approve = match decider {
        Decider::Auto(answer) => *answer,
        Decider::Prompt(prompter) => {
            let summary = format!(
                "sudo on {}: {} (uid {}) wants to run as {}: {} {}\n  cwd: {}\n  callers: {}\n",
                escape_for_terminal(&request.host),
                escape_for_terminal(&request.user),
                request.uid,
                runas_label(request.runas_uid),
                escape_for_terminal(&request.command),
                escape_for_terminal(&request.argv.join(" ")),
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
        identity.approve(opened)?
    } else {
        identity.deny(&request.request_id)
    };
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

/// Where a verdict comes from: `--auto` for tests, otherwise the terminal.
enum Decider {
    Auto(bool),
    Prompt(Prompter),
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
        let Ok(remaining) = u64::try_from(expires_at - now()) else {
            return Ok(None);
        };
        if remaining == 0 {
            return Ok(None);
        }
        while lines.try_recv().is_ok() {}
        print!("{summary}Approve? [y/N] ");
        io::stdout().flush()?;
        match tokio::time::timeout(Duration::from_secs(remaining), lines.recv()).await {
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

#[cfg(test)]
mod tests {
    use super::{Prompter, now, runas_label};
    use tokio::sync::mpsc;

    /// The prompt names the target account for every request, including the
    /// root default that sudo leaves implicit.
    #[test]
    fn target_account_is_always_named() {
        assert_eq!(runas_label(0), "root (uid 0)");
        assert_eq!(runas_label(1000), "uid 1000");
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

    /// Waiting out the deadline is silence, not a denial.
    #[tokio::test]
    async fn unanswered_prompt_yields_no_verdict() {
        let (sender, receiver) = mpsc::channel(8);
        let prompter = Prompter::new(receiver);
        assert_eq!(prompter.ask("summary\n", now() + 1).await.unwrap(), None);
        drop(sender);
    }
}
