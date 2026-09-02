//! `oshioki-agent`: pairs a native device with a host and answers sudo
//! requests over NATS.
//!
//! This binary is the Linux and test build of the macOS agent (#9). It uses
//! a software P-256 key and a terminal prompt. macOS adds the Secure Enclave
//! backend and a native prompt on top of the same library.

use std::{
    fmt::Write as _,
    io::{self, BufRead as _, Write as _},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use futures::StreamExt as _;
use oshioki_agent::{Identity, OpenedRequest, parse_enrollment_url};
use oshioki_protocol::{ActivationV1, DecisionV1, RequestEnvelopeV1};
use tokio::sync::Mutex;
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
        activation.device.fingerprint, activation.device.label
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
    let prompt = Arc::new(Mutex::new(()));
    while let Some(message) = requests.next().await {
        let envelope: RequestEnvelopeV1 = match serde_json::from_slice(&message.payload) {
            Ok(envelope) => envelope,
            Err(error) => {
                warn!(%error, "ignoring malformed request");
                continue;
            }
        };
        let opened = match identity.open_request(&envelope) {
            Ok(Some(opened)) => opened,
            Ok(None) => continue,
            Err(error) => {
                warn!(request_id=%envelope.request_id, %error, "ignoring request");
                continue;
            }
        };
        let identity = Arc::clone(&identity);
        let nats = nats.clone();
        let prompt = Arc::clone(&prompt);
        tokio::spawn(async move {
            if let Err(error) = decide(&identity, &nats, &prompt, &opened, auto).await {
                warn!(request_id=%opened.request.request_id, %error, "decision failed");
            }
        });
    }
    bail!("request stream closed")
}

async fn decide(
    identity: &Identity,
    nats: &async_nats::Client,
    prompt: &Mutex<()>,
    opened: &OpenedRequest,
    auto: Option<Auto>,
) -> Result<()> {
    let request = &opened.request;
    let remaining = u64::try_from(request.expires_at - now()).unwrap_or(0);
    if remaining == 0 {
        bail!("request already expired");
    }
    let approve = match auto {
        Some(Auto::Approve) => true,
        Some(Auto::Deny) => false,
        None => {
            let _serialized = prompt.lock().await;
            let summary = format!(
                "sudo on {}: {} wants to run {} {}\n  cwd: {}\n  callers: {}\n",
                escape_for_terminal(&request.host),
                escape_for_terminal(&request.user),
                escape_for_terminal(&request.command),
                escape_for_terminal(&request.argv.join(" ")),
                escape_for_terminal(&request.cwd),
                escape_for_terminal(&request.pid_chain.join(" <- ")),
            );
            tokio::time::timeout(Duration::from_secs(remaining), ask(summary))
                .await
                .unwrap_or(Ok(false))?
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
    info!(request_id=%request.request_id, host=%request.host, verb, "decision published");
    Ok(())
}

/// Renders untrusted request text for a terminal.
///
/// Every field in the prompt comes from the requesting host: the command
/// line, the working directory, and process names read out of `/proc`. A
/// control character in any of them can repaint the screen and hide what is
/// really being approved, so escape the C0 and C1 ranges (ESC, CR, DEL and
/// friends) and the backslash that introduces them.
fn escape_for_terminal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character == '\\' {
            escaped.push_str("\\\\");
        } else if character.is_control() {
            let _ = write!(escaped, "\\u{{{:04x}}}", character as u32);
        } else {
            escaped.push(character);
        }
    }
    escaped
}

/// Terminal prompt. Any answer other than `y` denies.
async fn ask(summary: String) -> Result<bool> {
    tokio::task::spawn_blocking(move || {
        let mut stdout = io::stdout().lock();
        write!(stdout, "{summary}Approve? [y/N] ")?;
        stdout.flush()?;
        let mut answer = String::new();
        io::stdin().lock().read_line(&mut answer)?;
        Ok(answer.trim().eq_ignore_ascii_case("y"))
    })
    .await
    .context("prompt task")?
}

async fn connect_nats() -> Result<async_nats::Client> {
    let url = std::env::var("NATS_URL").context("NATS_URL is not set")?;
    let mut options = async_nats::ConnectOptions::new();
    if let (Ok(user), Ok(pass)) = (std::env::var("NATS_USER"), std::env::var("NATS_PASS")) {
        options = options.user_and_password(user, pass);
    }
    options.connect(&url).await.context("connect to NATS")
}

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

#[cfg(test)]
mod tests {
    use super::escape_for_terminal;

    #[test]
    fn escapes_terminal_control_sequences() {
        // A command that clears the line and prints a harmless one instead.
        assert_eq!(
            escape_for_terminal("/bin/rm -rf /\x1b[2K\rls"),
            "/bin/rm -rf /\\u{001b}[2K\\u{000d}ls"
        );
        // C1 controls have a one-byte escape in some terminals too.
        assert_eq!(
            escape_for_terminal("a\u{9b}b\u{7f}"),
            "a\\u{009b}b\\u{007f}"
        );
        // Backslashes are escaped so the rendering is unambiguous.
        assert_eq!(escape_for_terminal(r"C:\x1b"), r"C:\\x1b");
        // Ordinary text, including non-ASCII, passes through.
        assert_eq!(
            escape_for_terminal("お仕置き /usr/bin/id"),
            "お仕置き /usr/bin/id"
        );
    }
}
