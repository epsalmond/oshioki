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
    error::Error as StdError,
    fmt, fs,
    io::{self, BufRead as _, Write as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tracing::{debug, info, warn};
use url::{Host, Url};
use uuid::Uuid;

use oshioki_protocol::{
    ActivationV1, DecisionV1, DenyV1, DeviceKindV1, DevicePublicRecordV1, DeviceRegistryV1,
    EnrollmentIntentV1, EnrollmentSubmissionV1, EnvEntryV1, HookConfigV1,
    PRIVATE_PLUGIN_HOOK_PROTOCOL_VERSION, RequestEnvelopeV1, RequestV1, VERSION_V1,
    escape_for_terminal, verify_approval_v1, verify_deny_v1, verify_enrollment_v1,
    verify_native_approval_v1, verify_native_enrollment_v1, verify_software_native_enrollment_v1,
};
use oshioki_transport::{HookProgress, HookTransport, HookTransportFailure, NatsTransport};

const DEFAULT_CONFIG_DIR: &str = "/etc/oshioki";
/// How long the hook waits to connect to the local agent socket. A missing
/// socket fails fast into the NATS fallback; the approval deadline still
/// governs the wait for a verdict.
const AGENT_SOCKET_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const DAEMON_ACK_TIMEOUT: Duration = Duration::from_secs(3);
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(90);
const ENROLLMENT_TIMEOUT: Duration = Duration::from_secs(300);
const CHECK_RC_DENIED: i32 = 1;
const CHECK_RC_UNAVAILABLE: i32 = 2;

#[derive(Debug)]
struct ApprovalUnavailable(String);

impl fmt::Display for ApprovalUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl StdError for ApprovalUnavailable {}

fn approval_unavailable(detail: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(ApprovalUnavailable(detail.into()))
}
/// How long enroll waits for the server to confirm it stored the device.
const ACTIVATION_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Parser)]
#[command(name = "oshioki", about = "sudo approval hook", version)]
struct Cli {
    #[command(subcommand)]
    verb: Verb,
}

#[derive(Subcommand)]
enum Verb {
    Check {
        /// Required private handshake from the matching root-owned plugin.
        /// Hidden from normal operator help; a missing or mismatched value
        /// fails closed before any request bytes are accepted.
        #[arg(long, hide = true)]
        plugin_protocol_version: Option<u8>,
    },
    Enroll {
        #[arg(long, allow_hyphen_values = true)]
        resume: Option<String>,
        /// Permit a loopback enrollment origin for local development only.
        #[arg(long)]
        allow_localhost: bool,
    },
    Revoke {
        #[arg(allow_hyphen_values = true)]
        fingerprint: String,
    },
    Pin {
        #[arg(allow_hyphen_values = true)]
        fingerprint: String,
    },
    /// Pin a device record from a file, as printed by `oshioki-agent
    /// device-record`, for hosts the server never sees. The fingerprint
    /// confirmation is the same ceremony as `pin`; nothing is fetched.
    PinRecord {
        #[arg(allow_hyphen_values = true)]
        path: PathBuf,
    },
    Status,
    Watch,
    Test,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EnrollmentStateV1 {
    version: u8,
    enrollment_id: String,
    secret: String,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
struct ServerHealthV1 {
    status: String,
    #[serde(default)]
    origin: Option<String>,
    #[serde(default)]
    rp_id: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let checking = matches!(cli.verb, Verb::Check { .. });
    logging::init(checking);
    let result = match cli.verb {
        Verb::Check {
            plugin_protocol_version,
        } => cmd_check(plugin_protocol_version).await,
        Verb::Enroll {
            resume,
            allow_localhost,
        } => cmd_enroll(resume.as_deref(), allow_localhost).await,
        Verb::Revoke { fingerprint } => cmd_revoke(&fingerprint).await,
        Verb::Pin { fingerprint } => cmd_pin(&fingerprint).await,
        Verb::PinRecord { path } => cmd_pin_record(&path),
        Verb::Status => cmd_status(),
        Verb::Watch => cmd_watch().await,
        Verb::Test => cmd_test().await,
    };
    if let Err(error) = result {
        let exit_code = checking.then(|| check_error_exit_code(&error));
        let detail = display_error(&error);
        // The terminal gets sudo's one line; the system log gets the audit
        // record.
        if checking {
            if exit_code == Some(CHECK_RC_UNAVAILABLE) {
                warn!(target: "audit", error = %detail, "sudo approval unavailable; password fallback remains eligible");
            } else {
                warn!(target: "audit", error = %detail, "sudo request denied");
            }
        }
        eprintln!("error: {detail}");
        std::process::exit(exit_code.unwrap_or(CHECK_RC_DENIED));
    }
    Ok(())
}

const MAX_TERMINAL_ERROR_BYTES: usize = 4096;

fn display_error(error: &anyhow::Error) -> String {
    sanitize_terminal_text(&format!("{error:#}"))
}

/// Redacts NATS/TLS userinfo, escapes terminal controls, and caps diagnostics
/// before they reach stderr or the audit logger. Error details are useful for
/// transport repair, but they are still untrusted library text.
fn sanitize_terminal_text(text: &str) -> String {
    let redacted = text
        .split_whitespace()
        .map(redact_url_token)
        .collect::<Vec<_>>()
        .join(" ");
    let escaped = escape_for_terminal(&redacted);
    let mut output = escaped
        .chars()
        .take(MAX_TERMINAL_ERROR_BYTES)
        .collect::<String>();
    if escaped.chars().count() > MAX_TERMINAL_ERROR_BYTES {
        output.push_str("...");
    }
    output
}

fn redact_url_token(token: &str) -> String {
    let Some((scheme, rest)) = token.split_once("://") else {
        if let Some((_, host)) = token.rsplit_once('@') {
            return format!("<redacted>@{host}");
        }
        return token.to_owned();
    };
    if !matches!(scheme.to_ascii_lowercase().as_str(), "nats" | "tls") {
        return token.to_owned();
    }
    let Some((_, host)) = rest.rsplit_once('@') else {
        return token.to_owned();
    };
    format!("{scheme}://<redacted>@{host}")
}

/// Maps a failed check to the plugin's password-race contract. Explicit
/// denials and malformed or invalid decisions fail closed. A transport that
/// never became usable, or a request that expired without a decision, leaves
/// password fallback available to the plugin.
fn check_error_exit_code(error: &anyhow::Error) -> i32 {
    if error.chain().any(|cause| {
        cause.downcast_ref::<ApprovalUnavailable>().is_some()
            || cause.downcast_ref::<HookTransportFailure>().is_some()
    }) {
        CHECK_RC_UNAVAILABLE
    } else {
        CHECK_RC_DENIED
    }
}

/// Two sinks, like sudo: the terminal sees warnings and errors only, the
/// system log keeps the audit trail. Approval progress is intentionally shown
/// on the terminal so an operator knows which transport state is active.
///
/// Audit records carry the `audit` target: approvals, denials, and a local
/// agent leaving a request to NATS. The terminal layer drops that target and
/// the syslog layer is the only place it lands.
mod logging {
    use std::fmt::Write as _;
    use std::os::unix::net::UnixDatagram;

    use tracing::field::{Field, Visit};
    use tracing::{Event, Level, Subscriber};
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt as _};
    use tracing_subscriber::util::SubscriberInitExt as _;

    /// syslog(3) facility for security and authorization messages, the one
    /// sudo itself logs under.
    const LOG_AUTHPRIV: u8 = 10;
    /// Terminal default: warnings and errors, and never the audit trail.
    const TERMINAL_DEFAULT: &str = "warn,audit=off";
    /// System log: the audit trail at info, everything else only when it is
    /// a warning, so a library's connection chatter stays out of authpriv.
    const SYSLOG_DIRECTIVES: &str = "warn,audit=info";
    /// Longest datagram sent. syslogd implementations cap datagrams somewhere
    /// between 1 KiB and 8 KiB and drop anything over it whole; a bounded
    /// line keeps the record.
    const MAX_DATAGRAM_LINE: usize = 2048;

    /// `checking` is the sudo path: its terminal level comes from
    /// `OSHIOKI_LOG` in `config.env`, which root writes, never from the
    /// caller's environment. Other verbs run for a person and honour
    /// `RUST_LOG`.
    pub fn init(checking: bool) {
        let directives = if checking {
            super::read_env_file(&super::check_config_dir().join("config.env"))
                .ok()
                .and_then(|env| env.get("OSHIOKI_LOG").cloned())
        } else {
            std::env::var("RUST_LOG").ok()
        };
        let syslog = Syslog::connect();
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stderr)
                    .with_filter(terminal_filter(directives.as_deref())),
            )
            .with(
                SyslogLayer::new(move |severity, line| syslog.send(severity, line))
                    .with_filter(syslog_filter()),
            )
            .init();
    }

    /// An override is added on top of the default rather than replacing
    /// it, and never below a warn floor. An empty string would otherwise
    /// mean "nothing", a typo such as `garbage` is a valid directive for a
    /// target that never logs, and a bare `off` or `error` replaces the
    /// global level; each alone would take the warnings with it. `info`
    /// opens the hook's own chatter; the audit trail stays off the terminal
    /// unless asked for by name with `audit=info`, since a denial already
    /// has sudo's own error line there.
    pub fn terminal_filter(directives: Option<&str>) -> EnvFilter {
        directives
            .map(str::trim)
            .filter(|directives| !directives.is_empty() && keeps_the_warn_floor(directives))
            .and_then(|directives| {
                EnvFilter::try_new(format!("{TERMINAL_DEFAULT},{directives}")).ok()
            })
            .unwrap_or_else(|| EnvFilter::new(TERMINAL_DEFAULT))
    }

    /// A bare level in an override becomes the global level, so `off` and
    /// `error` are refused: the terminal never drops below warnings.
    fn keeps_the_warn_floor(directives: &str) -> bool {
        directives
            .split(',')
            .map(str::trim)
            .filter(|directive| !directive.contains('='))
            .filter_map(|level| level.parse::<LevelFilter>().ok())
            .all(|level| level >= LevelFilter::WARN)
    }

    pub fn syslog_filter() -> EnvFilter {
        EnvFilter::new(SYSLOG_DIRECTIVES)
    }

    /// The system log. On Linux the local syslog datagram socket, spoken
    /// to in the BSD format syslogd and journald accept. On macOS the
    /// unified log via logger(1): datagrams to the legacy socket are
    /// accepted there and then dropped, verified on Sequoia. Best effort
    /// either way and never waited on: a missing sink, a full buffer, or a
    /// slow log daemon drops the line, because an audit sink must never
    /// stall or fail a sudo.
    struct Syslog {
        sink: Option<Sink>,
        pid: u32,
    }

    enum Sink {
        Socket(UnixDatagram),
        Logger,
    }

    const LOGGER: &str = "/usr/bin/logger";

    impl Syslog {
        fn connect() -> Self {
            let pid = std::process::id();
            if cfg!(target_os = "macos") && std::path::Path::new(LOGGER).is_file() {
                return Self {
                    sink: Some(Sink::Logger),
                    pid,
                };
            }
            let socket = ["/dev/log", "/var/run/syslog", "/var/run/log"]
                .iter()
                .find_map(|path| {
                    let socket = UnixDatagram::unbound().ok()?;
                    socket.connect(path).ok()?;
                    socket.set_nonblocking(true).ok()?;
                    Some(socket)
                });
            Self {
                sink: socket.map(Sink::Socket),
                pid,
            }
        }

        fn send(&self, severity: u8, line: &str) {
            match &self.sink {
                None => {}
                Some(Sink::Socket(socket)) => {
                    let _ = socket.send(datagram(self.pid, severity, line).as_bytes());
                }
                Some(Sink::Logger) => {
                    // Fire and forget: the hook exits right after the
                    // record and launchd reaps the child, and a wedged
                    // log daemon must not hold a sudo. The message keeps
                    // the same `oshioki[pid]:` prefix as the datagram so
                    // the unified log can be filtered on it; `--` keeps a
                    // line starting with `-` from being read as an option.
                    let _ = std::process::Command::new(LOGGER)
                        .env_clear()
                        .args(["-t", "oshioki", "-p"])
                        .arg(format!("authpriv.{}", severity_name(severity)))
                        .arg("--")
                        .arg(format!("oshioki[{}]: {}", self.pid, sanitize(line)))
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .spawn();
                }
            }
        }
    }

    /// The line cut to a datagram-safe length with every control character
    /// (newlines above all) replaced, so a value that came from outside
    /// cannot forge a second record.
    pub fn sanitize(line: &str) -> String {
        let mut clean = String::with_capacity(line.len().min(MAX_DATAGRAM_LINE));
        for c in line.chars() {
            let c = if c.is_control() { ' ' } else { c };
            if clean.len() + c.len_utf8() > MAX_DATAGRAM_LINE {
                break;
            }
            clean.push(c);
        }
        clean
    }

    /// `<PRI>oshioki[pid]: line`, the BSD syslog datagram.
    pub fn datagram(pid: u32, severity: u8, line: &str) -> String {
        format!(
            "<{}>oshioki[{pid}]: {}",
            LOG_AUTHPRIV * 8 + severity,
            sanitize(line)
        )
    }

    /// syslog(3) severity names, as logger(1) -p takes them.
    pub fn severity_name(severity: u8) -> &'static str {
        match severity {
            3 => "err",
            4 => "warning",
            6 => "info",
            _ => "debug",
        }
    }

    /// One syslog line per event: the message, then `key=value` fields.
    pub struct SyslogLayer<F> {
        sink: F,
    }

    impl<F: Fn(u8, &str) + Send + Sync + 'static> SyslogLayer<F> {
        pub fn new(sink: F) -> Self {
            Self { sink }
        }
    }

    /// syslog(3) severities: err 3, warning 4, info 6, debug 7.
    pub fn severity(level: Level) -> u8 {
        match level {
            Level::ERROR => 3,
            Level::WARN => 4,
            Level::INFO => 6,
            _ => 7,
        }
    }

    #[derive(Default)]
    struct Line {
        message: String,
        fields: String,
    }

    impl Visit for Line {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                let _ = write!(self.message, "{value:?}");
            } else {
                let _ = write!(self.fields, " {}={value:?}", field.name());
            }
        }
        fn record_str(&mut self, field: &Field, value: &str) {
            if field.name() == "message" {
                self.message.push_str(value);
            } else {
                let _ = write!(self.fields, " {}={value}", field.name());
            }
        }
    }

    pub fn render(event: &Event<'_>) -> String {
        let mut line = Line::default();
        event.record(&mut line);
        format!("{}{}", line.message, line.fields)
    }

    impl<S, F> Layer<S> for SyslogLayer<F>
    where
        S: Subscriber,
        F: Fn(u8, &str) + Send + Sync + 'static,
    {
        fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
            (self.sink)(severity(*event.metadata().level()), &render(event));
        }
    }

    #[cfg(test)]
    mod tests {
        use std::io;
        use std::sync::{Arc, Mutex};

        use tracing_subscriber::layer::{Layer as _, SubscriberExt as _};

        use super::{SyslogLayer, datagram, severity, syslog_filter, terminal_filter};

        /// A terminal captured in memory.
        #[derive(Clone, Default)]
        struct Captured(Arc<Mutex<Vec<u8>>>);
        impl io::Write for Captured {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        impl Captured {
            fn text(&self) -> String {
                String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
            }
        }

        /// Both production layers with their real filters, the terminal
        /// under the given override; returns what each sink received after
        /// one of every kind of event.
        fn run_both(terminal_directives: Option<&str>) -> (String, Vec<(u8, String)>) {
            let terminal = Captured::default();
            let writer = terminal.clone();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let sink = Arc::clone(&seen);
            let subscriber = tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_writer(move || writer.clone())
                        .with_filter(terminal_filter(terminal_directives)),
                )
                .with(
                    SyslogLayer::new(move |severity, line| {
                        sink.lock().unwrap().push((severity, line.to_string()));
                    })
                    .with_filter(syslog_filter()),
                );
            tracing::subscriber::with_default(subscriber, || {
                tracing::info!(target: "audit", request_id = "r1", "sudo request approved");
                tracing::warn!(target: "audit", error = "deadline", "sudo request denied");
                tracing::warn!("counter regressed");
                tracing::info!("no agent on the socket; trying NATS");
                tracing::info!(target: "oshioki_transport::nats", "connected successfully");
                tracing::info!(target: "async_nats", "event: connected");
            });
            let seen = seen.lock().unwrap().clone();
            (terminal.text(), seen)
        }

        #[test]
        fn terminal_shows_warnings_and_never_the_audit_trail() {
            let (terminal, _) = run_both(None);
            assert!(terminal.contains("counter regressed"), "{terminal}");
            assert!(!terminal.contains("sudo request"), "{terminal}");
            assert!(!terminal.contains("trying NATS"), "{terminal}");
            assert!(!terminal.contains("connected"), "{terminal}");
        }

        #[test]
        fn syslog_carries_the_audit_trail_and_warnings_only() {
            let (_, seen) = run_both(None);
            assert_eq!(
                seen,
                vec![
                    (6, "sudo request approved request_id=r1".to_string()),
                    (4, "sudo request denied error=deadline".to_string()),
                    (4, "counter regressed".to_string()),
                ]
            );
        }

        #[test]
        fn empty_or_broken_override_keeps_the_default_instead_of_silence() {
            for broken in [
                Some(""),
                Some("   "),
                Some("garbage!!!"),
                Some("="),
                Some("off"),
                Some("error"),
                Some("audit=off,off"),
            ] {
                let (terminal, seen) = run_both(broken);
                assert!(
                    terminal.contains("counter regressed"),
                    "{broken:?}: {terminal}"
                );
                assert!(!terminal.contains("sudo request"), "{broken:?}: {terminal}");
                assert_eq!(seen.len(), 3, "{broken:?}");
            }
        }

        #[test]
        fn a_real_override_opens_the_terminal_for_development() {
            let (terminal, seen) = run_both(Some("info"));
            assert!(terminal.contains("trying NATS"), "{terminal}");
            assert!(terminal.contains("counter regressed"), "{terminal}");
            let (terminal, _) = run_both(Some("debug"));
            assert!(terminal.contains("trying NATS"), "{terminal}");
            assert!(terminal.contains("connected"), "{terminal}");
            assert!(!terminal.contains("sudo request"), "{terminal}");
            // The system log is not the terminal's to change.
            assert_eq!(seen.len(), 3);
            // The audit trail on a terminal is asked for by name.
            let (terminal, _) = run_both(Some("audit=info"));
            assert!(terminal.contains("sudo request approved"), "{terminal}");
            assert!(terminal.contains("sudo request denied"), "{terminal}");
            assert!(!terminal.contains("trying NATS"), "{terminal}");
        }

        #[test]
        fn datagram_is_bounded_and_cannot_forge_a_second_record() {
            let forged = "curl failed\n<86>oshioki[1]: sudo request approved\r\0tail";
            let line = datagram(42, 6, forged);
            assert_eq!(
                line,
                "<86>oshioki[42]: curl failed <86>oshioki[1]: sudo request approved  tail"
            );
            assert!(!line[1..].contains(['\n', '\r', '\0']));
            let long = "é".repeat(3000);
            let line = datagram(1, 4, &long);
            assert!(line.starts_with("<84>oshioki[1]: "));
            assert!(line.len() <= "<84>oshioki[1]: ".len() + super::MAX_DATAGRAM_LINE);
            assert!(line.ends_with('é'), "cut on a char boundary");
        }

        #[test]
        fn sanitize_replaces_every_control_character_and_bounds_the_line() {
            let dirty = "a\nb\rc\0d\te\u{85}f";
            let clean = super::sanitize(dirty);
            assert_eq!(clean, "a b c d e f");
            assert!(clean.chars().all(|c| !c.is_control()));
            let long = super::sanitize(&"ü".repeat(5000));
            assert!(long.len() <= super::MAX_DATAGRAM_LINE);
            assert!(long.len() > super::MAX_DATAGRAM_LINE - 2);
            assert!(long.chars().all(|c| c == 'ü'));
        }

        #[test]
        fn severities_map_like_syslog() {
            assert_eq!(
                super::severity_name(severity(tracing::Level::TRACE)),
                "debug"
            );
            for (level, name) in [
                (tracing::Level::ERROR, "err"),
                (tracing::Level::WARN, "warning"),
                (tracing::Level::INFO, "info"),
                (tracing::Level::DEBUG, "debug"),
            ] {
                assert_eq!(super::severity_name(severity(level)), name);
            }
            assert_eq!(severity(tracing::Level::ERROR), 3);
            assert_eq!(severity(tracing::Level::WARN), 4);
            assert_eq!(severity(tracing::Level::INFO), 6);
            assert_eq!(severity(tracing::Level::DEBUG), 7);
            assert_eq!(severity(tracing::Level::TRACE), 7);
        }
    }
}

async fn cmd_check(plugin_protocol_version: Option<u8>) -> Result<()> {
    if plugin_protocol_version != Some(PRIVATE_PLUGIN_HOOK_PROTOCOL_VERSION) {
        bail!("plugin/hook protocol handshake failed");
    }
    let request = build_request(&parse_sudo_stdin()?)?;
    execute_request_at(request, APPROVAL_TIMEOUT, check_config_dir(), false).await
}

async fn execute_request(request: RequestV1, timeout: Duration) -> Result<()> {
    let directory = config_dir();
    execute_request_at(request, timeout, &directory, true).await
}

// The transport state matrix is kept in one place so each outcome maps to a
// distinct user-visible status and exit classification.
#[allow(clippy::single_match_else, clippy::too_many_lines)]
async fn execute_request_at(
    request: RequestV1,
    timeout: Duration,
    directory: &Path,
    announce_url: bool,
) -> Result<()> {
    eprintln!(
        "Oshioki is trying: {}",
        escape_for_terminal(&request.command)
    );
    io::stderr().flush()?;
    // The transport set first: a config naming no working transport fails
    // before any request is built, not at the first sudo afterwards.
    let nats_url = transports_from(directory)?.nats_url;
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
    // This is the hook's trusted capability decision. A server delivery
    // receipt may extend the short native liveness wait only when a pinned,
    // active WebAuthn device is actually among this request's recipients.
    let has_browser_recipient = active
        .iter()
        .any(|device| device.kind == DeviceKindV1::Webauthn);
    let envelope = seal_request(&request, &raw_request, &active)?;
    let payload = serde_json::to_vec(&envelope)?;
    if payload.len() > oshioki_protocol::v1::MAX_ENVELOPE_BYTES {
        bail!("request envelope exceeds 3 MiB");
    }
    let progress: std::sync::Arc<dyn Fn(HookProgress) + Send + Sync> =
        std::sync::Arc::new(|event: HookProgress| match event {
            HookProgress::TransportFailed(error) => {
                eprintln!("Transport failed: {}", sanitize_terminal_text(&error));
            }
            HookProgress::DaemonNotResponding(error) => {
                eprintln!("Daemon not responding: {}", sanitize_terminal_text(&error));
            }
            HookProgress::RequestDelivered => {
                eprintln!("Request delivered; waiting for approver...");
                let _ = io::stderr().flush();
            }
            HookProgress::WaitingForApproval => {
                eprintln!("Waiting for approval...");
                let _ = io::stderr().flush();
            }
            HookProgress::ProtocolFailed(error) => {
                eprintln!(
                    "Transport protocol failed: {}",
                    sanitize_terminal_text(&error)
                );
            }
        });
    // One deadline covers both transports: whatever the socket attempt
    // consumes comes out of the NATS fallback's budget, so a dead agent can
    // never stretch one sudo invocation past the approval timeout. With no
    // NATS fallback configured the socket answer is final: silence denies at
    // once instead of waiting out a deadline nobody else can meet.
    let deadline = tokio::time::Instant::now() + timeout;
    let decision = match try_agent_socket(
        directory,
        &request.request_id,
        &payload,
        deadline,
        &progress,
    )
    .await?
    {
        SocketOutcome::Decision(decision) => decision,
        SocketOutcome::Unconfigured => match &nats_url {
            Some(url) => {
                debug!("no agent socket configured; trying NATS");
                nats_fallback(
                    directory,
                    &request,
                    payload,
                    deadline,
                    url,
                    NatsFallbackOptions {
                        announce_url,
                        has_browser_recipient,
                    },
                    progress.clone(),
                )
                .await?
            }
            // The transport check above guarantees a fallback here.
            None => bail!(
                "no approval transports configured: OSHIOKI_AGENT_SOCKET is unset and NATS_URL is not set in {}",
                directory.join("config.env").display()
            ),
        },
        SocketOutcome::Silent(SocketSilence::NoAgent { path, error }) => match &nats_url {
            Some(url) => {
                eprintln!(
                    "Transport failed: socket {}: {}",
                    sanitize_terminal_text(&path.display().to_string()),
                    sanitize_terminal_text(&error)
                );
                debug!(path = %path.display(), "no agent on the socket; trying NATS");
                nats_fallback(
                    directory,
                    &request,
                    payload,
                    deadline,
                    url,
                    NatsFallbackOptions {
                        announce_url,
                        has_browser_recipient,
                    },
                    progress.clone(),
                )
                .await?
            }
            None => {
                eprintln!(
                    "Transport failed: socket {}: {}",
                    sanitize_terminal_text(&path.display().to_string()),
                    sanitize_terminal_text(&error)
                );
                return Err(approval_unavailable(format!(
                    "no agent on {} ({error}) and no NATS fallback configured — denying request {}",
                    path.display(),
                    request.request_id
                )));
            }
        },
        SocketOutcome::Silent(SocketSilence::NoAck { path, error }) => match &nats_url {
            Some(url) => {
                eprintln!(
                    "Daemon not responding: socket {}: {}",
                    sanitize_terminal_text(&path.display().to_string()),
                    sanitize_terminal_text(&error)
                );
                nats_fallback(
                    directory,
                    &request,
                    payload,
                    deadline,
                    url,
                    NatsFallbackOptions {
                        announce_url,
                        has_browser_recipient,
                    },
                    progress.clone(),
                )
                .await?
            }
            None => {
                eprintln!(
                    "Daemon not responding: socket {}: {}",
                    sanitize_terminal_text(&path.display().to_string()),
                    sanitize_terminal_text(&error)
                );
                return Err(approval_unavailable(format!(
                    "daemon not responding on {} ({error}) and no NATS fallback configured — denying request {}",
                    path.display(),
                    request.request_id
                )));
            }
        },
    };
    apply_decision(
        decision,
        &request,
        &raw_request,
        &active,
        &mut registry,
        directory,
    )
    .await
}

/// The approval transports a config directory offers. At least one is always
/// present: [`transports_from`] refuses an empty set before any request is
/// built, so a config that names no working transport fails at startup
/// instead of at the first sudo afterwards.
#[derive(Debug)]
struct Transports {
    socket: Option<PathBuf>,
    nats_url: Option<String>,
}

#[derive(Clone, Copy)]
struct NatsFallbackOptions {
    announce_url: bool,
    has_browser_recipient: bool,
}

/// Reads the transport set from `config.env`. A missing or empty
/// `OSHIOKI_AGENT_SOCKET` means no socket transport; a missing or empty
/// `NATS_URL` means no NATS transport (socket-only). Both absent is a
/// configuration error, not a fallback: there is nothing to fall back to.
fn transports_from(directory: &Path) -> Result<Transports> {
    let env = read_env_file(&directory.join("config.env"))?;
    let transports = Transports {
        socket: env
            .get("OSHIOKI_AGENT_SOCKET")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from),
        nats_url: env
            .get("NATS_URL")
            .filter(|value| !value.is_empty())
            .cloned(),
    };
    if transports.socket.is_none() && transports.nats_url.is_none() {
        bail!(
            "no approval transports configured: OSHIOKI_AGENT_SOCKET is unset and NATS_URL is not set in {}",
            directory.join("config.env").display()
        );
    }
    Ok(transports)
}

/// Runs the NATS fallback for a request the socket did not answer. Only
/// called when `config.env` names a NATS URL. Failures name the server and
/// the failed step with the credentials redacted, so a dead or
/// misconfigured NATS reads as what it is instead of a library error.
async fn nats_fallback(
    directory: &Path,
    request: &RequestV1,
    payload: Vec<u8>,
    deadline: tokio::time::Instant,
    nats_url: &str,
    options: NatsFallbackOptions,
    progress: std::sync::Arc<dyn Fn(HookProgress) + Send + Sync>,
) -> Result<DecisionV1> {
    let remaining = deadline
        .checked_duration_since(tokio::time::Instant::now())
        .unwrap_or(Duration::ZERO);
    if remaining.is_zero() {
        return Err(approval_unavailable(
            "sudo decision deadline exceeded before the NATS fallback ran",
        ));
    }
    let display = nats_display_url(nats_url);
    let connect_timeout = remaining.min(DAEMON_ACK_TIMEOUT);
    let transport = match tokio::time::timeout(connect_timeout, transport_from(directory)).await {
        Err(_) => {
            let error = format!(
                "NATS connection timed out after {}ms",
                connect_timeout.as_millis()
            );
            eprintln!(
                "Transport failed: NATS fallback to {}: {}",
                sanitize_terminal_text(&display),
                sanitize_terminal_text(&error)
            );
            return Err(approval_unavailable(format!(
                "NATS fallback to {display} failed: connect: {error}"
            )));
        }
        Ok(transport) => match transport {
            Ok(transport) => transport,
            Err(error) => {
                eprintln!(
                    "Transport failed: NATS fallback to {} failed: connect: {}",
                    sanitize_terminal_text(&display),
                    display_error(&error)
                );
                return Err(approval_unavailable(format!(
                    "NATS fallback to {display} failed: connect: {error:#}"
                )));
            }
        },
    };
    let remaining = deadline
        .checked_duration_since(tokio::time::Instant::now())
        .unwrap_or(Duration::ZERO);
    if remaining.is_zero() {
        return Err(approval_unavailable(
            "sudo decision deadline exceeded before the NATS verdict wait",
        ));
    }
    if options.announce_url {
        let config = load_hook_config_from(directory)?;
        println!(
            "Approval URL (expires in {} seconds):\n  {}",
            remaining.as_secs(),
            approval_url(&config.server_base_url, &request.request_id)
        );
        io::stdout().flush()?;
    }
    transport
        .request_decision(
            &request.host,
            &request.request_id,
            payload,
            remaining,
            options.has_browser_recipient,
            progress,
        )
        .await
        .with_context(|| format!("NATS fallback to {display} failed: wait for a verdict"))
}

/// Renders a NATS URL for error messages: scheme and host without
/// credentials, so a fallback failure can name the server it could not
/// reach without leaking the password next to it.
fn nats_display_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return "<invalid NATS URL>".into();
    };
    let after_credentials = rest.rsplit('@').next().unwrap_or(rest);
    let host = after_credentials
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_credentials);
    format!("{scheme}://{host}")
}

/// What one attempt at the local agent socket concluded.
enum SocketOutcome {
    /// An agent took the request; the verdict is final.
    Decision(DecisionV1),
    /// No socket is configured; only NATS can answer.
    Unconfigured,
    /// A socket is configured but no verdict came back; the caller falls
    /// back to NATS while the deadline allows, or denies at once when no
    /// NATS fallback is configured.
    Silent(SocketSilence),
}

/// How a configured socket produced no verdict. The distinction decides the
/// message, not the outcome: both fall back to NATS when one is configured
/// and deny at once when none is.
enum SocketSilence {
    /// Nothing answered at the path: missing or stale file, refused or
    /// timed-out connect, or a write that never landed.
    NoAgent { path: PathBuf, error: String },
    /// The socket accepted the request but never sent the required alive
    /// acknowledgement.
    NoAck { path: PathBuf, error: String },
}

/// Ask the local agent over its Unix socket, if one is configured.
///
/// Only a missing or unreachable socket, or an agent that hangs up before
/// acknowledging falls back: in those cases no agent took responsibility for
/// the request. A verdict, a malformed reply, a post-ack hangup, or the
/// deadline expiring while an agent holds the request is final and fails
/// closed on error.
#[allow(clippy::too_many_lines)]
async fn try_agent_socket(
    directory: &Path,
    request_id: &str,
    payload: &[u8],
    deadline: tokio::time::Instant,
    progress: &std::sync::Arc<dyn Fn(HookProgress) + Send + Sync>,
) -> Result<SocketOutcome> {
    let Some(path) = agent_socket_from(directory)? else {
        return Ok(SocketOutcome::Unconfigured);
    };
    let connect_wait = deadline
        .checked_duration_since(tokio::time::Instant::now())
        .unwrap_or(Duration::ZERO)
        .min(AGENT_SOCKET_CONNECT_TIMEOUT);
    if connect_wait.is_zero() {
        return Ok(SocketOutcome::Silent(SocketSilence::NoAgent {
            path,
            error: "request deadline expired before connect".into(),
        }));
    }
    let stream = match tokio::time::timeout(connect_wait, UnixStream::connect(&path)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            return Ok(SocketOutcome::Silent(SocketSilence::NoAgent {
                path,
                error: error.to_string(),
            }));
        }
        Err(_) => {
            return Ok(SocketOutcome::Silent(SocketSilence::NoAgent {
                path,
                error: format!("connect timed out after {}ms", connect_wait.as_millis()),
            }));
        }
    };
    let (mut reader, mut writer) = stream.into_split();
    let frame = oshioki_protocol::socket_v1::encode_frame(payload)?;
    let write_wait = deadline
        .checked_duration_since(tokio::time::Instant::now())
        .unwrap_or(Duration::ZERO);
    let write_wait = write_wait.min(DAEMON_ACK_TIMEOUT);
    if write_wait.is_zero() {
        return Ok(SocketOutcome::Silent(SocketSilence::NoAgent {
            path,
            error: "request deadline expired before write".into(),
        }));
    }
    let write_result = tokio::time::timeout(write_wait, writer.write_all(&frame)).await;
    let write_result = match write_result {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("write timed out after {}ms", write_wait.as_millis()),
        )),
    };
    if let Err(error) = write_result {
        return Ok(SocketOutcome::Silent(SocketSilence::NoAgent {
            path,
            error: error.to_string(),
        }));
    }
    drop(writer);
    let remaining = deadline
        .checked_duration_since(tokio::time::Instant::now())
        .unwrap_or(Duration::ZERO);
    if remaining.is_zero() {
        return Err(approval_unavailable(
            "sudo decision deadline exceeded waiting for the local agent",
        ));
    }
    let ack_wait = remaining.min(DAEMON_ACK_TIMEOUT);
    let bytes = match tokio::time::timeout(ack_wait, read_frame(&mut reader)).await {
        Ok(Ok(Some(bytes))) => bytes,
        Ok(Ok(None)) => {
            return Ok(SocketOutcome::Silent(SocketSilence::NoAck {
                path,
                error: "agent closed before acknowledging".into(),
            }));
        }
        Ok(Err(error)) => {
            return Ok(SocketOutcome::Silent(SocketSilence::NoAck {
                path,
                error: error.to_string(),
            }));
        }
        Err(_) => {
            return Ok(SocketOutcome::Silent(SocketSilence::NoAck {
                path,
                error: format!(
                    "daemon acknowledgement timed out after {}ms",
                    ack_wait.as_millis()
                ),
            }));
        }
    };
    let acknowledgement: oshioki_protocol::AliveV1 = serde_json::from_slice(&bytes).context(
        "decode socket daemon acknowledgement; upgrade oshioki-agent before using this hook",
    )?;
    acknowledgement.validate(request_id).context(
        "invalid socket daemon acknowledgement; upgrade oshioki-agent before using this hook",
    )?;
    progress(HookProgress::WaitingForApproval);
    let remaining = deadline
        .checked_duration_since(tokio::time::Instant::now())
        .unwrap_or(Duration::ZERO);
    if remaining.is_zero() {
        return Err(approval_unavailable(
            "sudo decision deadline exceeded waiting for the local agent",
        ));
    }
    let bytes = match tokio::time::timeout(remaining, read_frame(&mut reader)).await {
        Ok(Ok(Some(bytes))) => bytes,
        Ok(Ok(None)) => {
            // Once an agent has sent AliveV1 it owns this request. An EOF
            // before a verdict is therefore an unexpected cancellation and
            // must deny; an ordinary timeout below remains unavailable so an
            // unanswered request can expire normally.
            return Err(anyhow::anyhow!(
                "agent closed after acknowledging without a verdict"
            ));
        }
        Ok(Err(error)) => return Err(error),
        Err(_) => {
            return Err(approval_unavailable(
                "sudo decision deadline exceeded waiting for the local agent",
            ));
        }
    };
    let decision: DecisionV1 = serde_json::from_slice(&bytes).context("decode socket decision")?;
    Ok(SocketOutcome::Decision(decision))
}

/// The socket path from `OSHIOKI_AGENT_SOCKET` in `config.env`, if set.
/// Sudo scrubs the hook's environment, so the socket must come from the
/// root-owned config file rather than a process variable.
fn agent_socket_from(directory: &Path) -> Result<Option<PathBuf>> {
    let env = read_env_file(&directory.join("config.env"))?;
    Ok(env
        .get("OSHIOKI_AGENT_SOCKET")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from))
}

/// Read one length-delimited frame. A peer that hangs up before delivering
/// one has not answered, so the caller treats that as no answer.
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

/// Applies one decision to a request. Invalid decisions fail closed.
async fn apply_decision(
    decision: DecisionV1,
    request: &RequestV1,
    raw_request: &[u8],
    active: &[DevicePublicRecordV1],
    registry: &mut DeviceRegistryV1,
    directory: &Path,
) -> Result<()> {
    // A verdict is an answer about one request during its lifetime. Once the
    // request has expired there is nothing left to decide, and a signature
    // that arrives late must not stand in for one that arrived in time.
    if request.expires_at <= now() {
        bail!("request expired before its verdict was applied");
    }
    match decision {
        DecisionV1::Deny(denial) => {
            denial.validate_shape().context("validate deny decision")?;
            if denial.version != VERSION_V1 || denial.request_id != request.request_id {
                bail!("malformed deny decision");
            }
            let device = active
                .iter()
                .find(|device| device.fingerprint == denial.device_fingerprint)
                .context("deny from unpinned device")?;
            if denial.signature.is_some() {
                // Native verdicts authenticate here: only the pinned device
                // key can produce this signature, so no NATS credential
                // suffices to deny for another device.
                verify_deny_v1(&denial, device).context("deny verification failed")?;
            } else {
                // Browser verdicts carry no device signature (the key never
                // leaves its authenticator); they arrive relayed by the
                // server after bearer-token authentication, so the server's
                // record confirms them. A direct forgery has no record.
                let config = load_hook_config_from(directory)?;
                if !server_confirms_denial(&config.server_base_url, &denial).await {
                    bail!("denial is not server-confirmed");
                }
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
            info!(target: "audit", request_id=%request.request_id, fingerprint=%device.fingerprint, kind=%device.kind, "sudo request approved");
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
                    matches!(
                        device.kind,
                        DeviceKindV1::Software | DeviceKindV1::SecureEnclave
                    ) && device.fingerprint == approval.device_fingerprint
                })
                .context("native approval does not name one pinned native device")?;
            verify_native_approval_v1(&approval, raw_request, device)
                .context("native approval verification failed")?;
            info!(target: "audit", request_id=%request.request_id, fingerprint=%device.fingerprint, kind=%device.kind, "sudo request approved");
            Ok(())
        }
    }
}

fn approval_url(server_base_url: &str, request_id: &str) -> String {
    format!("{server_base_url}/r/{request_id}")
}

/// The system configuration and its enrollment state are root-owned. A
/// caller-supplied config directory is intentionally allowed for local
/// development and tests, where the caller owns the state instead.
fn require_enroll_privileges(directory: &Path) -> Result<()> {
    if enroll_needs_root(directory, nix::unistd::geteuid().as_raw()) {
        bail!(
            "`oshioki enroll` needs the system configuration; run `sudo oshioki enroll` (or set OSHIOKI_CONFIG_DIR for a user-owned development configuration)"
        );
    }
    Ok(())
}

fn enroll_needs_root(directory: &Path, effective_uid: u32) -> bool {
    directory == Path::new(DEFAULT_CONFIG_DIR) && effective_uid != 0
}

/// Parses and checks the configured browser origin before creating any
/// enrollment state. Local-only origins are useful for development, but a
/// phone cannot use the Mac's loopback interface.
fn enrollment_origin(config: &HookConfigV1, allow_localhost: bool) -> Result<Url> {
    let origin = Url::parse(&config.server_base_url)
        .map_err(|_| anyhow::anyhow!("invalid enrollment origin in hook configuration"))?;
    let valid_shape = origin.scheme() == "https"
        && origin.host_str().is_some()
        && origin.username().is_empty()
        && origin.password().is_none()
        && (origin.path().is_empty() || origin.path() == "/")
        && origin.query().is_none()
        && origin.fragment().is_none();
    if !valid_shape {
        bail!("invalid enrollment origin in hook configuration");
    }
    if !allow_localhost
        && origin
            .host()
            .as_ref()
            .is_some_and(is_local_only_enrollment_host)
    {
        bail!(
            "the enrollment origin is reachable only from this computer; run `oshioki-phone-setup` as your normal user to configure a phone-reachable HTTPS origin (Tailscale is preferred), or pass `--allow-localhost` for local development"
        );
    }
    Ok(origin)
}

fn is_local_only_enrollment_host(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => {
            let domain = domain.trim_end_matches('.');
            let suffix = ".localhost";
            domain.eq_ignore_ascii_case("localhost")
                || (domain.len() > suffix.len()
                    && domain[domain.len() - suffix.len()..].eq_ignore_ascii_case(suffix))
        }
        Host::Ipv4(address) => address.is_loopback() || address.is_unspecified(),
        Host::Ipv6(address) => {
            address.is_loopback()
                || address.is_unspecified()
                || address
                    .to_ipv4()
                    .is_some_and(|address| address.is_loopback() || address.is_unspecified())
        }
    }
}

/// Checks that the public server is reachable over HTTPS and serves the same
/// `WebAuthn` configuration as the hook. Older servers may omit the metadata,
/// but a partial or conflicting pair is rejected.
async fn preflight_enrollment_server(config: &HookConfigV1, origin: &Url) -> Result<()> {
    let health_url = origin
        .join("/healthz")
        .map_err(|_| anyhow::anyhow!("invalid enrollment health URL"))?;
    let body = http_get(health_url.as_str())
        .await
        .context("enrollment server health check failed")?;
    let health: ServerHealthV1 = serde_json::from_slice(&body)
        .context("enrollment server returned an invalid health response")?;
    validate_server_health(config, &health)
}

fn validate_server_health(config: &HookConfigV1, health: &ServerHealthV1) -> Result<()> {
    if health.status != "ok" {
        bail!("enrollment server is not ready");
    }
    match (health.origin.as_deref(), health.rp_id.as_deref()) {
        (None, None) => Ok(()),
        (Some(origin), Some(rp_id)) if origin == config.origin && rp_id == config.rp_id => Ok(()),
        (Some(_), Some(_)) => {
            bail!("enrollment server WebAuthn configuration does not match the hook")
        }
        _ => bail!("enrollment server returned incomplete WebAuthn configuration"),
    }
}

async fn cmd_enroll(resume: Option<&str>, allow_localhost: bool) -> Result<()> {
    let directory = config_dir();
    require_enroll_privileges(&directory)?;
    let config = load_hook_config_from(&directory)?;
    let origin = enrollment_origin(&config, allow_localhost)?;
    preflight_enrollment_server(&config, &origin).await?;
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
    let transport = transport_from(&config_dir()).await?;
    let reply_subject = format!("oshioki.enrollment.submission.{}", state.enrollment_id);
    let intent = EnrollmentIntentV1 {
        version: VERSION_V1,
        enrollment_id: state.enrollment_id.clone(),
        secret_hash: URL_SAFE_NO_PAD.encode(Sha256::digest(secret_bytes)),
        expires_at: state.expires_at,
        reply_subject,
    };
    let enrollment_url = format!(
        "{}/enroll/{}#{}",
        config.server_base_url, state.enrollment_id, state.secret
    );
    let remaining = u64::try_from(state.expires_at - now()).context("enrollment expiry")?;
    let submission_deadline = tokio::time::Instant::now()
        + Duration::from_secs(remaining.min(ENROLLMENT_TIMEOUT.as_secs()));
    // Deliver the intent first so the enrollment URL never outruns the row
    // the server builds from it: publish, confirm, then print, then wait.
    let reply_stream = transport.publish_enrollment_intent(&intent).await?;
    println!(
        "Enrollment URL (expires in five minutes):\n  {enrollment_url}\nNative agent:\n  oshioki-agent pair '{enrollment_url}'"
    );
    let submission = transport
        .await_submission(&state.enrollment_id, reply_stream, submission_deadline)
        .await?;
    let device = match &submission {
        EnrollmentSubmissionV1::Webauthn(submission) => {
            verify_enrollment_v1(submission, &secret_bytes, &config).context("verify enrollment")?
        }
        EnrollmentSubmissionV1::Software(submission) => {
            verify_software_native_enrollment_v1(submission, &secret_bytes)
                .context("verify software native enrollment")?
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
    let confirmation =
        activate_device(transport.as_ref(), &state.enrollment_id, &device, &config).await;
    // The enrollment itself is spent either way: the device is pinned here
    // and the server has consumed the intent, so there is nothing for
    // `--resume` to redo. What may still be missing is the server's copy.
    remove_enrollment_state(&state_path);
    confirmation?;
    println!(
        "Device enrolled: {} ({})",
        device.fingerprint,
        escape_for_terminal(&device.label)
    );
    Ok(())
}

/// Publishes the activation, then reads the device back from the server until
/// the record it serves is the one that was just enrolled.
///
/// The read-back is the confirmation. A message on NATS would be cheaper, but
/// every consumer can publish on the device subjects, so the device being
/// enrolled could acknowledge its own activation; only the server's own HTTPS
/// answer says what the server actually stored. A server that predates this
/// device kind, or that cannot store the record at all, drops the activation
/// silently, and without this check both `enroll` and the agent would report
/// success.
async fn activate_device(
    transport: &dyn HookTransport,
    enrollment_id: &str,
    device: &DevicePublicRecordV1,
    config: &HookConfigV1,
) -> Result<()> {
    let activation = ActivationV1 {
        version: VERSION_V1,
        enrollment_id: enrollment_id.to_owned(),
        device: device.clone(),
    };
    transport.publish_activation(&activation).await?;
    let url = format!(
        "{}/api/v1/devices/{}",
        config.server_base_url, device.fingerprint
    );
    let deadline = tokio::time::Instant::now() + ACTIVATION_TIMEOUT;
    let mut last_error;
    loop {
        match server_device_matches(&url, device).await {
            Ok(true) => return Ok(()),
            // A different record is settled state, not a missing message:
            // restating the activation cannot change what is stored.
            Ok(false) => last_error = "the server serves a different record".into(),
            Err(error) => {
                last_error = format!("{error:#}");
                // The server only activates against the stored submission,
                // which travels over NATS on its own subject; this restatement
                // may overtake it, and the first publish may have been lost.
                // Restating is safe — a stored activation is idempotent — so
                // a slow submission heals here instead of failing the enroll.
                transport.publish_activation(&activation).await?;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep_until(
            (tokio::time::Instant::now() + Duration::from_millis(500)).min(deadline),
        )
        .await;
    }
    bail!(
        "device {} ({}) is pinned on this host and can approve sudo here, but the server did \
         not serve it within {} seconds ({}): the server state is unknown, not rejected. \
         Check it with `curl {}`; if the record is missing, run `oshioki enroll` again for \
         this device once the server is healthy",
        device.fingerprint,
        device.kind,
        ACTIVATION_TIMEOUT.as_secs(),
        escape_for_terminal(&last_error),
        url
    )
}

/// Whether the server serves exactly the record that was just enrolled.
/// Whether the server's record authenticates an unsigned denial: the recorded
/// verdict must be a denial for the same request from the same fingerprint.
/// Only the authenticated API writes that record, so a directly forged NATS
/// denial — which has none — fails here. Pure, so tests can drive it without
/// a server.
fn denial_confirmed_by(recorded: &DecisionV1, denial: &DenyV1) -> bool {
    matches!(recorded, DecisionV1::Deny(recorded)
        if recorded.request_id == denial.request_id
            && recorded.device_fingerprint == denial.device_fingerprint)
}

/// Fetches the server's recorded verdict for a request and checks it against
/// an unsigned denial. Unreachable server, missing record, and mismatch all
/// mean the same thing: no confirmation, fail closed.
async fn server_confirms_denial(server_base_url: &str, denial: &DenyV1) -> bool {
    let url = format!(
        "{server_base_url}/api/v1/requests/{}/verdict",
        denial.request_id
    );
    let recorded: DecisionV1 = match http_get(&url).await {
        Ok(body) => match serde_json::from_slice(&body) {
            Ok(recorded) => recorded,
            Err(_) => return false,
        },
        Err(_) => return false,
    };
    denial_confirmed_by(&recorded, denial)
}

async fn server_device_matches(url: &str, device: &DevicePublicRecordV1) -> Result<bool> {
    let body = http_get(url).await?;
    let served: DevicePublicRecordV1 =
        serde_json::from_slice(&body).context("decode device record")?;
    served.validate()?;
    // Every field, not the identifying ones alone: the server stores the
    // activation record verbatim and never advances the signature counter, so
    // a served record that differs anywhere -- a rewritten label, another
    // device's API token hash -- is not the record that was just enrolled.
    // `active` is part of that: this record has to be servable right now.
    Ok(served == *device && served.active)
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
    let transport = transport_from(&config_dir()).await?;
    transport.revoke(fingerprint).await?;
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
    pin_device_record(&config_dir(), &device, &mut io::stdin().lock())
}

/// Pins a device record file exported for offline pairing. The record is
/// validated and pinning still needs the typed fingerprint confirmation,
/// but unlike `pin` there is no independent expected fingerprint to check
/// the record against: provenance is the file itself, so the confirmation
/// only proves the operator meant this record (and in `--local` setup it is
/// piped from the same export, making the step automatic).
fn cmd_pin_record(path: &Path) -> Result<()> {
    let raw = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let device: DevicePublicRecordV1 =
        serde_json::from_slice(&raw).context("decode device record")?;
    pin_device_record(&config_dir(), &device, &mut io::stdin().lock())
}

/// Shows a device record and pins it on typed fingerprint confirmation.
/// Shared by `pin` (record fetched from the server) and `pin-record`
/// (record carried over in a file): both write the same registry entry, so
/// a locally paired device approves exactly like an enrolled one.
fn pin_device_record(
    directory: &Path,
    device: &DevicePublicRecordV1,
    input: &mut impl io::BufRead,
) -> Result<()> {
    device.validate().context("device record")?;
    println!(
        "Fingerprint: {}\nLabel: {}\nCredential: {}",
        device.fingerprint,
        escape_for_terminal(&device.label),
        device.credential_id
    );
    print!("Type the full fingerprint to confirm: ");
    io::stdout().flush()?;
    let mut confirmation = String::new();
    input.read_line(&mut confirmation)?;
    if confirmation.trim() != device.fingerprint {
        bail!("fingerprint confirmation mismatch");
    }
    let mut registry = load_registry_from(directory)?;
    registry
        .devices
        .retain(|stored| stored.fingerprint != device.fingerprint);
    registry.devices.push(device.clone());
    registry.validate()?;
    write_registry_to(directory, &registry)?;
    println!("Device pinned: {}", device.fingerprint);
    Ok(())
}

fn cmd_status() -> Result<()> {
    let registry = load_registry()?;
    println!("Enrolled devices ({}):", registry.devices.len());
    for device in registry.devices {
        println!(
            "  {}  {}  kind={}  active={}",
            device.fingerprint,
            escape_for_terminal(&device.label),
            device.kind,
            device.active
        );
    }
    Ok(())
}

async fn cmd_test() -> Result<()> {
    execute_request(build_synthetic_request(), APPROVAL_TIMEOUT).await
}

async fn cmd_watch() -> Result<()> {
    let config = load_hook_config()?;
    let transport = transport_from(&config_dir()).await?;
    let mut subscription = transport.watch_requests().await?;
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

fn build_request(values: &[(String, String)]) -> Result<RequestV1> {
    let issued_at = now();
    let mut nonce = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let last_value = |key: &str| {
        values
            .iter()
            .rev()
            .find_map(|(candidate, value)| (candidate == key).then_some(value.as_str()))
    };
    // A current plugin emits this marker and the exact environment count.
    // Requiring it prevents a new hook from silently accepting the partial
    // environment produced by an older plugin. This is private framing; the
    // RequestV1 wire version remains unchanged.
    if last_value("meta.env_complete") != Some("1") {
        bail!("plugin payload does not attest to a complete environment");
    }
    let protocol_version = last_value("meta.protocol_version")
        .and_then(|value| value.parse::<u8>().ok())
        .context("missing or invalid plugin/hook protocol version")?;
    if protocol_version != PRIVATE_PLUGIN_HOOK_PROTOCOL_VERSION {
        bail!("unsupported plugin/hook protocol version: {protocol_version}");
    }
    let expected_env_count = last_value("meta.env_count")
        .and_then(|value| value.parse::<usize>().ok())
        .context("missing or invalid environment count")?;
    let command = last_value("info.command")
        .map(str::to_owned)
        .context("missing info.command")?;
    let argv = values
        .iter()
        .filter_map(|(key, _)| key.strip_prefix("argv.")?.parse::<u32>().ok())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .filter_map(|index| last_value(&format!("argv.{index}")).map(str::to_owned))
        .collect();
    // Preserve every environment entry in the order supplied by sudo,
    // including duplicate names. Ordering and duplicates are execution input;
    // a map or a finite allowlist here would make distinct sudo requests share
    // one approval.
    let env: Vec<EnvEntryV1> = values
        .iter()
        .filter_map(|(key, value)| {
            Some(EnvEntryV1 {
                name: key.strip_prefix("env.")?.to_owned(),
                value: value.clone(),
            })
        })
        .collect();
    if env.len() != expected_env_count {
        bail!(
            "environment count mismatch: payload says {expected_env_count}, received {}",
            env.len()
        );
    }
    let uid: u32 = last_value("info.uid")
        .and_then(|value| value.parse().ok())
        .unwrap_or(u32::MAX);
    let request = RequestV1 {
        version: VERSION_V1,
        request_id: Uuid::new_v4().to_string(),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        host: hostname(),
        user: last_value("info.user").map_or_else(|| "unknown".into(), str::to_owned),
        uid,
        runas_uid: last_value("info.runas_uid")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        cwd: last_value("info.cwd").map_or_else(|| "/".into(), str::to_owned),
        tty: last_value("info.tty")
            .map(str::to_owned)
            .filter(|value| !value.is_empty()),
        command,
        argv,
        pid_chain: pid_chain(),
        session: session_label(values, uid),
        env,
        issued_at,
        expires_at: issued_at + 90,
    };
    request.validate()?;
    Ok(request)
}

/// Resolves the caller's session label from the bound request values and
/// the invoking user's uid. First match wins; any step that does not apply
/// or fails falls through to the next one rather than erroring the request:
///
/// 1. An `OSHIOKI_SESSION` environment entry (`env.OSHIOKI_SESSION` in the
///    bound values), already documented in `docs/configuration.md`.
/// 2. Claude Code: `env.CLAUDE_PID` names a pid; `$HOME/.claude/sessions/<pid>.json`
///    (the invoking user's `$HOME`, looked up from their uid via the passwd
///    database rather than this process's own environment, which sudo has
///    already scrubbed and which may belong to a different user entirely)
///    holds `{"sessionId":...,"name":...}`. When `env.CLAUDE_CODE_SESSION_ID`
///    is also present it must match `sessionId`, guarding against a stale or
///    unrelated session file at a reused pid. `name` is used as the label.
///
/// Other coding agents can add a step the same shape: an env var naming a
/// pid or session id, and a per-user file to resolve it against.
///
/// The label is bounded and trimmed to satisfy `RequestV1::validate`; an
/// overlong or empty result after trimming is treated as no match.
fn session_label(values: &[(String, String)], uid: u32) -> Option<String> {
    let last_value = |key: &str| {
        values
            .iter()
            .rev()
            .find_map(|(candidate, value)| (candidate == key).then_some(value.as_str()))
    };
    if let Some(value) = last_value("env.OSHIOKI_SESSION") {
        if let Some(label) = normalize_session_label(value) {
            return Some(label);
        }
    }
    if let Some(pid) = last_value("env.CLAUDE_PID") {
        if let Some(label) =
            claude_code_session_label(pid, last_value("env.CLAUDE_CODE_SESSION_ID"), uid)
        {
            return Some(label);
        }
    }
    None
}

/// Bounds and trims a candidate session label to the limits
/// `RequestV1::validate` enforces: at most 64 characters, no control
/// characters, non-empty after trimming. Returns `None` rather than a
/// truncated value, since a clipped label could misrepresent the session.
fn normalize_session_label(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.chars().count() > 64
        || trimmed.chars().any(char::is_control)
    {
        return None;
    }
    Some(trimmed.to_owned())
}

/// Reads `$HOME/.claude/sessions/<pid>.json` for the invoking user (`uid`,
/// resolved via the passwd database, never this process's own environment)
/// and returns its `name` field, first verifying `sessionId` matches
/// `expected_session_id` when both are present. Any missing file, parse
/// failure, or mismatch yields `None` silently — this is a best-effort
/// label, not a trust boundary.
fn claude_code_session_label(
    pid: &str,
    expected_session_id: Option<&str>,
    uid: u32,
) -> Option<String> {
    let home = user_home_dir(uid)?;
    claude_code_session_label_at(&home, pid, expected_session_id)
}

/// The home-directory-independent half of [`claude_code_session_label`],
/// split out so tests can point it at a temporary directory instead of a
/// real account's home.
fn claude_code_session_label_at(
    home: &Path,
    pid: &str,
    expected_session_id: Option<&str>,
) -> Option<String> {
    let path = home.join(".claude").join("sessions").join(format!("{pid}.json"));
    let contents = std::fs::read(path).ok()?;
    let file: serde_json::Value = serde_json::from_slice(&contents).ok()?;
    if let Some(expected) = expected_session_id {
        let actual = file.get("sessionId").and_then(serde_json::Value::as_str);
        if actual != Some(expected) {
            return None;
        }
    }
    let name = file.get("name").and_then(serde_json::Value::as_str)?;
    normalize_session_label(name)
}

/// The invoking user's home directory, looked up by uid through the passwd
/// database. This process's own `HOME` environment variable is not a valid
/// substitute: sudo scrubs the plugin's environment before the hook ever
/// runs, and what remains (if anything) belongs to whichever account is
/// running the hook binary, not necessarily the invoking user.
fn user_home_dir(uid: u32) -> Option<PathBuf> {
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|user| user.dir)
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
        env: vec![],
        session: None,
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

fn parse_sudo_stdin() -> Result<Vec<(String, String)>> {
    let mut values = Vec::new();
    for line in io::stdin().lock().lines() {
        let line = line?;
        let (key, value) = line
            .split_once('=')
            .context("malformed plugin payload line")?;
        values.push((key.to_owned(), value.to_owned()));
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

/// Reads the selected transport name from `config.env`, failing closed on an
/// unknown value. Absent or empty means `nats`, the only backend. The flag
/// comes from `config.env` rather than the process environment: sudo scrubs
/// the environment, so this file is the hook's only channel.
fn selected_transport(directory: &Path) -> Result<String> {
    let env = read_env_file(&directory.join("config.env"))?;
    match env.get("OSHIOKI_TRANSPORT").map(String::as_str) {
        None | Some("" | "nats") => Ok("nats".to_owned()),
        Some(other) => bail!("unsupported transport: {other}"),
    }
}

/// Selects the hook transport named by `OSHIOKI_TRANSPORT` in `config.env`.
async fn transport_from(directory: &Path) -> Result<Box<dyn HookTransport>> {
    let name = selected_transport(directory)?;
    debug_assert_eq!(name, "nats");
    Ok(Box::new(NatsTransport::from_config_dir(directory).await?))
}
fn read_env_file(path: &Path) -> Result<HashMap<String, String>> {
    // The path rides along: this read opens every hook invocation, and a
    // half-installed host should learn which file is missing, not just
    // that something is.
    let content = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect())
}

async fn http_get(url: &str) -> Result<Vec<u8>> {
    let mut args = if config_dir() == Path::new(DEFAULT_CONFIG_DIR) {
        vec!["-q"]
    } else {
        Vec::new()
    };
    args.extend(["--fail", "--silent", "--show-error"]);
    // The system installation must not inherit a caller-controlled curl
    // configuration (which could enable redirects or disable TLS checks).
    // User-owned development configurations intentionally retain CURL_HOME;
    // the local E2E harness uses it to resolve its throwaway test hostname.
    args.extend(["--proto", "=https", "--max-time", "15", url]);
    let output = tokio::process::Command::new("/usr/bin/curl")
        .args(args)
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

    #[test]
    fn check_exit_codes_keep_password_fallback_only_for_unavailable_approval() {
        let unavailable = [
            approval_unavailable(
                "no agent on /run/oshioki.sock (Connection refused) and no NATS fallback configured",
            ),
            anyhow::Error::new(HookTransportFailure::Daemon(
                "daemon acknowledgement timed out".into(),
            )),
            anyhow::Error::new(HookTransportFailure::Transport(
                "NATS connection failed: certificate expired".into(),
            )),
            anyhow::Error::new(HookTransportFailure::Expired(
                "request expired without a verdict".into(),
            )),
        ];
        for error in unavailable {
            assert_eq!(
                check_error_exit_code(&error),
                CHECK_RC_UNAVAILABLE,
                "{error:#}"
            );
        }
        let nested = approval_unavailable("connection refused")
            .context("NATS fallback to tls://nats.example:4222 failed: connect");
        assert_eq!(check_error_exit_code(&nested), CHECK_RC_UNAVAILABLE);
        for message in [
            "request explicitly denied",
            "approval verification failed: invalid signature",
            "invalid request context",
            "NATS fallback to tls://nats.example:4222 failed: decode decision",
            "invalid request context: timeout was present in the command",
        ] {
            assert_eq!(
                check_error_exit_code(&anyhow::anyhow!(message)),
                CHECK_RC_DENIED,
                "{message}"
            );
        }
    }
    use p256::ecdsa::SigningKey;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
        assert!(matches!(
            cli.verb,
            Verb::Enroll {
                resume: Some(ref r),
                ..
            } if r == "-abc"
        ));
        let cli = Cli::try_parse_from(["oshioki", "enroll", "--allow-localhost"]).unwrap();
        assert!(matches!(
            cli.verb,
            Verb::Enroll {
                allow_localhost: true,
                resume: None,
            }
        ));
    }
    /// The complete effective environment reaches the signed request in its
    /// original order, including variables not in the finite display
    /// classification and duplicate names.
    #[test]
    fn build_request_binds_complete_environment() {
        let values = vec![
            ("info.command".into(), "/usr/bin/python3".into()),
            ("argv.1".into(), "/usr/bin/python3".into()),
            ("env.PYTHONINSPECT".into(), "1".into()),
            ("env.PERL5OPT".into(), "-M/tmp/attacker".into()),
            ("env.APP_MODE".into(), "unsafe".into()),
            ("env.PATH".into(), "/tmp/bin:/usr/bin".into()),
            ("env.PATH".into(), "/second".into()),
            ("env.LD_PRELOAD".into(), "/tmp/evil.so".into()),
            ("env.HOME".into(), "/root".into()),
            (
                "meta.protocol_version".into(),
                PRIVATE_PLUGIN_HOOK_PROTOCOL_VERSION.to_string(),
            ),
            ("meta.env_complete".into(), "1".into()),
            ("meta.env_count".into(), "7".into()),
        ];
        let request = build_request(&values).unwrap();
        let names: Vec<_> = request
            .env
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "PYTHONINSPECT",
                "PERL5OPT",
                "APP_MODE",
                "PATH",
                "PATH",
                "LD_PRELOAD",
                "HOME",
            ]
        );
        assert_eq!(request.env[0].value, "1");
        assert_eq!(request.env[1].value, "-M/tmp/attacker");
        assert_eq!(request.env[4].value, "/second");
        // The complete environment is part of the signed bytes, not
        // decoration or a finite allowlist projection.
        let raw = String::from_utf8(request.raw_json().unwrap()).unwrap();
        for name in ["PYTHONINSPECT", "PERL5OPT", "APP_MODE", "HOME"] {
            assert!(raw.contains(name), "{name} missing from {raw}");
        }
    }

    #[test]
    fn build_request_rejects_missing_or_mismatched_environment_attestation() {
        let base = vec![
            ("info.command".into(), "/usr/bin/true".into()),
            ("argv.1".into(), "/usr/bin/true".into()),
            ("env.APP_MODE".into(), "safe".into()),
        ];
        assert!(build_request(&base).is_err());

        let mut wrong_count = base.clone();
        wrong_count.extend([
            (
                "meta.protocol_version".into(),
                PRIVATE_PLUGIN_HOOK_PROTOCOL_VERSION.to_string(),
            ),
            ("meta.env_complete".into(), "1".into()),
            ("meta.env_count".into(), "2".into()),
        ]);
        assert!(build_request(&wrong_count).is_err());
    }

    /// An old plugin emits the environment markers without the private
    /// protocol version, while an explicitly mixed version must also fail
    /// closed before a request can be sealed.
    #[test]
    fn mixed_plugin_versions_fail_closed() {
        let base = vec![
            ("info.command".into(), "/usr/bin/true".into()),
            ("argv.1".into(), "/usr/bin/true".into()),
            ("env.APP_MODE".into(), "safe".into()),
            ("meta.env_complete".into(), "1".into()),
            ("meta.env_count".into(), "1".into()),
        ];
        assert!(build_request(&base).is_err(), "old plugin was accepted");
        let mut mismatched = base;
        mismatched.push(("meta.protocol_version".into(), "1".into()));
        assert!(
            build_request(&mismatched).is_err(),
            "unsupported plugin version was accepted"
        );
    }
    #[test]
    fn request_bytes_are_retained_in_every_sealed_body() {
        let request = build_synthetic_request();
        let raw = request.raw_json().unwrap();
        let credential = vec![1; 8];
        let signing = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
        let point = signing.verifying_key().to_encoded_point(false);
        let cose = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Integer(2.into()),
            ),
            (
                ciborium::Value::Integer(3.into()),
                ciborium::Value::Integer((-7).into()),
            ),
            (
                ciborium::Value::Integer((-1).into()),
                ciborium::Value::Integer(1.into()),
            ),
            (
                ciborium::Value::Integer((-2).into()),
                ciborium::Value::Bytes(point.x().unwrap().to_vec()),
            ),
            (
                ciborium::Value::Integer((-3).into()),
                ciborium::Value::Bytes(point.y().unwrap().to_vec()),
            ),
        ]);
        let mut public = Vec::new();
        ciborium::ser::into_writer(&cose, &mut public).unwrap();
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

    fn enrollment_config(origin: &str) -> HookConfigV1 {
        HookConfigV1 {
            version: VERSION_V1,
            origin: origin.into(),
            rp_id: "sudo.example".into(),
            server_base_url: origin.into(),
        }
    }

    #[test]
    fn enrollment_origin_rejects_local_only_hosts() {
        for origin in [
            "https://localhost",
            "https://localhost.",
            "https://sudo.localhost",
            "https://127.0.0.1",
            "https://0.0.0.0",
            "https://[::1]",
            "https://[::]",
            "https://[::ffff:127.0.0.1]",
        ] {
            let error = enrollment_origin(&enrollment_config(origin), false).unwrap_err();
            assert!(
                error.to_string().contains("oshioki-phone-setup"),
                "{origin}: {error:#}"
            );
        }
    }

    #[test]
    fn enrollment_origin_allows_a_phone_reachable_host_and_local_opt_in() {
        let config = enrollment_config("https://sudo.example.com:8443");
        assert_eq!(enrollment_origin(&config, false).unwrap().scheme(), "https");
        let local = enrollment_config("https://127.0.0.1:8443");
        assert_eq!(
            enrollment_origin(&local, true).unwrap().host_str(),
            Some("127.0.0.1")
        );
    }

    #[test]
    fn enrollment_origin_rejects_non_origin_url_shapes() {
        for origin in [
            "http://sudo.example",
            "https://user@sudo.example",
            "https://user:pass@sudo.example",
            "https://sudo.example/path",
            "https://sudo.example?query",
            "https://sudo.example#fragment",
        ] {
            let error = enrollment_origin(&enrollment_config(origin), true).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("invalid enrollment origin in hook configuration"),
                "{origin}: {error:#}"
            );
        }
    }

    #[test]
    fn enroll_root_requirement_only_applies_to_the_system_configuration() {
        assert!(enroll_needs_root(Path::new(DEFAULT_CONFIG_DIR), 501));
        assert!(!enroll_needs_root(Path::new(DEFAULT_CONFIG_DIR), 0));
        assert!(!enroll_needs_root(Path::new("/tmp/oshioki"), 501));
    }

    #[test]
    fn enrollment_health_requires_matching_configuration_when_present() {
        let config = enrollment_config("https://sudo.example");
        for body in [
            br#"{"status":"ok"}"#.as_slice(),
            br#"{"status":"ok","origin":"https://sudo.example","rp_id":"sudo.example"}"#.as_slice(),
        ] {
            let health: ServerHealthV1 = serde_json::from_slice(body).unwrap();
            assert!(validate_server_health(&config, &health).is_ok());
        }
        for body in [
            br#"{"status":"ok","origin":"https://other.example","rp_id":"sudo.example"}"#
                .as_slice(),
            br#"{"status":"ok","origin":"https://sudo.example"}"#.as_slice(),
            br#"{"status":"starting"}"#.as_slice(),
        ] {
            let health: ServerHealthV1 = serde_json::from_slice(body).unwrap();
            assert!(validate_server_health(&config, &health).is_err());
        }
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

    /// Nothing decides a request that is already dead, whatever the verdict
    /// says and whichever device kind signed it.
    #[tokio::test]
    async fn an_expired_request_rejects_every_verdict() {
        let mut request = build_synthetic_request();
        request.expires_at = now() - 1;
        let fingerprint = URL_SAFE_NO_PAD.encode([1; 16]);
        let mut registry = DeviceRegistryV1 {
            version: 1,
            devices: Vec::new(),
        };
        let decisions = [
            DecisionV1::Deny(oshioki_protocol::DenyV1 {
                version: VERSION_V1,
                request_id: request.request_id.clone(),
                device_fingerprint: fingerprint.clone(),
                signature: None,
            }),
            DecisionV1::ApproveNative(oshioki_protocol::ApproveNativeV1 {
                version: VERSION_V1,
                request_id: request.request_id.clone(),
                device_fingerprint: fingerprint.clone(),
                signature: URL_SAFE_NO_PAD.encode([2; 64]),
            }),
            DecisionV1::Approve(oshioki_protocol::ApproveV1 {
                version: VERSION_V1,
                request_id: request.request_id.clone(),
                device_fingerprint: fingerprint,
                credential_id: URL_SAFE_NO_PAD.encode([3; 16]),
                authenticator_data: URL_SAFE_NO_PAD.encode([4; 37]),
                client_data_json: URL_SAFE_NO_PAD.encode(b"{}"),
                signature: URL_SAFE_NO_PAD.encode([5; 64]),
            }),
        ];
        for decision in decisions {
            let error = apply_decision(
                decision,
                &request,
                &[],
                &[],
                &mut registry,
                Path::new("/nonexistent"),
            )
            .await
            .unwrap_err();
            assert!(
                error.to_string().contains("expired before its verdict"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn check_uses_the_root_owned_config_directory() {
        assert_eq!(check_config_dir(), Path::new("/etc/oshioki"));
    }

    /// One pinned Secure Enclave device with a real key, for denial tests.
    fn deny_test_device() -> (DevicePublicRecordV1, p256::ecdsa::SigningKey) {
        let signing = p256::ecdsa::SigningKey::from_bytes((&[21; 32]).into()).unwrap();
        let public = signing
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let credential_id = oshioki_protocol::native_credential_id(&public);
        let fingerprint = oshioki_protocol::device_fingerprint(&credential_id, &public, &[22; 32]);
        let device = DevicePublicRecordV1 {
            version: VERSION_V1,
            kind: DeviceKindV1::SecureEnclave,
            fingerprint,
            credential_id: URL_SAFE_NO_PAD.encode(&credential_id),
            credential_public_key: URL_SAFE_NO_PAD.encode(&public),
            box_public_key: URL_SAFE_NO_PAD.encode([22; 32]),
            label: "test".into(),
            api_token_hash: URL_SAFE_NO_PAD.encode([23; 32]),
            sign_count: 0,
            active: true,
        };
        device.validate().unwrap();
        (device, signing)
    }

    /// A device distinct from `deny_test_device`, for tests that need to
    /// seed the registry with an unrelated entry before pinning.
    fn other_test_device() -> DevicePublicRecordV1 {
        let signing = p256::ecdsa::SigningKey::from_bytes((&[31; 32]).into()).unwrap();
        let public = signing
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let credential_id = oshioki_protocol::native_credential_id(&public);
        let fingerprint = oshioki_protocol::device_fingerprint(&credential_id, &public, &[32; 32]);
        let device = DevicePublicRecordV1 {
            version: VERSION_V1,
            kind: DeviceKindV1::SecureEnclave,
            fingerprint,
            credential_id: URL_SAFE_NO_PAD.encode(&credential_id),
            credential_public_key: URL_SAFE_NO_PAD.encode(&public),
            box_public_key: URL_SAFE_NO_PAD.encode([32; 32]),
            label: "test".into(),
            api_token_hash: URL_SAFE_NO_PAD.encode([33; 32]),
            sign_count: 0,
            active: true,
        };
        device.validate().unwrap();
        device
    }

    fn deny_for(
        signing: &p256::ecdsa::SigningKey,
        request_id: &str,
        device: &DevicePublicRecordV1,
    ) -> DenyV1 {
        use p256::ecdsa::signature::Signer as _;
        let challenge = oshioki_protocol::deny_challenge(request_id, &device.fingerprint);
        let signature: p256::ecdsa::Signature = signing.sign(&challenge);
        DenyV1 {
            version: VERSION_V1,
            request_id: request_id.into(),
            device_fingerprint: device.fingerprint.clone(),
            signature: Some(URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())),
        }
    }

    /// A device-signed denial applies; a forgery, a cross-device denial, and
    /// an unsigned denial (with no server to confirm it) do not — each with
    /// its own error, so operators can tell attack from outage.
    #[tokio::test]
    async fn denial_signatures_decide_at_apply_time() {
        async fn apply(
            decision: DecisionV1,
            request: &RequestV1,
            active: &[DevicePublicRecordV1],
            registry: &mut DeviceRegistryV1,
        ) -> Result<()> {
            apply_decision(
                decision,
                request,
                &[],
                active,
                registry,
                Path::new("/nonexistent"),
            )
            .await
        }
        let (device, signing) = deny_test_device();
        let mut request = build_synthetic_request();
        request.request_id = "req-1".into();
        let mut registry = DeviceRegistryV1 {
            version: 1,
            devices: Vec::new(),
        };
        let active = [device.clone()];
        let error = apply(
            DecisionV1::Deny(deny_for(&signing, "req-1", &device)),
            &request,
            &active,
            &mut registry,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("explicitly denied"), "{error:#}");
        let other = p256::ecdsa::SigningKey::from_bytes((&[24; 32]).into()).unwrap();
        let error = apply(
            DecisionV1::Deny(deny_for(&other, "req-1", &device)),
            &request,
            &active,
            &mut registry,
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("deny verification failed"),
            "{error:#}"
        );
        let mut crossed = deny_for(&signing, "req-1", &device);
        crossed.device_fingerprint = URL_SAFE_NO_PAD.encode([25; 16]);
        let error = apply(DecisionV1::Deny(crossed), &request, &active, &mut registry)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("deny from unpinned device"),
            "{error:#}"
        );
        let unsigned = DenyV1 {
            version: VERSION_V1,
            request_id: "req-1".into(),
            device_fingerprint: device.fingerprint.clone(),
            signature: None,
        };
        let error = apply(DecisionV1::Deny(unsigned), &request, &active, &mut registry)
            .await
            .unwrap_err();
        assert!(
            !error.to_string().contains("explicitly denied"),
            "{error:#}"
        );
    }

    /// Offline pairing pins a carried-over record on the same typed
    /// confirmation: the confirmation writes the registry, and the pinned
    /// device is active immediately.
    #[test]
    fn pin_record_writes_the_registry_on_confirmation() {
        let dir = std::env::temp_dir().join(format!("oshioki-pinrecord-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (device, _) = deny_test_device();
        let mut input = std::io::Cursor::new(format!("{}\n", device.fingerprint));
        pin_device_record(&dir, &device, &mut input).unwrap();
        let registry = load_registry_from(&dir).unwrap();
        assert_eq!(registry.devices.len(), 1);
        assert_eq!(registry.devices[0], device);
        assert!(registry.devices[0].active);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A wrong confirmation refuses and writes nothing: a record nobody
    /// confirmed is not a pairing.
    #[test]
    fn pin_record_refuses_a_wrong_confirmation() {
        let dir = std::env::temp_dir().join(format!("oshioki-pinrefuse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (unrelated, _) = deny_test_device();
        write_registry_to(
            &dir,
            &DeviceRegistryV1 {
                version: 1,
                devices: vec![unrelated.clone()],
            },
        )
        .unwrap();
        let device = other_test_device();
        let mut input = std::io::Cursor::new("not-the-fingerprint\n");
        let error = pin_device_record(&dir, &device, &mut input).unwrap_err();
        assert!(
            error.to_string().contains("confirmation mismatch"),
            "{error:#}"
        );
        assert_eq!(load_registry_from(&dir).unwrap().devices, vec![unrelated]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An invalid record never reaches the confirmation: label included.
    #[test]
    fn pin_record_refuses_an_invalid_record() {
        let dir = std::env::temp_dir().join(format!("oshioki-pinbad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (unrelated, _) = deny_test_device();
        write_registry_to(
            &dir,
            &DeviceRegistryV1 {
                version: 1,
                devices: vec![unrelated.clone()],
            },
        )
        .unwrap();
        let mut device = other_test_device();
        device.label.clear();
        let mut input = std::io::Cursor::new(format!("{}\n", device.fingerprint));
        assert!(pin_device_record(&dir, &device, &mut input).is_err());
        assert_eq!(load_registry_from(&dir).unwrap().devices, vec![unrelated]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn pin_record_takes_a_path() {
        let cli = Cli::try_parse_from(["oshioki", "pin-record", "/tmp/record.json"]).unwrap();
        assert!(matches!(cli.verb, Verb::PinRecord { .. }));
    }

    /// The server's record confirms exactly the denial it recorded: same
    /// request, same fingerprint, denial kind. Anything else stands alone.
    #[test]
    fn server_records_confirm_only_matching_denials() {
        let denial = DenyV1 {
            version: VERSION_V1,
            request_id: "req-1".into(),
            device_fingerprint: URL_SAFE_NO_PAD.encode([26; 16]),
            signature: None,
        };
        assert!(denial_confirmed_by(
            &DecisionV1::Deny(denial.clone()),
            &denial
        ));
        let mut other_request = denial.clone();
        other_request.request_id = "req-2".into();
        assert!(!denial_confirmed_by(
            &DecisionV1::Deny(other_request),
            &denial
        ));
        let mut other_device = denial.clone();
        other_device.device_fingerprint = URL_SAFE_NO_PAD.encode([27; 16]);
        assert!(!denial_confirmed_by(
            &DecisionV1::Deny(other_device),
            &denial
        ));
        assert!(!denial_confirmed_by(
            &DecisionV1::ApproveNative(oshioki_protocol::ApproveNativeV1 {
                version: VERSION_V1,
                request_id: "req-1".into(),
                device_fingerprint: denial.device_fingerprint.clone(),
                signature: URL_SAFE_NO_PAD.encode([28; 64]),
            }),
            &denial
        ));
    }

    /// The TLS gate runs before any network: plaintext past loopback (or a
    /// foreign scheme) fails with the policy error rather than a connection
    /// timeout, so these cases never open a socket.
    #[tokio::test]
    async fn plaintext_nats_fails_before_connecting() {
        for (url, fragment) in [
            ("nats://203.0.1.1:4222", "refusing plaintext"),
            ("http://127.0.0.1:4222", "unsupported NATS URL scheme"),
        ] {
            let dir = std::env::temp_dir().join(format!("oshioki-hook-nats-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("config.env"),
                format!("NATS_URL={url}\nNATS_USER=u\nNATS_PASS=p\n"),
            )
            .unwrap();
            let Err(error) = transport_from(&dir).await else {
                panic!("plaintext NATS unexpectedly connected");
            };
            assert!(format!("{error:#}").contains(fragment), "{error:#}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    fn socket_test_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("oshioki-hook-socket-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn socket_test_config(dir: &Path, socket: Option<&Path>) {
        let mut config = String::from("NATS_URL=nats://127.0.0.1:4222\n");
        if let Some(socket) = socket {
            config.push_str("OSHIOKI_AGENT_SOCKET=");
            config.push_str(&socket.display().to_string());
            config.push('\n');
        }
        std::fs::write(dir.join("config.env"), config).unwrap();
    }

    fn test_progress() -> std::sync::Arc<dyn Fn(HookProgress) + Send + Sync> {
        std::sync::Arc::new(|_| {})
    }

    #[tokio::test]
    async fn unconfigured_socket_reports_unconfigured() {
        let dir = socket_test_dir("unconfigured");
        socket_test_config(&dir, None);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        assert!(matches!(
            try_agent_socket(&dir, "req-1", b"{}", deadline, &test_progress())
                .await
                .unwrap(),
            SocketOutcome::Unconfigured
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn missing_socket_path_reports_no_agent() {
        let dir = socket_test_dir("missing");
        socket_test_config(&dir, Some(Path::new("/nonexistent-oshioki-agent.sock")));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        assert!(matches!(
            try_agent_socket(&dir, "req-1", b"{}", deadline, &test_progress())
                .await
                .unwrap(),
            SocketOutcome::Silent(SocketSilence::NoAgent { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An agent that takes the connection but sends no alive acknowledgement
    /// is unavailable, rather than an approval or denial.
    #[tokio::test]
    async fn hanging_up_before_ack_reports_no_ack() {
        let dir = socket_test_dir("hangup");
        let socket_path = dir.join("agent.sock");
        socket_test_config(&dir, Some(&socket_path));
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        let serve = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream);
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        assert!(matches!(
            try_agent_socket(&dir, "req-1", b"ping", deadline, &test_progress())
                .await
                .unwrap(),
            SocketOutcome::Silent(SocketSilence::NoAck { .. })
        ));
        serve.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn socket_round_trip_returns_the_stub_verdict() {
        let dir = socket_test_dir("round-trip");
        let socket_path = dir.join("agent.sock");
        socket_test_config(&dir, Some(&socket_path));
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        let serve = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut prefix = [0u8; 4];
            AsyncReadExt::read_exact(&mut stream, &mut prefix)
                .await
                .unwrap();
            let len = u32::from_be_bytes(prefix) as usize;
            let mut request = vec![0u8; len];
            AsyncReadExt::read_exact(&mut stream, &mut request)
                .await
                .unwrap();
            assert!(!request.is_empty());
            let alive = oshioki_protocol::AliveV1::for_request("req-1");
            let alive_frame =
                oshioki_protocol::socket_v1::encode_frame(&serde_json::to_vec(&alive).unwrap())
                    .unwrap();
            AsyncWriteExt::write_all(&mut stream, &alive_frame)
                .await
                .unwrap();
            let decision = DecisionV1::Deny(oshioki_protocol::DenyV1 {
                version: VERSION_V1,
                request_id: "req-1".into(),
                device_fingerprint: "fp".into(),
                signature: None,
            });
            let frame =
                oshioki_protocol::socket_v1::encode_frame(&serde_json::to_vec(&decision).unwrap())
                    .unwrap();
            AsyncWriteExt::write_all(&mut stream, &frame).await.unwrap();
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        match try_agent_socket(&dir, "req-1", b"ping", deadline, &test_progress())
            .await
            .unwrap()
        {
            SocketOutcome::Decision(DecisionV1::Deny(denial)) => {
                assert_eq!(denial.request_id, "req-1");
            }
            SocketOutcome::Decision(_) => panic!("stub sent a deny"),
            SocketOutcome::Unconfigured | SocketOutcome::Silent(_) => {
                panic!("stub verdict was ignored")
            }
        }
        serve.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A process that owns the Linux agent state can replace the socket and
    /// use the readable software identity to produce a valid signature. The
    /// record remains explicitly software, so the installer must not pair it
    /// with passwordless sudo; the separate installer regression checks that
    /// policy while this test exercises the replacement-socket path itself.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn replacement_socket_with_software_identity_is_not_hardware_assurance() {
        use p256::ecdsa::{SigningKey, signature::Signer as _};

        let dir = socket_test_dir("software-replacement");
        // macOS caps AF_UNIX paths at 104 bytes; keep the socket outside the
        // descriptive temp directory so this test also runs there.
        let socket_path = PathBuf::from(format!("/tmp/oshioki-repl-{}.sock", Uuid::new_v4()));
        socket_test_config_no_nats(&dir, Some(&socket_path));

        let signing = SigningKey::from_slice(&[0x11; 32]).unwrap();
        let box_secret = x25519_dalek::StaticSecret::from([0x22; 32]);
        let credential_public_key = signing
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let credential_id = oshioki_protocol::native_credential_id(&credential_public_key);
        let device = DevicePublicRecordV1 {
            version: VERSION_V1,
            kind: DeviceKindV1::Software,
            fingerprint: oshioki_protocol::device_fingerprint(
                &credential_id,
                &credential_public_key,
                x25519_dalek::PublicKey::from(&box_secret).as_bytes(),
            ),
            credential_id: URL_SAFE_NO_PAD.encode(&credential_id),
            credential_public_key: URL_SAFE_NO_PAD.encode(&credential_public_key),
            box_public_key: URL_SAFE_NO_PAD
                .encode(x25519_dalek::PublicKey::from(&box_secret).as_bytes()),
            label: "linux".into(),
            api_token_hash: URL_SAFE_NO_PAD.encode([0x33; 32]),
            sign_count: 0,
            active: true,
        };
        device.validate().unwrap();
        let request = build_synthetic_request();
        let raw = request.raw_json().unwrap();
        let envelope = oshioki_protocol::RequestEnvelopeV1 {
            version: VERSION_V1,
            request_id: request.request_id.clone(),
            host: request.host.clone(),
            user: request.user.clone(),
            issued_at: request.issued_at,
            expires_at: request.expires_at,
            sealed: vec![oshioki_protocol::seal_v1(&raw, &device).unwrap()],
        };
        let payload = serde_json::to_vec(&envelope).unwrap();
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        let expected_fingerprint = device.fingerprint.clone();
        let expected_raw = raw.clone();
        let serve = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut prefix = [0u8; 4];
            stream.read_exact(&mut prefix).await.unwrap();
            let mut request_bytes = vec![0u8; u32::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut request_bytes).await.unwrap();
            let received: RequestEnvelopeV1 = serde_json::from_slice(&request_bytes).unwrap();
            let opened = oshioki_protocol::unseal_v1(&received.sealed[0], &box_secret).unwrap();
            assert_eq!(opened, expected_raw);
            let alive = oshioki_protocol::socket_v1::encode_frame(
                &serde_json::to_vec(&oshioki_protocol::AliveV1::for_request(
                    &received.request_id,
                ))
                .unwrap(),
            )
            .unwrap();
            stream.write_all(&alive).await.unwrap();
            let signature: p256::ecdsa::Signature =
                signing.sign(&oshioki_protocol::approve_challenge(&opened));
            let approval = oshioki_protocol::ApproveNativeV1 {
                version: VERSION_V1,
                request_id: received.request_id,
                device_fingerprint: expected_fingerprint,
                signature: URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
            };
            let frame = oshioki_protocol::socket_v1::encode_frame(
                &serde_json::to_vec(&DecisionV1::ApproveNative(approval)).unwrap(),
            )
            .unwrap();
            stream.write_all(&frame).await.unwrap();
        });

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let progress = test_progress();
        let decision =
            match try_agent_socket(&dir, &request.request_id, &payload, deadline, &progress)
                .await
                .unwrap()
            {
                SocketOutcome::Decision(decision) => decision,
                SocketOutcome::Unconfigured | SocketOutcome::Silent(_) => {
                    panic!("replacement socket verdict was ignored")
                }
            };
        let mut registry = DeviceRegistryV1 {
            version: VERSION_V1,
            devices: Vec::new(),
        };
        apply_decision(
            decision,
            &request,
            &raw,
            std::slice::from_ref(&device),
            &mut registry,
            &dir,
        )
        .await
        .unwrap();
        assert_eq!(device.kind, DeviceKindV1::Software);
        serve.await.unwrap();
        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn malformed_socket_reply_fails_closed_without_fallback() {
        let dir = socket_test_dir("malformed");
        let socket_path = dir.join("agent.sock");
        socket_test_config(&dir, Some(&socket_path));
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        let serve = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let frame = oshioki_protocol::socket_v1::encode_frame(b"not json").unwrap();
            AsyncWriteExt::write_all(&mut stream, &frame).await.unwrap();
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        assert!(
            try_agent_socket(&dir, "req-1", b"ping", deadline, &test_progress())
                .await
                .is_err()
        );
        serve.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Once an agent has acknowledged, a malformed verdict frame is a
    /// terminal protocol failure. It cannot fall back to another transport or
    /// become a password-eligible unavailable result.
    #[tokio::test]
    async fn malformed_socket_verdict_after_ack_fails_closed() {
        for (name, prefix) in [
            (
                "oversized",
                u32::try_from(oshioki_protocol::socket_v1::MAX_FRAME_BYTES + 1)
                    .unwrap()
                    .to_be_bytes(),
            ),
            ("empty", 0u32.to_be_bytes()),
        ] {
            let dir = socket_test_dir(name);
            let socket_path = dir.join("agent.sock");
            socket_test_config(&dir, Some(&socket_path));
            let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
            let serve = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request_prefix = [0u8; 4];
                stream.read_exact(&mut request_prefix).await.unwrap();
                let request_len = u32::from_be_bytes(request_prefix) as usize;
                let mut request = vec![0u8; request_len];
                stream.read_exact(&mut request).await.unwrap();
                let alive = oshioki_protocol::AliveV1::for_request("req-1");
                let alive_frame =
                    oshioki_protocol::socket_v1::encode_frame(&serde_json::to_vec(&alive).unwrap())
                        .unwrap();
                stream.write_all(&alive_frame).await.unwrap();
                stream.write_all(&prefix).await.unwrap();
            });
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let Err(error) =
                try_agent_socket(&dir, "req-1", b"ping", deadline, &test_progress()).await
            else {
                panic!("malformed {name} verdict was accepted");
            };
            assert_eq!(
                check_error_exit_code(&error),
                CHECK_RC_DENIED,
                "{name}: {error:#}"
            );
            serve.await.unwrap();
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[tokio::test]
    async fn silent_agent_fails_closed_without_fallback() {
        let dir = socket_test_dir("silent");
        let socket_path = dir.join("agent.sock");
        socket_test_config(&dir, Some(&socket_path));
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        let serve = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        assert!(matches!(
            try_agent_socket(&dir, "req-1", b"ping", deadline, &test_progress())
                .await
                .unwrap(),
            SocketOutcome::Silent(SocketSilence::NoAck { .. })
        ));
        serve.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A connected socket that never acknowledges is bounded by the short
    /// daemon liveness timeout, even when the approval deadline is long.
    #[tokio::test]
    async fn no_ack_socket_does_not_consume_the_approval_deadline() {
        let dir = socket_test_dir("no-ack-timeout");
        let socket_path = dir.join("agent.sock");
        socket_test_config(&dir, Some(&socket_path));
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        let serve = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let started = std::time::Instant::now();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let outcome = try_agent_socket(&dir, "req-1", b"ping", deadline, &test_progress())
            .await
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(6));
        assert!(matches!(
            outcome,
            SocketOutcome::Silent(SocketSilence::NoAck { .. })
        ));
        serve.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A missing config.env names the file, not just the OS error: this
    /// read opens every hook invocation on a half-installed host.
    #[test]
    fn missing_config_env_names_the_file() {
        let dir = socket_test_dir("missing-env");
        let error = transports_from(&dir).unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("config.env"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A config naming neither transport fails before any request is built,
    /// not at the first sudo afterwards.
    #[test]
    fn transports_rejects_an_empty_transport_set() {
        let dir = socket_test_dir("no-transports");
        std::fs::write(dir.join("config.env"), "OSHIOKI_ALLOW_PLAINTEXT_NATS=1\n").unwrap();
        let error = transports_from(&dir).unwrap_err();
        assert!(
            format!("{error:#}").contains("no approval transports configured"),
            "{error:#}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Each transport alone is a complete set: socket-only names no NATS,
    /// NATS-only names no socket.
    #[test]
    fn transports_accepts_each_transport_alone() {
        let dir = socket_test_dir("socket-only");
        socket_test_config_no_nats(&dir, Some(Path::new("/tmp/agent.sock")));
        let transports = transports_from(&dir).unwrap();
        assert!(transports.socket.is_some());
        assert!(transports.nats_url.is_none());
        let _ = std::fs::remove_dir_all(&dir);

        let dir = socket_test_dir("nats-only");
        socket_test_config(&dir, None);
        let transports = transports_from(&dir).unwrap();
        assert!(transports.socket.is_none());
        assert_eq!(
            transports.nats_url.as_deref(),
            Some("nats://127.0.0.1:4222")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Error text names the server without the secret.
    #[test]
    fn nats_display_url_redacts_credentials() {
        assert_eq!(
            nats_display_url("nats://oshioki:s3cret@127.0.0.1:4222"),
            "nats://127.0.0.1:4222"
        );
        assert_eq!(
            nats_display_url("tls://nats.example.com:4222"),
            "tls://nats.example.com:4222"
        );
        assert_eq!(nats_display_url("nats://[::1]:4222"), "nats://[::1]:4222");
        assert_eq!(
            nats_display_url("oshioki:s3cret@nats.example.com:4222"),
            "<invalid NATS URL>"
        );
        let noisy = sanitize_terminal_text(&format!(
            "tls://oshioki:s3cret@nats.example.com:4222\u{001b}[2K{}",
            "x".repeat(MAX_TERMINAL_ERROR_BYTES)
        ));
        assert!(!noisy.contains("s3cret"));
        assert!(!noisy.contains('\u{001b}'));
        assert!(noisy.ends_with("..."));
        assert_eq!(
            sanitize_terminal_text("connect to oshioki:s3cret@nats.example.com:4222 failed"),
            "connect to <redacted>@nats.example.com:4222 failed"
        );
        assert_eq!(
            sanitize_terminal_text("connect to sometoken@nats.example.com:4222 failed"),
            "connect to <redacted>@nats.example.com:4222 failed"
        );
    }

    /// Credentials are both-or-neither: one without the other is a config
    /// error, while neither reaches the URL policy check untouched.
    #[tokio::test]
    async fn nats_creds_are_both_or_neither() {
        let dir = socket_test_dir("half-creds");
        std::fs::write(
            dir.join("config.env"),
            "NATS_URL=nats://127.0.0.1:4222\nNATS_USER=u\n",
        )
        .unwrap();
        let Err(error) = transport_from(&dir).await else {
            panic!("half-credentials unexpectedly connected")
        };
        assert!(
            format!("{error:#}").contains("both or neither"),
            "{error:#}"
        );
        std::fs::write(dir.join("config.env"), "NATS_URL=nats://203.0.1.1:4222\n").unwrap();
        let Err(error) = transport_from(&dir).await else {
            panic!("plaintext NATS unexpectedly connected")
        };
        assert!(
            format!("{error:#}").contains("refusing plaintext"),
            "{error:#}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A directory with one pinned device and a request to decide, for the
    /// request-level transport tests below.
    fn decided_test_dir(name: &str) -> (PathBuf, RequestV1) {
        let dir = socket_test_dir(name);
        let (device, _) = deny_test_device();
        write_registry_to(
            &dir,
            &DeviceRegistryV1 {
                version: VERSION_V1,
                devices: vec![device],
            },
        )
        .unwrap();
        (dir, build_synthetic_request())
    }

    /// A stub agent that takes the connection, reads the request, and hangs
    /// up without an acknowledgement. Reading first matters: the hook always
    /// writes before reading, and a peer that vanishes before the write lands
    /// reads as no agent rather than an unavailable daemon.
    /// Takes an already-bound listener so the bind cannot race the hook's
    /// connect. Returns when the hook's side is done.
    async fn hangup_stub(listener: tokio::net::UnixListener) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut drain = Vec::new();
        let _ = AsyncReadExt::read_to_end(&mut stream, &mut drain).await;
        drop(stream);
    }

    /// A peer that acknowledges and then disconnects has taken responsibility
    /// for the request. The hook treats that unexpected post-ack EOF as a
    /// denial instead of falling back to another approval path.
    async fn acknowledged_hangup_stub(listener: tokio::net::UnixListener) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut prefix = [0u8; oshioki_protocol::socket_v1::FRAME_LEN_BYTES];
        stream.read_exact(&mut prefix).await.unwrap();
        let length = oshioki_protocol::socket_v1::decode_frame_len(prefix).unwrap();
        let mut request = vec![0u8; length];
        stream.read_exact(&mut request).await.unwrap();
        let request: oshioki_protocol::RequestEnvelopeV1 =
            serde_json::from_slice(&request).unwrap();
        let alive = oshioki_protocol::AliveV1::for_request(&request.request_id);
        let frame = oshioki_protocol::socket_v1::encode_frame(&serde_json::to_vec(&alive).unwrap())
            .unwrap();
        stream.write_all(&frame).await.unwrap();
        stream.flush().await.unwrap();
    }

    /// Binds a stub socket synchronously, before the hook can connect, and
    /// returns the listener for [`hangup_stub`].
    fn hangup_listener(socket_path: &Path) -> tokio::net::UnixListener {
        tokio::net::UnixListener::bind(socket_path).unwrap()
    }

    /// Socket-only hangup denies at once with no NATS attempt: nothing else
    /// could answer, so waiting out the deadline would only stall the sudo.
    #[tokio::test]
    async fn socket_only_hangup_denies_without_touching_nats() {
        let (dir, request) = decided_test_dir("hangup-deny");
        let socket_path = dir.join("agent.sock");
        socket_test_config_no_nats(&dir, Some(&socket_path));
        let serve = tokio::spawn(hangup_stub(hangup_listener(&socket_path)));
        let started = std::time::Instant::now();
        let error = execute_request_at(request, Duration::from_secs(30), &dir, false)
            .await
            .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(6));
        assert!(
            format!("{error:#}").contains("no NATS fallback configured"),
            "{error:#}"
        );
        assert!(
            format!("{error:#}").contains("daemon not responding"),
            "{error:#}"
        );
        serve.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn post_ack_socket_hangup_is_a_terminal_denial() {
        let (dir, request) = decided_test_dir("post-ack-hangup-deny");
        let socket_path = dir.join("agent.sock");
        socket_test_config_no_nats(&dir, Some(&socket_path));
        let serve = tokio::spawn(acknowledged_hangup_stub(hangup_listener(&socket_path)));
        let started = std::time::Instant::now();
        let error = execute_request_at(request, Duration::from_secs(30), &dir, false)
            .await
            .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(6));
        assert_eq!(check_error_exit_code(&error), CHECK_RC_DENIED);
        assert!(
            format!("{error:#}").contains("closed after acknowledging"),
            "{error:#}"
        );
        serve.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Socket-only with nothing on the socket names the path it tried.
    #[tokio::test]
    async fn socket_only_missing_agent_names_the_socket() {
        let (dir, request) = decided_test_dir("no-agent-deny");
        let socket_path = dir.join("agent.sock");
        socket_test_config_no_nats(&dir, Some(&socket_path));
        let error = execute_request_at(request, Duration::from_secs(30), &dir, false)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("no agent on"), "{error:#}");
        assert!(
            format!("{error:#}").contains("no NATS fallback configured"),
            "{error:#}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With NATS configured but unreachable, the fallback failure names the
    /// server and the failed step instead of leaking a library error.
    #[tokio::test]
    async fn nats_fallback_connect_failure_names_the_server() {
        let (dir, request) = decided_test_dir("nats-down");
        let socket_path = dir.join("agent.sock");
        let port = closed_loopback_port();
        std::fs::write(
            dir.join("config.env"),
            format!(
                "NATS_URL=nats://127.0.0.1:{port}\nNATS_USER=u\nNATS_PASS=p\nOSHIOKI_AGENT_SOCKET={}\n",
                socket_path.display()
            ),
        )
        .unwrap();
        let serve = tokio::spawn(hangup_stub(hangup_listener(&socket_path)));
        let started = std::time::Instant::now();
        let error = execute_request_at(request, Duration::from_secs(30), &dir, false)
            .await
            .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(6));
        let text = format!("{error:#}");
        assert!(
            text.contains(&format!("NATS fallback to nats://127.0.0.1:{port} failed")),
            "{text}"
        );
        assert!(!text.contains("NATS_PASS"), "{text}");
        serve.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A browser-capable request still fails promptly when its relay is down:
    /// the browser delivery receipt is an extension of native liveness only
    /// after a real server response, never a reason to wait ninety seconds
    /// for a server that cannot be reached.
    #[tokio::test]
    async fn browser_fallback_without_a_server_fails_fast() {
        let dir = socket_test_dir("browser-nats-down");
        let port = closed_loopback_port();
        std::fs::write(
            dir.join("config.env"),
            format!("NATS_URL=nats://127.0.0.1:{port}\nNATS_USER=u\nNATS_PASS=p\n"),
        )
        .unwrap();
        let request = build_synthetic_request();
        let started = std::time::Instant::now();
        let error = nats_fallback(
            &dir,
            &request,
            b"{}".to_vec(),
            tokio::time::Instant::now() + Duration::from_secs(90),
            &format!("nats://127.0.0.1:{port}"),
            NatsFallbackOptions {
                announce_url: false,
                has_browser_recipient: true,
            },
            test_progress(),
        )
        .await
        .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(6));
        assert_eq!(check_error_exit_code(&error), CHECK_RC_UNAVAILABLE);
        assert!(format!("{error:#}").contains("NATS fallback"), "{error:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A loopback TCP port nothing listens on: binding then dropping leaves
    /// a port the fallback connect refuses fast.
    fn closed_loopback_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
        listener.local_addr().expect("read the bound port").port()
    }

    fn socket_test_config_no_nats(dir: &Path, socket: Option<&Path>) {
        let mut config = String::new();
        if let Some(socket) = socket {
            config.push_str("OSHIOKI_AGENT_SOCKET=");
            config.push_str(&socket.display().to_string());
            config.push('\n');
        }
        std::fs::write(dir.join("config.env"), config).unwrap();
    }
    /// A DENY carried by the mock transport fails the request, exactly the
    /// observable contract the hook must honor: the mock proves the seam
    /// carries the verdict through without the wire.
    #[tokio::test]
    async fn mock_transport_carries_a_deny() {
        let (device, signing) = deny_test_device();
        let mut request = build_synthetic_request();
        request.request_id = "req-1".into();
        let transport = oshioki_transport::MockTransport::new();
        transport.push_verdict(DecisionV1::Deny(deny_for(&signing, "req-1", &device)));
        let decision = transport
            .request_decision(
                "nas",
                "req-1",
                b"{}".to_vec(),
                Duration::from_secs(1),
                false,
                test_progress(),
            )
            .await
            .unwrap();
        let mut registry = DeviceRegistryV1 {
            version: 1,
            devices: Vec::new(),
        };
        let error = apply_decision(
            decision,
            &request,
            &[],
            &[device],
            &mut registry,
            Path::new("/nonexistent"),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("explicitly denied"), "{error:#}");
    }

    /// A device-signed native approval carried by the mock transport
    /// approves against the pinned record: the seam carries the verdict and
    /// the hook's cryptographic check admits it.
    #[tokio::test]
    async fn mock_transport_carries_a_signed_approval() {
        use p256::ecdsa::signature::Signer as _;
        let (device, signing) = deny_test_device();
        let request = build_synthetic_request();
        let raw = request.raw_json().unwrap();
        let challenge = oshioki_protocol::v1::approve_challenge(&raw);
        let signature: p256::ecdsa::Signature = signing.sign(&challenge);
        let mut registry = DeviceRegistryV1 {
            version: 1,
            devices: Vec::new(),
        };
        let approval = DecisionV1::ApproveNative(oshioki_protocol::ApproveNativeV1 {
            version: VERSION_V1,
            request_id: request.request_id.clone(),
            device_fingerprint: device.fingerprint.clone(),
            signature: URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
        });
        let transport = oshioki_transport::MockTransport::new();
        transport.push_verdict(approval);
        let decision = transport
            .request_decision(
                "nas",
                &request.request_id,
                raw.clone(),
                Duration::from_secs(1),
                false,
                test_progress(),
            )
            .await
            .unwrap();
        apply_decision(
            decision,
            &request,
            &raw,
            std::slice::from_ref(&device),
            &mut registry,
            Path::new("/nonexistent"),
        )
        .await
        .expect("signed approval must approve");
    }

    fn write_claude_session_file(home: &Path, pid: &str, body: &str) {
        let dir = home.join(".claude").join("sessions");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{pid}.json")), body).unwrap();
    }

    fn temp_home(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "oshioki-session-label-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The ordinary case: a session file whose `sessionId` matches the
    /// caller-supplied one, so its `name` is used.
    #[test]
    fn claude_code_session_label_reads_name_on_matching_session_id() {
        let home = temp_home("match");
        write_claude_session_file(
            &home,
            "44930",
            r#"{"pid":44930,"sessionId":"abc-123","name":"oshioki-1b","nameSource":"derived"}"#,
        );
        assert_eq!(
            claude_code_session_label_at(&home, "44930", Some("abc-123")),
            Some("oshioki-1b".into())
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// A session id mismatch (a stale file at a reused pid) yields no
    /// label rather than an incorrect one.
    #[test]
    fn claude_code_session_label_rejects_session_id_mismatch() {
        let home = temp_home("mismatch");
        write_claude_session_file(
            &home,
            "44930",
            r#"{"pid":44930,"sessionId":"abc-123","name":"oshioki-1b"}"#,
        );
        assert_eq!(
            claude_code_session_label_at(&home, "44930", Some("different-session")),
            None
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Without an expected session id to check, the name is trusted as-is
    /// (the `CLAUDE_CODE_SESSION_ID` env entry is optional on the wire).
    #[test]
    fn claude_code_session_label_accepts_missing_expected_id() {
        let home = temp_home("noexpected");
        write_claude_session_file(
            &home,
            "44930",
            r#"{"pid":44930,"sessionId":"abc-123","name":"oshioki-1b"}"#,
        );
        assert_eq!(
            claude_code_session_label_at(&home, "44930", None),
            Some("oshioki-1b".into())
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// No session file at all (not a Claude Code session, or the pid is
    /// stale) is not an error — just no label.
    #[test]
    fn claude_code_session_label_missing_file_yields_none() {
        let home = temp_home("missing");
        assert_eq!(
            claude_code_session_label_at(&home, "999999", Some("abc-123")),
            None
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// A name longer than the 64-character bound `RequestV1::validate`
    /// enforces is rejected here rather than truncated, so the resolver
    /// never hands the caller a clipped label under a different meaning.
    #[test]
    fn claude_code_session_label_rejects_overlong_name() {
        let home = temp_home("overlong");
        let long_name = "x".repeat(65);
        write_claude_session_file(
            &home,
            "44930",
            &format!(r#"{{"pid":44930,"sessionId":"abc-123","name":"{long_name}"}}"#),
        );
        assert_eq!(
            claude_code_session_label_at(&home, "44930", Some("abc-123")),
            None
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Malformed JSON in the session file fails silently, same as a missing
    /// file: this is a best-effort label, not a trust boundary.
    #[test]
    fn claude_code_session_label_malformed_json_yields_none() {
        let home = temp_home("malformed");
        write_claude_session_file(&home, "44930", "not json");
        assert_eq!(
            claude_code_session_label_at(&home, "44930", Some("abc-123")),
            None
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// `session_label` prefers `OSHIOKI_SESSION` over a Claude Code session
    /// file when both are present.
    #[test]
    fn session_label_prefers_oshioki_session_env_over_claude_code() {
        let values = vec![
            ("env.OSHIOKI_SESSION".into(), "explicit-session".into()),
            ("env.CLAUDE_PID".into(), "44930".into()),
        ];
        assert_eq!(
            session_label(&values, nix::unistd::getuid().as_raw()),
            Some("explicit-session".into())
        );
    }

    /// An empty `OSHIOKI_SESSION` value does not win; the resolver falls
    /// through (to nothing, here, since there is no usable `CLAUDE_PID`
    /// session file for this uid in the test environment).
    #[test]
    fn session_label_treats_empty_oshioki_session_as_absent() {
        let values = vec![("env.OSHIOKI_SESSION".into(), String::new())];
        assert_eq!(session_label(&values, nix::unistd::getuid().as_raw()), None);
    }

    /// `normalize_session_label` trims whitespace, rejects control
    /// characters, and caps length at 64 characters.
    #[test]
    fn normalize_session_label_bounds_and_trims() {
        assert_eq!(normalize_session_label("  claude  "), Some("claude".into()));
        assert_eq!(normalize_session_label(""), None);
        assert_eq!(normalize_session_label("   "), None);
        assert_eq!(normalize_session_label(&"x".repeat(64)), Some("x".repeat(64)));
        assert_eq!(normalize_session_label(&"x".repeat(65)), None);
        assert_eq!(normalize_session_label("bad\u{0007}name"), None);
    }

    /// The invoking user's `$HOME` is resolved through the passwd database
    /// by uid: the current process's own uid must resolve to some home
    /// directory. `claude_code_session_label` (unlike the `_at` helper
    /// these other tests use) goes through this exact lookup, never through
    /// this process's own `HOME` environment variable — sudo has already
    /// scrubbed it and it need not belong to the invoking user at all.
    #[test]
    fn user_home_dir_resolves_the_current_uid() {
        let real_uid = nix::unistd::getuid().as_raw();
        assert!(
            user_home_dir(real_uid).is_some(),
            "current uid must resolve a home"
        );
    }
}
