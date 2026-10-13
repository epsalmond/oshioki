//! The `nats` transport: today's call sites verbatim behind the seam. Every
//! subject string and payload byte is identical to what hook and server sent
//! before the seam existed; only the connect helpers and the four hook
//! operations changed ownership, not behavior.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use async_nats::jetstream::{
    self, AckKind,
    consumer::{self, AckPolicy, pull},
    stream,
};
use futures::StreamExt as _;
use oshioki_protocol::{
    ALLOW_PLAINTEXT_NATS_ENV, ActivationV1, ControlMessageOutcome, ControlMessageV1, DecisionV1,
    EnrollmentIntentV1, EnrollmentSubmissionV1, TOOL_APPROVAL_SUBJECT, ToolAcknowledgementV1,
    ToolApprovalDecisionV1, ToolDeliveryV1, allow_plaintext_nats, auth_v1::AuthDecisionV1,
    check_nats_url, nats_url_is_tls,
};
use tracing::{debug, info};

use crate::{
    Ack, AckFuture, BoxFuture, DecisionStream, HookProgress, HookTransport, HookTransportFailure,
    InboundMessage, InboundStream, JetStreamMessage, RequestStream, ServerTransport,
};

const DAEMON_ACK_TIMEOUT: Duration = Duration::from_secs(3);

/// Which liveness receipt a message is being read as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceiptPosition {
    /// `AliveV1` on `oshioki.ack.<id>`.
    Alive,
    /// `DeliveryV1` on `oshioki.delivery.<id>`.
    Delivery,
}

/// True only when `bytes` decode as the receipt `position` expects and that
/// receipt names `request_id`. Anything else -- a kind this build does not
/// recognize (issue #66), bytes that do not decode, a receipt for another
/// request, or a different message kind -- is not this request's receipt and
/// the wait skips it.
fn receipt_matches(bytes: &[u8], request_id: &str, position: ReceiptPosition) -> bool {
    match (oshioki_protocol::decode_control_message(bytes), position) {
        (
            Ok(ControlMessageOutcome::Message(ControlMessageV1::Alive(alive))),
            ReceiptPosition::Alive,
        ) => alive.validate(request_id).is_ok(),
        (
            Ok(ControlMessageOutcome::Message(ControlMessageV1::Delivery(delivery))),
            ReceiptPosition::Delivery,
        ) => delivery.validate(request_id).is_ok(),
        _ => false,
    }
}

/// The command decision `bytes` carry for `request_id`, or `None` when the
/// message is anything else. Shape and signature checks stay in the hook.
fn command_decision_for(bytes: &[u8], request_id: &str) -> Option<DecisionV1> {
    let Ok(ControlMessageOutcome::Message(ControlMessageV1::Decision(decision))) =
        oshioki_protocol::decode_control_message(bytes)
    else {
        return None;
    };
    let named = match &decision {
        DecisionV1::Approve(approval) => &approval.request_id,
        DecisionV1::ApproveNative(approval) => &approval.request_id,
        DecisionV1::Deny(denial) => &denial.request_id,
    };
    (named == request_id).then_some(decision)
}

/// The authentication decision `bytes` carry for `request_id`, or `None`.
fn auth_decision_for(bytes: &[u8], request_id: &str) -> Option<AuthDecisionV1> {
    let Ok(ControlMessageOutcome::Message(ControlMessageV1::AuthDecision(decision))) =
        oshioki_protocol::decode_control_message(bytes)
    else {
        return None;
    };
    let named = match &decision {
        AuthDecisionV1::AuthenticateNative(approval) => &approval.request_id,
        AuthDecisionV1::AuthenticateWebauthn(approval) => &approval.request_id,
    };
    (named == request_id).then_some(decision)
}

#[allow(clippy::needless_pass_by_value)]
fn failure(kind: FailureKind, error: &anyhow::Error) -> anyhow::Error {
    let detail = format!("{error:#}");
    let error = match kind {
        FailureKind::Transport => HookTransportFailure::Transport(detail),
        FailureKind::Daemon => HookTransportFailure::Daemon(detail),
        FailureKind::Expired => HookTransportFailure::Expired(detail),
        FailureKind::Protocol => HookTransportFailure::Protocol(detail),
    };
    anyhow::Error::new(error)
}

enum FailureKind {
    Transport,
    Daemon,
    Expired,
    /// A message arrived and did not decode as the control message this
    /// point in the exchange expects. See [`HookTransportFailure::Protocol`].
    Protocol,
}

pub const REQUEST_STREAM: &str = "OSHIOKI";
pub const REQUEST_CONSUMER: &str = "oshioki-server-v1";
/// The durable consumer's subject filters. Command approval keeps its own
/// filter unchanged; contextual sudo authentication rides a separate subject
/// tree so the two lanes stay distinguishable on the wire.
///
/// Multiple filters need NATS 2.10 or newer, and the stream itself must carry
/// both subject trees. The server widens an existing stream and recreates the
/// durable when it starts; `RUNBOOK.md` is the recovery path if that repair
/// fails.
pub const REQUEST_CONSUMER_FILTERS: [&str; 3] =
    ["oshioki.request.>", "oshioki.auth.>", TOOL_APPROVAL_SUBJECT];

const CONSUMER_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// True when `existing` already captures every message `required` would.
/// `oshioki.>` covers `oshioki.request.>` and `oshioki.auth.>`; a lone
/// `oshioki.request.>` does not cover the authentication lane.
pub(crate) fn subject_covers(existing: &str, required: &str) -> bool {
    token_covers(&split_subject(existing), &split_subject(required))
}

fn split_subject(subject: &str) -> Vec<&str> {
    if subject.is_empty() {
        Vec::new()
    } else {
        subject.split('.').collect()
    }
}

fn token_covers(existing: &[&str], required: &[&str]) -> bool {
    let Some((have, rest_have)) = existing.split_first() else {
        return required.is_empty();
    };
    let Some((need, rest_need)) = required.split_first() else {
        return false;
    };
    if *have == ">" {
        return true;
    }
    if *have == "*" {
        return *need != ">" && token_covers(rest_have, rest_need);
    }
    if *need == "*" || *need == ">" {
        return false;
    }
    have == need && token_covers(rest_have, rest_need)
}

/// True when `existing` already includes every required subject, including
/// by a broader NATS wildcard.
pub(crate) fn subjects_cover(existing: &[String], required: &[&str]) -> bool {
    required
        .iter()
        .all(|need| existing.iter().any(|have| subject_covers(have, need)))
}

/// Existing subjects first, then any required subject that no existing
/// pattern already covers. Does not add a narrower subject that would
/// overlap a covering wildcard (`oshioki.>` plus `oshioki.request.>`).
pub(crate) fn merge_subjects(existing: &[String], required: &[&str]) -> Vec<String> {
    let mut subjects = existing.to_vec();
    for need in required {
        if !subjects.iter().any(|have| subject_covers(have, need)) {
            subjects.push((*need).to_owned());
        }
    }
    subjects
}

/// Durable filters as a list: `filter_subjects` wins when set, otherwise the
/// legacy single `filter_subject`.
pub(crate) fn consumer_filter_list(
    filter_subject: &str,
    filter_subjects: &[String],
) -> Vec<String> {
    if !filter_subjects.is_empty() {
        filter_subjects.to_vec()
    } else if !filter_subject.is_empty() {
        vec![filter_subject.to_owned()]
    } else {
        Vec::new()
    }
}

pub(crate) fn filters_match(active: &[String], required: &[&str]) -> bool {
    let mut left: Vec<&str> = active.iter().map(String::as_str).collect();
    let mut right = required.to_vec();
    left.sort_unstable();
    right.sort_unstable();
    left == right
}

fn pull_consumer_config() -> pull::Config {
    pull::Config {
        durable_name: Some(REQUEST_CONSUMER.into()),
        filter_subjects: REQUEST_CONSUMER_FILTERS
            .iter()
            .map(|subject| (*subject).to_owned())
            .collect(),
        ack_policy: AckPolicy::Explicit,
        ..Default::default()
    }
}

async fn ensure_request_stream(jetstream: &jetstream::Context) -> Result<stream::Stream> {
    let stream = jetstream
        .get_stream(REQUEST_STREAM)
        .await
        .context("open request stream")?;
    let current = stream.cached_info().config.clone();
    if subjects_cover(&current.subjects, &REQUEST_CONSUMER_FILTERS) {
        return Ok(stream);
    }
    let mut updated = current.clone();
    updated.subjects = merge_subjects(&current.subjects, &REQUEST_CONSUMER_FILTERS);
    info!(
        stream = REQUEST_STREAM,
        from = %current.subjects.join(","),
        to = %updated.subjects.join(","),
        "widening OSHIOKI stream subjects for the authentication lane"
    );
    jetstream
        .update_stream(updated)
        .await
        .context("widen OSHIOKI stream subjects for the authentication lane")?;
    let stream = jetstream
        .get_stream(REQUEST_STREAM)
        .await
        .context("re-open request stream after subject update")?;
    if !subjects_cover(
        &stream.cached_info().config.subjects,
        &REQUEST_CONSUMER_FILTERS,
    ) {
        bail!("OSHIOKI stream subjects still missing the authentication lane after update");
    }
    Ok(stream)
}

async fn drain_consumer(stream: &stream::Stream, name: &str) -> Result<(u64, usize)> {
    let deadline = tokio::time::Instant::now() + CONSUMER_DRAIN_TIMEOUT;
    loop {
        let info = stream
            .consumer_info(name)
            .await
            .context("read durable consumer pending counts")?;
        if info.num_pending == 0 && info.num_ack_pending == 0 {
            return Ok((0, 0));
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok((info.num_pending, info.num_ack_pending));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn ensure_request_consumer(
    stream: &stream::Stream,
) -> Result<consumer::Consumer<pull::Config>> {
    let consumer = stream
        .get_or_create_consumer(REQUEST_CONSUMER, pull_consumer_config())
        .await
        .context("open durable request consumer")?;
    let configured = &consumer.cached_info().config;
    let active = consumer_filter_list(&configured.filter_subject, &configured.filter_subjects);
    if filters_match(&active, &REQUEST_CONSUMER_FILTERS) {
        return Ok(consumer);
    }
    let (pending, ack_pending) = drain_consumer(stream, REQUEST_CONSUMER).await?;
    info!(
        consumer = REQUEST_CONSUMER,
        stream = REQUEST_STREAM,
        active_filters = %active.join(","),
        expected_filters = %REQUEST_CONSUMER_FILTERS.join(","),
        num_pending = pending,
        num_ack_pending = ack_pending,
        "recreating durable consumer so the authentication lane is delivered"
    );
    drop(consumer);
    stream
        .delete_consumer(REQUEST_CONSUMER)
        .await
        .context("delete durable request consumer with stale filters")?;
    let consumer = stream
        .create_consumer(pull_consumer_config())
        .await
        .context("recreate durable request consumer")?;
    let configured = &consumer.cached_info().config;
    let active = consumer_filter_list(&configured.filter_subject, &configured.filter_subjects);
    if !filters_match(&active, &REQUEST_CONSUMER_FILTERS) {
        bail!(
            "durable consumer {REQUEST_CONSUMER} filters are {} after recreate; expected {}",
            active.join(","),
            REQUEST_CONSUMER_FILTERS.join(",")
        );
    }
    Ok(consumer)
}
pub struct NatsTransport {
    client: async_nats::Client,
}

impl NatsTransport {
    pub fn from_client(client: async_nats::Client) -> Self {
        Self { client }
    }

    /// Hook role: configuration comes from `<directory>/config.env`. Sudo
    /// scrubs the hook's environment, so this file is the hook's only
    /// channel, never the process environment.
    pub async fn from_config_dir(directory: &Path) -> Result<Self> {
        let env = read_env_file(&directory.join("config.env"))?;
        let url = env.get("NATS_URL").context("NATS_URL not set")?.clone();
        check_nats_url(
            &url,
            allow_plaintext_nats(env.get(ALLOW_PLAINTEXT_NATS_ENV).map(String::as_str)),
        )
        .context("invalid NATS_URL")?;
        // A tls:// URL must stay TLS past the first server: the cluster
        // advertises more addresses on reconnect as bare host:port, which
        // parse as plaintext, so the options flag carries the requirement
        // with them.
        // Credentials are both-or-neither: a user without a password (or the
        // reverse) is a misconfiguration, while neither means the server
        // takes none. Empty values count as unset.
        let user = env
            .get("NATS_USER")
            .filter(|value| !value.is_empty())
            .cloned();
        let pass = env
            .get("NATS_PASS")
            .filter(|value| !value.is_empty())
            .cloned();
        let mut options = match (user, pass) {
            (Some(user), Some(pass)) => {
                async_nats::ConnectOptions::new().user_and_password(user, pass)
            }
            (None, None) => async_nats::ConnectOptions::new(),
            _ => anyhow::bail!(
                "config.env sets exactly one of NATS_USER and NATS_PASS; set both or neither"
            ),
        };
        if nats_url_is_tls(&url) {
            options = options.require_tls(true);
        }
        options
            .connect(url)
            .await
            .context("connect to NATS")
            .map(Self::from_client)
    }

    /// Server role: configuration comes from the process environment.
    pub async fn from_env() -> Result<Self> {
        let url = required_env("NATS_URL")?;
        check_nats_url(
            &url,
            allow_plaintext_nats(std::env::var(ALLOW_PLAINTEXT_NATS_ENV).ok().as_deref()),
        )
        .context("invalid NATS_URL")?;
        // Same both-or-neither credential contract as the hook.
        let user = std::env::var("NATS_USER")
            .ok()
            .filter(|value| !value.is_empty());
        let pass = std::env::var("NATS_PASS")
            .ok()
            .filter(|value| !value.is_empty());
        let mut options = match (user, pass) {
            (Some(user), Some(pass)) => {
                async_nats::ConnectOptions::new().user_and_password(user, pass)
            }
            (None, None) => async_nats::ConnectOptions::new(),
            _ => anyhow::bail!("set NATS_USER and NATS_PASS together or neither"),
        };
        if nats_url_is_tls(&url) {
            options = options.require_tls(true);
        }
        options
            .connect(url)
            .await
            .context("connect to NATS")
            .map(Self::from_client)
    }
}

fn read_env_file(path: &Path) -> Result<HashMap<String, String>> {
    let content = std::fs::read_to_string(path)?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect())
}

fn required_env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} not set"))
}

impl NatsTransport {
    /// The shared request/verdict round trip both hook lanes use. The caller
    /// picks the request subject and how a verdict payload is recognized;
    /// every subscription, receipt, and deadline rule below is identical for
    /// command approval and contextual authentication.
    ///
    /// Every reply subject here (`oshioki.ack.<id>`, `oshioki.delivery.<id>`,
    /// `oshioki.verdict.<id>`) is writable by more than the one peer that is
    /// supposed to answer, and request IDs travel in the clear on the request
    /// subject. So nothing that arrives on them is allowed to end the wait by
    /// being malformed: a message that does not decode as the expected kind
    /// for this request ID is skipped, exactly like a kind this build does not
    /// recognize (issue #66). Only the deadline or a closed subscription ends
    /// a wait without a receipt or decision.
    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    fn request_verdicts<T: Send + 'static>(
        &self,
        request_subject: String,
        request_id: &str,
        payload: Vec<u8>,
        timeout: Duration,
        has_browser_recipient: bool,
        progress: std::sync::Arc<dyn Fn(HookProgress) + Send + Sync>,
        accept: fn(&[u8], &str) -> Option<T>,
    ) -> BoxFuture<'_, DecisionStream<T>> {
        let request_id = request_id.to_owned();
        let ack_subject = format!("oshioki.ack.{request_id}");
        let decision_subject = format!("oshioki.verdict.{request_id}");
        Box::pin(async move {
            let started = tokio::time::Instant::now();
            let setup_timeout = timeout.min(DAEMON_ACK_TIMEOUT);
            let mut stage = "subscribing to decision";
            // Connection setup and request publication have a short bound. A
            // browser-capable request then waits for either the server's
            // durable delivery receipt or a native/browser AliveV1. A
            // native-only request keeps the strict three-second AliveV1
            // requirement.
            let setup = tokio::time::timeout(setup_timeout, async {
                let subscription = self
                    .client
                    .subscribe(decision_subject)
                    .await
                    .context("subscribe decision")?;
                let acknowledgements = self
                    .client
                    .subscribe(ack_subject)
                    .await
                    .context("subscribe daemon acknowledgement")?;
                let deliveries = if has_browser_recipient {
                    Some(
                        self.client
                            .subscribe(format!("oshioki.delivery.{request_id}"))
                            .await
                            .context("subscribe server delivery receipt")?,
                    )
                } else {
                    None
                };
                stage = "confirming decision subscription readiness";
                self.client
                    .flush()
                    .await
                    .context("flush decision subscription")?;
                stage = "publishing approval request";
                self.client
                    .publish(request_subject, payload.into())
                    .await
                    .context("publish request")?;
                self.client
                    .flush()
                    .await
                    .context("flush approval request")?;
                Ok::<_, anyhow::Error>((subscription, acknowledgements, deliveries))
            })
            .await;
            let (subscription, mut acknowledgements, mut deliveries) = match setup {
                Ok(Ok(streams)) => streams,
                Ok(Err(error)) => {
                    let detail = format!("{error:#}");
                    let typed = error.chain().any(|cause| {
                        cause
                            .downcast_ref::<HookTransportFailure>()
                            .is_some_and(|failure| {
                                matches!(
                                    failure,
                                    HookTransportFailure::Transport(_)
                                        | HookTransportFailure::Daemon(_)
                                )
                            })
                    });
                    if error.chain().any(|cause| {
                        cause
                            .downcast_ref::<HookTransportFailure>()
                            .is_some_and(|failure| {
                                matches!(failure, HookTransportFailure::Daemon(_))
                            })
                    }) {
                        progress(HookProgress::DaemonNotResponding(detail));
                    } else {
                        progress(HookProgress::TransportFailed(detail));
                    }
                    return Err(if typed {
                        error
                    } else {
                        failure(FailureKind::Transport, &error)
                    });
                }
                Err(_) => {
                    let detail = anyhow::anyhow!(
                        "sudo transport deadline exceeded after {}ms while {stage}",
                        setup_timeout.as_millis()
                    );
                    let error = failure(FailureKind::Transport, &detail);
                    progress(HookProgress::TransportFailed(format!("{error:#}")));
                    return Err(error);
                }
            };
            stage = "waiting for daemon or server delivery receipt";
            let receipt_wait = timeout
                .checked_sub(started.elapsed())
                .unwrap_or(Duration::ZERO)
                .min(DAEMON_ACK_TIMEOUT);
            if receipt_wait.is_zero() {
                let detail = anyhow::anyhow!("sudo decision deadline exceeded while {stage}");
                let error = failure(FailureKind::Daemon, &detail);
                progress(HookProgress::DaemonNotResponding(format!("{error:#}")));
                return Err(error);
            }
            // Anything on either subject that is not this request's receipt
            // -- an unrecognized kind, bytes that do not decode, a receipt for
            // another request, or a different message kind -- is skipped and
            // the race reads on. The `tokio::time::timeout` bounds the whole
            // loop, so a flood of skipped messages still ends at the short
            // receipt deadline, which is a daemon outage, not a denial.
            let receipt = tokio::time::timeout(receipt_wait, async {
                loop {
                    let (position, bytes) = if let Some(deliveries) = deliveries.as_mut() {
                        tokio::select! {
                            message = acknowledgements.next() => message
                                .map(|message| (ReceiptPosition::Alive, message.payload))
                                .ok_or_else(|| anyhow::anyhow!("daemon acknowledgement stream closed")),
                            message = deliveries.next() => message
                                .map(|message| (ReceiptPosition::Delivery, message.payload))
                                .ok_or_else(|| anyhow::anyhow!("server delivery receipt stream closed")),
                        }
                    } else {
                        acknowledgements
                            .next()
                            .await
                            .map(|message| (ReceiptPosition::Alive, message.payload))
                            .ok_or_else(|| anyhow::anyhow!("daemon acknowledgement stream closed"))
                    }?;
                    if receipt_matches(&bytes, &request_id, position) {
                        return Ok::<_, anyhow::Error>(position);
                    }
                    debug!(request_id = %request_id, "skipping a message that is not this request's receipt");
                }
            })
            .await;
            let receipt = match receipt {
                Ok(Ok(receipt)) => receipt,
                Ok(Err(detail)) => {
                    let error = failure(FailureKind::Daemon, &detail);
                    progress(HookProgress::DaemonNotResponding(format!("{error:#}")));
                    return Err(error);
                }
                Err(_) => {
                    let detail = if has_browser_recipient {
                        anyhow::anyhow!(
                            "daemon or server delivery receipt timeout after {}ms; upgrade oshioki-server before using browser approvals if it predates DeliveryV1",
                            receipt_wait.as_millis()
                        )
                    } else {
                        anyhow::anyhow!(
                            "daemon acknowledgement timeout after {}ms",
                            receipt_wait.as_millis()
                        )
                    };
                    let error = failure(FailureKind::Daemon, &detail);
                    progress(HookProgress::DaemonNotResponding(format!("{error:#}")));
                    return Err(error);
                }
            };
            match receipt {
                ReceiptPosition::Alive => progress(HookProgress::WaitingForApproval),
                ReceiptPosition::Delivery => {
                    progress(HookProgress::RequestDelivered);
                    stage = "waiting for browser or daemon acknowledgement";
                    let remaining = timeout
                        .checked_sub(started.elapsed())
                        .unwrap_or(Duration::ZERO);
                    if remaining.is_zero() {
                        let detail =
                            anyhow::anyhow!("sudo decision deadline exceeded while {stage}");
                        return Err(failure(FailureKind::Expired, &detail));
                    }
                    let acknowledged = tokio::time::timeout(remaining, async {
                        loop {
                            let message = acknowledgements.next().await.ok_or_else(|| {
                                anyhow::anyhow!("daemon acknowledgement stream closed")
                            })?;
                            if receipt_matches(&message.payload, &request_id, ReceiptPosition::Alive)
                            {
                                return Ok::<_, anyhow::Error>(());
                            }
                            debug!(request_id = %request_id, "skipping a message that is not this request's acknowledgement");
                        }
                    })
                    .await;
                    match acknowledged {
                        Ok(Ok(())) => progress(HookProgress::WaitingForApproval),
                        Ok(Err(detail)) => return Err(failure(FailureKind::Expired, &detail)),
                        Err(_) => {
                            let detail =
                                anyhow::anyhow!("sudo decision deadline exceeded while {stage}");
                            return Err(failure(FailureKind::Expired, &detail));
                        }
                    }
                }
            }
            let deadline = started + timeout;
            if deadline <= tokio::time::Instant::now() {
                let detail = anyhow::anyhow!(
                    "sudo decision deadline exceeded after {}ms while waiting for decision",
                    timeout.as_millis()
                );
                return Err(failure(FailureKind::Expired, &detail));
            }
            let wait = VerdictWait {
                subscription,
                request_id,
                accept,
                deadline,
                timeout,
                finished: false,
            };
            Ok(Box::pin(futures::stream::unfold(wait, next_verdict)) as DecisionStream<T>)
        })
    }
}

/// The decision subscription for one request, read lazily by the hook.
struct VerdictWait<T> {
    subscription: async_nats::Subscriber,
    request_id: String,
    accept: fn(&[u8], &str) -> Option<T>,
    deadline: tokio::time::Instant,
    timeout: Duration,
    finished: bool,
}

/// Reads the next message on the decision subject that `accept` recognizes
/// for this request, skipping everything else until the deadline. Ends the
/// stream after one terminal error.
async fn next_verdict<T>(mut wait: VerdictWait<T>) -> Option<(Result<T>, VerdictWait<T>)> {
    if wait.finished {
        return None;
    }
    loop {
        let message = match tokio::time::timeout_at(wait.deadline, wait.subscription.next()).await {
            Ok(Some(message)) => message,
            Ok(None) => {
                wait.finished = true;
                let error = failure(
                    FailureKind::Daemon,
                    &anyhow::anyhow!("decision stream closed"),
                );
                return Some((Err(error), wait));
            }
            Err(_) => {
                wait.finished = true;
                let detail = anyhow::anyhow!(
                    "sudo decision deadline exceeded after {}ms while waiting for decision",
                    wait.timeout.as_millis()
                );
                return Some((Err(failure(FailureKind::Expired, &detail)), wait));
            }
        };
        if let Some(decision) = (wait.accept)(&message.payload, &wait.request_id) {
            return Some((Ok(decision), wait));
        }
        debug!(request_id = %wait.request_id, "skipping a message that is not a decision for this request");
    }
}

impl HookTransport for NatsTransport {
    fn request_decision(
        &self,
        host: &str,
        request_id: &str,
        payload: Vec<u8>,
        timeout: Duration,
        has_browser_recipient: bool,
        progress: std::sync::Arc<dyn Fn(HookProgress) + Send + Sync>,
    ) -> BoxFuture<'_, DecisionStream<DecisionV1>> {
        self.request_verdicts(
            format!("oshioki.request.{host}"),
            request_id,
            payload,
            timeout,
            has_browser_recipient,
            progress,
            command_decision_for,
        )
    }

    fn request_authentication(
        &self,
        host: &str,
        request_id: &str,
        payload: Vec<u8>,
        timeout: Duration,
        has_browser_recipient: bool,
        progress: std::sync::Arc<dyn Fn(HookProgress) + Send + Sync>,
    ) -> BoxFuture<'_, DecisionStream<AuthDecisionV1>> {
        self.request_verdicts(
            format!("oshioki.auth.{host}"),
            request_id,
            payload,
            timeout,
            has_browser_recipient,
            progress,
            auth_decision_for,
        )
    }

    fn request_tool_approval(
        &self,
        request_id: &str,
        payload: Vec<u8>,
        timeout: Duration,
        progress: std::sync::Arc<dyn Fn(HookProgress) + Send + Sync>,
    ) -> BoxFuture<'_, ToolApprovalDecisionV1> {
        let request_id = request_id.to_owned();
        let delivery_subject = format!("oshioki.tool.delivery.{request_id}");
        let acknowledgement_subject = format!("oshioki.tool.ack.{request_id}");
        let verdict_subject = format!("oshioki.tool.verdict.{request_id}");
        Box::pin(async move {
            let request_id_for_wait = request_id.clone();
            let result = tokio::time::timeout(timeout, async {
                // Subscribe and flush every response subject before sending
                // the request. Otherwise a fast phone can answer before the
                // requester is listening.
                let mut deliveries = self.client.subscribe(delivery_subject).await?;
                let mut acknowledgements = self.client.subscribe(acknowledgement_subject).await?;
                let mut verdicts = self.client.subscribe(verdict_subject).await?;
                self.client.flush().await?;
                self.client
                    .publish(TOOL_APPROVAL_SUBJECT, payload.into())
                    .await?;
                self.client.flush().await?;

                let delivery = deliveries
                    .next()
                    .await
                    .context("tool approval delivery stream closed")?;
                let delivery: ToolDeliveryV1 = serde_json::from_slice(&delivery.payload)
                    .context("decode tool approval delivery")?;
                delivery
                    .validate(&request_id_for_wait)
                    .context("tool approval delivery did not match request")?;
                progress(HookProgress::RequestDelivered);

                let acknowledgement = acknowledgements
                    .next()
                    .await
                    .context("tool browser acknowledgement stream closed")?;
                let acknowledgement: ToolAcknowledgementV1 =
                    serde_json::from_slice(&acknowledgement.payload)
                        .context("decode tool browser acknowledgement")?;
                acknowledgement
                    .validate(&request_id_for_wait)
                    .context("tool browser acknowledgement did not match request")?;
                progress(HookProgress::WaitingForApproval);

                let verdict = verdicts
                    .next()
                    .await
                    .context("tool decision stream closed")?;
                let verdict: ToolApprovalDecisionV1 = serde_json::from_slice(&verdict.payload)
                    .context("decode tool approval decision")?;
                if verdict.request_id() != request_id_for_wait {
                    anyhow::bail!("tool approval decision did not match request");
                }
                verdict
                    .validate_shape()
                    .context("validate tool approval decision")?;
                Ok::<_, anyhow::Error>(verdict)
            })
            .await;
            match result {
                Ok(Ok(decision)) => Ok(decision),
                Ok(Err(error)) => {
                    let detail = format!("{error:#}");
                    progress(HookProgress::ProtocolFailed(detail));
                    Err(failure(FailureKind::Protocol, &error))
                }
                Err(_) => {
                    let detail = anyhow::anyhow!(
                        "tool approval deadline exceeded after {}ms",
                        timeout.as_millis()
                    );
                    progress(HookProgress::DaemonNotResponding(format!("{detail:#}")));
                    Err(failure(FailureKind::Expired, &detail))
                }
            }
        })
    }

    fn publish_enrollment_intent(
        &self,
        intent: &EnrollmentIntentV1,
    ) -> BoxFuture<'_, InboundStream> {
        let reply_subject = intent.reply_subject.clone();
        let payload = serde_json::to_vec(intent);
        Box::pin(async move {
            let subscription = self
                .client
                .subscribe(reply_subject)
                .await
                .context("subscribe enrollment submission")?;
            self.client
                .flush()
                .await
                .context("flush enrollment subscription")?;
            self.client
                .publish("oshioki.enrollment.intent", payload?.into())
                .await?;
            self.client.flush().await?;
            Ok(Box::pin(subscription.map(|message| InboundMessage {
                subject: message.subject.to_string(),
                payload: message.payload.to_vec(),
            })) as InboundStream)
        })
    }

    fn await_submission(
        &self,
        enrollment_id: &str,
        mut reply_stream: InboundStream,
        submission_deadline: tokio::time::Instant,
    ) -> BoxFuture<'_, EnrollmentSubmissionV1> {
        let enrollment_id = enrollment_id.to_owned();
        Box::pin(async move {
            let wait = submission_deadline
                .checked_duration_since(tokio::time::Instant::now())
                .unwrap_or(Duration::ZERO);
            let message = tokio::time::timeout(wait, reply_stream.next())
                .await
                .context("enrollment timeout")?
                .context("enrollment stream closed")?;
            let submission: EnrollmentSubmissionV1 =
                serde_json::from_slice(&message.payload).context("decode enrollment submission")?;
            if submission.enrollment_id() != enrollment_id {
                anyhow::bail!("enrollment id mismatch");
            }
            Ok(submission)
        })
    }

    fn publish_activation(&self, activation: &ActivationV1) -> BoxFuture<'_, ()> {
        let result = serde_json::to_vec(activation).map(|payload| {
            (
                format!("oshioki.enrollment.activation.{}", activation.enrollment_id),
                payload,
            )
        });
        Box::pin(async move {
            let (subject, payload) = result?;
            self.client.publish(subject, payload.into()).await?;
            self.client.flush().await?;
            Ok(())
        })
    }

    fn revoke(&self, fingerprint: &str) -> BoxFuture<'_, ()> {
        let fingerprint = fingerprint.to_owned();
        Box::pin(async move {
            let confirmation_subject = format!("oshioki.device.revoked.{fingerprint}");
            let mut confirmation = self.client.subscribe(confirmation_subject).await?;
            self.client.flush().await?;
            self.client
                .publish(
                    format!("oshioki.device.revoke.{fingerprint}"),
                    Vec::new().into(),
                )
                .await?;
            self.client.flush().await?;
            tokio::time::timeout(Duration::from_secs(15), confirmation.next())
                .await
                .context("server revocation confirmation timeout")?
                .context("server revocation confirmation stream closed")?;
            Ok(())
        })
    }

    fn watch_requests(&self) -> BoxFuture<'_, InboundStream> {
        Box::pin(async move {
            let subscriber = self.client.subscribe("oshioki.request.>").await?;
            Ok(Box::pin(subscriber.map(|message| InboundMessage {
                subject: message.subject.to_string(),
                payload: message.payload.to_vec(),
            })) as InboundStream)
        })
    }
}

impl ServerTransport for NatsTransport {
    fn requests(&self) -> BoxFuture<'_, RequestStream> {
        Box::pin(async move {
            let jetstream = jetstream::new(self.client.clone());
            let stream = ensure_request_stream(&jetstream).await?;
            let consumer = ensure_request_consumer(&stream).await?;
            let messages = consumer.messages().await?;
            Ok(Box::pin(messages.map(|result| {
                result
                    .map(|message| {
                        // Payload out first, then the handle moves into one
                        // closure: the consumer names the acknowledgement it
                        // wants and only that future is ever built.
                        let subject = message.subject.to_string();
                        let payload = message.payload.to_vec();
                        vec![JetStreamMessage {
                            subject,
                            payload,
                            ack: Box::new(move |kind| match kind {
                                Ack::Term => Box::pin(async move {
                                    message
                                        .ack_with(AckKind::Term)
                                        .await
                                        .map_err(|error| anyhow::anyhow!(error.to_string()))
                                }) as AckFuture,
                                Ack::Ok => Box::pin(async move {
                                    message
                                        .double_ack()
                                        .await
                                        .map_err(|error| anyhow::anyhow!(error.to_string()))
                                }) as AckFuture,
                            }),
                        }]
                    })
                    .map_err(Into::into)
            })) as RequestStream)
        })
    }

    fn subscribe(&self, subject: &str) -> BoxFuture<'_, InboundStream> {
        let subject = subject.to_owned();
        Box::pin(async move {
            let subscriber = self.client.subscribe(subject).await?;
            Ok(Box::pin(subscriber.map(|message| InboundMessage {
                subject: message.subject.to_string(),
                payload: message.payload.to_vec(),
            })) as InboundStream)
        })
    }

    fn publish(&self, subject: String, payload: Vec<u8>) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.client.publish(subject, payload.into()).await?;
            self.client.flush().await?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deny(request_id: &str) -> DecisionV1 {
        DecisionV1::Deny(oshioki_protocol::DenyV1 {
            version: oshioki_protocol::VERSION_V1,
            request_id: request_id.into(),
            device_fingerprint: "fp".into(),
            signature: None,
        })
    }

    fn auth_decision(request_id: &str) -> AuthDecisionV1 {
        AuthDecisionV1::AuthenticateNative(oshioki_protocol::auth_v1::AuthApproveNativeV1 {
            version: oshioki_protocol::auth_v1::AUTH_WIRE_VERSION,
            request_id: request_id.into(),
            device_fingerprint: "fp".into(),
            signature: "c2ln".into(),
        })
    }

    /// The receipt race returns only this request's receipt of the kind its
    /// subject carries. A future kind (issue #66), garbage, a receipt for
    /// another request, and a valid message of another kind are all skipped:
    /// any publisher on the subject could send them.
    #[test]
    fn only_this_requests_receipt_ends_the_receipt_wait() {
        let alive = serde_json::to_vec(&oshioki_protocol::AliveV1::for_request("req-1")).unwrap();
        let delivery =
            serde_json::to_vec(&oshioki_protocol::DeliveryV1::for_request("req-1")).unwrap();
        assert!(receipt_matches(&alive, "req-1", ReceiptPosition::Alive));
        assert!(receipt_matches(
            &delivery,
            "req-1",
            ReceiptPosition::Delivery
        ));
        let other_alive =
            serde_json::to_vec(&oshioki_protocol::AliveV1::for_request("req-2")).unwrap();
        let other_delivery =
            serde_json::to_vec(&oshioki_protocol::DeliveryV1::for_request("req-2")).unwrap();
        let future_kind = br#"{"type":"future_kind","version":1,"request_id":"req-1"}"#.to_vec();
        let decision = serde_json::to_vec(&deny("req-1")).unwrap();
        for position in [ReceiptPosition::Alive, ReceiptPosition::Delivery] {
            for skipped in [
                &other_alive,
                &other_delivery,
                &future_kind,
                &decision,
                &b"not json".to_vec(),
                &Vec::new(),
            ] {
                assert!(!receipt_matches(skipped, "req-1", position), "{position:?}");
            }
        }
        assert!(!receipt_matches(&delivery, "req-1", ReceiptPosition::Alive));
        assert!(!receipt_matches(&alive, "req-1", ReceiptPosition::Delivery));
    }

    /// The decision wait yields only a decoded command decision naming this
    /// request. Everything else on the verdict subject is skipped rather than
    /// returned for the hook to fail on.
    #[test]
    fn only_this_requests_command_decision_is_a_candidate() {
        let ours = serde_json::to_vec(&deny("req-1")).unwrap();
        assert_eq!(command_decision_for(&ours, "req-1"), Some(deny("req-1")));
        for skipped in [
            serde_json::to_vec(&deny("req-2")).unwrap(),
            serde_json::to_vec(&auth_decision("req-1")).unwrap(),
            serde_json::to_vec(&oshioki_protocol::AliveV1::for_request("req-1")).unwrap(),
            br#"{"type":"future_kind","version":1,"request_id":"req-1"}"#.to_vec(),
            br#"{"action":"deny","request_id":"req-1"}"#.to_vec(),
            br#"{"action":"explode","request_id":"req-1"}"#.to_vec(),
            b"not json".to_vec(),
        ] {
            assert_eq!(command_decision_for(&skipped, "req-1"), None);
        }
    }

    /// The same filter on the authentication lane: a command decision is not
    /// an authentication candidate, and neither is another request's answer.
    #[test]
    fn only_this_requests_authentication_decision_is_a_candidate() {
        let ours = serde_json::to_vec(&auth_decision("req-1")).unwrap();
        assert_eq!(
            auth_decision_for(&ours, "req-1"),
            Some(auth_decision("req-1"))
        );
        for skipped in [
            serde_json::to_vec(&auth_decision("req-2")).unwrap(),
            serde_json::to_vec(&deny("req-1")).unwrap(),
            br#"{"type":"future_kind","version":1,"request_id":"req-1"}"#.to_vec(),
            br#"{"type":"sudo_authentication_native","request_id":"req-1"}"#.to_vec(),
            b"not json".to_vec(),
        ] {
            assert_eq!(auth_decision_for(&skipped, "req-1"), None);
        }
    }

    #[test]
    fn stream_subjects_are_merged_without_dropping_existing() {
        let existing = vec!["oshioki.request.>".into(), "oshioki.other.>".into()];
        assert!(!subjects_cover(&existing, &REQUEST_CONSUMER_FILTERS));
        assert_eq!(
            merge_subjects(&existing, &REQUEST_CONSUMER_FILTERS),
            vec![
                "oshioki.request.>",
                "oshioki.other.>",
                "oshioki.auth.>",
                "oshioki.tool.request",
            ]
        );
        let already = merge_subjects(&existing, &REQUEST_CONSUMER_FILTERS);
        assert!(subjects_cover(&already, &REQUEST_CONSUMER_FILTERS));
        assert_eq!(merge_subjects(&already, &REQUEST_CONSUMER_FILTERS), already);
    }

    #[test]
    fn a_covering_wildcard_does_not_need_narrower_subjects() {
        let existing = vec!["oshioki.>".into()];
        assert!(subjects_cover(&existing, &REQUEST_CONSUMER_FILTERS));
        assert_eq!(
            merge_subjects(&existing, &REQUEST_CONSUMER_FILTERS),
            existing
        );
        assert!(subject_covers(">", "oshioki.request.>"));
        assert!(!subject_covers("oshioki.request.>", "oshioki.auth.>"));
        assert!(!subject_covers("oshioki.*", "oshioki.request.>"));
    }

    #[test]
    fn a_legacy_single_filter_does_not_match_the_authentication_lane() {
        let active = consumer_filter_list("oshioki.request.>", &[]);
        assert_eq!(active, vec!["oshioki.request.>"]);
        assert!(!filters_match(&active, &REQUEST_CONSUMER_FILTERS));
        let both = consumer_filter_list(
            "",
            &[
                "oshioki.auth.>".into(),
                "oshioki.request.>".into(),
                "oshioki.tool.request".into(),
            ],
        );
        assert!(filters_match(&both, &REQUEST_CONSUMER_FILTERS));
    }
}
