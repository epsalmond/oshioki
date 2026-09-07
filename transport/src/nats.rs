//! The `nats` transport: today's call sites verbatim behind the seam. Every
//! subject string and payload byte is identical to what hook and server sent
//! before the seam existed; only the connect helpers and the four hook
//! operations changed ownership, not behavior.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, Result};
use async_nats::jetstream::{
    self, AckKind,
    consumer::{AckPolicy, pull},
};
use futures::StreamExt as _;
use oshioki_protocol::{
    ALLOW_PLAINTEXT_NATS_ENV, ActivationV1, AliveV1, DecisionV1, DeliveryV1, EnrollmentIntentV1,
    EnrollmentSubmissionV1, allow_plaintext_nats, check_nats_url, nats_url_is_tls,
};

use crate::{
    Ack, AckFuture, BoxFuture, HookProgress, HookTransport, HookTransportFailure, InboundMessage,
    InboundStream, JetStreamMessage, RequestStream, ServerTransport,
};

const DAEMON_ACK_TIMEOUT: Duration = Duration::from_secs(3);

#[allow(clippy::needless_pass_by_value)]
fn failure(kind: FailureKind, error: &anyhow::Error) -> anyhow::Error {
    let detail = format!("{error:#}");
    let error = match kind {
        FailureKind::Transport => HookTransportFailure::Transport(detail),
        FailureKind::Daemon => HookTransportFailure::Daemon(detail),
        FailureKind::Expired => HookTransportFailure::Expired(detail),
    };
    anyhow::Error::new(error)
}

enum FailureKind {
    Transport,
    Daemon,
    Expired,
}

enum InitialReceipt {
    Alive(Vec<u8>),
    Delivery(Vec<u8>),
}

pub const REQUEST_STREAM: &str = "OSHIOKI";
pub const REQUEST_CONSUMER: &str = "oshioki-server-v1";
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

impl HookTransport for NatsTransport {
    #[allow(clippy::too_many_lines)]
    fn request_decision(
        &self,
        host: &str,
        request_id: &str,
        payload: Vec<u8>,
        timeout: Duration,
        has_browser_recipient: bool,
        progress: std::sync::Arc<dyn Fn(HookProgress) + Send + Sync>,
    ) -> BoxFuture<'_, DecisionV1> {
        let request_subject = format!("oshioki.request.{host}");
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
            let (mut subscription, mut acknowledgements, mut deliveries) = match setup {
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
            let receipt = tokio::time::timeout(receipt_wait, async {
                if let Some(deliveries) = deliveries.as_mut() {
                    tokio::select! {
                        message = acknowledgements.next() => message
                            .map(|message| InitialReceipt::Alive(message.payload.to_vec()))
                            .ok_or_else(|| anyhow::anyhow!("daemon acknowledgement stream closed")),
                        message = deliveries.next() => message
                            .map(|message| InitialReceipt::Delivery(message.payload.to_vec()))
                            .ok_or_else(|| anyhow::anyhow!("server delivery receipt stream closed")),
                    }
                } else {
                    acknowledgements
                        .next()
                        .await
                        .map(|message| InitialReceipt::Alive(message.payload.to_vec()))
                        .ok_or_else(|| anyhow::anyhow!("daemon acknowledgement stream closed"))
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
                InitialReceipt::Alive(bytes) => {
                    let acknowledgement: AliveV1 = match serde_json::from_slice(&bytes)
                        .context("decode daemon acknowledgement; upgrade oshioki-agent before using this hook")
                    {
                        Ok(acknowledgement) => acknowledgement,
                        Err(error) => {
                            let detail = format!("{error:#}");
                            progress(HookProgress::ProtocolFailed(detail));
                            return Err(error);
                        }
                    };
                    if let Err(error) = acknowledgement
                        .validate(&request_id)
                        .context("invalid daemon acknowledgement; upgrade oshioki-agent before using this hook")
                    {
                        let detail = format!("{error:#}");
                        progress(HookProgress::ProtocolFailed(detail));
                        return Err(error);
                    }
                    progress(HookProgress::WaitingForApproval);
                }
                InitialReceipt::Delivery(bytes) => {
                    let delivery: DeliveryV1 = match serde_json::from_slice(&bytes)
                        .context("decode server delivery receipt; upgrade oshioki-server before using this hook")
                    {
                        Ok(delivery) => delivery,
                        Err(error) => {
                            let detail = format!("{error:#}");
                            progress(HookProgress::ProtocolFailed(detail));
                            return Err(error);
                        }
                    };
                    if let Err(error) = delivery
                        .validate(&request_id)
                        .context("invalid server delivery receipt; upgrade oshioki-server before using this hook")
                    {
                        let detail = format!("{error:#}");
                        progress(HookProgress::ProtocolFailed(detail));
                        return Err(error);
                    }
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
                    let bytes = match tokio::time::timeout(remaining, acknowledgements.next()).await
                    {
                        Ok(Some(message)) => message.payload,
                        Ok(None) => {
                            let detail = anyhow::anyhow!("daemon acknowledgement stream closed");
                            return Err(failure(FailureKind::Expired, &detail));
                        }
                        Err(_) => {
                            let detail =
                                anyhow::anyhow!("sudo decision deadline exceeded while {stage}");
                            return Err(failure(FailureKind::Expired, &detail));
                        }
                    };
                    let acknowledgement: AliveV1 = match serde_json::from_slice(&bytes)
                        .context("decode browser acknowledgement; upgrade oshioki-server before using browser approvals")
                    {
                        Ok(acknowledgement) => acknowledgement,
                        Err(error) => {
                            let detail = format!("{error:#}");
                            progress(HookProgress::ProtocolFailed(detail));
                            return Err(error);
                        }
                    };
                    if let Err(error) = acknowledgement
                        .validate(&request_id)
                        .context("invalid browser acknowledgement; upgrade oshioki-server before using browser approvals")
                    {
                        let detail = format!("{error:#}");
                        progress(HookProgress::ProtocolFailed(detail));
                        return Err(error);
                    }
                    progress(HookProgress::WaitingForApproval);
                }
            }
            let remaining = timeout
                .checked_sub(started.elapsed())
                .unwrap_or(Duration::ZERO);
            if remaining.is_zero() {
                let detail = anyhow::anyhow!(
                    "sudo decision deadline exceeded after {}ms while waiting for decision",
                    timeout.as_millis()
                );
                return Err(failure(FailureKind::Expired, &detail));
            }
            let result = tokio::time::timeout(remaining, async {
                let message = subscription.next().await.ok_or_else(|| {
                    let error = anyhow::anyhow!("decision stream closed");
                    failure(FailureKind::Daemon, &error)
                })?;
                serde_json::from_slice(&message.payload).context("decode decision")
            })
            .await;
            match result {
                Ok(Ok(decision)) => Ok(decision),
                Ok(Err(error)) => Err(error),
                Err(_) => {
                    let detail = anyhow::anyhow!(
                        "sudo decision deadline exceeded after {}ms while waiting for decision",
                        timeout.as_millis()
                    );
                    let error = failure(FailureKind::Expired, &detail);
                    Err(error)
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
            let stream = jetstream::new(self.client.clone())
                .get_stream(REQUEST_STREAM)
                .await
                .context("open request stream")?;
            let consumer = stream
                .get_or_create_consumer(
                    REQUEST_CONSUMER,
                    pull::Config {
                        durable_name: Some(REQUEST_CONSUMER.into()),
                        filter_subject: "oshioki.request.>".into(),
                        ack_policy: AckPolicy::Explicit,
                        ..Default::default()
                    },
                )
                .await
                .context("open durable request consumer")?;
            let messages = consumer.messages().await?;
            Ok(Box::pin(messages.map(|result| {
                result
                    .map(|message| {
                        // Payload out first, then the handle moves into one
                        // closure: the consumer names the acknowledgement it
                        // wants and only that future is ever built.
                        let payload = message.payload.to_vec();
                        vec![JetStreamMessage {
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
