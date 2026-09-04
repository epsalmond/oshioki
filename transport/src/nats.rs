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
use futures::{Stream, StreamExt as _};
use oshioki_protocol::{
    ALLOW_PLAINTEXT_NATS_ENV, ActivationV1, DecisionV1, EnrollmentIntentV1, EnrollmentSubmissionV1,
    allow_plaintext_nats, check_nats_url, nats_url_is_tls,
};

use crate::{
    AckFuture, BoxFuture, HookTransport, InboundMessage, InboundStream, JetStreamMessage,
    RequestStream, ServerTransport,
};

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
        let user = std::env::var("NATS_USER").ok().filter(|value| !value.is_empty());
        let pass = std::env::var("NATS_PASS").ok().filter(|value| !value.is_empty());
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

    /// Subscribes to the request subjects verbatim, for `oshioki watch`.
    /// Watch stays a NATS-only viewer rather than a seam operation: it
    /// decides nothing.
    pub async fn watch_requests(
        &self,
    ) -> Result<std::pin::Pin<Box<dyn Stream<Item = InboundMessage> + Send>>> {
        let subscriber = self.client.subscribe("oshioki.request.>").await?;
        Ok(Box::pin(subscriber.map(|message| InboundMessage {
            subject: message.subject.to_string(),
            payload: message.payload.to_vec(),
        })))
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
    fn request_decision(
        &self,
        host: &str,
        request_id: &str,
        payload: Vec<u8>,
        timeout: Duration,
    ) -> BoxFuture<'_, DecisionV1> {
        let request_subject = format!("oshioki.request.{host}");
        let decision_subject = format!("oshioki.verdict.{request_id}");
        Box::pin(async move {
            let mut stage = "subscribing to decision";
            tokio::time::timeout(timeout, async {
                let mut subscription = self
                    .client
                    .subscribe(decision_subject)
                    .await
                    .context("subscribe decision")?;
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
                stage = "waiting for decision";
                let message = subscription
                    .next()
                    .await
                    .context("decision stream closed")?;
                serde_json::from_slice(&message.payload).context("decode decision")
            })
            .await
            .with_context(|| {
                format!(
                    "sudo decision deadline exceeded after {}ms while {stage}",
                    timeout.as_millis()
                )
            })?
        })
    }

    fn enroll(
        &self,
        intent: &EnrollmentIntentV1,
        submission_deadline: tokio::time::Instant,
    ) -> BoxFuture<'_, EnrollmentSubmissionV1> {
        let reply_subject = intent.reply_subject.clone();
        let enrollment_id = intent.enrollment_id.clone();
        let payload = serde_json::to_vec(intent);
        Box::pin(async move {
            let mut subscription = self
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
            let wait = submission_deadline
                .checked_duration_since(tokio::time::Instant::now())
                .unwrap_or(Duration::ZERO);
            let message = tokio::time::timeout(wait, subscription.next())
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
                        // Payload out first, then the handle is shared between
                        // the two single-use ack futures: the consumer
                        // resolves exactly one.
                        let payload = message.payload.to_vec();
                        let message = std::sync::Arc::new(message);
                        let term_message = std::sync::Arc::clone(&message);
                        vec![JetStreamMessage {
                            payload,
                            term: Box::pin(async move {
                                term_message
                                    .ack_with(AckKind::Term)
                                    .await
                                    .map_err(|error| anyhow::anyhow!(error.to_string()))
                            }) as AckFuture,
                            ack: Box::pin(async move {
                                message
                                    .double_ack()
                                    .await
                                    .map_err(|error| anyhow::anyhow!(error.to_string()))
                            }) as AckFuture,
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
