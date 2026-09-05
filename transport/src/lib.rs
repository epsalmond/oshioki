//! The seam between oshioki and how its messages travel. A transport owns
//! connections, subject selection, and delivery semantics; what travels on
//! those subjects, the v1 JSON envelopes and the sealed bodies inside them,
//! is defined by `oshioki-protocol` and is identical on every transport.
//! `OSHIOKI_TRANSPORT` selects the backend at startup; `nats` is the default
//! and the only one this crate ships today, and `mock` serves unit tests.

pub mod mock;
pub mod nats;

use std::pin::Pin;

use anyhow::Result;
use futures::Stream;

pub use mock::MockTransport;
pub use nats::NatsTransport;
use oshioki_protocol::{ActivationV1, DecisionV1, EnrollmentIntentV1, EnrollmentSubmissionV1};

/// A boxed future the traits hand back, so they stay object-safe: hook and
/// server hold `Box<dyn ...Transport>` and dynamic dispatch needs `Pin<Box>`
/// here, not `impl Future` in the method position.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// What the hook needs from a transport: one sudo decision round trip and
/// the enrollment/revocation lanes. Production hooks run exactly one of
/// these per process, so the trait is object-safe and the hook holds a
/// `Box<dyn HookTransport>`.
pub trait HookTransport: Send + Sync {
    /// Publishes the sealed request for `host` and waits up to `timeout` for
    /// one decision on `request_id`, failing when the deadline fires.
    fn request_decision(
        &self,
        host: &str,
        request_id: &str,
        payload: Vec<u8>,
        timeout: std::time::Duration,
    ) -> BoxFuture<'_, DecisionV1>;

    /// Publishes the enrollment intent, confirming server-side delivery
    /// before returning. Returns the pre-publish reply subscription so the
    /// caller can hand it to `await_submission`: dropping it here would
    /// lose the reply, so the caller owns it.
    fn publish_enrollment_intent(
        &self,
        intent: &EnrollmentIntentV1,
    ) -> BoxFuture<'_, InboundStream>;

    /// Waits for the device's submission on the reply stream opened by
    /// `publish_enrollment_intent`, bound by `submission_deadline`. Legal
    /// only on a stream that call returned: the subscription must predate
    /// the intent or the reply can race past it.
    fn await_submission(
        &self,
        enrollment_id: &str,
        reply_stream: InboundStream,
        submission_deadline: tokio::time::Instant,
    ) -> BoxFuture<'_, EnrollmentSubmissionV1>;

    /// Publishes the activation for an enrolled device.
    fn publish_activation(&self, activation: &ActivationV1) -> BoxFuture<'_, ()>;

    /// Requests revocation of `fingerprint` and waits for the server's
    /// confirmation.
    fn revoke(&self, fingerprint: &str) -> BoxFuture<'_, ()>;

    /// Streams one delivery per approval request, as `oshioki watch` prints
    /// them, until the stream is dropped. The stream yields raw request
    /// subjects so a terminal viewer can show hosts.
    fn watch_requests(&self) -> BoxFuture<'_, InboundStream>;
}

/// One inbound core pub/sub delivery with its physical subject, so handlers
/// can strip a known prefix to recover a fingerprint
/// (`oshioki.device.revoke.<fingerprint>`), as today.
pub struct InboundMessage {
    pub subject: String,
    pub payload: Vec<u8>,
}

/// The acknowledgement one message-carrying future resolves to. `Send`-boxed
/// (rather than `async fn` on a trait) so the single-use ack handles stay
/// move-safe through the store-transaction boundary.
pub type AckFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

/// Which acknowledgement a delivery resolves to: `Term` rejects the message
/// permanently so it never redelivers, `Ok` accepts it with server-side
/// confirmation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ack {
    Term,
    Ok,
}

/// Builds a delivery's one acknowledgement on demand, so only the arm the
/// consumer actually reaches is ever constructed.
pub type AckFn = Box<dyn FnOnce(Ack) -> AckFuture + Send>;

/// One durable request-stream delivery. `ack` is single-use: calling it
/// consumes the message's acknowledgement exactly once.
pub struct JetStreamMessage {
    pub payload: Vec<u8>,
    pub ack: AckFn,
}

/// What the server needs from a transport: the durable request source plus
/// plain subscribe/publish for the enrollment, verdict, and revocation lanes.
pub trait ServerTransport: Send + Sync {
    /// Opens the durable request source. The stream yields one batch per
    /// delivery; batches stay one message each, matching today's consumer.
    /// The liveness heartbeat stays in the server, not here.
    fn requests(&self) -> BoxFuture<'_, RequestStream>;

    /// Subscribes to one subject (wildcards allowed) until the stream is
    /// dropped.
    fn subscribe(&self, subject: &str) -> BoxFuture<'_, InboundStream>;

    /// Publishes one payload on `subject` and confirms server-side delivery
    /// before returning (publish then flush).
    fn publish(&self, subject: String, payload: Vec<u8>) -> BoxFuture<'_, ()>;
}

/// The durable request source `ServerTransport::requests` opens: one batch
/// per delivery, one message per batch.
pub type RequestStream = Pin<Box<dyn Stream<Item = Result<Vec<JetStreamMessage>>> + Send>>;

/// One open subscription `ServerTransport::subscribe` yields.
pub type InboundStream = Pin<Box<dyn Stream<Item = InboundMessage> + Send>>;
