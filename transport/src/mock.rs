//! The `mock` transport: an in-memory stand-in for unit tests. Queues what
//! hook and server operations return, records what they publish, revoke, and
//! activate, and never touches a network. Every wait fails immediately when
//! its queue is empty, so a missing queue entry fails the test fast instead
//! of hanging it.

use std::collections::VecDeque;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow};
use oshioki_protocol::{ActivationV1, DecisionV1, EnrollmentIntentV1, EnrollmentSubmissionV1};

use crate::{
    Ack, AckFuture, BoxFuture, HookTransport, InboundMessage, InboundStream, JetStreamMessage,
    RequestStream, ServerTransport,
};

/// The subject the hook's enrollment intent goes out on, mirrored from the
/// NATS transport so recordings compare against the real one.
const ENROLLMENT_INTENT_SUBJECT: &str = "oshioki.enrollment.intent";

/// Test-side stub for one `JetStream` message: payload plus a channel each
/// acknowledgement resolves, so the test observes which ack the consumer
/// reached (Term vs `DoubleAck`).
pub struct JetStreamMessageStub {
    pub payload: Vec<u8>,
    pub on_term: Option<Sender<()>>,
    pub on_ack: Option<Sender<()>>,
}

#[derive(Default)]
struct MockState {
    /// Verdicts queued by the test for `HookTransport::request_decision`.
    hook_verdicts: VecDeque<Result<DecisionV1>>,
    /// Submissions queued by the test for `publish_enrollment_intent`.
    hook_submissions: VecDeque<Result<EnrollmentSubmissionV1>>,
    /// Requests queued by the test for `ServerTransport::requests`.
    server_requests: VecDeque<JetStreamMessageStub>,
    /// Every (subject, payload) the code under test published, in order.
    published: Vec<(String, Vec<u8>)>,
    /// Every fingerprint the code under test revoked.
    revoked: Vec<String>,
    /// Every activation payload.
    activations: Vec<ActivationV1>,
}

#[derive(Clone, Default)]
pub struct MockTransport {
    state: Arc<Mutex<MockState>>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues one verdict for the next `request_decision` call.
    pub fn push_verdict(&self, decision: DecisionV1) {
        self.lock().hook_verdicts.push_back(Ok(decision));
    }

    /// Queues one submission for the next enrollment round trip.
    pub fn push_submission(&self, submission: EnrollmentSubmissionV1) {
        self.lock().hook_submissions.push_back(Ok(submission));
    }

    /// Queues one request-stream message for the next `requests` batch.
    pub fn push_request(&self, stub: JetStreamMessageStub) {
        self.lock().server_requests.push_back(stub);
    }

    /// Everything published so far, in order: subject and payload.
    pub fn published(&self) -> Vec<(String, Vec<u8>)> {
        self.lock().published.clone()
    }

    /// Every fingerprint passed to `revoke`, in order.
    pub fn revoked(&self) -> Vec<String> {
        self.lock().revoked.clone()
    }

    /// Every activation passed to `publish_activation`, in order.
    pub fn activations(&self) -> Vec<ActivationV1> {
        self.lock().activations.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MockState> {
        self.state.lock().expect("mock state poisoned")
    }
}

impl HookTransport for MockTransport {
    fn request_decision(
        &self,
        _host: &str,
        _request_id: &str,
        _payload: Vec<u8>,
        _timeout: std::time::Duration,
    ) -> BoxFuture<'_, DecisionV1> {
        let outcome = self
            .lock()
            .hook_verdicts
            .pop_front()
            .unwrap_or_else(|| Err(anyhow!("mock transport timed out: no queued verdict")));
        Box::pin(async move { outcome })
    }

    fn publish_enrollment_intent(
        &self,
        intent: &EnrollmentIntentV1,
    ) -> BoxFuture<'_, InboundStream> {
        let reply_subject = intent.reply_subject.clone();
        let encoded = serde_json::to_vec(intent);
        let queued = {
            let mut state = self.lock();
            if let Ok(payload) = &encoded {
                state
                    .published
                    .push((ENROLLMENT_INTENT_SUBJECT.to_owned(), payload.clone()));
            }
            state
                .hook_submissions
                .pop_front()
                .unwrap_or_else(|| Err(anyhow!("mock transport timed out: no queued submission")))
        };
        Box::pin(async move {
            encoded?;
            // The queued submission rides back on the reply subject, so
            // `await_submission` decodes exactly what the wire would carry.
            let payload = serde_json::to_vec(&queued?)?;
            Ok(Box::pin(futures::stream::iter([InboundMessage {
                subject: reply_subject,
                payload,
            }])) as InboundStream)
        })
    }

    fn await_submission(
        &self,
        enrollment_id: &str,
        mut reply_stream: InboundStream,
        _submission_deadline: tokio::time::Instant,
    ) -> BoxFuture<'_, EnrollmentSubmissionV1> {
        let enrollment_id = enrollment_id.to_owned();
        Box::pin(async move {
            use futures::StreamExt as _;
            let message = reply_stream
                .next()
                .await
                .ok_or_else(|| anyhow!("enrollment stream closed"))?;
            let submission: EnrollmentSubmissionV1 = serde_json::from_slice(&message.payload)?;
            if submission.enrollment_id() != enrollment_id {
                anyhow::bail!("enrollment id mismatch");
            }
            Ok(submission)
        })
    }

    fn publish_activation(&self, activation: &ActivationV1) -> BoxFuture<'_, ()> {
        self.lock().activations.push(activation.clone());
        Box::pin(async { Ok(()) })
    }

    fn revoke(&self, fingerprint: &str) -> BoxFuture<'_, ()> {
        self.lock().revoked.push(fingerprint.to_owned());
        Box::pin(async { Ok(()) })
    }

    fn watch_requests(&self) -> BoxFuture<'_, InboundStream> {
        // Watch only prints requests; tests drive behavior through the
        // verdict/submission queues, so an empty stream is honest.
        Box::pin(async { Ok(Box::pin(futures::stream::empty()) as _) })
    }
}

fn stub_ack(sender: Option<Sender<()>>) -> AckFuture {
    Box::pin(async move {
        if let Some(sender) = sender {
            sender
                .send(())
                .map_err(|_| anyhow!("mock ack channel closed"))?;
        }
        Ok(())
    })
}

impl ServerTransport for MockTransport {
    fn requests(&self) -> BoxFuture<'_, RequestStream> {
        let stubs: Vec<JetStreamMessageStub> = self.lock().server_requests.drain(..).collect();
        let batches: Vec<Result<Vec<JetStreamMessage>>> = stubs
            .into_iter()
            .map(|stub| {
                let (on_term, on_ack) = (stub.on_term, stub.on_ack);
                Ok(vec![JetStreamMessage {
                    payload: stub.payload,
                    ack: Box::new(move |kind| match kind {
                        Ack::Term => stub_ack(on_term),
                        Ack::Ok => stub_ack(on_ack),
                    }),
                }])
            })
            .collect();
        Box::pin(async move { Ok(Box::pin(futures::stream::iter(batches)) as _) })
    }

    fn subscribe(&self, _subject: &str) -> BoxFuture<'_, InboundStream> {
        // Server unit tests drive `Store` directly, not subject handlers, so
        // the mock has no inbound queue: an empty stream is honest.
        Box::pin(async { Ok(Box::pin(futures::stream::empty()) as _) })
    }

    fn publish(&self, subject: String, payload: Vec<u8>) -> BoxFuture<'_, ()> {
        self.lock().published.push((subject, payload));
        Box::pin(async { Ok(()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oshioki_protocol::VERSION_V1;

    /// The accessors capture what the operations record: revocation
    /// fingerprints, activation payloads, and publishes, in order.
    #[tokio::test]
    async fn mock_records_revocation_and_publications() {
        let transport = MockTransport::new();
        transport.revoke("fp-1").await.unwrap();
        let activation = ActivationV1 {
            version: VERSION_V1,
            enrollment_id: "enroll-1".into(),
            device: oshioki_protocol::DevicePublicRecordV1 {
                version: VERSION_V1,
                kind: oshioki_protocol::DeviceKindV1::SecureEnclave,
                fingerprint: "fp-1".into(),
                credential_id: "cred".into(),
                credential_public_key: "pub".into(),
                box_public_key: "box".into(),
                label: "device".into(),
                api_token_hash: "hash".into(),
                sign_count: 0,
                active: true,
            },
        };
        transport.publish_activation(&activation).await.unwrap();
        ServerTransport::publish(&transport, "a.b".into(), b"x".to_vec())
            .await
            .unwrap();
        assert_eq!(transport.revoked(), ["fp-1"]);
        assert_eq!(transport.activations(), [activation]);
        assert_eq!(transport.published(), [("a.b".to_string(), b"x".to_vec())]);
    }

    /// The enrollment round trip records the intent on the real subject and
    /// hands the queued submission back on the reply stream, so the hook's
    /// publish-then-wait ordering is exercised without a wire.
    #[tokio::test]
    async fn mock_carries_an_enrollment_submission() {
        let transport = MockTransport::new();
        let submission =
            EnrollmentSubmissionV1::SecureEnclave(oshioki_protocol::NativeEnrollmentSubmissionV1 {
                version: VERSION_V1,
                enrollment_id: "enroll-1".into(),
                credential_public_key: "pub".into(),
                box_public_key: "box".into(),
                api_token_hash: "hash".into(),
                label: "device".into(),
                proof_signature: "sig".into(),
                transcript_hmac: "hmac".into(),
            });
        transport.push_submission(submission.clone());
        let intent = EnrollmentIntentV1 {
            version: VERSION_V1,
            enrollment_id: "enroll-1".into(),
            secret_hash: "hash".into(),
            expires_at: 0,
            reply_subject: "oshioki.enrollment.submission.enroll-1".into(),
        };
        let stream = transport.publish_enrollment_intent(&intent).await.unwrap();
        assert_eq!(
            transport
                .published()
                .first()
                .map(|(subject, _)| subject.clone()),
            Some(ENROLLMENT_INTENT_SUBJECT.to_owned()),
            "the intent must be recorded before the wait begins"
        );
        let received = transport
            .await_submission("enroll-1", stream, tokio::time::Instant::now())
            .await
            .unwrap();
        assert_eq!(received.enrollment_id(), submission.enrollment_id());
    }
}
