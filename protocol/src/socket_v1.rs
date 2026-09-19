//! Length-delimited frames for the local agent socket.
//!
//! The hook and the agent exchange the exact same JSON documents they would
//! publish on NATS (`RequestEnvelopeV1` one way, `DecisionV1` the other),
//! wrapped in a 4-byte big-endian length prefix. The cap is shared so a peer
//! can never make the other side allocate more than the largest envelope the
//! protocol already accepts. Everything here is pure: async I/O lives with
//! the callers.

use crate::{
    Error, VERSION_V1,
    auth_v1::{AUTH_NATIVE_DECISION_TYPE, AUTH_WEBAUTHN_DECISION_TYPE, AuthDecisionV1},
    v1::MAX_ENVELOPE_BYTES,
};

/// The server's durable routing receipt for a browser-capable request. It is
/// published on a subject distinct from the agent/browser liveness subject:
/// receipt of this message proves only that the relay committed a request to
/// an active browser recipient, never that a browser has opened it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeliveryV1 {
    #[serde(rename = "type")]
    pub message_type: String,
    pub version: u8,
    pub request_id: String,
}

impl DeliveryV1 {
    pub fn for_request(request_id: &str) -> Self {
        Self {
            message_type: "delivery".into(),
            version: VERSION_V1,
            request_id: request_id.into(),
        }
    }

    pub fn validate(&self, request_id: &str) -> Result<(), Error> {
        if self.message_type != "delivery"
            || self.version != VERSION_V1
            || self.request_id != request_id
        {
            return Err(Error::BadVerdict("invalid delivery receipt".into()));
        }
        Ok(())
    }
}

/// The first response a native agent sends for a request. It proves that an
/// agent received and accepted responsibility for the request; it carries no
/// authorization and is never sufficient to approve sudo.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AliveV1 {
    #[serde(rename = "type")]
    pub message_type: String,
    pub version: u8,
    pub request_id: String,
}

impl AliveV1 {
    pub fn for_request(request_id: &str) -> Self {
        Self {
            message_type: "alive".into(),
            version: VERSION_V1,
            request_id: request_id.into(),
        }
    }

    pub fn validate(&self, request_id: &str) -> Result<(), Error> {
        if self.message_type != "alive"
            || self.version != VERSION_V1
            || self.request_id != request_id
        {
            return Err(Error::BadVerdict("invalid alive acknowledgement".into()));
        }
        Ok(())
    }
}

/// One recognized kind of control message on a channel the liveness
/// acknowledgement and the signed verdict share: the socket frame stream
/// after the request envelope, and the NATS `oshioki.ack.<request_id>`
/// subject. A reader checks a message's kind before committing to a
/// type-specific decode, so an unexpected message at that point in the
/// exchange produces [`ControlMessageOutcome::UnknownKind`] instead of a
/// decode error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessageV1 {
    Alive(AliveV1),
    Delivery(DeliveryV1),
    /// A command-approval verdict (the `oshioki.request.<host>` / legacy
    /// socket lane). Tagged on `action`; see the module doc on
    /// [`ControlMessageProbe`].
    Decision(crate::v1::DecisionV1),
    /// A contextual-authentication verdict (the `oshioki.auth.<host>` lane,
    /// issue #73). Unlike `DecisionV1` this carries its own `type` field, so
    /// it is recognized the same way `AliveV1`/`DeliveryV1` are.
    AuthDecision(AuthDecisionV1),
}

/// What decoding one inbound control message concluded.
#[derive(Debug)]
pub enum ControlMessageOutcome {
    /// A recognized, structurally decoded message.
    Message(ControlMessageV1),
    /// A kind this build does not recognize -- most likely a message type a
    /// newer peer added. This is not evidence of anything: the caller treats
    /// the request as not yet answered and keeps waiting, subject to its own
    /// deadline, instead of failing to parse it as whatever it expected.
    UnknownKind(String),
}

/// A minimal, partial view used only to route a raw message to its
/// type-specific decoder. `AliveV1` and `DeliveryV1` are self-describing
/// through their own `type` field; `DecisionV1` carries no such field today
/// (it is only internally tagged on `action` once a reader already assumes
/// it is a decision), so its presence is inferred from `action` being set
/// with no `type` alongside it. This keeps `AliveV1`/`DeliveryV1`'s wire
/// shape byte-for-byte unchanged and lets a pre-existing peer's `DecisionV1`
/// (no `type` field at all) keep decoding exactly as before.
#[derive(serde::Deserialize)]
struct ControlMessageProbe {
    #[serde(rename = "type")]
    message_type: Option<String>,
    action: Option<serde_json::Value>,
}

/// Decode one control message off the shared ack/verdict channel.
///
/// Bytes that are not valid JSON at all, or that are a JSON object carrying
/// neither a `type` nor an `action` field, are a genuine decode fault: a
/// truncated frame, framing corruption, or an entirely different protocol,
/// not a message this reader merely fails to recognize. Those are `Err`.
///
/// Bytes that name a `type` this build does not recognize are
/// [`ControlMessageOutcome::UnknownKind`] rather than an error: the message
/// is self-describing, this reader simply predates it, and it is skipped
/// rather than treated as a decode failure per issue #66.
///
/// A recognized `type` (or, for a `type`-less legacy `DecisionV1`, a bare
/// `action` field) that then fails to decode as its own shape -- a missing
/// field, a version-skewed type change -- is also `Err`: the message
/// announced what it was and did not match it, which is exactly the version
/// skew this function exists to make a soft fault rather than a silent
/// misparse as some other type.
pub fn decode_control_message(bytes: &[u8]) -> Result<ControlMessageOutcome, Error> {
    let probe: ControlMessageProbe = serde_json::from_slice(bytes)
        .map_err(|error| Error::Decode(format!("undecodable control message: {error}")))?;
    match probe.message_type.as_deref() {
        Some("alive") => serde_json::from_slice(bytes)
            .map(|alive| ControlMessageOutcome::Message(ControlMessageV1::Alive(alive)))
            .map_err(|error| Error::Decode(format!("undecodable alive message: {error}"))),
        Some("delivery") => serde_json::from_slice(bytes)
            .map(|delivery| ControlMessageOutcome::Message(ControlMessageV1::Delivery(delivery)))
            .map_err(|error| Error::Decode(format!("undecodable delivery message: {error}"))),
        Some(AUTH_NATIVE_DECISION_TYPE | AUTH_WEBAUTHN_DECISION_TYPE) => {
            serde_json::from_slice(bytes)
                .map(|decision| {
                    ControlMessageOutcome::Message(ControlMessageV1::AuthDecision(decision))
                })
                .map_err(|error| {
                    Error::Decode(format!("undecodable authentication decision: {error}"))
                })
        }
        Some(other) => Ok(ControlMessageOutcome::UnknownKind(other.to_owned())),
        None if probe.action.is_some() => serde_json::from_slice(bytes)
            .map(|decision| ControlMessageOutcome::Message(ControlMessageV1::Decision(decision)))
            .map_err(|error| Error::Decode(format!("undecodable decision message: {error}"))),
        None => Err(Error::Decode(
            "control message carries neither a type nor an action field".into(),
        )),
    }
}

/// Bytes of the big-endian length prefix on every frame.
pub const FRAME_LEN_BYTES: usize = 4;

/// Largest frame payload, in bytes. Decisions are small, but one shared cap
/// keeps the check in a single place.
pub const MAX_FRAME_BYTES: usize = MAX_ENVELOPE_BYTES;

/// Wrap one JSON document for the socket.
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, Error> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(Error::InvalidRequest(format!(
            "frame is {} bytes, larger than the {MAX_FRAME_BYTES} byte cap",
            payload.len(),
        )));
    }
    let len = u32::try_from(payload.len())
        .map_err(|_| Error::InvalidRequest("frame length does not fit u32".into()))?;
    let mut frame = Vec::with_capacity(FRAME_LEN_BYTES + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Validate a length prefix read off the socket.
pub fn decode_frame_len(prefix: [u8; 4]) -> Result<usize, Error> {
    let len = usize::try_from(u32::from_be_bytes(prefix)).unwrap_or(MAX_FRAME_BYTES + 1);
    if len > MAX_FRAME_BYTES {
        return Err(Error::InvalidRequest(format!(
            "frame claims {len} bytes, larger than the {MAX_FRAME_BYTES} byte cap",
        )));
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alive_ack_binds_the_request_and_has_no_verdict_fields() {
        let ack = AliveV1::for_request("req-1");
        let encoded = serde_json::to_vec(&ack).unwrap();
        assert_eq!(
            encoded,
            br#"{"type":"alive","version":1,"request_id":"req-1"}"#
        );
        ack.validate("req-1").unwrap();
        assert!(ack.validate("req-2").is_err());
    }

    #[test]
    fn delivery_receipt_is_typed_and_binds_the_request() {
        let delivery = DeliveryV1::for_request("req-1");
        let encoded = serde_json::to_vec(&delivery).unwrap();
        assert_eq!(
            encoded,
            br#"{"type":"delivery","version":1,"request_id":"req-1"}"#
        );
        delivery.validate("req-1").unwrap();
        assert!(delivery.validate("req-2").is_err());
    }

    #[test]
    fn frame_round_trips_arbitrary_bytes() {
        let payload = b"{\"version\":1}";
        let frame = encode_frame(payload).unwrap();
        assert_eq!(frame.len(), FRAME_LEN_BYTES + payload.len());
        let len = decode_frame_len(frame[..FRAME_LEN_BYTES].try_into().unwrap()).unwrap();
        assert_eq!(len, payload.len());
        assert_eq!(&frame[FRAME_LEN_BYTES..], payload);
    }

    #[test]
    fn empty_frame_is_just_a_prefix() {
        let frame = encode_frame(&[]).unwrap();
        assert_eq!(frame, vec![0, 0, 0, 0]);
    }

    #[test]
    fn oversize_payload_is_refused_before_allocating() {
        let payload = vec![0u8; MAX_FRAME_BYTES + 1];
        assert!(encode_frame(&payload).is_err());
    }

    #[test]
    fn oversize_length_prefix_is_refused() {
        let oversize = u32::try_from(MAX_FRAME_BYTES + 1).expect("cap fits u32");
        assert!(decode_frame_len(oversize.to_be_bytes()).is_err());
    }

    #[test]
    fn control_message_recognizes_alive_and_delivery_by_their_own_type() {
        let alive = AliveV1::for_request("req-1");
        match decode_control_message(&serde_json::to_vec(&alive).unwrap()).unwrap() {
            ControlMessageOutcome::Message(ControlMessageV1::Alive(decoded)) => {
                assert_eq!(decoded, alive);
            }
            other => panic!("expected an alive message, got {other:?}"),
        }

        let delivery = DeliveryV1::for_request("req-1");
        match decode_control_message(&serde_json::to_vec(&delivery).unwrap()).unwrap() {
            ControlMessageOutcome::Message(ControlMessageV1::Delivery(decoded)) => {
                assert_eq!(decoded, delivery);
            }
            other => panic!("expected a delivery message, got {other:?}"),
        }
    }

    #[test]
    fn control_message_infers_a_legacy_type_less_decision_from_its_action_field() {
        let decision = crate::v1::DecisionV1::Deny(crate::v1::DenyV1 {
            version: VERSION_V1,
            request_id: "req-1".into(),
            device_fingerprint: "fp".into(),
            signature: None,
        });
        let bytes = serde_json::to_vec(&decision).unwrap();
        // A pre-#66 peer's decision carries no `type` field at all.
        assert!(!String::from_utf8_lossy(&bytes).contains("\"type\""));
        match decode_control_message(&bytes).unwrap() {
            ControlMessageOutcome::Message(ControlMessageV1::Decision(decoded)) => {
                assert_eq!(decoded, decision);
            }
            other => panic!("expected a decision message, got {other:?}"),
        }
    }

    #[test]
    fn control_message_recognizes_an_authentication_decision_by_its_own_type() {
        let decision = AuthDecisionV1::AuthenticateNative(crate::auth_v1::AuthApproveNativeV1 {
            version: crate::auth_v1::AUTH_WIRE_VERSION,
            request_id: "req-1".into(),
            device_fingerprint: "fp".into(),
            signature: "c2ln".into(),
        });
        let bytes = serde_json::to_vec(&decision).unwrap();
        match decode_control_message(&bytes).unwrap() {
            ControlMessageOutcome::Message(ControlMessageV1::AuthDecision(decoded)) => {
                assert_eq!(decoded, decision);
            }
            other => panic!("expected an authentication decision, got {other:?}"),
        }
    }

    #[test]
    fn control_message_distinguishes_a_cross_lane_decision_from_an_unknown_kind() {
        // A legacy command-approval decision arriving where an
        // authentication decision was expected decodes fine -- it is
        // evidence of a real cross-lane bug, not an unrecognized kind.
        let decision = crate::v1::DecisionV1::Deny(crate::v1::DenyV1 {
            version: VERSION_V1,
            request_id: "req-1".into(),
            device_fingerprint: "fp".into(),
            signature: None,
        });
        match decode_control_message(&serde_json::to_vec(&decision).unwrap()).unwrap() {
            ControlMessageOutcome::Message(ControlMessageV1::Decision(_)) => {}
            other @ (ControlMessageOutcome::Message(_) | ControlMessageOutcome::UnknownKind(_)) => {
                panic!("expected a decision message, got {other:?}")
            }
        }
    }

    #[test]
    fn control_message_skips_an_unrecognized_kind_instead_of_erroring() {
        let future_message = br#"{"type":"future_kind","version":1,"request_id":"req-1"}"#;
        match decode_control_message(future_message).unwrap() {
            ControlMessageOutcome::UnknownKind(kind) => assert_eq!(kind, "future_kind"),
            other @ ControlMessageOutcome::Message(_) => {
                panic!("expected an unrecognized kind, got {other:?}")
            }
        }
    }

    #[test]
    fn control_message_rejects_garbage_bytes_as_a_decode_fault() {
        assert!(decode_control_message(b"not json").is_err());
        assert!(decode_control_message(b"").is_err());
        // Valid JSON with neither a `type` nor an `action` field is exactly
        // as unclassifiable as garbage bytes: nothing here says what this
        // message even claims to be.
        assert!(decode_control_message(br#"{"version":1}"#).is_err());
    }

    #[test]
    fn control_message_rejects_a_recognized_type_that_fails_its_own_shape() {
        // Named "alive" but missing the fields `AliveV1` requires: version
        // skew, not an unrecognized kind, so this is still a decode fault.
        let malformed = br#"{"type":"alive","request_id":"req-1"}"#;
        assert!(decode_control_message(malformed).is_err());
    }
}
