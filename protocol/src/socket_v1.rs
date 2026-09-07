//! Length-delimited frames for the local agent socket.
//!
//! The hook and the agent exchange the exact same JSON documents they would
//! publish on NATS (`RequestEnvelopeV1` one way, `DecisionV1` the other),
//! wrapped in a 4-byte big-endian length prefix. The cap is shared so a peer
//! can never make the other side allocate more than the largest envelope the
//! protocol already accepts. Everything here is pure: async I/O lives with
//! the callers.

use crate::{Error, VERSION_V1, v1::MAX_ENVELOPE_BYTES};

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
}
