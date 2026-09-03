//! Length-delimited frames for the local agent socket.
//!
//! The hook and the agent exchange the exact same JSON documents they would
//! publish on NATS (`RequestEnvelopeV1` one way, `DecisionV1` the other),
//! wrapped in a 4-byte big-endian length prefix. The cap is shared so a peer
//! can never make the other side allocate more than the largest envelope the
//! protocol already accepts. Everything here is pure: async I/O lives with
//! the callers.

use crate::{Error, v1::MAX_ENVELOPE_BYTES};

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
