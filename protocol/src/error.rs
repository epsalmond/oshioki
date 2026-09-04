//! Error type for the protocol crate.

use thiserror::Error;

/// All failure modes of the approval protocol.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("verdict failed verification: {0}")]
    BadVerdict(String),
    #[error("decode failed: {0}")]
    Decode(String),
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    // WebAuthn verification failures
    #[error("challenge mismatch")]
    BadChallenge,
    #[error("origin mismatch")]
    BadOrigin,
    #[error("relying party ID mismatch")]
    BadRpId,
    #[error("user presence flag not set")]
    MissingUserPresence,
    #[error("user verification flag not set")]
    MissingUserVerification,
    #[error("request expired")]
    Expired,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("malformed authenticator data")]
    MalformedAuthenticatorData,
    #[error("malformed client data JSON")]
    MalformedClientData,
    #[error("unexpected credential type")]
    UnexpectedCredentialType,
}
