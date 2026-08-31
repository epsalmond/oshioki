//! Shared protocol types and crypto for sudo approval.
//!
//! This crate defines the wire format between the approval hook, server, and
//! browser page. Everything here is pure and
//! deterministic so the hook's approve/deny decision and the server's relay
//! use the exact same logic.

#![forbid(unsafe_code)]

pub mod enrollment_v1;
pub mod error;
pub mod v1;
pub mod webauthn_v1;

pub use enrollment_v1::{enrollment_hmac, verify_enrollment_v1};
pub use error::Error;
pub use v1::{
    ActivationV1, ApproveV1, DecisionV1, DenyV1, DevicePublicRecordV1, DeviceRegistryV1,
    EnrollmentIntentV1, EnrollmentStatusV1, EnrollmentSubmissionV1, HookConfigV1,
    RequestEnvelopeV1, RequestV1, SealedDeviceBodyV1, VERSION_V1, approve_challenge,
    decode_base64url, device_fingerprint, seal_v1,
};
pub use webauthn_v1::{AssertionOutcomeV1, verify_approval_v1};
