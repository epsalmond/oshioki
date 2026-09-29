//! Secure Enclave signing for the macOS approval agent.
//!
//! The agent holds a P-256 key that only the Mac's Secure Enclave can use, and
//! only after Touch ID. The enclave never releases the private key, so signing
//! happens inside the enclave and the Touch ID sheet is the approval itself.
//!
//! The macOS implementation contains unsafe calls for Security.framework.
//! The sudo plugin has separate unsafe operations for its C ABI. On other
//! targets this crate is empty, and nothing links Security.framework.

#[cfg(target_os = "macos")]
mod mac;

#[cfg(target_os = "macos")]
pub use mac::{EnclaveSigner, PromptCanceller, SignError, screen_is_locked};
