//! Shared protocol types and crypto for sudo approval.
//!
//! This crate defines the wire format between the sudo plugin, the approval
//! hook, the server, and the browser page. Everything here is pure and
//! deterministic so the hook's approve/deny decision and the server's relay
//! use the exact same logic.

#![forbid(unsafe_code)]

pub mod error;
pub mod request;
pub mod verdict;
pub mod verify;

pub use error::Error;
pub use request::Request;
pub use verdict::Verdict;
pub use verify::verify;
