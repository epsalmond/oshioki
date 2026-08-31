//! The approval request.

use serde::{Deserialize, Serialize};

/// A single sudo authorization decision, sent from the hook to the server.
///
/// The cleartext header carries only what routing and analytics need
/// (`id`, `host`, `user`, `ts`). The sealed body carries the full request,
/// encrypted per device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub id: String,
    pub nonce: [u8; 16],
    pub host: String,
    pub user: String,
    pub uid: u32,
    pub runas_uid: u32,
    pub cwd: String,
    pub tty: Option<String>,
    pub command: String,
    pub argv: Vec<String>,
    /// Up to 5 ancestors as `pid:comm`, nearest first.
    pub pid_chain: Vec<String>,
    pub ts: i64,
    pub expiry: i64,
}
