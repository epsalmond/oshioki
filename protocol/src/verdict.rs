//! The approval verdict, a signed statement of approve.

use serde::{Deserialize, Serialize};

/// A response to a request. Only an approve is carried; deny is the absence
/// of a valid approve (unsigned by design).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    pub id: String,
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub client_data_json: String,
    pub signature: Vec<u8>,
}
