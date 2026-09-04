//! Version-one wire types and cryptographic framing.
//!
//! Opaque bytes use unpadded base64url.  Validation happens at every trust
//! boundary; callers must not accept a merely deserializable message.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use p256::ecdsa::{Signature, signature::Verifier as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{Error, native_v1::sec1_p256_verifying_key, webauthn_v1::cose_p256_verifying_key};

pub const VERSION_V1: u8 = 1;
pub const MAX_DEVICES: usize = 8;
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;
pub const MAX_ENVELOPE_BYTES: usize = 3 * 1024 * 1024;
const CHALLENGE_DOMAIN: &[u8] = b"oshioki/approve/v1\0";
const DENY_DOMAIN: &[u8] = b"oshioki/deny/v1\0";
const FINGERPRINT_DOMAIN: &[u8] = b"oshioki/fingerprint/v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvEntryV1 {
    pub name: String,
    pub value: String,
}

/// Environment variables that can change what a command does without
/// changing its path or arguments: the dynamic loader, command resolution,
/// shell startup files, interpreter search paths, pagers and editors, and
/// trust configuration. The plugin sends only these, so secrets that happen
/// to sit in the environment never enter the request at all — not the sealed
/// body, not server storage, not logs.
pub fn is_approval_env(name: &str) -> bool {
    matches!(
        name,
        "BASH_ENV"
            | "CLASSPATH"
            | "DYLD_FALLBACK_LIBRARY_PATH"
            | "DYLD_INSERT_LIBRARIES"
            | "DYLD_LIBRARY_PATH"
            | "EDITOR"
            | "ENV"
            | "GCONV_PATH"
            | "HOSTALIASES"
            | "JAVA_TOOL_OPTIONS"
            | "JDK_JAVA_OPTIONS"
            | "LD_AUDIT"
            | "LD_CONFIG"
            | "LD_LIBRARY_PATH"
            | "LD_PRELOAD"
            | "LD_PROFILE"
            | "LOCPATH"
            | "LUA_CPATH"
            | "LUA_PATH"
            | "MANPAGER"
            | "NLSPATH"
            | "NODE_OPTIONS"
            | "NODE_PATH"
            | "PAGER"
            | "PATH"
            | "PERL5LIB"
            | "PERLLIB"
            | "PYTHONHOME"
            | "PYTHONPATH"
            | "PYTHONSTARTUP"
            | "RES_OPTIONS"
            | "RUBYLIB"
            | "RUBYOPT"
            | "SHELLOPTS"
            | "SSL_CERT_DIR"
            | "SSL_CERT_FILE"
            | "SYSTEMD_EDITOR"
            | "SYSTEMD_PAGER"
            | "VISUAL"
            | "_JAVA_OPTIONS"
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestV1 {
    pub version: u8,
    pub request_id: String,
    pub nonce: String,
    pub host: String,
    pub user: String,
    pub uid: u32,
    pub runas_uid: u32,
    pub cwd: String,
    pub tty: Option<String>,
    pub command: String,
    pub argv: Vec<String>,
    pub pid_chain: Vec<String>,
    /// Curated execution environment (see [`is_approval_env`]). Signed as
    /// part of the raw request bytes, so two different environments never
    /// share an approval. Empty environments serialize to nothing, so
    /// requests written before the field existed are byte-identical to new
    /// ones without it — and old signatures keep verifying.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<EnvEntryV1>,
    pub issued_at: i64,
    pub expires_at: i64,
}

impl RequestV1 {
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != VERSION_V1 || !valid_id(&self.request_id) {
            return Err(Error::InvalidRequest(
                "unsupported version or request id".into(),
            ));
        }
        if decode_base64url(&self.nonce)?.len() != 16 || self.expires_at <= self.issued_at {
            return Err(Error::InvalidRequest("invalid nonce or expiry".into()));
        }
        if self.host.is_empty()
            || self.host.len() > 255
            || self.user.is_empty()
            || self.user.len() > 256
            || self.cwd.len() > 64 * 1024
            || self.command.is_empty()
            || self.command.len() > 64 * 1024
            || self.argv.len() > 4096
            || self.pid_chain.len() > 5
            || self.pid_chain.iter().any(|entry| entry.len() > 512)
            || self.env.len() > 64
            || self
                .env
                .iter()
                .any(|entry| entry.name.len() > 256 || entry.value.len() > 32768)
        {
            return Err(Error::InvalidRequest("invalid request field size".into()));
        }
        Ok(())
    }

    pub fn raw_json(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let raw = serde_json::to_vec(self).map_err(|e| Error::InvalidRequest(e.to_string()))?;
        if raw.len() > MAX_REQUEST_BYTES {
            return Err(Error::InvalidRequest("request exceeds 256 KiB".into()));
        }
        Ok(raw)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedDeviceBodyV1 {
    pub device_fingerprint: String,
    pub ephemeral_pub: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEnvelopeV1 {
    pub version: u8,
    pub request_id: String,
    pub host: String,
    pub user: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub sealed: Vec<SealedDeviceBodyV1>,
}

impl RequestEnvelopeV1 {
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != VERSION_V1
            || !valid_id(&self.request_id)
            || self.host.is_empty()
            || self.host.len() > 255
            || self.user.is_empty()
            || self.user.len() > 256
            || self.sealed.is_empty()
            || self.sealed.len() > MAX_DEVICES
            || self.expires_at <= self.issued_at
        {
            return Err(Error::InvalidRequest("invalid request envelope".into()));
        }
        for body in &self.sealed {
            if !valid_fingerprint(&body.device_fingerprint)
                || decode_exact(&body.ephemeral_pub, 32).is_err()
                || decode_exact(&body.nonce, 12).is_err()
                || decode_base64url(&body.ciphertext)?.len() < 16
            {
                return Err(Error::InvalidRequest("invalid sealed body".into()));
            }
        }
        let bytes = serde_json::to_vec(self).map_err(|e| Error::InvalidRequest(e.to_string()))?;
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(Error::InvalidRequest("envelope exceeds 3 MiB".into()));
        }
        Ok(())
    }
}

/// How a device proves an approval.
///
/// `webauthn` devices sign `WebAuthn` assertions from a browser. `secure-enclave`
/// devices sign the challenge directly with a P-256 key (the native agent).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceKindV1 {
    #[default]
    #[serde(rename = "webauthn")]
    Webauthn,
    #[serde(rename = "secure-enclave")]
    SecureEnclave,
}

impl DeviceKindV1 {
    /// The wire spelling of the kind, identical to its serde tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Webauthn => "webauthn",
            Self::SecureEnclave => "secure-enclave",
        }
    }
}

impl std::fmt::Display for DeviceKindV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A pinned approval device.
///
/// For `secure-enclave` records `credential_public_key` is the 65-byte SEC1
/// uncompressed P-256 point, `credential_id` is the SHA-256 of that point,
/// and `sign_count` is always zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePublicRecordV1 {
    pub version: u8,
    /// Absent from records written before native devices existed; those are
    /// `WebAuthn`, so the field defaults rather than failing the load.
    #[serde(default)]
    pub kind: DeviceKindV1,
    pub fingerprint: String,
    pub credential_id: String,
    pub credential_public_key: String,
    pub box_public_key: String,
    pub label: String,
    pub api_token_hash: String,
    pub sign_count: u32,
    pub active: bool,
}

impl DevicePublicRecordV1 {
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != VERSION_V1
            || !valid_fingerprint(&self.fingerprint)
            || decode_base64url(&self.credential_id)?.is_empty()
            || decode_base64url(&self.credential_public_key)?.is_empty()
            || decode_exact(&self.box_public_key, 32).is_err()
            || decode_exact(&self.api_token_hash, 32).is_err()
            || self.label.is_empty()
            || self.label.len() > 128
        {
            return Err(Error::InvalidRequest("invalid device record".into()));
        }
        let public_key = decode_base64url(&self.credential_public_key)?;
        match self.kind {
            DeviceKindV1::Webauthn => {
                crate::webauthn_v1::cose_p256_verifying_key(&public_key)?;
            }
            DeviceKindV1::SecureEnclave => {
                crate::native_v1::sec1_p256_verifying_key(&public_key)?;
                if decode_base64url(&self.credential_id)?
                    != crate::native_v1::native_credential_id(&public_key)
                    || self.sign_count != 0
                {
                    return Err(Error::InvalidRequest(
                        "invalid secure-enclave device record".into(),
                    ));
                }
            }
        }
        let expected = device_fingerprint(
            &decode_base64url(&self.credential_id)?,
            &decode_base64url(&self.credential_public_key)?,
            &decode_exact(&self.box_public_key, 32)?,
        );
        if self.fingerprint != expected {
            return Err(Error::InvalidRequest("device fingerprint mismatch".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRegistryV1 {
    pub version: u8,
    pub devices: Vec<DevicePublicRecordV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookConfigV1 {
    pub version: u8,
    pub origin: String,
    pub rp_id: String,
    pub server_base_url: String,
}

impl HookConfigV1 {
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != VERSION_V1
            || !self.origin.starts_with("https://")
            || self.origin.ends_with('/')
            || self.rp_id.is_empty()
            || self.rp_id.contains('/')
            || self.server_base_url != self.origin
        {
            return Err(Error::InvalidRequest("invalid hook configuration".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentIntentV1 {
    pub version: u8,
    pub enrollment_id: String,
    pub secret_hash: String,
    pub expires_at: i64,
    pub reply_subject: String,
}

impl EnrollmentIntentV1 {
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != VERSION_V1
            || !valid_id(&self.enrollment_id)
            || decode_exact(&self.secret_hash, 32).is_err()
            || self.reply_subject != format!("oshioki.enrollment.submission.{}", self.enrollment_id)
        {
            return Err(Error::InvalidRequest("invalid enrollment intent".into()));
        }
        Ok(())
    }
}

/// An enrollment submission, tagged by device kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind")]
pub enum EnrollmentSubmissionV1 {
    #[serde(rename = "webauthn")]
    Webauthn(WebauthnEnrollmentSubmissionV1),
    #[serde(rename = "secure-enclave")]
    SecureEnclave(NativeEnrollmentSubmissionV1),
}

/// Deserialization also accepts the untagged shape browsers sent before
/// native devices existed: a submission with no `kind` is a `WebAuthn` one,
/// so a cached page still gets the 202 or 409 it expects rather than a raw
/// deserialization failure.
///
/// The `kind` field decides which variant is parsed and nothing falls back to
/// the other: a submission tagged `secure-enclave` that carries `WebAuthn`
/// fields is an error, not a `WebAuthn` enrollment. Parsing the chosen variant
/// on its own also keeps serde's own message ("missing field
/// `proof_signature`"), which an untagged enum would replace with "data did
/// not match any variant".
impl<'de> Deserialize<'de> for EnrollmentSubmissionV1 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let value = serde_json::Value::deserialize(deserializer)?;
        let kind = match value.get("kind") {
            None | Some(serde_json::Value::Null) => DeviceKindV1::Webauthn,
            Some(serde_json::Value::String(tag)) if tag == DeviceKindV1::Webauthn.as_str() => {
                DeviceKindV1::Webauthn
            }
            Some(serde_json::Value::String(tag)) if tag == DeviceKindV1::SecureEnclave.as_str() => {
                DeviceKindV1::SecureEnclave
            }
            Some(tag) => {
                // The tag is whatever the peer sent, and this message ends up
                // in a log or on an operator's terminal.
                let rendered: String = crate::escape_for_terminal(&tag.to_string())
                    .chars()
                    .take(64)
                    .collect();
                return Err(D::Error::custom(format!(
                    "unknown enrollment submission kind {rendered}"
                )));
            }
        };
        match kind {
            DeviceKindV1::Webauthn => serde_json::from_value(value)
                .map(Self::Webauthn)
                .map_err(D::Error::custom),
            DeviceKindV1::SecureEnclave => serde_json::from_value(value)
                .map(Self::SecureEnclave)
                .map_err(D::Error::custom),
        }
    }
}

impl EnrollmentSubmissionV1 {
    pub fn enrollment_id(&self) -> &str {
        match self {
            Self::Webauthn(submission) => &submission.enrollment_id,
            Self::SecureEnclave(submission) => &submission.enrollment_id,
        }
    }
    pub fn kind(&self) -> DeviceKindV1 {
        match self {
            Self::Webauthn(_) => DeviceKindV1::Webauthn,
            Self::SecureEnclave(_) => DeviceKindV1::SecureEnclave,
        }
    }
    pub fn validate_shape(&self) -> Result<(), Error> {
        match self {
            Self::Webauthn(submission) => submission.validate_shape(),
            Self::SecureEnclave(submission) => submission.validate_shape(),
        }
    }
}

/// Native enrollment: a P-256 public key plus an immediate proof signature.
///
/// `proof_signature` is DER ECDSA P-256 over the proof message from
/// [`crate::native_v1::native_enrollment_proof`]. `credential_id` is not
/// carried; it is derived from the public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeEnrollmentSubmissionV1 {
    pub version: u8,
    pub enrollment_id: String,
    pub credential_public_key: String,
    pub box_public_key: String,
    pub api_token_hash: String,
    pub label: String,
    pub proof_signature: String,
    pub transcript_hmac: String,
}

impl NativeEnrollmentSubmissionV1 {
    pub fn validate_shape(&self) -> Result<(), Error> {
        if self.version != VERSION_V1
            || !valid_id(&self.enrollment_id)
            || decode_exact(&self.credential_public_key, 65).is_err()
            || decode_exact(&self.box_public_key, 32).is_err()
            || decode_exact(&self.api_token_hash, 32).is_err()
            || self.label.is_empty()
            || self.label.len() > 128
            || !(8..=256).contains(&decode_base64url(&self.proof_signature)?.len())
            || decode_exact(&self.transcript_hmac, 32).is_err()
        {
            return Err(Error::InvalidRequest(
                "invalid native enrollment submission shape".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebauthnEnrollmentSubmissionV1 {
    pub version: u8,
    pub enrollment_id: String,
    pub registration_client_data_json: String,
    pub attestation_object: String,
    pub proof_authenticator_data: String,
    pub proof_client_data_json: String,
    pub proof_signature: String,
    pub credential_id: String,
    pub box_public_key: String,
    pub api_token_hash: String,
    pub label: String,
    pub transcript_hmac: String,
}

impl WebauthnEnrollmentSubmissionV1 {
    pub fn validate_shape(&self) -> Result<(), Error> {
        if self.version != VERSION_V1
            || !valid_id(&self.enrollment_id)
            || decode_base64url(&self.registration_client_data_json)?.len() > 16 * 1024
            || decode_base64url(&self.attestation_object)?.len() > 128 * 1024
            || decode_base64url(&self.proof_authenticator_data)?.len() > 1024
            || decode_base64url(&self.proof_client_data_json)?.len() > 16 * 1024
            || decode_base64url(&self.proof_signature)?.len() > 256
            || decode_base64url(&self.credential_id)?.is_empty()
            || decode_base64url(&self.credential_id)?.len() > 1024
            || decode_exact(&self.box_public_key, 32).is_err()
            || decode_exact(&self.api_token_hash, 32).is_err()
            || self.label.is_empty()
            || self.label.len() > 128
            || decode_exact(&self.transcript_hmac, 32).is_err()
        {
            return Err(Error::InvalidRequest(
                "invalid enrollment submission shape".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationV1 {
    pub version: u8,
    pub enrollment_id: String,
    pub device: DevicePublicRecordV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentStatusV1 {
    Pending,
    Active,
    Expired,
    Rejected,
}

impl DeviceRegistryV1 {
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != VERSION_V1 || self.devices.len() > MAX_DEVICES {
            return Err(Error::InvalidRequest("invalid device registry".into()));
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut credentials = std::collections::BTreeSet::new();
        for device in &self.devices {
            device.validate()?;
            if !seen.insert(&device.fingerprint) {
                return Err(Error::InvalidRequest("duplicate device fingerprint".into()));
            }
            if !credentials.insert(&device.credential_id) {
                return Err(Error::InvalidRequest("duplicate credential id".into()));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum DecisionV1 {
    Approve(ApproveV1),
    ApproveNative(ApproveNativeV1),
    Deny(DenyV1),
}

/// A native approval: DER ECDSA P-256 over the 32 challenge bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproveNativeV1 {
    pub version: u8,
    pub request_id: String,
    pub device_fingerprint: String,
    pub signature: String,
}

impl ApproveNativeV1 {
    pub fn validate_shape(&self) -> Result<(), Error> {
        if self.version != VERSION_V1
            || !valid_id(&self.request_id)
            || !valid_fingerprint(&self.device_fingerprint)
            || !(8..=256).contains(&decode_base64url(&self.signature)?.len())
        {
            return Err(Error::BadVerdict("invalid native approval shape".into()));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproveV1 {
    pub version: u8,
    pub request_id: String,
    pub device_fingerprint: String,
    pub credential_id: String,
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenyV1 {
    pub version: u8,
    pub request_id: String,
    pub device_fingerprint: String,
    /// Base64url DER ECDSA P-256 over [`deny_challenge`], present on native
    /// (NATS) verdicts where the device key signs. Absent on browser
    /// verdicts: the authenticator key never leaves its hardware, so those
    /// authenticate at the API with the device token and the hook confirms
    /// them against the server's record instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl ApproveV1 {
    pub fn validate_shape(&self) -> Result<(), Error> {
        let authenticator_data = decode_base64url(&self.authenticator_data)?;
        let client_data = decode_base64url(&self.client_data_json)?;
        let signature = decode_base64url(&self.signature)?;
        if self.version != VERSION_V1
            || !valid_id(&self.request_id)
            || !valid_fingerprint(&self.device_fingerprint)
            || decode_base64url(&self.credential_id)?.is_empty()
            || !(37..=1024).contains(&authenticator_data.len())
            || client_data.is_empty()
            || client_data.len() > 16 * 1024
            || !(8..=256).contains(&signature.len())
        {
            return Err(Error::BadVerdict("invalid approval shape".into()));
        }
        Ok(())
    }
}

impl DenyV1 {
    pub fn validate_shape(&self) -> Result<(), Error> {
        if self.version != VERSION_V1
            || !valid_id(&self.request_id)
            || !valid_fingerprint(&self.device_fingerprint)
        {
            return Err(Error::BadVerdict("invalid denial shape".into()));
        }
        if let Some(signature) = &self.signature {
            if signature.is_empty() {
                return Err(Error::BadVerdict("empty denial signature".into()));
            }
            decode_base64url(signature)?;
        }
        Ok(())
    }
}

/// The 32 bytes a device signs to deny: domain-separated over the request id
/// and its own fingerprint, so a denial authenticates exactly one request
/// from exactly one device. Replays across requests or devices challenge
/// differently and fail verification. Separate domain from approvals, so a
/// denial signature is never a valid approval signature and vice versa.
pub fn deny_challenge(request_id: &str, device_fingerprint: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DENY_DOMAIN);
    hash.update(request_id.as_bytes());
    hash.update([0]);
    hash.update(device_fingerprint.as_bytes());
    hash.finalize().into()
}

/// Verifies a device-signed denial against its pinned record. The credential
/// key parses according to the device kind; both `WebAuthn` and Secure Enclave
/// devices speak DER ECDSA P-256.
pub fn verify_deny_v1(denial: &DenyV1, device: &DevicePublicRecordV1) -> Result<(), Error> {
    device.validate()?;
    denial.validate_shape()?;
    if denial.request_id.is_empty() || denial.device_fingerprint != device.fingerprint {
        return Err(Error::BadVerdict(
            "denial does not match pinned device".into(),
        ));
    }
    let signature = denial
        .signature
        .as_deref()
        .ok_or_else(|| Error::BadVerdict("denial is unsigned".into()))?;
    let key = match device.kind {
        DeviceKindV1::Webauthn => {
            cose_p256_verifying_key(&decode_base64url(&device.credential_public_key)?)?
        }
        DeviceKindV1::SecureEnclave => {
            sec1_p256_verifying_key(&decode_base64url(&device.credential_public_key)?)?
        }
    };
    let signature =
        Signature::from_der(&decode_base64url(signature)?).map_err(|_| Error::InvalidSignature)?;
    key.verify(
        &deny_challenge(&denial.request_id, &denial.device_fingerprint),
        &signature,
    )
    .map_err(|_| Error::InvalidSignature)
}

pub fn encode_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn decode_base64url(value: &str) -> Result<Vec<u8>, Error> {
    if value.contains('=') {
        return Err(Error::Decode("padded base64url is forbidden".into()));
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Error::Decode("invalid base64url".into()))
}

pub fn approve_challenge(raw_request_json: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(CHALLENGE_DOMAIN);
    hash.update(raw_request_json);
    hash.finalize().into()
}
pub fn device_fingerprint(
    credential_id: &[u8],
    credential_public_key: &[u8],
    box_public_key: &[u8],
) -> String {
    let mut hash = Sha256::new();
    hash.update(FINGERPRINT_DOMAIN);
    hash.update((credential_id.len() as u64).to_be_bytes());
    hash.update(credential_id);
    hash.update((credential_public_key.len() as u64).to_be_bytes());
    hash.update(credential_public_key);
    hash.update(box_public_key);
    encode_base64url(&hash.finalize()[..16])
}

pub fn seal_v1(
    raw_request_json: &[u8],
    device: &DevicePublicRecordV1,
) -> Result<SealedDeviceBodyV1, Error> {
    if raw_request_json.len() > MAX_REQUEST_BYTES {
        return Err(Error::InvalidRequest("request exceeds 256 KiB".into()));
    }
    device.validate()?;
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let mut nonce = [0_u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    seal_v1_with_material(raw_request_json, device, &secret, nonce)
}

fn seal_v1_with_material(
    raw_request_json: &[u8],
    device: &DevicePublicRecordV1,
    secret: &StaticSecret,
    nonce: [u8; 12],
) -> Result<SealedDeviceBodyV1, Error> {
    let peer: [u8; 32] = decode_exact(&device.box_public_key, 32)?
        .try_into()
        .map_err(|_| Error::Decode("box key length".into()))?;
    let public = PublicKey::from(secret);
    let shared = secret.diffie_hellman(&PublicKey::from(peer));
    if shared.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(Error::InvalidRequest(
            "all-zero X25519 shared secret".into(),
        ));
    }
    let cipher = ChaCha20Poly1305::new(shared.as_bytes().into());
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), raw_request_json)
        .map_err(|_| Error::InvalidRequest("seal encryption failed".into()))?;
    Ok(SealedDeviceBodyV1 {
        device_fingerprint: device.fingerprint.clone(),
        ephemeral_pub: encode_base64url(public.as_bytes()),
        nonce: encode_base64url(&nonce),
        ciphertext: encode_base64url(&ciphertext),
    })
}

/// Opens a sealed body with the device's X25519 secret and returns the raw
/// request bytes. The caller must still parse and validate them.
pub fn unseal_v1(sealed: &SealedDeviceBodyV1, box_secret: &StaticSecret) -> Result<Vec<u8>, Error> {
    let ephemeral: [u8; 32] = decode_exact(&sealed.ephemeral_pub, 32)?
        .try_into()
        .map_err(|_| Error::Decode("ephemeral key length".into()))?;
    let nonce = decode_exact(&sealed.nonce, 12)?;
    let ciphertext = decode_base64url(&sealed.ciphertext)?;
    let shared = box_secret.diffie_hellman(&PublicKey::from(ephemeral));
    if shared.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(Error::InvalidRequest(
            "all-zero X25519 shared secret".into(),
        ));
    }
    let cipher = ChaCha20Poly1305::new(shared.as_bytes().into());
    let raw = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_slice())
        .map_err(|_| Error::Decode("sealed body does not open".into()))?;
    if raw.len() > MAX_REQUEST_BYTES {
        return Err(Error::InvalidRequest("request exceeds 256 KiB".into()));
    }
    Ok(raw)
}

pub(crate) fn decode_exact(value: &str, length: usize) -> Result<Vec<u8>, Error> {
    let decoded = decode_base64url(value)?;
    if decoded.len() == length {
        Ok(decoded)
    } else {
        Err(Error::Decode("invalid byte length".into()))
    }
}
pub(crate) fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
fn valid_fingerprint(value: &str) -> bool {
    decode_base64url(value).is_ok_and(|bytes| bytes.len() == 16)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn challenge_binds_exact_raw_bytes() {
        assert_ne!(
            approve_challenge(br#"{\"a\":1}"#),
            approve_challenge(br#"{ \"a\": 1 }"#)
        );
    }
    #[test]
    fn rejects_padded_base64url() {
        assert!(decode_base64url("AA==").is_err());
    }

    fn minimal_request() -> RequestV1 {
        RequestV1 {
            version: VERSION_V1,
            request_id: "req-1".into(),
            nonce: encode_base64url(&[1; 16]),
            host: "host.example".into(),
            user: "eric".into(),
            uid: 1000,
            runas_uid: 0,
            cwd: "/home/eric".into(),
            tty: None,
            command: "/usr/bin/apt".into(),
            argv: vec!["apt".into()],
            pid_chain: vec![],
            env: vec![],
            issued_at: 1_000,
            expires_at: 1_090,
        }
    }

    /// The allowlist pins behavior-shaping variables and nothing else:
    /// loaders, resolution, shells, interpreters, pagers, trust config.
    /// Anything carrying secrets or mere preferences stays out, so it never
    /// enters the sealed request.
    #[test]
    fn approval_env_list_covers_the_dangerous_and_little_else() {
        for name in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "PATH",
            "PYTHONPATH",
            "BASH_ENV",
            "PAGER",
            "SSL_CERT_FILE",
        ] {
            assert!(is_approval_env(name), "{name}");
        }
        for name in [
            "HOME",
            "LANG",
            "TERM",
            "USER",
            "AWS_SECRET_ACCESS_KEY",
            "path",
            "Ld_PreLoad",
            "",
        ] {
            assert!(!is_approval_env(name), "{name}");
        }
    }

    /// An empty environment serializes to nothing: a new request without
    /// env is byte-identical to one written before the field existed, and
    /// an old payload loads with an empty environment. Old hooks and old
    /// signatures keep working in both directions.
    #[test]
    fn pre_env_requests_load_with_empty_env() {
        let mut request = minimal_request();
        let json = serde_json::to_string(&request).unwrap();
        assert!(!json.contains("\"env\""), "{json}");
        let loaded: RequestV1 = serde_json::from_str(&json).unwrap();
        assert!(loaded.env.is_empty());
        loaded.validate().unwrap();
        request.env = vec![EnvEntryV1 {
            name: "PATH".into(),
            value: "/usr/bin".into(),
        }];
        let with_env = serde_json::to_string(&request).unwrap();
        assert!(with_env.contains("\"env\""), "{with_env}");
        let round_tripped: RequestV1 = serde_json::from_str(&with_env).unwrap();
        assert_eq!(round_tripped.env, request.env);
        round_tripped.validate().unwrap();
    }

    #[test]
    fn env_entries_have_size_bounds() {
        let mut request = minimal_request();
        request.env = vec![
            EnvEntryV1 {
                name: "PATH".into(),
                value: "/usr/bin".into(),
            };
            65
        ];
        assert!(request.validate().is_err());
        request.env.truncate(1);
        request.env[0].name = "x".repeat(257);
        assert!(request.validate().is_err());
        request.env[0].name = "PATH".into();
        request.env[0].value = "x".repeat(32769);
        assert!(request.validate().is_err());
    }

    /// The approval signs the raw request bytes, so requests that differ
    /// only in environment hash — and sign — differently. Two materially
    /// different environments can never share an approval payload.
    #[test]
    fn different_environments_never_share_an_approval() {
        let bare = minimal_request();
        let mut one = bare.clone();
        one.env = vec![EnvEntryV1 {
            name: "LD_PRELOAD".into(),
            value: "/tmp/evil.so".into(),
        }];
        let mut other = bare.clone();
        other.env = vec![EnvEntryV1 {
            name: "LD_PRELOAD".into(),
            value: "/tmp/other.so".into(),
        }];
        let raw_bare = bare.raw_json().unwrap();
        let raw_one = one.raw_json().unwrap();
        let raw_other = other.raw_json().unwrap();
        assert_ne!(raw_bare, raw_one);
        assert_ne!(raw_one, raw_other);
        assert_ne!(approve_challenge(&raw_bare), approve_challenge(&raw_one));
        assert_ne!(approve_challenge(&raw_one), approve_challenge(&raw_other));
    }

    /// A record written before the `kind` field existed must still load, as
    /// `WebAuthn`. Both the host's `devices.json` and the server's
    /// `public_record_json` column hold exactly this shape.
    #[test]
    fn pre_kind_device_record_loads_as_webauthn() {
        use p256::ecdsa::SigningKey;
        let signing = SigningKey::from_slice(&[0x33; 32]).unwrap();
        let point = signing.verifying_key().to_encoded_point(false);
        let cose = crate::webauthn_v1::tests::cose_key(point.x().unwrap(), point.y().unwrap());
        let credential_id = [7; 32];
        let box_key = [8; 32];
        let record_json = format!(
            r#"{{"version":1,"fingerprint":"{}","credential_id":"{}","credential_public_key":"{}","box_public_key":"{}","label":"laptop","api_token_hash":"{}","sign_count":4,"active":true}}"#,
            device_fingerprint(&credential_id, &cose, &box_key),
            encode_base64url(&credential_id),
            encode_base64url(&cose),
            encode_base64url(&box_key),
            encode_base64url(&[9; 32]),
        );
        let device: DevicePublicRecordV1 = serde_json::from_str(&record_json).unwrap();
        assert_eq!(device.kind, DeviceKindV1::Webauthn);
        device.validate().unwrap();

        let registry: DeviceRegistryV1 =
            serde_json::from_str(&format!(r#"{{"version":1,"devices":[{record_json}]}}"#)).unwrap();
        registry.validate().unwrap();
        assert_eq!(registry.devices[0].kind, DeviceKindV1::Webauthn);
    }

    /// `as_str` is the serde tag: the transcript HMAC and the device list
    /// both depend on the two staying the same string.
    #[test]
    fn kind_renders_as_its_serde_tag() {
        for kind in [DeviceKindV1::Webauthn, DeviceKindV1::SecureEnclave] {
            assert_eq!(serde_json::to_string(&kind).unwrap(), format!("\"{kind}\""));
            assert_eq!(kind.to_string(), kind.as_str());
        }
    }

    /// Browser pages cached before the `kind` tag existed post a
    /// bare `WebAuthn` submission; it must still parse as one.
    #[test]
    fn enrollment_submission_without_kind_is_webauthn() {
        let untagged = r#"{"version":1,"enrollment_id":"e1","registration_client_data_json":"AA","attestation_object":"AQ","proof_authenticator_data":"Ag","proof_client_data_json":"Aw","proof_signature":"BA","credential_id":"BQ","box_public_key":"Bg","api_token_hash":"Bw","label":"laptop","transcript_hmac":"CA"}"#;
        let submission: EnrollmentSubmissionV1 = serde_json::from_str(untagged).unwrap();
        assert_eq!(submission.kind(), DeviceKindV1::Webauthn);
        assert_eq!(submission.enrollment_id(), "e1");

        let tagged = serde_json::to_string(&submission).unwrap();
        assert!(tagged.contains(r#""kind":"webauthn""#));
        assert_eq!(
            serde_json::from_str::<EnrollmentSubmissionV1>(&tagged).unwrap(),
            submission
        );

        let native = r#"{"kind":"secure-enclave","version":1,"enrollment_id":"e1","credential_public_key":"AA","box_public_key":"AQ","api_token_hash":"Ag","label":"mac","proof_signature":"Aw","transcript_hmac":"BA"}"#;
        let native: EnrollmentSubmissionV1 = serde_json::from_str(native).unwrap();
        assert_eq!(native.kind(), DeviceKindV1::SecureEnclave);
    }

    /// A malformed submission must say which field is wrong. An untagged
    /// enum answers "data did not match any variant" instead, which names
    /// nothing an operator can act on.
    #[test]
    fn malformed_native_submission_names_the_missing_field() {
        let native = r#"{"kind":"secure-enclave","version":1,"enrollment_id":"e1","credential_public_key":"AA","box_public_key":"AQ","api_token_hash":"Ag","label":"mac","transcript_hmac":"BA"}"#;
        let error = serde_json::from_str::<EnrollmentSubmissionV1>(native).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("missing field `proof_signature`"),
            "{error}"
        );
    }

    /// The tag decides the variant. A submission that claims to be native
    /// but carries `WebAuthn` fields is rejected rather than parsed as the
    /// other kind.
    #[test]
    fn kind_is_authoritative_over_the_fields() {
        let mislabelled = r#"{"kind":"secure-enclave","version":1,"enrollment_id":"e1","registration_client_data_json":"AA","attestation_object":"AQ","proof_authenticator_data":"Ag","proof_client_data_json":"Aw","proof_signature":"BA","credential_id":"BQ","box_public_key":"Bg","api_token_hash":"Bw","label":"laptop","transcript_hmac":"CA"}"#;
        let error = serde_json::from_str::<EnrollmentSubmissionV1>(mislabelled).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("missing field `credential_public_key`"),
            "{error}"
        );
    }

    #[test]
    fn unknown_kind_is_rejected() {
        let unknown = r#"{"kind":"totp","version":1,"enrollment_id":"e1"}"#;
        let error = serde_json::from_str::<EnrollmentSubmissionV1>(unknown).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(r#"unknown enrollment submission kind "totp""#),
            "{error}"
        );
        // A tag that is not a string is unknown too.
        let not_a_string =
            serde_json::from_str::<EnrollmentSubmissionV1>(r#"{"kind":7,"version":1}"#)
                .unwrap_err();
        assert!(
            not_a_string
                .to_string()
                .contains("unknown enrollment submission kind 7"),
            "{not_a_string}"
        );
        // An escape sequence in the tag does not reach the terminal raw.
        let escaped = serde_json::from_str::<EnrollmentSubmissionV1>(
            "{\"kind\":\"a\\u001b[2Kb\",\"version\":1}",
        )
        .unwrap_err();
        assert!(escaped.to_string().contains(r"a\\u001b[2Kb"), "{escaped}");
    }

    #[test]
    fn fixed_seal_vector() {
        let recipient_secret = StaticSecret::from([7; 32]);
        let recipient_public = PublicKey::from(&recipient_secret);
        let credential_id = [1; 16];
        let credential_key = [2; 32];
        let fingerprint =
            device_fingerprint(&credential_id, &credential_key, recipient_public.as_bytes());
        let device = DevicePublicRecordV1 {
            version: 1,
            kind: DeviceKindV1::Webauthn,
            fingerprint,
            credential_id: encode_base64url(&credential_id),
            credential_public_key: encode_base64url(&credential_key),
            box_public_key: encode_base64url(recipient_public.as_bytes()),
            label: "vector".into(),
            api_token_hash: encode_base64url(&[3; 32]),
            sign_count: 0,
            active: true,
        };
        let raw = br#"{"version":1,"request_id":"vector-1"}"#;
        let sealed =
            seal_v1_with_material(raw, &device, &StaticSecret::from([9; 32]), [11; 12]).unwrap();
        assert_eq!(
            encode_base64url(recipient_public.as_bytes()),
            "E75P6uryBMf9M1j8nAByGIHRdCeBKCJ-xnTzf3_pe20"
        );
        assert_eq!(
            sealed.ephemeral_pub,
            "V9tLNZ8jrl4Ubk4lEgVnBHIlBjSMFQwUdT0Mkz0E1CE"
        );
        assert_eq!(sealed.nonce, "CwsLCwsLCwsLCwsL");
        assert_eq!(
            sealed.ciphertext,
            "WGPFmg8nyJM8A4tNZfX1esd_ehYPrFuiMKhs5FTOL35DUvX_DGXi6B03BbDA8HPF5zbxCGE"
        );
        assert_eq!(
            encode_base64url(&approve_challenge(raw)),
            "mTBOp81bPTi4PmjpqFmNPFz3vFWCzk1yBKBHmHEkWV4"
        );
        assert_eq!(unseal_v1(&sealed, &recipient_secret).unwrap(), raw);
        assert!(unseal_v1(&sealed, &StaticSecret::from([8; 32])).is_err());
        let mut tampered = sealed.clone();
        tampered.ciphertext = encode_base64url(&[0; 32]);
        assert!(unseal_v1(&tampered, &recipient_secret).is_err());
    }

    /// One pinned device with a real key, in either credential encoding, for
    /// denial round trips.
    fn deny_fixture(kind: DeviceKindV1) -> (DevicePublicRecordV1, p256::ecdsa::SigningKey) {
        use p256::ecdsa::SigningKey;
        let signing = SigningKey::from_bytes((&[11; 32]).into()).unwrap();
        let point = signing.verifying_key().to_encoded_point(false);
        let public = point.as_bytes().to_vec();
        let (credential_id, credential_public_key) = match kind {
            DeviceKindV1::SecureEnclave => (
                encode_base64url(&crate::native_v1::native_credential_id(&public)),
                encode_base64url(&public),
            ),
            DeviceKindV1::Webauthn => {
                let cose =
                    crate::webauthn_v1::tests::cose_key(point.x().unwrap(), point.y().unwrap());
                (encode_base64url(&[9; 16]), encode_base64url(&cose))
            }
        };
        let credential_public_key_bytes = decode_base64url(&credential_public_key).unwrap();
        let device = DevicePublicRecordV1 {
            version: VERSION_V1,
            kind,
            fingerprint: device_fingerprint(
                &decode_base64url(&credential_id).unwrap(),
                &credential_public_key_bytes,
                &[7; 32],
            ),
            credential_id,
            credential_public_key,
            box_public_key: encode_base64url(&[7; 32]),
            label: "laptop".into(),
            api_token_hash: encode_base64url(&[8; 32]),
            sign_count: 0,
            active: true,
        };
        device.validate().unwrap();
        (device, signing)
    }

    fn signed_denial(
        signing: &p256::ecdsa::SigningKey,
        request_id: &str,
        device: &DevicePublicRecordV1,
    ) -> DenyV1 {
        use p256::ecdsa::signature::Signer as _;
        let challenge = deny_challenge(request_id, &device.fingerprint);
        let signature: p256::ecdsa::Signature = signing.sign(&challenge);
        DenyV1 {
            version: VERSION_V1,
            request_id: request_id.into(),
            device_fingerprint: device.fingerprint.clone(),
            signature: Some(encode_base64url(signature.to_der().as_bytes())),
        }
    }

    /// A device-signed denial verifies against its pinned record in both
    /// credential encodings, and the challenge is input-sensitive.
    #[test]
    fn signed_denials_verify_per_device_kind() {
        for kind in [DeviceKindV1::Webauthn, DeviceKindV1::SecureEnclave] {
            let (device, signing) = deny_fixture(kind);
            let denial = signed_denial(&signing, "req-1", &device);
            denial.validate_shape().unwrap();
            verify_deny_v1(&denial, &device).unwrap();
        }
        assert_ne!(deny_challenge("req-1", "fp"), deny_challenge("req-2", "fp"));
        assert_ne!(
            deny_challenge("req-1", "fp-a"),
            deny_challenge("req-1", "fp-b")
        );
    }

    /// Forged, cross-device, cross-request, tampered, and unsigned denials
    /// all fail: the hook can pin exactly one meaning to one signature.
    #[test]
    fn denial_forgeries_do_not_verify() {
        use p256::ecdsa::signature::Signer as _;
        let (device, signing) = deny_fixture(DeviceKindV1::SecureEnclave);
        let denial = signed_denial(&signing, "req-1", &device);
        let other_signing = p256::ecdsa::SigningKey::from_bytes((&[12; 32]).into()).unwrap();
        let other_signature: p256::ecdsa::Signature =
            other_signing.sign(&deny_challenge("req-1", &device.fingerprint));
        let mut forged = denial.clone();
        forged.signature = Some(encode_base64url(other_signature.to_der().as_bytes()));
        assert!(verify_deny_v1(&forged, &device).is_err());
        let mut crossed = denial.clone();
        crossed.device_fingerprint = encode_base64url(&[8; 16]);
        assert!(verify_deny_v1(&crossed, &device).is_err());
        let mut replayed = denial.clone();
        replayed.request_id = "req-2".into();
        assert!(verify_deny_v1(&replayed, &device).is_err());
        let mut tampered = denial.clone();
        tampered.request_id = "req-1-tampered".into();
        assert!(verify_deny_v1(&tampered, &device).is_err());
        let mut unsigned = denial.clone();
        unsigned.signature = None;
        assert!(verify_deny_v1(&unsigned, &device).is_err());
        let mut empty = denial.clone();
        empty.signature = Some(String::new());
        assert!(empty.validate_shape().is_err());
    }

    /// A denial written without a signature — the browser shape — still
    /// parses, with the signature absent rather than empty.
    #[test]
    fn unsigned_denials_parse_for_the_browser_path() {
        let denial: DenyV1 = serde_json::from_str(
            r#"{"version":1,"request_id":"req-1","device_fingerprint":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
        )
        .unwrap();
        assert_eq!(denial.signature, None);
        denial.validate_shape().unwrap();
        let round_tripped: DenyV1 =
            serde_json::from_str(&serde_json::to_string(&denial).unwrap()).unwrap();
        assert_eq!(round_tripped.signature, None);
    }
}
