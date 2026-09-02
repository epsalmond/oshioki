//! Version-one wire types and cryptographic framing.
//!
//! Opaque bytes use unpadded base64url.  Validation happens at every trust
//! boundary; callers must not accept a merely deserializable message.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::Error;

pub const VERSION_V1: u8 = 1;
pub const MAX_DEVICES: usize = 8;
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;
pub const MAX_ENVELOPE_BYTES: usize = 3 * 1024 * 1024;
const CHALLENGE_DOMAIN: &[u8] = b"oshioki/approve/v1\0";
const FINGERPRINT_DOMAIN: &[u8] = b"oshioki/fingerprint/v1\0";

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
impl<'de> Deserialize<'de> for EnrollmentSubmissionV1 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "kind")]
        enum Tagged {
            #[serde(rename = "webauthn")]
            Webauthn(WebauthnEnrollmentSubmissionV1),
            #[serde(rename = "secure-enclave")]
            SecureEnclave(NativeEnrollmentSubmissionV1),
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Tagged(Tagged),
            UntaggedWebauthn(WebauthnEnrollmentSubmissionV1),
        }
        Ok(match Wire::deserialize(deserializer)? {
            Wire::Tagged(Tagged::Webauthn(submission)) | Wire::UntaggedWebauthn(submission) => {
                Self::Webauthn(submission)
            }
            Wire::Tagged(Tagged::SecureEnclave(submission)) => Self::SecureEnclave(submission),
        })
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
        Ok(())
    }
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
}
