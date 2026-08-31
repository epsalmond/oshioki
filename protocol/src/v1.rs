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
const CHALLENGE_DOMAIN: &[u8] = b"management-plane-sudo-approve/approve/v1\0";
const FINGERPRINT_DOMAIN: &[u8] = b"management-plane-sudo-approve/fingerprint/v1\0";

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePublicRecordV1 {
    pub version: u8,
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
        crate::webauthn_v1::cose_p256_verifying_key(&decode_base64url(
            &self.credential_public_key,
        )?)?;
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
            || self.reply_subject != format!("sudo.enrollment.submission.{}", self.enrollment_id)
        {
            return Err(Error::InvalidRequest("invalid enrollment intent".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentSubmissionV1 {
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

impl EnrollmentSubmissionV1 {
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
    Deny(DenyV1),
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

fn decode_exact(value: &str, length: usize) -> Result<Vec<u8>, Error> {
    let decoded = decode_base64url(value)?;
    if decoded.len() == length {
        Ok(decoded)
    } else {
        Err(Error::Decode("invalid byte length".into()))
    }
}
fn valid_id(value: &str) -> bool {
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
            "5VNwjeIaxy3rOFXvz7lUoZvgjLjgWdxzU3255JY4qBI"
        );
    }
}
