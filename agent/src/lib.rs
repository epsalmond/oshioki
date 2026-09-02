//! Native approval agent library: device identity, request opening, and
//! decision construction.
//!
//! The agent holds a P-256 signing key and an X25519 box key. The signing
//! key sits behind the [`Signer`] trait so the software backend used here
//! and in tests can be swapped for a Secure Enclave key on macOS. The box
//! key is always a software key; the enclave cannot hold X25519.

#![forbid(unsafe_code)]

use std::{fs, io::Write as _, os::unix::fs::OpenOptionsExt as _, path::Path};

use anyhow::{Context as _, Result, bail};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use oshioki_protocol::{
    ApproveNativeV1, DecisionV1, DenyV1, DeviceKindV1, DevicePublicRecordV1,
    NativeEnrollmentSubmissionV1, RequestEnvelopeV1, RequestV1, VERSION_V1, approve_challenge,
    decode_base64url, device_fingerprint, encode_base64url, native_credential_id,
    native_enrollment_proof, native_v1::native_transcript_hmac, unseal_v1,
};

/// Signs approval challenges and enrollment proofs. DER ECDSA P-256 with
/// SHA-256 as the message hash.
pub trait Signer {
    /// The 65-byte SEC1 uncompressed public point.
    fn public_key_sec1(&self) -> Vec<u8>;
    fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>>;
}

/// A P-256 key held in process memory.
pub struct SoftwareSigner(SigningKey);

impl Signer for SoftwareSigner {
    fn public_key_sec1(&self) -> Vec<u8> {
        self.0
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }
    fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signature: Signature = self.0.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

/// On-disk form of the software identity. Mode 0600.
#[derive(Serialize, Deserialize)]
struct IdentityFileV1 {
    version: u8,
    signing_key: String,
    box_secret: String,
    api_token_hash: String,
}

/// The agent's device identity: signer, box key, and API token hash.
pub struct Identity {
    signer: Box<dyn Signer + Send + Sync>,
    box_secret: StaticSecret,
    api_token_hash: [u8; 32],
}

impl Identity {
    /// Builds an identity from fixed material, for tests and vectors.
    pub fn from_material(
        signing: [u8; 32],
        box_secret: [u8; 32],
        api_token_hash: [u8; 32],
    ) -> Result<Self> {
        Ok(Self {
            signer: Box::new(SoftwareSigner(
                SigningKey::from_slice(&signing).context("invalid signing scalar")?,
            )),
            box_secret: StaticSecret::from(box_secret),
            api_token_hash,
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        let file: IdentityFileV1 = serde_json::from_slice(
            &fs::read(path).with_context(|| format!("read {}", path.display()))?,
        )
        .context("decode identity file")?;
        if file.version != VERSION_V1 {
            bail!("unsupported identity file version");
        }
        Self::from_material(
            exact_32(&file.signing_key)?,
            exact_32(&file.box_secret)?,
            exact_32(&file.api_token_hash)?,
        )
    }

    /// Writes the identity with mode 0600. Fails if the file exists.
    pub fn save_new(&self, path: &Path, signing: &SigningKey) -> Result<()> {
        let file = IdentityFileV1 {
            version: VERSION_V1,
            signing_key: encode_base64url(&signing.to_bytes()),
            box_secret: encode_base64url(self.box_secret.as_bytes()),
            api_token_hash: encode_base64url(&self.api_token_hash),
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut handle = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("create {}", path.display()))?;
        handle.write_all(&serde_json::to_vec_pretty(&file)?)?;
        handle.write_all(b"\n")?;
        Ok(())
    }

    /// Generates and persists a software identity in one step.
    pub fn generate_to(path: &Path) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let signing = SigningKey::random(&mut rng);
        let mut token = [0_u8; 32];
        rng.fill_bytes(&mut token);
        let identity = Self {
            signer: Box::new(SoftwareSigner(signing.clone())),
            box_secret: StaticSecret::random_from_rng(rng),
            api_token_hash: Sha256::digest(token).into(),
        };
        identity.save_new(path, &signing)?;
        Ok(identity)
    }

    pub fn public_key_sec1(&self) -> Vec<u8> {
        self.signer.public_key_sec1()
    }
    pub fn box_public_key(&self) -> [u8; 32] {
        PublicKey::from(&self.box_secret).to_bytes()
    }
    pub fn credential_id(&self) -> Vec<u8> {
        native_credential_id(&self.public_key_sec1())
    }
    pub fn fingerprint(&self) -> String {
        device_fingerprint(
            &self.credential_id(),
            &self.public_key_sec1(),
            &self.box_public_key(),
        )
    }

    /// The record the host pins after a successful enrollment.
    pub fn device_record(&self, label: &str) -> DevicePublicRecordV1 {
        DevicePublicRecordV1 {
            version: VERSION_V1,
            kind: DeviceKindV1::SecureEnclave,
            fingerprint: self.fingerprint(),
            credential_id: encode_base64url(&self.credential_id()),
            credential_public_key: encode_base64url(&self.public_key_sec1()),
            box_public_key: encode_base64url(&self.box_public_key()),
            label: label.to_owned(),
            api_token_hash: encode_base64url(&self.api_token_hash),
            sign_count: 0,
            active: true,
        }
    }

    /// Builds a native enrollment submission bound to the enrollment secret.
    pub fn enrollment_submission(
        &self,
        enrollment_id: &str,
        secret: &[u8; 32],
        label: &str,
    ) -> Result<NativeEnrollmentSubmissionV1> {
        let public = self.public_key_sec1();
        let box_public = self.box_public_key();
        let proof =
            native_enrollment_proof(secret, &public, &box_public, &self.api_token_hash, label);
        let mut submission = NativeEnrollmentSubmissionV1 {
            version: VERSION_V1,
            enrollment_id: enrollment_id.to_owned(),
            credential_public_key: encode_base64url(&public),
            box_public_key: encode_base64url(&box_public),
            api_token_hash: encode_base64url(&self.api_token_hash),
            label: label.to_owned(),
            proof_signature: encode_base64url(&self.signer.sign_der(&proof)?),
            transcript_hmac: String::new(),
        };
        submission.transcript_hmac =
            encode_base64url(&native_transcript_hmac(secret, &submission).context("transcript")?);
        submission.validate_shape().context("submission shape")?;
        Ok(submission)
    }

    /// Finds this device's sealed body in an envelope and opens it. Returns
    /// `None` when the envelope carries nothing for this device, which is
    /// the normal case for a host this device never enrolled with.
    pub fn open_request(&self, envelope: &RequestEnvelopeV1) -> Result<Option<OpenedRequest>> {
        envelope.validate().context("envelope")?;
        let fingerprint = self.fingerprint();
        let Some(sealed) = envelope
            .sealed
            .iter()
            .find(|body| body.device_fingerprint == fingerprint)
        else {
            return Ok(None);
        };
        let raw = unseal_v1(sealed, &self.box_secret).context("open sealed body")?;
        let request: RequestV1 = serde_json::from_slice(&raw).context("decode request")?;
        request.validate().context("request")?;
        if request.request_id != envelope.request_id
            || request.host != envelope.host
            || request.user != envelope.user
            || request.expires_at != envelope.expires_at
        {
            bail!("sealed request does not match its envelope");
        }
        Ok(Some(OpenedRequest { request, raw }))
    }

    /// Signs an approval over the retained raw bytes of an opened request.
    pub fn approve(&self, opened: &OpenedRequest) -> Result<DecisionV1> {
        let signature = self.signer.sign_der(&approve_challenge(&opened.raw))?;
        Ok(DecisionV1::ApproveNative(ApproveNativeV1 {
            version: VERSION_V1,
            request_id: opened.request.request_id.clone(),
            device_fingerprint: self.fingerprint(),
            signature: encode_base64url(&signature),
        }))
    }

    pub fn deny(&self, request_id: &str) -> DecisionV1 {
        DecisionV1::Deny(DenyV1 {
            version: VERSION_V1,
            request_id: request_id.to_owned(),
            device_fingerprint: self.fingerprint(),
        })
    }
}

/// A request this device may decide on, with the exact bytes to sign.
pub struct OpenedRequest {
    pub request: RequestV1,
    pub raw: Vec<u8>,
}

/// Parses the enrollment URL printed by `oshioki enroll`:
/// `<base>/enroll/<id>#<secret>`.
pub fn parse_enrollment_url(url: &str) -> Result<(String, [u8; 32])> {
    let (path, fragment) = url
        .rsplit_once('#')
        .context("enrollment URL has no secret fragment")?;
    let (_, enrollment_id) = path
        .rsplit_once("/enroll/")
        .context("enrollment URL has no /enroll/<id> path")?;
    let enrollment_id = enrollment_id.trim_end_matches('/');
    if enrollment_id.is_empty() {
        bail!("enrollment URL has an empty id");
    }
    Ok((enrollment_id.to_owned(), exact_32(fragment)?))
}

fn exact_32(value: &str) -> Result<[u8; 32]> {
    decode_base64url(value)
        .context("base64url")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use oshioki_protocol::{
        DeviceRegistryV1, seal_v1, verify_native_approval_v1, verify_native_enrollment_v1,
    };
    use std::os::unix::fs::PermissionsExt as _;

    fn identity() -> Identity {
        Identity::from_material([0x11; 32], [0x22; 32], [0x33; 32]).unwrap()
    }

    fn request() -> RequestV1 {
        RequestV1 {
            version: VERSION_V1,
            request_id: "req-1".into(),
            nonce: encode_base64url(&[9; 16]),
            host: "host.example".into(),
            user: "eric".into(),
            uid: 1000,
            runas_uid: 0,
            cwd: "/".into(),
            tty: None,
            command: "/bin/true".into(),
            argv: vec!["true".into()],
            pid_chain: vec![],
            issued_at: 1_000,
            expires_at: 1_090,
        }
    }

    fn envelope(
        request: &RequestV1,
        devices: &[DevicePublicRecordV1],
    ) -> (RequestEnvelopeV1, Vec<u8>) {
        let raw = request.raw_json().unwrap();
        let sealed = devices
            .iter()
            .map(|device| seal_v1(&raw, device).unwrap())
            .collect();
        (
            RequestEnvelopeV1 {
                version: VERSION_V1,
                request_id: request.request_id.clone(),
                host: request.host.clone(),
                user: request.user.clone(),
                issued_at: request.issued_at,
                expires_at: request.expires_at,
                sealed,
            },
            raw,
        )
    }

    #[test]
    fn enrollment_round_trips_through_the_hook_verifier() {
        let identity = identity();
        let secret = [5; 32];
        let submission = identity
            .enrollment_submission("enroll-1", &secret, "laptop")
            .unwrap();
        let device = verify_native_enrollment_v1(&submission, &secret).unwrap();
        assert_eq!(device, identity.device_record("laptop"));
        DeviceRegistryV1 {
            version: VERSION_V1,
            devices: vec![device],
        }
        .validate()
        .unwrap();
        assert!(verify_native_enrollment_v1(&submission, &[6; 32]).is_err());
    }

    #[test]
    fn opens_own_body_and_signs_a_verifiable_approval() {
        let identity = identity();
        let device = identity.device_record("laptop");
        let request = request();
        let (envelope, raw) = envelope(&request, std::slice::from_ref(&device));
        let opened = identity.open_request(&envelope).unwrap().unwrap();
        assert_eq!(opened.raw, raw);
        assert_eq!(opened.request, request);
        let DecisionV1::ApproveNative(approval) = identity.approve(&opened).unwrap() else {
            panic!("expected native approval");
        };
        verify_native_approval_v1(&approval, &raw, &device).unwrap();
        assert!(verify_native_approval_v1(&approval, b"{}", &device).is_err());
        let DecisionV1::Deny(denial) = identity.deny("req-1") else {
            panic!("expected denial");
        };
        denial.validate_shape().unwrap();
        assert_eq!(denial.device_fingerprint, device.fingerprint);
    }

    #[test]
    fn ignores_envelopes_for_other_devices() {
        let other = Identity::from_material([0x44; 32], [0x55; 32], [0x66; 32]).unwrap();
        let (envelope, _) = envelope(&request(), &[other.device_record("other")]);
        assert!(identity().open_request(&envelope).unwrap().is_none());
    }

    #[test]
    fn rejects_an_envelope_that_disagrees_with_its_body() {
        let identity = identity();
        let (mut envelope, _) = envelope(&request(), &[identity.device_record("laptop")]);
        envelope.user = "mallory".into();
        assert!(identity.open_request(&envelope).is_err());
    }

    #[test]
    fn parses_enrollment_urls() {
        let secret = encode_base64url(&[7; 32]);
        let (id, parsed) =
            parse_enrollment_url(&format!("https://sudo.example/enroll/abc-123#{secret}")).unwrap();
        assert_eq!(id, "abc-123");
        assert_eq!(parsed, [7; 32]);
        assert!(parse_enrollment_url("https://sudo.example/enroll/abc-123").is_err());
        assert!(parse_enrollment_url("https://sudo.example/x/abc#AAAA").is_err());
    }

    #[test]
    fn identity_file_round_trips_and_refuses_overwrite() {
        let dir = std::env::temp_dir().join(format!("oshioki-agent-{}", std::process::id()));
        let path = dir.join("agent.json");
        let _ = fs::remove_dir_all(&dir);
        let generated = Identity::generate_to(&path).unwrap();
        let loaded = Identity::load(&path).unwrap();
        assert_eq!(generated.fingerprint(), loaded.fingerprint());
        assert!(Identity::generate_to(&path).is_err());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
