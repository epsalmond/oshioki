//! Native approval agent library: device identity, request opening, and
//! decision construction.
//!
//! The agent holds a P-256 signing key and an X25519 box key. The signing
//! key sits behind the [`Signer`] trait so the software backend used here
//! and in tests can be swapped for a Secure Enclave key on macOS. The box
//! key is always a software key; the enclave cannot hold X25519.

#![forbid(unsafe_code)]

pub mod secret_store;
pub mod touchid;

use std::{fmt, fs, io::Write as _, os::unix::fs::OpenOptionsExt as _, path::Path, time::Duration};

use anyhow::{Context as _, Result, bail};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use oshioki_protocol::{
    ApproveNativeV1, DecisionV1, DenyV1, DeviceKindV1, DevicePublicRecordV1,
    NativeEnrollmentSubmissionV1, RequestEnvelopeV1, RequestV1, VERSION_V1, approve_challenge,
    decode_base64url, deny_challenge, device_fingerprint, encode_base64url, native_credential_id,
    native_enrollment_proof, native_v1::native_transcript_hmac, unseal_v1,
};

/// What the enrollment proof signature approves, for a backend that asks.
const ENROLL_REASON: &str = "enroll this device with a host";

/// Signs approval challenges and enrollment proofs. DER ECDSA P-256 with
/// SHA-256 as the message hash.
pub trait Signer {
    /// The 65-byte SEC1 uncompressed public point.
    fn public_key_sec1(&self) -> Vec<u8>;

    /// Signs `message`. `reason` says what the signature approves, in the
    /// second person: a backend that asks the operator shows it, and one that
    /// does not ignores it.
    fn sign_der(&self, message: &[u8], reason: &str) -> Result<Vec<u8>>;

    /// Starts a prompt attempt and returns its number. A backend that shows
    /// nothing has nothing to number.
    fn begin_prompt(&self) -> u64 {
        0
    }

    /// Dismisses that attempt's prompt, and only that attempt's. A number
    /// from an attempt that is already over does nothing.
    fn cancel_prompt(&self, _attempt: u64) {}
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
    fn sign_der(&self, message: &[u8], _reason: &str) -> Result<Vec<u8>> {
        let signature: Signature = self.0.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

/// A P-256 key in this Mac's Secure Enclave, used only after Touch ID.
#[cfg(target_os = "macos")]
struct EnclaveBackend(oshioki_enclave::EnclaveSigner);

#[cfg(target_os = "macos")]
impl Signer for EnclaveBackend {
    fn public_key_sec1(&self) -> Vec<u8> {
        self.0.public_key_sec1().to_vec()
    }
    fn sign_der(&self, message: &[u8], reason: &str) -> Result<Vec<u8>> {
        // The variant survives into the caller's anyhow chain, which is how
        // the prompt tells a dismissed sheet from an unusable key.
        self.0.sign_der(message, reason).map_err(anyhow::Error::new)
    }
    fn begin_prompt(&self) -> u64 {
        self.0.canceller().begin()
    }
    fn cancel_prompt(&self, attempt: u64) {
        self.0.canceller().cancel(attempt);
    }
}

/// Which backend holds the signing key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerKind {
    /// A P-256 key in the identity file, readable by anything that reads the
    /// file. The only kind outside macOS.
    Software,
    /// A P-256 key in the Mac's Secure Enclave, behind Touch ID.
    Enclave,
}

impl fmt::Display for SignerKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Software => "software",
            Self::Enclave => "enclave",
        })
    }
}

/// The signing key as the identity file stores it.
///
/// The software key is the secret scalar. The enclave key is the
/// enclave-encrypted blob, which is useless anywhere but the Mac that made it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum SigningFileV1 {
    Software { key: String },
    Enclave { blob: String },
}

impl SigningFileV1 {
    fn kind(&self) -> SignerKind {
        match self {
            Self::Software { .. } => SignerKind::Software,
            Self::Enclave { .. } => SignerKind::Enclave,
        }
    }
}

/// On-disk form of the identity. Mode 0600.
///
/// The box secret takes one of two forms. Legacy files carry it inline in
/// `box_secret`; current macOS files keep it in the login keychain and carry
/// only its account name in `box_secret_ref`. A file with both, or with
/// neither, is corrupt.
#[derive(Serialize, Deserialize)]
struct IdentityFileV1 {
    version: u8,
    signing: SigningFileV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    box_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    box_secret_ref: Option<String>,
    api_token_hash: String,
}

/// The agent's device identity: signer, box key, and API token hash.
///
/// The box key is always a software key: the enclave holds P-256 and nothing
/// else, so X25519 has nowhere else to live. On macOS the secret itself sits
/// in the login keychain and the file keeps only its account name; anywhere
/// else the file carries it inline.
pub struct Identity {
    signer: Box<dyn Signer + Send + Sync>,
    signing: SigningFileV1,
    box_secret: StaticSecret,
    box_secret_ref: Option<String>,
    api_token_hash: [u8; 32],
}

impl Identity {
    /// Builds a software identity from fixed material, for tests and vectors.
    pub fn from_material(
        signing: [u8; 32],
        box_secret: [u8; 32],
        api_token_hash: [u8; 32],
    ) -> Result<Self> {
        Ok(Self {
            signer: Box::new(SoftwareSigner(
                SigningKey::from_slice(&signing).context("invalid signing scalar")?,
            )),
            signing: SigningFileV1::Software {
                key: encode_base64url(&signing),
            },
            box_secret: StaticSecret::from(box_secret),
            box_secret_ref: None,
            api_token_hash,
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        #[cfg(target_os = "macos")]
        return Self::load_with(path, &secret_store::KeychainStore::oshioki());
        #[cfg(not(target_os = "macos"))]
        return Self::load_embedded(path);
    }

    /// Loads the identity through an explicit secret store. Production on
    /// macOS passes the login keychain; tests pass a memory store so no test
    /// run touches a real keychain.
    pub fn load_with(path: &Path, store: &dyn secret_store::SecretStore) -> Result<Self> {
        let file: IdentityFileV1 = serde_json::from_slice(
            &fs::read(path).with_context(|| format!("read {}", path.display()))?,
        )
        .context("decode identity file")?;
        if file.version != VERSION_V1 {
            bail!("unsupported identity file version");
        }
        let IdentityFileV1 {
            signing,
            box_secret,
            box_secret_ref,
            api_token_hash,
            ..
        } = file;
        let (secret, secret_ref) = match (box_secret, box_secret_ref) {
            (Some(_), Some(_)) => bail!(
                "identity file {} carries both an embedded secret and a keychain reference",
                path.display()
            ),
            (Some(secret), None) => {
                // Legacy file: the secret moves into the store before the
                // file is rewritten without it, so a crash in between leaves
                // the old file intact and the migration simply retries.
                let bytes = exact_32(&secret)?;
                let reference = new_secret_ref();
                store
                    .put(&reference, &bytes)
                    .context("move the box secret into the secret store")?;
                let stripped = IdentityFileV1 {
                    version: VERSION_V1,
                    signing: signing.clone(),
                    box_secret: None,
                    box_secret_ref: Some(reference.clone()),
                    api_token_hash: api_token_hash.clone(),
                };
                write_identity_file(path, &stripped, false)?;
                (bytes, Some(reference))
            }
            (None, Some(reference)) => {
                let bytes = store
                    .get(&reference)
                    .with_context(|| format!("read the box secret for {}", path.display()))?
                    .with_context(|| {
                        format!(
                            "the secret store holds nothing for {}; re-pair with --force",
                            path.display()
                        )
                    })?;
                (bytes, Some(reference))
            }
            (None, None) => bail!(
                "identity file {} has no box secret and no keychain reference",
                path.display()
            ),
        };
        Ok(Self {
            signer: signer_from_file(&signing)?,
            signing,
            box_secret: StaticSecret::from(secret),
            box_secret_ref: secret_ref,
            api_token_hash: exact_32(&api_token_hash)?,
        })
    }

    /// Loads a file that carries its box secret inline. The only form outside
    /// macOS; on macOS it exists for files the keychain cannot serve.
    #[cfg(not(target_os = "macos"))]
    fn load_embedded(path: &Path) -> Result<Self> {
        let file: IdentityFileV1 = serde_json::from_slice(
            &fs::read(path).with_context(|| format!("read {}", path.display()))?,
        )
        .context("decode identity file")?;
        if file.version != VERSION_V1 {
            bail!("unsupported identity file version");
        }
        if file.box_secret_ref.is_some() {
            bail!(
                "identity file {} points at a keychain this platform has no store for",
                path.display()
            );
        }
        let Some(secret) = file.box_secret else {
            bail!("identity file {} has no box secret", path.display());
        };
        Ok(Self {
            signer: signer_from_file(&file.signing)?,
            signing: file.signing,
            box_secret: StaticSecret::from(exact_32(&secret)?),
            box_secret_ref: None,
            api_token_hash: exact_32(&file.api_token_hash)?,
        })
    }

    /// Writes the identity with mode 0600. Fails if the file exists.
    pub fn save_new(&self, path: &Path) -> Result<()> {
        #[cfg(target_os = "macos")]
        return self.save_new_with(path, &secret_store::KeychainStore::oshioki());
        #[cfg(not(target_os = "macos"))]
        return self.save_embedded(path);
    }

    /// Persists through an explicit secret store. See [`Self::load_with`].
    pub fn save_new_with(&self, path: &Path, store: &dyn secret_store::SecretStore) -> Result<()> {
        let reference = new_secret_ref();
        store
            .put(&reference, self.box_secret.as_bytes())
            .context("store the box secret")?;
        let file = IdentityFileV1 {
            version: VERSION_V1,
            signing: match &self.signing {
                SigningFileV1::Software { key } => SigningFileV1::Software { key: key.clone() },
                SigningFileV1::Enclave { blob } => SigningFileV1::Enclave { blob: blob.clone() },
            },
            box_secret: None,
            box_secret_ref: Some(reference),
            api_token_hash: encode_base64url(&self.api_token_hash),
        };
        write_identity_file(path, &file, true)
    }

    /// Persists with the box secret inline. The only form outside macOS.
    #[cfg(not(target_os = "macos"))]
    fn save_embedded(&self, path: &Path) -> Result<()> {
        let file = IdentityFileV1 {
            version: VERSION_V1,
            signing: match &self.signing {
                SigningFileV1::Software { key } => SigningFileV1::Software { key: key.clone() },
                SigningFileV1::Enclave { blob } => SigningFileV1::Enclave { blob: blob.clone() },
            },
            box_secret: Some(encode_base64url(self.box_secret.as_bytes())),
            box_secret_ref: None,
            api_token_hash: encode_base64url(&self.api_token_hash),
        };
        write_identity_file(path, &file, true)
    }

    /// The keychain account holding this identity's box secret, if the file
    /// keeps only a reference. Lets `--force` re-pair clean up the old entry.
    pub fn secret_ref(&self) -> Option<&str> {
        self.box_secret_ref.as_deref()
    }

    /// Generates a key of the requested kind and persists it in one step.
    ///
    /// Creating an enclave key shows no Touch ID sheet: the access control is
    /// checked when the key signs, not when it is made.
    pub fn generate_to(path: &Path, kind: SignerKind) -> Result<Self> {
        #[cfg(target_os = "macos")]
        return Self::generate_to_with(path, kind, &secret_store::KeychainStore::oshioki());
        #[cfg(not(target_os = "macos"))]
        return Self::generate_embedded(path, kind);
    }

    /// Generates through an explicit secret store. See [`Self::load_with`].
    pub fn generate_to_with(
        path: &Path,
        kind: SignerKind,
        store: &dyn secret_store::SecretStore,
    ) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let mut token = [0_u8; 32];
        rng.fill_bytes(&mut token);
        let (signer, signing) = new_signer(kind, &mut rng)?;
        let identity = Self {
            signer,
            signing,
            box_secret: StaticSecret::random_from_rng(rng),
            box_secret_ref: None,
            api_token_hash: Sha256::digest(token).into(),
        };
        identity.save_new_with(path, store)?;
        Ok(identity)
    }

    /// Generates with the box secret inline. The only form outside macOS.
    #[cfg(not(target_os = "macos"))]
    fn generate_embedded(path: &Path, kind: SignerKind) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let mut token = [0_u8; 32];
        rng.fill_bytes(&mut token);
        let (signer, signing) = new_signer(kind, &mut rng)?;
        let identity = Self {
            signer,
            signing,
            box_secret: StaticSecret::random_from_rng(rng),
            box_secret_ref: None,
            api_token_hash: Sha256::digest(token).into(),
        };
        identity.save_embedded(path)?;
        Ok(identity)
    }

    /// Which backend holds the signing key.
    pub fn signer_kind(&self) -> SignerKind {
        self.signing.kind()
    }

    /// Starts a prompt attempt on the signing backend and returns its number.
    pub fn begin_prompt(&self) -> u64 {
        self.signer.begin_prompt()
    }

    /// Dismisses that attempt's prompt. See [`Signer::cancel_prompt`].
    pub fn cancel_prompt(&self, attempt: u64) {
        self.signer.cancel_prompt(attempt);
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
            proof_signature: encode_base64url(&self.signer.sign_der(&proof, ENROLL_REASON)?),
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
    ///
    /// `reason` is what a backend that asks the operator puts on screen. With
    /// the enclave backend this call blocks for the whole Touch ID interaction,
    /// so callers keep it off the async runtime.
    pub fn approve(&self, opened: &OpenedRequest, reason: &str) -> Result<DecisionV1> {
        let signature = self
            .signer
            .sign_der(&approve_challenge(&opened.raw), reason)?;
        Ok(DecisionV1::ApproveNative(ApproveNativeV1 {
            version: VERSION_V1,
            request_id: opened.request.request_id.clone(),
            device_fingerprint: self.fingerprint(),
            signature: encode_base64url(&signature),
        }))
    }

    /// Refuses a request with a device-signed denial: only this device's key
    /// can produce the signature, so no NATS credential suffices to deny
    /// for it. `reason` is shown by backends that ask the operator (like an
    /// approval reason) and ignored by backends that do not.
    pub fn deny(&self, opened: &OpenedRequest, reason: &str) -> Result<DecisionV1> {
        let challenge = deny_challenge(&opened.request.request_id, &self.fingerprint());
        let signature = self.signer.sign_der(&challenge, reason)?;
        Ok(DecisionV1::Deny(DenyV1 {
            version: VERSION_V1,
            request_id: opened.request.request_id.clone(),
            device_fingerprint: self.fingerprint(),
            signature: Some(encode_base64url(&signature)),
        }))
    }
}

/// A request this device may decide on, with the exact bytes to sign.
#[derive(Clone)]
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

/// Rebuilds the signing backend the identity file names.
fn signer_from_file(signing: &SigningFileV1) -> Result<Box<dyn Signer + Send + Sync>> {
    match signing {
        SigningFileV1::Software { key } => Ok(Box::new(SoftwareSigner(
            SigningKey::from_slice(&exact_32(key)?).context("invalid signing scalar")?,
        ))),
        SigningFileV1::Enclave { blob } => {
            enclave_signer(decode_base64url(blob).context("enclave key blob")?)
        }
    }
}

/// Creates a signing key of the requested kind, and its persistable form.
fn new_signer(
    kind: SignerKind,
    rng: &mut (impl rand::CryptoRng + rand::RngCore),
) -> Result<(Box<dyn Signer + Send + Sync>, SigningFileV1)> {
    match kind {
        SignerKind::Software => {
            let signing = SigningKey::random(rng);
            let file = SigningFileV1::Software {
                key: encode_base64url(&signing.to_bytes()),
            };
            Ok((Box::new(SoftwareSigner(signing)), file))
        }
        SignerKind::Enclave => new_enclave_signer(),
    }
}

#[cfg(target_os = "macos")]
fn new_enclave_signer() -> Result<(Box<dyn Signer + Send + Sync>, SigningFileV1)> {
    let signer = oshioki_enclave::EnclaveSigner::create().context("create a Secure Enclave key")?;
    let file = SigningFileV1::Enclave {
        blob: encode_base64url(signer.blob()),
    };
    Ok((Box::new(EnclaveBackend(signer)), file))
}

#[cfg(not(target_os = "macos"))]
fn new_enclave_signer() -> Result<(Box<dyn Signer + Send + Sync>, SigningFileV1)> {
    bail!("a Secure Enclave key needs macOS; pair with --signer software instead")
}

#[cfg(target_os = "macos")]
fn enclave_signer(blob: Vec<u8>) -> Result<Box<dyn Signer + Send + Sync>> {
    Ok(Box::new(EnclaveBackend(
        oshioki_enclave::EnclaveSigner::from_blob(blob)
            .context("reattach this Mac's Secure Enclave key")?,
    )))
}

#[cfg(not(target_os = "macos"))]
fn enclave_signer(_blob: Vec<u8>) -> Result<Box<dyn Signer + Send + Sync>> {
    bail!("this identity holds a Secure Enclave key, which only the Mac that made it can use")
}

/// How long is left before `expires_at`, to sub-second precision, or `None`
/// once that instant has passed.
///
/// Whole-second arithmetic rounds the wait up: a request expiring in 200ms
/// reads as one second left, and a prompt would keep accepting an answer long
/// after the hook stopped listening for one.
pub fn remaining_until(expires_at: i64) -> Option<Duration> {
    let deadline = time::OffsetDateTime::from_unix_timestamp(expires_at).ok()?;
    let remaining = deadline - time::OffsetDateTime::now_utc();
    if remaining.is_positive() {
        Duration::try_from(remaining).ok()
    } else {
        None
    }
}

fn exact_32(value: &str) -> Result<[u8; 32]> {
    decode_base64url(value)
        .context("base64url")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes"))
}

/// A fresh keychain account name for a box secret. Random, so two identities
/// in different state directories never share an entry.
fn new_secret_ref() -> String {
    let mut bytes = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    encode_base64url(&bytes)
}

/// Writes the identity file with mode 0600. `create_new` refuses to replace
/// an existing file; without it the file is replaced atomically, so a crash
/// leaves either the old file or the new one, never a half-written file.
fn write_identity_file(path: &Path, file: &IdentityFileV1, create_new: bool) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut body = serde_json::to_vec_pretty(&file)?;
    body.push(b'\n');
    if create_new {
        let mut handle = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("create {}", path.display()))?;
        handle.write_all(&body)?;
        return Ok(());
    }
    let staging = path.with_extension("tmp");
    {
        let mut handle = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&staging)
            .with_context(|| format!("stage {}", staging.display()))?;
        handle.write_all(&body)?;
        handle
            .sync_all()
            .with_context(|| format!("flush {}", staging.display()))?;
    }
    fs::rename(&staging, path).with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_store::SecretStore as _;
    use oshioki_protocol::{
        DeviceRegistryV1, seal_v1, verify_deny_v1, verify_native_approval_v1,
        verify_native_enrollment_v1,
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
            env: vec![],
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
        let DecisionV1::ApproveNative(approval) = identity.approve(&opened, "run true").unwrap()
        else {
            panic!("expected native approval");
        };
        verify_native_approval_v1(&approval, &raw, &device).unwrap();
        assert!(verify_native_approval_v1(&approval, b"{}", &device).is_err());
        let DecisionV1::Deny(denial) = identity.deny(&opened, "refuse true").unwrap() else {
            panic!("expected denial");
        };
        denial.validate_shape().unwrap();
        assert_eq!(denial.device_fingerprint, device.fingerprint);
        // The denial authenticates against the pinned record: the hook
        // accepts exactly this, and nothing forged, replayed, or borrowed
        // from another device.
        verify_deny_v1(&denial, &device).unwrap();
        let mut forged = denial.clone();
        forged.signature = Some(encode_base64url(&[9; 64]));
        assert!(verify_deny_v1(&forged, &device).is_err());
        let mut crossed = denial.clone();
        crossed.device_fingerprint = encode_base64url(&[7; 16]);
        assert!(verify_deny_v1(&crossed, &device).is_err());
        let mut replayed = denial.clone();
        replayed.request_id = "req-2".into();
        assert!(verify_deny_v1(&replayed, &device).is_err());
        let mut unsigned = denial.clone();
        unsigned.signature = None;
        assert!(verify_deny_v1(&unsigned, &device).is_err());
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
        let store = secret_store::MemoryStore::new();
        let generated = Identity::generate_to_with(&path, SignerKind::Software, &store).unwrap();
        let loaded = Identity::load_with(&path, &store).unwrap();
        assert_eq!(generated.fingerprint(), loaded.fingerprint());
        assert_eq!(loaded.signer_kind(), SignerKind::Software);
        assert!(Identity::generate_to_with(&path, SignerKind::Software, &store).is_err());
        // The file keeps a reference, never the secret itself.
        let stored: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(stored.get("box_secret").is_none());
        assert!(stored["box_secret_ref"].is_string());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The signing key is a tagged field, so the file says which backend holds
    /// it. A file that only carried bytes could not describe an enclave key.
    #[test]
    fn the_identity_file_names_its_signing_backend() {
        let dir = std::env::temp_dir().join(format!("oshioki-tagged-{}", std::process::id()));
        let path = dir.join("agent.json");
        let _ = fs::remove_dir_all(&dir);
        let store = secret_store::MemoryStore::new();
        Identity::generate_to_with(&path, SignerKind::Software, &store).unwrap();
        let stored: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(stored["signing"]["kind"], "software");
        assert!(stored["signing"]["key"].is_string());
        assert!(stored.get("signing_key").is_none());

        // An enclave record loads only on the Mac that made the blob. Anywhere
        // else the agent has to say so rather than start with no signer.
        fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "version": VERSION_V1,
                "signing": {"kind": "enclave", "blob": encode_base64url(&[9_u8; 32])},
                "box_secret_ref": stored["box_secret_ref"],
                "api_token_hash": stored["api_token_hash"],
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(Identity::load_with(&path, &store).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A legacy file carrying its box secret inline migrates on load: the
    /// secret moves into the store, the file is rewritten without it, and the
    /// device keeps its fingerprint.
    #[test]
    fn a_legacy_file_migrates_its_secret_into_the_store() {
        let dir = std::env::temp_dir().join(format!("oshioki-migrate-{}", std::process::id()));
        let path = dir.join("agent.json");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let secret = encode_base64url(&[0x55; 32]);
        fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "version": VERSION_V1,
                "signing": {"kind": "software", "key": encode_base64url(&[0x54; 32])},
                "box_secret": secret,
                "api_token_hash": encode_base64url(&[0x56; 32]),
            }))
            .unwrap(),
        )
        .unwrap();
        let store = secret_store::MemoryStore::new();
        let before = Identity::load_with(&path, &store).unwrap();
        let stripped: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(stripped.get("box_secret").is_none());
        let reference = stripped["box_secret_ref"].as_str().unwrap();
        assert_eq!(store.get(reference).unwrap(), Some([0x55; 32]));
        // The second load serves the secret from the store, same device.
        let after = Identity::load_with(&path, &store).unwrap();
        assert_eq!(before.fingerprint(), after.fingerprint());
        assert_eq!(after.secret_ref(), Some(reference));
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A file with both forms, or with neither, is corrupt rather than a
    /// guess about which secret to use.
    #[test]
    fn an_ambiguous_or_empty_secret_form_is_refused() {
        let dir = std::env::temp_dir().join(format!("oshioki-ambiguous-{}", std::process::id()));
        let path = dir.join("agent.json");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let store = secret_store::MemoryStore::new();
        for (name, file) in [
            (
                "both",
                serde_json::json!({
                    "version": VERSION_V1,
                    "signing": {"kind": "software", "key": encode_base64url(&[0x54; 32])},
                    "box_secret": encode_base64url(&[0x55; 32]),
                    "box_secret_ref": "ref",
                    "api_token_hash": encode_base64url(&[0x56; 32]),
                }),
            ),
            (
                "neither",
                serde_json::json!({
                    "version": VERSION_V1,
                    "signing": {"kind": "software", "key": encode_base64url(&[0x54; 32])},
                    "api_token_hash": encode_base64url(&[0x56; 32]),
                }),
            ),
        ] {
            fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
            assert!(Identity::load_with(&path, &store).is_err(), "{name}");
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A reference whose entry is gone names re-pairing, so the operator
    /// knows the fix instead of seeing a keychain error.
    #[test]
    fn a_missing_store_entry_names_repairing() {
        let dir = std::env::temp_dir().join(format!("oshioki-gone-{}", std::process::id()));
        let path = dir.join("agent.json");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "version": VERSION_V1,
                "signing": {"kind": "software", "key": encode_base64url(&[0x54; 32])},
                "box_secret_ref": "no-such-entry",
                "api_token_hash": encode_base64url(&[0x56; 32]),
            }))
            .unwrap(),
        )
        .unwrap();
        let store = secret_store::MemoryStore::new();
        let Err(error) = Identity::load_with(&path, &store) else {
            panic!("a missing store entry loaded");
        };
        assert!(error.to_string().contains("--force"), "{error:#}");
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A Secure Enclave key cannot be conjured on a machine without one.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn an_enclave_key_is_refused_off_macos() {
        let dir = std::env::temp_dir().join(format!("oshioki-noenclave-{}", std::process::id()));
        let path = dir.join("agent.json");
        let _ = fs::remove_dir_all(&dir);
        let Err(error) = Identity::generate_to(&path, SignerKind::Enclave) else {
            panic!("this machine has no Secure Enclave");
        };
        assert!(error.to_string().contains("macOS"));
        assert!(!path.exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
