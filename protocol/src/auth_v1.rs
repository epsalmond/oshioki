//! Version-two contextual sudo authentication protocol.
//!
//! Authentication has a separate wire version, type tag, decision tag, and
//! cryptographic domain from legacy command approval. The inner request is
//! sealed with the same device transport primitive as command approval, but a
//! command approval signature can never satisfy an authentication verifier.
//!
//! [`TrustedAuthContextV1`] contains values captured from PAM and the
//! privileged process. [`SubmittedAuthContextV1`] is display context supplied
//! by the caller or a host resolver; it is authenticated as part of the
//! request but is not a claim about the final sudo execution payload.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, signature::Verifier as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::StaticSecret;

use crate::{
    Error,
    v1::{
        DeviceKindV1, DevicePublicRecordV1, DeviceRegistryV1, HookConfigV1, MAX_DEVICES,
        MAX_REQUEST_BYTES, SealedDeviceBodyV1, decode_base64url, decode_exact, valid_fingerprint,
        valid_id, validate_request_timing,
    },
    webauthn_v1::{AssertionOutcomeV1, cose_p256_verifying_key},
};

/// Wire version reserved for contextual sudo authentication.
///
/// The legacy command protocol uses [`crate::VERSION_V1`] (`1`). Keeping the
/// numeric versions distinct matters because legacy serde structs ignore
/// unknown fields. A legacy peer therefore rejects an authentication envelope
/// during validation even if it attempts to decode it as a command.
pub const AUTH_WIRE_VERSION: u8 = 2;
pub const AUTH_ENVELOPE_TYPE: &str = "sudo_authentication";
pub const AUTH_REQUEST_TYPE: &str = "sudo_authentication_request";
pub const AUTH_NATIVE_DECISION_TYPE: &str = "sudo_authentication_native";
pub const AUTH_WEBAUTHN_DECISION_TYPE: &str = "sudo_authentication_webauthn";

const AUTH_CHALLENGE_DOMAIN: &[u8] = b"oshioki/authenticate/sudo/v1\0";
const MAX_SERVICE_BYTES: usize = 128;
const MAX_USER_BYTES: usize = 256;
const MAX_TTY_BYTES: usize = 4096;
const MAX_LABEL_BYTES: usize = 256;
const MAX_SESSION_BYTES: usize = 256;
const MAX_INVOCATION_STRING_BYTES: usize = 64 * 1024;
const MAX_INVOCATION_ARGS: usize = 4096;

/// Identity and PAM/process context captured by the trusted host-side module.
///
/// `pam_user`/`pam_uid` identify the account sudo authenticates. They may
/// differ from `invoking_uid`/`invoking_user` under sudo's rootpw, targetpw,
/// or runaspw policy. `invoking_user` is optional because name-service lookup
/// can fail; the numeric invoking UID remains explicit in that case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedAuthContextV1 {
    pub host: String,
    pub service: String,
    pub pam_user: String,
    pub pam_uid: u32,
    pub invoking_uid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invoking_user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tty: Option<String>,
}

impl TrustedAuthContextV1 {
    pub fn validate(&self) -> Result<(), Error> {
        if self.host.is_empty()
            || self.host.len() > 255
            || self.service.is_empty()
            || self.service.len() > MAX_SERVICE_BYTES
            || self.pam_user.is_empty()
            || self.pam_user.len() > MAX_USER_BYTES
            || self
                .invoking_user
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > MAX_USER_BYTES)
            || self
                .tty
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > MAX_TTY_BYTES)
        {
            return Err(Error::InvalidRequest(
                "invalid trusted authentication context".into(),
            ));
        }
        if self.host.chars().any(char::is_control)
            || self.service.chars().any(char::is_control)
            || self.pam_user.chars().any(char::is_control)
            || self
                .invoking_user
                .as_ref()
                .is_some_and(|value| value.chars().any(char::is_control))
            || self
                .tty
                .as_ref()
                .is_some_and(|value| value.chars().any(char::is_control))
        {
            return Err(Error::InvalidRequest(
                "trusted authentication context contains control characters".into(),
            ));
        }
        Ok(())
    }
}

/// Invocation context submitted for operator awareness.
///
/// The PAM API does not provide sudo's finalized `command_info`, `run_argv`,
/// or `run_envp`. This enum therefore makes missing and partial context
/// explicit. No variant means that a verifier may claim the signature
/// authorizes a particular final executable, argv, cwd, or environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AuthInvocationV1 {
    Available {
        command: String,
        argv: Vec<String>,
        cwd: String,
    },
    Truncated {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        command: Option<String>,
        argv: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        /// Number of omitted arguments when known. `None` is valid when a
        /// byte bound cut through an argument or omitted context without a
        /// reliable count.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        omitted_args: Option<u32>,
    },
    Unavailable,
}

impl AuthInvocationV1 {
    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Available { command, argv, cwd } => {
                if command.is_empty() || cwd.is_empty() {
                    return Err(Error::InvalidRequest(
                        "available invocation needs command and cwd".into(),
                    ));
                }
                validate_invocation_strings(command, cwd, argv)?;
            }
            Self::Truncated {
                command,
                argv,
                cwd,
                omitted_args,
            } => {
                if omitted_args.is_some_and(|count| count == 0) {
                    return Err(Error::InvalidRequest(
                        "truncated invocation omitted no arguments".into(),
                    ));
                }
                if command.as_ref().is_some_and(String::is_empty)
                    || cwd.as_ref().is_some_and(String::is_empty)
                {
                    return Err(Error::InvalidRequest(
                        "truncated invocation contains an empty optional field".into(),
                    ));
                }
                validate_invocation_strings(
                    command.as_deref().unwrap_or_default(),
                    cwd.as_deref().unwrap_or_default(),
                    argv,
                )?;
            }
            Self::Unavailable => {}
        }
        Ok(())
    }
}

fn validate_invocation_strings(command: &str, cwd: &str, argv: &[String]) -> Result<(), Error> {
    if command.len() > MAX_INVOCATION_STRING_BYTES
        || cwd.len() > MAX_INVOCATION_STRING_BYTES
        || argv.len() > MAX_INVOCATION_ARGS
        || argv
            .iter()
            .any(|arg| arg.len() > MAX_INVOCATION_STRING_BYTES)
        || command.contains('\0')
        || cwd.contains('\0')
        || argv.iter().any(|arg| arg.contains('\0'))
    {
        return Err(Error::InvalidRequest(
            "invocation exceeds bounds or contains NUL".into(),
        ));
    }
    Ok(())
}

/// Caller-supplied or host-resolved context shown with an authentication
/// request. These fields are signed, but remain distinct from trusted PAM
/// identity and from the final sudo execution payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmittedAuthContextV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_label: Option<String>,
    pub invocation: AuthInvocationV1,
}

impl SubmittedAuthContextV1 {
    pub fn validate(&self) -> Result<(), Error> {
        if self
            .session
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_SESSION_BYTES)
            || self
                .agent_label
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > MAX_LABEL_BYTES)
            || self
                .session
                .as_ref()
                .is_some_and(|value| value.chars().any(char::is_control))
            || self
                .agent_label
                .as_ref()
                .is_some_and(|value| value.chars().any(char::is_control))
        {
            return Err(Error::InvalidRequest(
                "invalid submitted authentication context".into(),
            ));
        }
        self.invocation.validate()
    }
}

/// The exact inner bytes that are authenticated by a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthRequestV1 {
    #[serde(rename = "type")]
    pub message_type: String,
    pub version: u8,
    pub request_id: String,
    pub nonce: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub trusted: TrustedAuthContextV1,
    pub submitted: SubmittedAuthContextV1,
}

impl AuthRequestV1 {
    pub fn validate(&self) -> Result<(), Error> {
        if self.message_type != AUTH_REQUEST_TYPE
            || self.version != AUTH_WIRE_VERSION
            || !valid_id(&self.request_id)
            || decode_exact(&self.nonce, 16).is_err()
            || self.expires_at <= self.issued_at
        {
            return Err(Error::InvalidRequest(
                "invalid authentication request header".into(),
            ));
        }
        self.trusted.validate()?;
        self.submitted.validate()?;
        Ok(())
    }

    pub fn validate_at(&self, now: i64) -> Result<(), Error> {
        self.validate()?;
        validate_request_timing(self.issued_at, self.expires_at, now)
    }

    pub fn raw_json(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let raw =
            serde_json::to_vec(self).map_err(|error| Error::InvalidRequest(error.to_string()))?;
        if raw.len() > MAX_REQUEST_BYTES {
            return Err(Error::InvalidRequest(
                "authentication request exceeds 256 KiB".into(),
            ));
        }
        Ok(raw)
    }
}

/// An opened authentication request retaining the exact decrypted bytes that
/// a hardware device must sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedAuthRequestV1 {
    pub request: AuthRequestV1,
    pub raw: Vec<u8>,
}

/// Public envelope for the separate authentication transport lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthEnvelopeV1 {
    #[serde(rename = "type")]
    pub message_type: String,
    pub version: u8,
    pub request_id: String,
    pub host: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub sealed: Vec<SealedDeviceBodyV1>,
}

impl AuthEnvelopeV1 {
    pub fn validate(&self) -> Result<(), Error> {
        if self.message_type != AUTH_ENVELOPE_TYPE
            || self.version != AUTH_WIRE_VERSION
            || !valid_id(&self.request_id)
            || self.host.is_empty()
            || self.host.len() > 255
            || self.host.chars().any(char::is_control)
            || self.sealed.is_empty()
            || self.sealed.len() > MAX_DEVICES
            || self.expires_at <= self.issued_at
        {
            return Err(Error::InvalidRequest(
                "invalid authentication envelope".into(),
            ));
        }
        let mut fingerprints = std::collections::BTreeSet::new();
        for body in &self.sealed {
            if !valid_fingerprint(&body.device_fingerprint)
                || !fingerprints.insert(&body.device_fingerprint)
                || decode_exact(&body.ephemeral_pub, 32).is_err()
                || decode_exact(&body.nonce, 12).is_err()
                || decode_base64url(&body.ciphertext)?.len() < 16
            {
                return Err(Error::InvalidRequest(
                    "invalid authentication sealed body".into(),
                ));
            }
        }
        let bytes =
            serde_json::to_vec(self).map_err(|error| Error::InvalidRequest(error.to_string()))?;
        if bytes.len() > crate::v1::MAX_ENVELOPE_BYTES {
            return Err(Error::InvalidRequest(
                "authentication envelope exceeds 3 MiB".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_at(&self, now: i64) -> Result<(), Error> {
        self.validate()?;
        validate_request_timing(self.issued_at, self.expires_at, now)
    }

    /// Opens the body addressed to one device and verifies that its trusted
    /// request metadata matches the untrusted routing envelope. A missing
    /// recipient is normal and returns `Ok(None)`.
    pub fn open_for_device(
        &self,
        device_fingerprint: &str,
        box_secret: &StaticSecret,
        now: i64,
    ) -> Result<Option<OpenedAuthRequestV1>, Error> {
        self.validate_at(now)?;
        let Some(sealed) = self
            .sealed
            .iter()
            .find(|body| body.device_fingerprint == device_fingerprint)
        else {
            return Ok(None);
        };
        let raw = crate::v1::unseal_v1(sealed, box_secret)?;
        let request = parse_auth_request_at(&raw, now)?;
        if request.request_id != self.request_id
            || request.trusted.host != self.host
            || request.issued_at != self.issued_at
            || request.expires_at != self.expires_at
        {
            return Err(Error::InvalidRequest(
                "sealed authentication request does not match its envelope".into(),
            ));
        }
        Ok(Some(OpenedAuthRequestV1 { request, raw }))
    }
}

/// A native Secure Enclave authentication assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthApproveNativeV1 {
    pub version: u8,
    pub request_id: String,
    pub device_fingerprint: String,
    pub signature: String,
}

impl AuthApproveNativeV1 {
    pub fn validate_shape(&self) -> Result<(), Error> {
        if self.version != AUTH_WIRE_VERSION
            || !valid_id(&self.request_id)
            || !valid_fingerprint(&self.device_fingerprint)
            || !(8..=256).contains(&decode_base64url(&self.signature)?.len())
        {
            return Err(Error::BadVerdict(
                "invalid native authentication approval shape".into(),
            ));
        }
        Ok(())
    }
}

/// A `WebAuthn` hardware-backed authentication assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthApproveWebauthnV1 {
    pub version: u8,
    pub request_id: String,
    pub device_fingerprint: String,
    pub credential_id: String,
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
}

impl AuthApproveWebauthnV1 {
    pub fn validate_shape(&self) -> Result<(), Error> {
        let authenticator_data = decode_base64url(&self.authenticator_data)?;
        let client_data = decode_base64url(&self.client_data_json)?;
        let signature = decode_base64url(&self.signature)?;
        if self.version != AUTH_WIRE_VERSION
            || !valid_id(&self.request_id)
            || !valid_fingerprint(&self.device_fingerprint)
            || decode_base64url(&self.credential_id)?.is_empty()
            || !(37..=1024).contains(&authenticator_data.len())
            || client_data.is_empty()
            || client_data.len() > 16 * 1024
            || !(8..=256).contains(&signature.len())
        {
            return Err(Error::BadVerdict(
                "invalid WebAuthn authentication approval shape".into(),
            ));
        }
        Ok(())
    }
}

/// New decision lane. The `type` tag is intentionally different from the
/// legacy `DecisionV1` `action` tag, so old consumers reject it at parse time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AuthDecisionV1 {
    #[serde(rename = "sudo_authentication_native")]
    AuthenticateNative(AuthApproveNativeV1),
    #[serde(rename = "sudo_authentication_webauthn")]
    AuthenticateWebauthn(AuthApproveWebauthnV1),
}

impl AuthDecisionV1 {
    pub fn validate_shape(&self) -> Result<(), Error> {
        match self {
            Self::AuthenticateNative(approval) => approval.validate_shape(),
            Self::AuthenticateWebauthn(approval) => approval.validate_shape(),
        }
    }
}

/// A domain-separated ECDSA challenge over the exact serialized auth request.
pub fn auth_challenge(raw_auth_request_json: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(AUTH_CHALLENGE_DOMAIN);
    hash.update(raw_auth_request_json);
    hash.finalize().into()
}

fn parse_auth_request_at(raw: &[u8], now: i64) -> Result<AuthRequestV1, Error> {
    if raw.len() > MAX_REQUEST_BYTES {
        return Err(Error::InvalidRequest(
            "authentication request exceeds 256 KiB".into(),
        ));
    }
    let request: AuthRequestV1 = serde_json::from_slice(raw).map_err(|error| {
        Error::InvalidRequest(format!("decode authentication request: {error}"))
    })?;
    request.validate_at(now)?;
    Ok(request)
}

/// Verifies a native authentication assertion against a pinned Secure Enclave
/// device record. The caller is responsible for selecting an active record
/// from the enrolled registry; this function deliberately verifies the pinned
/// record it is given and does not implement registry membership policy.
pub fn verify_native_authentication_v1(
    approval: &AuthApproveNativeV1,
    raw_auth_request_json: &[u8],
    device: &DevicePublicRecordV1,
    now: i64,
) -> Result<(), Error> {
    let request = parse_auth_request_at(raw_auth_request_json, now)?;
    approval.validate_shape()?;
    device.validate()?;
    if device.kind != DeviceKindV1::SecureEnclave
        || approval.device_fingerprint != device.fingerprint
        || approval.request_id != request.request_id
    {
        return Err(Error::BadVerdict(
            "native authentication does not match a Secure Enclave device or request".into(),
        ));
    }
    let key = crate::native_v1::sec1_p256_verifying_key(&decode_base64url(
        &device.credential_public_key,
    )?)?;
    let signature = Signature::from_der(&decode_base64url(&approval.signature)?)
        .map_err(|_| Error::InvalidSignature)?;
    key.verify(&auth_challenge(raw_auth_request_json), &signature)
        .map_err(|_| Error::InvalidSignature)
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    type_: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: bool,
}

/// Verifies a `WebAuthn` hardware assertion against a pinned `WebAuthn` device.
pub fn verify_webauthn_authentication_v1(
    approval: &AuthApproveWebauthnV1,
    raw_auth_request_json: &[u8],
    device: &DevicePublicRecordV1,
    config: &HookConfigV1,
    now: i64,
) -> Result<AssertionOutcomeV1, Error> {
    let request = parse_auth_request_at(raw_auth_request_json, now)?;
    config.validate()?;
    approval.validate_shape()?;
    device.validate()?;
    if device.kind != DeviceKindV1::Webauthn
        || approval.device_fingerprint != device.fingerprint
        || approval.credential_id != device.credential_id
        || approval.request_id != request.request_id
    {
        return Err(Error::BadVerdict(
            "WebAuthn authentication does not match a pinned hardware device or request".into(),
        ));
    }

    let client_data_json = decode_base64url(&approval.client_data_json)?;
    let client_data: ClientData =
        serde_json::from_slice(&client_data_json).map_err(|_| Error::MalformedClientData)?;
    if client_data.type_ != "webauthn.get" {
        return Err(Error::UnexpectedCredentialType);
    }
    if client_data.origin != config.origin || client_data.cross_origin {
        return Err(Error::BadOrigin);
    }
    let expected_challenge = URL_SAFE_NO_PAD.encode(auth_challenge(raw_auth_request_json));
    if client_data.challenge != expected_challenge {
        return Err(Error::BadChallenge);
    }

    let authenticator_data = decode_base64url(&approval.authenticator_data)?;
    if authenticator_data.len() < 37 {
        return Err(Error::MalformedAuthenticatorData);
    }
    let expected_rp_hash: [u8; 32] = Sha256::digest(config.rp_id.as_bytes()).into();
    if authenticator_data[..32] != expected_rp_hash {
        return Err(Error::BadRpId);
    }
    let flags = authenticator_data[32];
    if flags & 0x01 == 0 {
        return Err(Error::MissingUserPresence);
    }
    if flags & 0x04 == 0 {
        return Err(Error::MissingUserVerification);
    }

    let credential_public_key = decode_base64url(&device.credential_public_key)?;
    let verifying_key = cose_p256_verifying_key(&credential_public_key)?;
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data_json));
    let signature = Signature::from_der(&decode_base64url(&approval.signature)?)
        .map_err(|_| Error::InvalidSignature)?;
    verifying_key
        .verify(&signed, &signature)
        .map_err(|_| Error::InvalidSignature)?;

    let observed_sign_count = u32::from_be_bytes(
        authenticator_data[33..37]
            .try_into()
            .map_err(|_| Error::MalformedAuthenticatorData)?,
    );
    Ok(AssertionOutcomeV1 {
        observed_sign_count,
        counter_regressed: observed_sign_count > 0
            && device.sign_count > 0
            && observed_sign_count <= device.sign_count,
    })
}

/// Returns whether a pinned device has an accepted hardware assurance kind.
/// Software native devices are deliberately excluded.
pub fn is_hardware_auth_device(device: &DevicePublicRecordV1) -> bool {
    matches!(
        device.kind,
        DeviceKindV1::Webauthn | DeviceKindV1::SecureEnclave
    )
}

/// Selects active hardware devices as authentication envelope recipients.
/// The caller still owns registry validation and must pin the selected record
/// before verifying a returned assertion.
pub fn hardware_auth_recipients(registry: &DeviceRegistryV1) -> Vec<&DevicePublicRecordV1> {
    registry
        .devices
        .iter()
        .filter(|device| device.active && is_hardware_auth_device(device))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DecisionV1, RequestEnvelopeV1, VERSION_V1, approve_challenge, device_fingerprint,
        encode_base64url, seal_v1,
    };
    use p256::{
        ecdsa::{SigningKey, signature::Signer as _},
        elliptic_curve::rand_core::OsRng,
    };

    const NOW: i64 = 10_000;

    fn signing_key() -> SigningKey {
        SigningKey::random(&mut OsRng)
    }

    fn secure_enclave_device(key: &SigningKey, box_key: &[u8; 32]) -> DevicePublicRecordV1 {
        let point = key.verifying_key().to_encoded_point(false);
        let sec1 = point.as_bytes();
        let credential_id = crate::native_v1::native_credential_id(sec1);
        DevicePublicRecordV1 {
            version: VERSION_V1,
            kind: DeviceKindV1::SecureEnclave,
            fingerprint: device_fingerprint(&credential_id, sec1, box_key),
            credential_id: encode_base64url(&credential_id),
            credential_public_key: encode_base64url(sec1),
            box_public_key: encode_base64url(box_key),
            label: "enclave".into(),
            api_token_hash: encode_base64url(&[7; 32]),
            sign_count: 0,
            active: true,
        }
    }

    fn webauthn_fixture(key: &SigningKey) -> (DevicePublicRecordV1, HookConfigV1) {
        let point = key.verifying_key().to_encoded_point(false);
        let cose = vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Integer(2.into()),
            ),
            (
                ciborium::Value::Integer(3.into()),
                ciborium::Value::Integer((-7).into()),
            ),
            (
                ciborium::Value::Integer((-1).into()),
                ciborium::Value::Integer(1.into()),
            ),
            (
                ciborium::Value::Integer((-2).into()),
                ciborium::Value::Bytes(point.x().unwrap().to_vec()),
            ),
            (
                ciborium::Value::Integer((-3).into()),
                ciborium::Value::Bytes(point.y().unwrap().to_vec()),
            ),
        ];
        let mut cose_bytes = Vec::new();
        ciborium::ser::into_writer(&ciborium::Value::Map(cose), &mut cose_bytes).unwrap();
        let credential_id = vec![7; 32];
        let box_public = [8; 32];
        let device = DevicePublicRecordV1 {
            version: VERSION_V1,
            kind: DeviceKindV1::Webauthn,
            fingerprint: device_fingerprint(&credential_id, &cose_bytes, &box_public),
            credential_id: encode_base64url(&credential_id),
            credential_public_key: encode_base64url(&cose_bytes),
            box_public_key: encode_base64url(&box_public),
            label: "webauthn".into(),
            api_token_hash: encode_base64url(&[9; 32]),
            sign_count: 0,
            active: true,
        };
        let config = HookConfigV1 {
            version: VERSION_V1,
            origin: "https://sudo.example".into(),
            rp_id: "sudo.example".into(),
            server_base_url: "https://sudo.example".into(),
        };
        (device, config)
    }

    #[allow(clippy::too_many_arguments)]
    fn webauthn_approval(
        key: &SigningKey,
        _raw: &[u8],
        device: &DevicePublicRecordV1,
        _config: &HookConfigV1,
        client_type: &str,
        challenge: [u8; 32],
        origin: &str,
        rp_id: &str,
        flags: u8,
    ) -> AuthApproveWebauthnV1 {
        let client = format!(
            r#"{{"type":"{}","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
            client_type,
            URL_SAFE_NO_PAD.encode(challenge),
            origin,
        );
        let mut authenticator_data = Sha256::digest(rp_id.as_bytes()).to_vec();
        authenticator_data.push(flags);
        authenticator_data.extend_from_slice(&0_u32.to_be_bytes());
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(&Sha256::digest(client.as_bytes()));
        let signature: Signature = key.sign(&signed);
        AuthApproveWebauthnV1 {
            version: AUTH_WIRE_VERSION,
            request_id: "auth-1".into(),
            device_fingerprint: device.fingerprint.clone(),
            credential_id: device.credential_id.clone(),
            authenticator_data: encode_base64url(&authenticator_data),
            client_data_json: encode_base64url(client.as_bytes()),
            signature: encode_base64url(signature.to_der().as_bytes()),
        }
    }

    fn auth_request() -> AuthRequestV1 {
        AuthRequestV1 {
            message_type: AUTH_REQUEST_TYPE.into(),
            version: AUTH_WIRE_VERSION,
            request_id: "auth-1".into(),
            nonce: encode_base64url(&[3; 16]),
            issued_at: NOW,
            expires_at: NOW + 60,
            trusted: TrustedAuthContextV1 {
                host: "host.example".into(),
                service: "sudo".into(),
                pam_user: "root".into(),
                pam_uid: 0,
                invoking_uid: 1000,
                invoking_user: Some("eric".into()),
                tty: Some("/dev/ttys001".into()),
            },
            submitted: SubmittedAuthContextV1 {
                session: Some("session-1".into()),
                agent_label: Some("agent".into()),
                invocation: AuthInvocationV1::Available {
                    command: "/usr/bin/id".into(),
                    argv: vec!["id".into()],
                    cwd: "/tmp".into(),
                },
            },
        }
    }

    fn native_approval(
        key: &SigningKey,
        raw: &[u8],
        device: &DevicePublicRecordV1,
    ) -> AuthApproveNativeV1 {
        let signature: Signature = key.sign(&auth_challenge(raw));
        AuthApproveNativeV1 {
            version: AUTH_WIRE_VERSION,
            request_id: "auth-1".into(),
            device_fingerprint: device.fingerprint.clone(),
            signature: encode_base64url(signature.to_der().as_bytes()),
        }
    }

    #[test]
    fn authentication_requires_new_type_and_wire_version() {
        let raw = serde_json::to_vec(&auth_request()).unwrap();
        let request_as_command: Result<crate::RequestV1, _> = serde_json::from_slice(&raw);
        assert!(request_as_command.is_err());

        let envelope = AuthEnvelopeV1 {
            message_type: AUTH_ENVELOPE_TYPE.into(),
            version: AUTH_WIRE_VERSION,
            request_id: "auth-1".into(),
            host: "host.example".into(),
            issued_at: NOW,
            expires_at: NOW + 60,
            sealed: vec![],
        };
        assert!(envelope.validate().is_err());
        let envelope_bytes = serde_json::to_vec(&envelope).unwrap();
        let old: Result<RequestEnvelopeV1, _> = serde_json::from_slice(&envelope_bytes);
        assert!(old.is_err() || old.unwrap().validate().is_err());

        let decision = AuthDecisionV1::AuthenticateNative(AuthApproveNativeV1 {
            version: AUTH_WIRE_VERSION,
            request_id: "auth-1".into(),
            device_fingerprint: encode_base64url(&[8; 16]),
            signature: encode_base64url(&[9; 64]),
        });
        let decision_bytes = serde_json::to_vec(&decision).unwrap();
        let old_decision: Result<DecisionV1, _> = serde_json::from_slice(&decision_bytes);
        assert!(old_decision.is_err());
    }

    #[test]
    fn old_command_signature_cannot_authenticate_new_request() {
        let key = signing_key();
        let device = secure_enclave_device(&key, &[4; 32]);
        let raw = auth_request().raw_json().unwrap();
        let old_signature: Signature = key.sign(&approve_challenge(&raw));
        let approval = AuthApproveNativeV1 {
            version: AUTH_WIRE_VERSION,
            request_id: "auth-1".into(),
            device_fingerprint: device.fingerprint.clone(),
            signature: encode_base64url(old_signature.to_der().as_bytes()),
        };
        assert!(matches!(
            verify_native_authentication_v1(&approval, &raw, &device, NOW),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn native_authentication_binds_request_id_and_expiry() {
        let key = signing_key();
        let device = secure_enclave_device(&key, &[5; 32]);
        let raw = auth_request().raw_json().unwrap();
        let approval = native_approval(&key, &raw, &device);
        verify_native_authentication_v1(&approval, &raw, &device, NOW).unwrap();
        assert!(verify_native_authentication_v1(&approval, &raw, &device, NOW + 61).is_err());

        let mut crossed = approval.clone();
        crossed.request_id = "other".into();
        assert!(verify_native_authentication_v1(&crossed, &raw, &device, NOW).is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn webauthn_authentication_binds_purpose_challenge_origin_rp_and_uv() {
        let key = signing_key();
        let (device, config) = webauthn_fixture(&key);
        let raw = auth_request().raw_json().unwrap();
        let valid = webauthn_approval(
            &key,
            &raw,
            &device,
            &config,
            "webauthn.get",
            auth_challenge(&raw),
            &config.origin,
            &config.rp_id,
            0x05,
        );
        assert_eq!(
            verify_webauthn_authentication_v1(&valid, &raw, &device, &config, NOW)
                .unwrap()
                .observed_sign_count,
            0
        );

        let wrong_purpose = webauthn_approval(
            &key,
            &raw,
            &device,
            &config,
            "webauthn.create",
            auth_challenge(&raw),
            &config.origin,
            &config.rp_id,
            0x05,
        );
        assert!(matches!(
            verify_webauthn_authentication_v1(&wrong_purpose, &raw, &device, &config, NOW),
            Err(Error::UnexpectedCredentialType)
        ));

        let wrong_challenge = webauthn_approval(
            &key,
            &raw,
            &device,
            &config,
            "webauthn.get",
            approve_challenge(&raw),
            &config.origin,
            &config.rp_id,
            0x05,
        );
        assert!(matches!(
            verify_webauthn_authentication_v1(&wrong_challenge, &raw, &device, &config, NOW),
            Err(Error::BadChallenge)
        ));

        let wrong_origin = webauthn_approval(
            &key,
            &raw,
            &device,
            &config,
            "webauthn.get",
            auth_challenge(&raw),
            "https://evil.example",
            &config.rp_id,
            0x05,
        );
        assert!(matches!(
            verify_webauthn_authentication_v1(&wrong_origin, &raw, &device, &config, NOW),
            Err(Error::BadOrigin)
        ));

        let wrong_rp = webauthn_approval(
            &key,
            &raw,
            &device,
            &config,
            "webauthn.get",
            auth_challenge(&raw),
            &config.origin,
            "evil.example",
            0x05,
        );
        assert!(matches!(
            verify_webauthn_authentication_v1(&wrong_rp, &raw, &device, &config, NOW),
            Err(Error::BadRpId)
        ));

        let missing_uv = webauthn_approval(
            &key,
            &raw,
            &device,
            &config,
            "webauthn.get",
            auth_challenge(&raw),
            &config.origin,
            &config.rp_id,
            0x01,
        );
        assert!(matches!(
            verify_webauthn_authentication_v1(&missing_uv, &raw, &device, &config, NOW),
            Err(Error::MissingUserVerification)
        ));

        let software_key = signing_key();
        let mut software = secure_enclave_device(&software_key, &[12; 32]);
        software.kind = DeviceKindV1::Software;
        let software_assertion = webauthn_approval(
            &software_key,
            &raw,
            &software,
            &config,
            "webauthn.get",
            auth_challenge(&raw),
            &config.origin,
            &config.rp_id,
            0x05,
        );
        assert!(matches!(
            verify_webauthn_authentication_v1(&software_assertion, &raw, &software, &config, NOW),
            Err(Error::BadVerdict(_))
        ));
    }

    #[test]
    fn software_device_never_satisfies_native_authentication() {
        let key = signing_key();
        let mut device = secure_enclave_device(&key, &[6; 32]);
        device.kind = DeviceKindV1::Software;
        let raw = auth_request().raw_json().unwrap();
        let approval = native_approval(&key, &raw, &device);
        assert!(verify_native_authentication_v1(&approval, &raw, &device, NOW).is_err());

        let inactive = {
            let mut copy = secure_enclave_device(&key, &[7; 32]);
            copy.active = false;
            copy
        };
        let registry = DeviceRegistryV1 {
            version: VERSION_V1,
            devices: vec![device, inactive],
        };
        assert!(hardware_auth_recipients(&registry).is_empty());
    }

    #[test]
    fn auth_envelope_checks_inner_metadata_after_unseal() {
        let key = signing_key();
        let box_secret = StaticSecret::from([9; 32]);
        let box_public = x25519_dalek::PublicKey::from(&box_secret).to_bytes();
        let device = secure_enclave_device(&key, &box_public);
        let raw = auth_request().raw_json().unwrap();
        let sealed = seal_v1(&raw, &device).unwrap();
        let envelope = AuthEnvelopeV1 {
            message_type: AUTH_ENVELOPE_TYPE.into(),
            version: AUTH_WIRE_VERSION,
            request_id: "wrong-id".into(),
            host: "host.example".into(),
            issued_at: NOW,
            expires_at: NOW + 60,
            sealed: vec![sealed],
        };
        assert!(
            envelope
                .open_for_device(&device.fingerprint, &box_secret, NOW)
                .is_err()
        );

        let sealed = seal_v1(&raw, &device).unwrap();
        let envelope = AuthEnvelopeV1 {
            message_type: AUTH_ENVELOPE_TYPE.into(),
            version: AUTH_WIRE_VERSION,
            request_id: "auth-1".into(),
            host: "host.example".into(),
            issued_at: NOW,
            expires_at: NOW + 60,
            sealed: vec![sealed],
        };
        let opened = envelope
            .open_for_device(&device.fingerprint, &box_secret, NOW)
            .unwrap()
            .unwrap();
        assert_eq!(opened.request.request_id, "auth-1");
    }

    #[test]
    fn opened_auth_request_retains_exact_decrypted_bytes_for_signing() {
        let key = signing_key();
        let box_secret = StaticSecret::from([10; 32]);
        let box_public = x25519_dalek::PublicKey::from(&box_secret).to_bytes();
        let device = secure_enclave_device(&key, &box_public);
        let canonical = auth_request().raw_json().unwrap();
        let mut raw = b" \n".to_vec();
        raw.extend_from_slice(&canonical);
        raw.extend_from_slice(b" \n");
        let sealed = seal_v1(&raw, &device).unwrap();
        let envelope = AuthEnvelopeV1 {
            message_type: AUTH_ENVELOPE_TYPE.into(),
            version: AUTH_WIRE_VERSION,
            request_id: "auth-1".into(),
            host: "host.example".into(),
            issued_at: NOW,
            expires_at: NOW + 60,
            sealed: vec![sealed],
        };
        let opened = envelope
            .open_for_device(&device.fingerprint, &box_secret, NOW)
            .unwrap()
            .unwrap();
        assert_eq!(opened.raw, raw);
        let approval = native_approval(&key, &opened.raw, &device);
        verify_native_authentication_v1(&approval, &opened.raw, &device, NOW).unwrap();
    }

    #[test]
    fn invocation_status_makes_missing_context_explicit_and_bounded() {
        let unavailable = AuthInvocationV1::Unavailable;
        unavailable.validate().unwrap();
        let truncated = AuthInvocationV1::Truncated {
            command: Some("sudo\t".into()),
            argv: vec!["sudo\n".into()],
            cwd: None,
            omitted_args: None,
        };
        truncated.validate().unwrap();
        let invalid = AuthInvocationV1::Truncated {
            command: None,
            argv: vec!["sudo".into()],
            cwd: None,
            omitted_args: Some(0),
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn challenge_is_domain_separated_from_command_approval() {
        let raw = auth_request().raw_json().unwrap();
        assert_ne!(auth_challenge(&raw), approve_challenge(&raw));
    }
}
