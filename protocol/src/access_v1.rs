//! Timed credential access is a separate purpose from sudo and tool approval.
//! The broker verifies requester identity; a pinned hardware device authorizes
//! these exact bytes. Ceremony expiry never becomes the grant duration.

use p256::ecdsa::{Signature, signature::Verifier as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use x25519_dalek::StaticSecret;

use crate::v1::{decode_base64url, valid_id};
use crate::{DeviceKindV1, DevicePublicRecordV1, Error, HookConfigV1, SealedDeviceBodyV1};

pub const ACCESS_VERSION: u8 = 4;
pub const ACCESS_REQUEST_TYPE: &str = "credential_access_request";
pub const ACCESS_ENVELOPE_TYPE: &str = "credential_access";
pub const DEFAULT_ACCESS_SECONDS: u32 = 300;
pub const MAX_ACCESS_SECONDS: u32 = 3600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessRequestV1 {
    #[serde(rename = "type")]
    pub message_type: String,
    pub version: u8,
    pub audience: String,
    pub principal: String,
    pub host: String,
    pub vault: String,
    pub service: String,
    pub purpose: String,
    pub duration_seconds: u32,
    pub request_id: String,
    pub nonce: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

impl AccessRequestV1 {
    pub fn validate_at(&self, now: i64) -> Result<(), Error> {
        if self.message_type != ACCESS_REQUEST_TYPE
            || self.version != ACCESS_VERSION
            || !valid_id(&self.request_id)
            || decode_base64url(&self.nonce)?.len() != 32
            || !(1..=MAX_ACCESS_SECONDS).contains(&self.duration_seconds)
            || [
                &self.audience,
                &self.principal,
                &self.host,
                &self.vault,
                &self.service,
                &self.purpose,
            ]
            .into_iter()
            .any(|s| s.is_empty() || s.len() > 1024 || s.chars().any(char::is_control))
        {
            return Err(Error::InvalidRequest(
                "invalid credential access request".into(),
            ));
        }
        if self.expires_at <= self.issued_at
            || self.expires_at <= now
            || self.issued_at > now.saturating_add(5)
            || self
                .expires_at
                .checked_sub(self.issued_at)
                .is_none_or(|lifetime| lifetime > 90)
        {
            return Err(Error::InvalidRequest(
                "invalid or expired access ceremony".into(),
            ));
        }
        Ok(())
    }
}

pub fn parse_access_request_at(raw: &[u8], now: i64) -> Result<AccessRequestV1, Error> {
    if raw.len() > 16 * 1024 {
        return Err(Error::InvalidRequest("access request too large".into()));
    }
    let request: AccessRequestV1 =
        serde_json::from_slice(raw).map_err(|e| Error::InvalidRequest(e.to_string()))?;
    request.validate_at(now)?;
    Ok(request)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessEnvelopeV1 {
    #[serde(rename = "type")]
    pub message_type: String,
    pub version: u8,
    pub request_id: String,
    pub sealed: Vec<SealedDeviceBodyV1>,
}

impl AccessEnvelopeV1 {
    pub fn open(
        &self,
        fingerprint: &str,
        secret: &StaticSecret,
        now: i64,
    ) -> Result<Option<(AccessRequestV1, Vec<u8>)>, Error> {
        if self.message_type != ACCESS_ENVELOPE_TYPE
            || self.version != ACCESS_VERSION
            || !valid_id(&self.request_id)
            || self.sealed.len() > crate::v1::MAX_DEVICES
        {
            return Err(Error::InvalidRequest("invalid access envelope".into()));
        }
        let Some(body) = self
            .sealed
            .iter()
            .find(|b| b.device_fingerprint == fingerprint)
        else {
            return Ok(None);
        };
        let raw = crate::unseal_v1(body, secret)?;
        let request = parse_access_request_at(&raw, now)?;
        if request.request_id != self.request_id {
            return Err(Error::InvalidRequest("access envelope id mismatch".into()));
        }
        Ok(Some((request, raw)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AccessDecisionV1 {
    #[serde(rename = "credential_access_native")]
    Native {
        version: u8,
        request_id: String,
        device_fingerprint: String,
        signature: String,
    },
    #[serde(rename = "credential_access_webauthn")]
    Webauthn(crate::auth_v1::AuthApproveWebauthnV1),
}

impl AccessDecisionV1 {
    pub fn fingerprint(&self) -> &str {
        match self {
            Self::Native {
                device_fingerprint, ..
            } => device_fingerprint,
            Self::Webauthn(assertion) => &assertion.device_fingerprint,
        }
    }
}

pub fn access_challenge(raw: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"oshioki/credential-access/approve/v1\0");
    hash.update(raw);
    hash.finalize().into()
}

pub fn verify_access_decision(
    decision: &AccessDecisionV1,
    raw: &[u8],
    device: &DevicePublicRecordV1,
    config: &HookConfigV1,
    now: i64,
) -> Result<(), Error> {
    let request = parse_access_request_at(raw, now)?;
    device.validate()?;
    if !device.active || decision.fingerprint() != device.fingerprint {
        return Err(Error::BadVerdict(
            "access approver is not active or pinned".into(),
        ));
    }
    match decision {
        AccessDecisionV1::Native {
            version,
            request_id,
            signature,
            ..
        } => {
            if *version != ACCESS_VERSION
                || *request_id != request.request_id
                || device.kind != DeviceKindV1::SecureEnclave
            {
                return Err(Error::BadVerdict(
                    "wrong access purpose or device kind".into(),
                ));
            }
            let key =
                crate::sec1_p256_verifying_key(&decode_base64url(&device.credential_public_key)?)?;
            let sig = Signature::from_der(&decode_base64url(signature)?)
                .map_err(|_| Error::InvalidSignature)?;
            key.verify(&access_challenge(raw), &sig)
                .map_err(|_| Error::InvalidSignature)
        }
        AccessDecisionV1::Webauthn(assertion) => {
            if assertion.version != ACCESS_VERSION
                || assertion.request_id != request.request_id
                || device.kind != DeviceKindV1::Webauthn
                || assertion.credential_id != device.credential_id
            {
                return Err(Error::BadVerdict(
                    "wrong access assertion or credential".into(),
                ));
            }
            let mut shape = assertion.clone();
            shape.version = crate::AUTH_WIRE_VERSION;
            shape.validate_shape()?;
            let outcome = crate::auth_v1::verify_webauthn_challenge(
                assertion,
                device,
                config,
                &access_challenge(raw),
            )?;
            if outcome.counter_regressed {
                return Err(Error::BadVerdict(
                    "access assertion counter regressed".into(),
                ));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VERSION_V1, device_fingerprint, encode_base64url};
    use p256::ecdsa::{SigningKey, signature::Signer as _};

    fn fixture() -> (SigningKey, DevicePublicRecordV1, HookConfigV1, Vec<u8>) {
        let key = SigningKey::from_slice(&[11; 32]).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let id = crate::native_credential_id(point.as_bytes());
        let device = DevicePublicRecordV1 {
            version: VERSION_V1,
            kind: DeviceKindV1::SecureEnclave,
            fingerprint: device_fingerprint(&id, point.as_bytes(), &[7; 32]),
            credential_id: encode_base64url(&id),
            credential_public_key: encode_base64url(point.as_bytes()),
            box_public_key: encode_base64url(&[7; 32]),
            api_token_hash: encode_base64url(&[8; 32]),
            label: "test hardware".into(),
            sign_count: 0,
            active: true,
        };
        let config = HookConfigV1 {
            version: VERSION_V1,
            server_base_url: "https://approvals.example".into(),
            rp_id: "approvals.example".into(),
            origin: "https://approvals.example".into(),
        };
        let r = AccessRequestV1 {
            message_type: ACCESS_REQUEST_TYPE.into(),
            version: ACCESS_VERSION,
            audience: "test-broker".into(),
            principal: "SSH:key".into(),
            host: "test-host".into(),
            vault: "default".into(),
            service: "catalog".into(),
            purpose: "read diagnostic".into(),
            duration_seconds: DEFAULT_ACCESS_SECONDS,
            request_id: "access-1".into(),
            nonce: encode_base64url(&[9; 32]),
            issued_at: 1000,
            expires_at: 1090,
        };
        (key, device, config, serde_json::to_vec(&r).unwrap())
    }

    fn decision(key: &SigningKey, device: &DevicePublicRecordV1, raw: &[u8]) -> AccessDecisionV1 {
        let sig: Signature = key.sign(&access_challenge(raw));
        AccessDecisionV1::Native {
            version: ACCESS_VERSION,
            request_id: "access-1".into(),
            device_fingerprint: device.fingerprint.clone(),
            signature: encode_base64url(sig.to_der().as_bytes()),
        }
    }

    #[test]
    fn access_binds_exact_scope_hardware_pin_and_separate_purpose() {
        let (key, device, config, raw) = fixture();
        let answer = decision(&key, &device, &raw);
        // Full 90-second ceremony, including an approval after the sudo
        // ingress skew window, is distinct from the 5-minute access lease.
        verify_access_decision(&answer, &raw, &device, &config, 1060).unwrap();
        for field in [
            "audience",
            "principal",
            "host",
            "vault",
            "service",
            "purpose",
            "request_id",
            "nonce",
        ] {
            let mut request: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            request[field] = serde_json::Value::String("different".into());
            assert!(
                verify_access_decision(
                    &answer,
                    &serde_json::to_vec(&request).unwrap(),
                    &device,
                    &config,
                    1001
                )
                .is_err(),
                "{field}"
            );
        }
        let mut request: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        request["duration_seconds"] = 600.into();
        assert!(
            verify_access_decision(
                &answer,
                &serde_json::to_vec(&request).unwrap(),
                &device,
                &config,
                1001
            )
            .is_err()
        );
        let wrong = SigningKey::from_slice(&[12; 32]).unwrap();
        assert!(
            verify_access_decision(
                &decision(&wrong, &device, &raw),
                &raw,
                &device,
                &config,
                1001
            )
            .is_err()
        );
        let mut inactive = device.clone();
        inactive.active = false;
        assert!(verify_access_decision(&answer, &raw, &inactive, &config, 1001).is_err());
        let mut software = device.clone();
        software.kind = DeviceKindV1::Software;
        assert!(verify_access_decision(&answer, &raw, &software, &config, 1001).is_err());
        let sig: Signature = key.sign(&crate::approve_challenge(&raw));
        let sudo_signature = AccessDecisionV1::Native {
            version: ACCESS_VERSION,
            request_id: "access-1".into(),
            device_fingerprint: device.fingerprint.clone(),
            signature: encode_base64url(sig.to_der().as_bytes()),
        };
        assert!(verify_access_decision(&sudo_signature, &raw, &device, &config, 1001).is_err());
        assert!(verify_access_decision(&answer, &raw, &device, &config, 1090).is_err());
    }

    #[test]
    fn duration_and_ceremony_limits_are_independent() {
        let (_, _, _, raw) = fixture();
        let mut request: AccessRequestV1 = serde_json::from_slice(&raw).unwrap();
        request.duration_seconds = MAX_ACCESS_SECONDS;
        request.validate_at(1001).unwrap();
        request.duration_seconds = MAX_ACCESS_SECONDS + 1;
        assert!(request.validate_at(1001).is_err());
        request.duration_seconds = 0;
        assert!(request.validate_at(1001).is_err());
        request.duration_seconds = DEFAULT_ACCESS_SECONDS;
        request.expires_at = 1091;
        assert!(request.validate_at(1001).is_err());
    }

    fn webauthn_device(key: &SigningKey) -> DevicePublicRecordV1 {
        let point = key.verifying_key().to_encoded_point(false);
        let public = ciborium::Value::Map(vec![
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
        ]);
        let mut cose = Vec::new();
        ciborium::ser::into_writer(&public, &mut cose).unwrap();
        let id = vec![1, 2, 3];
        DevicePublicRecordV1 {
            version: VERSION_V1,
            kind: DeviceKindV1::Webauthn,
            fingerprint: device_fingerprint(&id, &cose, &[7; 32]),
            credential_id: encode_base64url(&id),
            credential_public_key: encode_base64url(&cose),
            box_public_key: encode_base64url(&[7; 32]),
            api_token_hash: encode_base64url(&[8; 32]),
            label: "test passkey".into(),
            sign_count: 0,
            active: true,
        }
    }

    fn webauthn_answer(
        key: &SigningKey,
        device: &DevicePublicRecordV1,
        config: &HookConfigV1,
        raw: &[u8],
        flags: u8,
        challenge: [u8; 32],
    ) -> AccessDecisionV1 {
        let client = serde_json::to_vec(
            &serde_json::json!({"type":"webauthn.get","origin":config.origin,
            "challenge":encode_base64url(&challenge),"crossOrigin":false}),
        )
        .unwrap();
        let mut auth = Sha256::digest(config.rp_id.as_bytes()).to_vec();
        auth.push(flags);
        auth.extend_from_slice(&1u32.to_be_bytes());
        let mut signed = auth.clone();
        signed.extend_from_slice(&Sha256::digest(&client));
        let sig: Signature = key.sign(&signed);
        let request = parse_access_request_at(raw, 1001).unwrap();
        AccessDecisionV1::Webauthn(crate::auth_v1::AuthApproveWebauthnV1 {
            version: ACCESS_VERSION,
            request_id: request.request_id,
            device_fingerprint: device.fingerprint.clone(),
            credential_id: device.credential_id.clone(),
            authenticator_data: encode_base64url(&auth),
            client_data_json: encode_base64url(&client),
            signature: encode_base64url(sig.to_der().as_bytes()),
        })
    }

    #[test]
    fn access_webauthn_reuses_origin_rp_uv_and_purpose_verification() {
        let (key, _, config, raw) = fixture();
        let device = webauthn_device(&key);
        let answer = webauthn_answer(&key, &device, &config, &raw, 0x05, access_challenge(&raw));
        verify_access_decision(&answer, &raw, &device, &config, 1001).unwrap();
        let no_uv = webauthn_answer(&key, &device, &config, &raw, 0x01, access_challenge(&raw));
        assert!(verify_access_decision(&no_uv, &raw, &device, &config, 1001).is_err());
        let sudo = webauthn_answer(
            &key,
            &device,
            &config,
            &raw,
            0x05,
            crate::auth_challenge(&raw),
        );
        assert!(verify_access_decision(&sudo, &raw, &device, &config, 1001).is_err());
        let mut other_origin = config.clone();
        other_origin.origin = "https://other.example".into();
        other_origin.server_base_url = other_origin.origin.clone();
        assert!(verify_access_decision(&answer, &raw, &device, &other_origin, 1001).is_err());
        let mut other_rp = config.clone();
        other_rp.rp_id = "other.example".into();
        assert!(verify_access_decision(&answer, &raw, &device, &other_rp, 1001).is_err());
    }
}
