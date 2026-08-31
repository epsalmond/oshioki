//! `WebAuthn` assertion verification for version one approvals.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{
    Error,
    v1::{
        ApproveV1, DevicePublicRecordV1, HookConfigV1, VERSION_V1, approve_challenge,
        decode_base64url,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssertionOutcomeV1 {
    pub observed_sign_count: u32,
    pub counter_regressed: bool,
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

pub fn verify_approval_v1(
    approval: &ApproveV1,
    raw_request_json: &[u8],
    device: &DevicePublicRecordV1,
    config: &HookConfigV1,
) -> Result<AssertionOutcomeV1, Error> {
    config.validate()?;
    device.validate()?;
    if approval.version != VERSION_V1
        || approval.request_id.is_empty()
        || approval.device_fingerprint != device.fingerprint
        || approval.credential_id != device.credential_id
    {
        return Err(Error::BadVerdict(
            "approval record does not match pinned device".into(),
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
    let challenge = URL_SAFE_NO_PAD.encode(approve_challenge(raw_request_json));
    if client_data.challenge != challenge {
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

pub fn cose_p256_verifying_key(cose_bytes: &[u8]) -> Result<VerifyingKey, Error> {
    let value: serde_cbor::Value =
        serde_cbor::from_slice(cose_bytes).map_err(|_| Error::InvalidSignature)?;
    let serde_cbor::Value::Map(entries) = value else {
        return Err(Error::InvalidSignature);
    };
    let mut kty = None;
    let mut alg = None;
    let mut crv = None;
    let mut x = None;
    let mut y = None;
    for (key, value) in entries {
        let serde_cbor::Value::Integer(label) = key else {
            continue;
        };
        match (label, value) {
            (1, serde_cbor::Value::Integer(value)) => kty = Some(value),
            (3, serde_cbor::Value::Integer(value)) => alg = Some(value),
            (-1, serde_cbor::Value::Integer(value)) => crv = Some(value),
            (-2, serde_cbor::Value::Bytes(value)) => x = Some(value),
            (-3, serde_cbor::Value::Bytes(value)) => y = Some(value),
            _ => {}
        }
    }
    if kty != Some(2) || alg != Some(-7) || crv != Some(1) {
        return Err(Error::InvalidSignature);
    }
    let (Some(x), Some(y)) = (x, y) else {
        return Err(Error::InvalidSignature);
    };
    if x.len() != 32 || y.len() != 32 {
        return Err(Error::InvalidSignature);
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(4);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| Error::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::{device_fingerprint, encode_base64url};
    use p256::{
        ecdsa::{SigningKey, signature::Signer as _},
        elliptic_curve::rand_core::OsRng,
    };
    use std::collections::BTreeMap;

    fn fixture() -> (SigningKey, DevicePublicRecordV1, HookConfigV1) {
        let signing = SigningKey::random(&mut OsRng);
        let point = signing.verifying_key().to_encoded_point(false);
        let mut cose = BTreeMap::new();
        cose.insert(serde_cbor::Value::Integer(1), serde_cbor::Value::Integer(2));
        cose.insert(
            serde_cbor::Value::Integer(3),
            serde_cbor::Value::Integer(-7),
        );
        cose.insert(
            serde_cbor::Value::Integer(-1),
            serde_cbor::Value::Integer(1),
        );
        cose.insert(
            serde_cbor::Value::Integer(-2),
            serde_cbor::Value::Bytes(point.x().unwrap().to_vec()),
        );
        cose.insert(
            serde_cbor::Value::Integer(-3),
            serde_cbor::Value::Bytes(point.y().unwrap().to_vec()),
        );
        let cose = serde_cbor::to_vec(&serde_cbor::Value::Map(cose)).unwrap();
        let credential_id = vec![7; 32];
        let box_key = vec![8; 32];
        let fp = device_fingerprint(&credential_id, &cose, &box_key);
        let device = DevicePublicRecordV1 {
            version: 1,
            fingerprint: fp,
            credential_id: encode_base64url(&credential_id),
            credential_public_key: encode_base64url(&cose),
            box_public_key: encode_base64url(&box_key),
            label: "test".into(),
            api_token_hash: encode_base64url(&[9; 32]),
            sign_count: 4,
            active: true,
        };
        let config = HookConfigV1 {
            version: 1,
            origin: "https://sudo.example".into(),
            rp_id: "sudo.example".into(),
            server_base_url: "https://sudo.example".into(),
        };
        (signing, device, config)
    }

    fn signed(
        raw: &[u8],
        signing: &SigningKey,
        device: &DevicePublicRecordV1,
        config: &HookConfigV1,
        cross_origin: bool,
        count: u32,
    ) -> ApproveV1 {
        let client = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}","crossOrigin":{}}}"#,
            URL_SAFE_NO_PAD.encode(approve_challenge(raw)),
            config.origin,
            cross_origin
        );
        let mut auth = Sha256::digest(config.rp_id.as_bytes()).to_vec();
        auth.push(0x05);
        auth.extend_from_slice(&count.to_be_bytes());
        let mut message = auth.clone();
        message.extend_from_slice(&Sha256::digest(client.as_bytes()));
        let signature: Signature = signing.sign(&message);
        ApproveV1 {
            version: 1,
            request_id: "request-1".into(),
            device_fingerprint: device.fingerprint.clone(),
            credential_id: device.credential_id.clone(),
            authenticator_data: encode_base64url(&auth),
            client_data_json: encode_base64url(client.as_bytes()),
            signature: encode_base64url(signature.to_der().as_bytes()),
        }
    }

    #[test]
    fn validates_exact_bytes_and_reports_counter_regression() {
        let (signing, device, config) = fixture();
        let raw = br#"{"version":1,"request_id":"request-1"}"#;
        let approval = signed(raw, &signing, &device, &config, false, 3);
        let result = verify_approval_v1(&approval, raw, &device, &config).unwrap();
        assert!(result.counter_regressed);
        assert!(verify_approval_v1(&approval, b"different", &device, &config).is_err());
    }

    #[test]
    fn rejects_cross_origin() {
        let (signing, device, config) = fixture();
        let raw = b"request";
        let approval = signed(raw, &signing, &device, &config, true, 0);
        assert!(matches!(
            verify_approval_v1(&approval, raw, &device, &config),
            Err(Error::BadOrigin)
        ));
    }

    #[test]
    fn registry_rejects_duplicate_credential_id() {
        let (_, first, _) = fixture();
        let mut second = first.clone();
        let box_key = [10; 32];
        second.box_public_key = encode_base64url(&box_key);
        second.fingerprint = device_fingerprint(
            &decode_base64url(&second.credential_id).unwrap(),
            &decode_base64url(&second.credential_public_key).unwrap(),
            &box_key,
        );
        let registry = crate::DeviceRegistryV1 {
            version: 1,
            devices: vec![first, second],
        };
        assert!(registry.validate().is_err());
    }
}
