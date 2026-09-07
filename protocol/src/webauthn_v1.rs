//! `WebAuthn` assertion verification for version one approvals.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ciborium::Value;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::Cursor;

use crate::{
    Error,
    v1::{
        ApproveV1, DeviceKindV1, DevicePublicRecordV1, HookConfigV1, VERSION_V1, approve_challenge,
        decode_base64url,
    },
};

/// Maximum encoded size accepted for a `WebAuthn` attestation object.
pub(crate) const MAX_ATTESTATION_CBOR_BYTES: usize = 128 * 1024;
/// COSE keys are small maps. Keep malformed persisted records from allocating
/// unbounded memory while decoding them.
pub(crate) const MAX_COSE_CBOR_BYTES: usize = 4 * 1024;
pub(crate) const MAX_CBOR_DEPTH: usize = 16;
pub(crate) const MAX_CBOR_ITEMS: usize = 256;

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
        || device.kind != DeviceKindV1::Webauthn
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
    let value =
        decode_cbor_value(cose_bytes, MAX_COSE_CBOR_BYTES).map_err(|()| Error::InvalidSignature)?;
    let Value::Map(entries) = value else {
        return Err(Error::InvalidSignature);
    };
    let mut kty = None;
    let mut alg = None;
    let mut crv = None;
    let mut x = None;
    let mut y = None;
    for (key, value) in entries {
        let Value::Integer(label) = key else {
            continue;
        };
        match (label, value) {
            (label, Value::Integer(value)) if label == 1.into() => kty = Some(value),
            (label, Value::Integer(value)) if label == 3.into() => alg = Some(value),
            (label, Value::Integer(value)) if label == (-1).into() => crv = Some(value),
            (label, Value::Bytes(value)) if label == (-2).into() => x = Some(value),
            (label, Value::Bytes(value)) if label == (-3).into() => y = Some(value),
            _ => {}
        }
    }
    if kty != Some(2.into()) || alg != Some((-7).into()) || crv != Some(1.into()) {
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

/// Decode exactly one bounded CBOR value and reject duplicate map keys.
///
/// `ciborium` supplies a recursion limit, while the value walk bounds the
/// total number of nodes and catches duplicate keys without relying on a map
/// implementation that might silently overwrite them. The cursor check is
/// deliberately kept outside the decoder: serde decoders generally consume
/// one value, so accepting an unexamined suffix would make the signed data
/// ambiguous.
pub(crate) fn decode_cbor_value(bytes: &[u8], max_bytes: usize) -> Result<Value, ()> {
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(());
    }
    let mut cursor = Cursor::new(bytes);
    let value =
        ciborium::de::from_reader_with_recursion_limit::<Value, _>(&mut cursor, MAX_CBOR_DEPTH)
            .map_err(|_| ())?;
    if usize::try_from(cursor.position()).map_err(|_| ())? != bytes.len() {
        return Err(());
    }
    let mut item_count = 0;
    validate_cbor_value(&value, 0, &mut item_count)?;
    Ok(value)
}

fn validate_cbor_value(value: &Value, depth: usize, item_count: &mut usize) -> Result<(), ()> {
    if depth > MAX_CBOR_DEPTH {
        return Err(());
    }
    *item_count = item_count.checked_add(1).ok_or(())?;
    if *item_count > MAX_CBOR_ITEMS {
        return Err(());
    }
    match value {
        Value::Tag(_, value) => validate_cbor_value(value, depth + 1, item_count),
        Value::Array(values) => values
            .iter()
            .try_for_each(|value| validate_cbor_value(value, depth + 1, item_count)),
        Value::Map(entries) => {
            for (index, (key, value)) in entries.iter().enumerate() {
                if entries[..index]
                    .iter()
                    .any(|(previous, _)| cbor_values_equal(previous, key))
                {
                    return Err(());
                }
                validate_cbor_value(key, depth + 1, item_count)?;
                validate_cbor_value(value, depth + 1, item_count)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

// CBOR map keys are values, and maps are unordered. `Value`'s derived
// equality compares map entry order, so compare nested maps as sets here.
fn cbor_values_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Integer(left), Value::Integer(right)) => left == right,
        (Value::Bytes(left), Value::Bytes(right)) => left == right,
        (Value::Text(left), Value::Text(right)) => left == right,
        (Value::Float(left), Value::Float(right)) => left.to_bits() == right.to_bits(),
        (Value::Bool(left), Value::Bool(right)) => left == right,
        (Value::Null, Value::Null) => true,
        (Value::Tag(left_tag, left), Value::Tag(right_tag, right)) => {
            left_tag == right_tag && cbor_values_equal(left, right)
        }
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| cbor_values_equal(left, right))
        }
        (Value::Map(left), Value::Map(right)) => {
            if left.len() != right.len() {
                return false;
            }
            let mut matched = vec![false; right.len()];
            left.iter().all(|(left_key, left_value)| {
                right
                    .iter()
                    .enumerate()
                    .any(|(index, (right_key, right_value))| {
                        !matched[index]
                            && cbor_values_equal(left_key, right_key)
                            && cbor_values_equal(left_value, right_value)
                            && {
                                matched[index] = true;
                                true
                            }
                    })
            })
        }
        _ => false,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::v1::{device_fingerprint, encode_base64url};
    use p256::{
        ecdsa::{SigningKey, signature::Signer as _},
        elliptic_curve::rand_core::OsRng,
    };

    /// Encodes a P-256 point as a COSE ES256 key, for fixtures.
    pub(crate) fn cose_key(x: &[u8], y: &[u8]) -> Vec<u8> {
        let cose = vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(3.into()), Value::Integer((-7).into())),
            (Value::Integer((-1).into()), Value::Integer(1.into())),
            (Value::Integer((-2).into()), Value::Bytes(x.to_vec())),
            (Value::Integer((-3).into()), Value::Bytes(y.to_vec())),
        ];
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&Value::Map(cose), &mut encoded).unwrap();
        encoded
    }

    fn fixture() -> (SigningKey, DevicePublicRecordV1, HookConfigV1) {
        let signing = SigningKey::random(&mut OsRng);
        let point = signing.verifying_key().to_encoded_point(false);
        let cose = cose_key(point.x().unwrap(), point.y().unwrap());
        let credential_id = vec![7; 32];
        let box_key = vec![8; 32];
        let fp = device_fingerprint(&credential_id, &cose, &box_key);
        let device = DevicePublicRecordV1 {
            version: 1,
            kind: DeviceKindV1::Webauthn,
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
        flags: u8,
        count: u32,
    ) -> ApproveV1 {
        let client = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}","crossOrigin":{}}}"#,
            URL_SAFE_NO_PAD.encode(approve_challenge(raw)),
            config.origin,
            cross_origin
        );
        let mut auth = Sha256::digest(config.rp_id.as_bytes()).to_vec();
        auth.push(flags);
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
        let approval = signed(raw, &signing, &device, &config, false, 0x05, 3);
        let result = verify_approval_v1(&approval, raw, &device, &config).unwrap();
        assert!(result.counter_regressed);
        assert!(verify_approval_v1(&approval, b"different", &device, &config).is_err());
    }

    #[test]
    fn rejects_cross_origin() {
        let (signing, device, config) = fixture();
        let raw = b"request";
        let approval = signed(raw, &signing, &device, &config, true, 0x05, 0);
        assert!(matches!(
            verify_approval_v1(&approval, raw, &device, &config),
            Err(Error::BadOrigin)
        ));
    }

    #[test]
    fn rejects_wrong_origin() {
        let (signing, device, config) = fixture();
        let raw = b"request";
        let approval = signed(raw, &signing, &device, &config, false, 0x05, 0);
        let mut wrong = config.clone();
        wrong.origin = "https://other.example".into();
        wrong.server_base_url = wrong.origin.clone();
        assert!(matches!(
            verify_approval_v1(&approval, raw, &device, &wrong),
            Err(Error::BadOrigin)
        ));
    }

    #[test]
    fn rejects_wrong_rp_id() {
        let (signing, device, config) = fixture();
        let raw = b"request";
        let approval = signed(raw, &signing, &device, &config, false, 0x05, 0);
        let mut wrong = config.clone();
        wrong.rp_id = "other.example".into();
        assert!(matches!(
            verify_approval_v1(&approval, raw, &device, &wrong),
            Err(Error::BadRpId)
        ));
    }

    #[test]
    fn rejects_missing_user_verification() {
        let (signing, device, config) = fixture();
        let raw = b"request";
        let approval = signed(raw, &signing, &device, &config, false, 0x01, 0);
        assert!(matches!(
            verify_approval_v1(&approval, raw, &device, &config),
            Err(Error::MissingUserVerification)
        ));
    }

    #[test]
    fn rejects_malformed_cose() {
        assert!(cose_p256_verifying_key(&[0xff]).is_err());
    }

    #[test]
    fn rejects_deeply_nested_cose() {
        let mut value = Value::Integer(0.into());
        for _ in 0..=MAX_CBOR_DEPTH {
            value = Value::Array(vec![value]);
        }
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&value, &mut encoded).unwrap();
        assert!(cose_p256_verifying_key(&encoded).is_err());
    }

    #[test]
    fn rejects_oversized_cose() {
        assert!(cose_p256_verifying_key(&vec![0; MAX_COSE_CBOR_BYTES + 1]).is_err());
    }

    #[test]
    fn rejects_cose_with_duplicate_map_key() {
        let value = Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(1.into()), Value::Integer(2.into())),
        ]);
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&value, &mut encoded).unwrap();
        assert!(cose_p256_verifying_key(&encoded).is_err());
    }

    #[test]
    fn rejects_cose_with_trailing_data() {
        let (_, device, _) = fixture();
        let mut encoded = decode_base64url(&device.credential_public_key).unwrap();
        encoded.push(0);
        assert!(cose_p256_verifying_key(&encoded).is_err());
    }

    #[test]
    fn rejects_cose_with_too_many_items() {
        let value = Value::Array(vec![Value::Null; MAX_CBOR_ITEMS]);
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&value, &mut encoded).unwrap();
        assert!(cose_p256_verifying_key(&encoded).is_err());
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
