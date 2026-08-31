//! Resumable enrollment transcript verification.

use std::io::Cursor;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use p256::ecdsa::{Signature, signature::Verifier as _};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{
    Error,
    v1::{
        DevicePublicRecordV1, EnrollmentSubmissionV1, HookConfigV1, VERSION_V1, decode_base64url,
        device_fingerprint, encode_base64url,
    },
    webauthn_v1::cose_p256_verifying_key,
};

type HmacSha256 = Hmac<Sha256>;
const REGISTRATION_DOMAIN: &[u8] = b"management-plane-sudo-approve/enroll/registration/v1\0";
const PROOF_DOMAIN: &[u8] = b"management-plane-sudo-approve/enroll/proof/v1\0";
const TRANSCRIPT_DOMAIN: &[u8] = b"management-plane-sudo-approve/enroll/transcript/v1\0";

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    type_: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: bool,
}

pub fn enrollment_hmac(secret: &[u8; 32], domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    transcript_mac(secret, domain, fields)
        .finalize()
        .into_bytes()
        .into()
}

fn transcript_mac(secret: &[u8; 32], domain: &[u8], fields: &[&[u8]]) -> HmacSha256 {
    let mut key_derivation = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key");
    key_derivation.update(domain);
    let derived = key_derivation.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&derived).expect("HMAC accepts any key");
    for field in fields {
        mac.update(&(field.len() as u64).to_be_bytes());
        mac.update(field);
    }
    mac
}

pub fn verify_enrollment_v1(
    submission: &EnrollmentSubmissionV1,
    secret: &[u8; 32],
    config: &HookConfigV1,
) -> Result<DevicePublicRecordV1, Error> {
    config.validate()?;
    submission.validate_shape()?;
    let registration_client_data = decode_base64url(&submission.registration_client_data_json)?;
    let attestation_object = decode_base64url(&submission.attestation_object)?;
    let proof_authenticator_data = decode_base64url(&submission.proof_authenticator_data)?;
    let proof_client_data = decode_base64url(&submission.proof_client_data_json)?;
    let proof_signature = decode_base64url(&submission.proof_signature)?;
    let submitted_credential_id = decode_base64url(&submission.credential_id)?;
    let box_public_key = decode_base64url(&submission.box_public_key)?;
    let api_token_hash = decode_base64url(&submission.api_token_hash)?;
    let supplied_hmac = decode_base64url(&submission.transcript_hmac)?;
    if secret.len() != 32 || box_public_key.len() != 32 || api_token_hash.len() != 32 {
        return Err(Error::InvalidRequest(
            "invalid enrollment field length".into(),
        ));
    }

    transcript_mac(
        secret,
        TRANSCRIPT_DOMAIN,
        &[
            submission.enrollment_id.as_bytes(),
            &registration_client_data,
            &attestation_object,
            &proof_authenticator_data,
            &proof_client_data,
            &proof_signature,
            &submitted_credential_id,
            &box_public_key,
            &api_token_hash,
            submission.label.as_bytes(),
        ],
    )
    .verify_slice(&supplied_hmac)
    .map_err(|_| Error::BadVerdict("transcript HMAC mismatch".into()))?;

    let registration: ClientData = serde_json::from_slice(&registration_client_data)
        .map_err(|_| Error::MalformedClientData)?;
    if registration.type_ != "webauthn.create"
        || registration.origin != config.origin
        || registration.cross_origin
        || registration.challenge
            != URL_SAFE_NO_PAD.encode(enrollment_hmac(secret, REGISTRATION_DOMAIN, &[]))
    {
        return Err(Error::BadChallenge);
    }
    let (credential_id, cose_key, registration_count) =
        parse_attestation(&attestation_object, &config.rp_id)?;
    if credential_id != submitted_credential_id {
        return Err(Error::BadVerdict(
            "registration credential id mismatch".into(),
        ));
    }
    let verifying_key = cose_p256_verifying_key(&cose_key)?;

    let proof: ClientData =
        serde_json::from_slice(&proof_client_data).map_err(|_| Error::MalformedClientData)?;
    let expected_proof = enrollment_hmac(
        secret,
        PROOF_DOMAIN,
        &[
            &credential_id,
            &box_public_key,
            &api_token_hash,
            submission.label.as_bytes(),
        ],
    );
    if proof.type_ != "webauthn.get"
        || proof.origin != config.origin
        || proof.cross_origin
        || proof.challenge != URL_SAFE_NO_PAD.encode(expected_proof)
    {
        return Err(Error::BadChallenge);
    }
    let proof_count = verify_assertion_data(
        &proof_authenticator_data,
        &proof_client_data,
        &proof_signature,
        &config.rp_id,
        &verifying_key,
    )?;
    let sign_count = proof_count.max(registration_count);
    let fingerprint = device_fingerprint(&credential_id, &cose_key, &box_public_key);
    let device = DevicePublicRecordV1 {
        version: VERSION_V1,
        fingerprint,
        credential_id: encode_base64url(&credential_id),
        credential_public_key: encode_base64url(&cose_key),
        box_public_key: encode_base64url(&box_public_key),
        label: submission.label.clone(),
        api_token_hash: encode_base64url(&api_token_hash),
        sign_count,
        active: true,
    };
    device.validate()?;
    Ok(device)
}

fn parse_attestation(
    attestation_object: &[u8],
    rp_id: &str,
) -> Result<(Vec<u8>, Vec<u8>, u32), Error> {
    let value: serde_cbor::Value = serde_cbor::from_slice(attestation_object)
        .map_err(|_| Error::MalformedAuthenticatorData)?;
    let serde_cbor::Value::Map(entries) = value else {
        return Err(Error::MalformedAuthenticatorData);
    };
    let mut format = None;
    let mut auth_data = None;
    for (key, value) in entries {
        match (key, value) {
            (serde_cbor::Value::Text(key), serde_cbor::Value::Text(value)) if key == "fmt" => {
                format = Some(value);
            }
            (serde_cbor::Value::Text(key), serde_cbor::Value::Bytes(value))
                if key == "authData" =>
            {
                auth_data = Some(value);
            }
            _ => {}
        }
    }
    if format.as_deref() != Some("none") {
        return Err(Error::BadVerdict("attestation format must be none".into()));
    }
    let auth_data = auth_data.ok_or(Error::MalformedAuthenticatorData)?;
    if auth_data.len() < 55 || &auth_data[..32] != Sha256::digest(rp_id.as_bytes()).as_slice() {
        return Err(Error::BadRpId);
    }
    let flags = auth_data[32];
    if flags & 0x01 == 0 {
        return Err(Error::MissingUserPresence);
    }
    if flags & 0x04 == 0 {
        return Err(Error::MissingUserVerification);
    }
    if flags & 0x40 == 0 {
        return Err(Error::MalformedAuthenticatorData);
    }
    let count = u32::from_be_bytes(
        auth_data[33..37]
            .try_into()
            .map_err(|_| Error::MalformedAuthenticatorData)?,
    );
    let credential_len = usize::from(u16::from_be_bytes(
        auth_data[53..55]
            .try_into()
            .map_err(|_| Error::MalformedAuthenticatorData)?,
    ));
    let credential_end = 55_usize
        .checked_add(credential_len)
        .ok_or(Error::MalformedAuthenticatorData)?;
    if credential_end >= auth_data.len() {
        return Err(Error::MalformedAuthenticatorData);
    }
    let credential_id = auth_data[55..credential_end].to_vec();
    let mut cursor = Cursor::new(&auth_data[credential_end..]);
    let cose: serde_cbor::Value =
        serde_cbor::from_reader(&mut cursor).map_err(|_| Error::MalformedAuthenticatorData)?;
    let cose = serde_cbor::to_vec(&cose).map_err(|_| Error::MalformedAuthenticatorData)?;
    cose_p256_verifying_key(&cose)?;
    Ok((credential_id, cose, count))
}

fn verify_assertion_data(
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
    rp_id: &str,
    verifying_key: &p256::ecdsa::VerifyingKey,
) -> Result<u32, Error> {
    if authenticator_data.len() < 37
        || &authenticator_data[..32] != Sha256::digest(rp_id.as_bytes()).as_slice()
    {
        return Err(Error::BadRpId);
    }
    let flags = authenticator_data[32];
    if flags & 0x01 == 0 {
        return Err(Error::MissingUserPresence);
    }
    if flags & 0x04 == 0 {
        return Err(Error::MissingUserVerification);
    }
    let mut message = authenticator_data.to_vec();
    message.extend_from_slice(&Sha256::digest(client_data_json));
    let signature = Signature::from_der(signature).map_err(|_| Error::InvalidSignature)?;
    verifying_key
        .verify(&message, &signature)
        .map_err(|_| Error::InvalidSignature)?;
    Ok(u32::from_be_bytes(
        authenticator_data[33..37]
            .try_into()
            .map_err(|_| Error::MalformedAuthenticatorData)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{
        ecdsa::{Signature, SigningKey, signature::Signer as _},
        elliptic_curve::rand_core::OsRng,
    };
    use serde_cbor::Value;
    use std::collections::BTreeMap;

    fn fixture() -> (EnrollmentSubmissionV1, [u8; 32], HookConfigV1) {
        let secret = [9; 32];
        let config = HookConfigV1 {
            version: 1,
            origin: "https://sudo.example".into(),
            rp_id: "sudo.example".into(),
            server_base_url: "https://sudo.example".into(),
        };
        let signing = SigningKey::random(&mut OsRng);
        let point = signing.verifying_key().to_encoded_point(false);
        let mut cose = BTreeMap::new();
        cose.insert(Value::Integer(1), Value::Integer(2));
        cose.insert(Value::Integer(3), Value::Integer(-7));
        cose.insert(Value::Integer(-1), Value::Integer(1));
        cose.insert(
            Value::Integer(-2),
            Value::Bytes(point.x().unwrap().to_vec()),
        );
        cose.insert(
            Value::Integer(-3),
            Value::Bytes(point.y().unwrap().to_vec()),
        );
        let cose = serde_cbor::to_vec(&Value::Map(cose)).unwrap();
        let credential_id = vec![7; 24];
        let box_key = vec![8; 32];
        let token_hash = vec![6; 32];
        let label = "profile";
        let registration_client = format!(
            r#"{{"type":"webauthn.create","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
            URL_SAFE_NO_PAD.encode(enrollment_hmac(&secret, REGISTRATION_DOMAIN, &[])),
            config.origin
        )
        .into_bytes();
        let mut registration_auth = Sha256::digest(config.rp_id.as_bytes()).to_vec();
        registration_auth.push(0x45);
        registration_auth.extend_from_slice(&1_u32.to_be_bytes());
        registration_auth.extend_from_slice(&[0; 16]);
        registration_auth
            .extend_from_slice(&u16::try_from(credential_id.len()).unwrap().to_be_bytes());
        registration_auth.extend_from_slice(&credential_id);
        registration_auth.extend_from_slice(&cose);
        let mut attestation = BTreeMap::new();
        attestation.insert(Value::Text("fmt".into()), Value::Text("none".into()));
        attestation.insert(
            Value::Text("authData".into()),
            Value::Bytes(registration_auth),
        );
        attestation.insert(Value::Text("attStmt".into()), Value::Map(BTreeMap::new()));
        let attestation = serde_cbor::to_vec(&Value::Map(attestation)).unwrap();
        let proof_challenge = enrollment_hmac(
            &secret,
            PROOF_DOMAIN,
            &[&credential_id, &box_key, &token_hash, label.as_bytes()],
        );
        let proof_client = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
            URL_SAFE_NO_PAD.encode(proof_challenge),
            config.origin
        )
        .into_bytes();
        let mut proof_auth = Sha256::digest(config.rp_id.as_bytes()).to_vec();
        proof_auth.push(0x05);
        proof_auth.extend_from_slice(&2_u32.to_be_bytes());
        let mut signed = proof_auth.clone();
        signed.extend_from_slice(&Sha256::digest(&proof_client));
        let signature: Signature = signing.sign(&signed);
        let signature = signature.to_der().as_bytes().to_vec();
        let fields = [
            b"enrollment-1".as_slice(),
            registration_client.as_slice(),
            attestation.as_slice(),
            proof_auth.as_slice(),
            proof_client.as_slice(),
            signature.as_slice(),
            credential_id.as_slice(),
            box_key.as_slice(),
            token_hash.as_slice(),
            label.as_bytes(),
        ];
        let transcript_hmac = enrollment_hmac(&secret, TRANSCRIPT_DOMAIN, &fields);
        let submission = EnrollmentSubmissionV1 {
            version: 1,
            enrollment_id: "enrollment-1".into(),
            registration_client_data_json: encode_base64url(&registration_client),
            attestation_object: encode_base64url(&attestation),
            proof_authenticator_data: encode_base64url(&proof_auth),
            proof_client_data_json: encode_base64url(&proof_client),
            proof_signature: encode_base64url(&signature),
            credential_id: encode_base64url(&credential_id),
            box_public_key: encode_base64url(&box_key),
            api_token_hash: encode_base64url(&token_hash),
            label: label.into(),
            transcript_hmac: encode_base64url(&transcript_hmac),
        };
        (submission, secret, config)
    }

    #[test]
    fn verifies_registration_and_immediate_proof() {
        let (submission, secret, config) = fixture();
        let device = verify_enrollment_v1(&submission, &secret, &config).unwrap();
        assert_eq!(device.sign_count, 2);
        assert!(device.active);
    }

    #[test]
    fn rejects_hmac_substitution() {
        let (mut submission, secret, config) = fixture();
        submission.label = "substituted".into();
        assert!(verify_enrollment_v1(&submission, &secret, &config).is_err());
    }

    #[test]
    fn rejects_wrong_origin_and_rp_id() {
        let (submission, secret, mut config) = fixture();
        config.origin = "https://other.example".into();
        config.server_base_url = config.origin.clone();
        assert!(verify_enrollment_v1(&submission, &secret, &config).is_err());
        let (submission, secret, mut config) = fixture();
        config.rp_id = "other.example".into();
        assert!(verify_enrollment_v1(&submission, &secret, &config).is_err());
    }
}
