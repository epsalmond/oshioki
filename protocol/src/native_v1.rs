//! Native (Secure Enclave) approval and enrollment verification.
//!
//! A native device holds a P-256 key outside any browser. It signs the same
//! 32-byte challenge the `WebAuthn` path signs, with no authenticator data,
//! client data, origin, or relying party ID. Signatures are DER ECDSA with
//! SHA-256 as the message hash, which is what the Secure Enclave produces for
//! `ecdsaSignatureMessageX962SHA256`.

use hmac::Mac as _;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use sha2::{Digest, Sha256};

use crate::{
    Error,
    enrollment_v1::{TRANSCRIPT_DOMAIN, enrollment_hmac, transcript_mac},
    v1::{
        ApproveNativeV1, DeviceKindV1, DevicePublicRecordV1, NativeEnrollmentSubmissionV1,
        VERSION_V1, approve_challenge, decode_base64url, device_fingerprint, encode_base64url,
    },
};

const NATIVE_PROOF_DOMAIN: &[u8] = b"oshioki/enroll/native-proof/v1\0";
const NATIVE_KIND_TAG: &[u8] = b"secure-enclave";

/// Parses a 65-byte SEC1 uncompressed P-256 point.
pub fn sec1_p256_verifying_key(sec1: &[u8]) -> Result<VerifyingKey, Error> {
    if sec1.len() != 65 || sec1[0] != 4 {
        return Err(Error::InvalidSignature);
    }
    VerifyingKey::from_sec1_bytes(sec1).map_err(|_| Error::InvalidSignature)
}

/// The credential ID of a native device: SHA-256 of its SEC1 public point.
pub fn native_credential_id(sec1: &[u8]) -> Vec<u8> {
    Sha256::digest(sec1).to_vec()
}

/// Verifies a native approval against the retained raw request bytes.
pub fn verify_native_approval_v1(
    approval: &ApproveNativeV1,
    raw_request_json: &[u8],
    device: &DevicePublicRecordV1,
) -> Result<(), Error> {
    device.validate()?;
    approval.validate_shape()?;
    if device.kind != DeviceKindV1::SecureEnclave
        || approval.device_fingerprint != device.fingerprint
    {
        return Err(Error::BadVerdict(
            "native approval does not match pinned device".into(),
        ));
    }
    let key = sec1_p256_verifying_key(&decode_base64url(&device.credential_public_key)?)?;
    let signature = Signature::from_der(&decode_base64url(&approval.signature)?)
        .map_err(|_| Error::InvalidSignature)?;
    key.verify(&approve_challenge(raw_request_json), &signature)
        .map_err(|_| Error::InvalidSignature)
}

/// The 32-byte proof message a native device signs during enrollment.
pub fn native_enrollment_proof(
    secret: &[u8; 32],
    credential_public_key: &[u8],
    box_public_key: &[u8],
    api_token_hash: &[u8],
    label: &str,
) -> [u8; 32] {
    enrollment_hmac(
        secret,
        NATIVE_PROOF_DOMAIN,
        &[
            &native_credential_id(credential_public_key),
            credential_public_key,
            box_public_key,
            api_token_hash,
            label.as_bytes(),
        ],
    )
}

/// The transcript fields, in the order both sides feed them to the HMAC.
///
/// Signer and verifier read this one list; a field added to only one of them
/// would make every enrollment fail with no explanation.
fn native_transcript_fields(
    submission: &NativeEnrollmentSubmissionV1,
) -> Result<Vec<Vec<u8>>, Error> {
    Ok(vec![
        submission.enrollment_id.as_bytes().to_vec(),
        NATIVE_KIND_TAG.to_vec(),
        decode_base64url(&submission.credential_public_key)?,
        decode_base64url(&submission.box_public_key)?,
        decode_base64url(&submission.api_token_hash)?,
        submission.label.as_bytes().to_vec(),
        decode_base64url(&submission.proof_signature)?,
    ])
}

/// The transcript HMAC over a native submission, computed by both sides.
pub fn native_transcript_hmac(
    secret: &[u8; 32],
    submission: &NativeEnrollmentSubmissionV1,
) -> Result<[u8; 32], Error> {
    let fields = native_transcript_fields(submission)?;
    let fields: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    Ok(enrollment_hmac(secret, TRANSCRIPT_DOMAIN, &fields))
}

/// Verifies a native enrollment and returns the device record to pin.
pub fn verify_native_enrollment_v1(
    submission: &NativeEnrollmentSubmissionV1,
    secret: &[u8; 32],
) -> Result<DevicePublicRecordV1, Error> {
    submission.validate_shape()?;
    let credential_public_key = decode_base64url(&submission.credential_public_key)?;
    let box_public_key = decode_base64url(&submission.box_public_key)?;
    let api_token_hash = decode_base64url(&submission.api_token_hash)?;
    let proof_signature = decode_base64url(&submission.proof_signature)?;
    let supplied_hmac = decode_base64url(&submission.transcript_hmac)?;

    let fields = native_transcript_fields(submission)?;
    let fields: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    transcript_mac(secret, TRANSCRIPT_DOMAIN, &fields)
        .verify_slice(&supplied_hmac)
        .map_err(|_| Error::BadVerdict("transcript HMAC mismatch".into()))?;

    let key = sec1_p256_verifying_key(&credential_public_key)?;
    let proof = native_enrollment_proof(
        secret,
        &credential_public_key,
        &box_public_key,
        &api_token_hash,
        &submission.label,
    );
    let signature = Signature::from_der(&proof_signature).map_err(|_| Error::InvalidSignature)?;
    key.verify(&proof, &signature)
        .map_err(|_| Error::InvalidSignature)?;

    let credential_id = native_credential_id(&credential_public_key);
    let device = DevicePublicRecordV1 {
        version: VERSION_V1,
        kind: DeviceKindV1::SecureEnclave,
        fingerprint: device_fingerprint(&credential_id, &credential_public_key, &box_public_key),
        credential_id: encode_base64url(&credential_id),
        credential_public_key: submission.credential_public_key.clone(),
        box_public_key: submission.box_public_key.clone(),
        label: submission.label.clone(),
        api_token_hash: submission.api_token_hash.clone(),
        sign_count: 0,
        active: true,
    };
    device.validate()?;
    Ok(device)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::ApproveV1;
    use crate::webauthn_v1::verify_approval_v1;
    use crate::{HookConfigV1, webauthn_v1};
    use p256::ecdsa::{SigningKey, signature::Signer as _};

    const SECRET: [u8; 32] = [5; 32];
    const RAW: &[u8] = br#"{"version":1,"request_id":"native-1"}"#;

    fn signing_key() -> SigningKey {
        SigningKey::from_slice(&[0x11; 32]).unwrap()
    }

    fn submission(key: &SigningKey, label: &str) -> NativeEnrollmentSubmissionV1 {
        let public = key.verifying_key().to_encoded_point(false);
        let box_public = [6; 32];
        let api_token_hash = [7; 32];
        let proof = native_enrollment_proof(
            &SECRET,
            public.as_bytes(),
            &box_public,
            &api_token_hash,
            label,
        );
        let signature: Signature = key.sign(&proof);
        let mut submission = NativeEnrollmentSubmissionV1 {
            version: VERSION_V1,
            enrollment_id: "enroll-1".into(),
            credential_public_key: encode_base64url(public.as_bytes()),
            box_public_key: encode_base64url(&box_public),
            api_token_hash: encode_base64url(&api_token_hash),
            label: label.into(),
            proof_signature: encode_base64url(signature.to_der().as_bytes()),
            transcript_hmac: String::new(),
        };
        submission.transcript_hmac =
            encode_base64url(&native_transcript_hmac(&SECRET, &submission).unwrap());
        submission
    }

    fn device() -> DevicePublicRecordV1 {
        verify_native_enrollment_v1(&submission(&signing_key(), "vector"), &SECRET).unwrap()
    }

    fn approval(key: &SigningKey, raw: &[u8], device: &DevicePublicRecordV1) -> ApproveNativeV1 {
        let signature: Signature = key.sign(&approve_challenge(raw));
        ApproveNativeV1 {
            version: VERSION_V1,
            request_id: "native-1".into(),
            device_fingerprint: device.fingerprint.clone(),
            signature: encode_base64url(signature.to_der().as_bytes()),
        }
    }

    #[test]
    fn enrolls_and_approves() {
        let device = device();
        assert_eq!(device.kind, DeviceKindV1::SecureEnclave);
        assert_eq!(device.sign_count, 0);
        let approval = approval(&signing_key(), RAW, &device);
        verify_native_approval_v1(&approval, RAW, &device).unwrap();
    }

    #[test]
    fn rejects_signature_over_different_bytes() {
        let device = device();
        let approval = approval(
            &signing_key(),
            br#"{"version":1,"request_id":"other"}"#,
            &device,
        );
        assert!(verify_native_approval_v1(&approval, RAW, &device).is_err());
    }

    #[test]
    fn rejects_replayed_signature_for_new_request() {
        // A fresh request has fresh raw bytes (nonce and id), so an old
        // signature never verifies even when the device is the same.
        let device = device();
        let old = approval(&signing_key(), RAW, &device);
        let fresh = br#"{"version":1,"request_id":"native-2","nonce":"x"}"#;
        assert!(verify_native_approval_v1(&old, fresh, &device).is_err());
    }

    #[test]
    fn rejects_wrong_fingerprint_and_wrong_key() {
        let device = device();
        let mut approval = approval(&signing_key(), RAW, &device);
        approval.device_fingerprint = "AAAAAAAAAAAAAAAAAAAAAA".into();
        assert!(verify_native_approval_v1(&approval, RAW, &device).is_err());
        let other = SigningKey::from_slice(&[0x22; 32]).unwrap();
        let forged = self::approval(&other, RAW, &device);
        assert!(matches!(
            verify_native_approval_v1(&forged, RAW, &device),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn rejects_webauthn_record_in_native_approval() {
        let key = signing_key();
        let point = key.verifying_key().to_encoded_point(false);
        let cose = webauthn_v1::tests::cose_key(point.x().unwrap(), point.y().unwrap());
        let credential_id = [1; 16];
        let box_public = [6; 32];
        let webauthn = DevicePublicRecordV1 {
            version: VERSION_V1,
            kind: DeviceKindV1::Webauthn,
            fingerprint: device_fingerprint(&credential_id, &cose, &box_public),
            credential_id: encode_base64url(&credential_id),
            credential_public_key: encode_base64url(&cose),
            box_public_key: encode_base64url(&box_public),
            label: "browser".into(),
            api_token_hash: encode_base64url(&[7; 32]),
            sign_count: 0,
            active: true,
        };
        let approval = approval(&key, RAW, &webauthn);
        assert!(verify_native_approval_v1(&approval, RAW, &webauthn).is_err());
    }

    #[test]
    fn rejects_native_record_in_webauthn_approval() {
        let device = device();
        let approval = ApproveV1 {
            version: VERSION_V1,
            request_id: "native-1".into(),
            device_fingerprint: device.fingerprint.clone(),
            credential_id: device.credential_id.clone(),
            authenticator_data: encode_base64url(&[0; 37]),
            client_data_json: encode_base64url(b"{}"),
            signature: encode_base64url(&[0; 64]),
        };
        let config = HookConfigV1 {
            version: VERSION_V1,
            origin: "https://sudo.example".into(),
            rp_id: "sudo.example".into(),
            server_base_url: "https://sudo.example".into(),
        };
        assert!(verify_approval_v1(&approval, RAW, &device, &config).is_err());
    }

    #[test]
    fn rejects_tampered_enrollment() {
        let key = signing_key();
        let mut relabeled = submission(&key, "vector");
        relabeled.label = "other".into();
        assert!(verify_native_enrollment_v1(&relabeled, &SECRET).is_err());

        let mut wrong_secret = submission(&key, "vector");
        wrong_secret.transcript_hmac =
            encode_base64url(&native_transcript_hmac(&[9; 32], &wrong_secret).unwrap());
        assert!(verify_native_enrollment_v1(&wrong_secret, &SECRET).is_err());

        let other = SigningKey::from_slice(&[0x22; 32]).unwrap();
        let mut swapped_key = submission(&key, "vector");
        swapped_key.credential_public_key =
            encode_base64url(other.verifying_key().to_encoded_point(false).as_bytes());
        swapped_key.transcript_hmac =
            encode_base64url(&native_transcript_hmac(&SECRET, &swapped_key).unwrap());
        assert!(matches!(
            verify_native_enrollment_v1(&swapped_key, &SECRET),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn rejects_bad_secure_enclave_record() {
        let mut device = device();
        device.sign_count = 1;
        assert!(device.validate().is_err());
        let mut device = self::device();
        device.credential_id = encode_base64url(&[1; 32]);
        assert!(device.validate().is_err());
    }
}
