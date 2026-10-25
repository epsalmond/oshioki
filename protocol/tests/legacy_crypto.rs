//! Frozen pre-upgrade credentials, produced once by the v0.4.3 dependencies.
//! Never regenerate these values with the current crypto libraries.

use oshioki_protocol::{
    ApproveV1, DevicePublicRecordV1, Error, HookConfigV1, decode_base64url, device_fingerprint,
    webauthn_v1::{cose_p256_verifying_key, verify_approval_v1},
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../test-vectors/legacy-crypto-v043/fixtures.json"
    ))
    .unwrap()
}

fn bytes(value: &Value) -> Vec<u8> {
    decode_base64url(value.as_str().unwrap()).unwrap()
}

#[test]
fn frozen_old_webauthn_assertions_accept_both_s_forms_and_reject_tampering() {
    let fixture = fixture();
    let old = &fixture["webauthn"];
    let device: DevicePublicRecordV1 = serde_json::from_value(old["device"].clone()).unwrap();
    let config: HookConfigV1 = serde_json::from_value(old["config"].clone()).unwrap();
    let raw = bytes(&old["raw_request_json"]);

    let low = Signature::from_der(&bytes(&old["approval_low_s"]["signature"])).unwrap();
    let high = Signature::from_der(&bytes(&old["approval_high_s"]["signature"])).unwrap();
    assert_eq!(low.normalize_s(), low);
    assert_ne!(high, low);
    assert_eq!(high.normalize_s(), low);

    for name in ["approval_low_s", "approval_high_s"] {
        let approval: ApproveV1 = serde_json::from_value(old[name].clone()).unwrap();
        let outcome = verify_approval_v1(&approval, &raw, &device, &config).unwrap();
        assert_eq!(outcome.observed_sign_count, 5);
        assert!(!outcome.counter_regressed);
    }
    let damaged: ApproveV1 =
        serde_json::from_value(old["approval_tampered_signature"].clone()).unwrap();
    assert!(matches!(
        verify_approval_v1(&damaged, &raw, &device, &config),
        Err(Error::InvalidSignature)
    ));
}

#[test]
fn old_scalar_sec1_cose_fingerprint_and_der_encodings_remain_identical() {
    let fixture = fixture();
    let old = &fixture["webauthn"];
    let scalar = bytes(&old["private_scalar"]);
    let signing = SigningKey::from_slice(&scalar).unwrap();
    assert_eq!(signing.to_bytes().as_slice(), scalar);
    let public = signing.verifying_key().to_sec1_point(false);
    assert_eq!(public.as_bytes(), bytes(&old["public_sec1"]));

    let cose = ciborium::Value::Map(vec![
        (1.into(), 2.into()),
        (3.into(), (-7).into()),
        ((-1).into(), 1.into()),
        (
            (-2).into(),
            ciborium::Value::Bytes(public.x().unwrap().to_vec()),
        ),
        (
            (-3).into(),
            ciborium::Value::Bytes(public.y().unwrap().to_vec()),
        ),
    ]);
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&cose, &mut encoded).unwrap();
    assert_eq!(encoded, bytes(&old["cose_public_key"]));
    assert_eq!(
        cose_p256_verifying_key(&encoded).unwrap(),
        *signing.verifying_key()
    );
    let device: DevicePublicRecordV1 = serde_json::from_value(old["device"].clone()).unwrap();
    assert_eq!(
        device_fingerprint(
            &decode_base64url(&device.credential_id).unwrap(),
            &encoded,
            &decode_base64url(&device.box_public_key).unwrap(),
        ),
        device.fingerprint
    );

    let mut signed = bytes(&old["authenticator_data"]);
    signed.extend_from_slice(&Sha256::digest(bytes(&old["client_data_json"])));
    assert_eq!(signed, bytes(&old["signed_message"]));
    let signature: Signature = signing.sign(&signed);
    let low = signature.normalize_s();
    assert_eq!(
        low.to_der().as_bytes(),
        bytes(&old["approval_low_s"]["signature"])
    );
}
