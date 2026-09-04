//! Fixed vectors for native enrollment and approval.
//!
//! Regenerate with `OSHIOKI_WRITE_VECTORS=1 cargo test -p oshioki-agent
//! --test native_vectors` after an intentional protocol change, and say so in
//! the commit message. ECDSA here is RFC 6979 deterministic, so the
//! signatures are stable.

use oshioki_agent::Identity;
use oshioki_protocol::{
    DecisionV1, RequestV1, VERSION_V1, approve_challenge, encode_base64url,
    native_enrollment_proof, verify_native_approval_v1, verify_native_enrollment_v1,
};
use serde::{Deserialize, Serialize};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/native_v1.json");

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Vectors {
    signing_scalar: String,
    box_secret: String,
    api_token_hash: String,
    enrollment_secret: String,
    enrollment_id: String,
    label: String,
    credential_public_key: String,
    credential_id: String,
    box_public_key: String,
    fingerprint: String,
    proof_message: String,
    proof_signature: String,
    transcript_hmac: String,
    raw_request: String,
    challenge: String,
    approval_signature: String,
}

fn request() -> RequestV1 {
    RequestV1 {
        version: VERSION_V1,
        request_id: "vector-request".into(),
        nonce: encode_base64url(&[3; 16]),
        host: "host.example".into(),
        user: "eric".into(),
        uid: 1000,
        runas_uid: 0,
        cwd: "/home/eric".into(),
        tty: Some("/dev/pts/0".into()),
        command: "/usr/bin/true".into(),
        argv: vec!["true".into()],
        pid_chain: vec!["1 systemd".into()],
        env: vec![],
        issued_at: 1_700_000_000,
        expires_at: 1_700_000_090,
    }
}

fn generate() -> Vectors {
    let signing = [0x11; 32];
    let box_secret = [0x22; 32];
    let api_token_hash = [0x33; 32];
    let secret = [0x44; 32];
    let identity = Identity::from_material(signing, box_secret, api_token_hash).unwrap();
    let submission = identity
        .enrollment_submission("vector-enrollment", &secret, "vector laptop")
        .unwrap();
    let device = verify_native_enrollment_v1(&submission, &secret).unwrap();
    let raw = request().raw_json().unwrap();
    let DecisionV1::ApproveNative(approval) = identity
        .approve(
            &oshioki_agent::OpenedRequest {
                request: request(),
                raw: raw.clone(),
            },
            // The reason reaches a backend that asks the operator, and never
            // the signature: the vectors below must not move when it changes.
            "run /usr/bin/true as root (uid 0) on host.example",
        )
        .unwrap()
    else {
        panic!("expected native approval");
    };
    verify_native_approval_v1(&approval, &raw, &device).unwrap();
    Vectors {
        signing_scalar: encode_base64url(&signing),
        box_secret: encode_base64url(&box_secret),
        api_token_hash: encode_base64url(&api_token_hash),
        enrollment_secret: encode_base64url(&secret),
        enrollment_id: submission.enrollment_id.clone(),
        label: submission.label.clone(),
        credential_public_key: device.credential_public_key.clone(),
        credential_id: device.credential_id.clone(),
        box_public_key: device.box_public_key.clone(),
        fingerprint: device.fingerprint.clone(),
        proof_message: encode_base64url(&native_enrollment_proof(
            &secret,
            &identity.public_key_sec1(),
            &identity.box_public_key(),
            &api_token_hash,
            &submission.label,
        )),
        proof_signature: submission.proof_signature.clone(),
        transcript_hmac: submission.transcript_hmac.clone(),
        raw_request: String::from_utf8(raw.clone()).unwrap(),
        challenge: encode_base64url(&approve_challenge(&raw)),
        approval_signature: approval.signature,
    }
}

#[test]
fn native_vectors_are_stable() {
    let generated = generate();
    if std::env::var_os("OSHIOKI_WRITE_VECTORS").is_some() {
        std::fs::write(
            PATH,
            serde_json::to_string_pretty(&generated).unwrap() + "\n",
        )
        .unwrap();
    }
    let stored: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert_eq!(generated, stored);
}
