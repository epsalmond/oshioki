//! Frozen previous-release wire shapes. Regenerate with
//! `OSHIOKI_WRITE_COMPAT_GOLDENS=1 cargo test -p oshioki-protocol --test compat_goldens`.

use std::{fs, path::PathBuf};

use oshioki_protocol::{
    AUTH_ENVELOPE_TYPE, AUTH_REQUEST_TYPE, AUTH_WIRE_VERSION, AliveV1, AuthEnvelopeV1,
    AuthInvocationV1, AuthRequestV1, DecisionV1, DeliveryV1, DenyV1, DeviceKindV1,
    DevicePublicRecordV1, DeviceRegistryV1, RequestV1, SealedDeviceBodyV1, SubmittedAuthContextV1,
    TrustedAuthContextV1, VERSION_V1, decode_base64url, device_fingerprint, encode_base64url,
};
use p256::ecdsa::SigningKey;
use serde::Deserialize;

fn goldens_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/compat/goldens")
}

fn golden_path(name: &str) -> PathBuf {
    goldens_dir().join(name)
}

fn write_or_compare(name: &str, value: &serde_json::Value) {
    let pretty = serde_json::to_string_pretty(value).unwrap() + "\n";
    let path = golden_path(name);
    if std::env::var_os("OSHIOKI_WRITE_COMPAT_GOLDENS").is_some() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, pretty).unwrap();
        return;
    }
    let stored = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "missing golden {}: {error}; regenerate with OSHIOKI_WRITE_COMPAT_GOLDENS=1",
            path.display()
        )
    });
    assert_eq!(stored, pretty, "{}", path.display());
}

fn cose_key(x: &[u8], y: &[u8]) -> Vec<u8> {
    let cose = ciborium::Value::Map(vec![
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
            ciborium::Value::Bytes(x.to_vec()),
        ),
        (
            ciborium::Value::Integer((-3).into()),
            ciborium::Value::Bytes(y.to_vec()),
        ),
    ]);
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&cose, &mut encoded).unwrap();
    encoded
}

fn request() -> RequestV1 {
    RequestV1 {
        version: VERSION_V1,
        request_id: "req-1".into(),
        nonce: encode_base64url(&[1; 16]),
        host: "host.example".into(),
        user: "eric".into(),
        uid: 1000,
        runas_uid: 0,
        cwd: "/home/eric".into(),
        tty: None,
        command: "/usr/bin/apt".into(),
        argv: vec!["apt".into()],
        pid_chain: vec![],
        env: vec![],
        session: None,
        issued_at: 1_000,
        expires_at: 1_090,
    }
}

#[derive(Deserialize)]
struct PreSessionRequest {
    version: u8,
    request_id: String,
    command: String,
}

#[derive(Deserialize)]
struct PreTypeDecision {
    action: String,
    request_id: String,
}

#[derive(Deserialize)]
struct PreAuthEnvelope {
    version: u8,
    request_id: String,
}

fn webauthn_device() -> DevicePublicRecordV1 {
    let signing = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
    let point = signing.verifying_key().to_encoded_point(false);
    let cose = cose_key(point.x().unwrap(), point.y().unwrap());
    let credential_id = vec![1; 16];
    let box_public_key = vec![3; 32];
    let fingerprint = device_fingerprint(&credential_id, &cose, &box_public_key);
    DevicePublicRecordV1 {
        version: VERSION_V1,
        kind: DeviceKindV1::Webauthn,
        fingerprint,
        credential_id: encode_base64url(&credential_id),
        credential_public_key: encode_base64url(&cose),
        box_public_key: encode_base64url(&box_public_key),
        label: "phone".into(),
        api_token_hash: encode_base64url(&[4; 32]),
        sign_count: 0,
        active: true,
    }
}

#[test]
fn request_and_control_goldens_round_trip() {
    let request = request();
    request.validate().unwrap();
    let request_json = serde_json::to_value(&request).unwrap();
    write_or_compare("request-v1.json", &request_json);
    let loaded: RequestV1 = serde_json::from_value(request_json).unwrap();
    loaded.validate().unwrap();
    assert_eq!(loaded, request);

    let mut with_session = request.clone();
    with_session.session = Some("claude".into());
    let old: PreSessionRequest =
        serde_json::from_value(serde_json::to_value(&with_session).unwrap()).unwrap();
    assert_eq!(old.version, VERSION_V1);
    assert_eq!(old.request_id, "req-1");
    assert_eq!(old.command, "/usr/bin/apt");

    let alive = AliveV1::for_request("req-1");
    alive.validate("req-1").unwrap();
    write_or_compare("alive-v1.json", &serde_json::to_value(&alive).unwrap());

    let delivery = DeliveryV1::for_request("req-1");
    delivery.validate("req-1").unwrap();
    write_or_compare(
        "delivery-v1.json",
        &serde_json::to_value(&delivery).unwrap(),
    );

    let deny = DecisionV1::Deny(DenyV1 {
        version: VERSION_V1,
        request_id: "req-1".into(),
        device_fingerprint: webauthn_device().fingerprint,
        signature: None,
    });
    write_or_compare("decision-v1.json", &serde_json::to_value(&deny).unwrap());
    let old_decision: PreTypeDecision =
        serde_json::from_value(serde_json::to_value(&deny).unwrap()).unwrap();
    assert_eq!(old_decision.action, "deny");
    assert_eq!(old_decision.request_id, "req-1");
    let _ = decode_base64url(&request.nonce).unwrap();
}

#[test]
fn device_and_auth_goldens_round_trip() {
    let device = webauthn_device();
    device.validate().unwrap();
    let mut without_kind = serde_json::to_value(&device).unwrap();
    without_kind.as_object_mut().unwrap().remove("kind");
    let second = {
        let signing = SigningKey::from_bytes((&[5; 32]).into()).unwrap();
        let point = signing.verifying_key().to_encoded_point(false);
        let cose = cose_key(point.x().unwrap(), point.y().unwrap());
        let credential_id = vec![6; 16];
        let box_public_key = vec![7; 32];
        let fingerprint = device_fingerprint(&credential_id, &cose, &box_public_key);
        DevicePublicRecordV1 {
            version: VERSION_V1,
            kind: DeviceKindV1::Webauthn,
            fingerprint,
            credential_id: encode_base64url(&credential_id),
            credential_public_key: encode_base64url(&cose),
            box_public_key: encode_base64url(&box_public_key),
            label: "laptop".into(),
            api_token_hash: encode_base64url(&[8; 32]),
            sign_count: 0,
            active: true,
        }
    };
    second.validate().unwrap();
    let registry = serde_json::json!({
        "version": VERSION_V1,
        "devices": [without_kind, serde_json::to_value(&second).unwrap()],
    });
    write_or_compare("devices-v1.json", &registry);
    let loaded_registry: DeviceRegistryV1 = serde_json::from_value(registry).unwrap();
    loaded_registry.validate().unwrap();
    assert_eq!(loaded_registry.devices[0].kind, DeviceKindV1::Webauthn);

    let auth_request = AuthRequestV1 {
        message_type: AUTH_REQUEST_TYPE.into(),
        version: AUTH_WIRE_VERSION,
        request_id: "auth-1".into(),
        nonce: encode_base64url(&[7; 16]),
        issued_at: 1_000,
        expires_at: 1_090,
        trusted: TrustedAuthContextV1 {
            host: "host.example".into(),
            service: "sudo".into(),
            pam_user: "eric".into(),
            pam_uid: 1000,
            invoking_uid: 1000,
            invoking_user: Some("eric".into()),
            tty: Some("/dev/pts/0".into()),
        },
        submitted: SubmittedAuthContextV1 {
            session: None,
            agent_label: None,
            invocation: AuthInvocationV1::Available {
                command: "/usr/bin/true".into(),
                argv: vec!["true".into()],
                cwd: "/home/eric".into(),
            },
        },
    };
    auth_request.validate().unwrap();
    let envelope = AuthEnvelopeV1 {
        message_type: AUTH_ENVELOPE_TYPE.into(),
        version: AUTH_WIRE_VERSION,
        request_id: "auth-1".into(),
        host: "host.example".into(),
        issued_at: 1_000,
        expires_at: 1_090,
        sealed: vec![SealedDeviceBodyV1 {
            device_fingerprint: device.fingerprint,
            ephemeral_pub: encode_base64url(&[8; 32]),
            nonce: encode_base64url(&[9; 12]),
            ciphertext: encode_base64url(&[10; 32]),
        }],
    };
    envelope.validate().unwrap();
    write_or_compare(
        "auth-envelope-v2.json",
        &serde_json::to_value(&envelope).unwrap(),
    );
    write_or_compare(
        "auth-request-v2.json",
        &serde_json::to_value(&auth_request).unwrap(),
    );
    let old_envelope: PreAuthEnvelope =
        serde_json::from_value(serde_json::to_value(&envelope).unwrap()).unwrap();
    assert_eq!(old_envelope.version, AUTH_WIRE_VERSION);
    assert_eq!(old_envelope.request_id, "auth-1");
}

fn read_golden(name: &str) -> String {
    let path = golden_path(name);
    fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "{}: {error}; regenerate with OSHIOKI_WRITE_COMPAT_GOLDENS=1",
            path.display()
        )
    })
}

#[test]
fn stored_goldens_decode_as_current_types() {
    if std::env::var_os("OSHIOKI_WRITE_COMPAT_GOLDENS").is_some() {
        return;
    }
    serde_json::from_str::<RequestV1>(&read_golden("request-v1.json"))
        .unwrap()
        .validate()
        .unwrap();
    serde_json::from_str::<AliveV1>(&read_golden("alive-v1.json"))
        .unwrap()
        .validate("req-1")
        .unwrap();
    serde_json::from_str::<DeliveryV1>(&read_golden("delivery-v1.json"))
        .unwrap()
        .validate("req-1")
        .unwrap();
    let _ = serde_json::from_str::<DecisionV1>(&read_golden("decision-v1.json")).unwrap();
    serde_json::from_str::<DeviceRegistryV1>(&read_golden("devices-v1.json"))
        .unwrap()
        .validate()
        .unwrap();
    serde_json::from_str::<AuthEnvelopeV1>(&read_golden("auth-envelope-v2.json"))
        .unwrap()
        .validate()
        .unwrap();
    serde_json::from_str::<AuthRequestV1>(&read_golden("auth-request-v2.json"))
        .unwrap()
        .validate()
        .unwrap();
}
