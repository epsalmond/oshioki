//! Frozen base-generated inputs; never regenerate these with candidate libraries.
use super::*;
use oshioki_protocol::{decode_base64url, encode_base64url};

fn legacy() -> serde_json::Value {
    serde_json::from_slice(include_bytes!(
        "../../test-vectors/legacy-crypto-v043/fixtures.json"
    ))
    .unwrap()
}

fn bytes(value: &serde_json::Value) -> Vec<u8> {
    decode_base64url(value.as_str().unwrap()).unwrap()
}

fn header<'a>(built: &'a BuiltPushRequest, name: &str) -> &'a str {
    std::str::from_utf8(&built.headers.iter().find(|(key, _)| key == name).unwrap().1).unwrap()
}

#[test]
fn frozen_old_web_push_decrypts_exact_bytes_and_rejects_tampering() {
    let fixtures = legacy();
    let push = &fixtures["web_push"];
    let receiver = p256::SecretKey::from_slice(&bytes(&push["recipient_private_scalar"])).unwrap();
    let auth = WebPushAuth::clone_from_slice(&bytes(&push["auth"]));
    let plaintext = include_bytes!("../../test-vectors/legacy-crypto-v043/expected-plaintext.bin");
    assert_eq!(bytes(&push["plaintext"]), plaintext);
    assert_eq!(
        bytes(&push["ciphertext"]),
        include_bytes!("../../test-vectors/legacy-crypto-v043/old-ciphertext.bin")
    );
    for request in push["requests"].as_array().unwrap() {
        let ciphertext = bytes(&request["ciphertext"]);
        assert_eq!(
            ciphertext.len().to_string(),
            request["headers"]["content-length"]
        );
        assert_eq!(
            u32::from_be_bytes(ciphertext[16..20].try_into().unwrap()),
            80
        );
        assert_eq!(
            web_push_native::decrypt(ciphertext, &receiver, &auth).unwrap(),
            plaintext
        );
    }
    assert!(
        web_push_native::decrypt(bytes(&push["tampered_ciphertext"]), &receiver, &auth).is_err()
    );
    let wrong_auth = WebPushAuth::clone_from_slice(&[0; db::PUSH_AUTH_BYTES]);
    assert!(web_push_native::decrypt(bytes(&push["ciphertext"]), &receiver, &wrong_auth).is_err());
}

#[test]
fn frozen_old_vapid_signatures_and_claims_match_fixed_metadata() {
    let fixtures = legacy();
    let vapid = &fixtures["vapid"];
    let public = p256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes(&vapid["public_sec1"])).unwrap();
    for fixture in vapid["tokens"].as_array().unwrap() {
        let text = fixture["jwt"].as_str().unwrap();
        let token = jwt_compact::UntrustedToken::new(text).unwrap();
        // Signature validation deliberately has no wall-clock expiration check:
        // these historical tokens have a fixed signing time. Fresh TTL is below.
        let verified = Es256
            .validator::<VapidClaims>(&public)
            .validate(&token)
            .unwrap();
        assert_eq!(
            serde_json::to_value(verified.claims()).unwrap(),
            fixture["claims"]
        );
        let signed_at = fixture["signed_at"].as_i64().unwrap();
        let ttl = fixture["ttl"].as_i64().unwrap();
        assert_eq!(
            verified.claims().expiration.unwrap().timestamp(),
            signed_at + ttl
        );
        assert_eq!(
            fixture["authorization"],
            format!(
                "vapid t={text}, k={}",
                vapid["public_identity"].as_str().unwrap()
            )
        );

        let (signed, signature) = text.rsplit_once('.').unwrap();
        let mut signature = decode_base64url(signature).unwrap();
        assert_eq!(signature.len(), 64);
        signature[0] ^= 1;
        let tampered = format!("{signed}.{}", encode_base64url(&signature));
        let tampered = jwt_compact::UntrustedToken::new(&tampered).unwrap();
        assert!(
            Es256
                .validator::<VapidClaims>(&public)
                .validate(&tampered)
                .is_err()
        );
    }
}

#[test]
fn frozen_old_vapid_pem_keeps_bytes_scalar_and_advertised_identity() {
    let fixtures = legacy();
    let dir = std::env::temp_dir().join(format!("oshioki-old-vapid-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&dir).unwrap();
    let path = dir.join("vapid-private.pem");
    let old_pem = include_bytes!("../../test-vectors/legacy-crypto-v043/vapid-test-only.pem");
    fs::write(&path, old_pem).unwrap();
    for _ in 0..2 {
        let config = load_vapid_config(&dir.join("state.sqlite3"), "https://sudo.test").unwrap();
        assert_eq!(config.public_key, fixtures["vapid"]["public_identity"]);
        assert_eq!(
            config.private_key.as_slice(),
            bytes(&fixtures["vapid"]["private_scalar"])
        );
        assert_eq!(fs::read(&path).unwrap(), old_pem);
    }
    fs::remove_dir_all(dir).unwrap();
}

fn load_frozen_vapid_for_fresh_push(fixtures: &serde_json::Value) -> VapidConfig {
    let dir = std::env::temp_dir().join(format!("oshioki-fresh-vapid-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&dir).unwrap();
    let pem_path = dir.join("vapid-private.pem");
    let old_pem = include_bytes!("../../test-vectors/legacy-crypto-v043/vapid-test-only.pem");
    fs::write(&pem_path, old_pem).unwrap();
    // Use the fixture subject as the fallback, without changing process-wide env.
    let vapid = load_vapid_config(
        &dir.join("state.sqlite3"),
        fixtures["vapid"]["subject"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(fs::read(&pem_path).unwrap(), old_pem);
    assert_eq!(vapid.public_key, fixtures["vapid"]["public_identity"]);
    assert_eq!(
        vapid.private_key.as_slice(),
        bytes(&fixtures["vapid"]["private_scalar"])
    );
    fs::remove_dir_all(dir).unwrap();
    vapid
}

#[test]
fn candidate_push_preserves_fresh_ttl_headers_claims_and_provider_size_boundary() {
    let fixtures = legacy();
    let push = &fixtures["web_push"];
    let receiver = p256::SecretKey::from_slice(&bytes(&push["recipient_private_scalar"])).unwrap();
    let auth = WebPushAuth::clone_from_slice(&bytes(&push["auth"]));
    let vapid = load_frozen_vapid_for_fresh_push(&fixtures);
    let public =
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes(&fixtures["vapid"]["public_sec1"]))
            .unwrap();
    let mut item = tests::test_push_item();
    item.endpoint = push["endpoint"].as_str().unwrap().to_owned();
    item.p256dh = bytes(&push["recipient_public_sec1"]);
    item.auth = auth.to_vec();
    // RFC 8030 providers must accept 4096-byte bodies. The retained builder
    // uses 86 bytes of header and 17 bytes of delimiter/tag, with no rounding.
    // Preserve existing behavior above that guarantee; provider rejection is
    // classified separately by the existing delivery lifecycle tests.
    for payload in [
        bytes(&push["plaintext"]),
        vec![],
        vec![0; 1],
        vec![0; 3993],
        vec![0; 3994],
    ] {
        item.payload = payload;
        for ttl in [0, 1, 300] {
            let before = chrono::Utc::now().timestamp();
            let built = build_push_request(&vapid, &item, ttl).unwrap();
            let after = chrono::Utc::now().timestamp();
            assert_eq!(
                web_push_native::decrypt(built.body.clone(), &receiver, &auth).unwrap(),
                item.payload
            );
            assert_eq!(built.body.len(), item.payload.len() + 103);
            assert_eq!(
                u32::from_be_bytes(built.body[16..20].try_into().unwrap()) as usize,
                item.payload.len() + 17
            );
            assert_eq!(
                header(&built, "content-length"),
                built.body.len().to_string()
            );
            assert_eq!(header(&built, "content-encoding"), "aes128gcm");
            assert_eq!(header(&built, "content-type"), "application/octet-stream");
            assert_eq!(header(&built, "ttl"), ttl.to_string());
            let (text, advertised) = header(&built, "authorization")
                .strip_prefix("vapid t=")
                .unwrap()
                .split_once(", k=")
                .unwrap();
            assert_eq!(advertised, vapid.public_key);
            let token = jwt_compact::UntrustedToken::new(text).unwrap();
            let verified = Es256
                .validator::<VapidClaims>(&public)
                .validate(&token)
                .unwrap();
            assert_eq!(
                verified.claims().custom.aud,
                "https://push.example.test:8443"
            );
            assert_eq!(verified.claims().custom.sub, vapid.subject);
            let expiration = verified.claims().expiration.unwrap().timestamp();
            assert!((before + i64::from(ttl)..=after + i64::from(ttl)).contains(&expiration));
            let parts: Vec<_> = text.split('.').collect();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&decode_base64url(parts[0]).unwrap())
                    .unwrap(),
                json!({"alg":"ES256"})
            );
            assert_eq!(decode_base64url(parts[2]).unwrap().len(), 64);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&decode_base64url(parts[1]).unwrap())
                    .unwrap(),
                json!({"exp":expiration,"aud":"https://push.example.test:8443","sub":vapid.subject})
            );
            // Opt-in interoperability evidence for the independent old executable.
            // Only public test material is exported; normal test runs emit nothing.
            if ttl == 300
                && item.payload == bytes(&push["plaintext"])
                && let Some(path) = std::env::var_os("OSHIOKI_TEST_PUSH_ORACLE_DIR")
            {
                let path = PathBuf::from(path);
                fs::create_dir(&path).unwrap(); // Refuse to overwrite evidence.
                fs::write(path.join("candidate-ciphertext.bin"), &built.body).unwrap();
                fs::write(path.join("candidate-jwt.txt"), text).unwrap();
                let headers: std::collections::BTreeMap<_, _> = built
                    .headers
                    .iter()
                    .map(|(key, value)| (key, std::str::from_utf8(value).unwrap()))
                    .collect();
                fs::write(
                    path.join("candidate-signing-window.json"),
                    serde_json::to_vec_pretty(&json!({
                        "before": before, "after": after, "ttl": ttl,
                        "expiry": expiration, "endpoint": item.endpoint,
                        "vapid_public_key": vapid.public_key, "headers": headers,
                    }))
                    .unwrap(),
                )
                .unwrap();
            }
        }
    }
    item.p256dh = vec![4; db::PUSH_P256DH_BYTES];
    assert!(build_push_request(&vapid, &item, 300).is_err());
}
