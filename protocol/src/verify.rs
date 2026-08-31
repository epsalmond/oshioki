//! `WebAuthn` assertion verification.
//!
//! This module verifies that a Touch ID / Face ID prompt actually signed the
//! exact sudo request. This is the security-critical path: if verification
//! fails for any reason, the hook denies.
//!
//! A valid assertion proves:
//! 1. The user touched the biometric sensor (UP + UV flags)
//! 2. The authenticator signed this exact request (challenge binds it)
//! 3. The signature came from the pinned device key (ECDSA verify)
//!
//! Anything else — wrong challenge, wrong origin, expired, bad signature — is
//! a deny.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{Error, Request, Verdict};

/// Canonical origin for the approval page.
const EXPECTED_ORIGIN: &str = "https://sudo.internal.psalmond.com";

/// Relying party ID (used to compute rpIdHash).
const RP_ID: &str = "sudo.internal.psalmond.com";

/// `WebAuthn` client data JSON structure.
#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    type_: String,
    challenge: String,
    origin: String,
}

/// Verify a `WebAuthn` assertion against a request.
///
/// Returns `Ok(())` only if every check passes. Any failure returns an
/// `Error` describing which check failed.
///
/// The credential public key is the COSE key (CBOR bytes) pinned during
/// enrollment.
pub fn verify(verdict: &Verdict, request: &Request, credential_pub: &[u8]) -> Result<(), Error> {
    // 1. Check expiry
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    if now >= request.expiry {
        return Err(Error::Expired);
    }

    // 2. Parse client data JSON
    let client_data: ClientData =
        serde_json::from_str(&verdict.client_data_json).map_err(|_| Error::MalformedClientData)?;

    // 3. Check type
    if client_data.type_ != "webauthn.get" {
        return Err(Error::UnexpectedCredentialType);
    }

    // 4. Check origin
    if client_data.origin != EXPECTED_ORIGIN {
        return Err(Error::BadOrigin);
    }

    // 5. Check challenge
    let canonical_json =
        serde_json::to_string(request).map_err(|e| Error::InvalidRequest(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(canonical_json.as_bytes());
    hasher.update(b"approve");
    let challenge_hash = hasher.finalize();
    let expected_challenge = URL_SAFE_NO_PAD.encode(challenge_hash);
    if client_data.challenge != expected_challenge {
        return Err(Error::BadChallenge);
    }

    // 6. Parse authenticator data
    if verdict.authenticator_data.len() != 37 {
        return Err(Error::MalformedAuthenticatorData);
    }
    let rp_id_hash = &verdict.authenticator_data[..32];
    let flags = verdict.authenticator_data[32];

    // 7. Check rpIdHash
    let mut hasher = Sha256::new();
    hasher.update(RP_ID.as_bytes());
    let expected_rp_id_hash = hasher.finalize();
    if rp_id_hash != expected_rp_id_hash.as_slice() {
        return Err(Error::BadRpId);
    }

    // 8. Check UP flag (bit 0)
    if flags & 0x01 == 0 {
        return Err(Error::MissingUserPresence);
    }

    // 9. Check UV flag (bit 2)
    if flags & 0x04 == 0 {
        return Err(Error::MissingUserVerification);
    }

    // 10. Parse credential public key (COSE format)
    let (x, y) = parse_cose_p256_key(credential_pub)?;

    // 11. Build P-256 verifying key
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04); // uncompressed point
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let public_key = VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| Error::InvalidSignature)?;

    // 12. Build signature message: authenticator_data || SHA256(client_data_json)
    let mut hasher = Sha256::new();
    hasher.update(verdict.client_data_json.as_bytes());
    let client_data_hash = hasher.finalize();
    let mut message = Vec::with_capacity(verdict.authenticator_data.len() + 32);
    message.extend_from_slice(&verdict.authenticator_data);
    message.extend_from_slice(&client_data_hash);

    // 13. Parse and verify ECDSA signature
    let signature = Signature::from_der(&verdict.signature).map_err(|_| Error::InvalidSignature)?;
    public_key
        .verify(&message, &signature)
        .map_err(|_| Error::InvalidSignature)?;

    Ok(())
}

/// Parse a COSE P-256 public key and extract the x,y coordinates.
///
/// COSE key structure for EC2 (elliptic curve, P-256):
/// - `kty` (1) = 2 (EC2)
/// - `params` contains (`Label::Int(-1)`, Crv), (`Label::Int(-2)`, X),
///   (`Label::Int(-3)`, Y)
/// - Crv = 1 (P-256)
/// - X and Y are 32-byte coordinates
fn parse_cose_p256_key(cose_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    // Parse as generic CBOR. A COSE P-256 EC2 key is a map with
    // integer labels mapping to byte strings.
    let value: serde_cbor::Value =
        serde_cbor::from_slice(cose_bytes).map_err(|_| Error::InvalidSignature)?;

    let mut x: Option<Vec<u8>> = None;
    let mut y: Option<Vec<u8>> = None;

    if let serde_cbor::Value::Map(pairs) = value {
        for (k, v) in pairs {
            if let (serde_cbor::Value::Integer(n), serde_cbor::Value::Bytes(bytes)) = (k, v) {
                match n {
                    -2 => x = Some(bytes),
                    -3 => y = Some(bytes),
                    _ => {}
                }
            }
        }
    }

    match (x, y) {
        (Some(x), Some(y)) if x.len() == 32 && y.len() == 32 => Ok((x, y)),
        _ => Err(Error::InvalidSignature),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer as _};
    use p256::elliptic_curve::rand_core::OsRng;
    use std::collections::BTreeMap;

    /// Build a request for testing.
    fn test_request() -> Request {
        Request {
            id: "test-id".to_string(),
            nonce: [0; 16],
            host: "nas".to_string(),
            user: "eric".to_string(),
            uid: 1000,
            runas_uid: 0,
            cwd: "/home/eric".to_string(),
            tty: Some("/dev/pts/0".to_string()),
            command: "/usr/bin/true".to_string(),
            argv: vec!["/usr/bin/true".to_string()],
            pid_chain: vec![],
            ts: 1_000_000,
            expiry: i64::MAX - 1000,
        }
    }

    /// Create a P-256 keypair and sign a verdict.
    fn sign_verdict(
        request: &Request,
        authenticator_data: &[u8],
        signing_key: &SigningKey,
    ) -> Verdict {
        let canonical_json = serde_json::to_string(request).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(canonical_json.as_bytes());
        hasher.update(b"approve");
        let challenge_hash = hasher.finalize();
        let challenge = URL_SAFE_NO_PAD.encode(challenge_hash);

        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{EXPECTED_ORIGIN}"}}"#
        );

        let mut hasher = Sha256::new();
        hasher.update(client_data_json.as_bytes());
        let client_data_hash = hasher.finalize();

        let mut message = Vec::new();
        message.extend_from_slice(authenticator_data);
        message.extend_from_slice(&client_data_hash);

        let signature: Signature = signing_key.sign(&message);

        Verdict {
            id: request.id.clone(),
            credential_id: vec![1, 2, 3],
            authenticator_data: authenticator_data.to_vec(),
            client_data_json,
            signature: signature.to_der().to_bytes().to_vec(),
        }
    }

    /// Build authenticator data with the given flags.
    fn auth_data(flags: u8) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(RP_ID.as_bytes());
        let rp_id_hash = hasher.finalize();
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&rp_id_hash);
        data.push(flags);
        data.extend_from_slice(&[0, 0, 0, 1]); // counter
        data
    }

    /// Export a signing key as COSE format (CBOR with x,y coordinates).
    fn export_cose_key(signing_key: &SigningKey) -> Vec<u8> {
        let public_key = signing_key.verifying_key();
        let point = public_key.to_encoded_point(false);
        let x = point.x().unwrap().to_vec();
        let y = point.y().unwrap().to_vec();

        // Build a CBOR map with -2: x_bytes, -3: y_bytes. This is the structure
        // our parse_cose_p256_key function expects.
        let mut map = BTreeMap::new();
        map.insert(serde_cbor::Value::Integer(-2), serde_cbor::Value::Bytes(x));
        map.insert(serde_cbor::Value::Integer(-3), serde_cbor::Value::Bytes(y));

        serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap()
    }

    #[test]
    fn verify_valid_assertion() {
        let signing_key = SigningKey::random(&mut OsRng);
        let request = test_request();
        let auth_data = auth_data(0b101); // UP + UV
        let verdict = sign_verdict(&request, &auth_data, &signing_key);
        let cose_key = export_cose_key(&signing_key);

        let result = verify(&verdict, &request, &cose_key);
        assert!(result.is_ok(), "valid assertion should verify: {result:?}");
    }

    #[test]
    fn verify_wrong_challenge() {
        let signing_key = SigningKey::random(&mut OsRng);
        let request = test_request();
        let auth_data = auth_data(0b101);
        let mut verdict = sign_verdict(&request, &auth_data, &signing_key);

        // Tamper with the challenge
        verdict.client_data_json = verdict.client_data_json.replace(
            "\"webauthn.get\"",
            "\"webauthn.get\",\"challenge\":\"wrong\"",
        );

        let cose_key = export_cose_key(&signing_key);
        let result = verify(&verdict, &request, &cose_key);
        assert!(matches!(
            result,
            Err(Error::MalformedClientData | Error::BadChallenge)
        ));
    }

    #[test]
    fn verify_wrong_origin() {
        let signing_key = SigningKey::random(&mut OsRng);
        let request = test_request();
        let auth_data = auth_data(0b101);
        let mut verdict = sign_verdict(&request, &auth_data, &signing_key);

        // Tamper with the origin
        verdict.client_data_json = verdict
            .client_data_json
            .replace(EXPECTED_ORIGIN, "https://wrong.example.com");

        let cose_key = export_cose_key(&signing_key);
        let result = verify(&verdict, &request, &cose_key);
        assert!(matches!(result, Err(Error::BadOrigin)));
    }

    #[test]
    fn verify_missing_uv_flag() {
        let signing_key = SigningKey::random(&mut OsRng);
        let request = test_request();
        let auth_data = auth_data(0b001); // UP only, no UV
        let verdict = sign_verdict(&request, &auth_data, &signing_key);
        let cose_key = export_cose_key(&signing_key);

        let result = verify(&verdict, &request, &cose_key);
        assert!(matches!(result, Err(Error::MissingUserVerification)));
    }

    #[test]
    fn verify_expired() {
        let signing_key = SigningKey::random(&mut OsRng);
        let mut request = test_request();
        request.expiry = 1; // Already expired
        let auth_data = auth_data(0b101);
        let verdict = sign_verdict(&request, &auth_data, &signing_key);
        let cose_key = export_cose_key(&signing_key);

        let result = verify(&verdict, &request, &cose_key);
        assert!(matches!(result, Err(Error::Expired)));
    }

    #[test]
    fn verify_wrong_key() {
        let signing_key1 = SigningKey::random(&mut OsRng);
        let signing_key2 = SigningKey::random(&mut OsRng);
        let request = test_request();
        let auth_data = auth_data(0b101);
        let verdict = sign_verdict(&request, &auth_data, &signing_key1);
        let cose_key = export_cose_key(&signing_key2); // Wrong key

        let result = verify(&verdict, &request, &cose_key);
        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    // --- Additional tamper vectors per SERVER_PLAN §13 ---

    #[test]
    fn verify_field_reorder_denies() {
        // JSON field reordering changes the canonical hash.
        // Sign original request, verify against reordered one.
        let signing_key = SigningKey::random(&mut OsRng);
        let request = test_request();
        let auth_data = auth_data(0b101);
        let verdict = sign_verdict(&request, &auth_data, &signing_key);
        let cose_key = export_cose_key(&signing_key);

        // Build a reordered request struct (different JSON serialization).
        let mut tampered = test_request();
        // Swapping two string fields changes canonical JSON order.
        tampered.host = request.user.clone();
        tampered.user = request.host.clone();

        let result = verify(&verdict, &tampered, &cose_key);
        assert!(matches!(result, Err(Error::BadChallenge)));
    }

    #[test]
    fn verify_casing_change_denies() {
        // Casing changes in user/host break the signature.
        // Sign original request with correct case, verify against modified request.
        let signing_key = SigningKey::random(&mut OsRng);
        let request = test_request(); // Correct case
        let auth_data = auth_data(0b101);
        let verdict = sign_verdict(&request, &auth_data, &signing_key);
        let cose_key = export_cose_key(&signing_key);

        // Modify request after signing — challenge won't match.
        let mut tampered = test_request();
        tampered.user = "ERIC".to_string(); // uppercase

        let result = verify(&verdict, &tampered, &cose_key);
        assert!(matches!(result, Err(Error::BadChallenge)));
    }

    #[test]
    fn verify_whitespace_change_denies() {
        // Whitespace in cwd changes the canonical hash.
        let signing_key = SigningKey::random(&mut OsRng);
        let request = test_request();
        let auth_data = auth_data(0b101);
        let verdict = sign_verdict(&request, &auth_data, &signing_key);
        let cose_key = export_cose_key(&signing_key);

        let mut tampered = test_request();
        tampered.cwd = "  /home/eric  ".to_string();

        let result = verify(&verdict, &tampered, &cose_key);
        assert!(matches!(result, Err(Error::BadChallenge)));
    }

    #[test]
    fn verify_missing_tty_denies() {
        // Missing tty field (when present in signed request) denies.
        let signing_key = SigningKey::random(&mut OsRng);
        let request = test_request();
        let auth_data = auth_data(0b101);
        let verdict = sign_verdict(&request, &auth_data, &signing_key);
        let cose_key = export_cose_key(&signing_key);

        let mut tampered = test_request();
        tampered.tty = None;

        let result = verify(&verdict, &tampered, &cose_key);
        assert!(matches!(result, Err(Error::BadChallenge)));
    }

    #[test]
    fn verify_wrong_rp_id_denies() {
        // Wrong rpId in authenticator data denies.
        let signing_key = SigningKey::random(&mut OsRng);
        let request = test_request();
        // Build auth_data with wrong rpIdHash.
        let mut hasher = Sha256::new();
        hasher.update(b"wrong.example.com");
        let wrong_hash = hasher.finalize();
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&wrong_hash);
        auth_data.push(0b101);
        auth_data.extend_from_slice(&[0, 0, 0, 1]);

        let verdict = sign_verdict(&request, &auth_data, &signing_key);
        let cose_key = export_cose_key(&signing_key);

        let result = verify(&verdict, &request, &cose_key);
        assert!(matches!(result, Err(Error::BadRpId)));
    }

    #[test]
    fn verify_wrong_type_denies() {
        // client_data.type != "webauthn.get" denies.
        let signing_key = SigningKey::random(&mut OsRng);
        let request = test_request();
        let canonical_json = serde_json::to_string(&request).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(canonical_json.as_bytes());
        hasher.update(b"approve");
        let challenge_hash = hasher.finalize();
        let challenge = URL_SAFE_NO_PAD.encode(challenge_hash);

        let client_data_json = format!(
            r#"{{"type":"webauthn.create","challenge":"{challenge}","origin":"{EXPECTED_ORIGIN}"}}"#
        );

        let auth_data = auth_data(0b101);
        let mut message = Vec::new();
        message.extend_from_slice(&auth_data);
        let mut hasher = Sha256::new();
        hasher.update(client_data_json.as_bytes());
        message.extend_from_slice(&hasher.finalize());

        let signature: Signature = signing_key.sign(&message);

        let verdict = Verdict {
            id: request.id.clone(),
            credential_id: vec![1, 2, 3],
            authenticator_data: auth_data.clone(),
            client_data_json,
            signature: signature.to_der().to_bytes().to_vec(),
        };

        let cose_key = export_cose_key(&signing_key);
        let result = verify(&verdict, &request, &cose_key);
        assert!(matches!(result, Err(Error::UnexpectedCredentialType)));
    }

    #[test]
    fn verify_missing_up_flag_denies() {
        // Missing UP flag denies.
        let signing_key = SigningKey::random(&mut OsRng);
        let request = test_request();
        let auth_data = auth_data(0b100); // UV only, no UP
        let verdict = sign_verdict(&request, &auth_data, &signing_key);
        let cose_key = export_cose_key(&signing_key);

        let result = verify(&verdict, &request, &cose_key);
        assert!(matches!(result, Err(Error::MissingUserPresence)));
    }

    #[test]
    fn verify_malformed_authenticator_data_denies() {
        // Wrong length authenticator data denies.
        let signing_key = SigningKey::random(&mut OsRng);
        let request = test_request();
        // Only 20 bytes instead of 37
        let auth_data = auth_data(0b101)[..20].to_vec();
        let verdict = sign_verdict(&request, &auth_data, &signing_key);
        let cose_key = export_cose_key(&signing_key);

        let result = verify(&verdict, &request, &cose_key);
        assert!(matches!(result, Err(Error::MalformedAuthenticatorData)));
    }
}
