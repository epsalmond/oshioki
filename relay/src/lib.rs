//! A separate, opt-in browser ceremony protocol. These signatures cannot
//! authorize sudo or satisfy Google's `WebAuthn` challenge.

use std::collections::BTreeMap;

use anyhow::{Result, bail, ensure};
use oshioki_protocol::{decode_base64url, encode_base64url};
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer as _, Verifier as _},
};
use serde::{Deserialize, Serialize};
use url::Url;

pub const MAX_FRAME: usize = 16_384;
pub const MAX_LIFETIME: u64 = 300;
const DOMAIN: &[u8] = b"oshioki/browser-ceremony/v1\0";

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Action {
    Probe,
    Offer { nonce: String },
    Authorize { nonce: String, account: String },
    Authorized { nonce: String, signature: String },
    Start { nonce: String, url: String },
    Ready,
    Stop,
    Failed,
    Closed,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub version: u8,
    pub attempt: String,
    pub expires: u64,
    pub action: Action,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    body: String,
    signature: String,
}

pub fn sign(message: &Message, key: &SigningKey) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(message)?;
    let signature: Signature = key.sign(&[DOMAIN, &body].concat());
    let bytes = serde_json::to_vec(&Envelope {
        body: encode_base64url(&body),
        signature: encode_base64url(signature.to_der().as_bytes()),
    })?;
    ensure!(bytes.len() <= MAX_FRAME, "ceremony frame too large");
    Ok(bytes)
}

pub fn verify(bytes: &[u8], key: &VerifyingKey, now: u64) -> Result<Message> {
    ensure!(bytes.len() <= MAX_FRAME, "ceremony frame too large");
    let envelope: Envelope = serde_json::from_slice(bytes)?;
    let body = decode_base64url(&envelope.body)?;
    let signature = Signature::from_der(&decode_base64url(&envelope.signature)?)?;
    key.verify(&[DOMAIN, &body].concat(), &signature)?;
    let message: Message = serde_json::from_slice(&body)?;
    ensure!(message.version == 1, "unsupported ceremony version");
    ensure!(
        uuid::Uuid::parse_str(&message.attempt).is_ok_and(|id| id.to_string() == message.attempt),
        "invalid attempt id"
    );
    ensure!(
        message.expires > now && message.expires - now <= MAX_LIFETIME,
        "invalid ceremony expiry"
    );
    Ok(message)
}

/// Challenge signed by the Mac's enrolled Oshioki Secure Enclave identity.
/// Relay keys authenticate transport; this separate signature proves that a
/// person approved this account-bound ceremony on the Mac.
pub fn approval_challenge(
    lane: &str,
    attempt: &str,
    expires: u64,
    nonce: &str,
    account: &str,
) -> Vec<u8> {
    oshioki_protocol::browser_relay_challenge(lane, attempt, expires, nonce, account)
}

/// Accept only the first-party gcloud authorization-code flow. Unknown and
/// duplicated parameters fail closed, including credential-bearing fields.
/// Return the sole loopback callback port; destinations never come from NATS.
pub fn google_callback_port(raw: &str) -> Result<u16> {
    ensure!(
        raw.len() <= 8192
            && raw.is_ascii()
            && !raw.bytes().any(|b| b.is_ascii_control() || b == b'\\'),
        "invalid OAuth URL encoding"
    );
    let url = Url::parse(raw)?;
    ensure!(
        url.scheme() == "https"
            && url.host_str() == Some("accounts.google.com")
            && url.port().is_none()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && matches!(url.path(), "/o/oauth2/auth" | "/o/oauth2/v2/auth"),
        "OAuth endpoint outside allowlist"
    );
    let mut params = BTreeMap::new();
    for (name, value) in url.query_pairs() {
        ensure!(
            matches!(
                name.as_ref(),
                "client_id"
                    | "redirect_uri"
                    | "response_type"
                    | "scope"
                    | "state"
                    | "code_challenge"
                    | "code_challenge_method"
                    | "access_type"
                    | "prompt"
                    | "login_hint"
                    | "include_granted_scopes"
                    | "rapt"
            ),
            "OAuth parameter outside allowlist"
        );
        // rapt is a reauthentication proof token, never a relay payload.
        ensure!(
            name != "rapt",
            "reauthentication proof tokens cannot be relayed"
        );
        ensure!(
            params
                .insert(name.into_owned(), value.into_owned())
                .is_none(),
            "duplicate OAuth parameter"
        );
    }
    let get = |name: &str| params.get(name).map(String::as_str).unwrap_or_default();
    ensure!(
        get("client_id") == "32555940559.apps.googleusercontent.com"
            && get("response_type") == "code",
        "unsupported OAuth client or response type"
    );
    ensure!(
        !get("state").is_empty() && !get("scope").is_empty(),
        "missing OAuth state or scope"
    );
    ensure!(
        get("code_challenge_method") == "S256"
            && decode_base64url(get("code_challenge"))?.len() == 32,
        "PKCE S256 is required"
    );
    let redirect = get("redirect_uri");
    let callback = Url::parse(redirect)?;
    let Some(port) = callback.port() else {
        bail!("explicit callback port required")
    };
    ensure!(
        port >= 1024 && redirect == format!("http://localhost:{port}/"),
        "callback must be canonical localhost on an unprivileged port"
    );
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn url() -> String {
        format!(
            "https://accounts.google.com/o/oauth2/auth?client_id=32555940559.apps.googleusercontent.com&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8085%2F&scope=openid&state=example&code_challenge_method=S256&code_challenge={}",
            encode_base64url(&[7; 32])
        )
    }

    #[test]
    fn validates_google_and_canonical_loopback_only() {
        assert_eq!(google_callback_port(&url()).unwrap(), 8085);
        for value in [
            url().replace("accounts.google.com", "accounts.google.com.evil.test"),
            url().replace("https://", "http://"),
            url().replace("accounts.google.com", "user@accounts.google.com"),
            url().replace("localhost", "127.0.0.1"),
            url().replace("8085", "22"),
            url().replace("response_type=code", "response_type=token"),
            url().replace("method=S256", "method=plain"),
            url().replace("32555940559", "attacker"),
            format!("{}&redirect_uri=http://localhost:8888/", url()),
            format!("{}&access_token=secret", url()),
            format!("{}&code=secret", url()),
            format!("{}&rapt=secret", url()),
            format!("{}#fragment", url()),
        ] {
            assert!(
                google_callback_port(&value).is_err(),
                "accepted malformed URL"
            );
        }
    }

    #[test]
    fn signatures_bind_type_id_expiry_and_exact_body() {
        let key = SigningKey::random(&mut rand::rngs::OsRng);
        let other = SigningKey::random(&mut rand::rngs::OsRng);
        let message = Message {
            version: 1,
            attempt: uuid::Uuid::new_v4().to_string(),
            expires: 200,
            action: Action::Probe,
        };
        let bytes = sign(&message, &key).unwrap();
        assert!(verify(&bytes, key.verifying_key(), 100).is_ok());
        assert!(verify(&bytes, other.verifying_key(), 100).is_err());
        assert!(verify(&bytes, key.verifying_key(), 200).is_err());
        assert!(verify(&bytes, key.verifying_key(), 0).is_ok());
        let mut envelope: Envelope = serde_json::from_slice(&bytes).unwrap();
        let mut changed = message;
        changed.action = Action::Stop;
        envelope.body = encode_base64url(&serde_json::to_vec(&changed).unwrap());
        assert!(
            verify(
                &serde_json::to_vec(&envelope).unwrap(),
                key.verifying_key(),
                100
            )
            .is_err()
        );
        changed.expires = 401;
        assert!(verify(&sign(&changed, &key).unwrap(), key.verifying_key(), 100).is_err());
    }

    #[test]
    fn browser_approval_binds_lane_attempt_expiry_nonce_and_account() {
        let baseline = approval_challenge("lane-a", "attempt-a", 200, "nonce-a", "a@example.com");
        for changed in [
            approval_challenge("lane-b", "attempt-a", 200, "nonce-a", "a@example.com"),
            approval_challenge("lane-a", "attempt-b", 200, "nonce-a", "a@example.com"),
            approval_challenge("lane-a", "attempt-a", 201, "nonce-a", "a@example.com"),
            approval_challenge("lane-a", "attempt-a", 200, "nonce-b", "a@example.com"),
            approval_challenge("lane-a", "attempt-a", 200, "nonce-a", "b@example.com"),
        ] {
            assert_ne!(baseline, changed);
        }
        assert_ne!(
            oshioki_protocol::browser_relay_signature_payload(&baseline),
            baseline
        );
    }
}
