//! Opt-in browser approval for native tool permission prompts.
//!
//! Tool approvals deliberately use a distinct envelope, decision tags, NATS
//! subject tree, and WebAuthn challenge domains. The signed bytes are the
//! exact JSON received from the hook, including its complete tool input.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, signature::Verifier as _};
use serde::{
    Deserialize, Serialize,
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fmt};
use x25519_dalek::StaticSecret;

use crate::{
    Error,
    v1::{
        DeviceKindV1, DevicePublicRecordV1, HookConfigV1, MAX_DEVICES, MAX_ENVELOPE_BYTES,
        MAX_REQUEST_BYTES, SealedDeviceBodyV1, decode_base64url, decode_exact, seal_v1, unseal_v1,
        valid_fingerprint, valid_id, validate_request_timing,
    },
    webauthn_v1::{AssertionOutcomeV1, cose_p256_verifying_key},
};

pub const TOOL_WIRE_VERSION: u8 = 3;
pub const TOOL_ENVELOPE_TYPE: &str = "tool_approval";
pub const TOOL_REQUEST_TYPE: &str = "tool_approval_request";
pub const TOOL_APPROVE_TYPE: &str = "tool_approval_approve_webauthn";
pub const TOOL_DENY_TYPE: &str = "tool_approval_deny_webauthn";
pub const TOOL_ACK_TYPE: &str = "tool_approval_ack";
pub const TOOL_DELIVERY_TYPE: &str = "tool_approval_delivery";
pub const TOOL_APPROVAL_SUBJECT: &str = "oshioki.tool.request";

const TOOL_APPROVE_DOMAIN: &[u8] = b"oshioki/tool-approval/approve/v1\0";
const TOOL_DENY_DOMAIN: &[u8] = b"oshioki/tool-approval/deny/v1\0";
const MAX_TOOL_NAME_BYTES: usize = 256;
const MAX_CONTEXT_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolHarnessV1 {
    Codex,
    Claude,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolAcknowledgementV1 {
    #[serde(rename = "type")]
    pub message_type: String,
    pub version: u8,
    pub request_id: String,
}

impl ToolAcknowledgementV1 {
    pub fn for_request(request_id: &str) -> Self {
        Self {
            message_type: TOOL_ACK_TYPE.into(),
            version: TOOL_WIRE_VERSION,
            request_id: request_id.into(),
        }
    }

    pub fn validate(&self, request_id: &str) -> Result<(), Error> {
        if self.message_type != TOOL_ACK_TYPE
            || self.version != TOOL_WIRE_VERSION
            || self.request_id != request_id
            || !valid_id(request_id)
        {
            return Err(Error::BadVerdict(
                "tool acknowledgement does not match request".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolDeliveryV1 {
    #[serde(rename = "type")]
    pub message_type: String,
    pub version: u8,
    pub request_id: String,
}

impl ToolDeliveryV1 {
    pub fn for_request(request_id: &str) -> Self {
        Self {
            message_type: TOOL_DELIVERY_TYPE.into(),
            version: TOOL_WIRE_VERSION,
            request_id: request_id.into(),
        }
    }

    pub fn validate(&self, request_id: &str) -> Result<(), Error> {
        if self.message_type != TOOL_DELIVERY_TYPE
            || self.version != TOOL_WIRE_VERSION
            || self.request_id != request_id
            || !valid_id(request_id)
        {
            return Err(Error::BadVerdict(
                "tool delivery does not match request".into(),
            ));
        }
        Ok(())
    }
}

impl ToolHarnessV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
        }
    }
}

/// Context copied from the native event. Session and agent labels are display
/// hints supplied by the hook, not authenticated harness identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ToolContextV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_mode: Option<String>,
}

impl ToolContextV1 {
    fn validate(&self) -> Result<(), Error> {
        for value in [
            self.session_id.as_deref(),
            self.turn_id.as_deref(),
            self.agent_id.as_deref(),
            self.agent_type.as_deref(),
            self.permission_mode.as_deref(),
        ] {
            if value.is_some_and(|value| {
                value.is_empty()
                    || value.len() > MAX_CONTEXT_BYTES
                    || value.chars().any(char::is_control)
            }) {
                return Err(Error::InvalidRequest("invalid tool context field".into()));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolApprovalRequestV1 {
    #[serde(rename = "type")]
    pub message_type: String,
    pub version: u8,
    pub request_id: String,
    /// Random 128-bit freshness value in base64url form.
    pub nonce: String,
    pub harness: ToolHarnessV1,
    pub event: String,
    pub tool_name: String,
    pub tool_input: Value,
    pub cwd: String,
    /// Exact native hook JSON supplied on stdin. This retains every context
    /// field, including fields this version does not interpret, and is signed
    /// as part of the enclosing request. The parsed fields above must match it.
    pub native_event_json: String,
    #[serde(default)]
    pub context: ToolContextV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub issued_at: i64,
    pub expires_at: i64,
}

impl ToolApprovalRequestV1 {
    pub fn validate(&self) -> Result<(), Error> {
        if self.message_type != TOOL_REQUEST_TYPE
            || self.version != TOOL_WIRE_VERSION
            || !valid_id(&self.request_id)
            || decode_base64url(&self.nonce)?.len() != 16
            || self.event != "PermissionRequest"
            || self.tool_name.is_empty()
            || self.tool_name.len() > MAX_TOOL_NAME_BYTES
            || self.cwd.is_empty()
            || self.cwd.len() > MAX_CONTEXT_BYTES
            || self.native_event_json.is_empty()
            || self.native_event_json.len() > MAX_REQUEST_BYTES
            || self.description.as_ref().is_some_and(|value| {
                value.len() > MAX_CONTEXT_BYTES || value.chars().any(char::is_control)
            })
            || self.tool_input.is_null()
        {
            return Err(Error::InvalidRequest(
                "invalid tool approval request".into(),
            ));
        }
        self.context.validate()?;
        let native_event = strict_json_value(self.native_event_json.as_bytes())?;
        let Value::Object(_) = native_event else {
            return Err(Error::InvalidRequest(
                "native tool event must be a JSON object".into(),
            ));
        };
        if native_event.get("hook_event_name").and_then(Value::as_str) != Some(self.event.as_str())
            || native_event.get("tool_name").and_then(Value::as_str)
                != Some(self.tool_name.as_str())
            || native_event.get("tool_input") != Some(&self.tool_input)
            || native_event.get("cwd").and_then(Value::as_str) != Some(self.cwd.as_str())
            || !context_matches(
                &native_event,
                "session_id",
                self.context.session_id.as_deref(),
            )
            || !context_matches(&native_event, "turn_id", self.context.turn_id.as_deref())
            || !context_matches(&native_event, "agent_id", self.context.agent_id.as_deref())
            || !context_matches(
                &native_event,
                "agent_type",
                self.context.agent_type.as_deref(),
            )
            || !context_matches(
                &native_event,
                "permission_mode",
                self.context.permission_mode.as_deref(),
            )
        {
            return Err(Error::InvalidRequest(
                "tool approval fields do not match the retained native event".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_at(&self, now: i64) -> Result<(), Error> {
        self.validate()?;
        validate_request_timing(self.issued_at, self.expires_at, now)
    }
}

/// Parse a request while rejecting duplicate object keys at every depth.
/// serde_json's ordinary Value parser keeps the last duplicate key, which
/// would make the displayed value differ from the value a reviewer expects.
pub fn parse_tool_request_at(raw: &[u8], now: i64) -> Result<ToolApprovalRequestV1, Error> {
    if raw.len() > MAX_REQUEST_BYTES {
        return Err(Error::InvalidRequest("tool request exceeds 256 KiB".into()));
    }
    let value = strict_json_value(raw)?;
    let request: ToolApprovalRequestV1 = serde_json::from_value(value)
        .map_err(|error| Error::InvalidRequest(format!("decode tool request: {error}")))?;
    request.validate_at(now)?;
    Ok(request)
}

fn context_matches(event: &Value, key: &str, expected: Option<&str>) -> bool {
    match (event.get(key), expected) {
        (None, None) | (Some(Value::Null), None) => true,
        (Some(Value::String(actual)), Some(expected)) => actual == expected,
        _ => false,
    }
}

fn strict_json_value(raw: &[u8]) -> Result<Value, Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = StrictValueSeed
        .deserialize(&mut deserializer)
        .map_err(|error| Error::InvalidRequest(format!("decode tool JSON: {error}")))?;
    deserializer
        .end()
        .map_err(|error| Error::InvalidRequest(format!("decode tool JSON: {error}")))?;
    Ok(value)
}

struct StrictValueSeed;

impl<'de> DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::from(value))
    }
    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::from(value))
    }
    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }
    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictValueSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            let value = map.next_value_seed(StrictValueSeed)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolSealedBodyV1 {
    pub device_fingerprint: String,
    pub ephemeral_pub: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolApprovalEnvelopeV1 {
    #[serde(rename = "type")]
    pub message_type: String,
    pub version: u8,
    pub request_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub sealed: Vec<ToolSealedBodyV1>,
}

impl ToolApprovalEnvelopeV1 {
    pub fn validate_at(&self, now: i64) -> Result<(), Error> {
        if self.message_type != TOOL_ENVELOPE_TYPE
            || self.version != TOOL_WIRE_VERSION
            || !valid_id(&self.request_id)
            || self.sealed.is_empty()
            || self.sealed.len() > MAX_DEVICES
        {
            return Err(Error::InvalidRequest(
                "invalid tool approval envelope".into(),
            ));
        }
        for body in &self.sealed {
            if !valid_fingerprint(&body.device_fingerprint)
                || decode_exact(&body.ephemeral_pub, 32).is_err()
                || decode_exact(&body.nonce, 12).is_err()
                || decode_base64url(&body.ciphertext)?.len() < 16
            {
                return Err(Error::InvalidRequest("invalid tool sealed body".into()));
            }
        }
        let bytes =
            serde_json::to_vec(self).map_err(|error| Error::InvalidRequest(error.to_string()))?;
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(Error::InvalidRequest("tool envelope exceeds 3 MiB".into()));
        }
        validate_request_timing(self.issued_at, self.expires_at, now)
    }
}

pub fn seal_tool_request_v1(
    request: &ToolApprovalRequestV1,
    devices: &[DevicePublicRecordV1],
) -> Result<(Vec<u8>, ToolApprovalEnvelopeV1), Error> {
    request.validate()?;
    if devices.is_empty() || devices.len() > MAX_DEVICES {
        return Err(Error::InvalidRequest("invalid tool recipient count".into()));
    }
    let raw =
        serde_json::to_vec(request).map_err(|error| Error::InvalidRequest(error.to_string()))?;
    if raw.len() > MAX_REQUEST_BYTES {
        return Err(Error::InvalidRequest("tool request exceeds 256 KiB".into()));
    }
    let sealed = devices
        .iter()
        .map(|device| {
            seal_v1(&raw, device).map(|body| ToolSealedBodyV1 {
                device_fingerprint: body.device_fingerprint,
                ephemeral_pub: body.ephemeral_pub,
                nonce: body.nonce,
                ciphertext: body.ciphertext,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let envelope = ToolApprovalEnvelopeV1 {
        message_type: TOOL_ENVELOPE_TYPE.into(),
        version: TOOL_WIRE_VERSION,
        request_id: request.request_id.clone(),
        issued_at: request.issued_at,
        expires_at: request.expires_at,
        sealed,
    };
    let bytes =
        serde_json::to_vec(&envelope).map_err(|error| Error::InvalidRequest(error.to_string()))?;
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(Error::InvalidRequest("tool envelope exceeds 3 MiB".into()));
    }
    Ok((raw, envelope))
}

pub fn unseal_tool_body_v1(
    body: &ToolSealedBodyV1,
    box_secret: &StaticSecret,
) -> Result<Vec<u8>, Error> {
    unseal_v1(
        &SealedDeviceBodyV1 {
            device_fingerprint: body.device_fingerprint.clone(),
            ephemeral_pub: body.ephemeral_pub.clone(),
            nonce: body.nonce.clone(),
            ciphertext: body.ciphertext.clone(),
        },
        box_secret,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolDecisionActionV1 {
    Approve,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolApprovalWebauthnV1 {
    pub version: u8,
    pub request_id: String,
    pub device_fingerprint: String,
    pub credential_id: String,
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
}

impl ToolApprovalWebauthnV1 {
    pub fn validate_shape(&self) -> Result<(), Error> {
        let auth_data = decode_base64url(&self.authenticator_data)?;
        let client_data = decode_base64url(&self.client_data_json)?;
        let signature = decode_base64url(&self.signature)?;
        if self.version != TOOL_WIRE_VERSION
            || !valid_id(&self.request_id)
            || !valid_fingerprint(&self.device_fingerprint)
            || decode_base64url(&self.credential_id)?.is_empty()
            || !(37..=1024).contains(&auth_data.len())
            || client_data.is_empty()
            || client_data.len() > 16 * 1024
            || !(8..=256).contains(&signature.len())
        {
            return Err(Error::BadVerdict(
                "invalid tool WebAuthn decision shape".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ToolApprovalDecisionV1 {
    #[serde(rename = "tool_approval_approve_webauthn")]
    Approve(ToolApprovalWebauthnV1),
    #[serde(rename = "tool_approval_deny_webauthn")]
    Deny(ToolApprovalWebauthnV1),
}

impl ToolApprovalDecisionV1 {
    pub fn request_id(&self) -> &str {
        match self {
            Self::Approve(value) | Self::Deny(value) => &value.request_id,
        }
    }
    pub fn device_fingerprint(&self) -> &str {
        match self {
            Self::Approve(value) | Self::Deny(value) => &value.device_fingerprint,
        }
    }
    pub fn assertion(&self) -> &ToolApprovalWebauthnV1 {
        match self {
            Self::Approve(value) | Self::Deny(value) => value,
        }
    }
    pub fn action(&self) -> ToolDecisionActionV1 {
        match self {
            Self::Approve(_) => ToolDecisionActionV1::Approve,
            Self::Deny(_) => ToolDecisionActionV1::Deny,
        }
    }
    pub fn validate_shape(&self) -> Result<(), Error> {
        self.assertion().validate_shape()
    }
}

pub fn tool_approval_challenge(action: ToolDecisionActionV1, raw_request_json: &[u8]) -> [u8; 32] {
    let domain = match action {
        ToolDecisionActionV1::Approve => TOOL_APPROVE_DOMAIN,
        ToolDecisionActionV1::Deny => TOOL_DENY_DOMAIN,
    };
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(raw_request_json);
    hash.finalize().into()
}

pub fn verify_tool_decision_v1(
    decision: &ToolApprovalDecisionV1,
    raw_request_json: &[u8],
    device: &DevicePublicRecordV1,
    config: &HookConfigV1,
    now: i64,
) -> Result<AssertionOutcomeV1, Error> {
    let request = parse_tool_request_at(raw_request_json, now)?;
    decision.validate_shape()?;
    device.validate()?;
    let assertion = decision.assertion();
    if device.kind != DeviceKindV1::Webauthn
        || assertion.device_fingerprint != device.fingerprint
        || assertion.credential_id != device.credential_id
        || assertion.request_id != request.request_id
    {
        return Err(Error::BadVerdict(
            "tool decision does not match request or pinned WebAuthn device".into(),
        ));
    }
    verify_webauthn_for_challenge(
        &assertion.authenticator_data,
        &assertion.client_data_json,
        &assertion.signature,
        &tool_approval_challenge(decision.action(), raw_request_json),
        device,
        config,
    )
}

fn verify_webauthn_for_challenge(
    authenticator_data: &str,
    client_data_json: &str,
    signature: &str,
    expected_challenge: &[u8; 32],
    device: &DevicePublicRecordV1,
    config: &HookConfigV1,
) -> Result<AssertionOutcomeV1, Error> {
    config.validate()?;
    let client_data_json = decode_base64url(client_data_json)?;
    #[derive(Deserialize)]
    struct ClientData {
        #[serde(rename = "type")]
        type_: String,
        challenge: String,
        origin: String,
        #[serde(default)]
        cross_origin: bool,
    }
    let client_data: ClientData =
        serde_json::from_slice(&client_data_json).map_err(|_| Error::MalformedClientData)?;
    if client_data.type_ != "webauthn.get" {
        return Err(Error::UnexpectedCredentialType);
    }
    if client_data.origin != config.origin || client_data.cross_origin {
        return Err(Error::BadOrigin);
    }
    if client_data.challenge != URL_SAFE_NO_PAD.encode(expected_challenge) {
        return Err(Error::BadChallenge);
    }
    let auth_data = decode_base64url(authenticator_data)?;
    if auth_data.len() < 37 {
        return Err(Error::MalformedAuthenticatorData);
    }
    if &auth_data[..32] != Sha256::digest(config.rp_id.as_bytes()).as_slice() {
        return Err(Error::BadRpId);
    }
    if auth_data[32] & 0x01 == 0 {
        return Err(Error::MissingUserPresence);
    }
    if auth_data[32] & 0x04 == 0 {
        return Err(Error::MissingUserVerification);
    }
    let credential_key = decode_base64url(&device.credential_public_key)?;
    let verifying_key = cose_p256_verifying_key(&credential_key)?;
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data_json));
    let signature =
        Signature::from_der(&decode_base64url(signature)?).map_err(|_| Error::InvalidSignature)?;
    verifying_key
        .verify(&signed, &signature)
        .map_err(|_| Error::InvalidSignature)?;
    let observed_sign_count = u32::from_be_bytes(
        auth_data[33..37]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn request_json(input: &str) -> Vec<u8> {
        let native_event = format!(
            r#"{{"hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{input},"cwd":"/tmp/project","session_id":"session-1","turn_id":"turn-1"}}"#
        );
        format!(
            r#"{{"type":"tool_approval_request","version":3,"request_id":"tool-1","nonce":"AAAAAAAAAAAAAAAAAAAAAA","harness":"codex","event":"PermissionRequest","tool_name":"Bash","tool_input":{input},"cwd":"/tmp/project","native_event_json":{},"context":{{"session_id":"session-1","turn_id":"turn-1"}},"issued_at":1000,"expires_at":1090}}"#,
            serde_json::to_string(&native_event).unwrap()
        )
        .into_bytes()
    }

    #[test]
    fn challenge_binds_raw_request_and_has_separate_decision_domains() {
        let raw = request_json(r#"{"command":"echo hello"}"#);
        let approval = tool_approval_challenge(ToolDecisionActionV1::Approve, &raw);
        let denial = tool_approval_challenge(ToolDecisionActionV1::Deny, &raw);
        assert_ne!(approval, denial);
        assert_ne!(
            approval,
            tool_approval_challenge(
                ToolDecisionActionV1::Approve,
                &request_json(r#"{ "command":"echo hello"}"#),
            )
        );
    }

    #[test]
    fn parser_accepts_a_native_request_and_preserves_complete_tool_input() {
        let raw = request_json(r#"{"command":"echo hello","metadata":{"cwd":"/tmp"}}"#);
        let parsed = parse_tool_request_at(&raw, 1000).unwrap();
        assert_eq!(parsed.harness, ToolHarnessV1::Codex);
        assert_eq!(parsed.tool_input["command"], "echo hello");
        assert_eq!(parsed.tool_input["metadata"]["cwd"], "/tmp");
        assert_eq!(parsed.context.session_id.as_deref(), Some("session-1"));
    }

    #[test]
    fn parser_rejects_duplicate_keys_at_every_depth() {
        for raw in [
            request_json(r#"{"command":"one","command":"two"}"#),
            br#"{"type":"tool_approval_request","version":3,"request_id":"tool-1","nonce":"AAAAAAAAAAAAAAAAAAAAAA","harness":"codex","event":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"echo"},"tool_input":{"command":"other"},"cwd":"/tmp","issued_at":1000,"expires_at":1090}"#.to_vec(),
        ] {
            assert!(parse_tool_request_at(&raw, 1000).is_err());
        }
        let embedded = request_json(r#"{"command":"echo"}"#);
        let mut request = serde_json::from_slice::<Value>(&embedded).unwrap();
        request["native_event_json"] = Value::String(
            r#"{"hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"echo"},"cwd":"/tmp/project","session_id":"session-1","turn_id":"turn-1","future":"one","future":"two"}"#.into(),
        );
        assert!(parse_tool_request_at(&serde_json::to_vec(&request).unwrap(), 1000).is_err());
    }

    #[test]
    fn parser_rejects_unsupported_events_versions_and_expired_requests() {
        let mut request =
            serde_json::from_slice::<Value>(&request_json(r#"{"command":"echo"}"#)).unwrap();
        request["version"] = Value::from(2);
        assert!(parse_tool_request_at(&serde_json::to_vec(&request).unwrap(), 1000).is_err());
        request["version"] = Value::from(3);
        request["event"] = Value::String("PreToolUse".into());
        assert!(parse_tool_request_at(&serde_json::to_vec(&request).unwrap(), 1000).is_err());
        request["event"] = Value::String("PermissionRequest".into());
        assert!(parse_tool_request_at(&serde_json::to_vec(&request).unwrap(), 1090).is_err());
    }

    #[test]
    fn request_and_envelope_limits_are_kept_at_the_existing_bounds() {
        assert_eq!(MAX_REQUEST_BYTES, 256 * 1024);
        assert_eq!(MAX_ENVELOPE_BYTES, 3 * 1024 * 1024);
        assert_eq!(MAX_DEVICES, 8);
        assert!(parse_tool_request_at(&vec![b' '; MAX_REQUEST_BYTES + 1], 1000).is_err());
    }
}
