//! Browser backed decisions for native coding-agent permission prompts.

use anyhow::{Context as _, Result, bail};
use clap::{Subcommand, ValueEnum};
use oshioki_protocol::{
    DeviceKindV1, HookConfigV1, ToolApprovalDecisionV1, ToolApprovalRequestV1, ToolContextV1,
    ToolDecisionActionV1, ToolHarnessV1, seal_tool_request_v1, verify_tool_decision_v1,
};
use oshioki_transport::{HookProgress, HookTransport, NatsTransport};
use rand::RngCore as _;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::Instant;
use url::Url;
use uuid::Uuid;

const PROFILE_ROOT_NAME: &str = "oshioki/approvals";
const ACTIVE_PROFILE_FILE: &str = "active-profile";
const CONFIG_ENV_FILE: &str = "config.env";
const MAX_HARNESS_CONFIG_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROFILE_CONFIG_BYTES: usize = 64 * 1024;
const MAX_PROFILE_REGISTRY_BYTES: usize = 128 * 1024;
const MAX_PROFILE_CREDENTIAL_BYTES: usize = 16 * 1024;
const MAX_NATIVE_EVENT_BYTES: usize = oshioki_protocol::v1::MAX_REQUEST_BYTES;
const MAX_DECISION_BYTES: usize = 64 * 1024;
const TOOL_REQUEST_LIFETIME_SECS: i64 = 90;
const TOOL_DECISION_WAIT: Duration = Duration::from_secs(85);
const ADAPTER_BUDGET: Duration = Duration::from_secs(105);
const HOOK_TIMEOUT_SECONDS: u64 = 120;
const OWNED_HOOK_TAG: &str = "oshioki-managed-hook-v1";
const STATUS_APPROVAL: &str = "Waiting for Oshioki browser approval";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(super) enum HarnessArg {
    Codex,
    Claude,
}

impl HarnessArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
        }
    }

    fn protocol(self) -> ToolHarnessV1 {
        match self {
            Self::Codex => ToolHarnessV1::Codex,
            Self::Claude => ToolHarnessV1::Claude,
        }
    }

    fn status_message() -> &'static str {
        STATUS_APPROVAL
    }

    fn all_marker(self) -> String {
        format!("{OWNED_HOOK_TAG}-{}", self.as_str())
    }
}

#[derive(Debug, Subcommand)]
pub(super) enum ApprovalCommand {
    /// Create a fresh user-owned profile and enroll its browser authenticator.
    Setup {
        /// A short name for this user's independent approval profile.
        #[arg(long)]
        profile: String,
        /// Public HTTPS origin of the Oshioki server.
        #[arg(long)]
        server_url: String,
        /// Owner-only NATS requester credentials for this user.
        #[arg(long)]
        nats_config: PathBuf,
    },
    /// Add the one-shot permission hook to user configuration.
    Install {
        /// Native agents to configure.
        #[arg(value_enum, required = true, num_args = 1..)]
        harnesses: Vec<HarnessArg>,
    },
    /// Handle one native `PermissionRequest` event from stdin.
    Request {
        /// Native agent that produced the event.
        #[arg(long, value_enum)]
        harness: HarnessArg,
        /// Internal ownership marker used by installed hook entries.
        #[arg(long, hide = true)]
        managed_hook: Option<String>,
    },
    /// Remove only Oshioki-owned permission hook entries.
    Uninstall {
        /// Native agents to remove.
        #[arg(value_enum, required = true, num_args = 1..)]
        harnesses: Vec<HarnessArg>,
    },
}

pub(super) async fn run(command: ApprovalCommand) -> Result<()> {
    match command {
        ApprovalCommand::Setup {
            profile,
            server_url,
            nats_config,
        } => setup(&profile, &server_url, &nats_config).await,
        ApprovalCommand::Install { harnesses } => install(harnesses),
        ApprovalCommand::Request {
            harness,
            managed_hook,
        } => {
            // This is a native permission adapter. Every local error means
            // “no Oshioki decision”; the host agent keeps its normal prompt.
            if managed_hook
                .as_deref()
                .is_some_and(|tag| tag != harness.all_marker())
            {
                return Ok(());
            }
            if let Err(error) = request_and_render(harness).await {
                eprintln!("oshioki approvals: {}", super::display_error(&error));
            }
            Ok(())
        }
        ApprovalCommand::Uninstall { harnesses } => uninstall(harnesses),
    }
}

async fn setup(profile: &str, server_url: &str, nats_config: &Path) -> Result<()> {
    require_user_session()?;
    validate_profile_id(profile)?;
    let credentials = read_nats_config(nats_config)?;
    let config = hook_config(server_url)?;
    let root = approvals_root()?;
    ensure_approvals_tree(&root)?;
    let profile_dir = root.join(profile);
    ensure_user_private_directory(&profile_dir)?;

    let config_path = profile_dir.join("hook.json");
    let credentials_path = profile_dir.join(CONFIG_ENV_FILE);

    if config_path.exists() {
        ensure_user_private_file(&config_path)?;
        let current = load_profile_hook_config(&profile_dir)?;
        if current != config {
            bail!("profile already exists with a different server URL; choose another --profile");
        }
    } else {
        write_private_json(&config_path, &config)?;
    }

    if credentials_path.exists() {
        let current = read_profile_credentials(&credentials_path)?;
        if current != credentials {
            bail!(
                "profile already exists with different NATS credentials; choose another --profile"
            );
        }
    } else {
        let contents = format!(
            "NATS_URL={}\nNATS_USER={}\nNATS_PASS={}\n",
            credentials["NATS_URL"], credentials["NATS_USER"], credentials["NATS_PASS"]
        );
        write_atomic(&credentials_path, contents.as_bytes(), 0o600, true)?;
    }

    let mut registry = load_profile_registry(&profile_dir)?;
    registry.validate()?;
    let has_active_browser = registry
        .devices
        .iter()
        .any(|device| device.active && device.kind == DeviceKindV1::Webauthn);
    if !profile_setup_complete(&profile_dir)? || !has_active_browser {
        // This is the normal enrollment flow with an explicit user profile;
        // no root-owned hook files or host pin registry are consulted.
        super::cmd_enroll_at(&profile_dir, None, false, true).await?;
        registry = load_profile_registry(&profile_dir)?;
        if !registry
            .devices
            .iter()
            .any(|device| device.active && device.kind == DeviceKindV1::Webauthn)
        {
            bail!("enrollment completed without an active browser authenticator");
        }
        write_atomic(
            &profile_dir.join("setup-complete"),
            b"browser-enrolled-v1\n",
            0o600,
            true,
        )?;
    }

    write_active_profile(&root, profile)?;
    println!("Oshioki approvals profile '{profile}' is ready.");
    println!("Next: oshioki approvals install codex claude");
    Ok(())
}

fn install(harnesses: Vec<HarnessArg>) -> Result<()> {
    require_user_session()?;
    for harness in unique_harnesses(harnesses) {
        let path = user_settings_path(harness)?;
        ensure_settings_parent(path.parent().context("settings file has no parent")?)?;
        install_harness_at(&path, harness)?;
        println!(
            "Installed Oshioki PermissionRequest hook for {}.",
            harness.as_str()
        );
    }
    println!("Restart the native agent to load the hook.");
    println!("Codex will ask you to review and trust the new hook in /hooks.");
    Ok(())
}

fn uninstall(harnesses: Vec<HarnessArg>) -> Result<()> {
    require_user_session()?;
    for harness in unique_harnesses(harnesses) {
        let path = user_settings_path(harness)?;
        if !path.exists() {
            println!(
                "No Oshioki PermissionRequest hook found for {}.",
                harness.as_str()
            );
            continue;
        }
        let changed = uninstall_harness_at(&path, harness)?;
        if changed {
            println!(
                "Removed Oshioki PermissionRequest hook for {}.",
                harness.as_str()
            );
        } else {
            println!(
                "No Oshioki PermissionRequest hook found for {}.",
                harness.as_str()
            );
        }
    }
    println!("Restart the native agent to apply the configuration change.");
    Ok(())
}

fn unique_harnesses(harnesses: Vec<HarnessArg>) -> Vec<HarnessArg> {
    let mut seen = HashSet::new();
    harnesses
        .into_iter()
        .filter(|harness| seen.insert(harness.as_str()))
        .collect()
}

fn install_harness_at(path: &Path, harness: HarnessArg) -> Result<()> {
    let mut config = read_settings(path)?;
    remove_owned_hook(&mut config, harness)?;
    let command = managed_command(harness)?;
    let group = serde_json::json!({
        "hooks": [{
            "type": "command",
            "command": command,
            "timeout": HOOK_TIMEOUT_SECONDS,
            "statusMessage": HarnessArg::status_message()
        }]
    });
    permission_request_groups(&mut config)?.push(group);
    write_settings(path, &config)
}

fn uninstall_harness_at(path: &Path, harness: HarnessArg) -> Result<bool> {
    let mut config = read_settings(path)?;
    let changed = remove_owned_hook(&mut config, harness)?;
    if changed {
        write_settings(path, &config)?;
    }
    Ok(changed)
}

fn permission_request_groups(config: &mut Value) -> Result<&mut Vec<Value>> {
    let root = config
        .as_object_mut()
        .context("native agent settings root must be a JSON object")?;
    let hooks = root
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .context("native agent settings hooks must be an object")?;
    hooks
        .entry("PermissionRequest")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .context("PermissionRequest settings must be an array")
}

fn remove_owned_hook(config: &mut Value, harness: HarnessArg) -> Result<bool> {
    let Some(hooks) = config.get_mut("hooks") else {
        return Ok(false);
    };
    let Some(events) = hooks.as_object_mut() else {
        bail!("native agent settings hooks must be an object");
    };
    let Some(groups) = events.get_mut("PermissionRequest") else {
        return Ok(false);
    };
    let Some(groups) = groups.as_array_mut() else {
        bail!("PermissionRequest settings must be an array");
    };
    let marker = harness.all_marker();
    let mut changed = false;
    let mut retained = Vec::with_capacity(groups.len());
    for mut group in std::mem::take(groups) {
        let removed_from_group = group
            .get_mut("hooks")
            .and_then(Value::as_array_mut)
            .is_some_and(|handlers| {
                let before = handlers.len();
                handlers.retain(|handler| !is_owned_handler(handler, &marker));
                before != handlers.len()
            });
        changed |= removed_from_group;
        let no_handlers = group
            .get("hooks")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty);
        let otherwise_empty = group
            .as_object()
            .is_some_and(|object| object.keys().all(|key| key == "hooks" || key == "matcher"));
        if !(removed_from_group && no_handlers && otherwise_empty) {
            retained.push(group);
        }
    }
    *groups = retained;
    Ok(changed)
}

fn is_owned_handler(handler: &Value, marker: &str) -> bool {
    handler.get("type").and_then(Value::as_str) == Some("command")
        && handler
            .get("command")
            .and_then(Value::as_str)
            .is_some_and(|command| command.contains(marker))
}

fn managed_command(harness: HarnessArg) -> Result<String> {
    let executable = std::env::current_exe().context("locate the oshioki executable")?;
    let marker = harness.all_marker();
    Ok(format!(
        "{} approvals request --harness {} --managed-hook={marker}",
        shell_quote(&executable.to_string_lossy()),
        harness.as_str()
    ))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn read_settings(path: &Path) -> Result<Value> {
    let value = if path.exists() {
        ensure_settings_file_owned(path)?;
        read_strict_json_file(path, MAX_HARNESS_CONFIG_BYTES)?
    } else {
        Value::Object(Map::new())
    };
    value
        .as_object()
        .context("native agent settings root must be a JSON object")?;
    Ok(value)
}

fn write_settings(path: &Path, value: &Value) -> Result<()> {
    let mut contents = serde_json::to_vec_pretty(value)?;
    contents.push(b'\n');
    write_atomic(path, &contents, 0o600, false)
}

async fn request_and_render(harness: HarnessArg) -> Result<()> {
    let deadline = Instant::now() + ADAPTER_BUDGET;
    let result = tokio::time::timeout_at(deadline, async {
        let action = request_decision(harness).await?;
        let bytes =
            native_output(Some(action))?.context("verified decision produced no native output")?;
        io::stdout().lock().write_all(&bytes)?;
        Ok::<(), anyhow::Error>(())
    })
    .await;
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            eprintln!(
                "Oshioki approval unavailable; continuing with the native permission flow: {}",
                super::display_error(&error)
            );
            Ok(())
        }
        Err(_) => {
            eprintln!(
                "Oshioki approval exceeded the adapter deadline; continuing with the native permission flow."
            );
            Ok(())
        }
    }
}

fn native_output(action: Option<ToolDecisionActionV1>) -> Result<Option<Vec<u8>>> {
    let Some(action) = action else {
        return Ok(None);
    };
    let response = match action {
        ToolDecisionActionV1::Approve => serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": { "behavior": "allow" }
            }
        }),
        ToolDecisionActionV1::Deny => serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {
                    "behavior": "deny",
                    "message": "Denied by the enrolled Oshioki browser authenticator."
                }
            }
        }),
    };
    let mut bytes = serde_json::to_vec(&response)?;
    bytes.push(b'\n');
    Ok(Some(bytes))
}

async fn request_decision(harness: HarnessArg) -> Result<ToolDecisionActionV1> {
    let mut input = Vec::with_capacity(4096);
    io::stdin()
        .take((MAX_NATIVE_EVENT_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .context("read native permission event")?;
    if input.is_empty() {
        bail!("native permission event was empty");
    }
    if input.len() > MAX_NATIVE_EVENT_BYTES {
        bail!("native permission event exceeds 256 KiB");
    }
    let native_event_json =
        String::from_utf8(input).context("native permission event is not UTF-8")?;
    let native_event = parse_native_event(native_event_json)?;
    let root = approvals_root()?;
    let profile = read_active_profile(&root)?;
    let directory = profile_dir(&root, &profile)?;
    ensure_user_private_file(&directory.join("hook.json"))?;
    let config = load_profile_hook_config(&directory)?;
    preflight_tool_approval(&config).await?;
    let registry = load_profile_registry(&directory)?;
    let devices = registry
        .devices
        .into_iter()
        .filter(|device| device.active && device.kind == DeviceKindV1::Webauthn)
        .collect::<Vec<_>>();
    if devices.is_empty() {
        bail!("profile has no active browser authenticator");
    }

    // Connect before starting the signed lifetime so the 85-second wait and
    // verification fit inside the request's 90-second validity window.
    let profile_credentials = read_profile_credentials(&directory.join(CONFIG_ENV_FILE))?;
    oshioki_protocol::check_nats_url(&profile_credentials["NATS_URL"], false)
        .context("invalid profile requester NATS URL")?;
    let transport = NatsTransport::from_config_dir(&directory).await?;
    let request = tool_request(harness, native_event)?;
    let (raw_request, envelope) = seal_tool_request_v1(&request, &devices)?;
    let payload = serde_json::to_vec(&envelope)?;
    if payload.len() > oshioki_protocol::v1::MAX_ENVELOPE_BYTES {
        bail!("tool approval envelope exceeds 3 MiB");
    }
    let progress: std::sync::Arc<dyn Fn(HookProgress) + Send + Sync> = std::sync::Arc::new(|_| {});
    let decision = tokio::time::timeout(
        TOOL_DECISION_WAIT,
        transport.request_tool_approval(&request.request_id, payload, TOOL_DECISION_WAIT, progress),
    )
    .await
    .context("tool approval wait exceeded 85 seconds")??;
    let raw_decision = serde_json::to_vec(&decision)?;
    if raw_decision.len() > MAX_DECISION_BYTES {
        bail!("tool approval decision exceeds 64 KiB");
    }
    let decision: ToolApprovalDecisionV1 =
        serde_json::from_slice(&raw_decision).context("decode tool approval decision")?;
    if decision.request_id() != request.request_id {
        bail!("tool approval decision request id mismatch");
    }
    let device = devices
        .iter()
        .find(|device| device.fingerprint == decision.device_fingerprint())
        .context("tool approval decision is not from an active pinned browser device")?;
    verify_tool_decision_v1(&decision, &raw_request, device, &config, super::now())
        .context("verify signed tool approval decision")?;
    Ok(decision.action())
}

struct NativeEvent {
    raw_json: String,
    tool_name: String,
    tool_input: Value,
    cwd: String,
    context: ToolContextV1,
    description: Option<String>,
}

fn parse_native_event(native_event_json: String) -> Result<NativeEvent> {
    if native_event_json.len() > MAX_NATIVE_EVENT_BYTES {
        bail!("native permission event exceeds 256 KiB");
    }
    let native_event = parse_strict_json(native_event_json.as_bytes())
        .context("decode native permission event")?;
    let event_name = required_string(&native_event, "hook_event_name")?;
    if event_name != "PermissionRequest" {
        bail!("unsupported native event");
    }
    let tool_name = required_string(&native_event, "tool_name")?.to_owned();
    let tool_input = native_event
        .get("tool_input")
        .context("native permission event has no tool_input")?
        .clone();
    let cwd = required_string(&native_event, "cwd")?.to_owned();
    let context = ToolContextV1 {
        session_id: optional_string(&native_event, "session_id")?,
        turn_id: optional_string(&native_event, "turn_id")?,
        agent_id: optional_string(&native_event, "agent_id")?,
        agent_type: optional_string(&native_event, "agent_type")?,
        permission_mode: optional_string(&native_event, "permission_mode")?,
    };
    let description = match tool_input.get("description") {
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Null) | None => None,
        Some(_) => bail!("tool_input.description must be a string"),
    };

    Ok(NativeEvent {
        raw_json: native_event_json,
        tool_name,
        tool_input,
        cwd,
        context,
        description,
    })
}

fn tool_request(harness: HarnessArg, event: NativeEvent) -> Result<ToolApprovalRequestV1> {
    let issued_at = super::now();
    let mut nonce = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let request = ToolApprovalRequestV1 {
        message_type: oshioki_protocol::TOOL_REQUEST_TYPE.to_owned(),
        version: oshioki_protocol::TOOL_WIRE_VERSION,
        request_id: Uuid::new_v4().to_string(),
        nonce: oshioki_protocol::encode_base64url(&nonce),
        harness: harness.protocol(),
        event: "PermissionRequest".to_owned(),
        tool_name: event.tool_name,
        tool_input: event.tool_input,
        cwd: event.cwd,
        context: event.context,
        description: event.description,
        native_event_json: event.raw_json,
        issued_at,
        expires_at: issued_at + TOOL_REQUEST_LIFETIME_SECS,
    };
    request.validate()?;
    Ok(request)
}

#[cfg(test)]
fn build_tool_request(
    harness: HarnessArg,
    native_event_json: String,
) -> Result<ToolApprovalRequestV1> {
    tool_request(harness, parse_native_event(native_event_json)?)
}

#[derive(Debug, Deserialize)]
struct ToolCapabilities {
    tool_approval_version: Option<u8>,
}

async fn preflight_tool_approval(config: &HookConfigV1) -> Result<()> {
    let url = Url::parse(&config.server_base_url)?.join("/api/v1/capabilities")?;
    if url.scheme() != "https" {
        bail!("tool approval capability check requires HTTPS");
    }
    let response = super::http_get(url.as_str())
        .await
        .context("server does not advertise browser tool approvals")?;
    let capabilities: ToolCapabilities = serde_json::from_slice(&response)
        .context("server returned an invalid capability response")?;
    if capabilities.tool_approval_version != Some(1) {
        bail!("server does not support browser tool approvals");
    }
    Ok(())
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("native permission event is missing string field {key}"))
}

fn optional_string(value: &Value, key: &str) -> Result<Option<String>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => bail!("native permission event field {key} must be a string or null"),
    }
}

fn approvals_root() -> Result<PathBuf> {
    let home = user_home()?;
    let config_home = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(path) => {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                bail!("XDG_CONFIG_HOME must be an absolute path");
            }
            path
        }
        None => home.join(".config"),
    };
    Ok(config_home.join(PROFILE_ROOT_NAME))
}

fn user_home() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    let home = PathBuf::from(home);
    if !home.is_absolute() {
        bail!("HOME must be an absolute path");
    }
    Ok(home)
}

fn profile_dir(root: &Path, profile: &str) -> Result<PathBuf> {
    validate_profile_id(profile)?;
    let directory = root.join(profile);
    verify_user_private_directory(&directory)?;
    Ok(directory)
}

fn load_profile_registry(directory: &Path) -> Result<super::DeviceRegistryV1> {
    let path = directory.join("devices.json");
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            ensure_user_private_file(&path)?;
            let value = read_strict_json_file(&path, MAX_PROFILE_REGISTRY_BYTES)?;
            let registry: super::DeviceRegistryV1 = serde_json::from_value(value)?;
            registry.validate()?;
            Ok(registry)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(super::DeviceRegistryV1 {
            version: oshioki_protocol::VERSION_V1,
            devices: Vec::new(),
        }),
        Err(error) => Err(error.into()),
    }
}

fn load_profile_hook_config(directory: &Path) -> Result<HookConfigV1> {
    let path = directory.join("hook.json");
    ensure_user_private_file(&path)?;
    let value = read_strict_json_file(&path, MAX_PROFILE_CONFIG_BYTES)?;
    let config: HookConfigV1 = serde_json::from_value(value)?;
    config.validate()?;
    Ok(config)
}

fn profile_setup_complete(directory: &Path) -> Result<bool> {
    let path = directory.join("setup-complete");
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            ensure_user_private_file(&path)?;
            if read_bounded_file(&path, 64)?.as_slice() != b"browser-enrolled-v1\n" {
                bail!("profile setup marker is invalid");
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn validate_profile_id(profile: &str) -> Result<()> {
    if profile.is_empty()
        || profile.len() > 64
        || profile == "."
        || profile == ".."
        || !profile
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || !profile.as_bytes()[0].is_ascii_alphanumeric()
    {
        bail!(
            "profile id must start with a letter or number and contain only letters, numbers, '.', '_' or '-'"
        );
    }
    Ok(())
}

fn read_active_profile(root: &Path) -> Result<String> {
    verify_user_private_directory(root)?;
    let path = root.join(ACTIVE_PROFILE_FILE);
    ensure_user_private_file(&path)?;
    let profile = String::from_utf8(read_bounded_file(&path, 66)?)
        .context("active approvals profile is not UTF-8")?;
    let profile = profile.trim_end_matches(['\r', '\n']);
    validate_profile_id(profile)?;
    Ok(profile.to_owned())
}

fn write_active_profile(root: &Path, profile: &str) -> Result<()> {
    validate_profile_id(profile)?;
    write_atomic(
        &root.join(ACTIVE_PROFILE_FILE),
        format!("{profile}\n").as_bytes(),
        0o600,
        true,
    )
}

fn hook_config(server_url: &str) -> Result<HookConfigV1> {
    let url = Url::parse(server_url).context("invalid server URL")?;
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || (url.path() != "/" && !url.path().is_empty())
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("server URL must be an HTTPS origin without credentials, path, query, or fragment");
    }
    let origin = format!(
        "{}://{}",
        url.scheme(),
        url[url::Position::BeforeHost..].trim_end_matches('/')
    );
    let host = url.host_str().context("server URL has no hostname")?;
    let rp_id = host.trim_matches(['[', ']']).to_ascii_lowercase();
    let config = HookConfigV1 {
        version: oshioki_protocol::VERSION_V1,
        origin: origin.clone(),
        rp_id,
        server_base_url: origin,
    };
    config.validate()?;
    Ok(config)
}

fn read_nats_config(path: &Path) -> Result<HashMap<String, String>> {
    ensure_user_private_file(path)?;
    let metadata = fs::metadata(path)?;
    if metadata.permissions().mode() & 0o777 != 0o600 {
        bail!("NATS config must have mode 0600");
    }
    if metadata.len() > 16 * 1024 {
        bail!("NATS config exceeds 16 KiB");
    }
    let text = String::from_utf8(read_bounded_file(path, MAX_PROFILE_CREDENTIAL_BYTES)?)
        .with_context(|| format!("read NATS config {}", path.display()))?;
    let mut values = HashMap::new();
    for (line_number, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .with_context(|| format!("NATS config line {} must be KEY=VALUE", line_number + 1))?;
        if !matches!(key, "NATS_URL" | "NATS_USER" | "NATS_PASS") {
            bail!("unknown NATS config key: {key}");
        }
        if value.is_empty() || value.trim() != value || value.contains(['\r', '\n']) {
            bail!("NATS config value for {key} is empty or has surrounding whitespace");
        }
        if values.insert(key.to_owned(), value.to_owned()).is_some() {
            bail!("duplicate NATS config key: {key}");
        }
    }
    if values.len() != 3 {
        bail!("NATS config must contain exactly NATS_URL, NATS_USER, and NATS_PASS");
    }
    let url = &values["NATS_URL"];
    oshioki_protocol::check_nats_url(url, false).context("invalid requester NATS URL")?;
    Ok(values)
}

fn read_profile_credentials(path: &Path) -> Result<HashMap<String, String>> {
    ensure_user_private_file(path)?;
    let text = String::from_utf8(read_bounded_file(path, MAX_PROFILE_CREDENTIAL_BYTES)?)?;
    let mut values = HashMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=') {
            if values.insert(key.to_owned(), value.to_owned()).is_some() {
                bail!("profile NATS config has duplicate keys");
            }
        }
    }
    if values.len() != 3
        || !values.contains_key("NATS_URL")
        || !values.contains_key("NATS_USER")
        || !values.contains_key("NATS_PASS")
    {
        bail!("profile NATS config is incomplete");
    }
    Ok(values)
}

fn require_user_session() -> Result<()> {
    if nix::unistd::geteuid().as_raw() == 0 {
        bail!("run approvals setup/install as the regular user, without sudo");
    }
    Ok(())
}

fn ensure_user_private_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => verify_user_private_directory(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)
                .with_context(|| format!("create profile directory {}", path.display()))?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            verify_user_private_directory(path)
        }
        Err(error) => Err(error.into()),
    }
}

fn ensure_approvals_tree(root: &Path) -> Result<()> {
    let config_home = root
        .parent()
        .and_then(Path::parent)
        .context("approvals profile path has no config home")?;
    fs::create_dir_all(config_home)?;
    ensure_settings_parent(config_home)?;
    let app_directory = root.parent().context("approvals root has no parent")?;
    ensure_settings_parent(app_directory)?;
    ensure_user_private_directory(root)
}

fn verify_user_private_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect private directory {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        bail!("refusing unsafe user profile directory {}", path.display());
    }
    Ok(())
}

fn ensure_user_private_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect private file {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        bail!("refusing unsafe user file {}", path.display());
    }
    Ok(())
}

fn ensure_settings_parent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if !metadata.file_type().is_symlink()
                && metadata.is_dir()
                && metadata.uid() == nix::unistd::geteuid().as_raw()
                && metadata.permissions().mode() & 0o022 == 0 =>
        {
            Ok(())
        }
        Ok(_) => bail!(
            "refusing unsafe native agent config directory {}",
            path.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != nix::unistd::geteuid().as_raw()
            {
                bail!(
                    "refusing unsafe native agent config directory {}",
                    path.display()
                );
            }
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn user_settings_path(harness: HarnessArg) -> Result<PathBuf> {
    let home = user_home()?;
    match harness {
        HarnessArg::Codex => {
            let codex_home = match std::env::var_os("CODEX_HOME") {
                Some(path) => {
                    let path = PathBuf::from(path);
                    if !path.is_absolute() {
                        bail!("CODEX_HOME must be absolute when set");
                    }
                    let metadata = fs::symlink_metadata(&path)
                        .context("CODEX_HOME must already exist and be accessible")?;
                    if metadata.file_type().is_symlink()
                        || !metadata.is_dir()
                        || metadata.uid() != nix::unistd::geteuid().as_raw()
                    {
                        bail!("refusing unsafe CODEX_HOME {}", path.display());
                    }
                    path
                }
                None => home.join(".codex"),
            };
            Ok(codex_home.join("hooks.json"))
        }
        HarnessArg::Claude => Ok(home.join(".claude/settings.json")),
    }
}

fn read_strict_json_file(path: &Path, limit: usize) -> Result<Value> {
    let bytes = read_bounded_file(path, limit)
        .with_context(|| format!("read JSON config {}", path.display()))?;
    parse_strict_json(&bytes)
}

fn read_bounded_file(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let limit_plus_one = limit.checked_add(1).context("file size limit overflow")?;
    let read_limit = u64::try_from(limit_plus_one)?;
    let mut bytes = Vec::with_capacity(limit.min(4096));
    fs::File::open(path)?
        .take(read_limit)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bail!("{} exceeds its {} byte size limit", path.display(), limit);
    }
    Ok(bytes)
}

fn parse_strict_json(bytes: &[u8]) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValueSeed
        .deserialize(&mut deserializer)
        .context("parse JSON with unique keys")?;
    deserializer.end().context("trailing data after JSON")?;
    Ok(value)
}

struct StrictValueSeed;

impl<'de> DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
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
        formatter.write_str("JSON without duplicate keys")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictValueSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate JSON key {key:?}")));
            }
            let value = map.next_value_seed(StrictValueSeed)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

fn write_private_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut contents = serde_json::to_vec_pretty(value)?;
    contents.push(b'\n');
    write_atomic(path, &contents, 0o600, true)
}

fn write_atomic(path: &Path, contents: &[u8], mode: u32, private: bool) -> Result<()> {
    let parent = path.parent().context("file path has no parent")?;
    fs::create_dir_all(parent)?;
    if private {
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let old_mode = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.uid() != nix::unistd::geteuid().as_raw()
                || (private && metadata.permissions().mode() & 0o077 != 0)
            {
                bail!("refusing to overwrite unsafe user file {}", path.display());
            }
            Some(metadata.permissions().mode() & 0o777)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let temporary = parent.join(format!(".oshioki-{}.tmp", Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let result = (|| -> Result<()> {
        let mut file = options.open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::set_permissions(
            &temporary,
            fs::Permissions::from_mode(old_mode.unwrap_or(mode)),
        )?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn ensure_settings_file_owned(path: &Path) -> Result<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.permissions().mode() & 0o022 != 0
        {
            bail!("refusing unsafe native settings file {}", path.display());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("oshioki-approvals-{}", Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn event_adapter_preserves_exact_json_and_rejects_bad_events() {
        let raw = r#"{"session_id":"session-1","turn_id":"turn-2","cwd":"/tmp/project","tool_name":"Bash","tool_input":{"command":"echo ok"},"hook_event_name":"PermissionRequest","permission_mode":"default","future_field":{"kept":true}}"#;
        let request = build_tool_request(HarnessArg::Codex, raw.to_owned()).unwrap();
        assert_eq!(request.native_event_json, raw);
        assert_eq!(request.tool_name, "Bash");
        assert_eq!(request.cwd, "/tmp/project");
        assert_eq!(request.harness, ToolHarnessV1::Codex);
        assert_eq!(request.context.session_id.as_deref(), Some("session-1"));
        assert_eq!(request.context.turn_id.as_deref(), Some("turn-2"));
        request.validate().unwrap();

        let duplicate = r#"{"hook_event_name":"PermissionRequest","tool_name":"Bash","tool_name":"Other","tool_input":{"command":"echo ok"},"cwd":"/tmp"}"#;
        assert!(build_tool_request(HarnessArg::Claude, duplicate.to_owned()).is_err());
        let unsupported = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"},"cwd":"/tmp"}"#;
        assert!(build_tool_request(HarnessArg::Claude, unsupported.to_owned()).is_err());
        assert!(
            build_tool_request(HarnessArg::Claude, " ".repeat(MAX_NATIVE_EVENT_BYTES + 1)).is_err()
        );
    }

    #[test]
    fn native_output_is_empty_without_a_verified_action_and_never_rewrites_input() {
        assert!(native_output(None).unwrap().is_none());
        for action in [ToolDecisionActionV1::Approve, ToolDecisionActionV1::Deny] {
            let bytes = native_output(Some(action)).unwrap().unwrap();
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            let output = value.get("hookSpecificOutput").unwrap();
            assert_eq!(
                output.get("hookEventName").and_then(Value::as_str),
                Some("PermissionRequest")
            );
            let decision = output.get("decision").unwrap();
            assert_eq!(
                decision.get("behavior").and_then(Value::as_str),
                Some(match action {
                    ToolDecisionActionV1::Approve => "allow",
                    ToolDecisionActionV1::Deny => "deny",
                })
            );
            assert!(decision.get("updatedInput").is_none());
            assert!(decision.get("updatedPermissions").is_none());
            assert!(decision.get("interrupt").is_none());
        }
    }

    #[test]
    fn install_is_idempotent_and_preserves_existing_agent_settings() {
        for harness in [HarnessArg::Codex, HarnessArg::Claude] {
            let temp = TempDir::new();
            let path = temp.0.join("settings.json");
            let parent_mode = fs::symlink_metadata(&temp.0).unwrap().permissions().mode() & 0o777;
            let original = serde_json::json!({
                "permissions": { "defaultMode": "default", "allow": ["Read"] },
                "sandbox": { "mode": "workspace-write" },
                "hooks": {
                    "PermissionRequest": [{
                        "matcher": "Bash",
                        "hooks": [{ "type": "command", "command": "keep-me", "timeout": 9 }]
                    }, { "matcher": "Edit", "hooks": [] }],
                    "PostToolUse": [{ "hooks": [{ "type": "command", "command": "also-keep" }] }]
                }
            });
            fs::write(&path, serde_json::to_vec_pretty(&original).unwrap()).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();

            install_harness_at(&path, harness).unwrap();
            install_harness_at(&path, harness).unwrap();
            assert_eq!(
                fs::symlink_metadata(&path).unwrap().permissions().mode() & 0o777,
                0o400
            );
            assert_eq!(
                fs::symlink_metadata(&temp.0).unwrap().permissions().mode() & 0o777,
                parent_mode
            );
            let installed = read_settings(&path).unwrap();
            assert_eq!(installed["permissions"], original["permissions"]);
            assert_eq!(installed["sandbox"], original["sandbox"]);
            assert_eq!(
                installed["hooks"]["PostToolUse"],
                original["hooks"]["PostToolUse"]
            );
            let groups = installed["hooks"]["PermissionRequest"].as_array().unwrap();
            assert_eq!(groups.len(), 3);
            let owned = groups
                .iter()
                .filter(|group| {
                    group["hooks"].as_array().is_some_and(|handlers| {
                        handlers
                            .iter()
                            .any(|handler| is_owned_handler(handler, &harness.all_marker()))
                    })
                })
                .count();
            assert_eq!(owned, 1);

            assert!(uninstall_harness_at(&path, harness).unwrap());
            let removed = read_settings(&path).unwrap();
            assert_eq!(removed["permissions"], original["permissions"]);
            assert_eq!(removed["sandbox"], original["sandbox"]);
            assert_eq!(
                removed["hooks"]["PostToolUse"],
                original["hooks"]["PostToolUse"]
            );
            assert_eq!(
                removed["hooks"]["PermissionRequest"],
                original["hooks"]["PermissionRequest"]
            );
            assert!(!uninstall_harness_at(&path, harness).unwrap());
        }
    }

    #[test]
    fn settings_with_duplicate_keys_are_refused_without_rewrite() {
        let temp = TempDir::new();
        let path = temp.0.join("settings.json");
        let original =
            br#"{"permissions":{"defaultMode":"default","defaultMode":"bypassPermissions"}}"#;
        fs::write(&path, original).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(install_harness_at(&path, HarnessArg::Claude).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
    }

    #[test]
    fn profile_ids_cannot_select_parent_paths() {
        for invalid in ["", ".", "..", "../outside", "/tmp", "has space"] {
            assert!(
                validate_profile_id(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        assert!(validate_profile_id("work-laptop.1").is_ok());
    }

    #[test]
    fn server_url_is_reduced_to_a_valid_https_origin() {
        let config = hook_config("https://approvals.example.com:8443/").unwrap();
        assert_eq!(config.origin, "https://approvals.example.com:8443");
        assert_eq!(config.rp_id, "approvals.example.com");
        assert!(hook_config("http://approvals.example.com").is_err());
        assert!(hook_config("https://approvals.example.com/setup").is_err());
    }
}
