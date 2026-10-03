use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::process::{Command, Stdio};

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "oshioki-installed-approval-command-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn installed_command(settings: &std::path::Path) -> String {
    let bytes = fs::read(settings).unwrap();
    let config: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let groups = config["hooks"]["PermissionRequest"].as_array().unwrap();
    let commands = groups
        .iter()
        .flat_map(|group| group["hooks"].as_array().unwrap())
        .filter_map(|handler| handler["command"].as_str())
        .filter(|command| command.contains("--managed-hook="))
        .collect::<Vec<_>>();
    assert_eq!(commands.len(), 1);
    commands[0].to_owned()
}

#[test]
fn exact_installed_commands_reach_both_native_request_adapters() {
    let temp = TempDir::new();
    let home = temp.0.join("home");
    let config_home = temp.0.join("config");
    let codex_home = temp.0.join("codex");
    for directory in [&home, &config_home, &codex_home] {
        fs::create_dir(directory).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let approvals_root = config_home.join("oshioki/approvals");
    fs::create_dir_all(&approvals_root).unwrap();
    fs::set_permissions(&approvals_root, fs::Permissions::from_mode(0o700)).unwrap();

    let executable = env!("CARGO_BIN_EXE_oshioki");
    let installed = Command::new(executable)
        .args(["approvals", "install", "codex", "claude"])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config_home)
        .env("CODEX_HOME", &codex_home)
        .output()
        .unwrap();
    assert!(
        installed.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&installed.stderr)
    );

    let native_event = br#"{"hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"printf fixture"},"cwd":"/tmp/oshioki-fixture"}"#;
    let configurations = [
        (
            "codex",
            codex_home.join("hooks.json"),
            "oshioki-managed-hook-v1-codex",
        ),
        (
            "claude",
            home.join(".claude/settings.json"),
            "oshioki-managed-hook-v1-claude",
        ),
    ];
    for (harness, settings, marker) in configurations {
        let command = installed_command(&settings);
        assert!(command.contains(&format!("--harness {harness} --managed-hook={marker}")));

        // Run the exact command string written into native settings. With no
        // active profile, reaching the adapter reports an unavailable
        // approval and abstains; a mismatched ownership marker silently
        // exits without that adapter message.
        let mut child = Command::new("/bin/sh")
            .args(["-c", &command])
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &config_home)
            .env("CODEX_HOME", &codex_home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(native_event).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{harness} adapter must abstain");
        assert!(output.stdout.is_empty(), "{harness} must not decide");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Oshioki approval unavailable"),
            "{harness} installed command did not reach the request adapter: {stderr}"
        );
    }
}
