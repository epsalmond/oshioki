#[test]
fn registry_setup_upgrade_preserves_state() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../scripts/test-registry-setup-upgrade");
    let result = std::process::Command::new("python3")
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_oshioki"))
        .output()
        .expect("run offline registry setup upgrade fixture");
    assert!(
        result.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
