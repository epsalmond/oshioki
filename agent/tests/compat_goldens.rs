//! Frozen previous-release identity files. Regenerate with
//! `OSHIOKI_WRITE_COMPAT_GOLDENS=1 cargo test -p oshioki-agent --test compat_goldens`.

use std::{fs, os::unix::fs::PermissionsExt as _, path::PathBuf};

use oshioki_agent::{Identity, secret_store::MemoryStore};
use oshioki_protocol::{VERSION_V1, encode_base64url};

fn goldens_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/compat/goldens")
}

#[test]
fn a_legacy_identity_golden_migrates_without_changing_the_fingerprint() {
    let signing = encode_base64url(&[0x11; 32]);
    let box_secret = encode_base64url(&[0x22; 32]);
    let api_token_hash = encode_base64url(&[0x33; 32]);
    let generated = serde_json::json!({
        "version": VERSION_V1,
        "signing": {"kind": "software", "key": signing},
        "box_secret": box_secret,
        "api_token_hash": api_token_hash,
    });
    let pretty = serde_json::to_string_pretty(&generated).unwrap() + "\n";
    let path = goldens_dir().join("identity-legacy.json");
    if std::env::var_os("OSHIOKI_WRITE_COMPAT_GOLDENS").is_some() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &pretty).unwrap();
    } else {
        let stored = fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!(
                "missing {}: {error}; regenerate with OSHIOKI_WRITE_COMPAT_GOLDENS=1",
                path.display()
            )
        });
        assert_eq!(stored, pretty);
    }

    let dir = std::env::temp_dir().join(format!(
        "oshioki-compat-identity-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let live = dir.join("agent.json");
    fs::write(&live, fs::read(&path).unwrap()).unwrap();
    let store = MemoryStore::new();
    let loaded = Identity::load_with(&live, &store).unwrap();
    let expected = Identity::from_material([0x11; 32], [0x22; 32], [0x33; 32]).unwrap();
    assert_eq!(loaded.fingerprint(), expected.fingerprint());
    let stripped: serde_json::Value = serde_json::from_slice(&fs::read(&live).unwrap()).unwrap();
    assert!(stripped.get("box_secret").is_none());
    assert!(stripped["box_secret_ref"].is_string());
    let prev = dir.join("agent.json.prev");
    assert_eq!(
        fs::metadata(&prev).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let prev_file: serde_json::Value = serde_json::from_slice(&fs::read(&prev).unwrap()).unwrap();
    assert_eq!(prev_file["box_secret"], box_secret);
    fs::remove_dir_all(&dir).unwrap();
}
