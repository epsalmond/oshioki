//! Presets the macOS install name (`LC_ID_DYLIB`) of the sudo approval
//! plugin, for the same reason `pam/build.rs` does it for the PAM module:
//! Homebrew rewrites and re-signs any dylib in a keg whose id is not already
//! the keg's opt path, which invalidates the checksum recorded in the
//! release `SHA256SUMS` (issue #87).
//!
//! sudo `dlopen`s this plugin by the absolute path in `sudo.conf`, so the id
//! is never consulted at load time; it exists here only to make Homebrew's
//! fixup a no-op. Override with `OSHIOKI_PLUGIN_INSTALL_NAME` for an Intel
//! or otherwise non-default Homebrew prefix.

/// The keg path the tap's arm64 bottle always lands on. Note the basename:
/// the release artifact renames `liboshioki_plugin.dylib` to `oshioki.dylib`
/// and Homebrew derives the new id from the basename of the *old* id, so
/// this has to spell the installed name, not the cargo output name.
const DEFAULT_INSTALL_NAME: &str = "/opt/homebrew/opt/oshioki/libexec/oshioki.dylib";

/// Rejects an override that would not survive the linker command line. The
/// value is spliced into `-Wl,-install_name,<name>`: a comma there splits
/// into extra ld64 arguments, and a newline ends the `cargo:` directive and
/// starts whatever the rest of the value spells. A relative path would link
/// silently and only fail later, in Homebrew's fixup.
fn checked_install_name(var: &str, name: &str) -> String {
    assert!(!name.is_empty(), "{var} is empty; unset it or give a path");
    assert!(
        name.starts_with('/'),
        "{var} must be an absolute path, got {name:?}"
    );
    assert!(
        !name.contains(','),
        "{var} must not contain a comma: it would split into further linker \
         arguments. Got {name:?}"
    );
    assert!(
        !name.contains(['\n', '\r']),
        "{var} must not contain a newline: it would inject cargo directives. \
         Got {name:?}"
    );
    name.to_owned()
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=OSHIOKI_PLUGIN_INSTALL_NAME");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    let name = match std::env::var("OSHIOKI_PLUGIN_INSTALL_NAME") {
        Ok(name) => checked_install_name("OSHIOKI_PLUGIN_INSTALL_NAME", &name),
        Err(_) => DEFAULT_INSTALL_NAME.to_owned(),
    };
    println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,{name}");
}
