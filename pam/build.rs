//! Presets the macOS install name (`LC_ID_DYLIB`) of the PAM module.
//!
//! Homebrew's `Keg#fix_dynamic_linkage` rewrites every dylib in a keg so its
//! id is `<opt_record>/<path relative to the keg>/<basename of the old id>`,
//! then ad hoc re-signs each file it touched. That rewrite happens after the
//! release artifact was hashed into `SHA256SUMS`, so a bottled copy of this
//! module no longer matches its recorded checksum and
//! `install-oshioki-hook --contextual-pam` refuses to install it (issue #87).
//!
//! `change_dylib_id` returns early when the file already carries that exact
//! id (`Library/Homebrew/extend/os/mac/keg.rb`: `return false if
//! file.dylib_id == id`), and only modified files are re-signed. Linking with
//! the keg's opt path up front therefore makes the whole fixup a no-op and
//! leaves the shipped bytes -- and their checksum -- intact.
//!
//! The id is inert at load time either way: `OpenPAM`'s `openpam_dynamic`
//! `dlopen`s a module by the absolute path in the auth line, and dyld
//! resolves that path from the filesystem. `LC_ID_DYLIB` only names the
//! library for things that link against it, and nothing links against a PAM
//! module. So a module installed at `/usr/local/lib/pam/` from the release
//! tarball loads exactly the same with this id as it did with its own path.
//!
//! Override `OSHIOKI_PAM_INSTALL_NAME` for an Intel prefix
//! (`/usr/local/opt/oshioki/libexec/...`) or any non-default Homebrew
//! prefix. Non-macOS targets get nothing: ELF has no equivalent, and the
//! Linux lane ships the module through the .deb.

/// Where the Homebrew keg lands on Apple silicon, which is the only
/// architecture the tap bottles.
const DEFAULT_INSTALL_NAME: &str = "/opt/homebrew/opt/oshioki/libexec/liboshioki_pam.dylib";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=OSHIOKI_PAM_INSTALL_NAME");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    let name = std::env::var("OSHIOKI_PAM_INSTALL_NAME")
        .unwrap_or_else(|_| DEFAULT_INSTALL_NAME.to_owned());
    // cdylib-only: a plain `rustc-link-arg` would also reach the test
    // harness binary, and `-install_name` on an executable is an error.
    // rustc emits its own `-install_name` first; ld64 takes the last one.
    println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,{name}");
}
