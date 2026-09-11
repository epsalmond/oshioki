//! Load-time self-test for a built PAM module.
//!
//! The installer runs this between staging `liboshioki_pam.so` into the
//! platform security directory and referencing it from `/etc/pam.d/sudo`.
//! At that point the module is present but inert, so a failure here costs
//! nothing: no PAM configuration has been touched yet. Once the auth line is
//! in place, the same fault would be a broken sudo stack on a live host.
//!
//! What it proves is narrow and deliberately so: the file is a loadable
//! shared object for this architecture, every one of its undefined symbols
//! resolves (`RTLD_NOW`, so a missing `libpam` or an ABI drift fails here
//! rather than at the first sudo), and it exports the two entry points the
//! `auth` stack will call. It does not call either one — invoking
//! `pam_sm_authenticate` without a PAM handle is not a test, it is a crash —
//! and it proves nothing about the module's decisions.
//!
//! `dlopen` is not inert: any ELF initialiser in the object (a Rust `#[ctor]`,
//! a C++ static constructor, an initialiser pulled in by a dependency) runs in
//! this process the moment it loads. `liboshioki_pam` has none today, and must
//! not acquire one — but the installer runs this as root, so a module that
//! grew a constructor would be running that code as root, before any PAM file
//! references it. That is the reason to keep the self-test to load-and-look-up
//! and never to call an entry point.
//!
//! The workspace denies `unsafe_code`; this module is the one place in the
//! hook that lifts it, following `enclave/src/mac.rs`. The unsafety is
//! confined to three libc calls on a caller-supplied path.
#![allow(unsafe_code)]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use anyhow::{Result, bail};

/// The entry points a PAM `auth` stack calls on this module. `pam_sm_setcred`
/// is included because a stack that authenticates will also call it, and an
/// auth module that exports only the first is rejected at use time by
/// Linux-PAM.
const REQUIRED_SYMBOLS: [&str; 2] = ["pam_sm_authenticate", "pam_sm_setcred"];

/// `RTLD_NOW | RTLD_LOCAL`: resolve everything immediately, and keep the
/// symbols out of the global namespace so this process cannot accidentally
/// start resolving against the module under test.
fn open_flags() -> c_int {
    libc::RTLD_NOW | libc::RTLD_LOCAL
}

/// The most recent dynamic-linker error, as bounded lossy UTF-8.
fn dl_error() -> String {
    // SAFETY: dlerror takes no arguments and returns either NULL or a
    // pointer to a NUL-terminated string owned by the linker, valid until
    // the next dlerror call on this thread. It is read before any further
    // dl* call.
    let raw: *mut c_char = unsafe { libc::dlerror() };
    if raw.is_null() {
        return "no dynamic linker diagnostic available".to_owned();
    }
    // SAFETY: raw is non-null and NUL-terminated per dlerror's contract; the
    // borrow ends before this function returns.
    let text = unsafe { CStr::from_ptr(raw) }.to_string_lossy();
    text.chars().take(512).collect()
}

/// `dlopen` the module, `dlsym` each required entry point, `dlclose`.
///
/// Returns `Ok(())` only when every step succeeded. The caller maps that to
/// exit 0; every error path here becomes a non-zero exit with one stderr
/// line naming the step that failed.
pub fn run(module: &Path) -> Result<()> {
    // dlopen without a slash searches the loader's paths. Requiring an
    // absolute path means the file self-tested is exactly the file the
    // installer staged, never a same-named module elsewhere on the search
    // path.
    if !module.is_absolute() {
        bail!(
            "pam-selftest needs an absolute module path: {}",
            module.display()
        );
    }
    let metadata = std::fs::symlink_metadata(module)
        .map_err(|error| anyhow::anyhow!("cannot stat {}: {error}", module.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("refusing to self-test a symlink: {}", module.display());
    }
    if !metadata.is_file() {
        bail!("not a regular file: {}", module.display());
    }

    let path = CString::new(module.as_os_str().as_bytes())
        .map_err(|_| anyhow::anyhow!("module path contains a NUL byte"))?;

    // SAFETY: path is a live NUL-terminated C string for the duration of the
    // call; the flags are libc constants. dlopen returns NULL on failure.
    let handle: *mut c_void = unsafe { libc::dlopen(path.as_ptr(), open_flags()) };
    if handle.is_null() {
        bail!("dlopen failed for {}: {}", module.display(), dl_error());
    }

    let mut missing: Vec<&str> = Vec::new();
    for symbol in REQUIRED_SYMBOLS {
        let name = CString::new(symbol).expect("symbol names are static and NUL-free");
        // Clear any stale diagnostic so a NULL result below is attributable.
        // SAFETY: see dl_error.
        let _ = unsafe { libc::dlerror() };
        // SAFETY: handle is a live dlopen handle that has not been closed,
        // and name is a live NUL-terminated C string. The returned address is
        // only compared against NULL and never called.
        let address = unsafe { libc::dlsym(handle, name.as_ptr()) };
        if address.is_null() {
            missing.push(symbol);
        }
    }

    // Close before reporting, so a failed self-test does not leave the module
    // mapped into the installer's helper process.
    // SAFETY: handle came from the dlopen above and is closed exactly once.
    let closed = unsafe { libc::dlclose(handle) };

    if !missing.is_empty() {
        bail!(
            "{} does not export {}",
            module.display(),
            missing.join(" and ")
        );
    }
    if closed != 0 {
        bail!("dlclose failed for {}: {}", module.display(), dl_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relative_path_is_refused_before_any_dlopen() {
        let error = run(Path::new("liboshioki_pam.so")).unwrap_err();
        assert!(
            format!("{error}").contains("absolute"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_missing_file_is_reported_as_a_stat_failure() {
        let error = run(Path::new("/nonexistent/oshioki/liboshioki_pam.so")).unwrap_err();
        assert!(
            format!("{error}").contains("cannot stat"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_file_that_is_not_a_shared_object_fails_at_dlopen() {
        // /etc/hostname is a regular file on every platform this builds for
        // and is definitively not a loadable object.
        let error = run(Path::new("/etc/hostname")).unwrap_err();
        assert!(
            format!("{error}").contains("dlopen failed"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn the_required_symbol_set_is_the_auth_entry_points() {
        assert_eq!(REQUIRED_SYMBOLS, ["pam_sm_authenticate", "pam_sm_setcred"]);
    }
}
