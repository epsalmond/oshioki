//! `approval_exec` — the sudo approval plugin (cdylib).
//!
//! Exports the `SUDO_APPROVAL_PLUGIN` vtable sudo looks up when it loads this
//! library. The plugin forks `management-plane-sudo-approve check` and maps
//! its exit code to the sudo approval API contract.
//!
//! This module is the only unsafe code in the workspace. Every unsafe block
//! carries a `// SAFETY:` comment explaining why it is sound.

// The plugin runs inside sudo's process and crosses the FFI boundary, so it is
// the one place unsafe is unavoidable. Everything unsafe lives here.
#![allow(unsafe_code)]
// The sudo approval plugin ABI requires allocation to stay inside the FFI
// boundary. A leak would corrupt sudo's heap.
#![deny(clippy::alloc_instead_of_core)]
#![deny(clippy::std_instead_of_alloc)]

use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::io::Write as _;
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::panic::catch_unwind;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Sudo plugin ABI constants (from /usr/include/sudo_plugin.h)
// ---------------------------------------------------------------------------

/// Plugin type tag: approval plugin.
const SUDO_APPROVAL_PLUGIN: c_uint = 4;

/// Sudo API version we declare: 1.0 (`(1 << 16) | 0`).
///
/// sudo checks the major version only; declaring 1.0 against a 1.21 host is
/// the conventional approach and gives us the widest compatibility window.
const SUDO_API_VERSION: c_uint = 1 << 16;

/// Approval `open` return codes. Zero means "disable this plugin" to sudo and
/// would fail open, so capture failures must use the fatal error result.
const SUDO_RC_OK: c_int = 1;
const SUDO_RC_ERROR: c_int = -1;

// ---------------------------------------------------------------------------
// Callback type aliases matching sudo_plugin.h
// ---------------------------------------------------------------------------

/// printf-style logging callback sudo passes to `open`.
#[allow(dead_code)]
type SudoPrintf = unsafe extern "C" fn(c_int, *const c_char, ...) -> c_int;

/// Conversation function sudo passes to `open` (interactive prompts).
#[allow(dead_code)]
type SudoConv = unsafe extern "C" fn(
    c_int,
    *const c_void, // sudo_conv_message array
    *mut c_void,   // sudo_conv_reply array
    *mut c_void,   // callback closure
) -> c_int;

// ---------------------------------------------------------------------------
// approval_plugin vtable layout
// ---------------------------------------------------------------------------

/// Mirrors `struct approval_plugin` from `sudo_plugin.h`.
///
/// Field order and types must match the C struct exactly; sudo dlopens this
/// library and reads the struct at offset 0 of the exported symbol.
#[repr(C)]
pub struct ApprovalPlugin {
    type_: c_uint,
    version: c_uint,
    open: Option<
        unsafe extern "C" fn(
            c_uint,
            SudoConv,
            SudoPrintf,
            *const *const c_char, // settings
            *const *const c_char, // user_info
            c_int,                // submit_optind
            *const *const c_char, // submit_argv
            *const *const c_char, // submit_envp
            *const *const c_char, // plugin_options
            *const *const c_char, // errstr (out)
        ) -> c_int,
    >,
    close: Option<unsafe extern "C" fn()>,
    check: Option<
        unsafe extern "C" fn(
            *const *const c_char, // command_info
            *const *const c_char, // run_argv
            *const *const c_char, // run_envp
            *const *const c_char, // errstr (out)
        ) -> c_int,
    >,
    show_version: Option<unsafe extern "C" fn(c_int) -> c_int>,
}

// ---------------------------------------------------------------------------
// Exported static
// ---------------------------------------------------------------------------

/// The symbol sudo looks up (`dlsym("approval_exec")`).
///
/// Sudo calls `open` unconditionally before `check`, so both callbacks must
/// be present. `close` and `show_version` are optional.
///
/// # Safety
///
/// The struct is `#[repr(C)]` and matches the ABI layout that sudo's
/// `dlopen`/`dlsym` reads. All function pointers are either null or point to
/// functions with the correct C-calling-convention signatures.
#[unsafe(no_mangle)]
#[allow(non_upper_case_globals)]
pub static approval_exec: ApprovalPlugin = ApprovalPlugin {
    type_: SUDO_APPROVAL_PLUGIN,
    version: SUDO_API_VERSION,
    open: Some(plugin_open),
    close: None,
    check: Some(check),
    show_version: None,
};

/// `open` and `check` receive different parts of one sudo request. Copy the
/// invoking identity while sudo owns it, then consume it exactly once in
/// `check` so a later request can never inherit stale identity.
static USER_INFO: Mutex<Option<Vec<(String, String)>>> = Mutex::new(None);

/// Capture the invoking identity for the following one-shot approval check.
///
/// Sudo 1.9 supplies `user_info` only to `open`; the plugin must copy it here
/// because sudo owns the pointed-to strings and `check` runs later.
extern "C" fn plugin_open(
    _version: c_uint,
    _conversation: SudoConv,
    _sudo_plugin_printf: SudoPrintf,
    _settings: *const *const c_char,
    user_info: *const *const c_char,
    _submit_optind: c_int,
    _submit_argv: *const *const c_char,
    _submit_envp: *const *const c_char,
    _plugin_options: *const *const c_char,
    _errstr: *const *const c_char,
) -> c_int {
    // SAFETY: sudo supplies the valid, callback-scoped `user_info` array.
    unsafe { capture_open_user_info(user_info) }
}

/// Capture `user_info` and map every failure to sudo's fatal open result.
///
/// # Safety
///
/// `user_info` must satisfy `capture_user_info`'s pointer contract.
unsafe fn capture_open_user_info(user_info: *const *const c_char) -> c_int {
    // No panics may cross the FFI boundary. A panic or poisoned state denies.
    let captured = catch_unwind(move || {
        // SAFETY: sudo passes a valid, NUL-terminated array whose strings live
        // for the duration of this callback. `capture_user_info` copies them.
        unsafe { capture_user_info(user_info) }
    });
    approval_open_result(captured.ok())
}

/// Map identity capture to sudo's approval `open` contract. In particular,
/// never return zero: sudo interprets zero as a request to unlink the plugin
/// and continue without its approval check.
fn approval_open_result(captured: Option<bool>) -> c_int {
    if captured == Some(true) {
        SUDO_RC_OK
    } else {
        SUDO_RC_ERROR
    }
}

// ---------------------------------------------------------------------------
// check — the approval gate
// ---------------------------------------------------------------------------

/// Sudo calls this after the policy plugin accepts the command.
///
/// Returns 1 to approve, 0 to deny. Never returns -1 (error).
extern "C" fn check(
    command_info: *const *const c_char,
    run_argv: *const *const c_char,
    run_envp: *const *const c_char,
    _errstr: *const *const c_char,
) -> c_int {
    // No panics may cross the FFI boundary. Anything that panics denies.
    let result = catch_unwind(move || {
        // SAFETY: All three pointers are valid, NUL-terminated argv-style
        // arrays passed by sudo. They remain valid for the duration of this
        // call. Sudo guarantees non-NULL pointers for command_info, run_argv,
        // and run_envp when calling an approval plugin.
        match unsafe { gather_context_after_open(command_info, run_argv, run_envp) } {
            Some(info) => run_hook(&info),
            None => 0,
        }
    });

    result.unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Context extraction
// ---------------------------------------------------------------------------

/// Serialized sudo context, ready to hand to the hook child process.
struct SudoContext {
    /// Newline-separated `key=value` pairs from `command_info`, `user_info`,
    /// and `run_envp`. `run_argv` is appended as positional entries.
    payload: Vec<u8>,
}

/// Replace any previous identity with the identity supplied to this `open`.
///
/// Clearing happens while holding the same lock as parsing. An invalid array,
/// a panic, or a poisoned mutex therefore cannot leave reusable identity.
///
/// # Safety
///
/// `user_info` must be a valid, NUL-terminated pointer to NUL-terminated C
/// strings for the duration of this call, as guaranteed by the sudo ABI.
unsafe fn capture_user_info(user_info: *const *const c_char) -> bool {
    let Ok(mut saved) = USER_INFO.lock() else {
        return false;
    };
    *saved = None;

    // SAFETY: The caller supplies sudo's valid `user_info` array.
    let Some(info) = (unsafe { parse_sudo_array(user_info) }) else {
        return false;
    };
    if !has_required_identity(&info) {
        return false;
    }

    *saved = Some(info);
    true
}

/// Consume identity from the immediately preceding successful `open` and
/// gather the remaining context passed to `check`.
///
/// # Safety
///
/// The three arrays must satisfy `gather_context`'s safety contract.
unsafe fn gather_context_after_open(
    command_info: *const *const c_char,
    run_argv: *const *const c_char,
    run_envp: *const *const c_char,
) -> Option<SudoContext> {
    let user_info = USER_INFO.lock().ok()?.take()?;
    // SAFETY: The caller supplies the valid sudo arrays required below.
    unsafe { gather_context(command_info, run_argv, run_envp, &user_info) }
}

/// Require a concrete invoking username and numeric uid. When duplicates are
/// present, the last value is authoritative because that is also how the hook
/// consumes the serialized key-value stream.
fn has_required_identity(info: &[(String, String)]) -> bool {
    let last_value = |key: &str| {
        info.iter()
            .rev()
            .find_map(|(candidate, value)| (candidate == key).then_some(value.as_str()))
    };

    last_value("user").is_some_and(|user| !user.is_empty())
        && last_value("uid").is_some_and(|uid| uid.parse::<u32>().is_ok())
}

/// Collect all sudo arrays into a single payload we can pipe to the hook.
///
/// # Safety
///
/// `command_info`, `run_argv`, and `run_envp` must be valid, NUL-terminated
/// pointers to NUL-terminated `char *` arrays (standard argv-style). `user_info`
/// must be a validated copy captured by `open`. These conditions are guaranteed
/// by the sudo plugin ABI and `gather_context_after_open`.
unsafe fn gather_context(
    command_info: *const *const c_char,
    run_argv: *const *const c_char,
    run_envp: *const *const c_char,
    user_info: &[(String, String)],
) -> Option<SudoContext> {
    // SAFETY: command_info, run_argv, and run_envp are valid NUL-terminated
    // arrays guaranteed by the sudo plugin ABI.
    let info = unsafe { parse_sudo_array(command_info) }?;
    // SAFETY: same contract as above.
    let argv = unsafe { parse_sudo_argv(run_argv) }?;
    // SAFETY: same contract as above.
    let envp = unsafe { parse_sudo_array(run_envp) }?;

    let mut payload = Vec::new();

    for (k, v) in &info {
        push_kv(&mut payload, "info.", k, v);
    }
    // `user_info` is supplied by sudo itself, whereas a policy plugin builds
    // `command_info`. Serialize the trusted identity second so the hook's
    // last-value-wins parser cannot accept a colliding command_info value.
    for (k, v) in user_info {
        push_kv(&mut payload, "info.", k, v);
    }
    // argv is positional — write each entry unambiguously. This binds the
    // exact command-line arguments to the approval. A positional encoding
    // cannot collide with the k=v lines for info/envp.
    for (i, value) in argv.iter().enumerate() {
        let key = format!("argv.{}", i + 1); // 1-based for readability
        push_kv(&mut payload, "", &key, value);
    }
    for (k, v) in &envp {
        push_kv(&mut payload, "env.", k, v);
    }

    Some(SudoContext { payload })
}

// ---------------------------------------------------------------------------
// Sudo array parser
// ---------------------------------------------------------------------------

/// Walk a NUL-terminated `char **` array and split each entry on the first `=`
/// into a (key, value) pair.
///
/// # Safety
///
/// `arr` must point to a valid, NUL-terminated array of NUL-terminated C
/// strings. The caller must ensure the data lives for the duration of the
/// call.
unsafe fn parse_sudo_array(arr: *const *const c_char) -> Option<Vec<(String, String)>> {
    // SAFETY: The caller provides the same valid, NUL-terminated array
    // required by parse_sudo_argv.
    Some(
        unsafe { parse_sudo_argv(arr) }?
            .into_iter()
            .map(|item| match item.find('=') {
                Some(separator) => (
                    item[..separator].to_string(),
                    item[separator + 1..].to_string(),
                ),
                None => (item, String::new()),
            })
            .collect(),
    )
}

/// Walk a NUL-terminated `char **` array without interpreting its entries.
///
/// Unlike sudo's context and environment arrays, `run_argv` contains plain
/// positional strings rather than `key=value` pairs.
///
/// # Safety
///
/// `arr` must point to a valid, NUL-terminated array of NUL-terminated C
/// strings. The caller must ensure the data lives for the duration of the
/// call.
unsafe fn parse_sudo_argv(arr: *const *const c_char) -> Option<Vec<String>> {
    let mut items = Vec::new();
    if arr.is_null() {
        return Some(items);
    }
    let mut i = 0usize;
    loop {
        // SAFETY: `arr.add(i)` stays within the array bounds because the
        // array is NUL-terminated (sudo ABI guarantee). We read only one
        // pointer at a time and stop at the first NULL.
        let ptr = unsafe { *arr.add(i) };
        if ptr.is_null() {
            break;
        }
        // SAFETY: `ptr` is a valid, NUL-terminated C string that lives as
        // long as the array does (borrowed from sudo's memory).
        let bytes = unsafe { CStr::from_ptr(ptr) }.to_bytes();
        // The child protocol is line-framed UTF-8. Replacing invalid bytes or
        // line delimiters would let distinct sudo inputs produce the same
        // approval payload, so unsupported values must deny the request.
        if bytes.contains(&b'\n') || bytes.contains(&b'\r') {
            return None;
        }
        let value = std::str::from_utf8(bytes).ok()?;
        items.push(value.to_owned());
        i += 1;
    }
    Some(items)
}

// ---------------------------------------------------------------------------
// Payload builder
// ---------------------------------------------------------------------------

/// Append one `<prefix><key>=<value>\n` line to the payload buffer.
///
/// Callers validate that `value` contains no line delimiters before reaching
/// this framing layer.
fn push_kv(buf: &mut Vec<u8>, prefix: &str, key: &str, value: &str) {
    buf.extend_from_slice(prefix.as_bytes());
    buf.extend_from_slice(key.as_bytes());
    buf.push(b'=');
    buf.extend_from_slice(value.as_bytes());
    buf.push(b'\n');
}

// ---------------------------------------------------------------------------
// Hook runner — fork, exec, pipe, wait
// ---------------------------------------------------------------------------

/// Full path to the helper binary.
const HOOK_PATH: &str = "/usr/local/sbin/management-plane-sudo-approve";

/// Argument vector passed to the hook.
const HOOK_ARGV: &[&str] = &["management-plane-sudo-approve", "check"];

/// Fork the hook, pipe `ctx` to its stdin, wait for it, and map the exit
/// status to the sudo approval contract.
///
/// Returns 1 (approve) only if the hook exits 0. Every other outcome —
/// exec failure, non-zero exit, signal — returns 0 (deny).
fn run_hook(ctx: &SudoContext) -> c_int {
    spawn_and_wait(ctx).unwrap_or(0)
}

/// Separated from `run_hook` so we can return `Option` (None = deny).
fn spawn_and_wait(ctx: &SudoContext) -> Option<c_int> {
    use nix::sys::wait::{WaitStatus, waitpid};
    use nix::unistd::{ForkResult, execvp, fork};

    // Build the pipe before forking so the child inherits it.
    let (read_fd, write_fd) = nix::unistd::pipe().ok()?;

    // SAFETY: After fork(), only the child runs in the child branch. The
    // parent keeps its memory; the child gets a copy-on-write snapshot. We
    // never touch the parent's memory from the child's exec path.
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            // Extract raw FD for File::from_raw_fd. We own the OwnedFd and
            // convert it to prevent double-close.
            let raw_write = write_fd.into_raw_fd();
            // SAFETY: raw_write is a valid, open file descriptor we own.
            let mut w = unsafe { std::fs::File::from_raw_fd(raw_write) };
            let _ = w.write_all(&ctx.payload);
            let _ = w.flush();
            drop(w); // close write end so child sees EOF

            // Close read end in the parent (safe: we own it).
            drop(read_fd);

            // Block until child exits.
            match waitpid(child, None) {
                Ok(WaitStatus::Exited(_, 0)) => Some(1),
                _ => Some(0),
            }
        }
        Ok(ForkResult::Child) => {
            // Extract raw FDs for the unsafe fd operations below.
            let raw_read = read_fd.into_raw_fd();
            let raw_write = write_fd.into_raw_fd();

            // Replace stdin with the read end of the pipe.
            let _ = nix::unistd::dup2(raw_read, 0);
            let _ = nix::unistd::close(raw_read);
            let _ = nix::unistd::close(raw_write);

            // Build CStrings for exec.
            let path = CString::new(HOOK_PATH).expect("hook path contains no NUL");
            let arg0 = CString::new(HOOK_ARGV[0]).expect("argv[0] contains no NUL");
            let arg1 = CString::new(HOOK_ARGV[1]).expect("argv[1] contains no NUL");
            let hook_args: [&CStr; 2] = [arg0.as_c_str(), arg1.as_c_str()];

            let _ = execvp(path.as_c_str(), &hook_args);
            // If execvp returns, it failed. Exit with a distinctive code the
            // parent maps to deny.
            std::process::exit(127);
        }
        Err(_) => {
            // fork failed; OwnedFd drop closes both ends.
            drop(read_fd);
            drop(write_fd);
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Compile-time layout check
// ---------------------------------------------------------------------------

// The approval_plugin struct must be exactly the size sudo expects: 2 x u32 +
// 4 function pointers = 4 + 4 + 8*4 = 40 bytes on LP64.
const _: () = assert!(
    size_of::<ApprovalPlugin>() == 2 * size_of::<c_uint>() + 4 * size_of::<usize>(),
    "ApprovalPlugin size mismatch with sudo ABI"
);

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::ptr;
    use std::sync::{Mutex, MutexGuard};

    static IDENTITY_TEST: Mutex<()> = Mutex::new(());

    fn identity_test() -> MutexGuard<'static, ()> {
        let guard = IDENTITY_TEST
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *USER_INFO
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        guard
    }

    fn c_array(values: &[&[u8]]) -> (Vec<CString>, Vec<*const c_char>) {
        let strings: Vec<_> = values
            .iter()
            .map(|value| CString::new(value.to_vec()).unwrap())
            .collect();
        let mut pointers: Vec<_> = strings.iter().map(|value| value.as_ptr()).collect();
        pointers.push(ptr::null());
        (strings, pointers)
    }

    fn gather_test_context(
        command_info: &[&[u8]],
        argv: &[&[u8]],
        envp: &[&[u8]],
    ) -> Option<SudoContext> {
        let (_command_info_strings, command_info_ptrs) = c_array(command_info);
        let (_argv_strings, argv_ptrs) = c_array(argv);
        let (_envp_strings, envp_ptrs) = c_array(envp);
        let user_info = vec![
            ("user".to_owned(), "approvalcaller".to_owned()),
            ("uid".to_owned(), "12345".to_owned()),
        ];

        // SAFETY: Each pointer array is NUL-terminated and its C strings live
        // for the duration of the call.
        unsafe {
            gather_context(
                command_info_ptrs.as_ptr(),
                argv_ptrs.as_ptr(),
                envp_ptrs.as_ptr(),
                &user_info,
            )
        }
    }

    fn gather_after_captured_identity(
        command_info: &[&[u8]],
        argv: &[&[u8]],
        envp: &[&[u8]],
    ) -> Option<SudoContext> {
        let (_command_info_strings, command_info_ptrs) = c_array(command_info);
        let (_argv_strings, argv_ptrs) = c_array(argv);
        let (_envp_strings, envp_ptrs) = c_array(envp);

        // SAFETY: Each pointer array is NUL-terminated and its C strings live
        // for the duration of the call.
        unsafe {
            gather_context_after_open(
                command_info_ptrs.as_ptr(),
                argv_ptrs.as_ptr(),
                envp_ptrs.as_ptr(),
            )
        }
    }

    fn capture_test_identity(values: &[&[u8]]) -> bool {
        let (_strings, pointers) = c_array(values);
        // SAFETY: The pointer array is NUL-terminated and its C strings live
        // for the duration of the call.
        unsafe { capture_user_info(pointers.as_ptr()) }
    }

    fn capture_test_open_result(values: &[&[u8]]) -> c_int {
        let (_strings, pointers) = c_array(values);
        // SAFETY: The pointer array is NUL-terminated and its C strings live
        // for the duration of the call.
        unsafe { capture_open_user_info(pointers.as_ptr()) }
    }

    #[test]
    fn approval_open_capture_failure_is_fatal_not_plugin_disable() {
        let _serial = identity_test();

        assert_eq!(approval_open_result(Some(true)), SUDO_RC_OK);
        assert_eq!(approval_open_result(Some(false)), SUDO_RC_ERROR);
        assert_eq!(approval_open_result(None), SUDO_RC_ERROR);
        assert_ne!(approval_open_result(Some(false)), 0);
        assert_ne!(approval_open_result(None), 0);

        assert_eq!(
            capture_test_open_result(&[b"user=approvalcaller", b"uid=12345"]),
            SUDO_RC_OK
        );
        assert_eq!(
            capture_test_open_result(&[b"user=missing-uid"]),
            SUDO_RC_ERROR
        );
    }

    #[test]
    fn open_identity_is_captured_for_exactly_one_check() {
        let _serial = identity_test();
        assert!(capture_test_identity(&[
            b"user=approvalcaller",
            b"uid=12345"
        ]));

        let context =
            gather_after_captured_identity(&[b"command=/usr/bin/echo"], &[b"/usr/bin/echo"], &[])
                .unwrap();
        let payload = String::from_utf8(context.payload).unwrap();
        assert!(payload.contains("info.user=approvalcaller\n"));
        assert!(payload.contains("info.uid=12345\n"));

        assert!(
            gather_after_captured_identity(&[b"command=/usr/bin/echo"], &[b"/usr/bin/echo"], &[],)
                .is_none()
        );
    }

    #[test]
    fn missing_or_replaced_identity_denies_without_reusing_stale_state() {
        let _serial = identity_test();
        assert!(
            gather_after_captured_identity(&[b"command=/usr/bin/echo"], &[b"/usr/bin/echo"], &[],)
                .is_none()
        );

        assert!(capture_test_identity(&[b"user=old", b"uid=1000"]));
        assert!(!capture_test_identity(&[b"user=new"]));
        assert!(
            gather_after_captured_identity(&[b"command=/usr/bin/echo"], &[b"/usr/bin/echo"], &[],)
                .is_none()
        );
    }

    #[test]
    fn invalid_identity_framing_denies_and_clears_stale_state() {
        let _serial = identity_test();
        assert!(capture_test_identity(&[b"user=old", b"uid=1000"]));
        assert!(!capture_test_identity(&[b"user=line\nbreak", b"uid=12345"]));
        assert!(
            gather_after_captured_identity(&[b"command=/usr/bin/echo"], &[b"/usr/bin/echo"], &[],)
                .is_none()
        );

        assert!(!capture_test_identity(&[b"user=bad\xff", b"uid=12345"]));
    }

    #[test]
    fn trusted_user_info_wins_over_duplicate_command_info_identity() {
        let _serial = identity_test();
        assert!(capture_test_identity(&[
            b"user=approvalcaller",
            b"uid=12345"
        ]));

        let context = gather_after_captured_identity(
            &[b"command=/usr/bin/echo", b"user=forged", b"uid=0"],
            &[b"/usr/bin/echo"],
            &[],
        )
        .unwrap();
        let payload = String::from_utf8(context.payload).unwrap();
        let parsed: HashMap<_, _> = payload
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect();
        assert_eq!(parsed.get("info.user"), Some(&"approvalcaller"));
        assert_eq!(parsed.get("info.uid"), Some(&"12345"));
    }

    #[test]
    fn gather_context_preserves_positional_argv() {
        let context = gather_test_context(
            &[b"command=/usr/bin/echo"],
            &[b"/usr/bin/echo", b"hello", b"world with spaces", b"-n"],
            &[],
        )
        .unwrap();

        assert_eq!(
            String::from_utf8(context.payload).unwrap(),
            concat!(
                "info.command=/usr/bin/echo\n",
                "info.user=approvalcaller\n",
                "info.uid=12345\n",
                "argv.1=/usr/bin/echo\n",
                "argv.2=hello\n",
                "argv.3=world with spaces\n",
                "argv.4=-n\n",
            )
        );
    }

    #[test]
    fn gather_context_rejects_line_delimiters_without_conflating_spaces() {
        let with_space = gather_test_context(
            &[b"command=/usr/bin/echo"],
            &[b"/usr/bin/echo", b"line break"],
            &[b"NAME=value"],
        )
        .unwrap();
        assert!(
            with_space
                .payload
                .windows(b"argv.2=line break\n".len())
                .any(|window| window == b"argv.2=line break\n")
        );

        assert!(
            gather_test_context(
                &[b"command=/usr/bin/echo"],
                &[b"/usr/bin/echo", b"line\nbreak"],
                &[b"NAME=value"],
            )
            .is_none()
        );
        assert!(
            gather_test_context(
                &[b"command=/usr/bin/echo\r"],
                &[b"/usr/bin/echo"],
                &[b"NAME=value"],
            )
            .is_none()
        );
        assert!(
            gather_test_context(
                &[b"command=/usr/bin/echo"],
                &[b"/usr/bin/echo"],
                &[b"NAME=line\nbreak"],
            )
            .is_none()
        );
    }

    #[test]
    fn gather_context_rejects_invalid_utf8_in_all_sudo_arrays() {
        assert!(
            gather_test_context(
                &[b"command=/usr/bin/\xff"],
                &[b"/usr/bin/echo"],
                &[b"NAME=value"],
            )
            .is_none()
        );
        assert!(
            gather_test_context(
                &[b"command=/usr/bin/echo"],
                &[b"/usr/bin/\xff"],
                &[b"NAME=value"],
            )
            .is_none()
        );
        assert!(
            gather_test_context(
                &[b"command=/usr/bin/echo"],
                &[b"/usr/bin/echo"],
                &[b"NAME=\xff"],
            )
            .is_none()
        );
    }
}
