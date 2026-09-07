//! `approval_exec` — the sudo approval plugin (cdylib).
//!
//! Exports the `SUDO_APPROVAL_PLUGIN` vtable sudo looks up when it loads this
//! library. The plugin forks `oshioki check` and maps
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
use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _, OwnedFd, RawFd};
use std::panic::catch_unwind;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

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
static OPEN_STATE: Mutex<Option<OpenState>> = Mutex::new(None);

struct OpenState {
    user_info: Vec<(String, String)>,
    noninteractive: bool,
}

/// Capture the invoking identity for the following one-shot approval check.
///
/// Sudo 1.9 supplies `user_info` only to `open`; the plugin must copy it here
/// because sudo owns the pointed-to strings and `check` runs later.
extern "C" fn plugin_open(
    _version: c_uint,
    _conversation: SudoConv,
    _sudo_plugin_printf: SudoPrintf,
    settings: *const *const c_char,
    user_info: *const *const c_char,
    _submit_optind: c_int,
    _submit_argv: *const *const c_char,
    _submit_envp: *const *const c_char,
    _plugin_options: *const *const c_char,
    _errstr: *const *const c_char,
) -> c_int {
    // SAFETY: sudo supplies valid, callback-scoped settings and user_info
    // arrays. The capture function copies both before this callback returns.
    unsafe { capture_open_state(settings, user_info) }
}

/// Capture `settings` and `user_info` and map every failure to sudo's fatal
/// open result.
///
/// # Safety
///
/// Both arrays must satisfy `parse_sudo_array`'s pointer contract.
unsafe fn capture_open_state(
    settings: *const *const c_char,
    user_info: *const *const c_char,
) -> c_int {
    // No panics may cross the FFI boundary. A panic or poisoned state denies.
    let captured = catch_unwind(move || {
        let mut state = OPEN_STATE.lock().ok()?;
        // Clear first: malformed input or a panic must never leave the prior
        // request's identity reusable by a later check.
        *state = None;
        // SAFETY: sudo passes valid, NUL-terminated arrays whose strings live
        // for the duration of this callback. Both parsers copy their values.
        let settings = unsafe { parse_sudo_array(settings) }?;
        let user_info = unsafe { parse_sudo_array(user_info) }?;
        if !has_required_identity(&user_info) {
            return Some(false);
        }
        let noninteractive = settings.iter().any(|(key, value)| {
            key == "noninteractive" && (value.is_empty() || value == "true" || value == "1")
        });
        *state = Some(OpenState {
            user_info,
            noninteractive,
        });
        Some(true)
    });
    approval_open_result(captured.ok().flatten())
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
    #[cfg(target_os = "linux")]
    username: String,
    #[cfg(target_os = "linux")]
    noninteractive: bool,
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
    let state = OPEN_STATE.lock().ok()?.take()?;
    // SAFETY: The caller supplies the valid sudo arrays required below.
    unsafe {
        gather_context(
            command_info,
            run_argv,
            run_envp,
            &state.user_info,
            state.noninteractive,
        )
    }
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
    noninteractive: bool,
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
    // Only behavior-shaping variables cross into the approval: the full
    // environment can carry secrets, and the curated list (shared with the
    // hook, which re-filters) is what the approver is shown and signs.
    for (k, v) in &envp {
        if oshioki_protocol::is_approval_env(k) {
            push_kv(&mut payload, "env.", k, v);
        }
    }

    #[cfg(target_os = "linux")]
    let username = user_info
        .iter()
        .rev()
        .find_map(|(key, value)| (key == "user").then_some(value.clone()))?;
    #[cfg(not(target_os = "linux"))]
    let _ = noninteractive;
    Some(SudoContext {
        payload,
        #[cfg(target_os = "linux")]
        username,
        #[cfg(target_os = "linux")]
        noninteractive,
    })
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
const HOOK_PATH: &str = "/usr/local/sbin/oshioki";

/// Argument vector passed to the hook.
const HOOK_ARGV: &[&str] = &["oshioki", "check"];

/// Fork the hook and wait for its verdict. On Linux, a cancellable password/PAM
/// attempt races the hook. Hook status 0 approves, status 1 explicitly denies,
/// and status 2 means that the approval transport was unavailable, leaving the
/// password branch eligible to win.
fn run_hook(ctx: &SudoContext) -> c_int {
    INTERRUPTED.store(false, Ordering::Relaxed);
    let Some(_signals) = InterruptGuard::install() else {
        return 0;
    };
    let Some(mut hook) = spawn_hook(ctx) else {
        return 0;
    };

    #[cfg(target_os = "linux")]
    return run_hook_with_password(ctx, &mut hook);

    #[cfg(not(target_os = "linux"))]
    run_hook_without_password(&mut hook)
}

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn interrupt_handler(_signal: c_int) {
    INTERRUPTED.store(true, Ordering::Relaxed);
}

struct InterruptGuard {
    previous: libc::sighandler_t,
}

impl InterruptGuard {
    fn install() -> Option<Self> {
        // SAFETY: The handler only performs an atomic store, which is
        // async-signal-safe. The returned disposition is restored on drop.
        let previous = unsafe {
            libc::signal(
                libc::SIGINT,
                interrupt_handler as *const () as libc::sighandler_t,
            )
        };
        (previous != libc::SIG_ERR).then_some(Self { previous })
    }
}

impl Drop for InterruptGuard {
    fn drop(&mut self) {
        // SAFETY: Restore the disposition that was active before this check.
        unsafe { libc::signal(libc::SIGINT, self.previous) };
    }
}

#[cfg(target_os = "linux")]
fn run_hook_with_password(ctx: &SudoContext, hook: &mut HookChild) -> c_int {
    let mut password = if ctx.noninteractive {
        None
    } else {
        spawn_password_process(&ctx.username)
    };
    let deadline = std::time::Instant::now() + PASSWORD_RACE_TIMEOUT;
    let mut hook_done = false;
    let mut hook_result = None;
    let mut password_done = password.is_none();
    let mut password_result = None;

    loop {
        if INTERRUPTED.load(Ordering::Relaxed) {
            cancel_hook(hook);
            drain_hook_stderr(hook, password.as_mut());
            cancel_password(password.take(), true);
            return 0;
        }
        if std::time::Instant::now() >= deadline {
            cancel_hook(hook);
            drain_hook_stderr(hook, password.as_mut());
            cancel_password(password.take(), true);
            return 0;
        }
        drain_password_ready(password.as_mut());
        drain_hook_stderr(hook, password.as_mut());
        if !hook_done {
            if let Some(result) = reap_hook(hook, true) {
                hook_done = true;
                hook_result = Some(result);
                drain_hook_stderr(hook, password.as_mut());
                match result {
                    HookResult::Approved => {
                        cancel_password(password.take(), true);
                        return 1;
                    }
                    HookResult::Denied | HookResult::Failed => {
                        cancel_password(password.take(), true);
                        return 0;
                    }
                    HookResult::Unavailable => {}
                }
            }
        }

        if !password_done {
            if let Some(worker) = &mut password {
                if let Some(result) = reap_password(worker) {
                    password_done = true;
                    password_result = Some(result);
                    if matches!(result, PasswordResult::Rejected) {
                        write_fd(libc::STDERR_FILENO, b"[sudo/oshioki] password rejected\n");
                    }
                }
            }
        }

        if matches!(password_result, Some(PasswordResult::Approved)) {
            // The hook is inspected first on every loop, so an explicit deny
            // that has already completed always defeats a password result.
            if matches!(hook_result, Some(HookResult::Denied | HookResult::Failed)) {
                cancel_password(password.take(), false);
                return 0;
            }
            cancel_hook(hook);
            cancel_password(password.take(), false);
            audit_password_fallback(&ctx.username);
            return 1;
        }

        if hook_done && password_done {
            cancel_password(password.take(), true);
            return 0;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(not(target_os = "linux"))]
fn run_hook_without_password(hook: &mut HookChild) -> c_int {
    let deadline = std::time::Instant::now() + PASSWORD_RACE_TIMEOUT;
    loop {
        if INTERRUPTED.load(Ordering::Relaxed) || std::time::Instant::now() >= deadline {
            cancel_hook(hook);
            drain_hook_stderr(hook, None);
            return 0;
        }
        drain_hook_stderr(hook, None);
        if let Some(result) = reap_hook(hook, true) {
            drain_hook_stderr(hook, None);
            return match result {
                HookResult::Approved => 1,
                HookResult::Denied | HookResult::Unavailable | HookResult::Failed => 0,
            };
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(target_os = "linux")]
fn audit_password_fallback(username: &str) {
    let Ok(format) = CString::new("[oshioki] password fallback approved for %s") else {
        return;
    };
    let Ok(user) = CString::new(username) else {
        return;
    };
    // SAFETY: both C strings are NUL-terminated and contain no user-provided
    // format directives. Only the invoking username is included; no command
    // or password enters the audit record.
    unsafe {
        libc::syslog(
            libc::LOG_AUTHPRIV | libc::LOG_INFO,
            format.as_ptr(),
            user.as_ptr(),
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HookResult {
    Approved,
    Denied,
    Unavailable,
    Failed,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PasswordResult {
    Approved,
    Rejected,
    Unavailable,
    Failed,
}

struct HookChild {
    pid: Option<nix::unistd::Pid>,
    stderr: Option<OwnedFd>,
}

#[cfg(target_os = "linux")]
struct PasswordWorker {
    pid: Option<nix::unistd::Pid>,
    tty: OwnedFd,
    saved_termios: libc::termios,
    terminal_needs_flush: bool,
    ready: Option<OwnedFd>,
    prompt: Vec<u8>,
    prompt_ready: bool,
}

/// Spawn the hook, feed its context, and return its verified child identity.
/// The parent owns the returned pid and must reap it on every path.
fn spawn_hook(ctx: &SudoContext) -> Option<HookChild> {
    use nix::unistd::{ForkResult, execvp, fork};

    // Build the stdin and stderr pipes before forking so the child inherits
    // both. The parent forwards only stderr, leaving command stdout alone.
    let (read_fd, write_fd) = nix::unistd::pipe().ok()?;
    let Ok((stderr_read, stderr_write)) = nix::unistd::pipe() else {
        drop(read_fd);
        drop(write_fd);
        return None;
    };

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
            drop(stderr_write);
            set_nonblocking(stderr_read.as_raw_fd());

            Some(HookChild {
                pid: Some(child),
                stderr: Some(stderr_read),
            })
        }
        Ok(ForkResult::Child) => {
            // Extract raw FDs for the unsafe fd operations below.
            let raw_read = read_fd.into_raw_fd();
            let raw_write = write_fd.into_raw_fd();
            let raw_stderr_read = stderr_read.into_raw_fd();
            let raw_stderr_write = stderr_write.into_raw_fd();

            // Replace stdin with the read end of the pipe.
            let _ = nix::unistd::dup2(raw_read, 0);
            let _ = nix::unistd::close(raw_read);
            let _ = nix::unistd::close(raw_write);
            let _ = nix::unistd::dup2(raw_stderr_write, 2);
            let _ = nix::unistd::close(raw_stderr_read);
            let _ = nix::unistd::close(raw_stderr_write);
            reset_child_signals();

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
            drop(stderr_read);
            drop(stderr_write);
            None
        }
    }
}

fn set_nonblocking(fd: RawFd) {
    // SAFETY: fd is an open descriptor owned by the caller. The existing file
    // status flags are preserved while adding O_NONBLOCK.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            let _ = libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}

fn hook_result(status: nix::sys::wait::WaitStatus) -> HookResult {
    match status {
        nix::sys::wait::WaitStatus::Exited(_, 0) => HookResult::Approved,
        nix::sys::wait::WaitStatus::Exited(_, 1) => HookResult::Denied,
        nix::sys::wait::WaitStatus::Exited(_, 2) => HookResult::Unavailable,
        _ => HookResult::Failed,
    }
}

/// Reap the child, optionally without blocking. The pid came directly from
/// `fork`, so this cannot target an unrelated process.
fn reap_hook(hook: &mut HookChild, nohang: bool) -> Option<HookResult> {
    use nix::sys::wait::{WaitPidFlag, waitpid};
    let pid = hook.pid?;
    let flags = nohang.then_some(WaitPidFlag::WNOHANG);
    match waitpid(pid, flags) {
        Ok(nix::sys::wait::WaitStatus::StillAlive) | Err(nix::errno::Errno::EINTR) => None,
        Ok(status) => {
            hook.pid = None;
            Some(hook_result(status))
        }
        Err(_) => {
            // ECHILD and other wait errors mean this child cannot be
            // accounted for. Keep the fail-closed result, but do not reuse
            // the pid in a later kill call.
            hook.pid = None;
            Some(HookResult::Failed)
        }
    }
}

fn write_fd(fd: RawFd, bytes: &[u8]) {
    let mut offset = 0;
    while offset < bytes.len() {
        // SAFETY: fd is an open descriptor owned by the caller and the slice
        // remains valid for the duration of this write.
        let written =
            unsafe { libc::write(fd, bytes[offset..].as_ptr().cast(), bytes.len() - offset) };
        if written > 0 {
            offset += usize::try_from(written).unwrap_or(0);
        } else if written < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
        {
            // Retry after the signal interrupted the write.
        } else {
            return;
        }
    }
}

#[cfg(target_os = "linux")]
fn drain_password_ready(worker: Option<&mut PasswordWorker>) {
    let Some(worker) = worker else {
        return;
    };
    let Some(ready_fd) = worker.ready.as_ref().map(std::os::fd::AsRawFd::as_raw_fd) else {
        return;
    };
    let mut bytes = [0u8; 16];
    loop {
        // SAFETY: bytes is writable storage and ready is an open pipe
        // descriptor owned by this process.
        let read = unsafe { libc::read(ready_fd, bytes.as_mut_ptr().cast(), bytes.len()) };
        if read > 0 {
            let read = usize::try_from(read).expect("positive ready-pipe read length");
            for state in &bytes[..read] {
                worker.prompt_ready = *state == 1 && worker.pid.is_some();
            }
            // Drain all queued state transitions before forwarding hook output
            // so a submitted password cannot be followed by a redraw.
            continue;
        }
        if read == 0 {
            worker.ready = None;
            worker.prompt_ready = false;
        } else {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if error.raw_os_error() != Some(libc::EAGAIN)
                && error.raw_os_error() != Some(libc::EWOULDBLOCK)
            {
                worker.ready = None;
                worker.prompt_ready = false;
            }
        }
        break;
    }
}

#[cfg(target_os = "linux")]
fn redraw_password_prompt(worker: &mut PasswordWorker) {
    if worker.prompt_ready && worker.pid.is_some() && worker.ready.is_some() {
        write_fd(worker.tty.as_raw_fd(), &worker.prompt);
    }
}

fn drain_hook_stderr(
    hook: &mut HookChild,
    #[cfg(target_os = "linux")] password: Option<&mut PasswordWorker>,
    #[cfg(not(target_os = "linux"))] _password: Option<&mut ()>,
) {
    #[cfg(target_os = "linux")]
    let mut output_seen = false;
    let Some(stderr_fd) = hook.stderr.as_ref().map(std::os::fd::AsRawFd::as_raw_fd) else {
        return;
    };
    loop {
        let mut bytes = [0u8; 4096];
        // SAFETY: bytes is writable storage and stderr is an open pipe
        // descriptor owned by this process.
        let read = unsafe { libc::read(stderr_fd, bytes.as_mut_ptr().cast(), bytes.len()) };
        if read > 0 {
            let read = usize::try_from(read).unwrap_or(0);
            // The hook sanitizes its own diagnostics. Forward the bytes to the
            // original stderr only; command stdout remains untouched.
            write_fd(libc::STDERR_FILENO, &bytes[..read]);
            #[cfg(target_os = "linux")]
            {
                output_seen = true;
            }
            continue;
        }
        if read == 0 {
            hook.stderr = None;
        } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        } else if std::io::Error::last_os_error().raw_os_error() != Some(libc::EAGAIN)
            && std::io::Error::last_os_error().raw_os_error() != Some(libc::EWOULDBLOCK)
        {
            hook.stderr = None;
        }
        break;
    }
    #[cfg(target_os = "linux")]
    if output_seen {
        if let Some(worker) = password {
            drain_password_ready(Some(&mut *worker));
            redraw_password_prompt(worker);
        }
    }
}

fn cancel_hook(hook: &mut HookChild) {
    if let Some(pid) = hook.pid {
        // SAFETY: pid was returned by fork and has not been reaped yet.
        unsafe { libc::kill(pid.as_raw(), libc::SIGTERM) };
        reap_after_signal_hook(hook);
    }
}

const CHILD_TERM_GRACE: Duration = Duration::from_millis(250);

fn reap_after_signal_hook(hook: &mut HookChild) {
    let deadline = std::time::Instant::now() + CHILD_TERM_GRACE;
    while hook.pid.is_some() && std::time::Instant::now() < deadline {
        if reap_hook(hook, true).is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let Some(pid) = hook.pid else {
        return;
    };
    // A child that ignores TERM cannot be allowed to hold sudo indefinitely.
    // The pid was retained from fork and is still unreaped, so this kill is
    // scoped to the hook child rather than an unrelated process.
    unsafe { libc::kill(pid.as_raw(), libc::SIGKILL) };
    reap_hook_blocking(hook);
}

#[cfg(target_os = "linux")]
fn cancel_password(worker: Option<PasswordWorker>, flush_input: bool) {
    if let Some(worker) = worker {
        if let Some(pid) = worker.pid {
            // SAFETY: pid was returned by fork and has not been reaped yet.
            unsafe { libc::kill(pid.as_raw(), libc::SIGTERM) };
            reap_after_signal_password(pid);
        }
        // The parent keeps an independent tty descriptor and termios
        // snapshot. Restore echo and flush partially typed input even when
        // PAM is blocked and the password process must be terminated.
        let flush = worker.terminal_needs_flush || flush_input;
        restore_terminal(worker.tty.as_raw_fd(), &worker.saved_termios, flush);
    }
}

#[cfg(target_os = "linux")]
fn reap_after_signal_password(pid: nix::unistd::Pid) {
    let deadline = std::time::Instant::now() + CHILD_TERM_GRACE;
    while std::time::Instant::now() < deadline {
        match nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
            Ok(nix::sys::wait::WaitStatus::StillAlive) | Err(nix::errno::Errno::EINTR) => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(_) | Err(_) => return,
        }
    }
    // SAFETY: pid is the unreaped password child returned by fork.
    unsafe { libc::kill(pid.as_raw(), libc::SIGKILL) };
    loop {
        let status = nix::sys::wait::waitpid(pid, None);
        if !matches!(status, Err(nix::errno::Errno::EINTR)) {
            break;
        }
    }
}

fn reap_hook_blocking(hook: &mut HookChild) {
    while hook.pid.is_some() {
        let _ = reap_hook(hook, false);
    }
}

const PASSWORD_RACE_TIMEOUT: Duration = Duration::from_secs(95);

/// Start a separate password process before any password bytes are read. A
/// process boundary makes a stuck PAM module cancellable; the parent owns a
/// duplicate tty fd so it can restore termios after killing that process.
#[cfg(target_os = "linux")]
fn spawn_password_process(username: &str) -> Option<PasswordWorker> {
    let (tty, saved_termios) = open_tty_for_password()?;
    let child_tty = duplicate_fd(&tty)?;
    let (ready_read, ready_write) = nix::unistd::pipe().ok()?;
    set_nonblocking(ready_read.as_raw_fd());
    if !set_quiet_terminal(tty.as_raw_fd(), &saved_termios) {
        return None;
    }
    let username = username.to_owned();
    let prompt = format!("[sudo/oshioki] password for {username}: ").into_bytes();
    // SAFETY: This fork occurs before any worker threads. The child only uses
    // inherited tty/cancellation fds and exits after tty/PAM cleanup.
    let forked = unsafe { nix::unistd::fork() };
    match forked {
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            drop(child_tty);
            drop(ready_write);
            Some(PasswordWorker {
                pid: Some(child),
                tty,
                saved_termios,
                terminal_needs_flush: false,
                ready: Some(ready_read),
                prompt,
                prompt_ready: false,
            })
        }
        Ok(nix::unistd::ForkResult::Child) => {
            drop(tty);
            drop(ready_read);
            reset_child_signals();
            let result =
                read_and_authenticate_password(&username, child_tty, saved_termios, &ready_write);
            let code = match result {
                PasswordResult::Approved => 0,
                PasswordResult::Rejected => 1,
                PasswordResult::Unavailable => 2,
                PasswordResult::Failed => 3,
            };
            // SAFETY: The child has restored its terminal before exiting.
            unsafe { libc::_exit(code) }
        }
        Err(_) => {
            drop(child_tty);
            drop(ready_read);
            drop(ready_write);
            restore_terminal(tty.as_raw_fd(), &saved_termios, true);
            None
        }
    }
}

#[cfg(target_os = "linux")]
fn reap_password(worker: &mut PasswordWorker) -> Option<PasswordResult> {
    use nix::sys::wait::{WaitPidFlag, waitpid};
    let pid = worker.pid?;
    match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
        Ok(nix::sys::wait::WaitStatus::StillAlive) | Err(nix::errno::Errno::EINTR) => None,
        Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => {
            worker.pid = None;
            worker.prompt_ready = false;
            worker.terminal_needs_flush = true;
            let result = match code {
                0 => PasswordResult::Approved,
                1 => PasswordResult::Rejected,
                2 => PasswordResult::Unavailable,
                _ => PasswordResult::Failed,
            };
            restore_terminal(
                worker.tty.as_raw_fd(),
                &worker.saved_termios,
                worker.terminal_needs_flush,
            );
            Some(result)
        }
        Ok(_) | Err(_) => {
            worker.pid = None;
            worker.prompt_ready = false;
            worker.terminal_needs_flush = true;
            restore_terminal(worker.tty.as_raw_fd(), &worker.saved_termios, true);
            Some(PasswordResult::Failed)
        }
    }
}

fn reset_child_signals() {
    // SAFETY: The password child is about to become an independent bounded
    // worker. Restore default termination behavior and clear sudo's inherited
    // signal mask so cancellation cannot be ignored by a parent policy.
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_DFL);
        libc::signal(libc::SIGINT, libc::SIG_DFL);
        let mut mask = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        libc::sigemptyset(mask.as_mut_ptr());
        libc::sigprocmask(libc::SIG_SETMASK, mask.as_ptr(), std::ptr::null_mut());
    }
}

#[cfg(target_os = "linux")]
fn duplicate_fd(fd: &OwnedFd) -> Option<OwnedFd> {
    let duplicate = unsafe { libc::dup(fd.as_raw_fd()) };
    if duplicate < 0 {
        None
    } else {
        // SAFETY: `duplicate` is a fresh descriptor returned by dup and is
        // owned by this call until transferred to OwnedFd.
        Some(unsafe { OwnedFd::from_raw_fd(duplicate) })
    }
}

#[cfg(target_os = "linux")]
fn open_tty_for_password() -> Option<(OwnedFd, libc::termios)> {
    let path = CString::new("/dev/tty").expect("tty path contains no NUL");
    // SAFETY: The path is a fixed NUL-terminated string and no borrowed
    // memory crosses the libc call.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    // SAFETY: `fd` is a fresh descriptor returned by open and is transferred
    // to OwnedFd exactly once.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // A background process group must not touch terminal attributes. This
    // check runs before any tcsetattr or fork, avoiding SIGTTOU for jobs.
    // SAFETY: fd is an open terminal descriptor and getpgrp has no arguments.
    let foreground = unsafe { libc::tcgetpgrp(fd.as_raw_fd()) };
    let process_group = unsafe { libc::getpgrp() };
    if foreground < 0 || foreground != process_group {
        return None;
    }
    let mut saved = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: `saved` points to writable storage and fd is a terminal owned by
    // this process.
    if unsafe { libc::tcgetattr(fd.as_raw_fd(), saved.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: tcgetattr initialized saved on success.
    Some((fd, unsafe { saved.assume_init() }))
}

#[cfg(target_os = "linux")]
fn set_quiet_terminal(fd: RawFd, saved: &libc::termios) -> bool {
    let mut quiet = *saved;
    quiet.c_lflag &= !(libc::ECHO | libc::ECHONL);
    // SAFETY: quiet was copied from a termios value read from this terminal.
    unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw const quiet) == 0 }
}

#[cfg(target_os = "linux")]
fn restore_terminal(fd: RawFd, saved: &libc::termios, flush_input: bool) {
    // SAFETY: fd is an open /dev/tty descriptor owned by the caller, and the
    // termios value came from tcgetattr on that same terminal.
    unsafe {
        if flush_input {
            libc::tcflush(fd, libc::TCIFLUSH);
        }
        libc::tcsetattr(fd, libc::TCSANOW, saved);
        if flush_input {
            // Finish a line containing partially typed bytes. The password
            // itself was never written to this descriptor.
            let newline = *b"\n";
            libc::write(fd, newline.as_ptr().cast(), newline.len());
        }
    }
}

#[cfg(target_os = "linux")]
struct PasswordTtyGuard {
    fd: RawFd,
    saved: libc::termios,
    flush_input: bool,
}

#[cfg(target_os = "linux")]
impl Drop for PasswordTtyGuard {
    fn drop(&mut self) {
        restore_terminal(self.fd, &self.saved, self.flush_input);
    }
}

/// Read one password using a pollable tty and authenticate it through the
/// system's `sudo` PAM service. The parent cancels this process with SIGTERM;
/// the parent-held tty descriptor then restores and flushes input before the
/// plugin returns.
#[cfg(target_os = "linux")]
fn read_and_authenticate_password(
    username: &str,
    tty: OwnedFd,
    saved: libc::termios,
    ready: &OwnedFd,
) -> PasswordResult {
    let fd = tty.as_raw_fd();
    let mut tty_file = unsafe { std::fs::File::from_raw_fd(tty.into_raw_fd()) };
    // Declare the file before the guard so Rust drops the guard first; its
    // restore operation therefore always sees a live tty descriptor.
    let mut guard = PasswordTtyGuard {
        fd,
        saved,
        flush_input: false,
    };
    let prompt = format!("[sudo/oshioki] password for {username}: ");
    if tty_file.write_all(prompt.as_bytes()).is_err() || tty_file.flush().is_err() {
        guard.flush_input = true;
        return PasswordResult::Unavailable;
    }
    // The parent set quiet mode before fork. Signal readiness only after the
    // prompt is visible, so a redraw can never precede echo suppression.
    write_fd(ready.as_raw_fd(), &[1]);

    let deadline = std::time::Instant::now() + PASSWORD_RACE_TIMEOUT;
    let mut input = Vec::with_capacity(4096);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            zeroize_bytes(&mut input);
            guard.flush_input = true;
            return PasswordResult::Unavailable;
        }
        let timeout_ms = remaining.as_millis().min(100) as libc::c_int;
        let mut fds = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        // SAFETY: fds points to two initialized pollfd values for this call.
        let polled = unsafe { libc::poll(&raw mut fds, 1, timeout_ms) };
        if polled < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            zeroize_bytes(&mut input);
            guard.flush_input = true;
            return PasswordResult::Unavailable;
        }
        if fds.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let mut bytes = [0u8; 256];
            // SAFETY: bytes is writable storage and fd is open.
            let read = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
            if read <= 0 {
                zeroize_bytes(&mut input);
                guard.flush_input = true;
                return PasswordResult::Unavailable;
            }
            let read = usize::try_from(read).expect("positive read length");
            if read > 4096 - input.len() {
                zeroize_bytes(&mut bytes[..read]);
                zeroize_bytes(&mut input);
                guard.flush_input = true;
                return PasswordResult::Rejected;
            }
            input.extend_from_slice(&bytes[..read]);
            zeroize_bytes(&mut bytes[..read]);
            if let Some(end) = input.iter().position(|byte| *byte == b'\n') {
                // Stop advertising an input reader before handing the line to
                // PAM. The child remains alive while PAM authenticates, but it
                // no longer accepts another password line.
                write_fd(ready.as_raw_fd(), &[0]);
                let password_end = end
                    .checked_sub(1)
                    .filter(|index| input[*index] == b'\r')
                    .unwrap_or(end);
                let result = if input[..password_end].contains(&0) {
                    guard.flush_input = true;
                    PasswordResult::Rejected
                } else {
                    authenticate_password_line(
                        username,
                        &input[..password_end],
                        authenticate_with_pam,
                    )
                };
                zeroize_bytes(&mut input);
                let _ = tty_file.write_all(b"\n");
                let _ = tty_file.flush();
                drop(tty_file);
                return result;
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn authenticate_password_line<F>(username: &str, password: &[u8], authenticate: F) -> PasswordResult
where
    F: FnOnce(&str, &[u8]) -> PasswordResult,
{
    // Enter means "skip". Do not send an empty password through PAM, since
    // the host's sudo stack may count it as a failed authentication attempt.
    if password.is_empty() {
        return PasswordResult::Unavailable;
    }
    authenticate(username, password)
}

#[cfg(target_os = "linux")]
fn zeroize_bytes(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: byte points into the uniquely borrowed secret buffer.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}

#[cfg(target_os = "linux")]
fn authenticate_with_pam(username: &str, password: &[u8]) -> PasswordResult {
    pam::authenticate(username, password)
}

#[cfg(target_os = "linux")]
mod pam {
    use super::PasswordResult;
    use std::ffi::{CStr, CString, c_char, c_int, c_void};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::ptr;

    const PAM_SUCCESS: c_int = 0;
    const PAM_CONV_ERR: c_int = 19;
    const PAM_PROMPT_ECHO_OFF: c_int = 1;
    const PAM_PROMPT_ECHO_ON: c_int = 2;
    const PAM_ERROR_MSG: c_int = 3;
    const PAM_TEXT_INFO: c_int = 4;
    const PAM_TTY: c_int = 3;
    const PAM_RUSER: c_int = 8;
    const PAM_SILENT: c_int = 0x8000;

    #[repr(C)]
    struct PamMessage {
        style: c_int,
        msg: *const c_char,
    }

    #[repr(C)]
    struct PamResponse {
        resp: *mut c_char,
        resp_retcode: c_int,
    }

    type PamHandle = c_void;
    type PamConversation = unsafe extern "C" fn(
        c_int,
        *const *const PamMessage,
        *mut *mut PamResponse,
        *mut c_void,
    ) -> c_int;
    #[repr(C)]
    struct PamConv {
        conv: Option<PamConversation>,
        data_ptr: *mut c_void,
    }

    type PamStart = unsafe extern "C" fn(
        *const c_char,
        *const c_char,
        *const PamConv,
        *mut *mut PamHandle,
    ) -> c_int;
    type PamAuthenticate = unsafe extern "C" fn(*mut PamHandle, c_int) -> c_int;
    type PamAcctMgmt = unsafe extern "C" fn(*mut PamHandle, c_int) -> c_int;
    type PamSetItem = unsafe extern "C" fn(*mut PamHandle, c_int, *const c_void) -> c_int;
    type PamEnd = unsafe extern "C" fn(*mut PamHandle, c_int) -> c_int;

    struct PamApi {
        library: *mut c_void,
        start: PamStart,
        authenticate: PamAuthenticate,
        acct_mgmt: PamAcctMgmt,
        set_item: PamSetItem,
        end: PamEnd,
    }

    impl Drop for PamApi {
        fn drop(&mut self) {
            // SAFETY: library was returned by dlopen and remains held until
            // all resolved calls have completed.
            unsafe { libc::dlclose(self.library) };
        }
    }

    impl PamApi {
        fn load() -> Option<Self> {
            let name = CString::new("libpam.so.0").ok()?;
            // SAFETY: name is a fixed NUL-terminated library name.
            let library = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
            if library.is_null() {
                return None;
            }
            let symbol = |name: &'static [u8]| -> *mut c_void {
                // SAFETY: every name below is NUL-terminated and library is
                // a live dlopen handle.
                unsafe { libc::dlsym(library, name.as_ptr().cast()) }
            };
            let start = symbol(b"pam_start\0");
            let authenticate = symbol(b"pam_authenticate\0");
            let acct_mgmt = symbol(b"pam_acct_mgmt\0");
            let set_item = symbol(b"pam_set_item\0");
            let end = symbol(b"pam_end\0");
            if [start, authenticate, acct_mgmt, set_item, end]
                .iter()
                .any(|ptr| ptr.is_null())
            {
                // SAFETY: library is the handle opened above and no PAM call
                // has begun.
                unsafe { libc::dlclose(library) };
                return None;
            }
            // SAFETY: dlsym resolved each symbol to the function type declared
            // by pam_appl.h; function and data pointers have the platform ABI
            // representation used by this Linux target.
            Some(Self {
                library,
                start: unsafe { std::mem::transmute::<*mut c_void, PamStart>(start) },
                authenticate: unsafe {
                    std::mem::transmute::<*mut c_void, PamAuthenticate>(authenticate)
                },
                acct_mgmt: unsafe { std::mem::transmute::<*mut c_void, PamAcctMgmt>(acct_mgmt) },
                set_item: unsafe { std::mem::transmute::<*mut c_void, PamSetItem>(set_item) },
                end: unsafe { std::mem::transmute::<*mut c_void, PamEnd>(end) },
            })
        }
    }

    struct ConversationData {
        username: CString,
        password: Vec<u8>,
    }

    impl Drop for ConversationData {
        fn drop(&mut self) {
            super::zeroize_bytes(&mut self.password);
        }
    }

    unsafe extern "C" fn conversation(
        count: c_int,
        messages: *const *const PamMessage,
        responses: *mut *mut PamResponse,
        data: *mut c_void,
    ) -> c_int {
        let result = catch_unwind(AssertUnwindSafe(|| {
            if responses.is_null() {
                return PAM_CONV_ERR;
            }
            // PAM must see a null output pointer on every failure path. We
            // publish the allocated array only after all messages succeed.
            // SAFETY: responses is non-null and points to PAM-owned writable
            // output storage for one response-array pointer.
            unsafe { *responses = ptr::null_mut() };
            if count <= 0 || messages.is_null() || data.is_null() {
                return PAM_CONV_ERR;
            }
            let count = usize::try_from(count).ok().filter(|count| *count <= 32);
            let Some(count) = count else {
                return PAM_CONV_ERR;
            };
            let data = unsafe { &*(data.cast::<ConversationData>()) };
            // pam_conv requires the callback to allocate the response array;
            // PAM owns it after a successful return and frees it later.
            let allocated = unsafe {
                libc::calloc(count, std::mem::size_of::<PamResponse>()).cast::<PamResponse>()
            };
            if allocated.is_null() {
                return PAM_CONV_ERR;
            }
            for index in 0..count {
                // SAFETY: PAM provides count message pointers and a response
                // array of the same count for this callback.
                let message = unsafe { *messages.add(index) };
                if message.is_null() {
                    unsafe { free_responses(allocated, count) };
                    return PAM_CONV_ERR;
                }
                // SAFETY: allocated points to count writable response slots.
                let response = unsafe { &mut *allocated.add(index) };
                response.resp = ptr::null_mut();
                response.resp_retcode = 0;
                let source = match unsafe { (*message).style } {
                    PAM_PROMPT_ECHO_OFF => &data.password,
                    PAM_PROMPT_ECHO_ON => data.username.as_bytes_with_nul(),
                    PAM_ERROR_MSG | PAM_TEXT_INFO => continue,
                    _ => {
                        unsafe { free_responses(allocated, count) };
                        return PAM_CONV_ERR;
                    }
                };
                // PAM expects calloc-compatible response storage and frees it
                // after the conversation returns.
                let response_allocated = unsafe { libc::malloc(source.len()) };
                if response_allocated.is_null() {
                    unsafe { free_responses(allocated, count) };
                    return PAM_CONV_ERR;
                }
                // SAFETY: allocated has source.len bytes and source is valid.
                unsafe {
                    ptr::copy_nonoverlapping(
                        source.as_ptr(),
                        response_allocated.cast(),
                        source.len(),
                    );
                }
                response.resp = response_allocated.cast();
            }
            // SAFETY: all count response slots are initialized and allocated
            // remains live for PAM to own after this successful return.
            unsafe { *responses = allocated };
            PAM_SUCCESS
        }));
        result.unwrap_or(PAM_CONV_ERR)
    }

    unsafe fn free_responses(responses: *mut PamResponse, count: usize) {
        for index in 0..count {
            // SAFETY: responses has count initialized slots from calloc.
            let response = unsafe { &mut *responses.add(index) };
            if !response.resp.is_null() {
                // SAFETY: response.resp was allocated by malloc above and its
                // bytes are private password/username material.
                unsafe {
                    let length = CStr::from_ptr(response.resp).to_bytes().len();
                    super::zeroize_bytes(std::slice::from_raw_parts_mut(
                        response.resp.cast::<u8>(),
                        length,
                    ));
                    libc::free(response.resp.cast());
                }
            }
        }
        // SAFETY: responses was allocated with calloc above.
        unsafe { libc::free(responses.cast()) };
    }

    pub(super) fn authenticate(username: &str, password: &[u8]) -> PasswordResult {
        let Some(api) = PamApi::load() else {
            return PasswordResult::Unavailable;
        };
        let Ok(user) = CString::new(username) else {
            return PasswordResult::Rejected;
        };
        let Ok(pass) = CString::new(password) else {
            return PasswordResult::Rejected;
        };
        let mut data = ConversationData {
            username: user,
            password: pass.into_bytes_with_nul(),
        };
        let conv = PamConv {
            conv: Some(conversation),
            data_ptr: (&raw mut data).cast(),
        };
        let service = CString::new("sudo").expect("PAM service contains no NUL");
        let mut handle = ptr::null_mut();
        // SAFETY: All strings and callback data live through the PAM calls;
        // handle is writable storage for pam_start.
        let start = unsafe {
            (api.start)(
                service.as_ptr(),
                data.username.as_ptr(),
                &raw const conv,
                &raw mut handle,
            )
        };
        if start != PAM_SUCCESS {
            if !handle.is_null() {
                // SAFETY: PAM returned a handle even though startup failed;
                // end it before releasing the dynamically loaded API.
                unsafe { (api.end)(handle, start) };
            }
            return PasswordResult::Rejected;
        }
        if handle.is_null() {
            return PasswordResult::Rejected;
        }
        let tty = CString::new("/dev/tty").expect("PAM tty contains no NUL");
        // Keep the host's sudo PAM service while supplying the same context
        // that sudo supplies to its own PAM conversation.
        let tty_result = unsafe { (api.set_item)(handle, PAM_TTY, tty.as_ptr().cast()) };
        let ruser_result =
            unsafe { (api.set_item)(handle, PAM_RUSER, data.username.as_ptr().cast()) };
        if tty_result != PAM_SUCCESS || ruser_result != PAM_SUCCESS {
            // PAM may reject optional context items. Treat that as a failed
            // authentication rather than silently running with weaker audit
            // context.
            unsafe { (api.end)(handle, PAM_CONV_ERR) };
            return PasswordResult::Rejected;
        }
        // SAFETY: handle was initialized by successful pam_start and the
        // callback remains valid for the lifetime of this handle.
        let auth = unsafe { (api.authenticate)(handle, 0) };
        let account = if auth == PAM_SUCCESS {
            // SAFETY: same live PAM handle and callback data as above.
            unsafe { (api.acct_mgmt)(handle, PAM_SILENT) }
        } else {
            auth
        };
        // SAFETY: handle is ended exactly once after the final PAM operation.
        unsafe { (api.end)(handle, account) };
        if auth == PAM_SUCCESS && account == PAM_SUCCESS {
            PasswordResult::Approved
        } else {
            PasswordResult::Rejected
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn conversation_data() -> ConversationData {
            ConversationData {
                username: CString::new("fixture").unwrap(),
                password: CString::new("password").unwrap().into_bytes_with_nul(),
            }
        }

        #[test]
        fn conversation_clears_output_after_unsupported_message_cleanup() {
            let mut data = conversation_data();
            let prompt = PamMessage {
                style: PAM_PROMPT_ECHO_OFF,
                msg: ptr::null(),
            };
            let unsupported = PamMessage {
                style: 99,
                msg: ptr::null(),
            };
            let messages = [&raw const prompt, &raw const unsupported];
            let mut responses = ptr::null_mut();
            // SAFETY: all message pointers and callback data live through the
            // direct callback invocation; responses is writable output.
            let result = unsafe {
                conversation(
                    2,
                    messages.as_ptr(),
                    &raw mut responses,
                    (&raw mut data).cast(),
                )
            };
            assert_eq!(result, PAM_CONV_ERR);
            assert!(responses.is_null());
        }

        #[test]
        fn conversation_clears_output_after_null_message_cleanup() {
            let mut data = conversation_data();
            let prompt = PamMessage {
                style: PAM_PROMPT_ECHO_OFF,
                msg: ptr::null(),
            };
            let messages = [&raw const prompt, ptr::null()];
            let mut responses = ptr::null_mut();
            // SAFETY: all message pointers and callback data live through the
            // direct callback invocation; responses is writable output.
            let result = unsafe {
                conversation(
                    2,
                    messages.as_ptr(),
                    &raw mut responses,
                    (&raw mut data).cast(),
                )
            };
            assert_eq!(result, PAM_CONV_ERR);
            assert!(responses.is_null());
        }

        #[test]
        fn conversation_publishes_responses_only_after_success() {
            let mut data = conversation_data();
            let prompt = PamMessage {
                style: PAM_PROMPT_ECHO_OFF,
                msg: ptr::null(),
            };
            let messages = [&raw const prompt];
            let mut responses = ptr::null_mut();
            // SAFETY: all message pointers and callback data live through the
            // direct callback invocation; responses is writable output.
            let result = unsafe {
                conversation(
                    1,
                    messages.as_ptr(),
                    &raw mut responses,
                    (&raw mut data).cast(),
                )
            };
            assert_eq!(result, PAM_SUCCESS);
            assert!(!responses.is_null());
            // SAFETY: success published an array with one initialized slot.
            assert_eq!(
                unsafe { CStr::from_ptr((*responses).resp) }.to_bytes(),
                b"password"
            );
            // SAFETY: the successful callback allocated one response array.
            unsafe { free_responses(responses, 1) };
        }

        #[test]
        fn empty_password_skips_pam_but_whitespace_reaches_it() {
            let mut calls = 0;
            let empty = super::super::authenticate_password_line("fixture", b"", |_, _| {
                calls += 1;
                PasswordResult::Approved
            });
            assert_eq!(empty, PasswordResult::Unavailable);
            assert_eq!(calls, 0);

            let whitespace =
                super::super::authenticate_password_line("fixture", b" ", |_, password| {
                    calls += 1;
                    assert_eq!(password, b" ");
                    PasswordResult::Rejected
                });
            assert_eq!(whitespace, PasswordResult::Rejected);
            assert_eq!(calls, 1);
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
        *OPEN_STATE
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
                false,
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
        unsafe { capture_open_state(ptr::null(), pointers.as_ptr()) == SUDO_RC_OK }
    }

    fn capture_test_open_result(values: &[&[u8]]) -> c_int {
        let (_strings, pointers) = c_array(values);
        // SAFETY: The pointer array is NUL-terminated and its C strings live
        // for the duration of the call.
        unsafe { capture_open_state(ptr::null(), pointers.as_ptr()) }
    }

    fn capture_test_open_with_settings(settings: &[&[u8]], values: &[&[u8]]) -> c_int {
        let (_setting_strings, setting_ptrs) = c_array(settings);
        let (_strings, pointers) = c_array(values);
        // SAFETY: Both pointer arrays are NUL-terminated and their C strings
        // live for the duration of the call.
        unsafe { capture_open_state(setting_ptrs.as_ptr(), pointers.as_ptr()) }
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
    #[cfg(target_os = "linux")]
    fn open_captures_noninteractive_without_trusting_caller_environment() {
        let _serial = identity_test();
        assert_eq!(
            capture_test_open_with_settings(
                &[b"noninteractive"],
                &[b"user=approvalcaller", b"uid=12345"]
            ),
            SUDO_RC_OK
        );
        let context =
            gather_after_captured_identity(&[b"command=/usr/bin/true"], &[b"/usr/bin/true"], &[])
                .unwrap();
        assert!(context.noninteractive);

        assert_eq!(
            capture_test_open_with_settings(
                &[b"noninteractive=false"],
                &[b"user=approvalcaller", b"uid=12345"]
            ),
            SUDO_RC_OK
        );
        assert!(
            !gather_after_captured_identity(&[b"command=/usr/bin/true"], &[b"/usr/bin/true"], &[],)
                .unwrap()
                .noninteractive
        );
    }

    #[test]
    fn failed_open_clears_previous_identity_and_settings() {
        let _serial = identity_test();
        assert_eq!(
            capture_test_open_with_settings(
                &[b"noninteractive"],
                &[b"user=approvalcaller", b"uid=12345"]
            ),
            SUDO_RC_OK
        );
        assert_eq!(
            capture_test_open_with_settings(&[], &[b"user=missing-uid"]),
            SUDO_RC_ERROR
        );
        assert!(
            gather_after_captured_identity(&[b"command=/usr/bin/true"], &[b"/usr/bin/true"], &[],)
                .is_none()
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

    /// Only behavior-shaping variables cross into the approval: the loader
    /// override and the command search path are bound, while preferences
    /// and secrets stay out of the payload entirely.
    #[test]
    fn gather_context_filters_the_environment_to_policy_variables() {
        let context = gather_test_context(
            &[b"command=/usr/bin/python3"],
            &[b"/usr/bin/python3", b"app.py"],
            &[
                b"LD_PRELOAD=/tmp/evil.so",
                b"PATH=/tmp/bin:/usr/bin",
                b"HOME=/root",
                b"AWS_SECRET_ACCESS_KEY=hunter2",
            ],
        )
        .unwrap();
        let payload = String::from_utf8(context.payload).unwrap();
        assert!(payload.contains("env.LD_PRELOAD=/tmp/evil.so\n"));
        assert!(payload.contains("env.PATH=/tmp/bin:/usr/bin\n"));
        assert!(!payload.contains("HOME="));
        assert!(!payload.contains("AWS_SECRET_ACCESS_KEY="));
        assert!(!payload.contains("hunter2"));
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
