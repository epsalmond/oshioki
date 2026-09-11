//! The first production PAM boundary for contextual oshioki authentication.
//!
//! This crate deliberately owns only the PAM-to-helper boundary.  The helper
//! receives one bounded private JSON request on stdin and returns its decision
//! only through its exit status:
//!
//! * `0` authenticates successfully;
//! * `2` means device authentication is unavailable, so the surrounding PAM
//!   stack continues with its normal password path;
//! * every other status, malformed output, or security check failure is an
//!   authentication failure and never authenticates.
//!
//! A helper that cannot be started, a cancelled call, and the bounded helper
//! deadline are all reported as `PAM_AUTHINFO_UNAVAIL`: the module kills the
//! helper process group and lets the stack fall back to a password.  A timeout
//! is never a hard authentication failure.
//!
//! Cancellation includes the terminal's own `Ctrl-C`.  The helper runs in its
//! own process group, so a terminal `SIGINT` is delivered to sudo and never to
//! the helper — and sudo *blocks* `SIGINT` and `SIGQUIT` for the whole
//! authentication phase.  The PAM method is `FLAG_STANDALONE`, so
//! `verify_user` never reaches the `auth_getpass` unblock window: they stay
//! blocked for the entire PAM conversation, and a blocked signal interrupts
//! nothing and simply becomes pending.  The
//! module therefore watches its own pending set, which costs one `sigpending`
//! read per poll interval and changes nothing about sudo's signal state.  See
//! `terminal_cancel_requested`, and `pam/README.md` for the one case XNU
//! cannot record.  Any *other* interrupted syscall in the pump loop is
//! cancellation too, after re-checking whether the helper's own exit
//! (`SIGCHLD`) caused the wakeup; see `interrupt_is_cancellation`.
//!
//! The module never reads `PAM_AUTHTOK`, never prompts, never accepts module
//! arguments as a helper-path override, and never starts a nested PAM or sudo
//! operation.
//!
//! Helper stderr is bounded and consumed for this first boundary slice. The
//! helper therefore owns any future terminal progress channel; this module
//! does not yet promise approval-link or progress rendering.

#![allow(unsafe_code)]

use std::ffi::{OsString, c_char, c_int, c_void};
use std::fs;
use std::io::{self, Read};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::ptr;
use std::time::{Duration, Instant};

use serde::Serialize;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("oshioki-pam supports Linux and macOS only");

// ---------------------------------------------------------------------------
// PAM ABI
// ---------------------------------------------------------------------------

/// Opaque handle supplied by the PAM host.
#[repr(C)]
pub struct PamHandle {
    _private: [u8; 0],
}

// Keep these local so the cdylib does not need bindgen or a platform-specific
// build script.  The SDK headers were checked against these values. Linux-PAM
// and Apple's OpenPAM assign different numbers to AUTH_ERR and
// AUTHINFO_UNAVAIL.
const PAM_SUCCESS: c_int = 0;
const PAM_SERVICE_ERR: c_int = 3;
const PAM_SYSTEM_ERR: c_int = 4;

#[cfg(target_os = "linux")]
const PAM_AUTH_ERR: c_int = 7;
#[cfg(target_os = "linux")]
const PAM_AUTHINFO_UNAVAIL: c_int = 9;
#[cfg(target_os = "linux")]
const PAM_NO_MODULE_DATA: c_int = 18;

#[cfg(target_os = "macos")]
const PAM_AUTH_ERR: c_int = 9;
#[cfg(target_os = "macos")]
const PAM_AUTHINFO_UNAVAIL: c_int = 12;
#[cfg(target_os = "macos")]
const PAM_NO_MODULE_DATA: c_int = 24;

/// Linux-PAM and `OpenPAM` both assign 26 to `PAM_ABORT`.  Verified against
/// `security/_pam_types.h` on Linux-PAM; the macOS value is taken from
/// `OpenPAM`'s `security/pam_constants.h` and is **not** validated on hardware
/// (see `pam/README.md`).
const PAM_ABORT: c_int = 26;

const PAM_SERVICE: c_int = 1;
const PAM_USER: c_int = 2;
const PAM_TTY: c_int = 3;
const PAM_RUSER: c_int = 8;

#[cfg(target_os = "linux")]
#[link(name = "pam")]
unsafe extern "C" {
    fn pam_get_data(
        pamh: *const PamHandle,
        module_data_name: *const c_char,
        data: *mut *const c_void,
    ) -> c_int;
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
    fn pam_set_data(
        pamh: *mut PamHandle,
        module_data_name: *const c_char,
        data: *mut c_void,
        cleanup: Option<unsafe extern "C" fn(*mut PamHandle, *mut c_void, c_int)>,
    ) -> c_int;
}

// Apple ships both libpam.1.tbd and libpam.2.tbd in the SDK.  The module
// data APIs used here are present in libpam.2.tbd; linking that exact SDK
// name avoids assuming a nonexistent unversioned libpam.tbd.
#[cfg(target_os = "macos")]
#[link(name = "pam.2")]
unsafe extern "C" {
    fn pam_get_data(
        pamh: *const PamHandle,
        module_data_name: *const c_char,
        data: *mut *const c_void,
    ) -> c_int;
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
    fn pam_set_data(
        pamh: *mut PamHandle,
        module_data_name: *const c_char,
        data: *mut c_void,
        cleanup: Option<unsafe extern "C" fn(*mut PamHandle, *mut c_void, c_int)>,
    ) -> c_int;
}

const HELPER_PATH: &str = "/usr/local/sbin/oshioki";
/// Private protocol version for the helper request.  Version 2 replaced the
/// resolved `uid` fields of version 1 with names only: the helper runs as root
/// and resolves them inside its own bounded budget, keeping NSS out of the
/// module.
const PAM_PROTOCOL_VERSION: u8 = 2;
const HELPER_ARGS: [&str; 3] = ["authenticate", "--pam-protocol-version", "2"];
/// The helper is additionally told the number of an inherited read-only pipe
/// descriptor.  The module holds the write end, so readable/EOF on that
/// descriptor means the PAM call is gone and the helper must exit.
const HELPER_LIVENESS_FLAG: &str = "--pam-liveness-fd";
const PAM_STATE_KEY: &[u8] = b"oshioki-pam-attempt-v1\0";

const MAX_TEXT_BYTES: usize = 4096;
const MAX_USER_BYTES: usize = 256;
const MAX_SERVICE_BYTES: usize = 32;
const MAX_ARG_COUNT: usize = 64;
const MAX_ARG_BYTES: usize = 4096;
const MAX_REQUEST_BYTES: usize = 16 * 1024;
/// Slack kept free below `MAX_REQUEST_BYTES` while advisory argv is trimmed,
/// so a serialized request always lands clear of the hard cap.
const REQUEST_HEADROOM_BYTES: usize = 1024;
const MAX_HELPER_STDOUT_BYTES: usize = 16 * 1024;
const MAX_HELPER_STDERR_BYTES: usize = 8 * 1024;
const HELPER_TIMEOUT: Duration = Duration::from_secs(90);
/// Grace period for draining helper output after its leader has exited,
/// measured from the moment of exit rather than clamped to `HELPER_TIMEOUT`.
const HELPER_DRAIN_GRACE: Duration = Duration::from_millis(100);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
/// Upper bound for the post-fork descriptor scan when the kernel cannot give
/// an exact list.  Keeps a pathological `RLIMIT_NOFILE` from turning the child
/// setup into a multi-second loop.
const MAX_FD_SCAN: RawFd = 1 << 20;

// ---------------------------------------------------------------------------
// Private helper request schema
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct Identity {
    name: String,
}

#[derive(Debug, Serialize)]
struct AdvisoryArgv {
    available: bool,
    truncated: bool,
    values: Vec<String>,
}

#[derive(Debug, Serialize)]
struct HelperRequest {
    pam_protocol_version: u8,
    principal: Identity,
    invoking: Identity,
    service: String,
    tty: Option<String>,
    process_pid: u32,
    submitted_argv: AdvisoryArgv,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContextKey {
    principal_name: String,
    invoking_name: String,
    service: String,
    tty: Option<String>,
    process_pid: u32,
}

#[derive(Debug)]
struct Context {
    key: ContextKey,
    request: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttemptOutcome {
    InProgress,
    Success,
    Unavailable,
    Failure,
}

/// Per-handle bookkeeping.  `context` is `None` until the first attempt on
/// this handle records one.
#[derive(Debug)]
struct AttemptState {
    context: Option<ContextKey>,
    outcome: AttemptOutcome,
}

impl AttemptState {
    fn empty() -> Self {
        Self {
            context: None,
            outcome: AttemptOutcome::InProgress,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StateDecision {
    /// Answer from the record already on this handle; do not start a helper.
    Reuse(c_int),
    /// Start one helper attempt and record its outcome.
    Run,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelperOutcome {
    Success,
    Unavailable,
    Failure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelperPathStatus {
    Valid,
    Unavailable,
    Insecure,
}

/// The status returned for a hard fault: a refused helper path
/// (`HelperPathStatus::Insecure`), a malformed helper answer, or a repeat
/// call on a handle that already has a result.  Never a transport problem,
/// a cancellation, or a deadline — those stay `PAM_AUTHINFO_UNAVAIL`.
///
/// Linux stacks spell fail-closed with a bracket control: the installer
/// writes `auth [... default=die] liboshioki_pam.so`, so `PAM_AUTH_ERR` ends
/// the chain with a denial.  `OpenPAM` has no bracket controls, so the macOS
/// entry is `auth sufficient /usr/local/lib/pam/liboshioki_pam.dylib`, and
/// under `sufficient` a `PAM_AUTH_ERR` is merely recorded and ignored —
/// evaluation continues into `pam_opendirectory` and a password authorises
/// the command anyway.  `PAM_ABORT` is the one status `OpenPAM` honours as
/// "abort the whole chain now", so macOS returns it to reach the same
/// fail-closed outcome Linux gets from `default=die`.
///
/// This is unvalidated on Mac hardware; see `pam/README.md`.
const fn hard_failure_status() -> c_int {
    if cfg!(target_os = "macos") {
        PAM_ABORT
    } else {
        PAM_AUTH_ERR
    }
}

// ---------------------------------------------------------------------------
// PAM entry point and per-handle bookkeeping
// ---------------------------------------------------------------------------

/// Authenticate the PAM handle through the fixed oshioki helper.
///
/// The signature mirrors `pam_sm_authenticate` from Linux-PAM and Apple's
/// `security/pam_modules.h`.  PAM module arguments are intentionally ignored;
/// in particular, none can replace the production helper path.
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    let result = std::panic::catch_unwind(|| authenticate(pamh));
    result.unwrap_or(PAM_SYSTEM_ERR)
}

/// The module has no credential-establishment side effect. A no-op callback
/// keeps the standard auth-module ABI complete on hosts that call `pam_setcred`
/// after authentication.
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

/// The PAM item and module-data calls this module needs.
///
/// The live implementation forwards to libpam.  Tests implement the same trait
/// with an in-process fake, so the handle state machine can be exercised
/// without a PAM stack.
trait PamAccess {
    /// Read one PAM item as bounded UTF-8 text.
    fn item(&self, item_type: c_int) -> Result<Option<String>, c_int>;
    /// Borrow this handle's attempt record, creating an empty one on first use.
    fn state(&mut self) -> Result<&mut AttemptState, c_int>;
}

struct LivePam {
    pamh: *mut PamHandle,
}

impl PamAccess for LivePam {
    fn item(&self, item_type: c_int) -> Result<Option<String>, c_int> {
        pam_item_string(self.pamh, item_type)
    }

    fn state(&mut self) -> Result<&mut AttemptState, c_int> {
        let raw = get_or_create_state(self.pamh)?;
        // SAFETY: the pointer is either the allocation just accepted by PAM or
        // the same module-owned allocation returned by pam_get_data. PAM keeps
        // it alive until pam_end and serializes ordinary callbacks on a
        // handle, and the borrow is tied to this &mut self.
        Ok(unsafe { &mut *raw })
    }
}

fn authenticate(pamh: *mut PamHandle) -> c_int {
    if pamh.is_null() {
        return PAM_SYSTEM_ERR;
    }

    // The helper is called from sudo's privileged PAM process.  This check is
    // a context check only; it is never used to infer PAM_RUSER.
    // SAFETY: geteuid has no pointer arguments and is safe to call here.
    if unsafe { libc::geteuid() } != 0 {
        return PAM_AUTH_ERR;
    }

    let mut pam = LivePam { pamh };
    authenticate_with(&mut pam, |request| match validate_helper_path() {
        HelperPathStatus::Valid => run_helper(request),
        HelperPathStatus::Unavailable => HelperOutcome::Unavailable,
        HelperPathStatus::Insecure => HelperOutcome::Failure,
    })
}

/// The module's whole decision path, independent of libpam.
///
/// `run` is invoked at most once per call and only when this handle has no
/// usable record for the current context.
fn authenticate_with<P, R>(pam: &mut P, run: R) -> c_int
where
    P: PamAccess,
    R: FnOnce(&[u8]) -> HelperOutcome,
{
    let context = match collect_context(pam) {
        Ok(context) => context,
        Err(status) => return status,
    };

    let state = match pam.state() {
        Ok(state) => state,
        Err(status) => return status,
    };
    if let StateDecision::Reuse(status) = decide_attempt(state, &context.key) {
        return status;
    }

    let outcome = run(&context.request);

    let state = match pam.state() {
        Ok(state) => state,
        Err(status) => return status,
    };
    state.outcome = match outcome {
        HelperOutcome::Success => AttemptOutcome::Success,
        HelperOutcome::Unavailable => AttemptOutcome::Unavailable,
        HelperOutcome::Failure => AttemptOutcome::Failure,
    };

    match outcome {
        HelperOutcome::Success => PAM_SUCCESS,
        HelperOutcome::Unavailable => PAM_AUTHINFO_UNAVAIL,
        HelperOutcome::Failure => hard_failure_status(),
    }
}

/// Decide whether this call may start a helper, or must answer from the
/// record already stored on the handle.
///
/// A PAM password retry on the same handle and context must not create a
/// second device request.  A previous success is deliberately not reused as an
/// authentication result for a later call: repeated calls fail closed.  A
/// different context on the same handle (sudo re-prompting for another
/// principal, for example) is a new transaction and resets the record instead
/// of inheriting an unrelated result.
fn decide_attempt(state: &mut AttemptState, key: &ContextKey) -> StateDecision {
    if state.context.as_ref() == Some(key) {
        return StateDecision::Reuse(match state.outcome {
            AttemptOutcome::Unavailable => PAM_AUTHINFO_UNAVAIL,
            AttemptOutcome::Success | AttemptOutcome::Failure | AttemptOutcome::InProgress => {
                hard_failure_status()
            }
        });
    }
    state.context = Some(key.clone());
    state.outcome = AttemptOutcome::InProgress;
    StateDecision::Run
}

fn get_or_create_state(pamh: *mut PamHandle) -> Result<*mut AttemptState, c_int> {
    let mut existing: *const c_void = ptr::null();
    // SAFETY: pamh is checked non-null by the entry point; the key is a
    // process-lifetime NUL-terminated constant; PAM writes only the output
    // pointer. PAM owns the handle and serializes normal module callbacks.
    let status = unsafe { pam_get_data(pamh, PAM_STATE_KEY.as_ptr().cast(), &raw mut existing) };
    if !existing.is_null() {
        // SAFETY: the only value stored under PAM_STATE_KEY is a Box from
        // this function, and PAM keeps it alive until pam_end.
        return Ok(existing.cast_mut().cast::<AttemptState>());
    }
    if status != PAM_SUCCESS && status != PAM_NO_MODULE_DATA {
        return Err(PAM_SYSTEM_ERR);
    }

    let raw = Box::into_raw(Box::new(AttemptState::empty()));
    // SAFETY: raw is a Box allocation transferred to PAM; cleanup_state is an
    // ABI-compatible callback that reconstructs that exact Box.
    let set_status = unsafe {
        pam_set_data(
            pamh,
            PAM_STATE_KEY.as_ptr().cast(),
            raw.cast(),
            Some(cleanup_state),
        )
    };
    if set_status != PAM_SUCCESS {
        // SAFETY: pam_set_data did not accept ownership on failure.
        unsafe { drop(Box::from_raw(raw)) };
        return Err(PAM_SYSTEM_ERR);
    }

    // SAFETY: PAM accepted raw and will retain it until cleanup_state. The
    // pointer is valid for the lifetime of the PAM handle.
    Ok(raw)
}

unsafe extern "C" fn cleanup_state(_pamh: *mut PamHandle, data: *mut c_void, _status: c_int) {
    if !data.is_null() {
        // SAFETY: data was created by Box::into_raw for AttemptState above and
        // PAM invokes this callback at most once for that stored pointer.
        unsafe { drop(Box::from_raw(data.cast::<AttemptState>())) };
    }
}

// ---------------------------------------------------------------------------
// Trusted context capture
// ---------------------------------------------------------------------------

fn collect_context<P: PamAccess>(pam: &P) -> Result<Context, c_int> {
    let service = pam.item(PAM_SERVICE)?.ok_or(PAM_SERVICE_ERR)?;
    if !is_supported_service(&service) {
        return Err(PAM_SERVICE_ERR);
    }
    validate_text(&service, MAX_SERVICE_BYTES).map_err(|()| PAM_AUTH_ERR)?;

    // Only the names are captured.  Resolving them through NSS can block for
    // an unbounded time on a stalled directory service, and that work would
    // sit outside the helper deadline, so the root helper resolves them inside
    // its own budget instead.
    let principal_name = bounded_identity(pam.item(PAM_USER)?)?;
    // PAM_RUSER is intentionally the sole source of invoking identity.  Do
    // not substitute an environment variable, PAM_USER, or getuid(): sudo can
    // normalize the process real UID independently of the invoking identity.
    let invoking_name = bounded_identity(pam.item(PAM_RUSER)?)?;

    let tty = pam.item(PAM_TTY)?.filter(|value| !value.is_empty());
    if let Some(tty) = &tty {
        validate_text(tty, MAX_TEXT_BYTES).map_err(|()| PAM_AUTH_ERR)?;
    }

    // SAFETY: getpid has no pointer arguments and is safe to call here.
    let process_pid = unsafe { libc::getpid() };
    let process_pid = u32::try_from(process_pid).map_err(|_| PAM_AUTH_ERR)?;
    let submitted_argv = capture_submitted_argv(std::env::args_os());

    let key = ContextKey {
        principal_name: principal_name.clone(),
        invoking_name: invoking_name.clone(),
        service: service.clone(),
        tty: tty.clone(),
        process_pid,
    };
    let mut request = HelperRequest {
        pam_protocol_version: PAM_PROTOCOL_VERSION,
        principal: Identity {
            name: principal_name,
        },
        invoking: Identity {
            name: invoking_name,
        },
        service,
        tty,
        process_pid,
        submitted_argv,
    };
    let request = serialize_request(&mut request).map_err(|()| PAM_AUTH_ERR)?;

    Ok(Context { key, request })
}

fn bounded_identity(value: Option<String>) -> Result<String, c_int> {
    let value = value.ok_or(PAM_AUTHINFO_UNAVAIL)?;
    validate_text(&value, MAX_USER_BYTES).map_err(|()| PAM_AUTH_ERR)?;
    Ok(value)
}

/// Serialize the request, trimming advisory argv until it fits.
///
/// JSON escaping can expand a legitimate Unix argument by about six times (a
/// control byte becomes a six-byte `\u00xx` escape), so the raw argv
/// allowance cannot bound the serialized request on its own.  Advisory
/// context is the only optional part of the request, so it is measured after
/// serialization and dropped from the end until the request clears the cap
/// with headroom.  Authentication must never fail solely because the process
/// argument vector was large.
fn serialize_request(request: &mut HelperRequest) -> Result<Vec<u8>, ()> {
    loop {
        let bytes = serde_json::to_vec(&*request).map_err(|_| ())?;
        if bytes.len().saturating_add(REQUEST_HEADROOM_BYTES) <= MAX_REQUEST_BYTES {
            return Ok(bytes);
        }
        if request.submitted_argv.values.pop().is_none() {
            // Nothing advisory is left: the mandatory fields alone exceed the
            // cap, which the per-item bounds above should already prevent.
            return Err(());
        }
        // `available` stays as captured: the argv was readable, it simply did
        // not fit.
        request.submitted_argv.truncated = true;
    }
}

fn pam_item_string(pamh: *mut PamHandle, item_type: c_int) -> Result<Option<String>, c_int> {
    let mut item: *const c_void = ptr::null();
    // SAFETY: pamh is a live PAM handle, item is a valid output slot, and the
    // item type is one of the XSSO PAM item constants above.
    let status = unsafe { pam_get_item(pamh, item_type, &raw mut item) };
    if status != PAM_SUCCESS {
        return Err(PAM_SYSTEM_ERR);
    }
    if item.is_null() {
        return Ok(None);
    }

    let mut bytes = Vec::new();
    for index in 0..MAX_TEXT_BYTES {
        // SAFETY: PAM item strings are NUL-terminated and owned by PAM for
        // the duration of the callback. The bounded scan prevents malformed
        // module input from causing an unbounded read.
        let byte = unsafe { *(item.cast::<u8>().add(index)) };
        if byte == 0 {
            break;
        }
        bytes.push(byte);
        if index + 1 == MAX_TEXT_BYTES {
            return Err(PAM_AUTH_ERR);
        }
    }
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| PAM_AUTH_ERR)?
        .to_owned();
    Ok(Some(value))
}

fn validate_text(value: &str, max_bytes: usize) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return Err(());
    }
    Ok(())
}

fn is_supported_service(service: &str) -> bool {
    matches!(service, "sudo" | "sudo-i")
}

fn capture_submitted_argv<I>(args: I) -> AdvisoryArgv
where
    I: IntoIterator<Item = OsString>,
{
    let mut values = Vec::new();
    let mut bytes = 0usize;
    let mut truncated = false;

    for arg in args {
        let raw = arg.as_os_str().as_bytes();
        let Ok(value) = std::str::from_utf8(raw) else {
            return AdvisoryArgv {
                available: false,
                truncated: false,
                values: Vec::new(),
            };
        };
        if values.len() >= MAX_ARG_COUNT
            || value.len() > MAX_TEXT_BYTES
            || bytes.saturating_add(value.len()) > MAX_ARG_BYTES
        {
            truncated = true;
            break;
        }
        bytes = bytes.saturating_add(value.len());
        values.push(value.to_owned());
    }

    AdvisoryArgv {
        available: !values.is_empty(),
        truncated,
        values,
    }
}

// ---------------------------------------------------------------------------
// Fixed helper validation and execution
// ---------------------------------------------------------------------------

/// Stat the fixed helper path and each parent directory.
///
/// These are local filesystem lookups on a fixed path and run before the
/// helper deadline exists, so they are deliberately outside it.  They touch no
/// network or directory service.
fn validate_helper_path() -> HelperPathStatus {
    let path = Path::new(HELPER_PATH);
    if secure_metadata(Path::new("/"), true).is_err() {
        return HelperPathStatus::Insecure;
    }
    let mut component = Path::new("/").to_path_buf();
    for name in ["usr", "local", "sbin"] {
        component.push(name);
        match secure_metadata(&component, true) {
            Ok(()) => {}
            Err(HelperPathStatus::Unavailable) => return HelperPathStatus::Unavailable,
            Err(HelperPathStatus::Insecure) => return HelperPathStatus::Insecure,
            Err(HelperPathStatus::Valid) => unreachable!(),
        }
    }
    match secure_metadata(path, false) {
        Ok(()) => HelperPathStatus::Valid,
        Err(status) => status,
    }
}

fn secure_metadata(path: &Path, directory: bool) -> Result<(), HelperPathStatus> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(HelperPathStatus::Unavailable);
        }
        Err(_) => return Err(HelperPathStatus::Insecure),
    };
    check_metadata(
        metadata.uid(),
        metadata.mode(),
        metadata.file_type().is_dir(),
        metadata.file_type().is_file(),
        directory,
    )
}

/// The ownership and permission rule for one path component, split out from
/// the stat so every combination can be tested without needing root.
fn check_metadata(
    uid: u32,
    mode: u32,
    is_directory: bool,
    is_regular_file: bool,
    directory_expected: bool,
) -> Result<(), HelperPathStatus> {
    // Root may update the helper, but an unprivileged group or user must not
    // be able to replace or modify any path component.
    if uid != 0 || mode & 0o022 != 0 {
        return Err(HelperPathStatus::Insecure);
    }
    if directory_expected {
        if !is_directory {
            return Err(HelperPathStatus::Insecure);
        }
    } else if !is_regular_file || mode & 0o111 == 0 || mode & 0o6000 != 0 {
        // A setuid or setgid helper would also break cancellation: Linux
        // clears PR_SET_PDEATHSIG across a credential-changing execve, so the
        // parent-death half of the contract would silently stop working.
        return Err(HelperPathStatus::Insecure);
    }
    Ok(())
}

struct ChildGuard {
    child: Child,
    /// Write end of the liveness pipe.  Dropping it, including when the whole
    /// sudo process dies without running destructors, is the helper's signal
    /// that the PAM call is gone.
    liveness_write: Option<OwnedFd>,
    leader_reaped: bool,
    finished: bool,
}

impl ChildGuard {
    fn new(child: Child, liveness_write: OwnedFd) -> Self {
        Self {
            child,
            liveness_write: Some(liveness_write),
            leader_reaped: false,
            finished: false,
        }
    }

    /// Has the leader exited?
    ///
    /// `WNOWAIT` deliberately leaves the zombie in place. While the leader is
    /// unreaped the kernel keeps its PID, and therefore the helper's process
    /// group ID, reserved; that is the only window in which `kill(-pgid)` is
    /// guaranteed to reach the helper tree and nothing else.
    ///
    /// Only `WEXITED` is requested, so a leader that has been *stopped*
    /// (`SIGSTOP`, `SIGTSTP`) is reported as still running: the module keeps
    /// waiting and the helper deadline eventually classifies it as
    /// unavailable and kills the group, which is the right answer — a
    /// suspended helper has not authenticated anything.
    ///
    /// `EINTR` is returned to the caller rather than reported as "not
    /// exited". `waitid` with `WNOHANG` does not block, so an interrupted one
    /// means a signal arrived, and the pump loop owns that classification;
    /// answering `false` here would swallow exactly the keystroke this module
    /// promises never to swallow.
    fn leader_exited(&self) -> io::Result<bool> {
        debug_assert!(
            !self.leader_reaped,
            "leader_exited must not run after the leader was reaped"
        );
        // Child::id() is already the unsigned id_t waitid expects.
        let pid = self.child.id();
        let mut info = MaybeUninit::<libc::siginfo_t>::zeroed();
        // SAFETY: waitid writes only into the zeroed siginfo value. The PID is
        // this guard's own child and has not been reaped.
        let status = unsafe {
            libc::waitid(
                libc::P_PID,
                pid,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
            )
        };
        if status == -1 {
            // Interrupted waits are reported, not retried; see above.
            return Err(io::Error::last_os_error());
        }
        // SAFETY: waitid either filled the value or left the zeroed bytes,
        // which POSIX defines as "no state change" for WNOHANG.
        let info = unsafe { info.assume_init() };
        Ok(siginfo_pid(&info) != 0)
    }

    /// Kill the whole helper process group.
    ///
    /// Only valid while the leader is unreaped: once the leader is reaped its
    /// PID, and so its process-group ID, can be recycled, and the signal would
    /// land on an unrelated group. Every caller is on a path that has not
    /// reaped yet, and the assertion below keeps it that way.
    fn kill_group(&self) {
        debug_assert!(
            !self.leader_reaped,
            "kill_group after reaping can target a recycled process group"
        );
        if self.leader_reaped {
            return;
        }
        let pid = self.child.id() as libc::pid_t;
        // SAFETY: setpgid(0, 0) in the child makes its PID the process-group
        // ID. A negative PID targets only that helper group, including any
        // descendants that did not change group themselves.
        unsafe {
            let _ = libc::kill(-pid, libc::SIGKILL);
        }
    }

    /// Reap the leader and return its status.
    ///
    /// After this the process group must not be signalled again, so the flag
    /// is set even when `wait` fails: once `wait` has been attempted the
    /// zombie may be gone either way.
    fn reap(&mut self) -> io::Result<ExitStatus> {
        let status = self.child.wait();
        self.leader_reaped = true;
        status
    }

    fn abort(&mut self) {
        if self.finished {
            return;
        }
        // Cooperative cancellation first: descendants that left the process
        // group still observe the closed liveness pipe.
        self.liveness_write.take();
        if !self.leader_reaped {
            // The leader is still running or still a zombie, so the group ID
            // is ours and the group kill is safe.
            self.kill_group();
            let pid = self.child.id() as libc::pid_t;
            // SAFETY: the child PID is the process started by Command and is
            // still owned by this guard because it has not been reaped.
            unsafe {
                let _ = libc::kill(pid, libc::SIGKILL);
            }
            let _ = self.reap();
        }
        self.finished = true;
    }
}

/// The sending PID recorded in a `siginfo_t`. Linux exposes it through an
/// accessor over a union; macOS has a plain field.
#[cfg(target_os = "linux")]
fn siginfo_pid(info: &libc::siginfo_t) -> libc::pid_t {
    // SAFETY: si_pid is initialized for the SIGCHLD-shaped siginfo that
    // waitid fills, and zeroed otherwise.
    unsafe { info.si_pid() }
}

#[cfg(target_os = "macos")]
fn siginfo_pid(info: &libc::siginfo_t) -> libc::pid_t {
    info.si_pid
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.abort();
    }
}

fn run_helper(request: &[u8]) -> HelperOutcome {
    run_helper_at(HELPER_PATH, request, HELPER_TIMEOUT)
}

fn run_helper_at(path: &str, request: &[u8], timeout: Duration) -> HelperOutcome {
    if request.len() > MAX_REQUEST_BYTES {
        return HelperOutcome::Failure;
    }
    spawn_and_pump_helper(path, request, timeout)
}

/// Create the liveness pipe.  Both ends are close-on-exec in the parent; the
/// child clears the flag on the read end only, after its descriptor sweep.
fn liveness_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1 as c_int; 2];
    // SAFETY: fds is a writable two-element array, the only output of the call.
    #[cfg(target_os = "linux")]
    let created = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    // SAFETY: same; macOS has no pipe2, so CLOEXEC is set immediately below.
    #[cfg(target_os = "macos")]
    let created = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if created != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors were just created by the kernel and are not
    // owned anywhere else.
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    // SAFETY: as above.
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    #[cfg(target_os = "macos")]
    {
        set_cloexec(read.as_raw_fd())?;
        set_cloexec(write.as_raw_fd())?;
    }
    Ok((read, write))
}

#[cfg(target_os = "macos")]
fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl operates on a descriptor owned by the caller.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: same descriptor, with the flags returned by F_GETFD.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Spawn the helper and pump its pipes until it exits or the deadline passes.
///
/// The caller is responsible for the request size bound; the timeout starts
/// here, so everything that can block on the helper is inside it.
#[allow(clippy::too_many_lines)]
fn spawn_and_pump_helper(path: &str, request: &[u8], timeout: Duration) -> HelperOutcome {
    let deadline = Instant::now() + timeout;
    let Ok((liveness_read, liveness_write)) = liveness_pipe() else {
        return HelperOutcome::Failure;
    };
    let liveness_fd = liveness_read.as_raw_fd();
    // SAFETY: getpid has no pointer arguments.
    let parent_pid = unsafe { libc::getpid() };

    let mut command = Command::new(path);
    command
        .args(HELPER_ARGS)
        .arg(HELPER_LIVENESS_FLAG)
        .arg(liveness_fd.to_string())
        .current_dir("/")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // `pre_exec` runs in the forked child after stdio has been installed and
    // before exec, so it needs no pre-spawn descriptor snapshot and cannot
    // miss a descriptor opened concurrently with the spawn.
    let child_setup = move || -> io::Result<()> {
        // Own process group, deliberately NOT a new session.  setsid()
        // would detach the helper from sudo's controlling terminal, so it
        // would never see SIGHUP on hangup and could not use the terminal
        // for future progress output.  A separate process group is what
        // lets the parent kill(-pgid) the whole helper tree, including
        // grandchildren the module never learned about, on both Linux and
        // macOS.
        //
        // The cost is that a terminal SIGINT goes to sudo's foreground
        // group and never reaches the helper, so Ctrl-C cannot cancel by
        // killing the helper directly.  terminal_cancel_requested closes
        // that gap in the parent instead.  Leaving the helper in sudo's foreground
        // group would not have delivered SIGINT for free anyway: sudo
        // *blocks* it for the whole authentication phase, and the blocked
        // mask survives both fork and execve whatever the disposition is,
        // so the helper would inherit the same deafness unless it reset
        // the mask itself.  (Dispositions are the weaker half of that: a
        // caught handler resets to SIG_DFL across execve, and only SIG_IGN
        // survives it.)  It would also give up the
        // guaranteed group kill above, hand the helper every other
        // terminal signal (SIGTSTP would suspend it mid-authentication),
        // turn cancellation into a signal-killed helper (a hard
        // PAM_AUTH_ERR under the existing exit rules), and still depend
        // on the helper choosing to die.
        // SAFETY: setpgid with both arguments zero only affects this child.
        if unsafe { libc::setpgid(0, 0) } == -1 {
            return Err(io::Error::last_os_error());
        }
        #[cfg(target_os = "linux")]
        {
            // If the PAM thread that forked us dies, so does the helper
            // leader, even when sudo is killed and no Rust destructor
            // runs.
            // SAFETY: PR_SET_PDEATHSIG takes one integer argument.
            if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } == -1 {
                return Err(io::Error::last_os_error());
            }
            // Close the race where the parent died between fork and
            // prctl, in which case the signal was already missed. The check is
            // process-scoped while PR_SET_PDEATHSIG is thread-scoped, which is
            // sufficient here: the supervising thread owns the helper
            // synchronously for its whole life, so it cannot exit before the
            // process without this call already having returned.
            // SAFETY: getppid has no pointer arguments.
            if unsafe { libc::getppid() } != parent_pid {
                // SAFETY: _exit performs no cleanup in the forked child.
                unsafe { libc::_exit(127) };
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            // macOS has no PR_SET_PDEATHSIG. The liveness pipe below is
            // the portable channel: its write end is held only by this
            // PAM call, so the helper sees EOF when the call or the whole
            // sudo process goes away. kqueue EVFILT_PROC would need a
            // second watching process to be useful and is not worth the
            // extra moving part here.
            let _ = parent_pid;
        }
        cloexec_unrelated_fds(liveness_fd)
    };
    // SAFETY: child_setup calls only async-signal-safe libc functions,
    // allocates nothing, and captures two integers by copy.
    unsafe {
        command.pre_exec(child_setup);
    }

    // Every spawn failure is unavailability, not a denial. The helper path's
    // security is decided separately by validate_helper_path; a transient
    // ETXTBSY during a package upgrade, an EACCES, EAGAIN or ENOMEM must fall
    // back to the password path instead of locking the operator out of sudo.
    let Ok(child) = command.spawn() else {
        return HelperOutcome::Unavailable;
    };
    // Only the child keeps the read end; otherwise EOF would never arrive.
    drop(liveness_read);
    let mut guard = ChildGuard::new(child, liveness_write);

    let Some(stdin) = guard.child.stdin.take() else {
        guard.abort();
        return HelperOutcome::Failure;
    };
    let Some(mut stdout) = guard.child.stdout.take() else {
        guard.abort();
        return HelperOutcome::Failure;
    };
    let Some(mut stderr) = guard.child.stderr.take() else {
        guard.abort();
        return HelperOutcome::Failure;
    };
    if set_nonblocking(stdin.as_raw_fd()).is_err()
        || set_nonblocking(stdout.as_raw_fd()).is_err()
        || set_nonblocking(stderr.as_raw_fd()).is_err()
    {
        guard.abort();
        return HelperOutcome::Failure;
    }
    // A helper that closes stdin before consuming its request causes a pipe
    // write to raise SIGPIPE. Block it only on this PAM-calling thread and
    // consume a signal generated by this invocation before restoring the
    // caller's mask; sudo's process-wide signal handlers remain untouched.
    let Ok(mut sigpipe) = SigpipeGuard::block() else {
        guard.abort();
        return HelperOutcome::Failure;
    };

    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut stdout_open = true;
    let mut stderr_open = true;
    let mut request_offset = 0usize;
    let mut stdin = Some(stdin);

    loop {
        // The operator pressed Ctrl-C (or Ctrl-\). sudo blocks the signal
        // here, so it lands in the pending set instead of interrupting
        // anything; this names the interrupt rather than inferring one from a
        // wakeup. Checked first, so cancellation beats every other reason to
        // leave the loop; POLL_INTERVAL bounds how long that takes.
        if terminal_cancel_requested() {
            guard.abort();
            return HelperOutcome::Unavailable;
        }
        if Instant::now() >= deadline {
            // Kill the group now rather than at scope exit, so the helper
            // tree is gone before this call returns to the PAM stack.
            guard.abort();
            return HelperOutcome::Unavailable;
        }

        if let Some(input) = stdin.as_ref()
            && request_offset < request.len()
        {
            match write_available(input.as_raw_fd(), request, &mut request_offset) {
                Ok(()) => {}
                // A signal landed in the request write.  The bytes written so
                // far are recorded in `request_offset`, so the only question
                // is whether this was cancellation.
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    if interrupt_is_cancellation(&guard) {
                        guard.abort();
                        return HelperOutcome::Unavailable;
                    }
                }
                Err(error) => {
                    if error.raw_os_error() == Some(libc::EPIPE) {
                        sigpipe.mark_generated();
                    }
                    guard.abort();
                    return HelperOutcome::Failure;
                }
            }
        }
        if request_offset == request.len() {
            // Closing stdin is the request framing terminator. It also
            // prevents a helper that reads until EOF from waiting forever.
            stdin.take();
        }

        let exited = match guard.leader_exited() {
            Ok(exited) => exited,
            // The wait itself was interrupted, so the loop has no answer about
            // the leader and a signal has arrived. `interrupt_is_cancellation`
            // re-asks; it can only answer `false` by observing `Ok(true)`, so
            // that branch means the leader really has exited and the exit
            // handling below is correct. A second `EINTR` from a syscall that
            // cannot block is cancellation rather than an endless retry.
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                if interrupt_is_cancellation(&guard) {
                    guard.abort();
                    return HelperOutcome::Unavailable;
                }
                true
            }
            Err(_) => {
                guard.abort();
                return HelperOutcome::Failure;
            }
        };
        if exited {
            // The leader is an unreaped zombie, so it still holds the process
            // group ID: kill the tree now, before reaping makes the ID
            // recyclable. Descendants cannot keep a pipe open past this point.
            guard.kill_group();
            let Ok(status) = guard.reap() else {
                guard.abort();
                return HelperOutcome::Failure;
            };
            let input_complete = request_offset == request.len();
            stdin.take();
            return finish_helper(
                &mut guard,
                status,
                &mut stdout,
                &mut stdout_bytes,
                &mut stdout_open,
                &mut stderr,
                &mut stderr_bytes,
                &mut stderr_open,
                input_complete,
            );
        }

        let reads = [
            read_available(
                &mut stdout,
                &mut stdout_bytes,
                MAX_HELPER_STDOUT_BYTES,
                &mut stdout_open,
            ),
            read_available(
                &mut stderr,
                &mut stderr_bytes,
                MAX_HELPER_STDERR_BYTES,
                &mut stderr_open,
            ),
        ];
        let mut read_interrupted = false;
        for read in reads {
            match read {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => read_interrupted = true,
                Err(_) => {
                    guard.abort();
                    return HelperOutcome::Failure;
                }
            }
        }
        if read_interrupted && interrupt_is_cancellation(&guard) {
            guard.abort();
            return HelperOutcome::Unavailable;
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        // This is where the module spends essentially all of its waiting time,
        // so it is where a terminal interrupt almost always lands.  An
        // interrupted poll is cancellation unless the helper's own exit caused
        // it.  Any other poll error means the module can no longer supervise
        // the helper, so the group is killed immediately and the call falls
        // back to a password.
        match poll_fds(
            stdin.as_ref().map(AsRawFd::as_raw_fd),
            &stdout,
            stdout_open,
            &stderr,
            stderr_open,
            remaining.min(POLL_INTERVAL),
        ) {
            Ok(PollWake::Ready) => {}
            Ok(PollWake::Interrupted) => {
                if interrupt_is_cancellation(&guard) {
                    guard.abort();
                    return HelperOutcome::Unavailable;
                }
            }
            Err(_) => {
                guard.abort();
                return HelperOutcome::Unavailable;
            }
        }
    }
}

/// What an interrupted syscall in the pump loop means for the helper.
///
/// `terminal_cancel_requested` is the precise channel for `Ctrl-C`; this is
/// the backstop for every *other* signal that can interrupt the loop.  The module cannot
/// ask which one was delivered: `sigpending` reports only *blocked* signals,
/// and the rest are consumed by sudo's own handlers.  All it knows is that a
/// syscall returned `EINTR`, which during PAM means sudo caught something
/// without `SA_RESTART`.
///
/// One benign interrupt *is* identifiable: `SIGCHLD` raised by the helper's
/// own exit, which sudo does catch in this phase.  Re-checking the leader here
/// excludes it, and the loop then carries on to read the exit status normally.
/// `waitid` is re-run rather than trusting the check earlier in the iteration,
/// because the exit can have happened in between.  This answers `false` only
/// for `Ok(true)`, so callers may read a `false` as "the leader has exited";
/// a `waitid` that is itself interrupted answers `true` (cancel) rather than
/// looping.
///
/// Anything else is treated as cancellation.  Measured on a stock Ubuntu sudo
/// (`SigCgt: ...16a07`), the signals it catches during authentication and
/// leaves unblocked are `SIGHUP`, `SIGUSR1`, `SIGUSR2`, `SIGALRM`, `SIGTERM`
/// and `SIGCHLD`; all but `SIGCHLD`, which is handled above, mean this sudo is
/// going away or timing out, and none of them is a reason to keep holding the
/// terminal on a device prompt.  `SIGINT` and `SIGQUIT` are caught too but
/// blocked, so they arrive through the pending-set rule rather than as
/// `EINTR`.  `SIGTSTP` is *not* in the caught set: `verify_user` sets it back
/// to `SIG_DFL` for the authentication phase (neither measured mask has bit
/// 19), so `Ctrl-Z` stops sudo — and this thread with it — the way it stops
/// any other process, and is never seen here as an interrupted syscall.
/// `SIGWINCH` is not among them either — it is left at its default and never
/// interrupts anything — so a terminal resize cannot cancel.  Being wrong in
/// this direction costs one password prompt, never a success and never a hard
/// failure.
///
/// A `waitid` that fails outright is cancellation too: a module that can no
/// longer supervise its helper must not keep holding the terminal.
fn interrupt_is_cancellation(guard: &ChildGuard) -> bool {
    !matches!(guard.leader_exited(), Ok(true))
}

/// Drain the pipes of a helper whose leader has already been killed off and
/// reaped by the caller, and classify its status.
///
/// The caller kills the process group while the leader is still an unreaped
/// zombie, so by the time this runs no descendant should be holding a pipe.
/// Nothing here may signal the group again: the leader is reaped and its
/// group ID can be recycled.
#[allow(clippy::too_many_arguments)]
fn finish_helper(
    guard: &mut ChildGuard,
    status: ExitStatus,
    stdout: &mut ChildStdout,
    stdout_bytes: &mut Vec<u8>,
    stdout_open: &mut bool,
    stderr: &mut ChildStderr,
    stderr_bytes: &mut Vec<u8>,
    stderr_open: &mut bool,
    input_complete: bool,
) -> HelperOutcome {
    // Drain bytes already available without allowing a child-held pipe to
    // defeat the total helper budget. This grace period is measured from now
    // rather than clamped to the helper deadline: a helper that exits
    // successfully in the last millisecond of its budget must still get its
    // output read, or a valid success would be reported as a failure.
    let drain_deadline = Instant::now() + HELPER_DRAIN_GRACE;
    while (*stdout_open || *stderr_open) && Instant::now() < drain_deadline {
        let reads = [
            read_available(stdout, stdout_bytes, MAX_HELPER_STDOUT_BYTES, stdout_open),
            read_available(stderr, stderr_bytes, MAX_HELPER_STDERR_BYTES, stderr_open),
        ];
        for read in reads {
            match read {
                Ok(()) => {}
                // Interrupted reads are retried here, not reported. The pump
                // loop reports them because a signal there may be the
                // operator cancelling; by this point the leader is reaped and
                // the outcome is already decided, so the only thing an EINTR
                // could do is turn a helper that already succeeded into a hard
                // authentication failure. The surrounding loop retries within
                // the drain grace, so it cannot spin unbounded: a signal
                // storm keeps it hot for at most the drain grace.
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return HelperOutcome::Failure,
            }
        }
        if (*stdout_open || *stderr_open)
            && poll_fds(
                None,
                stdout,
                *stdout_open,
                stderr,
                *stderr_open,
                Duration::from_millis(10),
            )
            .is_err()
        {
            return HelperOutcome::Failure;
        }
    }
    if !input_complete || *stdout_open || *stderr_open {
        return HelperOutcome::Failure;
    }
    guard.finished = true;
    classify_helper_result(status, stdout_bytes)
}

fn classify_helper_result(status: ExitStatus, stdout: &[u8]) -> HelperOutcome {
    // The helper protocol has no stdout response body. Whitespace is harmless
    // for diagnostics, but any other output is malformed and cannot approve.
    if stdout.iter().any(|byte| !byte.is_ascii_whitespace()) {
        return HelperOutcome::Failure;
    }
    match status.code() {
        Some(0) => HelperOutcome::Success,
        Some(2) => HelperOutcome::Unavailable,
        Some(_) | None => HelperOutcome::Failure,
    }
}

fn read_available<R: Read>(
    file: &mut R,
    output: &mut Vec<u8>,
    limit: usize,
    open: &mut bool,
) -> io::Result<()> {
    if !*open {
        return Ok(());
    }
    let mut buffer = [0u8; 4096];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => {
                *open = false;
                return Ok(());
            }
            Ok(read) => {
                if output.len().saturating_add(read) > limit {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "helper output bound",
                    ));
                }
                output.extend_from_slice(&buffer[..read]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            // Reported, not retried.  These descriptors are non-blocking, so
            // an interrupted read is rare, but swallowing it here would hide
            // a signal the pump loop has to classify. Bytes already appended
            // to `output` are kept.  The post-exit drain in `finish_helper`
            // retries instead: see the comment there for why the two callers
            // must differ.
            Err(error) if error.kind() == io::ErrorKind::Interrupted => return Err(error),
            Err(error) => return Err(error),
        }
    }
}

/// How a `poll` wait ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PollWake {
    /// The timeout expired or a descriptor became ready.
    Ready,
    /// A signal was delivered to this thread. The caller classifies it; see
    /// `interrupt_is_cancellation`.
    Interrupted,
}

/// Wait for helper pipe activity.
///
/// `EINTR` is reported distinctly rather than as an error or a plain wakeup:
/// during PAM, sudo catches signals without `SA_RESTART`, so an interrupted
/// `poll` is the module's only evidence that the operator (or the terminal)
/// signalled sudo while the helper was being waited on. Every other `poll`
/// failure is returned to the caller as an error.
fn poll_fds<O: AsRawFd, E: AsRawFd>(
    stdin_fd: Option<RawFd>,
    stdout: &O,
    stdout_open: bool,
    stderr: &E,
    stderr_open: bool,
    timeout: Duration,
) -> io::Result<PollWake> {
    let mut fds = [
        libc::pollfd {
            fd: -1,
            events: 0,
            revents: 0,
        },
        libc::pollfd {
            fd: -1,
            events: 0,
            revents: 0,
        },
        libc::pollfd {
            fd: -1,
            events: 0,
            revents: 0,
        },
    ];
    let mut nfds = 0usize;
    if let Some(fd) = stdin_fd {
        fds[nfds] = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        nfds += 1;
    }
    if stdout_open {
        fds[nfds] = libc::pollfd {
            fd: stdout.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        nfds += 1;
    }
    if stderr_open {
        fds[nfds] = libc::pollfd {
            fd: stderr.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        nfds += 1;
    }
    let millis = c_int::try_from(timeout.as_millis().min(c_int::MAX as u128)).unwrap_or(c_int::MAX);
    // SAFETY: fds points to zero to three initialized pollfd values; the
    // timeout is finite and bounded.
    let nfds = libc::nfds_t::try_from(nfds).unwrap_or(0);
    let ready = unsafe { libc::poll(fds.as_mut_ptr(), nfds, millis) };
    if ready == -1 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINTR) {
            return Ok(PollWake::Interrupted);
        }
        return Err(error);
    }
    Ok(PollWake::Ready)
}

fn write_available(fd: RawFd, request: &[u8], offset: &mut usize) -> io::Result<()> {
    while *offset < request.len() {
        let remaining = &request[*offset..];
        // SAFETY: remaining points to immutable bytes owned by the caller for
        // the duration of this nonblocking write.
        let written = unsafe { libc::write(fd, remaining.as_ptr().cast(), remaining.len()) };
        if written > 0 {
            let written = usize::try_from(written)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative helper write"))?;
            *offset = (*offset).saturating_add(written);
            continue;
        }
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "helper stdin closed",
            ));
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            // Reported to the caller instead of retried, for the reason given
            // on `read_available`: the pump loop owns signal classification.
            Some(code) if code == libc::EINTR => return Err(error),
            Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK => return Ok(()),
            _ => return Err(error),
        }
    }
    Ok(())
}

fn set_nonblocking(fd: c_int) -> io::Result<()> {
    // SAFETY: fcntl operates on the caller-owned pipe descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: same descriptor, with the flags returned by F_GETFL.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Signals the terminal uses to cancel. `SIGINT` is `Ctrl-C`; `SIGQUIT` is
/// `Ctrl-\`.
const CANCEL_SIGNALS: [c_int; 2] = [libc::SIGINT, libc::SIGQUIT];

/// Has the terminal asked to cancel this authentication?
///
/// The mechanism is `sigpending`, and the reason is what sudo actually does in
/// its authentication phase, which was measured rather than assumed. sudo's
/// `verify_user()` blocks `SIGINT` and `SIGQUIT` for the whole phase and
/// unblocks them only inside `auth_getpass()`, around its own password prompt
/// — which is why a stock stack ends at `Ctrl-C` but this module's wait did
/// not. The code has no platform conditionals, so this holds on Linux and
/// macOS alike. Two consequences follow, and together they decide the design:
///
/// * **`EINTR` never happens.** A blocked signal interrupts nothing, so a rule
///   that only watched for interrupted syscalls would see nothing at all while
///   the operator typed `Ctrl-C`. That is the defect this replaces.
/// * **`sigpending` sees it.** A terminal sudo *catches* both signals
///   (`init_signals` installs `sudo_handler`; measured on sudo 1.9.15p5 as
///   `SigCgt: ...16a07`), and a blocked signal with a catching disposition is
///   left pending by Linux and XNU alike, so a typed `Ctrl-C` sits in the
///   pending set for exactly as long as sudo holds it blocked — the whole of
///   this wait. sudo's own `user_interrupted()` is this same read.
///
/// One case is invisible on macOS and only on macOS: a sudo that *inherited*
/// `SIG_IGN` for `SIGINT`, which `init_signals` deliberately does not
/// overwrite. Linux keeps such a signal pending anyway; XNU discards it at
/// generation. That is a sudo started as a shell's background job, with no
/// interactive `Ctrl-C` to miss, and sudo's own `user_interrupted()` is
/// equally blind there. See `pam/README.md`.
///
/// `sigpending` is a read. Nothing is installed, nothing is consumed, and
/// nothing about sudo's own signal state changes: the signal is still pending
/// when the module returns, and sudo applies its own disposition to it on
/// unblock exactly as it would have. A module loaded into someone else's
/// process should not be installing handlers or swallowing signals, and this
/// does neither.
///
/// **Any** pending `SIGINT` or `SIGQUIT` cancels, including one that was
/// already pending when the wait began. There is deliberately no baseline
/// sample to subtract: standard signals do not queue, so a second `Ctrl-C`
/// merges into a bit that is already set and nothing ever *transitions*.
/// Ignoring a pre-existing pending signal would therefore make every later
/// keystroke invisible for the whole 90-second budget — the original defect,
/// reintroduced through the back door. Cancelling on a signal someone else
/// left pending costs one password prompt, which is exactly the error budget
/// this module already declares for unavailability; missing a real `Ctrl-C`
/// costs the operator their terminal.
fn terminal_cancel_requested() -> bool {
    let mut pending = MaybeUninit::<libc::sigset_t>::zeroed();
    // SAFETY: sigpending writes only into the zeroed set.
    if unsafe { libc::sigpending(pending.as_mut_ptr()) } != 0 {
        return false;
    }
    // SAFETY: the call above succeeded and filled the set.
    let pending = unsafe { pending.assume_init() };
    CANCEL_SIGNALS.into_iter().any(|signal| {
        // SAFETY: pending is an initialized set and the signal numbers are
        // constants.
        unsafe { libc::sigismember(&raw const pending, signal) == 1 }
    })
}

struct SigpipeGuard {
    set: libc::sigset_t,
    previous: libc::sigset_t,
    had_pending: bool,
    generated: bool,
}

impl SigpipeGuard {
    fn block() -> io::Result<Self> {
        // SAFETY: sigset_t values are initialized by sigemptyset before use;
        // pthread_sigmask updates only this PAM-calling thread.
        unsafe {
            let mut set = MaybeUninit::<libc::sigset_t>::zeroed().assume_init();
            if libc::sigemptyset(&raw mut set) != 0
                || libc::sigaddset(&raw mut set, libc::SIGPIPE) != 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut previous = MaybeUninit::<libc::sigset_t>::zeroed().assume_init();
            let status = libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, &raw mut previous);
            if status != 0 {
                return Err(io::Error::from_raw_os_error(status));
            }
            let mut pending = MaybeUninit::<libc::sigset_t>::zeroed().assume_init();
            if libc::sigpending(&raw mut pending) != 0 {
                let _ =
                    libc::pthread_sigmask(libc::SIG_SETMASK, &raw const previous, ptr::null_mut());
                return Err(io::Error::last_os_error());
            }
            let had_pending = libc::sigismember(&raw const pending, libc::SIGPIPE) == 1;
            Ok(Self {
                set,
                previous,
                had_pending,
                generated: false,
            })
        }
    }

    fn mark_generated(&mut self) {
        self.generated = true;
    }

    fn consume_generated(&self) {
        if self.had_pending || !self.generated {
            return;
        }
        // SAFETY: self.set is a valid singleton signal set. The preceding
        // EPIPE came from this thread's blocked pipe write, so sigwait
        // consumes only that newly generated SIGPIPE without changing the
        // process-wide signal disposition.
        unsafe {
            let mut pending = MaybeUninit::<libc::sigset_t>::zeroed().assume_init();
            if libc::sigpending(&raw mut pending) == 0
                && libc::sigismember(&raw const pending, libc::SIGPIPE) == 1
            {
                let mut signal = 0;
                let _ = libc::sigwait(&raw const self.set, &raw mut signal);
            }
        }
    }
}

impl Drop for SigpipeGuard {
    fn drop(&mut self) {
        self.consume_generated();
        // SAFETY: previous is the exact mask returned by pthread_sigmask for
        // this thread and remains valid until this guard is dropped.
        unsafe {
            let _ =
                libc::pthread_sigmask(libc::SIG_SETMASK, &raw const self.previous, ptr::null_mut());
        }
    }
}

// ---------------------------------------------------------------------------
// Post-fork descriptor cleanup
// ---------------------------------------------------------------------------

/// Mark every descriptor above stdio close-on-exec in the forked child, then
/// re-open `keep` to the exec'd helper.
///
/// This runs in the child between fork and exec, so no pre-spawn snapshot is
/// taken and a descriptor opened concurrently with the spawn cannot be missed.
/// Marking rather than closing preserves Rust's private exec-error pipe, which
/// is already close-on-exec and must stay usable until exec succeeds.
///
/// Linux uses `close_range(3, ~0, CLOSE_RANGE_CLOEXEC)`, which covers the
/// whole descriptor space in one call.  The fallback, and macOS, scan a
/// bounded range instead: on macOS the exact list would come from
/// `proc_pidinfo(PROC_PIDLISTFDS)`, which is tried first into a fixed stack
/// buffer because allocating after fork is not async-signal-safe, and the scan
/// covers the case where that list does not fit.  The scan bound is the hard
/// `RLIMIT_NOFILE` rather than the soft limit, so an already-open descriptor
/// above a lowered soft limit is still covered.
fn cloexec_unrelated_fds(keep: RawFd) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        const CLOSE_RANGE_CLOEXEC: u64 = 1 << 2;
        // SAFETY: close_range takes three integer arguments and touches no
        // caller memory.
        let result = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                3_u64,
                u64::from(u32::MAX),
                CLOSE_RANGE_CLOEXEC,
            )
        };
        if result == 0 {
            return restore_inherited_fd(keep);
        }
    }

    #[cfg(target_os = "macos")]
    if cloexec_listed_fds() {
        return restore_inherited_fd(keep);
    }

    let limit = max_fd_scan();
    let mut fd: RawFd = 3;
    while fd < limit {
        cloexec_raw(fd);
        fd += 1;
    }
    restore_inherited_fd(keep)
}

/// Mark one descriptor close-on-exec, ignoring descriptors that are not open.
fn cloexec_raw(fd: RawFd) {
    // SAFETY: fcntl operates on an inherited descriptor in the forked child.
    // Failed F_GETFD calls are already-closed or inaccessible descriptors and
    // can be ignored.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags != -1 {
        // SAFETY: the flags came from F_GETFD for this descriptor.
        unsafe {
            let _ = libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
        }
    }
}

/// Clear close-on-exec on the one descriptor the helper is meant to inherit.
///
/// Failure is fatal for the child: the helper would exec without its
/// cancellation channel and then die on EBADF. Returning the error from the
/// `pre_exec` closure makes `Command::spawn` report it through the exec
/// error pipe, so the parent sees a spawn failure and maps it to unavailable.
fn restore_inherited_fd(fd: RawFd) -> io::Result<()> {
    // SAFETY: fd is the liveness pipe read end created by this call.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Bound for the descriptor scan: the hard `RLIMIT_NOFILE`, clamped so an
/// unlimited hard limit cannot turn the scan into a multi-second loop.
fn max_fd_scan() -> RawFd {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes only into the rlimit value above.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) } != 0 {
        return MAX_FD_SCAN;
    }
    let bound = if limit.rlim_max > limit.rlim_cur {
        limit.rlim_max
    } else {
        limit.rlim_cur
    };
    RawFd::try_from(bound)
        .unwrap_or(MAX_FD_SCAN)
        .clamp(3, MAX_FD_SCAN)
}

/// macOS-only: mark exactly the open descriptors close-on-exec.
///
/// Uses a fixed stack buffer so nothing is allocated after fork. Returns false
/// when the kernel's list does not fit or the call fails, so the caller falls
/// back to the bounded scan.
#[cfg(target_os = "macos")]
fn cloexec_listed_fds() -> bool {
    const MAX_LISTED_FDS: usize = 1024;
    // Allocating after fork is not async-signal-safe, so the buffer is
    // deliberately on the stack; the caller falls back to a bounded scan when
    // the kernel's list does not fit.
    #[allow(clippy::large_stack_arrays)]
    let mut buffer = [libc::proc_fdinfo {
        proc_fd: 0,
        proc_fdtype: 0,
    }; MAX_LISTED_FDS];
    let Ok(size) = c_int::try_from(size_of_val(&buffer)) else {
        return false;
    };
    // SAFETY: getpid has no pointer arguments.
    let pid = unsafe { libc::getpid() };
    // proc_pidinfo is a thin syscall wrapper: it allocates nothing, takes no
    // locks, and writes only into the caller's buffer, so it is safe to call
    // between fork and exec where only async-signal-safe work is allowed.
    // SAFETY: buffer is a writable array of exactly `size` bytes and is the
    // only memory the call writes.
    let used = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            buffer.as_mut_ptr().cast(),
            size,
        )
    };
    if used <= 0 || used >= size {
        return false;
    }
    let count = usize::try_from(used).unwrap_or(0) / size_of::<libc::proc_fdinfo>();
    for entry in &buffer[..count] {
        if entry.proc_fd >= 3 {
            cloexec_raw(entry.proc_fd);
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Pure and isolated tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::HashMap;
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{PoisonError, RwLock, RwLockReadGuard};

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

    /// A thread handle carried to a signalling thread. `pthread_t` is a
    /// pointer on macOS and so not `Send`; the target thread is alive for the
    /// whole of each test that uses this, because it is the thread that joins
    /// the sender.
    struct ThreadHandle(libc::pthread_t);
    // SAFETY: the handle is only used with pthread_kill, and only while the
    // thread it names is parked in a helper wait.
    unsafe impl Send for ThreadHandle {}

    /// Serializes helper-script writes against helper spawns.
    ///
    /// `fs::write` holds a write descriptor on the script while it runs. Tests
    /// run in parallel, so another thread can fork during that window; the
    /// forked child inherits the writable descriptor until its own execve,
    /// and the kernel then fails that execve with ETXTBSY. Writers take the
    /// write lock, every spawn takes the read lock, so no fork can overlap a
    /// script write.
    static SPAWN: RwLock<()> = RwLock::new(());

    fn spawn_permit() -> RwLockReadGuard<'static, ()> {
        SPAWN.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// `run_helper_at` under the spawn lock. Every test spawn goes through
    /// this or `locked_spawn_and_pump`.
    fn locked_run_helper_at(path: &str, request: &[u8], timeout: Duration) -> HelperOutcome {
        let _permit = spawn_permit();
        run_helper_at(path, request, timeout)
    }

    fn locked_spawn_and_pump(path: &str, request: &[u8], timeout: Duration) -> HelperOutcome {
        let _permit = spawn_permit();
        spawn_and_pump_helper(path, request, timeout)
    }

    fn test_dir() -> std::path::PathBuf {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("oshioki-pam-test-{}-{id}", std::process::id()));
        fs::create_dir(&path).expect("create test directory");
        path
    }

    fn write_script(directory: &Path, body: &str) -> std::path::PathBuf {
        let _exclusive = SPAWN.write().unwrap_or_else(PoisonError::into_inner);
        let path = directory.join("helper");
        fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n")).expect("write helper");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("chmod helper");
        path
    }

    fn script(body: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let directory = test_dir();
        let path = write_script(&directory, body);
        (path, directory)
    }

    fn cleanup(directory: &Path) {
        let _ = fs::remove_dir_all(directory);
    }

    fn request() -> Vec<u8> {
        br#"{"pam_protocol_version":2,"principal":{"name":"alice"},"invoking":{"name":"alice"},"service":"sudo","tty":"/dev/ttys001","process_pid":123,"submitted_argv":{"available":false,"truncated":false,"values":[]}}"#.to_vec()
    }

    fn sample_request(argv: AdvisoryArgv) -> HelperRequest {
        HelperRequest {
            pam_protocol_version: PAM_PROTOCOL_VERSION,
            principal: Identity {
                name: "alice".to_owned(),
            },
            invoking: Identity {
                name: "alice".to_owned(),
            },
            service: "sudo".to_owned(),
            tty: Some("/dev/ttys001".to_owned()),
            process_pid: 123,
            submitted_argv: argv,
        }
    }

    /// True while the process exists and has not become a zombie. A reaped or
    /// exited-but-unreaped descendant both count as dead.
    fn process_is_alive(pid: libc::pid_t) -> bool {
        #[cfg(target_os = "linux")]
        {
            let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
                return false;
            };
            let Some((_, rest)) = stat.rsplit_once(')') else {
                return false;
            };
            let state = rest.trim_start().chars().next().unwrap_or('X');
            state != 'Z' && state != 'X'
        }
        #[cfg(not(target_os = "linux"))]
        {
            // SAFETY: signal 0 only probes for the process.
            unsafe { libc::kill(pid, 0) == 0 }
        }
    }

    #[test]
    fn supported_service_and_private_schema_are_bounded() {
        assert!(is_supported_service("sudo"));
        assert!(is_supported_service("sudo-i"));
        assert!(!is_supported_service("login"));
        assert!(request().len() < MAX_REQUEST_BYTES);
        let parsed: serde_json::Value = serde_json::from_slice(&request()).expect("valid JSON");
        assert_eq!(parsed["pam_protocol_version"], 2);
        assert_eq!(parsed["principal"]["name"], "alice");
        // Version 2 sends names only; the root helper resolves them.
        assert!(parsed["principal"]["uid"].is_null());
        assert!(parsed["invoking"]["uid"].is_null());
        assert!(parsed["submitted_argv"]["available"].is_boolean());
        assert!(parsed["submitted_argv"]["truncated"].is_boolean());
    }

    #[test]
    fn argv_availability_and_truncation_are_explicit() {
        let available = capture_submitted_argv([
            OsString::from("sudo"),
            OsString::from("-iu"),
            OsString::from("alice"),
        ]);
        assert!(available.available);
        assert!(!available.truncated);
        assert_eq!(available.values, ["sudo", "-iu", "alice"]);

        let truncated = capture_submitted_argv((0..=MAX_ARG_COUNT).map(|_| OsString::from("x")));
        assert!(truncated.available);
        assert!(truncated.truncated);
        assert_eq!(truncated.values.len(), MAX_ARG_COUNT);

        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let unavailable = capture_submitted_argv([OsString::from_vec(vec![0xff])]);
            assert!(!unavailable.available);
            assert!(!unavailable.truncated);
            assert!(unavailable.values.is_empty());
        }
    }

    #[test]
    fn json_escaped_argv_is_truncated_instead_of_failing_the_request() {
        // A legitimate Unix argument of control bytes passes the raw argv
        // allowance but expands about six times under JSON escaping.
        let control = String::from_utf8(vec![0x01; MAX_ARG_BYTES]).expect("ascii control bytes");
        let argv = capture_submitted_argv([OsString::from(control)]);
        assert!(argv.available);
        assert!(!argv.truncated);
        assert_eq!(argv.values.len(), 1);
        assert!(
            serde_json::to_vec(&sample_request(argv))
                .expect("serialize")
                .len()
                > MAX_REQUEST_BYTES
        );

        let control = String::from_utf8(vec![0x01; MAX_ARG_BYTES]).expect("ascii control bytes");
        let argv = capture_submitted_argv([OsString::from(control)]);
        let mut request = sample_request(argv);
        let bytes = serialize_request(&mut request).expect("request still serializes");
        assert!(bytes.len() + REQUEST_HEADROOM_BYTES <= MAX_REQUEST_BYTES);
        assert!(request.submitted_argv.truncated);
        assert!(request.submitted_argv.available);
        assert!(request.submitted_argv.values.is_empty());

        // The oversized advisory context must not stop authentication.
        let (path, directory) = script("cat >/dev/null\nexit 0");
        assert_eq!(
            locked_run_helper_at(path.to_str().unwrap(), &bytes, HELPER_TIMEOUT),
            HelperOutcome::Success
        );
        cleanup(&directory);
    }

    #[test]
    fn exit_status_mapping_never_treats_failure_as_success() {
        let (success, success_dir) = script("cat >/dev/null\nexit 0");
        assert_eq!(
            locked_run_helper_at(success.to_str().unwrap(), &request(), HELPER_TIMEOUT),
            HelperOutcome::Success
        );
        cleanup(&success_dir);

        let (unavailable, unavailable_dir) = script("cat >/dev/null\nexit 2");
        assert_eq!(
            locked_run_helper_at(unavailable.to_str().unwrap(), &request(), HELPER_TIMEOUT),
            HelperOutcome::Unavailable
        );
        cleanup(&unavailable_dir);

        let (failure, failure_dir) = script("cat >/dev/null\nexit 1");
        assert_eq!(
            locked_run_helper_at(failure.to_str().unwrap(), &request(), HELPER_TIMEOUT),
            HelperOutcome::Failure
        );
        cleanup(&failure_dir);

        let (malformed, malformed_dir) = script("cat >/dev/null\nprintf malformed\nexit 0");
        assert_eq!(
            locked_run_helper_at(malformed.to_str().unwrap(), &request(), HELPER_TIMEOUT),
            HelperOutcome::Failure
        );
        cleanup(&malformed_dir);
    }

    #[test]
    fn helper_default_budget_is_long_enough_for_device_approval() {
        assert_eq!(HELPER_TIMEOUT, Duration::from_secs(90));
    }

    #[test]
    fn sigpipe_from_a_closed_helper_input_is_consumed_on_this_thread() {
        let mut fds = [0; 2];
        // SAFETY: fds points to two writable integer slots and is closed below
        // after the deterministic EPIPE check.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: closing this read end makes the next write raise EPIPE.
        unsafe {
            libc::close(fds[0]);
        }
        let mut signal_guard = SigpipeGuard::block().expect("block SIGPIPE");
        let mut offset = 0;
        let error = write_available(fds[1], b"request", &mut offset).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EPIPE));
        signal_guard.mark_generated();
        drop(signal_guard);
        // SAFETY: fds[1] is the sole descriptor left from this test pipe.
        unsafe {
            libc::close(fds[1]);
        }
    }

    #[test]
    fn every_spawn_failure_falls_back_to_unavailable() {
        // The exec error still reaches the parent through Command's private
        // error pipe: the descriptor sweep marks descriptors close-on-exec
        // rather than closing them. It is classified as unavailable, not as a
        // denial, so a transient spawn problem cannot lock anyone out of sudo.
        let (path, directory) = script("exit 0");
        {
            let _exclusive = SPAWN.write().unwrap_or_else(PoisonError::into_inner);
            fs::write(&path, "#!/definitely/missing/interpreter\n").expect("replace helper");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("chmod helper");
        }
        let spawn_error = {
            let _permit = spawn_permit();
            Command::new(&path).arg("probe").spawn().unwrap_err()
        };
        assert_eq!(spawn_error.kind(), io::ErrorKind::NotFound);
        assert_eq!(
            locked_run_helper_at(path.to_str().unwrap(), &request(), HELPER_TIMEOUT),
            HelperOutcome::Unavailable
        );
        cleanup(&directory);

        // A non-executable helper (EACCES) and a missing one (ENOENT) are
        // unavailable too. Path security is decided by validate_helper_path,
        // not by the spawn result.
        let (denied, denied_dir) = script("exit 0");
        {
            let _exclusive = SPAWN.write().unwrap_or_else(PoisonError::into_inner);
            fs::set_permissions(&denied, fs::Permissions::from_mode(0o600)).expect("chmod helper");
        }
        assert_eq!(
            locked_run_helper_at(denied.to_str().unwrap(), &request(), HELPER_TIMEOUT),
            HelperOutcome::Unavailable
        );
        cleanup(&denied_dir);

        let missing = test_dir();
        assert_eq!(
            locked_run_helper_at(
                missing.join("absent").to_str().unwrap(),
                &request(),
                HELPER_TIMEOUT
            ),
            HelperOutcome::Unavailable
        );
        cleanup(&missing);
    }

    #[test]
    fn helper_timeout_kills_the_whole_descendant_tree() {
        let directory = test_dir();
        let pidfile = directory.join("grandchild.pid");
        // The grandchild records its own PID and then execs a long sleep, so
        // the test can assert on a process the module never knew about.
        let path = write_script(
            &directory,
            &format!(
                "sh -c 'echo $$ >\"$0\"; exec sleep 300' '{pidfile}' &\n                 while [ ! -s '{pidfile}' ]; do sleep 0.02; done\n                 cat >/dev/null\nsleep 300",
                pidfile = pidfile.display()
            ),
        );

        // The clock starts *after* the spawn permit is held. Tests that take
        // the exclusive side of `SPAWN` run for as long as their own wait
        // budget, and a timer started before the lock would be measuring that
        // queue rather than this timeout.
        let permit = spawn_permit();
        let started = Instant::now();
        let result = run_helper_at(
            path.to_str().unwrap(),
            &request(),
            Duration::from_millis(1500),
        );
        let elapsed = started.elapsed();
        drop(permit);
        assert_eq!(result, HelperOutcome::Unavailable);
        assert!(
            elapsed < Duration::from_secs(8),
            "the timed-out wait took {elapsed:?}"
        );

        let recorded = fs::read_to_string(&pidfile).expect("grandchild recorded its pid");
        let pid: libc::pid_t = recorded.trim().parse().expect("numeric pid");
        assert!(pid > 1);

        let mut alive = true;
        for _ in 0..500 {
            if !process_is_alive(pid) {
                alive = false;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!alive, "descendant {pid} survived the helper timeout");
        cleanup(&directory);
    }

    /// Applies sudo's authentication-phase signal state for one signal —
    /// blocked on this thread, with a process-wide disposition of either
    /// `SIG_IGN` or a no-op catching handler, per [`Disposition`] — and puts
    /// everything back on drop, consuming a pending instance first so the
    /// mask can be released safely.
    ///
    /// Restoration lives in `Drop` deliberately: a failing assertion in the
    /// middle of a test must not leave the rest of the suite, or the test
    /// runner, with a changed disposition, a changed mask, or an
    /// undeliverable signal parked in the pending set.
    struct BlockedSignal {
        signal: c_int,
        previous_action: libc::sigaction,
        previous_mask: libc::sigset_t,
        blocked: libc::sigset_t,
    }

    /// The disposition the surrounding process has installed while it blocks
    /// the signal.  Which one applies is not a detail: it decides whether the
    /// signal is left *pending* on Darwin.
    ///
    /// `sudo` installs `sudo_handler` for `SIGINT` and `SIGQUIT` in
    /// `init_signals`, so [`Disposition::Caught`] is what a terminal sudo
    /// actually has while this module waits.  It falls back to
    /// [`Disposition::Ignored`] only when sudo *inherited* `SIG_IGN` — the
    /// case for a sudo started as a shell's background job — because
    /// `init_signals` deliberately does not overwrite an inherited `SIG_IGN`.
    #[derive(Clone, Copy)]
    enum Disposition {
        Ignored,
        Caught,
    }

    extern "C" fn absorb_signal(_signal: c_int) {}

    impl BlockedSignal {
        fn apply(signal: c_int, disposition: Disposition) -> Self {
            // SAFETY: every value is stack-local and initialized before use;
            // the mask change is thread-local.
            unsafe {
                let mut previous_action = MaybeUninit::<libc::sigaction>::zeroed();
                let mut action = MaybeUninit::<libc::sigaction>::zeroed();
                let action_ptr = action.as_mut_ptr();
                (*action_ptr).sa_sigaction = match disposition {
                    Disposition::Ignored => libc::SIG_IGN,
                    Disposition::Caught => absorb_signal as *const () as usize,
                };
                libc::sigemptyset(&raw mut (*action_ptr).sa_mask);
                (*action_ptr).sa_flags = 0;
                assert_eq!(
                    libc::sigaction(signal, action_ptr, previous_action.as_mut_ptr()),
                    0,
                    "set the test disposition for the signal"
                );
                let mut blocked = MaybeUninit::<libc::sigset_t>::zeroed().assume_init();
                libc::sigemptyset(&raw mut blocked);
                libc::sigaddset(&raw mut blocked, signal);
                // The guard exists before the mask is touched, and is seeded
                // with this thread's *current* mask. A panic from the assert
                // below therefore still unwinds through a Drop that restores
                // the disposition, instead of leaking SIG_IGN into the rest of
                // the suite.
                let mut current_mask = MaybeUninit::<libc::sigset_t>::zeroed().assume_init();
                libc::sigemptyset(&raw mut current_mask);
                let _ =
                    libc::pthread_sigmask(libc::SIG_SETMASK, ptr::null(), &raw mut current_mask);
                let mut guard = Self {
                    signal,
                    previous_action: previous_action.assume_init(),
                    previous_mask: current_mask,
                    blocked,
                };
                let mut previous_mask = MaybeUninit::<libc::sigset_t>::zeroed().assume_init();
                assert_eq!(
                    libc::pthread_sigmask(
                        libc::SIG_BLOCK,
                        &raw const blocked,
                        &raw mut previous_mask
                    ),
                    0,
                    "block the signal on this thread"
                );
                guard.previous_mask = previous_mask;
                guard
            }
        }

        /// Make the signal pending on this thread without delivering it.
        fn raise_on_this_thread(&self) {
            // SAFETY: this thread blocks the signal, so it can only become
            // pending; `Drop` consumes it.
            unsafe {
                libc::pthread_kill(libc::pthread_self(), self.signal);
            }
        }
    }

    impl Drop for BlockedSignal {
        fn drop(&mut self) {
            // SAFETY: the pending instance is consumed before the mask is
            // released, then the saved disposition and mask are restored
            // exactly as they were.
            unsafe {
                let mut pending = MaybeUninit::<libc::sigset_t>::zeroed();
                if libc::sigpending(pending.as_mut_ptr()) == 0
                    && libc::sigismember(pending.as_ptr(), self.signal) == 1
                {
                    let mut signal = 0;
                    let _ = libc::sigwait(&raw const self.blocked, &raw mut signal);
                }
                libc::sigaction(
                    self.signal,
                    &raw const self.previous_action,
                    ptr::null_mut(),
                );
                libc::pthread_sigmask(
                    libc::SIG_SETMASK,
                    &raw const self.previous_mask,
                    ptr::null_mut(),
                );
            }
        }
    }

    /// Installs a handler for one signal and restores the previous action on
    /// drop, so a panicking assertion cannot leak it into other tests.
    struct HandlerFor {
        signal: c_int,
        previous: libc::sigaction,
    }

    impl HandlerFor {
        /// `flags` deliberately omits `SA_RESTART`, so a blocking syscall
        /// reports `EINTR` the way sudo's own PAM-phase handlers do.
        fn install(signal: c_int, handler: extern "C" fn(c_int)) -> Self {
            // SAFETY: the fields written below are the only ones sigaction
            // reads, and the mask is initialized by sigemptyset.
            unsafe {
                let mut previous = MaybeUninit::<libc::sigaction>::zeroed();
                let mut action = MaybeUninit::<libc::sigaction>::zeroed();
                let action_ptr = action.as_mut_ptr();
                (*action_ptr).sa_sigaction = handler as *const () as usize;
                libc::sigemptyset(&raw mut (*action_ptr).sa_mask);
                (*action_ptr).sa_flags = 0;
                assert_eq!(
                    libc::sigaction(signal, action_ptr, previous.as_mut_ptr()),
                    0,
                    "install the test handler"
                );
                Self {
                    signal,
                    previous: previous.assume_init(),
                }
            }
        }
    }

    impl Drop for HandlerFor {
        fn drop(&mut self) {
            // SAFETY: previous is the disposition this guard replaced.
            unsafe {
                libc::sigaction(self.signal, &raw const self.previous, ptr::null_mut());
            }
        }
    }

    /// A helper script that records a grandchild's PID and then sleeps, so a
    /// cancelled wait can be asserted to have killed the whole tree.
    fn sleeping_helper_with_grandchild(
        directory: &Path,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let pidfile = directory.join("grandchild.pid");
        let path = write_script(
            directory,
            &format!(
                "sh -c 'echo $$ >\"$0\"; exec sleep 300' '{pidfile}' &\n                 while [ ! -s '{pidfile}' ]; do sleep 0.02; done\n                 cat >/dev/null\nsleep 300",
                pidfile = pidfile.display()
            ),
        );
        (path, pidfile)
    }

    /// Asserts the recorded grandchild is gone, waiting a bounded time for the
    /// kill to be reaped.
    fn assert_descendant_died(pidfile: &Path, what: &str) {
        let recorded = fs::read_to_string(pidfile).expect("grandchild recorded its pid");
        let pid: libc::pid_t = recorded.trim().parse().expect("numeric pid");
        assert!(pid > 1);
        let mut alive = true;
        for _ in 0..500 {
            if !process_is_alive(pid) {
                alive = false;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!alive, "descendant {pid} survived {what}");
    }

    /// The body shared by the two blocked-`SIGINT` tests: the surrounding
    /// process *blocks* the signal, so nothing is delivered and no syscall
    /// returns `EINTR` — the keystroke only becomes pending. The wait must
    /// still end as `Unavailable`, promptly, with the helper tree dead.
    ///
    /// `pthread_kill` targets the pumping thread so the signal cannot be taken
    /// by another test thread. Signal state is process-wide, so this runs
    /// under the exclusive spawn lock.
    fn blocked_sigint_cancels_the_helper_wait(disposition: Disposition) {
        let directory = test_dir();
        let (path, pidfile) = sleeping_helper_with_grandchild(&directory);

        let exclusive = SPAWN.write().unwrap_or_else(PoisonError::into_inner);
        let signals = BlockedSignal::apply(libc::SIGINT, disposition);

        // SAFETY: pthread_self has no pointer arguments; the handle is used
        // only while this thread is inside the wait below.
        let target = ThreadHandle(unsafe { libc::pthread_self() });
        let signaller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            // SAFETY: the target thread blocks SIGINT, so this only makes it
            // pending; the guard consumes it.
            unsafe {
                libc::pthread_kill(target.0, libc::SIGINT);
            }
        });

        let started = Instant::now();
        let result = run_helper_at(path.to_str().unwrap(), &request(), Duration::from_secs(120));
        let elapsed = started.elapsed();
        signaller.join().unwrap();
        drop(signals);
        drop(exclusive);

        assert_eq!(result, HelperOutcome::Unavailable);
        assert!(
            elapsed < Duration::from_secs(2),
            "the cancelled wait took {elapsed:?}"
        );
        assert_descendant_died(&pidfile, "a cancelled helper wait");
        cleanup(&directory);
    }

    /// The production case on both platforms: sudo's `init_signals` installs
    /// `sudo_handler` for `SIGINT`, and `verify_user` blocks it for the whole
    /// authentication phase. A blocked signal with a *catching* disposition is
    /// left pending by both Linux and XNU, so `sigpending` sees the keystroke
    /// on macOS exactly as it does on Linux.
    #[test]
    fn a_blocked_and_caught_sigint_still_cancels_the_helper_wait() {
        blocked_sigint_cancels_the_helper_wait(Disposition::Caught);
    }

    /// The narrower case: sudo *inherited* `SIG_IGN` for `SIGINT` — a sudo
    /// started as a shell's background job — so `init_signals` left the
    /// disposition alone and the blocked signal is both ignored and blocked.
    ///
    /// Linux-only, and the restriction is a kernel difference rather than a
    /// test artefact. Linux keeps a blocked signal pending even when its
    /// disposition is `SIG_IGN`, because the handler may change before the
    /// unblock. XNU discards it at generation instead: measured on macOS
    /// 15.7.5, `sigpending` reports nothing after `pthread_kill`, `raise`, or
    /// `kill(getpid())` for a signal that is blocked *and* `SIG_IGN`, while
    /// the same probe with a catching or default disposition reports it
    /// pending. No amount of module-side work can observe a signal the kernel
    /// never recorded, and sudo's own `user_interrupted()` — which is the same
    /// `sigpending` read — has exactly the same blind spot there. See
    /// `pam/README.md`.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_blocked_and_ignored_sigint_still_cancels_the_helper_wait() {
        blocked_sigint_cancels_the_helper_wait(Disposition::Ignored);
    }

    /// The other half of that kernel difference, asserted rather than assumed:
    /// on XNU a `SIGINT` that is blocked *and* `SIG_IGN` is discarded at
    /// generation, so it never reaches the pending set and
    /// `terminal_cancel_requested` cannot see it. This test exists to fail
    /// loudly if a future macOS starts behaving like Linux — at which point
    /// the Linux-only test above can become cross-platform.
    ///
    /// The signal never becomes pending, so nothing is delivered when the
    /// guard restores the mask. Signal state is process-wide, so this runs
    /// under the exclusive spawn lock.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_blocked_and_ignored_sigint_is_discarded_by_xnu() {
        let exclusive = SPAWN.write().unwrap_or_else(PoisonError::into_inner);
        let signals = BlockedSignal::apply(libc::SIGINT, Disposition::Ignored);
        signals.raise_on_this_thread();
        // The claim is about the kernel, so read the pending set directly
        // rather than through terminal_cancel_requested, whose answer also
        // depends on CANCEL_SIGNALS and on SIGQUIT.
        // SAFETY: sigpending writes only into the zeroed set, which is then
        // read by sigismember.
        let pending_sigint = unsafe {
            let mut pending = MaybeUninit::<libc::sigset_t>::zeroed();
            assert_eq!(libc::sigpending(pending.as_mut_ptr()), 0, "sigpending");
            let pending = pending.assume_init();
            libc::sigismember(&raw const pending, libc::SIGINT)
        };
        drop(signals);
        drop(exclusive);
        assert_eq!(
            pending_sigint, 0,
            "XNU kept a blocked-and-ignored SIGINT pending; see pam/README.md"
        );
    }

    /// A signal that lands in the *drain* window must not turn a successful
    /// helper into an authentication failure.
    ///
    /// The pump loop and the post-exit drain deliberately treat `EINTR`
    /// differently: the loop reports it, because there a signal may be the
    /// operator cancelling; the drain retries it, because by then the leader
    /// is reaped and the only thing an interrupted read could still do is
    /// destroy a decision that has already been made.
    ///
    /// `finish_helper` is driven directly, as in the drain test above, for two
    /// reasons. Going through `run_helper_at` would let the pump loop absorb
    /// the signals first (correctly, as cancellation) and the drain would
    /// never see one; and it kills the helper's process group before draining,
    /// so nothing would still be holding the pipes open. Here a background
    /// `sleep` inherits the pipes and keeps the drain looping for a few tens
    /// of milliseconds, well inside the 100 ms grace.
    ///
    /// The descriptors are left *blocking*, which is what makes the interrupt
    /// deterministic: a blocking read is interrupted by a signal, where the
    /// non-blocking descriptors the pump loop installs would usually return
    /// `EAGAIN` first. A real `EINTR` here is therefore rare — which is
    /// exactly why the branch has to be right rather than relied upon, and
    /// why it needs a test that can force it.
    ///
    /// Reverting the drain to report `EINTR` makes this fail with
    /// `HelperOutcome::Failure`, the hard `PAM_AUTH_ERR` the split exists to
    /// prevent.
    #[test]
    fn a_signal_during_the_output_drain_does_not_fail_a_successful_helper() {
        extern "C" fn noop(_signal: c_int) {}

        let exclusive = SPAWN.write().unwrap_or_else(PoisonError::into_inner);
        let mut command = Command::new("/bin/sh");
        command
            // The leader exits at once; the background sleep inherits stdout
            // and stderr and holds them open, so the drain actually loops.
            .arg("-c")
            .arg("sleep 0.05 & exit 0")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: setpgid with both arguments zero only affects this child,
        // and keeps ChildGuard's group operations away from the test runner.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().expect("spawn drain probe");
        let (_read, write) = liveness_pipe().expect("liveness pipe");
        let mut guard = ChildGuard::new(child, write);
        let mut stdout = guard.child.stdout.take().expect("stdout");
        let mut stderr = guard.child.stderr.take().expect("stderr");
        // Deliberately left blocking; see the doc comment.
        let status = guard.reap().expect("reap drain probe");

        let handler = HandlerFor::install(libc::SIGUSR1, noop);
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        // SAFETY: pthread_self has no pointer arguments; the handle is used
        // only while this thread is inside the drain below, which joins the
        // signaller before returning.
        let target = ThreadHandle(unsafe { libc::pthread_self() });
        let signaller = {
            let stop = std::sync::Arc::clone(&stop);
            std::thread::spawn(move || {
                for _ in 0..75 {
                    if stop.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    // SAFETY: the target thread is live for the whole loop and
                    // the handler installed above is a no-op.
                    unsafe {
                        libc::pthread_kill(target.0, libc::SIGUSR1);
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
            })
        };

        let mut stdout_bytes = Vec::new();
        let mut stderr_bytes = Vec::new();
        let mut stdout_open = true;
        let mut stderr_open = true;
        let result = finish_helper(
            &mut guard,
            status,
            &mut stdout,
            &mut stdout_bytes,
            &mut stdout_open,
            &mut stderr,
            &mut stderr_bytes,
            &mut stderr_open,
            true,
        );
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        signaller.join().unwrap();
        drop(handler);
        drop(exclusive);

        assert_eq!(
            result,
            HelperOutcome::Success,
            "a signal in the drain window destroyed a successful helper \
             (stdout_open={stdout_open} stderr_open={stderr_open})"
        );
    }

    /// A cancellation signal that is *already* pending when the wait starts
    /// must cancel too.
    ///
    /// Standard signals do not queue: a second `Ctrl-C` merges into a bit that
    /// is already set, so nothing transitions. Any rule that waited for a
    /// transition would make every later keystroke invisible for the whole
    /// 90-second budget, which is the original defect wearing a disguise. The
    /// wait must therefore end on its first loop iteration.
    ///
    /// The helper here is a plain sleep with no grandchild: cancellation is so
    /// immediate that a helper tree would not have finished building itself,
    /// so the descendant kill is left to the two tests around this one.
    #[test]
    fn a_signal_already_pending_when_the_wait_starts_still_cancels() {
        let (path, directory) = script("sleep 300");

        let exclusive = SPAWN.write().unwrap_or_else(PoisonError::into_inner);
        // The catching disposition is sudo's own (`init_signals` installs
        // `sudo_handler`), and it is the one XNU also leaves pending; see
        // `a_blocked_and_caught_sigint_still_cancels_the_helper_wait`.
        let signals = BlockedSignal::apply(libc::SIGINT, Disposition::Caught);
        // Pending before the wait begins, exactly as a keystroke during an
        // earlier phase of the same PAM call would be.
        signals.raise_on_this_thread();

        let started = Instant::now();
        let result = run_helper_at(path.to_str().unwrap(), &request(), Duration::from_secs(120));
        let elapsed = started.elapsed();
        drop(signals);
        drop(exclusive);

        assert_eq!(result, HelperOutcome::Unavailable);
        // The pending check is the first statement in the pump loop, so this
        // is spawn cost and nothing else. The bound is loose only to survive a
        // loaded build machine; it is four orders of magnitude below the
        // 120-second budget the wait was given.
        assert!(
            elapsed < Duration::from_secs(2),
            "a pre-pending cancellation took {elapsed:?}"
        );
        cleanup(&directory);
    }

    /// The backstop rule: a signal the surrounding process *catches* (rather
    /// than blocks) interrupts the pump loop's syscalls, and an interrupted
    /// wait is cancellation too.
    ///
    /// sudo catches several signals in this phase, so this covers them without
    /// depending on which. `SIGUSR1` with a no-op handler installed without
    /// `SA_RESTART`, delivered to the pumping thread with `pthread_kill`,
    /// produces exactly the `EINTR` they would. Dispositions are process-wide,
    /// so it runs under the exclusive spawn lock and the handler is removed by
    /// a guard.
    #[test]
    fn a_caught_signal_during_the_helper_wait_cancels_as_unavailable() {
        extern "C" fn noop(_signal: c_int) {}

        let directory = test_dir();
        let (path, pidfile) = sleeping_helper_with_grandchild(&directory);

        let exclusive = SPAWN.write().unwrap_or_else(PoisonError::into_inner);
        let handler = HandlerFor::install(libc::SIGUSR1, noop);

        // SAFETY: pthread_self has no pointer arguments; the handle is used
        // only while this thread is inside the wait below.
        let target = ThreadHandle(unsafe { libc::pthread_self() });
        let signaller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            // SAFETY: the pumping thread is parked in the wait below and is
            // joined with it, so the handle is live.
            unsafe {
                libc::pthread_kill(target.0, libc::SIGUSR1);
            }
        });

        let started = Instant::now();
        let result = run_helper_at(path.to_str().unwrap(), &request(), Duration::from_secs(120));
        let elapsed = started.elapsed();
        signaller.join().unwrap();
        drop(handler);
        drop(exclusive);

        assert_eq!(result, HelperOutcome::Unavailable);
        assert!(
            elapsed < Duration::from_secs(2),
            "the interrupted wait took {elapsed:?}"
        );
        assert_descendant_died(&pidfile, "an interrupted helper wait");
        cleanup(&directory);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_helper_inherits_the_liveness_pipe_and_nothing_else() {
        let directory = test_dir();
        let report = directory.join("report");
        let leak = directory.join("leak-marker");
        // An unrelated descriptor the PAM process already holds open, with
        // close-on-exec deliberately clear (dup does not copy the flag), so
        // only the post-fork sweep can keep it out of the helper.
        let held = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&leak)
            .expect("open leak marker");
        // SAFETY: held owns a live descriptor; the duplicate is closed below.
        let inheritable = unsafe { libc::dup(held.as_raw_fd()) };
        assert!(inheritable >= 3);
        // SAFETY: F_GETFD reports the flags of the duplicate just created.
        assert_eq!(unsafe { libc::fcntl(inheritable, libc::F_GETFD) }, 0);

        let path = write_script(
            &directory,
            &format!(
                "cat >/dev/null\nfd=$5\n{{ echo \"args=$*\"; \
                 if [ -e /proc/$$/fd/$fd ]; then echo liveness=open; else echo liveness=missing; fi; \
                 ls -l /proc/$$/fd; }} >'{}' 2>&1\nexit 0",
                report.display()
            ),
        );
        assert_eq!(
            locked_run_helper_at(path.to_str().unwrap(), &request(), HELPER_TIMEOUT),
            HelperOutcome::Success
        );
        // SAFETY: inheritable is the duplicate created above and is not
        // owned anywhere else.
        unsafe {
            libc::close(inheritable);
        }
        drop(held);

        let observed = fs::read_to_string(&report).expect("helper wrote its report");
        assert!(
            observed.contains(&format!("{HELPER_LIVENESS_FLAG} ")),
            "helper argv missing the liveness flag: {observed}"
        );
        assert!(
            observed.contains("liveness=open"),
            "helper did not inherit the liveness descriptor: {observed}"
        );
        assert!(
            !observed.contains("leak-marker"),
            "helper inherited an unrelated descriptor: {observed}"
        );
        cleanup(&directory);
    }

    #[test]
    fn a_successful_helper_still_takes_its_descendants_with_it() {
        // Proves the group kill happens while the leader is an unreaped
        // zombie. If the kill were issued after reaping, the process group ID
        // would already be recyclable, the signal would miss, and this
        // grandchild would survive. It redirects the inherited pipes to
        // /dev/null so the leader's exit still closes them.
        let directory = test_dir();
        let pidfile = directory.join("grandchild.pid");
        let path = write_script(
            &directory,
            &format!(
                "sh -c 'echo $$ >\"$0\"; exec sleep 300' '{pidfile}' >/dev/null 2>&1 &\n\
                 while [ ! -s '{pidfile}' ]; do sleep 0.02; done\n\
                 cat >/dev/null\nexit 0",
                pidfile = pidfile.display()
            ),
        );

        assert_eq!(
            locked_run_helper_at(path.to_str().unwrap(), &request(), HELPER_TIMEOUT),
            HelperOutcome::Success
        );

        let recorded = fs::read_to_string(&pidfile).expect("grandchild recorded its pid");
        let pid: libc::pid_t = recorded.trim().parse().expect("numeric pid");
        assert!(pid > 1);
        let mut alive = true;
        for _ in 0..500 {
            if !process_is_alive(pid) {
                alive = false;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!alive, "descendant {pid} survived a successful helper");
        cleanup(&directory);
    }

    #[test]
    fn output_is_still_drained_after_the_helper_deadline_has_passed() {
        // A helper that exits successfully in the last millisecond of its
        // budget must still have its output read. The drain grace is measured
        // from the exit, so an already-expired deadline is not a failure.
        let _permit = spawn_permit();
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("exit 0")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: setpgid with both arguments zero only affects this child,
        // and keeps ChildGuard's group operations away from the test runner.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().expect("spawn drain probe");
        let (_read, write) = liveness_pipe().expect("liveness pipe");
        let mut guard = ChildGuard::new(child, write);
        let mut stdout = guard.child.stdout.take().expect("stdout");
        let mut stderr = guard.child.stderr.take().expect("stderr");
        set_nonblocking(stdout.as_raw_fd()).expect("nonblocking stdout");
        set_nonblocking(stderr.as_raw_fd()).expect("nonblocking stderr");
        let status = guard.reap().expect("reap drain probe");

        let started = Instant::now();
        let mut stdout_bytes = Vec::new();
        let mut stderr_bytes = Vec::new();
        let mut stdout_open = true;
        let mut stderr_open = true;
        let result = finish_helper(
            &mut guard,
            status,
            &mut stdout,
            &mut stdout_bytes,
            &mut stdout_open,
            &mut stderr,
            &mut stderr_bytes,
            &mut stderr_open,
            true,
        );
        assert_eq!(
            result,
            HelperOutcome::Success,
            "drained in {:?} of a {HELPER_DRAIN_GRACE:?} grace; stdout_open={stdout_open} stderr_open={stderr_open}",
            started.elapsed()
        );
        assert!(!stdout_open && !stderr_open);
    }

    #[test]
    fn helper_timeout_also_covers_a_full_bounded_request_write() {
        let (path, directory) = script("sleep 30");
        let request = vec![b'x'; MAX_REQUEST_BYTES];
        let started = Instant::now();
        let result =
            locked_run_helper_at(path.to_str().unwrap(), &request, Duration::from_millis(250));
        assert_eq!(result, HelperOutcome::Unavailable);
        assert!(started.elapsed() < Duration::from_secs(3));
        cleanup(&directory);
    }

    #[test]
    fn a_blocked_request_write_times_out_as_unavailable() {
        let (path, directory) = script("sleep 300");
        // Far larger than any pipe buffer, to a helper that never reads, so
        // the write blocks for real instead of fitting in the pipe.
        let request = vec![b'x'; 1024 * 1024];
        assert!(request.len() > MAX_REQUEST_BYTES);
        // The bound itself is enforced one level up.
        assert_eq!(
            locked_run_helper_at(path.to_str().unwrap(), &request, Duration::from_millis(250)),
            HelperOutcome::Failure
        );

        let started = Instant::now();
        let result =
            locked_spawn_and_pump(path.to_str().unwrap(), &request, Duration::from_millis(250));
        assert_eq!(result, HelperOutcome::Unavailable);
        assert!(started.elapsed() < Duration::from_secs(3));
        cleanup(&directory);
    }

    #[test]
    fn helper_output_bound_is_a_hard_failure() {
        let (path, directory) = script(
            "cat >/dev/null\ni=0\nwhile [ $i -lt 20000 ]; do printf x; i=$((i + 1)); done\nexit 0",
        );
        assert_eq!(
            locked_run_helper_at(path.to_str().unwrap(), &request(), HELPER_TIMEOUT),
            HelperOutcome::Failure
        );
        cleanup(&directory);
    }

    #[test]
    fn the_descriptor_scan_bound_is_sane() {
        let bound = max_fd_scan();
        assert!(bound >= 3, "scan must start above stdio");
        assert!(
            bound <= MAX_FD_SCAN,
            "an unlimited hard limit must be capped"
        );
    }

    #[test]
    fn exported_entry_has_isolated_abi_and_null_handle_fails_closed() {
        let _: extern "C" fn(*mut PamHandle, c_int, c_int, *const *const c_char) -> c_int =
            pam_sm_authenticate;
        let _: extern "C" fn(*mut PamHandle, c_int, c_int, *const *const c_char) -> c_int =
            pam_sm_setcred;
        assert_eq!(
            pam_sm_authenticate(ptr::null_mut(), 0, 0, ptr::null()),
            PAM_SYSTEM_ERR
        );
    }

    #[test]
    fn helper_path_validation_rejects_writable_metadata() {
        let directory = test_dir();
        let path = directory.join("helper");
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .expect("create helper");
        drop(file);
        let metadata = fs::symlink_metadata(&path).expect("stat helper");
        assert!(metadata.mode() & 0o222 != 0);
        assert_eq!(
            secure_metadata(&path, false),
            Err(HelperPathStatus::Insecure)
        );
        cleanup(&directory);
    }

    #[test]
    fn root_owned_but_group_or_world_writable_paths_are_rejected() {
        // Ownership is acceptable in every case below, so only the mode bits
        // decide: removing the group/other write check would fail this test.
        assert_eq!(check_metadata(0, 0o755, false, true, false), Ok(()));
        assert_eq!(
            check_metadata(0, 0o775, false, true, false),
            Err(HelperPathStatus::Insecure),
            "a root-owned group-writable helper must be rejected"
        );
        assert_eq!(
            check_metadata(0, 0o757, false, true, false),
            Err(HelperPathStatus::Insecure),
            "a root-owned world-writable helper must be rejected"
        );
        assert_eq!(check_metadata(0, 0o755, true, false, true), Ok(()));
        assert_eq!(
            check_metadata(0, 0o777, true, false, true),
            Err(HelperPathStatus::Insecure),
            "a root-owned world-writable directory must be rejected"
        );
        // A setuid or setgid helper is rejected: a credential-changing execve
        // clears PR_SET_PDEATHSIG and would disable parent-death cancellation.
        assert_eq!(
            check_metadata(0, 0o4755, false, true, false),
            Err(HelperPathStatus::Insecure),
            "a setuid helper must be rejected"
        );
        assert_eq!(
            check_metadata(0, 0o2755, false, true, false),
            Err(HelperPathStatus::Insecure),
            "a setgid helper must be rejected"
        );
        assert_eq!(
            check_metadata(0, 0o6755, false, true, false),
            Err(HelperPathStatus::Insecure)
        );
        // The sticky bit alone is not a credential change and stays allowed on
        // directories, which is how /tmp-style parents would look.
        assert_eq!(check_metadata(0, 0o1755, true, false, true), Ok(()));
        // Non-root ownership is still rejected on its own.
        assert_eq!(
            check_metadata(1000, 0o755, false, true, false),
            Err(HelperPathStatus::Insecure)
        );
        // A non-executable or wrong-type helper is rejected too.
        assert_eq!(
            check_metadata(0, 0o644, false, true, false),
            Err(HelperPathStatus::Insecure)
        );
        assert_eq!(
            check_metadata(0, 0o755, true, false, false),
            Err(HelperPathStatus::Insecure)
        );
    }

    // -----------------------------------------------------------------------
    // PAM handle lifecycle, driven through the PamAccess seam
    // -----------------------------------------------------------------------

    struct FakeHandle {
        items: HashMap<c_int, String>,
        state: Option<AttemptState>,
    }

    impl FakeHandle {
        fn new() -> Self {
            let mut items = HashMap::new();
            items.insert(PAM_SERVICE, "sudo".to_owned());
            items.insert(PAM_USER, "root".to_owned());
            items.insert(PAM_RUSER, "alice".to_owned());
            items.insert(PAM_TTY, "/dev/pts/1".to_owned());
            Self { items, state: None }
        }
    }

    impl PamAccess for FakeHandle {
        fn item(&self, item_type: c_int) -> Result<Option<String>, c_int> {
            Ok(self.items.get(&item_type).cloned())
        }

        fn state(&mut self) -> Result<&mut AttemptState, c_int> {
            Ok(self.state.get_or_insert_with(AttemptState::empty))
        }
    }

    fn attempt(handle: &mut FakeHandle, calls: &Cell<usize>, outcome: HelperOutcome) -> c_int {
        authenticate_with(handle, |request| {
            assert!(!request.is_empty());
            calls.set(calls.get() + 1);
            outcome
        })
    }

    #[test]
    fn attempt_state_is_owned_per_handle() {
        let calls = Cell::new(0);
        let mut first = FakeHandle::new();
        let mut second = FakeHandle::new();

        assert_eq!(
            attempt(&mut first, &calls, HelperOutcome::Unavailable),
            PAM_AUTHINFO_UNAVAIL
        );
        assert_eq!(calls.get(), 1);
        // A second handle has its own record and still runs the helper.
        assert_eq!(
            attempt(&mut second, &calls, HelperOutcome::Success),
            PAM_SUCCESS
        );
        assert_eq!(calls.get(), 2);
        // The first handle's record is untouched by the second.
        assert_eq!(
            attempt(&mut first, &calls, HelperOutcome::Success),
            PAM_AUTHINFO_UNAVAIL
        );
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn a_changed_context_resets_the_handle_record() {
        let calls = Cell::new(0);
        let mut handle = FakeHandle::new();
        assert_eq!(
            attempt(&mut handle, &calls, HelperOutcome::Unavailable),
            PAM_AUTHINFO_UNAVAIL
        );
        assert_eq!(calls.get(), 1);

        handle.items.insert(PAM_USER, "operator".to_owned());
        // A different principal on the same handle is a new transaction, not
        // a reuse of the previous result.
        assert_eq!(
            attempt(&mut handle, &calls, HelperOutcome::Success),
            PAM_SUCCESS
        );
        assert_eq!(calls.get(), 2);
        assert_eq!(
            handle
                .state
                .as_ref()
                .unwrap()
                .context
                .as_ref()
                .unwrap()
                .principal_name,
            "operator"
        );
    }

    #[test]
    fn a_password_retry_does_not_start_a_second_device_request() {
        let calls = Cell::new(0);
        let mut handle = FakeHandle::new();
        assert_eq!(
            attempt(&mut handle, &calls, HelperOutcome::Failure),
            hard_failure_status()
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(
            attempt(&mut handle, &calls, HelperOutcome::Success),
            hard_failure_status()
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn unavailable_is_reused_for_password_retries_on_the_same_handle() {
        let calls = Cell::new(0);
        let mut handle = FakeHandle::new();
        assert_eq!(
            attempt(&mut handle, &calls, HelperOutcome::Unavailable),
            PAM_AUTHINFO_UNAVAIL
        );
        assert_eq!(
            attempt(&mut handle, &calls, HelperOutcome::Unavailable),
            PAM_AUTHINFO_UNAVAIL
        );
        assert_eq!(
            attempt(&mut handle, &calls, HelperOutcome::Unavailable),
            PAM_AUTHINFO_UNAVAIL
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn a_device_success_is_never_reused_on_the_same_handle() {
        let calls = Cell::new(0);
        let mut handle = FakeHandle::new();
        assert_eq!(
            attempt(&mut handle, &calls, HelperOutcome::Success),
            PAM_SUCCESS
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(
            attempt(&mut handle, &calls, HelperOutcome::Success),
            hard_failure_status()
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(
            handle.state.as_ref().unwrap().outcome,
            AttemptOutcome::Success
        );
    }

    /// Linux keeps the hard fault as `PAM_AUTH_ERR`, which the installer's
    /// `default=die` control turns into a denial.  macOS has no bracket
    /// controls, so the same fault must be `PAM_ABORT` for `OpenPAM` to abort
    /// the chain under `auth sufficient`.  Unvalidated on hardware.
    #[test]
    fn a_hard_fault_maps_to_the_platform_fail_closed_status() {
        #[cfg(target_os = "macos")]
        assert_eq!(hard_failure_status(), PAM_ABORT);
        #[cfg(not(target_os = "macos"))]
        assert_eq!(hard_failure_status(), PAM_AUTH_ERR);
        // Both PAM implementations number PAM_ABORT 26, and neither numbers
        // it the same as its own PAM_AUTHINFO_UNAVAIL: a hard fault can never
        // be mistaken for the fall-through-to-password status.
        assert_eq!(PAM_ABORT, 26);
        assert_ne!(hard_failure_status(), PAM_AUTHINFO_UNAVAIL);
        assert_ne!(hard_failure_status(), PAM_SUCCESS);
    }

    /// The insecure-helper-path refusal reaches the same mapping, through
    /// `HelperPathStatus::Insecure` -> `HelperOutcome::Failure`.
    #[test]
    fn an_insecure_helper_path_returns_the_fail_closed_status() {
        let calls = Cell::new(0);
        let mut handle = FakeHandle::new();
        let status = match HelperPathStatus::Insecure {
            HelperPathStatus::Valid => unreachable!(),
            HelperPathStatus::Unavailable => HelperOutcome::Unavailable,
            HelperPathStatus::Insecure => HelperOutcome::Failure,
        };
        assert_eq!(attempt(&mut handle, &calls, status), hard_failure_status());
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn an_unsupported_service_is_rejected_before_any_helper_runs() {
        let calls = Cell::new(0);
        let mut handle = FakeHandle::new();
        handle.items.insert(PAM_SERVICE, "login".to_owned());
        assert_eq!(
            attempt(&mut handle, &calls, HelperOutcome::Success),
            PAM_SERVICE_ERR
        );
        assert_eq!(calls.get(), 0);

        let mut missing = FakeHandle::new();
        missing.items.remove(&PAM_RUSER);
        assert_eq!(
            attempt(&mut missing, &calls, HelperOutcome::Success),
            PAM_AUTHINFO_UNAVAIL
        );
        assert_eq!(calls.get(), 0);
    }
}
