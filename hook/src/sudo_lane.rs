//! The privileged sudo verbs (`check`, `authenticate`) run as root on behalf
//! of an unprivileged caller. Nothing of that caller's environment may steer
//! them: not the config directory, not curl's config file or CA and proxy
//! variables, not TLS key-log paths, not the working directory.
//!
//! The sudo plugin and the PAM module both start the hook in `/` with a fixed
//! (or empty) environment. This module is the hook's own guarantee, so a
//! future caller that forgets to do that is still safe: before any thread
//! exists, a sudo-lane hook whose environment is anything but the fixed one
//! replaces itself with a clean copy of itself, once. The workspace denies
//! `unsafe`, which rules out clearing the environment in place.

use std::ffi::OsString;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

/// The only caller-facing variable a sudo-lane hook keeps. Every executable
/// it starts is named by absolute path; this is a floor for libraries, not a
/// search path the hook depends on.
pub const PATH: &str = "/usr/bin:/bin";

/// Set on the one re-exec. A process that carries it has already been
/// restarted, so a still-unclean environment is refused rather than
/// restarted again.
pub const REEXEC_MARKER: &str = "OSHIOKI_SUDO_LANE_REEXEC";

static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Whether this process is serving a sudo verb. Set once, before the async
/// runtime starts.
pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// Marks the process as serving a sudo verb without touching its
/// environment. [`enter`] is the production entry point.
pub fn activate() {
    ACTIVE.store(true, Ordering::Relaxed);
}

/// What [`enter`] does with the environment it was given.
#[derive(Debug, PartialEq, Eq)]
pub enum Entry {
    /// Already the fixed environment: run.
    Proceed,
    /// Anything else, first time: re-exec with the fixed environment.
    Reexec,
    /// Anything else after the re-exec already happened: refuse.
    Refuse,
}

/// Enters the sudo lane: marks the process, moves to `/`, and re-executes
/// the hook once with only the fixed environment when the inherited one
/// holds anything else. Must run before any other thread exists. Returns
/// only when the environment is already clean or the re-exec could not
/// happen; a failure is reported as approval-unavailable so the password
/// path stays eligible.
pub fn enter() -> anyhow::Result<()> {
    activate();
    // Best effort: "/" is always present, and every hook path is absolute.
    let _ = std::env::set_current_dir("/");
    let error = match classify(std::env::vars_os()) {
        Entry::Proceed => return Ok(()),
        Entry::Refuse => {
            return Err(super::approval_unavailable(
                "the sudo helper still has a caller environment after restarting",
            ));
        }
        Entry::Reexec => match std::env::current_exe() {
            Ok(executable) => clean_command(&executable, std::env::args_os()).exec(),
            Err(error) => error,
        },
    };
    Err(super::approval_unavailable(format!(
        "could not restart the sudo helper with a clean environment: {error}"
    )))
}

/// The environment is clean when it is empty (the PAM module's contract),
/// exactly `PATH=`[`PATH`] (the sudo plugin's), or that plus the
/// [`REEXEC_MARKER`] (this module's own re-exec).
pub fn classify(vars: impl IntoIterator<Item = (OsString, OsString)>) -> Entry {
    let mut path = false;
    let mut marker = false;
    let mut other = false;
    for (name, value) in vars {
        if name == "PATH" && value == PATH && !path {
            path = true;
        } else if name == REEXEC_MARKER && value == "1" && !marker {
            marker = true;
        } else {
            other = true;
        }
    }
    let clean = !other && (path || !marker);
    if clean {
        Entry::Proceed
    } else if marker {
        Entry::Refuse
    } else {
        Entry::Reexec
    }
}

/// `executable` with the given argv (argv\[0\] kept), an environment of only
/// [`PATH`] and [`REEXEC_MARKER`], and `/` as its working directory.
/// Standard streams and any inherited descriptor without close-on-exec (the
/// PAM liveness fd) carry over unchanged.
pub fn clean_command(executable: &Path, args: impl IntoIterator<Item = OsString>) -> Command {
    let mut args = args.into_iter();
    let mut command = Command::new(executable);
    if let Some(arg0) = args.next() {
        command.arg0(arg0);
    }
    command
        .args(args)
        .env_clear()
        .env("PATH", PATH)
        .env(REEXEC_MARKER, "1")
        .current_dir("/");
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(entries: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        entries
            .iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value)))
            .collect()
    }

    #[test]
    fn only_the_empty_or_fixed_environment_counts_as_clean() {
        assert_eq!(classify(pairs(&[])), Entry::Proceed);
        assert_eq!(classify(pairs(&[("PATH", PATH)])), Entry::Proceed);
        assert_eq!(
            classify(pairs(&[("PATH", PATH), (REEXEC_MARKER, "1")])),
            Entry::Proceed
        );
        assert_eq!(
            classify(pairs(&[("PATH", "/tmp/evil:/usr/bin")])),
            Entry::Reexec
        );
        assert_eq!(classify(pairs(&[("CURL_HOME", "/tmp")])), Entry::Reexec);
        assert_eq!(
            classify(pairs(&[("PATH", PATH), ("PATH", PATH)])),
            Entry::Reexec
        );
        assert_eq!(
            classify(pairs(&[
                ("PATH", PATH),
                ("OSHIOKI_CONFIG_DIR", "/tmp/attacker"),
            ])),
            Entry::Reexec
        );
    }

    #[test]
    fn an_unclean_environment_after_the_reexec_is_refused_not_restarted() {
        assert_eq!(
            classify(pairs(&[
                ("PATH", PATH),
                (REEXEC_MARKER, "1"),
                ("CURL_HOME", "/tmp/attacker"),
            ])),
            Entry::Refuse
        );
        assert_eq!(classify(pairs(&[(REEXEC_MARKER, "1")])), Entry::Refuse);
        assert_eq!(
            classify(pairs(&[(REEXEC_MARKER, "1"), ("PATH", "/tmp/evil")])),
            Entry::Refuse
        );
    }

    #[test]
    fn clean_command_drops_the_caller_environment_and_directory() {
        // The re-exec target swapped for env(1), run with this test's own
        // ordinary environment: only the fixed variables may arrive, and
        // they must classify as clean so the restarted hook proceeds.
        let output = clean_command(Path::new("/usr/bin/env"), [OsString::from("env")])
            .output()
            .expect("run env");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let mut lines = stdout.lines().collect::<Vec<_>>();
        lines.sort_unstable();
        let marker = format!("{REEXEC_MARKER}=1");
        let path = format!("PATH={PATH}");
        assert_eq!(lines, [marker.as_str(), path.as_str()]);
        let received = lines.iter().map(|line| {
            let (name, value) = line.split_once('=').unwrap();
            (OsString::from(name), OsString::from(value))
        });
        assert_eq!(classify(received), Entry::Proceed);

        let output = clean_command(
            Path::new("/bin/sh"),
            ["sh", "-c", "pwd"].map(OsString::from),
        )
        .output()
        .expect("run pwd");
        assert_eq!(String::from_utf8_lossy(&output.stdout), "/\n");
    }
}
