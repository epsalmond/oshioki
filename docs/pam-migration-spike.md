# Linux PAM migration spike

This is a disposable Ubuntu 24.04 characterization for issue 73. It does not
change production Rust, sudoers, or PAM configuration. Run it with:

```sh
scripts/test-pam-migration-spike
```

The container compiles `tests/pam-spike/pam_oshioki_spike.c` against
`libpam0g-dev` and installs it only in the container's private `sudo` service.
The service deliberately contains no `common-auth` include:

```text
auth [success=done authinfo_unavail=ignore default=die] pam_oshioki_spike.so ...
auth required pam_unix.so
```

The module reads a root-only mode file and records `PAM_SERVICE`, `PAM_USER`,
`PAM_TTY`, `PAM_RHOST`, `PAM_RUSER`, environment counts/marker presence, and
the module process command line. It never reads or records `PAM_AUTHTOK`.
The final synthetic executable records its effective uid, argv, environment
count, and selected sudo metadata. The PTY driver reads the fixture password
from a private file and types it only when sudo asks; it prints status markers,
never command output or password bytes.

The container run records these behaviors:

- A `NOPASSWD` rule for one helper bypasses PAM, while a separate `PASSWD`
  helper still follows the PAM service. A policy-denied command never reaches
  the final executable; the script records whether that sudo version called
  PAM before returning the policy result.
- `PAM_SUCCESS` with `success=done` approves the `PASSWD` command without a
  password conversation; account management and the final command still run.
- `PAM_AUTH_ERR` with `default=die` rejects the command even though the fixture
  has the correct password. The denial can cause sudo to retry PAM according
  to its configured authentication retry count; this run observed three
  auth calls.
- `PAM_AUTHINFO_UNAVAIL` with `ignore` continues to `pam_unix`, so the normal
  password prompt authenticates the command.
- A successful password auth is timestamped. A second command on the same
  PTY uses the timestamp and skips PAM. `sudo -k` invalidates it; `sudo -n`
  then fails without a prompt or PAM call under Ubuntu's default
  `noninteractive_auth` setting, while interactive sudo invokes PAM again.
- The PAM service sees sudo's pre-exec process context and has no final-exec
  argv callback. The final probe records the argv and environment after sudo
  has selected the command. The emitted metadata files provide the concrete
  values for this image and version without recording secrets. This run
  observed `PAM_SERVICE=sudo`, `PAM_USER=fixture`, `PAM_TTY=/dev/pts/0`,
  `PAM_RHOST` empty, and `PAM_RUSER=fixture`; the module process command line
  was `sudo /usr/local/bin/pam-spike-pass unavailable`. The PAM environment
  list was empty and the process environment had 12 entries, while the final
  probe ran as `euid=0` with the synthetic argv and 13 environment entries.

This spike intentionally does not propose changing Oshioki's production PAM
stack or sudoers defaults. In particular, it does not enable
`noninteractive_auth`, install a module on a host, or treat process argv/env
as a substitute for the signed request and the final execution environment.
