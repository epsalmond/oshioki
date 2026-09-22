# Contextual sudo PAM contract

This crate connects sudo's PAM authentication to `oshioki authenticate`.
For installation and the user-visible mode comparison, see
[local sudo](../docs/local-sudo.md#sudo-authentication-through-pam).
This page is the implementation contract.

The installer edits only recognized service-specific sudo PAM layouts.
It does not change `common-auth` or run `pam-auth-update`. Migration remains
opt-in and requires a working hardware-backed device.

## Boundary and identity

The module exports `pam_sm_authenticate` and `pam_sm_setcred`; the latter
returns success without changing credentials. Only `sudo` and `sudo-i`
services are accepted, and effective UID must be 0.

`PAM_USER` is the principal being authenticated. `PAM_RUSER` is the invoking
user; sudo's `rootpw`, `targetpw`, and `runaspw` policies can make them differ.
The module passes names and the helper resolves them inside its bounded work.
It does not substitute the environment or `getuid()` for PAM identity.

The module reads neither `PAM_AUTHTOK` nor the PAM conversation, and does not
start another sudo/PAM operation. Module arguments cannot alter the helper path.
It captures service, optional tty, and process PID, but not `PAM_RHOST`.
Submitted argv is advisory context, not a verified final command or environment.

## Private helper protocol

The fixed invocation is:

```text
/usr/local/sbin/oshioki authenticate --pam-protocol-version 2 --pam-liveness-fd N
```

The module checks every directory from `/` through `/usr/local/sbin` for root
ownership and no group/other write permission. The helper must be a root-owned
regular executable, with no group/other write permission or setuid/setgid bits.
Local path checks precede the helper deadline.

The child starts in `/` with an empty environment, standard pipes, and one
liveness descriptor. The module writes one UTF-8 JSON request and closes stdin:

| Field | Meaning |
| --- | --- |
| `pam_protocol_version` | `2`; there is no version-1 compatibility shim. |
| `principal: {name}` | Account from `PAM_USER`. |
| `invoking: {name}` | Account from `PAM_RUSER`. |
| `service` | `sudo` or `sudo-i`. |
| `tty` | Nonempty tty or `null`. |
| `process_pid` | PID of the PAM process collecting context. |
| `submitted_argv: {available, truncated, values}` | Advisory UTF-8 process arguments, with explicit completeness flags. |

Bounds:

| Input/output | Limit |
| --- | --- |
| Identity names / service | 256 / 32 bytes |
| Other PAM text | 4096 bytes |
| Submitted argv | 64 values, 4096 raw bytes |
| Serialized request | 16 KiB after escaping; trim advisory argv with 1 KiB headroom |
| Helper stdout / stderr | 16 KiB / 8 KiB |
| Helper execution | 90 seconds |

Trimming sets `truncated` without changing `available`. Large advisory argv
alone cannot fail authentication. Stdout may contain only ASCII whitespace;
the exit status is the result. Stderr is bounded and discarded, so this channel
does not display progress or an approval URL.

## Results and cancellation

| Helper outcome | PAM result |
| --- | --- |
| Exit 0, valid output | `PAM_SUCCESS` |
| Exit 2; spawn failure; timeout; cancellation | `PAM_AUTHINFO_UNAVAIL` |
| Other exit/signal, malformed output, insecure path, security failure | `PAM_AUTH_ERR` |

A secure helper path that cannot be executed is unavailable; failing the path's
ownership/mode checks is a hard failure.

Installed controls differ by platform:

- Linux uses `[success=done authinfo_unavail=ignore module_unknown=ignore ignore=ignore default=die]`.
  Unavailability continues to the password path; hard failures stop it.
- macOS uses `auth sufficient` in `sudo_local`. Both unavailability and
  `PAM_AUTH_ERR` can continue to the stock password provider. A device failure
  is never authentication success; a subsequent password can authenticate.

There is no remote signed Deny action for this operation. Cancellation,
dismissal, timeout, or no decision are unavailable. Invalid signatures,
identity/purpose mismatches, replay, malformed data, and truncated frames are
failures. A clean connection close after acknowledgement produced no decision
and leaves fallback possible; receiving invalid decision bytes does not.

## Process lifetime

The helper gets its own process group via `setpgid`, retaining sudo's session.
The module kills all group members on completion, failure, and cancellation,
before reaping the leader so a recycled process-group ID cannot be targeted.

The PAM call owns the liveness pipe's only writer. EOF/readability tells the
helper that the call or sudo process is gone, including on macOS. Linux also
sets `PR_SET_PDEATHSIG(SIGKILL)`; rejecting setuid/setgid executables preserves
that behavior across exec.

Unrelated descriptors are marked close-on-exec in the forked child. Linux uses
`close_range`; macOS uses `proc_pidinfo` with a fixed buffer. The fallback
scans to the hard descriptor limit, capped at 2^20, so lowering the soft limit
does not hide an already open descriptor.

Sudo blocks SIGINT/SIGQUIT during PAM authentication. The module samples
`sigpending` every 25 ms; any pending cancellation counts, including one that
predates the wait. It installs no handlers and consumes no signals. Interrupted
pump operations also cancel, except for the helper's own exit notification.

In a terminal, Ctrl-C during a device wait returns unavailable and exposes the
normal password path; a second Ctrl-C ends sudo there. On macOS, a process that
inherited `SIG_IGN` can lose blocked SIGINT at generation. This affects
background/ignore-signal invocations during the module wait, not a normal
terminal sudo. Ctrl-Z suspends sudo normally; the wall-clock deadline continues.

## Retry state

A small record on the PAM handle binds the attempt to principal, invoking user,
service, tty, and process PID. Only an unavailable result is reused on the same
handle/context. Repeating success or failure returns `PAM_AUTH_ERR`; changing
context starts a new attempt. This suppresses duplicate device requests during
password retries without creating an authentication cache.

## Packaging

The helper and module must come from a matching release. The installer verifies
checksums, stages replacements, validates the stock stack, and supports status
and rollback. See [update and restore](../docs/update.md).

On macOS, `LC_ID_DYLIB` is set to the Homebrew `opt` path at link time so
bottling does not rewrite and re-sign the module after hashing.
`OSHIOKI_PAM_INSTALL_NAME` supports a different build prefix.
OpenPAM loads the absolute configured path; this install name does not redirect it.

## Verification and limits

Focused checks:

```sh
cargo test --locked -p oshioki-pam
cargo clippy --locked -p oshioki-pam --all-targets -- -D warnings
cargo fmt -p oshioki-pam -- --check
scripts/test-install-oshioki-hook
scripts/test-pam-acceptance
```

Tests cover schema/bounds, result mapping, secure path checks, blocked writes,
bounded output, descriptor inheritance, parent death, cancellation, cleanup of
descendants after both success and failure, ABI exports, and per-handle retry
state. Fake PAM handles do not prove real system-stack behavior.

Recorded supervised Linux and macOS sessions exercised native Secure Enclave
authentication, password recovery, status, rollback, baseline timestamps, and
terminal cancellation. Those observations are not validation of future builds
or every PAM layout.

Remaining acceptance scope includes browser WebAuthn through real PAM,
additional OS/service layouts, custom authentication/account/session stacks,
MFA and lockout variants, and advanced timestamp/principal policies.
Keep migration opt-in; the installer intentionally refuses custom layouts.
