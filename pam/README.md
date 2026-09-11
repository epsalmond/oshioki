# Oshioki PAM foundation

This crate is the first PAM-to-helper boundary for contextual sudo
authentication. It is foundation work, not a completed PAM migration and not
an installable release. The helper verb used by this module is not implemented
in the current `/usr/local/sbin/oshioki` binary, so enabling this module on a
host would not provide authentication.

There is currently no PAM installer, package integration, or `/etc/pam.d`
recipe. In particular, this crate does not modify `common-auth`, invoke
`pam-auth-update`, or claim a supported automatic change to a sudo PAM stack.
The platform layouts, staged installation, upgrade, rollback, and recovery
workflow remain deferred until the helper and stack contract are complete.

## PAM boundary

The module exports the standard `pam_sm_authenticate` and `pam_sm_setcred`
entry points for Linux-PAM and macOS OpenPAM. `pam_sm_setcred` has no
credential side effect and returns success. The module accepts only these PAM
services:

| PAM service | Support |
| --- | --- |
| `sudo` | supported by the boundary |
| `sudo-i` | supported by the boundary |
| anything else | rejected with `PAM_SERVICE_ERR` |

Authentication also requires the PAM process to have effective UID 0. The
module never reads `PAM_AUTHTOK`, prompts through the PAM conversation, or
starts another PAM or sudo operation. PAM module arguments are ignored and
cannot replace the fixed helper path.

The principal is `PAM_USER`, the account sudo is authenticating. The invoking
identity is `PAM_RUSER`; it is kept separate because sudo can authenticate a
different account under `rootpw`, `targetpw`, or `runaspw`. The module sends
both **names** and does not resolve them itself. Name resolution is NSS work:
`getpwnam_r` can block for an unbounded time on a stalled directory service,
and it would run before the module's helper deadline exists. The helper already
runs as root, so it resolves both names inside its own bounded budget and
decides what an unknown name means. The module does not substitute an
environment value, `getuid()`, or `PAM_USER` for `PAM_RUSER`. Missing, empty,
or invalid identity text still makes device authentication unavailable or fail
according to the specific validation result.

The current boundary captures `PAM_SERVICE`, optional `PAM_TTY`, and the PAM
process PID. It does not currently capture `PAM_RHOST`. The submitted process
argument vector is advisory context: it is UTF-8 text from the module process,
with explicit availability and truncation flags. It is not a verified final
sudo command, executable, argument vector, or environment.

## Private helper interface

The module always starts:

```text
/usr/local/sbin/oshioki authenticate --pam-protocol-version 2 --pam-liveness-fd N
```

The path and argument list are private implementation details. No PAM option
can override them. `N` is the only non-standard descriptor the helper
inherits: the read end of a pipe whose write end is held solely by this PAM
call. Readability or EOF on that descriptor means the PAM call, or the whole
sudo process, is gone, and the helper must exit and take its own descendants
with it. That is the portable half of the cancellation contract; on Linux the
module additionally arms `PR_SET_PDEATHSIG(SIGKILL)` in the child so the
helper leader dies with the PAM thread even when no destructor runs.

Before starting the helper, the module requires `/`, `/usr`, `/usr/local`, and
`/usr/local/sbin` to be root-owned and free of group/other write permission.
The helper must also be a root-owned executable regular file with no
group/other write permission **and no setuid or setgid bit**. A
credential-changing `execve` clears `PR_SET_PDEATHSIG` on Linux, which would
silently disable the parent-death half of the cancellation contract above, so
such a helper is rejected rather than run. These are local `lstat` calls on a
fixed path.
They involve no network or directory service, and they deliberately run
**before** the helper deadline starts, so they are not covered by it.

The child runs with working directory `/`, an empty environment, and only its
standard pipes plus the liveness descriptor retained. It calls `setpgid(0, 0)`,
not `setsid()`: its own process group is what lets the module kill the whole
helper tree with `kill(-pgid)`, while staying in sudo's session keeps the
controlling terminal reachable for a future progress channel and keeps hangup
signals meaningful. The cost of that separate group is that a terminal
`SIGINT` goes to sudo's foreground group and never reaches the helper; the
cancellation rule below closes that gap in the module instead. Unrelated descriptors are removed in the forked child
between fork and exec, so no pre-spawn snapshot is taken and a descriptor
opened concurrently with the spawn cannot be missed. Linux uses
`close_range(3, ~0, CLOSE_RANGE_CLOEXEC)`; macOS asks the kernel for the exact
open list with `proc_pidinfo(PROC_PIDLISTFDS)` into a fixed stack buffer,
because allocating after fork is not async-signal-safe. Both fall back to a
scan bounded by the **hard** `RLIMIT_NOFILE` (clamped to 2^20), so an
already-open descriptor above a lowered soft limit is still covered.
Descriptors are marked close-on-exec rather than closed, which keeps Rust's
private exec-error pipe usable until exec succeeds.

The module writes one UTF-8 JSON request to standard input and closes the
pipe to frame the request. The current fields are:

| Field | Type | Meaning |
| --- | --- | --- |
| `pam_protocol_version` | number | Always `2` for this private boundary. |
| `principal` | `{name}` | `PAM_USER`; the helper resolves it. |
| `invoking` | `{name}` | `PAM_RUSER`; the helper resolves it. |
| `service` | string | `PAM_SERVICE`, currently `sudo` or `sudo-i`. |
| `tty` | string or `null` | Non-empty `PAM_TTY`, when available. |
| `process_pid` | number | PID of the PAM process collecting the request. |
| `submitted_argv` | `{available, truncated, values}` | Advisory UTF-8 arguments observed by the PAM process. |

An example request is:

```json
{"pam_protocol_version":2,"principal":{"name":"alice"},"invoking":{"name":"alice"},"service":"sudo","tty":"/dev/ttys001","process_pid":123,"submitted_argv":{"available":false,"truncated":false,"values":[]}}
```

Version 2 replaced version 1's resolved `uid` fields with names only, for the
reason given above. There is no version 1 helper in the shipping binary, so no
compatibility shim exists for it.

The request and helper output are bounded. Names and service text are capped
at 256 and 32 bytes respectively; other PAM text is capped at 4096 bytes.
The submitted arguments are capped at 64 values and 4096 aggregate raw bytes.
The serialized request is capped at 16 KiB, measured **after** JSON escaping:
a legitimate Unix argument of control bytes expands about six times when
escaped, so the raw argv cap alone cannot bound the request. The module
therefore serializes, measures, and drops advisory arguments from the end
until the request fits with 1 KiB of headroom, setting `truncated` as it does
so. `available` keeps its captured meaning (the argv was readable), so a fully
trimmed request is `available: true, truncated: true, values: []`.
Authentication never fails merely because the process argument vector was
large. Helper stdout is capped at 16 KiB and stderr at 8 KiB.

The helper has no JSON response body. Its stdout may contain only ASCII
whitespace. Any other stdout bytes, an over-limit stream, an I/O error, an
invalid helper path, or a non-success security check is not an authentication
success. Helper stderr is consumed within its bound and currently discarded;
it is not forwarded to the terminal or system log by this module.

## Result and retry contract

The helper exit status is the decision channel:

| Helper result | PAM result | Meaning |
| --- | --- | --- |
| exit `0` | `PAM_SUCCESS` | Device authentication accepted. |
| exit `2` | `PAM_AUTHINFO_UNAVAIL` | Device authentication is unavailable; the surrounding PAM stack may continue its normal password path. |
| any other exit, signal, malformed output, or security failure | `PAM_AUTH_ERR` (Linux) / `PAM_ABORT` (macOS) | Authentication did not succeed. |

The hard-failure status is platform-dependent because the two PAM
implementations express "stop here, fail closed" differently. On Linux the
installer writes a bracket control
(`auth [success=done authinfo_unavail=ignore module_unknown=ignore ignore=ignore default=die]`),
so `PAM_AUTH_ERR` falls under `default=die` and denies the command. OpenPAM
has no bracket controls: the macOS entry is
`auth sufficient /usr/local/lib/pam/liboshioki_pam.dylib` in
`/etc/pam.d/sudo_local`, and under `sufficient` a `PAM_AUTH_ERR` is merely
recorded and ignored — evaluation would continue into `pam_opendirectory` and
a typed password would authorise the command, silently erasing the refusal.
`PAM_ABORT` (26 in both implementations) is the one status OpenPAM honours as
an immediate abort of the whole chain, so macOS returns it for exactly the
cases Linux dies on: a refused helper path, malformed helper output, and a
repeat call on a handle that already has a result. The unavailable path is
unchanged on both platforms.

**This macOS mapping is unvalidated on hardware.** It is covered only by
`a_hard_fault_maps_to_the_platform_fail_closed_status` in `pam/src/lib.rs`,
which asserts the constant, not OpenPAM's reaction to it. If supervised Mac
validation shows that `PAM_ABORT` under `sufficient` does not abort the
chain, the fallback is to keep plain `PAM_AUTH_ERR` and document the
asymmetry rather than to change the control word.

Any failure to start the helper, and the bounded 90-second helper deadline,
are classified as unavailable, never as a hard authentication failure. That
covers a missing executable, a permission error, and transient conditions such
as the `ETXTBSY` window of a package upgrade or a temporary resource shortage:
none of them are evidence about the operator, and treating them as denials
would lock people out of sudo. Whether the helper path is acceptable at all is
a separate decision, made by the path checks above.

The deadline starts when the helper is spawned and covers every part of the
exchange that can block on the helper: the request write, both output reads,
and the wait for exit. Once the helper's leader exits, its output is drained
under a short grace period measured from that exit rather than from the
deadline, so a helper that succeeds in the last millisecond of its budget is
still read and still succeeds. It is a helper deadline, not a whole-call
bound: the
preceding PAM item reads and the local path stats are outside it, and the
module therefore does not claim a bound on the entire `pam_sm_authenticate`
call. On expiry the module closes the liveness pipe and kills the helper
process group; when the leader exits normally it kills the group and the
liveness write end is released when the call's guard drops. Either way the
helper tree does not outlive the call. The group is always signalled while the
leader is still an unreaped zombie, because a reaped leader's process-group ID
can be recycled and the signal could then reach an unrelated group;
final stack fallback behavior still depends on the administrator's sudo PAM
controls. The helper verb is not yet present in the shipping hook, so this
table is a private foundation contract rather than an enabled product flow.

## Cancellation

The terminal user can abort a sudo that is waiting on a device with `Ctrl-C`,
and that abort is cancellation: `PAM_AUTHINFO_UNAVAIL`, never a success and
never a hard failure. The surrounding stack then takes its normal password
path, exactly as it would for a helper timeout, so the operator's *next*
`Ctrl-C`, at the password prompt, ends sudo the same way it ends a stock one.
The delay is bounded by the module's poll interval — 25 ms — plus the cost of
killing and reaping the helper tree, because the pending set is sampled once
per iteration.

The module cannot be signalled directly. The helper is in its own process
group, so the terminal delivers `SIGINT` only to sudo. What sudo does with it
was measured, not assumed: while the module is waiting,
`/proc/<sudo>/status` reports

```text
SigBlk: ...1006     SIGINT, SIGQUIT (and this module's own SIGPIPE) blocked
SigIgn: ...1006     SIGINT, SIGQUIT ignored
SigCgt: ...096a01   neither of them caught
```

sudo blocks *and* ignores both signals for the whole authentication phase and
installs catching handlers only inside `tgetpass`, around its own password
prompt. That is why a stock stack ends at `Ctrl-C` and why this module's wait
did not. Two consequences follow, and together they decide the design:

* **`EINTR` never happens.** A blocked signal interrupts no syscall, so a rule
  that only watched for interrupted syscalls would observe nothing at all
  while the operator typed `Ctrl-C`.
* **`sigpending` sees everything.** Linux deliberately does not discard a
  *blocked* signal even when its disposition is `SIG_IGN`, because the handler
  may change before it is unblocked. A typed `Ctrl-C` therefore sits in the
  process-pending set for exactly as long as sudo holds it blocked — the whole
  of this wait.

So the module samples its own pending set once per poll interval and treats a
pending `SIGINT` or `SIGQUIT` as cancellation: it aborts the helper process
group and returns unavailable. `sigpending` is a read. Nothing is installed,
nothing is consumed, and sudo's signal state is untouched — the signal is
still pending when the module returns and sudo applies its own disposition to
it on unblock, exactly as it would have.

**Any** pending cancellation signal counts, including one that was already
pending when the wait began, and there is deliberately no baseline sample to
subtract. Standard signals do not queue: a second `Ctrl-C` merges into a bit
that is already set, so nothing ever *transitions*. A rule that waited for a
transition would make every later keystroke invisible for the whole
90-second budget — the original defect, reintroduced through the back door.
Cancelling on a signal someone else left pending costs one password prompt,
which is precisely the error budget this module already declares for
unavailability; missing a real `Ctrl-C` costs the operator their terminal.

A second, weaker rule covers the signals sudo *does* catch in this phase.
Measured on the same stack, `SigCgt` covers `SIGHUP`, `SIGUSR1`, `SIGUSR2`,
`SIGALRM`, `SIGTERM`, `SIGCHLD` and `SIGTSTP`; for those, **every interrupted
syscall in the helper pump loop is also cancellation**. `poll`, the bounded
request write, the output reads, and the `waitid` that asks whether the leader
has exited all report `EINTR` upward rather than retrying or answering "not
yet", so no signal can be swallowed by a retry.

One benign interrupt is excluded: `SIGCHLD` raised by the helper's *own* exit.
Before cancelling, the module re-checks whether the leader has exited, and if
it has, the loop continues and reads the exit status normally, so a successful
helper is never turned into a cancellation by its own death.

Everything else in that list means this sudo is going away, being suspended,
or timing out. `SIGTSTP` is worth stating plainly: **`Ctrl-Z` during a device
wait cancels rather than suspends**, so the operator gets a password prompt
instead of a stopped sudo holding a device prompt and a live helper tree. That
is the intended outcome, and it is a consequence of the rule rather than
something the container suite exercises. `SIGWINCH` is *not* in the list —
sudo leaves it at its default in this phase, so a terminal resize cannot
cancel. Being wrong in this direction costs one password prompt, never a
success and never a hard failure.

A leader that has been *stopped* rather than exited is not a special case:
the module asks `waitid` only about exits, so a suspended helper reads as
still running and the helper deadline eventually classifies it as unavailable
and kills the group, which is the right answer for a helper that has not
authenticated anything.

Two alternatives were rejected. **Installing the module's own `SIGINT` handler**
for the length of the wait would work (the signal would be delivered on
unblock, or caught outright), but a PAM module loaded into someone else's
process should not be taking over the host's signals and then handing them
back; `sigpending` answers the same question by reading state that already
exists. **Leaving the helper in sudo's foreground process group** so the signal
reaches it directly would not even deliver: sudo blocks and ignores `SIGINT`
here, and both the blocked mask and an ignored disposition survive `fork` and
`execve`, so the helper would inherit the same deafness. It would also give up
the guaranteed `kill(-pgid)` of grandchildren the module never learned about
(the only portable mechanism on macOS, which has no `PR_SET_PDEATHSIG`), hand
the helper every other terminal signal including a `SIGTSTP` that could suspend
it mid-authentication, and turn cancellation into a signal-killed helper, which
the exit rules above classify as a hard `PAM_AUTH_ERR`.

## Denials and evidence

There is no remote Deny action or signed denial result in this boundary. A
helper that returns unavailable represents cancellation, dismissal, timeout,
or unavailable transport once the Authenticate verb is implemented. Invalid
signatures, wrong identity, wrong purpose, replay, expiry, malformed data,
and other security failures must not be converted into a successful
authentication.

The line between the two is whether decision bytes arrived. An agent that
acknowledges a request over the local socket and then drops the connection —
a crash, a restart, a killed connection — produced no decision at all, so on
the authentication lane the helper exits 2 and the password path stays open.
A stack written as `default=die` would otherwise turn an agent restart into a
sudo that is denied with no password prompt. Bytes that do arrive and fail to
decode as an authentication decision remain a hard failure, including a legacy
command-approval decision delivered on the authentication lane: those are
evidence of a broken or hostile peer, and a dropped connection is not. A
*truncated* frame — a partial length prefix, or a payload shorter than the
length it announced — is on the hard-failure side for the same reason as
garbage bytes, so an agent that emits one stray byte and then hangs up costs
the operator the password path, where a clean hangup on a frame boundary does
not. The legacy command-approval lane deliberately keeps its own rule, where a
post-ack hangup fails closed and the command is simply not run.

The module stores a small state record on each PAM handle. It prevents a
password retry on the same handle from creating a duplicate device request,
and it binds the record to principal name, invoking name, service, TTY, and
process PID. A call whose context differs from the record starts a fresh
attempt rather than inheriting the earlier result, so a handle reused for a
different principal is a new transaction. Only `unavailable` is replayed to
later calls on the same handle and context; success and failure both answer
`PAM_AUTH_ERR` on a repeat. This is per-transaction bookkeeping, not an
Oshioki authentication cache: a previous device success is not reused as a
later PAM success, and state is released when PAM cleans up the handle.

## Validation status

The current foundation has direct tests for the private JSON shape and bounds,
the serialized-size trimming of advisory argv, the supported service and
identity fields in that private schema, helper exit classification, malformed
stdout, missing or insecure helper paths, the ownership and mode rule for each
path component (including a root-owned but group/world-writable path), the
90-second default budget, bounded and deterministically blocked writes,
bounded output, SIGPIPE handling, cancellation by a caught signal, and the
exported PAM ABI. The path rule table also covers setuid and setgid
rejection.

Seven of these exercise the process boundary directly: a helper timeout is
asserted to kill a grandchild the module never knew about; a *successful*
helper is asserted to do the same, which is what proves the group is signalled
before the leader is reaped (a debug assertion in `kill_group` enforces the
same invariant); the spawned helper is asserted to inherit the liveness
descriptor and no unrelated inheritable descriptor; a request larger than any
pipe buffer is asserted to hit the deadline and return unavailable rather than
blocking; and output is asserted to be drained even when the helper deadline
has already passed.

The seventh is cancellation, and it reproduces sudo's measured state rather
than a convenient one: `SIGINT` ignored process-wide and blocked on the
pumping thread, raised with `pthread_kill` so it can only become pending. The
wait is asserted to end as unavailable within two seconds with the helper's
grandchild dead. A second test covers the weaker `EINTR` rule with a no-op
`SIGUSR1` handler installed without `SA_RESTART`. A third raises the signal
*before* the wait starts and asserts it still cancels, which is what keeps the
no-baseline rule above from being quietly re-broken. Signal state is
process-wide, so all three hold the suite's exclusive spawn lock and restore
the previous disposition, mask, and pending signal from a `Drop` guard, so a
failing assertion cannot leak any of it into the rest of the suite.

The handle state machine (state ownership per handle, context change resetting
the record, retry suppression, unavailable reuse, and success never being
reused) is driven through a small `PamAccess` seam over `pam_get_item`,
`pam_get_data`, and `pam_set_data`, with an in-process fake handle. These
tests do not drive real PAM identity callbacks.

On Linux with `libpam0g-dev` installed, the focused module checks pass with
the toolchain selected by this repository's `rust-toolchain.toml`:

```sh
cargo test -p oshioki-pam              # 27 tests
cargo clippy -p oshioki-pam --all-targets -- -D warnings
cargo fmt -p oshioki-pam -- --check
cargo build -p oshioki-pam             # exports pam_sm_authenticate, pam_sm_setcred
```

The macOS-only paths (the `pam.2` link name, `proc_pidinfo` descriptor
listing, and the pipe-only parent-death channel) are type-checked with
`cargo check -p oshioki-pam --target aarch64-apple-darwin` and clippy for the
same target, but they have not been executed on macOS in this pass. This is
build, test and ABI evidence only; real PAM stack behavior on either operating
system has not been validated.

The `authenticate` helper verb exists in the hook: it reads this schema,
seals a request to the enrolled hardware devices, and verifies the returned
assertion. It now has consumers. The helper publishes on
`oshioki.auth.<host>`; the agent subscribes to `oshioki.auth.>` alongside
`oshioki.request.>` and answers with a Secure Enclave assertion, and the
server's durable handler stores an authentication envelope in its own lane
and serves it at `/a/<id>` for a `WebAuthn` browser. Neither lane has a
refusal: cancelling sends nothing, and sudo falls back to a password at the
helper's deadline. **None of this has been exercised against a real PAM
stack**, so the module still must not be enabled in a PAM configuration.

The following acceptance work remains open:

- an accepted hardware-backed device flow end to end against real hardware;
- real stock sudo/PAM stacks on Linux and macOS, including required account,
  session, MFA, lockout, `pam_tid`, smart-card, and password fallback behavior;
- native sudo timestamps, `sudo -k`/`-K`, `sudo -v`, `sudo -n`, alternate
  principals, and administrator-selected `noninteractive_auth`;
- known stock sudo-only service layouts, refusal of customized layouts,
  staged module/config installation, upgrade, uninstall, and rollback. The
  Linux half of this is now driven by `scripts/install-oshioki-hook
  --contextual-pam` and covered by `scripts/test-install-oshioki-hook` and
  `scripts/test-pam-acceptance`; the macOS half (`sudo_local`, `pam_tid`
  coexistence, `PAM_ABORT`, code signing) is not;
- diagnostic and progress forwarding. The current helper stderr channel is
  bounded and discarded, so no approval link or progress display should be
  inferred from this crate;
- supervised Linux, Mac, and NAS validation with a retained recovery path.

Until those items are complete, this module must not be enabled in a PAM
configuration or presented as a complete contextual sudo authentication
feature.
