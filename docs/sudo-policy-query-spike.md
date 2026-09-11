# Sudo policy-query spike

This is a disposable Ubuntu 24.04/aarch64 characterization of a possible
policy-query helper. It is deliberately not a production change. Run it with:

```sh
scripts/test-sudo-policy-query
```

The runner starts an Ubuntu 24.04 container with a 64-process limit, installs
`sudo` and `gcc`, downloads the official `sudo_plugin.h` from the
`SUDO_1_9_15p5` tag, and verifies its SHA-256 before compiling the test-only
approval plugin. The plugin uses the approval ABI's `open` and `check`
callbacks, invokes `/usr/bin/sudo` by `execve` with explicit arguments
(`-nkll`, `-U <original user>`, `-u #<runas uid>`, optional `-g #<runas gid>`,
`--`, and the exact `run_argv`), and sets a fixed `LC_ALL=C`, `LANG=C`, and
`PATH`. The child is normalized to uid/gid 0 with no supplementary groups,
and its actual IDs are recorded.

The plugin captures at most 8 KiB of query output, escapes control bytes, logs
bounded synthetic metadata, and records an UNKNOWN/DENY result for every
request. It never authorizes a command. A marker in the query child's
environment would cause `open` to log `nested_open` and fail with the
approval ABI's fatal `-1` result; a positive control observed exactly that
failure with no `check` callback and no target execution. The successful
listing cases observed one outer `check`, zero nested opens, and zero runs of
the final synthetic command. This proves that `sudo -nkll` listing did not
recursively enter the approval `check` callback in this image.

The outer container uses a private `sudo` PAM service containing only
`pam_permit`, solely so PASSWD cases reach the approval callback without a
real password. That fixture does not characterize host authentication. The
query child itself remains `-n` and read-only.

Observed on sudo 1.9.15p5:

- Explicit NOPASSWD listed `Options: !authenticate`; explicit PASSWD listed
  `Options: authenticate`. Both reached the approval callback and were denied
  by the test plugin.
- `Defaults:fixture !authenticate` with an untagged command reached the
  callback, but the listing omitted an `Options:` line entirely. Defaults are
  therefore not reliably recoverable from one text listing.
- An alias with the allowed argument reached the callback; a mismatched
  argument and an explicit negation were rejected by sudo before the approval
  callback.
- Two same-command entries produced the last entry's
  `Options: authenticate` in the listing. A real alternate runas request
  recorded `other` and `spikegroup` plus their numeric uid/gid, and the
  root query child ran with uid, euid, gid, egid 0 and zero supplementary
  groups.
- A root listing for forbidden `/usr/bin/id` succeeded while the fixture
  identity listing returned status 1. Querying as root can therefore produce a
  false positive for the original caller.
- `listpw=always` made the commandless fixture `sudo -nkll` return 1;
  `listpw=never` returned 0. A successful commandless listing status is only a
  listing result. A command-specific status 0 reports that sudo's policy
  allowed the supplied context, but it does not report whether authentication
  is required.
- With a specific PASSWD entry early and a blanket NOPASSWD rule late, the
  query selected the late `/etc/sudoers.d/90-sudo-query` blanket entry and
  `RunAsUsers: ALL`. Reversing the files selected the late specific entry and
  `RunAsUsers: root` with `Options: authenticate`.
- An argv element containing a leading newline and fake indented
  `Options: !authenticate`/`Matched:` lines was logged as escaped
  `\\x0a` data. It remained UNKNOWN/DENY and never ran the target, so a naive
  line search would be unsafe.

The result is a feasibility boundary. Sudo's listing text is useful evidence
for diagnostics, but this spike found no reliable effective-authentication-
required bit to feed an approval decision. Output can be missing, ambiguous,
nonzero, or version-dependent; the test plugin treats every such condition as
UNKNOWN and denies. It also does not recreate all final execution state: the query
does not carry the complete post-policy environment, working directory,
`sudo -P` behavior, chroot, SELinux/AppArmor labels, setuid/setgid details,
editor resolution, I/O/intercept settings, or later sudo policy hooks.

The query must bind the exact original username and requested numeric runas
ids. Using root as the listing identity is demonstrably broader than the
fixture identity. The spike does not change production sudoers/PAM defaults,
enable `noninteractive_auth`, install a module on a host, or claim that
listing output can replace signed command and environment authorization.
