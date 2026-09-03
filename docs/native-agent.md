# Native agent

A native device signs approvals directly with a P-256 key instead of using a
browser and WebAuthn. Enroll one from the host:

```bash
oshioki enroll
```

`enroll` prints an enrollment URL and, below it, the `oshioki-agent` command
that consumes it. On the device:

```bash
oshioki-agent pair '<enrollment-url>' --label <label>
oshioki-agent run
```

`pair` creates a 0600 identity file (`agent.json`, under
`$OSHIOKI_AGENT_STATE` or `~/.config/oshioki` by default) on first use, then
submits the enrollment and waits for the host to activate it. On a Mac the
signing key is created in the Secure Enclave; everywhere else it is a P-256
key in that file. `pair --signer software` forces the software key on a Mac
too, which is what the tests use. On a Mac the file holds only a keychain
reference for the X25519 box secret, which lives in the login keychain;
anywhere else the file carries the secret itself. Pre-move files migrate on
first load, keeping the fingerprint.

One identity serves every host this device pairs with, so pairing again
reuses it. A `--signer` that disagrees with the identity already there is an
error. `pair --force` replaces the
identity: the device gets a new fingerprint, every host it had paired with
needs a new enrollment, and their old records should be revoked. `show` prints the fingerprint and which of
the two backends this device has.

`run` watches for sudo requests and prompts. A release build has no way
to skip the prompt: `run --auto approve` and `run --auto deny`, which decide
every request without asking, exist only when the agent is built with
`--features unattended`, as the Compose E2E does.
The terminal prompt and the browser page render the same request: the host, the
invoking user with their uid, the target account the command would run as
(`root (uid 0)` for sudo's default, otherwise the bare uid), the command, its
arguments, the working directory, and the caller process chain. An argument
that is empty or holds anything but plainly printable characters is shown in
shell single quotes, so one argument holding a space never reads as two.
A prompt nobody answers before the request expires publishes no verdict at
all, and the hook fails closed on its own deadline. The terminal prompt needs
a terminal: with stdin closed nothing could answer, so `run` stops rather than
leaving every request to time out. A Mac with an enclave key reads no stdin
and does not check this.

`enroll` pins the device locally and then confirms the server stored it by
reading `GET /api/v1/devices/<fingerprint>` back over HTTPS for up to fifteen
seconds. If that confirmation times out, the device is still pinned and can
approve sudo on the host; only the server's copy is unknown. The error says
so, and the fix is another `oshioki enroll` for that device once the server
is reachable.

The agent needs the same `NATS_URL` as the hook, plus `NATS_USER` and
`NATS_PASS` together where the server wants credentials; setting only one of
the pair is an error.

For the enrollment wire format, see [architecture.md](architecture.md).
For Mac Touch ID behavior, see [mac-approvals.md](mac-approvals.md).
