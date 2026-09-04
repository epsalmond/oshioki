# Mac approvals

On a Mac the Touch ID sheet is the approval. The signing key lives in the
Secure Enclave behind `biometryCurrentSet`, so the signature cannot exist
without the fingerprint, and there is no second confirmation to give. The
sheet reads "Oshioki is trying to run `<command and arguments>` as
`<account>` on `<host>`. Touch ID to allow this." The arguments are there
because `rm` and `rm -rf /` are different requests, rendered the same way the
terminal prompt renders them. The working directory and the caller process
chain go to the log, where there is room for them.

```bash
scripts/mac/bundle-agent
oshioki-agent pair '<enrollment-url>' --label mbp
scripts/mac/install-agent
```

`bundle-agent` wraps the binary in an `Oshioki.app`, unsigned unless
`--sign` names a codesigning identity. The sheet takes
its title and icon from the calling process's bundle, so without it the sheet
shows the binary's file name and a generic badge. `install-agent` writes
`~/Library/LaunchAgents/dev.oshioki.agent.plist` and loads it. It runs as the
user, needs no sudo, and logs to `~/Library/Logs/oshioki-agent.log`.

Pairing signs an enrollment proof, so it shows one Touch ID sheet of its own.

Three timing rules sit around the sheet. Only one sheet is up at a time, so
two requests at once cannot race for the sensor. A locked screen raises no
sheet: the enclave reports a dismissed sheet and an absent operator
identically, and a sheet nobody sees would turn into a denial nobody made.
The request's deadline tears down a waiting sheet and publishes nothing, the
same rule the terminal prompt follows. Dismissing the sheet denies at once.

A key is bound to the fingerprints enrolled when it was made. Adding or
removing a fingerprint invalidates it for good. The agent logs that and asks
for a re-pair; it is not something a retry fixes. See
[re-pairing in the runbook](../RUNBOOK.md#re-pairing).

The X25519 key that opens sealed requests stays a software key: the enclave
holds P-256 and nothing else. On a Mac the secret itself lives in the login
keychain under the `dev.oshioki.agent` service and the 0600 identity file
keeps only its account name; anywhere else the file carries the secret
inline. A file from before the move still loads: the secret is copied into
the keychain and the file rewritten without it, keeping the fingerprint. If
the keychain entry is gone the agent says to re-pair with `--force`, which
also removes the replaced entry. `bundle-agent --sign` applies
`scripts/mac/Oshioki.entitlements`, whose keychain access group keeps the
secret reachable from the LaunchAgent daemon; the Team ID is read from the
signing certificate because `codesign` leaves `$(AppIdentifierPrefix)`
unexpanded. NATS credentials never lived in the file: the agent and the
server both read `NATS_USER`/`NATS_PASS` from the environment.
