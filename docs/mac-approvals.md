# Mac approvals

A Secure Enclave signature requires Touch ID. The Touch ID sheet shows a
summary of the session, user, host, and command. Long commands are truncated
with an ellipsis; there is no separate full-request review window. The complete
command and environment remain bound to the signature even when the summary
cannot display them all.

Contextual PAM approvals authenticate a sudo session; their command context
is advisory. See [the mode comparison](local-sudo.md#sudo-authentication-through-pam).

## Start at login

For a Mac whose own sudo is configured, use `oshioki-laptop-setup` in the
[local](local-sudo.md) or [remote](remote-sudo.md) setup. It manages:

- `~/Library/LaunchAgents/com.oshioki.agent.plist`
- `~/.config/oshioki/agent.log`

It verifies the packaged agent and uses Homebrew's stable `opt` path, so an
upgrade followed by cleanup does not break the next login.

For an approval-only Mac using a source checkout, pair it first and load its
device-role NATS environment, then:

```sh
scripts/mac/install-agent
```

This separate installer manages `dev.oshioki.agent` and logs to
`~/Library/Logs/oshioki-agent.log`. It requires NATS and builds the app bundle
if needed. `--dry-run` previews a redacted plist; `--uninstall` removes this
LaunchAgent. Re-run it after rebuilding. Use only one installer/agent for an
identity at a time.

Check the service you installed:

```sh
launchctl print gui/$(id -u)/com.oshioki.agent
oshioki-agent show
tail -f ~/.config/oshioki/agent.log
```

For the source installer, substitute `dev.oshioki.agent` and its log path.

## Prompts and recovery

Only one Touch ID sheet can run at a time. A locked screen
cannot complete approval, and the request deadline ends an unanswered prompt.
Cancellation never approves a request. PAM cancellation leaves password
fallback available; command approval fails closed without a valid decision.

Set `OSHIOKI_SESSION` in the invoking shell to label requests. Without it the
summary uses a recognizable caller process or tty when available.

Adding or removing a Touch ID fingerprint invalidates the existing enclave
key. Retrying cannot repair that key: follow
[re-pairing](../RUNBOOK.md#re-pairing), then update every host that pinned it.

Identity creation and loading need the user's unlocked login keychain.
`User interaction is not allowed` usually means setup is running outside
that graphical session. Run setup in a Terminal window on the Mac.

For bundle signing and release checks, see [contributing](../CONTRIBUTING.md).
