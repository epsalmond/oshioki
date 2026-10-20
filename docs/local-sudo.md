# Approve local sudo

On a Mac, Oshioki can approve sudo through Touch ID without a server or network.

## Set up

[Install Oshioki](install.md), then run as your logged-in user:

```sh
oshioki-laptop-setup --local
```

Setup creates a Secure Enclave identity, pins its public record on this host,
configures a local socket, and starts the agent at login. Re-running it preserves
the identity. Linux source users run `scripts/oshioki-laptop-setup --local`;
their software agent needs an open terminal and the normal sudo password.

## Use and verify

Run your usual sudo command. On the default approval-plugin setup, review the
summary on the Touch ID sheet and approve. The command runs after approval.
For an explicit check:

```sh
sudo oshioki status
sudo -k
sudo true
```

A setup run may finish using an existing sudo timestamp; that alone is not a
new authentication. The cold check above exercises it.

To label requests from a shell:

```sh
export OSHIOKI_SESSION=maintenance
```

See [Mac approvals](mac-approvals.md) for what the prompt shows and
[the runbook](../RUNBOOK.md) if no prompt appears.

## Sudo authentication through PAM

Oshioki has two sudo modes:

| Mode | What you approve | Password and timestamp behavior |
| --- | --- | --- |
| Approval plugin (default, installed by `--prelaunch`) | The exact command and effective environment | Checks each command; hardware-backed devices use the installer's `NOPASSWD` rule, which is written only when `sudo -V` proves the plugin is loaded. Linux also offers a password fallback. |
| Contextual PAM (opt-in) | A sudo authentication, with advisory command context | Uses sudo's normal password fallback and timestamp policy; a warm timestamp can skip a new approval. |

PAM command context is not a signed promise of the final executable,
arguments, or environment. Choose the plugin when you need that binding.

To migrate an already configured Mac, first keep a second root shell open
and confirm you have a working password/console recovery path:

```sh
oshioki-laptop-setup --local --contextual-pam
sudo install-oshioki-hook --contextual-pam-status
sudo -k
sudo true
```

The installer accepts only recognized stock sudo PAM layouts and requires
a working hardware-backed device. A custom layout is a refusal to investigate,
not a reason to edit PAM by hand. On Linux, use the packaged installer with
`--contextual-pam` after pairing a Mac or browser device.

Cancellation or unavailable device authentication leaves the password path
available. On macOS, PAM's `sufficient` control also allows password fallback
after a hard device failure; Linux's installed control rejects hard failures.
See the [PAM contract](../pam/README.md) for those distinctions and support limits.

Restore ordinary sudo with the relevant
[disable command](../RUNBOOK.md#restore-ordinary-sudo).

### Non-interactive sudo

Sudo normally refuses `sudo -n` before starting PAM when a cold authentication
is required. In that default configuration Oshioki cannot receive an approval
request. Classic sudo 1.9.10 and newer provide `noninteractive_auth` for
authentication methods such as Oshioki that do not read from the PAM
conversation. Confirm the implementation and version first with `sudo -V`.

Enable it for the account that runs agents with a scoped sudoers entry,
replacing `alice` with that account:

```sudoers
Defaults:alice noninteractive_auth
```

Create or edit `/etc/sudoers.d/oshioki-noninteractive-auth` with
`sudo visudo -f /etc/sudoers.d/oshioki-noninteractive-auth`. `visudo` validates
the setting before installing the root-owned file. Keep its mode at `0440` and
use a name with no dots that does not end in `~`; sudo ignores other names in
that directory. Run `sudo visudo -c` and confirm its output lists the new file.
If it does not, the main sudoers policy does not include `/etc/sudoers.d`.

From a login shell for the same account named in `Defaults:`, run a cold
acceptance check:

```sh
sudo -k
sudo -n true
```

The cold check must produce an Oshioki approval and exit successfully after it
is approved. The setting does not grant sudo access or bypass authentication.
If Oshioki is unavailable or authentication does not complete, `sudo -n` fails
because its password fallback cannot prompt. Warm sudo timestamps retain their
normal behavior and can skip PAM entirely.

This setting also lets any non-TTY process running as that account send an
Oshioki request for a cold `sudo -n` command. Check the command and context in
each request, and do not approve unexpected or repeated requests.
