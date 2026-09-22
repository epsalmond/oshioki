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
| Approval plugin (default, installed by `--prelaunch`) | The exact command and effective environment | Checks each command; hardware-backed devices use the installer's `NOPASSWD` rule. Linux also offers a password fallback. |
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
