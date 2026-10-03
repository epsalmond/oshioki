# Browser approvals for Codex and Claude Code

Oshioki can answer one pending Codex or Claude Code permission request from an
enrolled browser. Each signed decision applies to that invocation only. A
phone approval does not add a native permission rule or change the tool input.
If the phone is unavailable, the request expires, or its result cannot be
verified, Oshioki returns no decision and the native agent keeps its usual
permission flow.

## Set up a user profile

Run setup as the account that runs Codex or Claude Code. Do not use `sudo`.
Ask the server operator for a private NATS requester config containing only
`NATS_URL`, `NATS_USER`, and `NATS_PASS`; it must be owned by your account and
mode `0600`.

```sh
oshioki approvals setup \
  --profile work \
  --server-url https://sudo.example.com \
  --nats-config ~/.config/oshioki/requester.env
```

Setup creates a fresh profile below
`${XDG_CONFIG_HOME:-~/.config}/oshioki/approvals/work`, stores its enrollment
and device records in owner-only files, and prints a browser enrollment URL.
Open the Oshioki browser app, go to `/setup`, paste the complete URL, and finish
the passkey prompt. See [phone enrollment](phone-enrollment.md) for browser and
passkey requirements.
The profile remains separate from `/etc/oshioki`; setup does not copy the host's
sudo credentials or pinned devices. Running setup again with the same server
and NATS credentials selects the profile and reuses its enrolled browser. Use a
new profile name to connect a different server or credential.

The profile's NATS user needs only the subjects used by enrollment and this
requester:

| Direction from the profile | Subjects |
| --- | --- |
| Publish | `oshioki.enrollment.intent`, `oshioki.enrollment.activation.>`, `oshioki.tool.request` |
| Subscribe | `oshioki.enrollment.submission.>`, `oshioki.tool.delivery.>`, `oshioki.tool.ack.>`, `oshioki.tool.verdict.>` |

The server role must receive `oshioki.tool.request` and publish the matching
`oshioki.tool.delivery.<id>`, `oshioki.tool.ack.<id>`, and
`oshioki.tool.verdict.<id>` replies. Keep those permissions on separate
requester and server accounts; do not copy the broader sudo-hook credentials
into a user profile.

## Install or remove the hooks

```sh
oshioki approvals install codex claude
```

The installer adds an Oshioki-owned `PermissionRequest` command hook to each
user settings file and preserves other hooks, permission settings, and sandbox
settings. It sets the native hook timeout to 120 seconds. Codex requires its
normal hook review: open `/hooks` and trust the new definition. Oshioki does
not bypass that review. Restart each agent to load its settings.

Remove the Oshioki-owned entries with:

```sh
oshioki approvals uninstall codex claude
```

Uninstall leaves unrelated entries in both settings files intact.

## What the phone decides

The hook sends the complete native permission event, including the tool input
and working directory, to the enrolled browser through a separate tool approval
request. The browser signs an approve or deny response for that one request.
Oshioki verifies the signature against the user's pinned browser registry before
returning the native decision. It does not edit the input, remember the result,
or add persistent permission rules.

Only Codex and Claude Code `PermissionRequest` events are handled. Malformed,
duplicate-key, unsupported, oversized, expired, cancelled, or unverifiable
requests produce no Oshioki decision. The hook prints native JSON on stdout
only after a signature verifies; otherwise stdout stays empty so the native
permission flow remains in control.
