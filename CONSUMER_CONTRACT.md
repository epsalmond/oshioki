# Sudo approve consumer contract

## Issue #868

#868 supplies the production runtime. It must provide:

- A `SUDO_APPROVE` JetStream stream for `sudo.request.>`.
- The durable `sudo-approve-server-v1` consumer permissions.
- Publish and subscribe permissions for `sudo.verdict.*` and
  `sudo.enrollment.*`.
- Publish and subscribe permissions for `sudo.device.revoke.*`.
- A writable SQLite path set by `SUDO_APPROVE_STATE_PATH`.
- `SUDO_APPROVE_ORIGIN=https://sudo.internal.psalmond.com` and
  `SUDO_APPROVE_RP_ID=sudo.internal.psalmond.com`.
- A selected server package or image, plus ntfy, DNS, TLS, promotion,
  exemptions, alerts, and rollback.

The runtime must not log or notify with request plaintext. An ntfy message may
contain host, user, request ID, and `/r/<id>` URL only.

## Issue #869

#869 installs the packaged Darwin client. It owns the read-only watcher
credential, LaunchAgent, `pam_tid`, laptop activation, and rollback. `watch`
accepts no shell command. The optional
`SUDO_APPROVE_OPENER` test seam is one executable path followed by one URL
argument.

Neither consumer changes the v1 wire format. A protocol change requires a new
version and a compatibility decision in this repository.
