# Oshioki consumer contract

## The deploying infrastructure

The deploying infrastructure supplies the production runtime. It must provide:

- An `OSHIOKI` JetStream stream for `oshioki.request.>`.
- The durable `oshioki-server-v1` consumer permissions.
- Publish and subscribe permissions for `oshioki.verdict.*` and
  `oshioki.enrollment.*`.
- Publish and subscribe permissions for `oshioki.device.>` (revocations and
  their confirmations).
- A writable SQLite path set by `OSHIOKI_STATE_PATH`.
- `OSHIOKI_ORIGIN=https://sudo.example.com` and
  `OSHIOKI_RP_ID=sudo.example.com`.
- A selected server package or image, plus ntfy, DNS, TLS, promotion,
  exemptions, alerts, and rollback.

The runtime must not log or notify with request plaintext. An ntfy message may
contain host, user, request ID, and `/r/<id>` URL only.

A device is either kind `webauthn` (a browser) or kind `secure-enclave` (the
native agent). The native agent is a NATS consumer only; it never calls the
server over HTTP. The deploying infrastructure's NATS permissions above must
cover it the same as any other consumer.

## The Mac installer

The Mac installer installs the packaged Darwin client. It owns the read-only
watcher credential, LaunchAgent, `pam_tid`, laptop activation, and rollback.
`watch` accepts no shell command. The optional `OSHIOKI_OPENER` test seam is
one executable path followed by one URL argument.

Neither consumer changes the v1 wire format. A protocol change requires a new
version and a compatibility decision in this repository.
