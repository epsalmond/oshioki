# Production requirements

What production needs that this repository does not provide: runtime,
packaging, and rollout. For how the pieces fit together, see
[architecture.md](architecture.md).

## Runtime

Production must provide:

- An `OSHIOKI` JetStream stream for `oshioki.request.>`.
- The durable `oshioki-server-v1` consumer permissions.
- Publish and subscribe permissions for `oshioki.verdict.*` and
  `oshioki.enrollment.*`.
- Publish and subscribe permissions for `oshioki.ack.*`. Native agents and
  the authenticated browser acknowledgement endpoint publish liveness
  messages before a human decision.
- Publish and subscribe permissions for `oshioki.delivery.*`. The server
  publishes a durable delivery receipt for a request routed to a pinned
  WebAuthn recipient, and the hook subscribes to report that the request
  reached the browser while it waits for a decision.
- Publish and subscribe permissions for `oshioki.device.>` (revocations and
  their confirmations). These apply to the `nats` transport; other transports
  document their own.
- A writable SQLite path set by `OSHIOKI_STATE_PATH`.
- `OSHIOKI_ORIGIN=https://sudo.example.com` and
  `OSHIOKI_RP_ID=sudo.example.com`.
- A selected server package or image, plus ntfy, DNS, TLS, alerts,
  and rollback.

The runtime must not log or notify with request plaintext. An ntfy message may
contain host, user, request ID, and `/r/<id>` URL only.

A device is kind `webauthn` (a browser), `software` (a native software key),
or `secure-enclave` (the native agent's hardware-backed key). Software native
devices never qualify for passwordless sudo. The native agent is a NATS
consumer only; it never calls the server over HTTP. The NATS permissions above must
cover it the same as any other consumer.

## The Mac installer (future — nothing ships yet)

A future Mac installer will install the packaged Darwin client. It will own
the read-only watcher credential, LaunchAgent, the `sudoers.d` passwordless
drop-in (coupled to the plugin block, never `pam_tid`: one Touch ID approval
per sudo, no password), laptop activation, and rollback.

Neither the runtime nor the Mac installer changes the v1 request or decision
wire format. `AliveV1` is a versioned liveness message on its own subject and
socket response frame. A protocol change requires a compatibility decision in
this repository.
