# Vault authorization

Oshioki asks a pinned human device to approve credential use. The secrets
broker authenticates the requester, decides which services need approval,
and enforces the resulting grant. Oshioki does not return credentials.

## Setup

Enroll or [pin an existing native device](native-agent.md#pair-without-a-server).
The request flow requires an active Secure Enclave identity and a running
`oshioki-agent`. Keep its private identity on the approval device; only public
device records belong in the requester and broker registries.

The requester configuration directory contains `devices.json`, `hook.json`
and `config.env` for the existing socket or NATS transport. The broker's
verification directory contains its own trusted `devices.json` and `hook.json`.
Keep that directory and the verifier executable outside requester write access.
Select the expected approver fingerprint in broker configuration, never from
the incoming request.

Same-host approval can use `OSHIOKI_AGENT_SOCKET`. Remote approval uses NATS;
see [configuration](configuration.md). The hook needs to publish to
`oshioki.access.<host>` and receive the existing ack/verdict subjects. The
native device needs to subscribe to `oshioki.access.>` and publish ack/verdict
responses. Use separate role credentials and TLS outside loopback.

Software signing identities cannot authorize vault access. The test-only
`oshioki-agent run --auto` mode never answers this purpose. The verifier also
supports pinned WebAuthn assertions using the trusted origin/RP settings in
`hook.json`, but browser vault-authorization UI is not included.

## Request authorization

For an Agent Vault build with timed-access support, configure
`AGENT_VAULT_ACCESS_POLICY` on the service with its audience, fixed Oshioki
helper path, verification directory, protected vault/service names and the
enrolled SSH public key mapped to an existing AgentID. The agent must have
instance role `no-access` and vault role `proxy`; approval does not change
those roles or enable raw-secret reads.

Use the broker proxy environment with a token for the enrolled AgentID:

```sh
agent-vault access request --service <service> --purpose <reason> \
  --ssh-key <existing-key-path> --oshioki-config <requester-config>
```

The public key must be loaded in `ssh-agent`; an unencrypted private-key path
also works. SSH enrollment is an operator step, not part of this command.
Access defaults to five minutes; add `--duration 1h` for an explicit duration
up to one hour. `--vault` selects the existing vault, and `--audience` must
match the broker policy when it differs from the server address.

Approve the native prompt, then retry the original CLI. Run the command
proactively or after the broker returns `access_required`. A dismissed,
expired or unavailable ceremony grants no access.

For another broker, its requester constructs the canonical request JSON and
passes those exact bytes to the helper (see the [request types](../protocol/src/access_v1.rs)):

```sh
oshioki access request --config-dir <requester-config> < request.json > approval.json
```

The request binds audience, principal, host, vault, service, purpose, duration,
request ID, nonce and a ceremony expiry of at most 90 seconds. The helper
returns JSON containing `request_json` and the signed `approval`; the broker
must authenticate the requester independently.

## Verify on the broker

Invoke the service-owned executable and pins with the returned JSON on stdin:

```sh
oshioki access verify --config-dir <service-owned-pins> \
  --approver <pinned-fingerprint> < approval.json
```

Successful verification exits 0 and prints:

```json
{"type":"credential_access_verified","version":4}
```

Reject errors, missing or unexpected output, and expired requests. This command
never uses the sudo/password fallback. The broker must still check requester
identity and service policy, then durably consume the request ID and store an
absolute grant expiry. Replaying an approval must not extend that expiry;
retain consumed IDs when migrating storage, including expired grant rows.

## Enforcement and validation

Agent Vault checks each new HTTP/1 request and HTTP/2 stream after service
matching and before credential resolution, including OAuth retries. Already
admitted streams may finish; expiry does not terminate them or provider-internal
lease renewal. Scope is the existing broker service match, not an API-operation
filter. Sessions sharing an enrolled SSH principal share its grant.

The integration's local CLI proof uses disposable native test identities and
fake credentials. It does not establish a live Touch ID ceremony, production
deployment, or compatibility with every provider CLI. Validate those paths
separately before relying on them.
