# Upgrade compatibility

An upgrade succeeds only when an already-enrolled user can still
authenticate, and a failed upgrade has a tested restore path that gives that
ability back to the previous release. Starting the new binary is not success.

This page is the release contract. Protocol, persistence, and CI changes
must keep it true. The v1 cryptographic domain strings (`oshioki/...`) and
existing test vectors do not change.

## Compatibility sets

A supported upgrade is the previous tagged release → the candidate, with
enrolled devices and at least one in-flight request. Components of one
release are a set when they share a private or control protocol that is not
additive:

- hook + sudo plugin + PAM module (private plugin/hook protocol; currently 2)
- hook + agent (socket `AliveV1` / decision frames)
- server + browser bundle + hook (NATS `DeliveryV1` / ack subjects)
- server + SQLite file + NATS stream/consumer config

Rolling inside a set is not required. Rolling across sets is allowed only
where the matrix below says so.

## Mixed-version matrix

Must keep working:

- New writer, old reader of public v1/v2 JSON (`RequestV1`, `DecisionV1`,
  authentication envelopes, device records, identity JSON) when the change
  is a new field with `#[serde(default)]` / `skip_serializing_if`.
- Old writer, new reader of those same types (missing fields default).
- New server opening a previous-release SQLite file that only needs additive
  objects (`CREATE TABLE IF NOT EXISTS`, nullable extra columns the old SQL
  never named).
- New server against a stream or durable consumer that still lacks a newly
  required subject: the server repairs it on start. It does not warn and
  continue.
- New agent loading a previous-release identity file (embedded `box_secret`
  or `box_secret_ref`).

Must fail closed with an actionable diagnostic (not hang, not silent allow,
not silent drop of an authentication lane):

- Plugin/hook private protocol mismatch.
- Hook/agent control-frame mismatch that is not an unknown skipped kind
  (wrong kind in a committed position, truncated frame after acknowledgement).
- Server binary versus a SQLite `user_version` the binary does not know how
  to read.
- NATS stream missing and uncreatable (misconfiguration, not an upgrade).

On Linux, a decode/unavailable fault on the plugin lane leaves PAM password
fallback eligible. That is not a substitute for a restore path on Darwin
passwordless installs.

## Wire rule

Additive fields stay on the current numeric version. A semantic or
incompatible change gets a new protocol version and an explicit dual-read
(and dual-write if rollback of the writer is in the matrix) plan in the same
PR. Do not set `#[serde(deny_unknown_fields)]` on public wire types.

Goldens live in `tests/compat/goldens/`. A protocol PR that changes a
serialized shape must update the matching golden and a matrix row, not only
a unit test. Regenerate with `OSHIOKI_WRITE_COMPAT_GOLDENS=1` as documented
in each golden test.

## SQLite rule

Two classes, no third:

1. **Additive (no `user_version` bump).** Extra tables or nullable columns.
   Old binaries keep working because every `SELECT` names columns. Do not
   bump `user_version` for this class.
2. **Breaking (`user_version` bump).** Anything that would make an older
   binary's SQL or `ready()` wrong. Before applying it, the server creates
   and verifies a restore snapshot next to `OSHIOKI_STATE_PATH`, named
   `<stem>.pre-v<from>.sqlite3` (for `state.sqlite3` at version 2,
   `state.pre-v2.sqlite3`). Rollback is: stop the new binary, replace the
   live database with that snapshot, start the previous binary.

Schema version 3 (outbox `expires_at`) already shipped as class 2 in
v0.1.14. Older binaries than that release cannot read a version-3 file;
the snapshot is the rollback path. This binary still snapshots before
applying V3 if it opens a version 0–2 file.

The server refuses `user_version` newer than it writes.

## Identity-file rule

Do not write both `box_secret` and `box_secret_ref` in the live file:
current and previous loaders treat that as corrupt.

Before rewriting a legacy file, the agent persists a 0600 sibling
`agent.json.prev` (original bytes, fsync, then atomic replace of
`agent.json`). Load verifies the new representation. Leave `.prev` until
an operator removes it. Restore is: copy `.prev` back to `agent.json` and
run the previous agent. A missing secret-store entry names that restore
as well as `--force`.

## NATS rule

On server start, after opening the existing `OSHIOKI` stream:

1. If stream subjects do not cover the consumer filters this build needs,
   update the stream (additive subject list). Fail startup if update fails.
2. If the durable's filters do not match, drain pending deliveries with a
   short timeout, delete the durable, and recreate it. Fail startup if the
   result still does not match.
3. Recreating the durable can drop in-flight command-lane deliveries. The
   hook then hits unavailable / password fallback rather than a silent
   authentication-lane black hole. The server logs the pending count.

A missing stream is still a misconfigured deployment; the server does not
create one.

## Release gates

CI must fail the release if a compatibility case would silently discard
auth state, require re-enrollment, or turn a recoverable upgrade into a
permanent outage. The gates are:

1. Previous-release goldens load on the candidate.
2. Old-reader/new-writer and new-reader/old-writer pass wherever this
   matrix allows it.
3. An upgrade with enrolled credentials and an in-flight request still
   approves, with no re-enroll.
4. Rollback via the SQLite snapshot and `agent.json.prev` lets the previous
   release authenticate again.
5. Stale NATS filters are repaired on start.
6. Unsupported mixes fail closed with a diagnostic or unavailable-with-fallback;
   they do not hang or silently allow.

Darwin Keychain / Secure Enclave is not in GitHub Actions; software-identity
Linux is the automated gate. Restore a Keychain-migrated identity with
`agent.json.prev` the same way.
