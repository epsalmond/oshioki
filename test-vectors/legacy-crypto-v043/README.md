# Frozen v0.4.3 crypto compatibility fixtures

All private keys and credentials here are public **TEST MATERIAL ONLY**. Never
use them for enrollment, host identity, or push subscriptions outside tests.

These files were generated once against Oshioki base commit
`b57f72b387aeb6f36f131babcfe1345476a86a9c`, using the exact baseline registry
versions. `provenance.json` preserves all 154 resolved package sources/checksums,
source and generator hashes, toolchain, and artifact hashes. The old key crates
were P256 0.13.2, ECDSA 0.16.9, elliptic-curve 0.13.8, crypto-bigint 0.5.5;
push/JWT used web-push-native 0.5.0, ece-native 0.5.0 and jwt-compact
0.9.0-beta.1. `released-source-equivalence.txt` records comparison with v0.4.3.

`fixtures.json` preserves old-produced ciphertext, subscription keys/auth,
HTTP headers for TTL 0/1/300, persisted VAPID scalar/PEM/public identity,
fixed-clock ES256 tokens, and WebAuthn device/config/assertion records with
low-S, equivalent high-S, and tampered DER signatures. Binary fields use
base64url without padding. WebAuthn signs authenticator data followed by the
SHA256 hash of client data. The frozen push plaintext is the exact baseline
application request notification JSON; it identifies a request separately from
the encrypted approval envelope. The fixed VAPID signing time is
2026-10-24T00:00:00Z, with canonical audience `https://push.example.test:8443`
and subject `mailto:test-only@example.test`.

`old-ciphertext.bin`, `expected-plaintext.bin`, and `vapid-test-only.pem` are
byte-exact copies from the JSON/generator output. `SHA256SUMS` covers every
retained data/provenance artifact. Check it with `sha256sum -c SHA256SUMS` from
this directory. Do not regenerate any fixtures during dependency upgrades.

The disposable generator and independent old receiver/verifier remain outside
the product dependency graph at `/tmp/oshioki-legacy-crypto-fixtures`; no old
crate or fixture generator is a product/dev dependency. Original provenance
paths refer to that isolated capture environment. Candidate ciphertext and JWTs
can be independently checked there using `verify-candidate.py`; this is separate
from the durable protocol and server regressions that consume these files.
