# Crypto dependency sources

The server retains its existing Web Push implementation and `ece-native` record
encryption. `vendor/web-push-native` is the published 0.5.0 crate with a narrow
P256 0.14 dependency/API patch. Its version identifies the original release;
it does not claim an upstream patched release. The original archive SHA-256 is
`7628c93e39aeee4c0bca50ae333052b4f174c653e8fca1d0a8e34f9bc4879c0c`.
See [vendor provenance](../vendor/web-push-native/OSHIOKI-VENDOR.md) for the exact
upstream commit, license origin, and supported features, and
[the source patch](web-push-native-p256-0.14.patch) for the full packaged-file
delta. ECDH, HKDF, ECE records, padding, headers, and salt generation are unchanged.

Only `serialization` is enabled, with default features disabled. Optional
upstream VAPID/`jwt-simple` code and upstream tests are retained unchanged for
provenance, but are unsupported by this patch: they still assume the optional
VAPID implementation and old APIs. The vendor is excluded from the application
workspace. Its unchanged historical `Cargo.lock` is upstream source evidence;
the root lockfile defines the product's actual build and audit graph.

The server signs VAPID JWTs using the official `jwt-compact` source pinned to
[6b410eeff261738123d6993388183fde66df5e26](https://github.com/slowli/jwt-compact/tree/6b410eeff261738123d6993388183fde66df5e26),
with only `clock,p256` enabled. This is unpublished upstream source, still
declaring version 0.9.0-beta.1, with its immutable git source recorded in the
root lockfile. The removed `std` feature is not requested. No OpenSSL, AWS-LC,
new ECE implementation, or alternative JWT backend is introduced.

Oshioki maintainers own these temporary source selections. Replace them with
reviewed compatible upstream releases when available, preserving the source
provenance and compatibility tests during that transition.

Server regressions consume the frozen base-generated data documented in
[`test-vectors/legacy-crypto-v043`](../test-vectors/legacy-crypto-v043/README.md).
They validate old ciphertext/signatures and persisted PEM identity, plus fresh
TTL/claim/header semantics, authentication failure, and exact provider-size
boundaries. The existing builder uses 103 bytes of overhead: 3993 plaintext
bytes produce the 4096-byte body all RFC 8030 providers must support. Larger
bodies retain the existing builder behavior and may be rejected by providers;
this dependency change adds no new payload policy. Historical JWT tests verify
fixed signature/claim metadata without applying current-clock expiry checks.
No vulnerable old implementation is a product or test dependency.

These tests establish local protocol compatibility. Retained browser/requester
upgrade acceptance and physical notification delivery remain separate checks.
