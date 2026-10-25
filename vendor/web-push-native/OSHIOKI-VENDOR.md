# Vendored web-push-native 0.5.0

This directory retains the published crate identity and version. It is an explicitly modified local copy, not a new upstream release.

- Published archive: https://static.crates.io/crates/web-push-native/web-push-native-0.5.0.crate
- Archive SHA-256: 7628c93e39aeee4c0bca50ae333052b4f174c653e8fca1d0a8e34f9bc4879c0c (verified independently against the base Cargo.lock and crates.io version metadata).
- Upstream source: https://github.com/leotaku/web-push-native/tree/6b0a3f10377af3c9401a7c1a60b1e34d41155c5d/web_push
- Source commit and subdirectory come from the unmodified packaged .cargo_vcs_info.json.
- License: MIT OR Apache-2.0. The archive does not include license files; LICENSE-MIT and LICENSE-APACHE were retrieved unchanged from the exact upstream source commit.
- Package files including Cargo.lock, README, optional VAPID source, and upstream tests are retained.

Local changes: p256 requirement 0.13.2 -> 0.14.0, its getrandom feature, supported Generate generation, and supported ToSec1Point/method renames in production and serialization source. ECDH, salt generation, HKDF labels, ECE record sizing/encryption, error handling, and HTTP assembly remain unchanged. Cargo.toml.orig mirrors the normalized manifest dependency change.

Use ONLY with default-features = false and features = ["serialization"]. The optional VAPID implementation and its jwt-simple dependency are not migrated or supported by this local patch. Their source and upstream tests are intentionally retained for provenance; do not enable the default feature set or run dependency tests expecting those APIs to be upgraded.

Keep this directory outside the application's workspace membership using an explicit workspace exclude. Prefer a direct path dependency over a registry [patch] so the active vendored source is visible in manifests. Remove or replace this delta when an appropriate upstream release is available after review.
