# Debian and Ubuntu apt repository

The signed repository is planned at
`https://epsalmond.github.io/oshioki`, but it is not active yet. GitHub Pages
and the archive signing key still need to be configured. Until the published
fingerprint below is set, install the `.deb` directly from a
[GitHub release](https://github.com/epsalmond/oshioki/releases).

Published archive signing fingerprint: **pending key configuration**.

## Enable repository publishing

Create a dedicated archive signing key and keep its primary key offline. The
key supplied to Actions must let GPG sign without an interactive prompt. In
the repository's **Settings → Secrets and variables → Actions**, configure:

- Secret `APT_SIGNING_PRIVATE_KEY`: ASCII-armored private signing key.
- Variable `APT_SIGNING_KEY_FINGERPRINT`: full primary fingerprint for that
  key, written as 40 or 64 hexadecimal characters.

Then set **Settings → Pages → Build and deployment → Source** to **GitHub
Actions**. The release workflow publishes the repository after it successfully
publishes a stable GitHub release. The apt job reads all stable releases,
checks each `.deb` against that release's `SHA256SUMS`, validates package
metadata, and retains every published version in the package index. Drafts and
prereleases are excluded.

To bootstrap the repository from the stable releases that already exist, run
the `release` workflow from the default branch with
`publish_apt_repository` enabled. This builds the repository from the release
assets already published; it does not create another release. The workflow
skips publication when both signing settings are absent and fails on partial
or invalid configuration. The deployment summary reports the active signing
fingerprint. Before enabling client instructions, replace the pending
fingerprint above with the full fingerprint verified against the configured
key.

## Install and update

These commands are ready once the repository is active and the fingerprint
above has been published. Replace `PENDING` in `expected_fingerprint` below
with that full fingerprint. The command stops before installing the key while
the value is pending, the keyring does not contain exactly one primary public
key, or the fingerprint does not match:

```sh
(
  set -e
  keyring_tmp="$(mktemp)"
  trap 'rm -f "$keyring_tmp"' EXIT
  expected_fingerprint='PENDING'
  curl --fail --show-error --silent --location \
    https://epsalmond.github.io/oshioki/oshioki-archive-keyring.gpg \
    --output "$keyring_tmp"
  gpg --show-keys --with-fingerprint "$keyring_tmp"
  keyring_info="$(gpg --show-keys --with-colons "$keyring_tmp")"
  public_key_count="$(printf '%s\n' "$keyring_info" \
    | awk -F: '$1 == "pub" { count++ } END { print count + 0 }')"
  actual_fingerprint="$(printf '%s\n' "$keyring_info" \
    | awk -F: '$1 == "fpr" { print toupper($10); exit }')"
  if [ "$public_key_count" != 1 ] || [ "$expected_fingerprint" = PENDING ] || [ "$actual_fingerprint" != "$expected_fingerprint" ]; then
    echo 'Oshioki archive key must contain exactly one public key matching the published fingerprint.' >&2
    exit 1
  fi
  sudo install -d -m 0755 /etc/apt/keyrings
  sudo install -m 0644 "$keyring_tmp" \
    /etc/apt/keyrings/oshioki-archive-keyring.gpg
)
```

Add the repository with `Signed-By` so this key is trusted only for the
Oshioki repository:

```sh
printf '%s\n' \
  'deb [arch=amd64 signed-by=/etc/apt/keyrings/oshioki-archive-keyring.gpg] https://epsalmond.github.io/oshioki stable main' \
  | sudo tee /etc/apt/sources.list.d/oshioki.list >/dev/null
sudo apt update
sudo apt install oshioki
```

To update later, run these commands when you choose:

```sh
sudo apt update
sudo apt upgrade
```

Oshioki does not enable unattended upgrades. Package updates refresh the
configured hook when `/etc/oshioki/install.env` exists and try-restart an
already running packaged server. They preserve enrolled devices. Restart any
running `oshioki-browser-relay serve` process manually after an update.
