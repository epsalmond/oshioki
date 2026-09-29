# Debian and Ubuntu apt repository

Configure apt to install and update Oshioki from
`https://epsalmond.github.io/oshioki`.

Published archive signing fingerprint: **AA93668ABF0040387C7EB51C1632F50E2226409D**.

## Install and update

Download and inspect the scoped archive key. The command stops before
installing it unless the keyring has exactly one primary public key with the
published fingerprint:

```sh
(
  set -e
  keyring_tmp="$(mktemp)"
  trap 'rm -f "$keyring_tmp"' EXIT
  expected_fingerprint='AA93668ABF0040387C7EB51C1632F50E2226409D'
  curl --fail --show-error --silent --location \
    https://epsalmond.github.io/oshioki/oshioki-archive-keyring.gpg \
    --output "$keyring_tmp"
  gpg --show-keys --with-fingerprint "$keyring_tmp"
  keyring_info="$(gpg --show-keys --with-colons "$keyring_tmp")"
  public_key_count="$(printf '%s\n' "$keyring_info" \
    | awk -F: '$1 == "pub" { count++ } END { print count + 0 }')"
  actual_fingerprint="$(printf '%s\n' "$keyring_info" \
    | awk -F: '$1 == "fpr" { print toupper($10); exit }')"
  if [ "$public_key_count" != 1 ] || [ "$actual_fingerprint" != "$expected_fingerprint" ]; then
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

For a one-time installation without configuring apt, download the amd64
`.deb` from a [GitHub release](https://github.com/epsalmond/oshioki/releases)
and run `sudo apt install ./oshioki_X.Y.Z_amd64.deb`.

## Repository administration

The repository's **Settings → Secrets and variables → Actions** contains the
signing configuration:

- Secret `APT_SIGNING_PRIVATE_KEY`: ASCII-armored signing-subkey export. It
  contains the public primary key, a nonusable primary secret-key stub, and
  the usable signing subkey; it has no usable primary private key.
- Variable `APT_SIGNING_KEY_FINGERPRINT`: full primary fingerprint shown
  above.

The cert-only RSA4096 primary key and RSA3072 signing subkey are retained in
`~/.local/share/oshioki/apt-signing` with mode 0700 on the directory and 0600
on files. The primary private key stays on this machine; these permissions
protect it, but the key is not physically offline. Actions receives only the
secret-subkey export. Keep protected backups and renew or replace the
two-year primary and signing subkey before they expire. For a signing-subkey
rotation, update the Actions secret and republish the public keyring. If the
primary key must be replaced, publish and verify its new fingerprint and
coordinate a client keyring rollover before signing only with the replacement.

Pages uses the GitHub Actions source. The `github-pages` environment permits
deployments from `main` for bootstrap and `v*` tag releases. The release
workflow publishes after a stable GitHub release succeeds. It reads all stable
releases, checks each `.deb` against that release's `SHA256SUMS`, validates
package metadata, and retains every published version in the package index.
Drafts and prereleases are excluded.

To bootstrap from existing stable releases, run the `release` workflow from
the default branch with `publish_apt_repository` enabled. This deploys the
already-published release assets and does not create another release. The
deployment summary includes the active signing fingerprint.
