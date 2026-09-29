# Debian and Ubuntu apt repository

Configure apt to install and update Oshioki from
`https://epsalmond.github.io/oshioki`.

Published archive signing fingerprint: **AA93668ABF0040387C7EB51C1632F50E2226409D**.

## Install

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

For package updates, follow [update and restore](update.md#debian-or-ubuntu).

For a one-time package install, follow
[Debian or Ubuntu installation](install.md#debian-or-ubuntu).

See [the runbook](../RUNBOOK.md#maintain-the-apt-repository) for signing,
rotation, and repository publishing.
