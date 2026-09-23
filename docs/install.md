# Install Oshioki

Install on each machine that runs sudo and each Mac that approves requests.
The browser login helper can be used on its own; it does not require sudo setup.

## macOS

Apple Silicon packages are available through Homebrew:

```sh
brew install epsalmond/oshioki/oshioki
```

Next, choose [local sudo](local-sudo.md), [remote sudo](remote-sudo.md),
[phone approval](phone-enrollment.md), or [Google login](browser-ceremony-relay.md).

Run setup helpers as your logged-in user. They request sudo when needed.
Mac identity creation and Touch ID require a graphical login session with an
unlocked login keychain.

## Debian or Ubuntu

Download the amd64 `.deb` from a
[release](https://github.com/epsalmond/oshioki/releases), then:

```sh
sudo apt install ./oshioki_X.Y.Z_amd64.deb
```

The package includes the sudo hook, plugin, PAM module, server, phone setup
helper, browser relay, and the opt-in `oshioki-google-login-setup` and
`oshioki-browser-service` commands. Python 3 is installed as a runtime
dependency (3.9 or newer) for these commands. It does not include the Linux
native agent or laptop setup helper; use a source build for those.

A fresh install does not activate sudo approval without host configuration
and a pinned device. Continue with [remote sudo](remote-sudo.md) or
[phone approval](phone-enrollment.md). For Google login on this host, follow
the [Google Cloud CLI login](browser-ceremony-relay.md) instructions. Its
wrapper and background services remain opt-in.

Browser relay packaging is new in the next release after 0.1.15. Earlier
packages require the source build below.

## From source

Install Rust through rustup; this checkout selects its pinned toolchain.
Linux also needs the PAM development headers (`libpam0g-dev` on Debian/Ubuntu).

```sh
cargo build --locked --release --workspace
```

Binaries are under `target/release`. To configure local sudo from this checkout:

```sh
scripts/oshioki-laptop-setup --local
```

For a manually configured host, create the installer manifest after building.
On Linux:

```sh
(cd target/release && sha256sum oshioki liboshioki_plugin.so liboshioki_pam.so > SHA256SUMS)
```

On macOS:

```sh
(cd target/release && shasum -a 256 oshioki liboshioki_plugin.dylib liboshioki_pam.dylib > SHA256SUMS)
```

Then use `scripts/install-oshioki-hook` wherever a guide uses the packaged
installer. Hashes must describe the binaries from this build.

## Activate a manually configured sudo host

Use this after the phone or remote guide has configured the host and pinned
a device. Keep a second root shell open until verification succeeds.

The installer is `install-oshioki-hook` on Homebrew,
`/usr/share/oshioki/install-oshioki-hook` on Debian, or
`scripts/install-oshioki-hook` in a checkout. For Debian:

```sh
sudo /usr/share/oshioki/install-oshioki-hook --prelaunch --dry-run --config-file /etc/oshioki/install.env
sudo /usr/share/oshioki/install-oshioki-hook --prelaunch --config-file /etc/oshioki/install.env
sudo /usr/share/oshioki/install-oshioki-hook --prelaunch-status
sudo -k
sudo true
```

The final command must produce and complete an approval. A successful
`oshioki test` checks delivery and signing, but does not prove sudo integration.

The installer preserves the device registry and leaves approval disabled
while it is empty. Hardware-backed devices qualify for its passwordless
sudoers rule; software native devices retain the normal sudo password.
The opt-in [PAM mode](local-sudo.md#sudo-authentication-through-pam) uses
sudo's authentication and timestamp behavior instead.
