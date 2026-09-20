# Oshioki-secured Google browser ceremonies

`oshioki-browser-relay` is an opt-in helper for a Google `gcloud auth login`
ceremony. The first-class mode runs entirely on one Mac: Oshioki shows one
Touch ID approval, then gcloud owns its normal browser and localhost callback.
An optional remote-requester mode adds signed NATS messages and short-lived SSH
forwarding when the requester and approving Mac are different machines.

The Oshioki approval authorizes this helper invocation to establish or renew
the configured Google account. It does not intercept ordinary gcloud commands
or take ownership of credentials already stored by gcloud. Routine commands
may refresh those credentials directly under gcloud's normal policy.

Google remains the authentication authority. The helper neither supplies a
Google password or passkey nor replaces Google's WebAuthn challenge. The
current adapter is intentionally Google-first-party gcloud only.

## Local Mac mode

Build the binary and the native agent from this checkout, or use release
artifacts built from the same reviewed source:

```sh
cargo build --locked --release -p oshioki-agent -p oshioki-browser-relay
```

Create a separate Secure Enclave identity for this helper. Keeping it separate
from the normal agent identity avoids unrelated agent box-secret access while
retaining the same native Touch ID experience:

```sh
mkdir -p ~/.config/oshioki/browser-relay
chmod 700 ~/.config/oshioki/browser-relay
oshioki-agent init --signer enclave \
  --state ~/.config/oshioki/browser-relay
oshioki-agent device-record --state ~/.config/oshioki/browser-relay \
  --label browser-relay
```

Use the `credential_public_key` from that public device record as
`approval_public_key`. Create a mode-600 local configuration, replacing the
account, paths, and public key:

```json
{
  "google_account": "you@example.com",
  "approval_identity": "/Users/you/.config/oshioki/browser-relay/identity.json",
  "approval_public_key": "REPLACE_WITH_THE_IDENTITY_PUBLIC_KEY",
  "local_label": "this Mac"
}
```

Run the local helper as the user who owns the gcloud profile:

```sh
chmod 600 ~/.config/oshioki/browser-relay/local.json
oshioki-browser-relay local-login \
  --config ~/.config/oshioki/browser-relay/local.json
```

The helper loads only the Secure Enclave signing blob. It does not read the
agent's unrelated box secret or its Keychain entry. It then shows one Oshioki
Touch ID prompt. If gcloud can reuse or refresh valid credentials, no browser
opens. If Google requires a new login, gcloud opens the default browser and
handles its own loopback callback directly. Approval denial, expiry, and
interruption start no gcloud process or leave one running.

The local mode does not require NATS, SSH, a server, a VM, a launchd service,
or a public listener. The local browser callback is owned by gcloud, so the
helper does not bind that port or inspect callback bytes.

## Optional remote requester

When the requester and approving Mac differ, use the remote `login` and `serve`
commands. This mode requires a private NATS account and lane reachable by both
peers, two relay-only software signing keys, and noninteractive SSH from the
Mac to the requester. The SSH destination is local Mac configuration and is
never accepted from a received message.

Remote setup keeps the same account-bound Oshioki approval fields:

- the requester pins the Mac identity public key as `approval_public_key`;
- the Mac pins its local `google_account` and `approval_identity`;
- the requester sends a signed account-bound authorization request;
- the Mac signs a challenge bound to lane, attempt, expiry, receiver nonce,
  and account after Touch ID;
- only then does the requester run gcloud without `--force`.

The browser fallback is the remote adapter's only extra behavior: it validates
Google's authorization URL, opens the Mac browser, and forwards the loopback
callback through short-lived SSH `-W` connections. Callback codes and tokens
never enter NATS. Remote configurations with incomplete account-approval
fields fail closed. Legacy configurations without account approval fields keep
the original browser-only behavior for migration.

## Trust and cleanup

Relay software keys authenticate the two relay peers; they cannot approve sudo
or sign Google's WebAuthn challenges. The separate Oshioki Secure Enclave key
signs only the domain-separated browser-ceremony approval challenge.

Every attempt has a short expiry, a fresh receiver nonce, and bounded IDs.
Success, denial, expiry, interruption, failed gcloud commands, and lost peers
clean up process groups and temporary listeners. The remote adapter requires
the requester and Mac to be upgraded together for account-bound mode.

## Verification scope

Automated tests cover URL validation, signed-frame binding, authenticated NATS,
headless account reuse, local gcloud orchestration, denial and timeout cleanup,
remote browser fallback, and process teardown. A real Google account, browser,
passkey, and Touch ID run is separate acceptance work; local fakes do not prove
Google policy or physical biometric behavior.
