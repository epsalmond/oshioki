# Google browser ceremony relay

Issue [#85](https://github.com/epsalmond/oshioki/issues/85): run the browser
part of a NAS `gcloud auth login` on the Mac that holds the Google passkey.
Google performs its own authentication. When account-bound mode is configured,
one Oshioki Touch ID prompt authorizes establishing or renewing that account's
gcloud access; routine gcloud commands remain headless and use gcloud's stored
credentials.

This is an opt-in companion binary, `oshioki-browser-relay`, separate from
the sudo agent, PAM, browser enrollment, and phone push. It is not enabled
by the existing installers. Google may require account selection, consent,
a password, or a CAPTCHA; those requirements remain visible in the browser.
One Touch ID tap is possible only when Google's session and account policy
permit it. The relay neither supplies Google credentials nor retries a
denied sign-in.

## Setup

Build on the NAS and Mac with `cargo build --locked --release -p
oshioki-browser-relay`, then place the binary on the respective user's PATH.
Run as the user who owns the gcloud credentials, without sudo.

Prerequisites:

- Current gcloud on the NAS with its normal browser-mode loopback flow and
  S256 PKCE. Only Google's first-party gcloud client is accepted.
- A logged-in graphical macOS session and default browser with the intended
  Google passkey available.
- NATS reachable by both peers. Remote connections require `tls://`; local
  `nats://127.0.0.1` connections are supported. Use a private account and
  subject permissions restricted to the configured ceremony lane.
- Noninteractive SSH from Mac to NAS over the tailnet, with the NAS host key
  already verified and pinned in `known_hosts`. Use an SSH configuration alias
  whose `HostName` is the NAS tailnet address. The account must permit direct
  TCP forwarding to NAS localhost. Do not enable remote or public listeners.

On **each** host, generate a different relay-only key:

```sh
mkdir -p ~/.config/oshioki-browser
chmod 700 ~/.config/oshioki-browser
oshioki-browser-relay keygen ~/.config/oshioki-browser/signing.key
```

The command prints only the public key. Exchange those public keys over a
trusted channel. Keep private keys on their original machines. These are
software keys for browser dispatch; they cannot approve sudo or sign Google's
WebAuthn challenges. Neither existing Oshioki approval keys nor Google
credentials are used for relay signing.

Choose a shared UUID for `lane` and create a private JSON configuration on
each host. Use absolute paths; `~` is not expanded in JSON. NAS example:

```json
{
  "nats_url": "tls://relay-user:REPLACE_WITH_PASSWORD@nats.example:4222",
  "lane": "a188ae7d-1be4-4a2c-9843-3a843c77a427",
  "private_key": "/home/eric/.config/oshioki-browser/signing.key",
  "peer_public_key": "REPLACE_WITH_MAC_PUBLIC_KEY",
  "google_account": "you@example.com",
  "approval_public_key": "REPLACE_WITH_MAC_OSHIOKI_PUBLIC_KEY"
}
```

On the Mac use its local key path, pin the NAS public key, and add the same
`"google_account": "you@example.com"` plus
`"ssh_destination": "nas-tailnet"` and
`"approval_identity": "/Users/you/.config/oshioki/agent.json"`. The Mac
identity must be a Secure Enclave identity; its public key is the value pinned
as `approval_public_key` on the NAS. The destination and identity path come
only from local configuration, never from a received request. Set both
configurations to mode 600. No changes to `/etc/oshioki` or its permissions
are needed.

The relay reads only the Secure Enclave signing blob from `approval_identity`;
it does not load the agent's unrelated box secret or its Keychain entry. The
Keychain-backed box identity remains available to the normal Oshioki agent.

`google_account`, `approval_public_key`, and `approval_identity` opt into the
headless account-bound flow. The NAS and Mac must be upgraded together for
that flow; incomplete account approval fields fail closed. Existing configs
without those fields retain the original browser-only behavior for migration.

The NAS NATS identity publishes to `oshioki.browser.v1.<lane>` and subscribes
to `oshioki.browser.v1.<lane>.reply.*`. The Mac has the inverse permissions.
These are core NATS subjects, not JetStream streams; stale ceremonies are
not queued for a disconnected Mac. Use the existing NATS deployment with
these additional scoped permissions. The existing approval subjects and
their payload formats do not change.

Start the receiver in the Mac login session:

```sh
oshioki-browser-relay serve --config ~/.config/oshioki-browser/config.json
```

On the NAS:

```sh
oshioki-browser-relay login --config ~/.config/oshioki-browser/config.json
```

For the literal `gcloud auth login` command, this optional shell wrapper
routes that exact invocation through the relay and leaves other invocations
to gcloud:

```sh
gcloud() {
  if [ "$#" -eq 2 ] && [ "$1" = auth ] && [ "$2" = login ]; then
    command oshioki-browser-relay login \
      --config "$HOME/.config/oshioki-browser/config.json"
  else
    command gcloud "$@"
  fi
}
```

In account-bound mode the binary starts `gcloud auth login <ACCOUNT>
--launch-browser` without `--force`. Gcloud activates valid stored credentials
without opening a browser; the relay then runs a bounded access-token check
with its output discarded. If gcloud needs a new login or reauthentication,
the URL is captured through Python's `BROWSER` launcher and the Mac opens the
browser. Gcloud itself validates the resulting account. No token or callback
code enters NATS. The legacy config path retains `--force` for compatibility.
Automatic detection/retry of arbitrary failed gcloud commands and non-Google
OAuth providers are not implemented.

## Lifetime and trust boundaries

1. The NAS sends a signed, expiring probe with a random attempt ID.
2. The Mac verifies the pinned key, version, ID and expiry, then returns a
   signed fresh nonce. Duplicate IDs are retained for their validity window;
   admission is bounded. A restarted receiver generates a different nonce.
3. In account-bound mode the NAS sends the configured account. The Mac shows
   one Touch ID prompt whose reason names the locally configured NAS alias and
   account. Its Secure Enclave signature is domain-separated from sudo and
   Google WebAuthn and is bound to the lane, attempt, expiry, receiver nonce,
   and account. The NAS verifies the pinned Mac Oshioki public key before
   starting gcloud.
4. The NAS starts gcloud. Its private local launcher socket captures the URL
   and sends a signed start bound to the nonce and the same attempt/expiry.
5. The Mac permits only Google authorization-code endpoints, the gcloud
   client ID, S256 PKCE, a state value, and a canonical
   `http://localhost:<unprivileged-port>/` redirect. Duplicate/unknown query
   fields, tokens, authorization codes and reauthentication proof tokens
   are rejected. The callback port is derived from the signed URL rather
   than duplicated in a second potentially conflicting field.
6. The Mac exclusively binds both `127.0.0.1` and `::1` at that port, then
   opens its default browser. Each accepted callback TCP connection uses
   `ssh -W localhost:<port>` to the locally pinned NAS destination. At most
   eight connections exist within the single active request.
7. Google redirects the browser through SSH to gcloud. Google codes/tokens
   never enter a NATS message. Callback bytes are not parsed or logged by
   the relay; gcloud validates OAuth state and exchanges the code itself.
8. Gcloud's exit, failure, SIGINT or SIGTERM causes a signed stop. Success
   additionally requires the Mac's signed cleanup acknowledgement. The
   browser session is bounded by a fixed maximum of 300 seconds from the initial probe; it is never renewed. Expiry,
   receiver cancellation and errors drop both listeners and their SSH
   subprocesses. No `ssh -L` listener can survive a receiver crash.

An unavailable Mac fails before launching gcloud. Port collisions, browser
launch failure, SSH failure, a bad URL, and Google denial fail closed.
Unauthenticated frames are discarded; without a valid next message the
attempt times out. A lost stop or a killed NAS wrapper leaves the Mac
listeners alive only until the original expiry. SIGKILL cannot run NAS
process-group cleanup; gcloud may remain until its own timeout. Restarting
the Mac receiver cannot replay an old start. The browser tab itself is not
closed automatically.

Messages contain the authorization URL (including OAuth state, public PKCE
challenge, scope and any login hint), so treat the NATS lane as private even
though it carries no Google authorization codes, verifiers, or tokens.
Transport encryption and scoped NATS credentials remain necessary.
No phone can host this loopback listener. This lane does not send phone
approvals; existing phone notification behavior is unchanged.

## Verification

Run `scripts/test-browser-relay` with `nats-server` and Python 3 installed.
It uses disposable local brokers, keys, shell processes and callback data;
it never authenticates a Google account, opens a real browser or uses real
SSH credentials. The tests exercise signed-frame/URL rejection, receiver
nonce replay rejection, both address families, port collisions, active
forward cancellation on timeout, stop cleanup, actual launcher subprocesses,
Google denial, Mac refusal and NATS payload inspection.

Ordinary workspace tests run the pure protocol tests. The broker-dependent
tests are explicitly ignored there and run by the dedicated script.

Before calling #85 accepted, verify on NAS + Mac:

- A configured account with valid gcloud credentials completes without a
  browser and the bounded access-token check succeeds.
- A new or reauthenticated login shows one Oshioki Touch ID prompt before
  the Google browser flow, then succeeds with the intended passkey.
- Google's denial and a request timeout return nonzero and leave neither
  callback address listening.
- Inspect the private test lane's decoded signed message bodies to confirm
  no callback authorization code or token crosses NATS. Do not publish raw
  production authorization URLs or NATS credentials in test reports.

Automated simulation is not proof of the real Google ceremony or Touch ID.
