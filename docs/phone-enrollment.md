# Approve sudo from a phone

Run setup and enrollment on the host whose sudo the phone will approve.
The phone opens a URL; it does not run the `oshioki` command.

## 1. Make the server reachable

[Install Oshioki](install.md). Choose one setup:

| Setup | Prerequisites |
| --- | --- |
| Tailscale (managed local server) | Python 3, `oshioki-server`, `nats-server`, Tailscale running on the host, and the phone on the same tailnet |
| Existing HTTPS server | An Oshioki origin trusted and reachable by host and phone, plus this host's NATS credentials |

For Tailscale, run as your normal user:

```sh
# On macOS, if NATS is not installed:
brew install nats-server
oshioki-phone-setup --check
oshioki-phone-setup
```

Setup starts a local server and JetStream broker on loopback and publishes
HTTPS through Tailscale Serve. It refuses to replace an unrelated Serve
configuration. On Linux it requires a systemd user service manager.

For an existing server, put `NATS_URL`, `NATS_USER`, and `NATS_PASS` in a
mode-600 file, then:

```sh
oshioki-phone-setup --server-url https://sudo.example.com --nats-config /path/to/hook-nats.env
```

That option configures the host without starting services. The server's
`OSHIOKI_ORIGIN` must match the HTTPS URL and `OSHIOKI_RP_ID` its hostname.
See [server requirements](requirements.md) if you operate that deployment.

## 2. Enroll

On the host:

```sh
sudo oshioki enroll
```

On a fresh Debian install, the hook may still be at
`/usr/share/oshioki/oshioki`; use
`sudo /usr/share/oshioki/oshioki enroll` until host activation installs it on PATH.

Keep that command running. The printed URL expires after five minutes.

On iPhone or iPad:

1. Open the Oshioki HTTPS origin and add it to the Home Screen.
2. Open the installed app, go to `/setup`, and paste the **complete** enrollment
   URL, including its `#secret` fragment.
3. Tap Continue and complete the passkey prompt.
4. After activation, tap Enable notifications.

Other supported browsers can open the enrollment URL directly. Enroll each
browser profile separately. An enrollment completed in a Safari tab may not
be available to the Home Screen app; use a fresh URL in the app if necessary.
A denied notification permission does not undo enrollment, but prevents push
delivery.

## 3. Activate and verify

On the host, confirm the device and send a test:

```sh
sudo oshioki status
sudo oshioki test
```

Use the full hook path above if it is not installed yet. Confirm that the phone
receives a notification, opens the request, and completes approval.

Then [activate sudo on the host](install.md#activate-a-manually-configured-sudo-host)
and approve a real `sudo true`. Setup configures reachability; enrollment and
activation are separate steps.

## Keep it working

The phone must reach the same HTTPS origin when a notification is tapped.
With Tailscale Serve, that means an active tailnet connection. Keep the hostname
stable: passkeys are scoped to the RP ID. Do not substitute `localhost`;
on the phone it refers to the phone itself.

Managed state and logs live under `~/.local/share/oshioki/phone-server`.
The default ports are NATS 14222 and HTTP 18443, configurable with
`--nats-port` and `--server-port`. Re-run setup after a package update.

On macOS the service labels are `com.oshioki.phone-server.nats` and
`com.oshioki.phone-server.server`. On Linux:

```sh
systemctl --user status oshioki-phone-server-nats.service oshioki-phone-server.service
```

The hosting user's service manager must remain running. Use an always-on server
if approvals must work while a laptop sleeps.

| Problem | Next step |
| --- | --- |
| URL expired | Run enrollment again; its lifetime cannot be extended. |
| Host preflight fails | Restore server health, HTTPS trust, and matching origin/RP ID first. |
| Host succeeds but phone cannot connect | Check the phone's network and tailnet access. |
| Enrolled but no notifications | Check permission and push registration in the installed app; `/healthz` alone does not prove delivery. |
| Server confirmation timed out | The host may already have pinned the device. Inspect status and re-enroll once the server is healthy. |

Local browser development can use `oshioki enroll --allow-localhost`; that
does not make the URL reachable from a phone.
