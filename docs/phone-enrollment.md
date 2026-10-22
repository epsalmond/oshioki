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
HTTPS through Tailscale Serve on port 18444 by default. Serve takes that port
for **all tailnet traffic to this host**, not only its `*.ts.net` name. Setup
refuses an unrelated Serve configuration or an existing TCP listener on the
chosen port, and stops if it cannot inspect listeners. On Linux it requires a
systemd user service manager.

Choose another free port with `--https-port <port>` if needed. You can request
`--https-port 443`, but Serve will intercept port 443 for every tailnet client;
setup refuses if another process already listens there. Use `--server-url`
with your existing HTTPS proxy when that proxy should keep serving the phone.

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

To approve requests from several hosts in one installed app, configure those
hosts to use the **same HTTPS origin and Oshioki backend** with the shared NATS
lanes. Repeat enrollment from each host and open each complete enrollment URL
inside that same installed app. Every enrollment keeps its own bearer, passkey,
and decryption key; notifications use one browser subscription for all saved
enrollments. Adding an enrollment to an app with notifications enabled registers
it automatically without another permission prompt. Enable notifications retries
registration for all saved enrollments and reports any partial failures.

Independent backends or HTTPS origins remain separate browser installations.
This feature does not synchronize enrollment credentials or browser notification
state between origins, browser profiles, or phones.

Refresh or reopen the app to load the current browser code before using several
enrollments. An older open app can still replace its subscription when switching
enrollments. If the server does not advertise multi-enrollment support, update it
first; the current app preserves existing notification settings until then.

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

Revoking one enrollment on its host disables only that identity's notification
membership and request access. Other saved enrollments keep the shared browser
subscription and continue to receive and approve their own requests. A generic
notification already in flight may still arrive after revocation; it does not
grant access to the revoked identity's request.

The current app automatically migrates an existing single-enrollment notification
subscription using its recorded original enrollment, even when a different
enrollment is displayed. It preserves the endpoint and the other saved keys.
Notification setup requires browser Web Locks support to coordinate tabs; an
unsupported browser preserves existing registrations and shows the prerequisite.

The app stores a random notification capability in origin-local IndexedDB. It
only proves control of the push endpoint and cannot fetch or approve requests.
If that storage is lost, or the original enrollment can no longer claim an old
subscription, the app preserves the existing endpoint and offers **Replace
notification subscription**. That explicit action unsubscribes the inaccessible
endpoint, creates a fresh one, and registers the enrollments still saved in the
app. Re-enroll first if the enrollment credentials themselves were also lost.
Clearing browser storage is not a way to transfer endpoint ownership.

Managed state and logs live under `~/.local/share/oshioki/phone-server`.
The default ports are NATS 14222, HTTP 18443, and Tailscale HTTPS 18444,
configurable with `--nats-port`, `--server-port`, and `--https-port`. Re-run
setup after a package update. Existing phone setup state keeps its recorded
browser origin; setup refuses an origin change because passkeys and browser
enrollment data are scoped to that origin. On
Linux, setup may leave a running service on the previous binary when its unit
is unchanged. Restart and verify the server unit:

```sh
systemctl --user restart oshioki-phone-server.service
systemctl --user status oshioki-phone-server.service
```

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
| Enrolled but no notifications | Check permission and registration for all saved enrollments in the installed app; `/healthz` alone does not prove delivery. |
| Some enrollments need attention | Retry Enable notifications; confirm each enrollment is still active. Successful registrations remain saved. |
| Notification ownership unavailable | Use the app's explicit Replace notification subscription action after checking that the desired enrollments are saved. |
| Server needs an update | Update the shared backend and refresh the app before enabling multi-enrollment notifications. |
| Server confirmation timed out | The host may already have pinned the device. Inspect status and re-enroll once the server is healthy. |

Local browser development can use `oshioki enroll --allow-localhost`; that
does not make the URL reachable from a phone.
