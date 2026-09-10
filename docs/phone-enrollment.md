# Enroll a phone

Run enrollment on the host whose sudo requests the phone will approve. Open
the resulting URL in the phone's browser. The phone does not run the
`oshioki` command.

The hook needs a reachable HTTPS Oshioki server and a NATS connection to
that server. Local Touch ID setup alone does not provide a browser server.
`localhost` refers to the device opening the URL, so it cannot serve as the
host's address on a phone.

## Tailscale setup

Tailscale is the first choice when it is running on the host. Connect the
phone to the same tailnet, then run these commands on the host:

```sh
oshioki-phone-setup
sudo oshioki enroll
```

Run the setup command as your normal user. It elevates only to update the
installed host configuration. Prerequisites are Python 3, `oshioki-server`,
`nats-server`, and a running Tailscale client. On macOS, install NATS with
`brew install nats-server`; the Oshioki release includes the server and
setup helper. From a source checkout, build the server and use the script:

```sh
cargo build --locked -p oshioki-server -p oshioki-hook
scripts/oshioki-phone-setup
```

Setup creates private persistent state for an owned local NATS broker with
JetStream and an Oshioki server. Both listen on loopback. Tailscale Serve
provides the HTTPS endpoint; the broker is not exposed to the phone. On
macOS, LaunchAgents supervise the services; on Linux, systemd user services
are required. Setup refuses an unrelated Tailscale Serve configuration.

Use `oshioki-phone-setup --check` to inspect prerequisites without applying
the setup. The default loopback ports are 14222 for NATS and 18443 for the
server; `--nats-port` and `--server-port` select alternatives. State and logs
live under `~/.local/share/oshioki/phone-server`.

The macOS service labels are `com.oshioki.phone-server.nats` and
`com.oshioki.phone-server.server`. On Linux, inspect them with:

```sh
systemctl --user status oshioki-phone-server-nats.service oshioki-phone-server.service
```

These are user services: the hosting user's service manager must be running
for the server to be available. An always-on server is preferable if other
hosts need approval while the laptop is asleep.

The printed enrollment URL expires after five minutes. Leave `enroll`
running while you open the URL and complete the browser's WebAuthn prompt.
Enrollment is complete when the host confirms the device was enrolled.

## An existing HTTPS server

Users without Tailscale can run an Oshioki server behind their own HTTPS
reverse proxy or use an existing deployment. The certificate must be
trusted by both the host and the phone, and the hostname must resolve and
be reachable from both. See [server configuration](configuration.md) and
[production requirements](requirements.md) for the server and NATS setup.

Configure the server with matching values:

```text
OSHIOKI_ORIGIN=https://sudo.example.com
OSHIOKI_RP_ID=sudo.example.com
```

Put the host role's NATS settings in a private file. Do not put credentials
in command arguments:

```text
NATS_URL=tls://nats.example.com:4222
NATS_USER=oshioki-hook
NATS_PASS=<host-role-password>
```

Then run:

```sh
chmod 600 /path/to/hook-nats.env
oshioki-phone-setup --server-url https://sudo.example.com --nats-config /path/to/hook-nats.env
sudo oshioki enroll
```

This option does not start local services or configure Tailscale. Plaintext
NATS is permitted only on loopback. An HTTPS reverse proxy can forward to
the server's loopback HTTP listener; WebAuthn uses the public HTTPS origin.

## Configuration and troubleshooting

Setup checks the public server before updating `/etc/oshioki/hook.json`,
`config.env`, and `install.env`. It preserves the local agent socket,
device registry, and native identity. The server's reported origin and RP
ID must agree with the host configuration. Keep the hostname stable:
browser credentials are scoped to their WebAuthn RP ID. Changing it after
enrollment requires planning for new browser credentials.

`sudo oshioki enroll` checks the HTTPS endpoint before creating an
enrollment. If it reports that the server is unavailable, fix server or
network access first. A successful host check cannot prove the phone's
network access; check that the phone is on the tailnet when using Serve.

For deliberate local browser development, use
`sudo oshioki enroll --allow-localhost`. This permits a loopback origin;
it does not bypass certificate verification or make the URL accessible
from another device.
