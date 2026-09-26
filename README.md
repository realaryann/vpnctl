# vpnctl

A Python CLI for a personal WireGuard VPN hosted on Lightsail.

## Development setup

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
vpnctl --help
```

The Mac needs OpenSSH and the `wg` executable from WireGuard tools.

## Local storage

All vpnctl runtime files live in the visible `vpnctl` folder in your home folder:

```text
~/vpnctl/
  identity.json
  server.json
  lightsail.conf
```

The next command that accesses storage automatically moves an existing
`~/.config/vpnctl` directory to `~/vpnctl`, keeping the same keys, enrollment,
and profile. If both directories exist, the command stops rather than merging
or overwriting identities. Resolve those conflicts before continuing.
Folder permissions remain `0700`, and generated files remain `0600`.
Your SSH private key stays at the path you selected during enrollment.

## Initialize and enroll

```sh
vpnctl keys init
vpnctl enroll
```

On first enrollment, type the server hostname/IP, SSH username, port, and
Lightsail SSH private-key path at the prompts. Use a real hostname/IP rather
than an SSH config alias. `~` in the key path is supported; enter paths with
spaces directly, without shell quotes. The private-key file must belong to
your user and have owner-only permissions (`chmod 600 /path/to/key.pem`).

Enrollment creates the local WireGuard identity if it does not exist. Its
private key stays on the Mac. OpenSSH uses the selected SSH key directly;
vpnctl does not copy it or save its contents/passphrase. SSH retains host-key
verification and can prompt for an encrypted key's passphrase. This flow uses
explicit connection settings rather than `~/.ssh/config` or SSH agent identities.

After successful enrollment, connection settings (including only the SSH key
path) and registration details are saved in `~/vpnctl/server.json` with
permissions `0600`. Later enrollments reuse them. To replace the settings or
choose a different key, run `vpnctl enroll --reconfigure` and type them again.
Changing servers does not revoke your peer from the previous server.

## Server requirements and behavior

The enrollment helper is sent over SSH and run with Python 3; no permanent
helper installation is required. The SSH user must be root or have passwordless
sudo permission to run the helper as root. This first implementation uses your
administrative SSH credential; a restricted, preinstalled helper is future work.

Supported server setup:

- Native, running `wg0`, managed through `/etc/wireguard/wg0.conf`.
- Root-owned configuration that is not group/other writable.
- One IPv4 interface address with a `/16` through `/30` subnet.
- A configured `ListenPort` matching the running interface, and matching server keys.
- `SaveConfig` absent or `false`; automatically rewriting configuration on
  shutdown is incompatible with this persistence approach.

The helper allocates an IPv4 `/32` from the configured subnet, excluding the
server, network/broadcast addresses and all ranges assigned to other peers in
both saved and running state. All remaining addresses are considered available;
manually reserved addresses outside WireGuard assignments are not tracked yet.
It reuses an existing assignment for the same public key. Complex preexisting
client configurations and runtime-only client peers require manual reconciliation.

New peers are appended without restarting wg0 or replacing existing peers.
The prior file is backed up to `/etc/wireguard/wg0.conf.vpnctl.bak` with owner-only
permissions (the backup is replaced on the next new enrollment). Enrollment
uses a lock to serialize vpnctl invocations; avoid other administrative edits
or interface restarts during enrollment.

The saved assignment is written before activation. If SSH is interrupted or
activation fails, retry with the same local identity; do not regenerate keys.
Local settings are only saved after a successful response, so a first failed
attempt may prompt for SSH details again.

## Generate a client profile

After successful enrollment:

```sh
vpnctl profile create
```

Enter the IPv4 DNS server address(es) from your working WireGuard configuration
when prompted, separated by commas. You can also supply `--dns ADDRESS`.
The DNS servers must be reachable through Lightsail. IPv6 DNS servers are not
supported by the current IPv4-only enrollment.

The command uses the enrolled address, server public key and WireGuard port,
and your existing local private key. The saved SSH hostname/IP is the default
VPN endpoint; use `--endpoint HOST` if the public VPN endpoint differs. This
option takes no port: the WireGuard port comes from enrollment, not the SSH port.
No SSH connection is needed to create a profile.

The profile is saved to `~/vpnctl/lightsail.conf` with permissions `0600`.
It contains your private key and is never printed. Existing profiles require
`--replace` to overwrite; disconnect the imported tunnel before regeneration
and reimport the updated file afterward.

The profile includes both default routes (`0.0.0.0/0, ::/0`). It assigns a
deterministic local IPv6 ULA to the tunnel, but does not register that IPv6
address on the server. IPv6 traffic is therefore directed into the tunnel and
rejected by the server's IPv4-only peer assignment. IPv6 internet access is
intentionally unavailable in this version. This is not a kill switch and does
not prevent traffic when the tunnel is deactivated. Verify IPv6 routing on your
Mac before relying on the profile; local/specific routes can take precedence.

To check the profile:

1. Disconnect your existing WireGuard tunnel.
2. Import `lightsail.conf` into the WireGuard app from the `vpnctl` folder
   in your home folder (or use Command-Shift-G to open `~/vpnctl/`).
3. Activate it and check for a recent handshake and increasing traffic counters.
4. Verify your public IPv4 matches Lightsail and DNS works. IPv6 internet
   requests should fail rather than use your ISP address.
5. Deactivate it and verify ordinary networking returns.

Profile generation does not start a tunnel or modify server settings.

## Connect from the CLI (macOS)

Deactivate the imported WireGuard app tunnel first, then run as your normal user:

```sh
vpnctl connect
```

The command requests administrator authentication through sudo. Do not run
`sudo vpnctl`: vpnctl needs your user's profile directory. It requires `wg`,
`wg-quick`, `wireguard-go`, and Bash 4+ on PATH. Homebrew Bash must precede
Apple's older `/bin/bash`.

Connect uses `~/vpnctl/lightsail.conf` and delegates route and DNS setup to
macOS wg-quick. Keep the profile in place and do not regenerate or edit it while
connected. Custom hooks and SaveConfig are unsupported. Repeated connect calls
report when the CLI-managed interface already exists. A local lock prevents
concurrent vpnctl connection attempts.

To stop the CLI-managed tunnel, run:

```sh
vpnctl disconnect
```

Disconnect requests administrator authentication, runs `wg-quick down`, and
verifies the interface mapping is gone. Repeated calls report that the tunnel
is already inactive. It does not stop tunnels managed by the WireGuard app.
Keep `~/vpnctl/lightsail.conf` available until shutdown completes.

`vpnctl status` remains a placeholder. For now, inspect the tunnel with:

```sh
sudo /opt/homebrew/bin/wg show
```

To disconnect manually on your current Homebrew installation:

```sh
sudo /opt/homebrew/bin/bash /opt/homebrew/bin/wg-quick down "$HOME/vpnctl/lightsail.conf"
```

Allow wg-quick's background monitor a moment to restore routes and DNS. Use
these same commands to inspect and stop an interface after a failed startup.
wg-quick performs its own startup cleanup; vpnctl does not claim that all
networking was restored following a failed operation.

An active interface does not confirm internet connectivity. Repeat the IPv4,
DNS and IPv6 checks above after first CLI activation: the app and wg-quick
configure macOS networking differently. CLI interface detection does not
manage the WireGuard app's separate tunnels.
