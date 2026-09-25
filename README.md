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
path) and registration details are saved in `~/.config/vpnctl/server.json` with
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

Enrollment currently registers the IPv4 peer only. Generating the full-tunnel
client profile, its DNS/IPv6 policy, and implementing connect/disconnect/status
remain separate milestones. Enrollment does not start the VPN.
