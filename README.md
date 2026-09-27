# vpnctl

A Python CLI that connects your Mac to your existing WireGuard VPN on AWS Lightsail.
It registers your Mac with the server, creates a VPN profile, and controls the connection.

## Requirements

- **Mac:** Python 3.11+, OpenSSH, WireGuard CLI tools (`wg`, `wg-quick`, `wireguard-go`), and Bash 4+ on your PATH. Homebrew Bash must come before `/bin/bash`.
- **Lightsail:** Python 3, a running `wg0` interface, and `/etc/wireguard/wg0.conf`. SSH access must allow root or passwordless sudo.
- **Server configuration:** one IPv4 subnet between `/16` and `/30`, `SaveConfig` absent or `false`, and saved server keys and listening port matching the running interface.

## Install

Run from the project folder:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

In a new terminal, activate `.venv` again before using `vpnctl`.

## First-time setup

### 1. Register your Mac

```sh
vpnctl enroll
```

Enter your Lightsail hostname/IP, SSH username, port, and SSH private-key file path.
Use the actual hostname/IP, not an SSH alias. The key file must be owned by you
with restricted permissions, such as `chmod 600 /path/to/key.pem`.

This creates your Mac's WireGuard keys if needed, registers its public key on the
server, and assigns a VPN address. Private keys stay on your Mac. Later enrollments
reuse the saved settings and identity.

### 2. Create the VPN profile

```sh
vpnctl profile create
```

At the DNS prompt, enter the IPv4 addresses from the `DNS =` line in your working
WireGuard client configuration. The profile is saved to `~/vpnctl/lightsail.conf`.

## Daily use

Deactivate any tunnel in the WireGuard app before using the CLI.

```sh
vpnctl connect
vpnctl status
vpnctl disconnect
```

Run these as your normal user, without `sudo`. They ask for your Mac administrator
password when needed. SSH access is only needed for enrollment.

Status shows the interface, latest handshake, and traffic counters. After your
first connection, check that websites load and your public IPv4 matches Lightsail.
After disconnecting, allow a moment for normal networking to return.

IPv4 internet traffic goes through the VPN. IPv6 internet access is intentionally
unavailable while connected; verify that it does not use your ISP connection.
There is no kill switch: disconnecting allows normal internet access.

## Your files

| File | What it stores |
| --- | --- |
| `~/vpnctl/identity.json` | Your Mac's WireGuard keys |
| `~/vpnctl/server.json` | Server details, SSH key path, and assigned VPN address |
| `~/vpnctl/lightsail.conf` | The VPN profile, including its private key |

These files have owner-only permissions. Keep them private and don't delete them
while using the VPN. Older storage at `~/.config/vpnctl` moves automatically to
`~/vpnctl`; if both folders exist, resolve the conflict before continuing.

## Useful commands

```sh
vpnctl --help
vpnctl keys init                 # Create or reuse your local identity
vpnctl enroll --reconfigure      # Change server or SSH settings
vpnctl profile create --replace  # Regenerate the profile; disconnect first
```

Changing servers does not remove your registration from the previous server.
If enrollment is interrupted, retry with the same identity rather than deleting keys.

If CLI shutdown fails, use these fallback commands for an Apple Silicon Homebrew installation:

```sh
sudo /opt/homebrew/bin/wg show
sudo /opt/homebrew/bin/bash /opt/homebrew/bin/wg-quick down "$HOME/vpnctl/lightsail.conf"
```
