"""Standalone helper sent to the Linux server over SSH; requires root.

No client private key is accepted. Existing peers and hooks are preserved.
Only native wg-quick configuration with SaveConfig disabled is supported.
"""

import base64
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


CONFIG = Path("/etc/wireguard/wg0.conf")
INTERFACE = "wg0"


class EnrollmentError(Exception):
    pass


def wg(*args, input_text=None):
    result = subprocess.run(["wg", *args], input=input_text, capture_output=True,
                            text=True, timeout=15)
    if result.returncode:
        raise EnrollmentError("WireGuard operation failed; ensure wg0 is running. Retry enrollment after resolving the issue.")
    return result.stdout.strip()


def parse_config(text):
    """Read repeated Peer sections while retaining the original text for writes."""
    interface = None
    peers = []
    current = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line == "[Interface]":
            if interface is not None:
                raise EnrollmentError("Multiple Interface sections are unsupported.")
            interface = current = {}
        elif line == "[Peer]":
            current = {}
            peers.append(current)
        elif current is not None and "=" in line:
            key, value = (part.strip() for part in line.split("=", 1))
            current.setdefault(key.lower(), []).append(value)
        else:
            raise EnrollmentError("Unsupported WireGuard configuration syntax; no changes made.")
    if interface is None:
        raise EnrollmentError("Missing Interface section.")
    return interface, peers


def networks(values):
    return [ipaddress.ip_network(item.strip(), strict=False)
            for value in values for item in value.split(",") if item.strip()]


def one_address(ranges, subnet):
    if len(ranges) != 1 or ranges[0].version != 4 or ranges[0].prefixlen != 32:
        raise EnrollmentError("Existing client must have exactly one IPv4 /32 assignment; refusing to change it.")
    address = ranges[0].network_address
    if address not in subnet or address in (subnet.network_address, subnet.broadcast_address):
        raise EnrollmentError("Existing client address is outside the usable server subnet.")
    return address


def write_file(path, text):
    fd, name = tempfile.mkstemp(prefix=".vpnctl-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        Path(name).unlink(missing_ok=True)


def enroll(public_key):
    decoded = base64.b64decode(public_key, validate=True)
    if len(decoded) != 32 or not any(decoded) or base64.b64encode(decoded).decode("ascii") != public_key:
        raise EnrollmentError("Invalid client public key.")
    if os.geteuid() != 0:
        raise EnrollmentError("Server enrollment requires root privileges.")
    lock_fd = os.open(str(CONFIG) + ".vpnctl.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise EnrollmentError("Another enrollment is running; retry shortly.") from None
        info = CONFIG.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise EnrollmentError("wg0.conf must be a root-owned regular file, not writable by group/others.")
        original = CONFIG.read_text(encoding="utf-8")
        interface, peers = parse_config(original)
        if any(value.lower() != "false" for value in interface.get("saveconfig", [])):
            raise EnrollmentError("SaveConfig must be disabled before automated enrollment; otherwise shutdown can overwrite persisted peers. No changes made.")
        addresses = [ipaddress.ip_interface(item.strip())
                     for value in interface.get("address", []) for item in value.split(",")]
        ipv4 = [address for address in addresses if address.version == 4]
        if len(ipv4) != 1 or not 16 <= ipv4[0].network.prefixlen <= 30:
            raise EnrollmentError("Expected one server IPv4 Address with a subnet between /16 and /30.")
        subnet = ipv4[0].network
        server_address = ipv4[0].ip
        server_public_key = wg("show", INTERFACE, "public-key")
        private_keys = interface.get("privatekey", [])
        if len(private_keys) != 1 or wg("pubkey", input_text=private_keys[0] + "\n") != server_public_key:
            raise EnrollmentError("Running server identity differs from wg0.conf; reconcile it before enrolling.")
        listen_port = int(wg("show", INTERFACE, "listen-port"))
        if not 1 <= listen_port <= 65535 or interface.get("listenport") != [str(listen_port)]:
            raise EnrollmentError("Set a persistent ListenPort matching running wg0 before enrolling.")

        assigned = {}
        for peer in peers:
            keys = peer.get("publickey", [])
            if len(keys) != 1 or keys[0] in assigned:
                raise EnrollmentError("Missing or duplicate peer public keys in wg0.conf.")
            assigned[keys[0]] = networks(peer.get("allowedips", []))
            if keys[0] == public_key and set(peer) - {"publickey", "allowedips"}:
                raise EnrollmentError("Existing client has additional peer settings; refusing to overwrite them.")
        live = {}
        for line in wg("show", INTERFACE, "allowed-ips").splitlines():
            key, value = line.split(None, 1)
            live[key] = [] if value.strip() == "(none)" else networks([value.replace(" ", ",")])
        occupied = [network for mapping in (assigned, live)
                    for key, ranges in mapping.items() if key != public_key
                    for network in ranges if network.version == 4]

        if public_key in assigned:
            address = one_address(assigned[public_key], subnet)
            if public_key in live and live[public_key] != assigned[public_key]:
                raise EnrollmentError("Client assignments differ between live and saved state; refusing to change them.")
        elif public_key in live:
            # A runtime-only peer may have extra settings that are not visible
            # in allowed-ips. Do not silently persist an incomplete definition.
            raise EnrollmentError("Client exists only in running wg0; persist its configuration before retrying.")
        else:
            address = next((candidate for candidate in subnet.hosts()
                            if candidate != server_address
                            and not any(candidate in network for network in occupied)), None)
            if address is None:
                raise EnrollmentError("No unused client addresses remain in the server subnet.")
        if address == server_address or any(address in network for network in occupied):
            raise EnrollmentError("Client address conflicts with another assignment; no changes made.")
        cidr = str(address) + "/32"
        created = public_key not in assigned
        if created:
            # Keep the latest pre-enrollment configuration as a protected backup.
            write_file(Path(str(CONFIG) + ".vpnctl.bak"), original)
            if CONFIG.read_text(encoding="utf-8") != original:
                raise EnrollmentError("wg0.conf changed during enrollment; retry.")
            updated = original.rstrip() + "\n\n[Peer]\nPublicKey = " + public_key + "\nAllowedIPs = " + cidr + "\n"
            write_file(CONFIG, updated)
        # Persist first. If this step fails, a retry uses the saved address and
        # completes activation rather than allocating another identity/address.
        if public_key not in live:
            wg("set", INTERFACE, "peer", public_key, "allowed-ips", cidr)
        current = wg("show", INTERFACE, "allowed-ips")
        if not any(line.split(None, 1) == [public_key, cidr] for line in current.splitlines()):
            raise EnrollmentError("Peer was saved but activation could not be verified. Retry enrollment.")
        return {"public_key": public_key, "address": cidr, "subnet": str(subnet),
                "server_public_key": server_public_key, "listen_port": listen_port,
                "interface": INTERFACE, "created": created}


def main():
    try:
        if len(sys.argv) != 2:
            raise EnrollmentError("Expected a client public key.")
        print(json.dumps(enroll(sys.argv[1])))
    except EnrollmentError as error:
        print("vpnctl server: " + str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        # Configuration and subprocess errors can contain the server private key.
        print("vpnctl server: Could not process wg0 configuration or run WireGuard. A peer may have been persisted; retry with the same identity after resolving the server issue.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
