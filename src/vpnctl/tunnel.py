"""macOS tunnel control through the installed WireGuard CLI tools."""

from contextlib import contextmanager
import fcntl
import os
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import time

from .storage import configDirectory


class TunnelError(Exception):
    """A tunnel operation could not complete safely."""


class Tunnel:
    def __init__(self):
        if platform.system() != "Darwin":
            raise TunnelError("Tunnel control currently supports macOS only.")
        if os.geteuid() == 0:
            raise TunnelError("Run vpnctl as your normal user; it will request sudo when needed.")
        self.directory = configDirectory()
        self.profile = self.directory / "lightsail.conf"
        self.wg = self._tool("wg")
        self.quick = self._tool("wg-quick")

    def authenticate(self):
        # Inherit the terminal so the sudo password prompt remains visible.
        result = subprocess.run(["/usr/bin/sudo", "-v"], check=False)
        if result.returncode:
            raise TunnelError("Administrator authentication was cancelled or failed.")

    @staticmethod
    def _tool(name):
        path = shutil.which(name)
        if path is None:
            raise TunnelError(f"Missing {name}. Install WireGuard CLI tools and ensure they are on PATH.")
        return path

    @contextmanager
    def locked(self):
        fd = os.open(self.directory / "tunnel.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise TunnelError("Another tunnel operation is running. Try again shortly.") from None
            yield

    def _read(self, *command):
        try:
            result = subprocess.run(["/usr/bin/sudo", "-n", "--", *command],
                                    capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            raise TunnelError("Timed out querying tunnel state or waiting for sudo.") from None
        if result.returncode:
            raise TunnelError("Could not query WireGuard. Check administrator authentication and the installed tools.")
        return result.stdout.strip()

    def interface(self):
        # wg-quick maps the profile name to a dynamically allocated macOS utun.
        # Match its socket/name timestamp check to avoid trusting a stale mapping.
        script = '''
p=/var/run/wireguard/lightsail.name
[ -f "$p" ] || exit 0
IFS= read -r iface < "$p"
case "$iface" in utun[0-9]*) ;; *) exit 1 ;; esac
[ -S "/var/run/wireguard/$iface.sock" ] || exit 0
a=$(/usr/bin/stat -f %m "$p") || exit 1
b=$(/usr/bin/stat -f %m "/var/run/wireguard/$iface.sock") || exit 1
d=$((b-a))
[ "$d" -lt 2 ] && [ "$d" -gt -2 ] || exit 0
printf '%s' "$iface"
'''
        interface = self._read("/bin/sh", "-c", script)
        if not interface:
            return None
        if not re.fullmatch(r"utun[0-9]+", interface):
            raise TunnelError("Invalid WireGuard interface mapping.")
        if interface not in self._read(self.wg, "show", "interfaces").split():
            return None
        return interface

    def _checkProfile(self):
        try:
            fd = os.open(self.profile, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            raise TunnelError("No profile found. Run vpnctl profile create first.") from None
        with os.fdopen(fd, encoding="utf-8") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise TunnelError("lightsail.conf must be a regular file owned by you with permissions 0600.")
            contents = stream.read(65537)
        if len(contents) > 65536:
            raise TunnelError("Profile is too large.")
        for raw in contents.splitlines():
            key = raw.split("#", 1)[0].split("=", 1)[0].strip().lower()
            if key in {"preup", "postup", "predown", "postdown", "saveconfig"}:
                raise TunnelError("Custom hooks and SaveConfig are unsupported. Use a vpnctl-generated profile.")

    def _change(self, action):
        self._checkProfile()
        bash = self._tool("bash")
        version = subprocess.run([bash, "-c", 'printf "%s" "${BASH_VERSINFO[0]}"'],
                                 capture_output=True, text=True, timeout=10)
        if version.returncode or not version.stdout.isdigit() or int(version.stdout) < 4:
            raise TunnelError("wg-quick requires Bash 4+. Put Homebrew bash on PATH before Apple's /bin/bash.")
        # Authenticate separately; do not pipe wg-quick output because its
        # background route monitor can inherit the pipe and keep it open.
        self._read("/usr/bin/true")
        with tempfile.TemporaryFile(mode="w+t") as output:
            result = subprocess.run(
                ["/usr/bin/sudo", "-n", "--", bash, self.quick, action, str(self.profile)],
                stdout=output, stderr=output, text=True,
            )
        if result.returncode:
            raise TunnelError(
                f"wg-quick {action} failed. See the README for manual inspection and shutdown commands. "
                "Check that the WireGuard app tunnel is deactivated and CLI dependencies are installed."
            )

    def connect(self):
        self._tool("wireguard-go")
        with self.locked():
            interface = self.interface()
            if interface:
                return f"Tunnel already active on {interface}. Use vpnctl status to inspect its handshake."
            self._change("up")
            interface = self.interface()
            if interface is None:
                raise TunnelError("Startup returned successfully but no interface was found. Inspect networking before retrying.")
            return f"Tunnel started on {interface}. Use vpnctl status to inspect its handshake."

    def disconnect(self):
        """Stop only the CLI-managed lightsail interface, if it exists."""
        with self.locked():
            if self.interface() is None:
                return "Tunnel already inactive: no CLI-managed lightsail interface."
            self._change("down")
            if self.interface() is not None:
                raise TunnelError("The interface still appears active after wg-quick down. See the README for manual shutdown.")
            return "Tunnel stopped. Allow a moment for wg-quick's background route and DNS cleanup."

    def status(self):
        """Report public runtime fields without exposing private or preshared keys."""
        with self.locked():
            interface = self.interface()
            if interface is None:
                return "Inactive: no CLI-managed lightsail tunnel. WireGuard app tunnels are managed separately."
            # Never use `wg show ... dump`: its output contains secret keys.
            handshakes = self._read(self.wg, "show", interface, "latest-handshakes")
            transfers = self._read(self.wg, "show", interface, "transfer")
            lines = ["Tunnel: lightsail (active)", f"Interface: {interface}"]
            try:
                traffic = {}
                for row in transfers.splitlines():
                    key, received, sent = row.split()
                    received, sent = int(received), int(sent)
                    if received < 0 or sent < 0:
                        raise ValueError
                    traffic[key] = (received, sent)
                for row in handshakes.splitlines():
                    key, timestamp = row.split()
                    stamp = int(timestamp)
                    if stamp < 0 or key not in traffic:
                        raise ValueError
                    if stamp == 0:
                        description = "never (handshake not established)"
                    else:
                        age = max(0, int(time.time()) - stamp)
                        description = f"{age} seconds ago"
                    received, sent = traffic[key]
                    lines.extend([
                        f"Peer: {key}",
                        f"Latest handshake: {description}",
                        f"Received: {received:,} bytes",
                        f"Sent: {sent:,} bytes",
                    ])
            except ValueError:
                raise TunnelError("Unexpected WireGuard status output. Retry vpnctl status.") from None
            if not handshakes:
                lines.append("No peers configured on this interface.")
            lines.append("An active interface does not by itself confirm internet connectivity.")
            return "\n".join(lines)
