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

from .storage import config_directory


class TunnelError(Exception):
    """A tunnel operation could not complete safely."""


class Tunnel:
    def __init__(self):
        if platform.system() != "Darwin":
            raise TunnelError("Tunnel control currently supports macOS only.")
        if os.geteuid() == 0:
            raise TunnelError("Run vpnctl as your normal user; it will request sudo when needed.")
        self.directory = config_directory()
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

    def _check_profile(self):
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

    def _start(self):
        self._check_profile()
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
                ["/usr/bin/sudo", "-n", "--", bash, self.quick, "up", str(self.profile)],
                stdout=output, stderr=output, text=True,
            )
        if result.returncode:
            raise TunnelError(
                "wg-quick up failed. See the README for manual inspection and shutdown commands. "
                "Check that the WireGuard app tunnel is deactivated and CLI dependencies are installed."
            )

    def connect(self):
        self._tool("wireguard-go")
        with self.locked():
            interface = self.interface()
            if interface:
                return f"Tunnel already active on {interface}. Use sudo wg show to inspect its handshake."
            self._start()
            interface = self.interface()
            if interface is None:
                raise TunnelError("Startup returned successfully but no interface was found. Inspect networking before retrying.")
            return f"Tunnel started on {interface}. Use sudo wg show to inspect its handshake."

