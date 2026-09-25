"""SSH transport for enrolling a public key on the existing Lightsail server."""

import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess

from .keys import validate_key


class EnrollmentError(Exception):
    """Enrollment could not complete."""


def validate_connection(settings: dict) -> Path:
    host = settings.get("host", "")
    user = settings.get("user", "")
    port = settings.get("port")
    if not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]*", host):
        raise EnrollmentError("Enter a server hostname or IP address without an SSH username or URL prefix.")
    if not isinstance(user, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", user):
        raise EnrollmentError("Invalid SSH username.")
    if type(port) is not int or not 1 <= port <= 65535:
        raise EnrollmentError("SSH port must be between 1 and 65535.")
    raw_path = settings.get("key_path")
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise EnrollmentError("An SSH private-key path is required.")
    try:
        path = Path(raw_path).expanduser().resolve(strict=True)
        info = path.stat()
    except (OSError, RuntimeError):
        raise EnrollmentError("The SSH private-key path does not resolve to an accessible file.") from None
    if not stat.S_ISREG(info.st_mode) or not os.access(path, os.R_OK):
        raise EnrollmentError("The SSH private key must be a readable regular file.")
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise EnrollmentError("The SSH private key must belong to you and have no group/other permissions (use chmod 600 on it).")
    return path


def register_peer(settings: dict, public_key: str) -> dict:
    key_path = validate_connection(settings)
    validate_key(public_key)
    helper = Path(__file__).with_name("server_enroll.py").read_text(encoding="utf-8")
    remote = ["python3", "-", public_key]
    if settings["user"] != "root":
        remote = ["sudo", "-n", "--", *remote]
    command = [
        "ssh", "-F", "/dev/null", "-T",
        "-o", "StrictHostKeyChecking=ask",
        "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
        "-o", "PreferredAuthentications=publickey",
        "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
        "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=2",
        "-i", str(key_path), "-p", str(settings["port"]),
        "-l", settings["user"], settings["host"], shlex.join(remote),
    ]
    try:
        # SSH reads host-key and passphrase prompts from the terminal. Only the
        # helper source and the WireGuard PUBLIC key are sent to the server.
        result = subprocess.run(command, input=helper, stdout=subprocess.PIPE,
                                text=True, timeout=120, check=False)
    except FileNotFoundError:
        raise EnrollmentError("OpenSSH 'ssh' was not found on PATH.") from None
    except subprocess.TimeoutExpired:
        raise EnrollmentError("Enrollment timed out; the server may have saved the peer. Retry with the same identity.") from None
    except (OSError, UnicodeError):
        raise EnrollmentError("Could not run SSH or read its response. Retry with the same identity.") from None
    if result.returncode:
        raise EnrollmentError("Enrollment failed. Check the SSH/server message above. The server needs Python 3, wg, and root or passwordless sudo access. Retrying with the same identity is safe.")
    try:
        response = json.loads(result.stdout)
        if not isinstance(response, dict) or response.get("public_key") != public_key:
            raise ValueError
        validate_key(response["server_public_key"])
        address = ipaddress.ip_interface(response["address"])
        if address.version != 4 or address.network.prefixlen != 32:
            raise ValueError
        if type(response["listen_port"]) is not int or not 1 <= response["listen_port"] <= 65535:
            raise ValueError
        if response["interface"] != "wg0":
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise EnrollmentError("Invalid enrollment response. The peer may already exist; retry with the same identity.") from None
    return response
