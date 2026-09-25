"""Persist a client identity without overwriting an existing one."""

import json
import os
import stat
import tempfile
from pathlib import Path

from .keys import derivePublicKey, generateKeypair, validate_key


class StorageError(Exception):
    """The local identity cannot be safely read or written."""


def _load_identity(path: Path) -> str:
    """Validate the stored keypair and return only its public key."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise StorageError("Identity must be a regular file owned by your user.")
        os.fchmod(stream.fileno(), 0o600)
        try:
            identity = json.loads(stream.read(4097))
        except (ValueError, UnicodeError):
            raise StorageError("Stored identity is invalid; it has not been replaced.") from None
    if (
        not isinstance(identity, dict)
        or identity.get("version") != 1
        or "private_key" not in identity
        or "public_key" not in identity
    ):
        raise StorageError("Stored identity is incomplete or unsupported; it has not been replaced.")
    validate_key(identity["private_key"])
    validate_key(identity["public_key"])
    if derivePublicKey(identity["private_key"]) != identity["public_key"]:
        raise StorageError("Stored public and private keys do not match; they have not been replaced.")
    return identity["public_key"]


def initialize_identity() -> tuple[Path, str, bool]:
    """Return (path, public key, created), reusing a valid existing identity."""
    directory = Path.home() / ".config" / "vpnctl"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise StorageError("Identity directory must be a real directory owned by your user.")
    directory.chmod(0o700)
    path = directory / "identity.json"
    try:
        return path, _load_identity(path), False
    except FileNotFoundError:
        pass

    private_key, public_key = generateKeypair()
    identity = {"version": 1, "private_key": private_key, "public_key": public_key}
    fd, temporary_name = tempfile.mkstemp(prefix=".identity-", dir=directory)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(identity, stream)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        try:
            # Publish a complete file atomically; never replace an existing identity.
            os.link(temporary_path, path)
        except FileExistsError:
            return path, _load_identity(path), False
        return path, public_key, True
    finally:
        temporary_path.unlink(missing_ok=True)
