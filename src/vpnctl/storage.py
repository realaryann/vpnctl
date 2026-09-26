"""Persist a client identity without overwriting an existing one."""

import json
import os
import stat
import tempfile
from pathlib import Path

from .keys import derivePublicKey, generateKeypair, validate_key


class StorageError(Exception):
    """The local identity cannot be safely read or written."""


def _read_identity(path: Path) -> dict:
    """Read and validate the stored keypair without displaying its contents."""
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
    return identity


def _load_identity(path: Path) -> str:
    return _read_identity(path)["public_key"]


def load_identity() -> dict:
    """Load an existing identity; never generate a replacement for a profile."""
    try:
        return _read_identity(config_directory() / "identity.json")
    except FileNotFoundError:
        raise StorageError("No local identity found. Run vpnctl enroll first.") from None


def save_profile(contents: str, replace: bool = False) -> Path:
    """Publish a complete owner-only profile, requiring explicit replacement."""
    directory = config_directory()
    target = directory / "lightsail.conf"
    fd, name = tempfile.mkstemp(prefix="profile-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(name, target)
        else:
            try:
                os.link(name, target)
            except FileExistsError:
                raise StorageError("Profile already exists. Use --replace to regenerate it while the tunnel is disconnected.") from None
    finally:
        Path(name).unlink(missing_ok=True)
    return target


def config_directory() -> Path:
    """Use a visible directory, migrating the old directory without merging it."""
    directory = Path.home() / "vpnctl"
    legacy = Path.home() / ".config" / "vpnctl"
    if os.path.lexists(legacy):
        legacy_info = legacy.lstat()
        if not stat.S_ISDIR(legacy_info.st_mode) or legacy_info.st_uid != os.getuid():
            raise StorageError("Legacy storage must be a real directory owned by your user before migration.")
        if os.path.lexists(directory):
            raise StorageError(
                "Both ~/vpnctl and ~/.config/vpnctl exist. Move the legacy files into "
                "~/vpnctl after resolving any conflicts, then remove the legacy directory. "
                "No identities have been overwritten."
            )
        # Rename the entire directory so identity, enrollment and profile move
        # together. If migration fails, stop rather than create a new identity.
        legacy.chmod(0o700)
        legacy.rename(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise StorageError("Identity directory must be a real directory owned by your user.")
    directory.chmod(0o700)
    return directory


def load_server_settings() -> dict | None:
    path = config_directory() / "server.json"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise StorageError("Server settings must be a regular file owned by your user.")
        os.fchmod(stream.fileno(), 0o600)
        try:
            settings = json.loads(stream.read(16385))
        except (ValueError, UnicodeError):
            raise StorageError("Invalid server settings. Run vpnctl enroll --reconfigure.") from None
    if not isinstance(settings, dict) or settings.get("version") != 1:
        raise StorageError("Unsupported server settings. Run vpnctl enroll --reconfigure.")
    return settings


def save_server_settings(settings: dict) -> None:
    directory = config_directory()
    fd, name = tempfile.mkstemp(prefix="server-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(settings, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, directory / "server.json")
    finally:
        Path(name).unlink(missing_ok=True)


def initialize_identity() -> tuple[Path, str, bool]:
    """Return (path, public key, created), reusing a valid existing identity."""
    directory = config_directory()
    path = directory / "identity.json"
    try:
        return path, _load_identity(path), False
    except FileNotFoundError:
        pass

    private_key, public_key = generateKeypair()
    identity = {"version": 1, "private_key": private_key, "public_key": public_key}
    fd, temporary_name = tempfile.mkstemp(prefix="identity-", dir=directory)
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
