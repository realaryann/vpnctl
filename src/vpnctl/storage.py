"""Persist a client identity without overwriting an existing one."""

import json
import os
import stat
import tempfile
from pathlib import Path

from .keys import derivePublicKey, generateKeypair, validateKey


class StorageError(Exception):
    """The local identity cannot be safely read or written."""


def _readIdentity(path: Path) -> dict:
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
    validateKey(identity["private_key"])
    validateKey(identity["public_key"])
    if derivePublicKey(identity["private_key"]) != identity["public_key"]:
        raise StorageError("Stored public and private keys do not match; they have not been replaced.")
    return identity


def _loadIdentity(path: Path) -> str:
    return _readIdentity(path)["public_key"]


def loadIdentity() -> dict:
    """Load an existing identity; never generate a replacement for a profile."""
    try:
        return _readIdentity(configDirectory() / "identity.json")
    except FileNotFoundError:
        raise StorageError("No local identity found. Run vpnctl enroll first.") from None


def saveProfile(contents: str, replace: bool = False) -> Path:
    """Publish a complete owner-only profile, requiring explicit replacement."""
    directory = configDirectory()
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


def configDirectory() -> Path:
    """Use a visible directory, migrating the old directory without merging it."""
    directory = Path.home() / "vpnctl"
    legacy = Path.home() / ".config" / "vpnctl"
    if os.path.lexists(legacy):
        legacyInfo = legacy.lstat()
        if not stat.S_ISDIR(legacyInfo.st_mode) or legacyInfo.st_uid != os.getuid():
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


def loadServerSettings() -> dict | None:
    path = configDirectory() / "server.json"
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


def saveServerSettings(settings: dict) -> None:
    directory = configDirectory()
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


def initializeIdentity() -> tuple[Path, str, bool]:
    """Return (path, public key, created), reusing a valid existing identity."""
    directory = configDirectory()
    path = directory / "identity.json"
    try:
        return path, _loadIdentity(path), False
    except FileNotFoundError:
        pass

    privateKey, publicKey = generateKeypair()
    identity = {"version": 1, "private_key": privateKey, "public_key": publicKey}
    fd, temporaryName = tempfile.mkstemp(prefix="identity-", dir=directory)
    temporaryPath = Path(temporaryName)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(identity, stream)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        try:
            # Publish a complete file atomically; never replace an existing identity.
            os.link(temporaryPath, path)
        except FileExistsError:
            return path, _loadIdentity(path), False
        return path, publicKey, True
    finally:
        temporaryPath.unlink(missing_ok=True)
