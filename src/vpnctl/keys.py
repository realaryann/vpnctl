"""Generate and validate client keys using the installed WireGuard tools."""

import base64
import binascii
import subprocess


class WireGuardKeyError(Exception):
    """A key is invalid or a WireGuard key operation failed."""


def validateKey(value: str) -> None:
    """Require a canonical base64-encoded, nonzero 32-byte key."""
    if not isinstance(value, str):
        raise WireGuardKeyError("Invalid WireGuard key format.")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise WireGuardKeyError("Invalid WireGuard key format.") from None
    if (
        len(decoded) != 32
        or not any(decoded)
        or base64.b64encode(decoded).decode("ascii") != value
    ):
        raise WireGuardKeyError("Invalid WireGuard key format.")


def _runWg(operation: str, privateKey: str | None = None) -> str:
    try:
        result = subprocess.run(
            ["wg", operation],
            input=privateKey + "\n" if privateKey is not None else None,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
    except FileNotFoundError:
        raise WireGuardKeyError("WireGuard 'wg' was not found. Install wireguard-tools and ensure wg is on PATH.") from None
    except subprocess.TimeoutExpired:
        raise WireGuardKeyError("WireGuard key operation timed out.") from None
    except (OSError, subprocess.CalledProcessError, UnicodeError):
        # Never include subprocess output: it may contain private key material.
        raise WireGuardKeyError("WireGuard key operation failed. Check your local wg installation.") from None
    value = result.stdout.strip()
    validateKey(value)
    return value


def generatePrivateKey() -> str:
    return _runWg("genkey")


def derivePublicKey(privateKey: str) -> str:
    validateKey(privateKey)
    return _runWg("pubkey", privateKey)


def generateKeypair() -> tuple[str, str]:
    privateKey = generatePrivateKey()
    publicKey = derivePublicKey(privateKey)
    return privateKey, publicKey
