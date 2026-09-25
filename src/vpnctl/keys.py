"""Generate and validate client keys using the installed WireGuard tools."""

import base64
import binascii
import subprocess


class WireGuardKeyError(Exception):
    """A key is invalid or a WireGuard key operation failed."""


def validate_key(value: str) -> None:
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


def _run_wg(operation: str, private_key: str | None = None) -> str:
    try:
        result = subprocess.run(
            ["wg", operation],
            input=private_key + "\n" if private_key is not None else None,
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
    validate_key(value)
    return value


def generatePrivateKey() -> str:
    return _run_wg("genkey")


def derivePublicKey(private_key: str) -> str:
    validate_key(private_key)
    return _run_wg("pubkey", private_key)


def generateKeypair() -> tuple[str, str]:
    private_key = generatePrivateKey()
    public_key = derivePublicKey(private_key)
    return private_key, public_key
