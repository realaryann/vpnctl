# Purpose of this module is to generate WireGuard keys for a new peer

import subprocess

def generatePrivateKey() -> str:
    result = subprocess.run(
                ["wg", "genkey"],
                capture_output=True,
                text=True,
                check=True,
            )
    return result.stdout.strip()

def derivePublicKey(private_key: str) -> str:
    result = subprocess.run(
        ["wg", "pubkey"],
        input=private_key + "\n",
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def generateKeypair() -> tuple[str, str]:
    private_key = generateKeypair()
    public_key = derivePublicKey(private_key)
    return private_key, public_key

