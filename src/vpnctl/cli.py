"""Command-line interface for managing the Lightsail VPN connection."""

import typer

from .keys import WireGuardKeyError
from .storage import StorageError, initialize_identity

app = typer.Typer(
    name="vpnctl",
    help="Enroll this Mac as a WireGuard peer and manage its VPN connection.",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)

keys_app = typer.Typer(help="Manage this Mac's WireGuard identity.", no_args_is_help=True)
app.add_typer(keys_app, name="keys")


@keys_app.command("init")
def keys_init() -> None:
    """Create a local keypair, or reuse the existing identity without replacing it."""
    try:
        path, public_key, created = initialize_identity()
    except (WireGuardKeyError, StorageError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=1) from None
    except OSError:
        typer.echo("Error: Could not access identity storage. Check ~/.config/vpnctl permissions.", err=True)
        raise typer.Exit(code=1) from None
    typer.echo("Created client identity." if created else "Using existing client identity.")
    typer.echo(f"Identity file: {path}")
    typer.echo(f"Public key: {public_key}")


def _not_implemented(command: str) -> None:
    typer.echo(f"{command} is not implemented yet.", err=True)
    raise typer.Exit(code=1)


@app.command()
def enroll() -> None:
    """Register this Mac as a peer on the Lightsail server."""
    _not_implemented("enroll")


@app.command()
def connect() -> None:
    """Start the WireGuard VPN connection."""
    _not_implemented("connect")


@app.command()
def disconnect() -> None:
    """Stop the WireGuard VPN connection."""
    _not_implemented("disconnect")


@app.command()
def status() -> None:
    """Show the current VPN connection status."""
    _not_implemented("status")


if __name__ == "__main__":
    app()
