"""Command-line interface for managing the Lightsail VPN connection."""

import sys

import typer

from .enrollment import EnrollmentError, register_peer, validate_connection
from .keys import WireGuardKeyError
from .storage import (
    StorageError,
    initialize_identity,
    load_server_settings,
    save_server_settings,
)

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
def enroll(
    reconfigure: bool = typer.Option(False, "--reconfigure", help="Prompt again for the server and SSH private-key path."),
) -> None:
    """Register this Mac on wg0; first use requires typing an SSH private-key path."""
    try:
        settings = None if reconfigure else load_server_settings()
        if settings is None:
            if not sys.stdin.isatty():
                raise EnrollmentError("First enrollment requires an interactive terminal so you can type the SSH private-key path.")
            typer.echo("Configure SSH access to your Lightsail server (wg0).")
            settings = {
                "version": 1,
                "host": typer.prompt("Lightsail hostname or IP address").strip(),
                "user": typer.prompt("SSH username").strip(),
                "port": typer.prompt("SSH port", default=22, type=int),
                # Intentionally no default, environment variable, key discovery,
                # or command-line option: first setup requires an explicit path.
                "key_path": typer.prompt("Type the path to your Lightsail SSH private key").strip(),
            }
        key_path = validate_connection(settings)
        settings["key_path"] = str(key_path)
        _, public_key, _ = initialize_identity()
        typer.echo(f"Enrolling on {settings['host']} (wg0). SSH may prompt for host verification or your key passphrase.")
        registration = register_peer(settings, public_key)
        settings["registration"] = registration
        try:
            save_server_settings(settings)
        except (OSError, StorageError):
            raise EnrollmentError("The server registered your peer, but saving local settings failed. Fix local storage permissions and rerun enroll with the same identity.") from None
    except (EnrollmentError, WireGuardKeyError, StorageError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=1) from None
    except OSError:
        typer.echo("Error: Could not access local configuration. Check ~/.config/vpnctl permissions.", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(f"Peer registered. Client VPN address: {registration['address']}")
    typer.echo("Saved SSH settings and enrollment details in ~/.config/vpnctl/server.json.")
    typer.echo("The VPN is not connected yet; client profile generation and tunnel control are still pending.")


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
