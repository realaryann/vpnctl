"""Command-line interface for managing the Lightsail VPN connection."""

import sys

import typer

from .enrollment import EnrollmentError, registerPeer, validateConnection
from .keys import WireGuardKeyError
from .profile import ProfileError, buildProfile
from .tunnel import Tunnel, TunnelError
from .storage import (
    StorageError,
    initializeIdentity,
    loadIdentity,
    loadServerSettings,
    saveProfile,
    saveServerSettings,
)

app = typer.Typer(
    name="vpnctl",
    help="Enroll this Mac as a WireGuard peer and manage its VPN connection.",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)

keysApp = typer.Typer(help="Manage this Mac's WireGuard identity.", no_args_is_help=True)
app.add_typer(keysApp, name="keys")

profileApp = typer.Typer(help="Generate a WireGuard client profile.", no_args_is_help=True)
app.add_typer(profileApp, name="profile")


@profileApp.command("create")
def profileCreate(
    dns: str | None = typer.Option(None, help="Comma-separated IPv4 DNS servers; prompts if omitted."),
    endpoint: str | None = typer.Option(None, help="Public server hostname/IP override, without a port."),
    replace: bool = typer.Option(False, "--replace", help="Replace an existing profile. Disconnect it first."),
) -> None:
    """Save an importable profile using the existing enrollment and identity."""
    try:
        settings = loadServerSettings()
        if settings is None:
            raise ProfileError("No enrollment found. Run vpnctl enroll first.")
        identity = loadIdentity()
        if dns is None:
            if not sys.stdin.isatty():
                raise ProfileError("Pass --dns with IPv4 DNS addresses, or run in an interactive terminal.")
            dns = typer.prompt("IPv4 DNS servers from your working configuration (comma-separated)")
        contents = buildProfile(identity, settings, dns, endpoint)
        path = saveProfile(contents, replace=replace)
    except (ProfileError, StorageError, WireGuardKeyError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=1) from None
    except OSError:
        typer.echo("Error: Could not read or save local configuration. Check ~/vpnctl permissions.", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(f"Profile saved: {path}")
    typer.echo("Disconnect your old tunnel, then import this file into the WireGuard app.")
    typer.echo("IPv4 uses the VPN; IPv6 is routed into the tunnel without server IPv6 access. Verify this on your Mac.")
    typer.echo("No tunnel has been started.")


@keysApp.command("init")
def keysInit() -> None:
    """Create a local keypair, or reuse the existing identity without replacing it."""
    try:
        path, publicKey, created = initializeIdentity()
    except (WireGuardKeyError, StorageError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=1) from None
    except OSError:
        typer.echo("Error: Could not access identity storage. Check ~/vpnctl permissions.", err=True)
        raise typer.Exit(code=1) from None
    typer.echo("Created client identity." if created else "Using existing client identity.")
    typer.echo(f"Identity file: {path}")
    typer.echo(f"Public key: {publicKey}")


@app.command()
def enroll(
    reconfigure: bool = typer.Option(False, "--reconfigure", help="Prompt again for the server and SSH private-key path."),
) -> None:
    """Register this Mac on wg0; first use requires typing an SSH private-key path."""
    try:
        settings = None if reconfigure else loadServerSettings()
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
        keyPath = validateConnection(settings)
        settings["key_path"] = str(keyPath)
        _, publicKey, _ = initializeIdentity()
        typer.echo(f"Enrolling on {settings['host']} (wg0). SSH may prompt for host verification or your key passphrase.")
        registration = registerPeer(settings, publicKey)
        settings["registration"] = registration
        try:
            saveServerSettings(settings)
        except (OSError, StorageError):
            raise EnrollmentError("The server registered your peer, but saving local settings failed. Fix local storage permissions and rerun enroll with the same identity.") from None
    except (EnrollmentError, WireGuardKeyError, StorageError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=1) from None
    except OSError:
        typer.echo("Error: Could not access local configuration. Check ~/vpnctl permissions.", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(f"Peer registered. Client VPN address: {registration['address']}")
    typer.echo("Saved SSH settings and enrollment details in ~/vpnctl/server.json.")
    typer.echo("Next: run vpnctl profile create to generate the client configuration.")


@app.command()
def connect() -> None:
    """Start the WireGuard VPN connection."""
    typer.echo("Checking local WireGuard state; macOS may request your administrator password.")
    try:
        tunnel = Tunnel()
        tunnel.authenticate()
        typer.echo(tunnel.connect())
    except (TunnelError, StorageError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=1) from None
    except (OSError, UnicodeError):
        typer.echo("Error: Could not access the profile or WireGuard tools. Check ~/vpnctl and your installation.", err=True)
        raise typer.Exit(code=1) from None



@app.command()
def disconnect() -> None:
    """Stop the WireGuard VPN connection."""
    typer.echo("Checking local WireGuard state; macOS may request your administrator password.")
    try:
        tunnel = Tunnel()
        tunnel.authenticate()
        typer.echo(tunnel.disconnect())
    except (TunnelError, StorageError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=1) from None
    except (OSError, UnicodeError):
        typer.echo("Error: Could not access the profile or WireGuard tools. Check ~/vpnctl and your installation.", err=True)
        raise typer.Exit(code=1) from None


@app.command()
def status() -> None:
    """Show the current VPN connection status."""
    typer.echo("Checking local WireGuard state; macOS may request your administrator password.")
    try:
        tunnel = Tunnel()
        tunnel.authenticate()
        typer.echo(tunnel.status())
    except (TunnelError, StorageError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=1) from None
    except (OSError, UnicodeError):
        typer.echo("Error: Could not access local WireGuard state. Check ~/vpnctl and your installation.", err=True)
        raise typer.Exit(code=1) from None


if __name__ == "__main__":
    app()
