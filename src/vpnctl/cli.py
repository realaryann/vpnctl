"""Command-line interface for managing the Lightsail VPN connection."""

import typer

app = typer.Typer(
    name="vpnctl",
    help="Enroll this Mac as a WireGuard peer and manage its VPN connection.",
    no_args_is_help=True,
)


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
