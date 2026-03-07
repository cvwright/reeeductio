"""Authentication test commands."""

import click

from ...client import AdminClient
from ..utils import echo_verbose, get_credential, handle_errors, parse_private_key


@click.group()
def auth():
    """Authentication operations."""
    pass


@auth.command("test")
@click.option(
    "--private-key",
    "-k",
    default=None,
    help="Admin private key in hex format",
)
@click.pass_context
@handle_errors
def test_auth(ctx, private_key: str):
    """Test admin authentication against the server."""
    base_url = ctx.obj["base_url"]
    private_key = get_credential(ctx, private_key, "private_key", "'--private-key' / '-k'")
    keypair = parse_private_key(private_key)
    echo_verbose(ctx, f"Space ID: {keypair.to_space_id()}")
    echo_verbose(ctx, f"User ID:  {keypair.to_user_id()}")

    click.echo(f"Testing authentication to {base_url}...")

    with AdminClient(keypair, base_url=base_url, auto_authenticate=False) as admin:
        admin.authenticate()
        space_id = admin.get_space_id()

        click.echo("Authentication successful!")
        click.echo(f"Admin Space ID: {space_id}")
