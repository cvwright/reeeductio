"""Main CLI entry point."""

import logging
import sys

import click
from click.core import ParameterSource

from .commands import auth, blob, key, opaque, role, space, tool, user
from .utils import parse_credentials_file


def _get_version() -> str:
    """Get package version, with fallback for development installs."""
    try:
        from importlib.metadata import version
        return version("reeeductio-client")
    except Exception:
        return "dev"


@click.group()
@click.version_option(version=_get_version())
@click.option(
    "--base-url",
    "-u",
    default="http://localhost:8000",
    help="Base URL of the reeeductio server",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
@click.option(
    "--credentials-file",
    "-f",
    default=None,
    help="Path to credentials file (JSON or plain text)",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Enable verbose/debug output",
)
@click.pass_context
def cli(ctx, base_url: str, output: str, credentials_file: str | None, verbose: bool):
    """Reeeductio admin CLI for space management."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose

    if verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format="[%(name)s] %(message)s",
            stream=sys.stderr,
        )
    else:
        logging.basicConfig(level=logging.WARNING)

    ctx.obj["credentials"] = {}
    if credentials_file:
        creds = parse_credentials_file(credentials_file)
        ctx.obj["credentials"] = creds
        # Use server from credentials file only if --base-url was not explicitly set
        if "base_url" in creds and ctx.get_parameter_source("base_url") == ParameterSource.DEFAULT:
            base_url = creds["base_url"]
        if verbose:
            click.echo(f"Credentials loaded from: {credentials_file}", err=True)
    ctx.obj["base_url"] = base_url
    ctx.obj["output"] = output
    if verbose:
        click.echo(f"Server: {base_url}", err=True)


@cli.command()
@click.pass_context
def help(ctx):
    """Show this help message and exit."""
    click.echo(ctx.parent.get_help())


# Register command groups
cli.add_command(space.space)
cli.add_command(key.key)
cli.add_command(blob.blob)
cli.add_command(auth.auth)
cli.add_command(user.user)
cli.add_command(tool.tool)
cli.add_command(opaque.opaque)
cli.add_command(role.role)


if __name__ == "__main__":
    cli()
