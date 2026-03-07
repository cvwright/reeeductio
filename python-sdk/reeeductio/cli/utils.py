"""Shared CLI utilities."""

import base64
import functools
import json
import sys

import click
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..crypto import Ed25519KeyPair
from ..exceptions import (
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    ReeeductioError,
    ValidationError,
)


def parse_private_key(private_key_str: str) -> Ed25519KeyPair:
    """Parse a private key into an Ed25519KeyPair.

    Accepts either hex or base64 encoding, detected by string length:
    - 64 characters: hex encoding (32 bytes)
    - 43-44 characters: base64 encoding (32 bytes, with or without padding)

    Args:
        private_key_str: Private key as hex (64 chars) or base64 (43-44 chars)

    Returns:
        Ed25519KeyPair with derived public key

    Raises:
        click.BadParameter: If the key format is invalid
    """
    key_len = len(private_key_str)

    try:
        if key_len == 64:
            # Hex encoding: 64 hex chars = 32 bytes
            private_bytes = bytes.fromhex(private_key_str)
        elif key_len in (43, 44):
            # Base64 encoding: 43-44 chars = 32 bytes
            # Handle both standard and URL-safe base64, with or without padding
            # Normalize: replace URL-safe chars and add padding if needed
            b64_str = private_key_str.replace("-", "+").replace("_", "/")
            if len(b64_str) == 43:
                b64_str += "="
            private_bytes = base64.b64decode(b64_str)
            if len(private_bytes) != 32:
                raise click.BadParameter(
                    f"Base64-decoded key must be 32 bytes, got {len(private_bytes)}"
                )
        else:
            raise click.BadParameter(
                f"Private key must be 64 hex chars or 43-44 base64 chars, got {key_len} chars"
            )

        # Derive public key from private key
        private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        return Ed25519KeyPair(private_key=private_bytes, public_key=public_bytes)

    except ValueError as e:
        raise click.BadParameter(f"Invalid key format: {e}")
    except Exception as e:
        raise click.BadParameter(f"Failed to parse private key: {e}")


def parse_credentials_file(path: str) -> dict:
    """Parse a credentials file (JSON or plain text) and return a normalized dict.

    Plain text format (one item per line):
        Label:  value

    JSON format:
        {"private_key_hex": "...", "symmetric_root_hex": "...", ...}

    Returns dict with keys: private_key, symmetric_root, base_url, space_id, user_id
    """
    try:
        with open(path) as f:
            content = f.read().strip()
    except OSError as e:
        raise click.UsageError(f"Cannot read credentials file '{path}': {e}")

    if content.startswith("{"):
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise click.UsageError(f"Invalid JSON in credentials file '{path}': {e}")
        key_map = {
            "private_key_hex": "private_key",
            "symmetric_root_hex": "symmetric_root",
            "base_url": "base_url",
            "space_id": "space_id",
            "user_id": "user_id",
        }
        return {dst: data[src] for src, dst in key_map.items() if src in data}

    # Plain text: "Label With Spaces:   value"
    label_map = {
        "private key": "private_key",
        "symmetric root": "symmetric_root",
        "server": "base_url",
        "space id": "space_id",
        "user id": "user_id",
    }
    result = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        label, _, value = line.partition(":")
        key = label.strip().lower()
        if key in label_map:
            result[label_map[key]] = value.strip()
    return result


def echo_verbose(ctx, msg: str) -> None:
    """Print msg to stderr if --verbose is enabled."""
    if ctx.obj.get("verbose"):
        click.echo(msg, err=True)


def get_credential(ctx, option_value: str | None, cred_key: str, param_hint: str) -> str:
    """Return option_value if provided, otherwise look it up in ctx.obj['credentials'].

    Raises click.UsageError if not found in either place.
    """
    if option_value is not None:
        return option_value
    value = ctx.obj.get("credentials", {}).get(cred_key)
    if value is not None:
        return value
    raise click.UsageError(
        f"Missing option {param_hint}. Provide it directly or via --credentials-file / -f."
    )


def handle_errors(func):
    """Decorator to handle SDK exceptions and display user-friendly errors."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except AuthenticationError as e:
            click.echo(f"Authentication failed: {e}", err=True)
            sys.exit(1)
        except AuthorizationError as e:
            click.echo(f"Permission denied: {e}", err=True)
            sys.exit(1)
        except NotFoundError as e:
            click.echo(f"Not found: {e}", err=True)
            sys.exit(1)
        except ValidationError as e:
            click.echo(f"Validation error: {e}", err=True)
            sys.exit(1)
        except ReeeductioError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        except click.ClickException:
            raise  # Let Click handle its own exceptions
        except Exception as e:
            click.echo(f"Unexpected error: {e}", err=True)
            sys.exit(1)

    return wrapper
