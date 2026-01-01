"""
Integration tests for path validation in channel operations
"""

import pytest
from backend.channel import Channel
from backend.sqlite_state_store import SqliteStateStore
from backend.sqlite_message_store import SqliteMessageStore
from backend.crypto import CryptoUtils
from cryptography.hazmat.primitives.asymmetric import ed25519
from backend.identifiers import create_typed_identifier
import base64
import json


@pytest.fixture
def admin_keypair():
    """Generate admin Ed25519 keypair and create channel ID"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    channel_id = create_typed_identifier('C', public_bytes)
    user_id = channel_id  # Admin is channel creator

    return {
        'private_key': private_key,
        'public_key': public_key,
        'public_bytes': public_bytes,
        'channel_id': channel_id,
        'user_id': user_id
    }


@pytest.fixture
def channel(temp_db_path, admin_keypair):
    """Create a test channel"""
    state_store = SqliteStateStore(temp_db_path)
    message_store = SqliteMessageStore(temp_db_path)
    crypto = CryptoUtils()

    channel_id = admin_keypair['channel_id']
    channel = Channel(
        channel_id=channel_id,
        state_store=state_store,
        message_store=message_store,
        blob_store=None,
        crypto=crypto
    )

    # Add admin as member
    member_data = {
        "public_key": admin_keypair['user_id'],
        "added_at": 1234567890,
        "added_by": admin_keypair['user_id']
    }
    state_store.set_state(
        channel_id,
        f"members/{admin_keypair['user_id']}",
        base64.b64encode(json.dumps(member_data).encode()).decode(),
        admin_keypair['user_id'],
        1234567890
    )

    return channel


@pytest.fixture
def admin_token(channel, admin_keypair):
    """Get JWT token for admin"""
    # Request challenge
    challenge_response = channel.request_challenge(admin_keypair['user_id'])
    challenge = challenge_response['challenge']

    # Sign challenge
    from cryptography.hazmat.primitives import serialization
    signature = admin_keypair['private_key'].sign(bytes.fromhex(challenge))
    signature_b64 = base64.b64encode(signature).decode()

    # Verify and get token
    token_response = channel.verify_challenge(
        admin_keypair['user_id'],
        challenge,
        signature_b64
    )

    return token_response['token']


class TestStatePathValidation:
    """Test path validation in state operations"""

    def test_valid_state_paths_accepted(self, channel, admin_token):
        """Test that valid paths are accepted"""
        valid_paths = [
            "profiles/alice",
            "topics/general/messages",
            "files/photo.jpg",
            "api/v1.0/users",
            "settings/theme",
        ]

        for path in valid_paths:
            data = base64.b64encode(b"test data").decode()
            # Should not raise
            timestamp = channel.set_state(path, data, admin_token)
            assert timestamp > 0

    def test_wildcard_injection_prevented(self, channel, admin_token):
        """Test that wildcards cannot be injected in user paths"""
        invalid_paths = [
            "profiles/{self}",
            "topics/{any}/messages",
            "auth/users/{other}/roles",
        ]

        for path in invalid_paths:
            data = base64.b64encode(b"test data").decode()
            with pytest.raises(ValueError) as exc_info:
                channel.set_state(path, data, admin_token)
            assert "reserved wildcard" in str(exc_info.value).lower()

    def test_braced_expressions_prevented(self, channel, admin_token):
        """Test that braced expressions cannot be used in paths"""
        invalid_paths = [
            "users/{custom}",
            "data/{id}",
            "files/{foo}/bar",
        ]

        for path in invalid_paths:
            data = base64.b64encode(b"test data").decode()
            with pytest.raises(ValueError) as exc_info:
                channel.set_state(path, data, admin_token)
            assert "braces" in str(exc_info.value).lower() or "invalid" in str(exc_info.value).lower()

    def test_special_characters_prevented(self, channel, admin_token):
        """Test that special characters are rejected"""
        invalid_paths = [
            "my file",           # Space
            "user@email/data",   # @
            "test/path?query",   # ?
            "data#anchor",       # #
        ]

        for path in invalid_paths:
            data = base64.b64encode(b"test data").decode()
            with pytest.raises(ValueError) as exc_info:
                channel.set_state(path, data, admin_token)
            assert "invalid" in str(exc_info.value).lower()

    def test_dots_allowed_in_paths(self, channel, admin_token):
        """Test that dots are allowed for file extensions and versioning"""
        valid_paths = [
            "files/photo.jpg",
            "documents/report.pdf",
            "api/v1.0/users",
            "config/app.yaml",
        ]

        for path in valid_paths:
            data = base64.b64encode(b"test data").decode()
            timestamp = channel.set_state(path, data, admin_token)
            assert timestamp > 0

    def test_get_state_validates_path(self, channel, admin_token):
        """Test that get_state also validates paths"""
        # Valid path works
        valid_path = "test/data"
        data = base64.b64encode(b"test").decode()
        channel.set_state(valid_path, data, admin_token)
        result = channel.get_state(valid_path, admin_token)
        assert result is not None

        # Invalid path rejected
        with pytest.raises(ValueError) as exc_info:
            channel.get_state("test/{self}", admin_token)
        assert "invalid" in str(exc_info.value).lower()

    def test_delete_state_validates_path(self, channel, admin_token):
        """Test that delete_state also validates paths"""
        # Create valid state
        valid_path = "test/data"
        data = base64.b64encode(b"test").decode()
        channel.set_state(valid_path, data, admin_token)

        # Valid deletion works
        channel.delete_state(valid_path, admin_token)

        # Invalid path rejected
        with pytest.raises(ValueError) as exc_info:
            channel.delete_state("test/{any}", admin_token)
        assert "invalid" in str(exc_info.value).lower()


class TestCapabilityPathValidation:
    """Test path validation for capability grants"""

    def test_capability_with_valid_wildcards_accepted(self, channel, admin_keypair, admin_token):
        """Test that capabilities with valid wildcards are accepted"""
        from backend.crypto import CryptoUtils
        crypto = CryptoUtils()

        # Create capability with {self} wildcard
        capability = {
            "op": "write",
            "path": "profiles/{self}/",
            "granted_by": admin_keypair['user_id'],
            "granted_at": 1234567890
        }

        # Sign capability
        signature = crypto.sign_capability(
            admin_keypair['channel_id'],
            admin_keypair['user_id'],
            capability,
            admin_keypair['public_bytes']
        )
        signature_b64 = base64.b64encode(signature).decode()

        # Store capability
        cap_path = f"members/{admin_keypair['user_id']}/rights/cap_001"
        cap_data = base64.b64encode(json.dumps(capability).encode()).decode()

        # Should not raise - valid wildcard in capability path
        timestamp = channel.set_state(
            cap_path,
            cap_data,
            admin_token,
            signature=signature_b64,
            signed_by=admin_keypair['user_id']
        )
        assert timestamp > 0

    def test_capability_with_unknown_wildcard_rejected(self, channel, admin_keypair, admin_token):
        """Test that capabilities with unknown wildcards are rejected"""
        from backend.crypto import CryptoUtils
        crypto = CryptoUtils()

        # Create capability with unknown {custom} wildcard
        capability = {
            "op": "write",
            "path": "users/{custom}/",
            "granted_by": admin_keypair['user_id'],
            "granted_at": 1234567890
        }

        # Sign capability
        signature = crypto.sign_capability(
            admin_keypair['channel_id'],
            admin_keypair['user_id'],
            capability,
            admin_keypair['public_bytes']
        )
        signature_b64 = base64.b64encode(signature).decode()

        # Try to store capability
        cap_path = f"members/{admin_keypair['user_id']}/rights/cap_002"
        cap_data = base64.b64encode(json.dumps(capability).encode()).decode()

        # Should raise - unknown wildcard
        with pytest.raises(ValueError) as exc_info:
            channel.set_state(
                cap_path,
                cap_data,
                admin_token,
                signature=signature_b64,
                signed_by=admin_keypair['user_id']
            )
        assert "invalid" in str(exc_info.value).lower()
