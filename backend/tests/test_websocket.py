"""
WebSocket streaming tests
"""
import pytest
import json
import base64
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import WebSocket, WebSocketDisconnect
from fastapi.testclient import TestClient

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from main import app, authenticate_websocket, channel_manager

class TestWebSocketAuthentication:
    """Test WebSocket authentication"""

    @pytest.mark.asyncio
    async def test_authenticate_websocket_success(self, admin_keypair):
        """Test successful WebSocket authentication"""
        channel_id = admin_keypair['channel_id']
        channel = channel_manager.get_channel(channel_id)
        jwt_data = channel.create_jwt(admin_keypair['user_id'])
        token = jwt_data['token']

        result = await authenticate_websocket(channel_id, token)

        assert result['channel_id'] == channel_id
        assert result['public_key'] == admin_keypair['user_id']

    @pytest.mark.asyncio
    async def test_authenticate_websocket_no_token(self):
        """Test WebSocket authentication fails without token"""
        with pytest.raises(WebSocketDisconnect) as exc_info:
            await authenticate_websocket("test_channel", None)

        assert exc_info.value.code == 1008
        assert "Authentication required" in exc_info.value.reason

    @pytest.mark.asyncio
    async def test_authenticate_websocket_invalid_token(self):
        """Test WebSocket authentication fails with invalid token"""
        with pytest.raises(WebSocketDisconnect) as exc_info:
            await authenticate_websocket("test_channel", "invalid_token")

        assert exc_info.value.code == 1008

    @pytest.mark.asyncio
    async def test_authenticate_websocket_wrong_channel(self, admin_keypair):
        """Test WebSocket authentication fails with wrong channel"""
        channel_id = admin_keypair['channel_id']
        channel = channel_manager.get_channel(channel_id)
        jwt_data = channel.create_jwt(admin_keypair['user_id'])
        token = jwt_data['token']

        with pytest.raises(WebSocketDisconnect) as exc_info:
            await authenticate_websocket("different_channel", token)

        assert exc_info.value.code == 1008
        assert "Token channel mismatch" in exc_info.value.reason


class TestWebSocketEndpoint:
    """Test WebSocket endpoint integration"""

    @pytest.fixture
    def client(self):
        """Create a test client"""
        return TestClient(app)

    def test_websocket_connect_without_token(self, client, admin_keypair):
        """Test WebSocket connection fails without token"""
        channel_id = admin_keypair['channel_id']

        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(f"/channels/{channel_id}/stream"):
                pass

    def test_websocket_connect_with_invalid_token(self, client, admin_keypair):
        """Test WebSocket connection fails with invalid token"""
        channel_id = admin_keypair['channel_id']

        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(
                f"/channels/{channel_id}/stream?token=invalid_token"
            ):
                pass

    def test_websocket_connect_success(self, client, admin_keypair, state_store):
        """Test successful WebSocket connection"""
        channel_id = admin_keypair['channel_id']
        user_id = admin_keypair['user_id']

        # Add user as member
        member_data = {
            "public_key": user_id,
            "added_at": 12345000,
            "added_by": user_id
        }
        member_b64 = base64.b64encode(json.dumps(member_data).encode()).decode()
        state_store.set_state(
            channel_id,
            f"members/{user_id}",
            member_b64,
            updated_by=user_id,
            updated_at=12345000
        )

        # Create JWT token
        channel = channel_manager.get_channel(channel_id)
        jwt_data = channel.create_jwt(user_id)
        token = jwt_data['token']

        # Connect via WebSocket
        with client.websocket_connect(
            f"/channels/{channel_id}/stream?token={token}"
        ) as websocket:
            # Send ping
            websocket.send_text("ping")

            # Receive pong
            data = websocket.receive_text()
            assert data == "pong"

    def test_websocket_receives_broadcast(self, client, admin_keypair, state_store):
        """Test WebSocket receives broadcast messages"""
        channel_id = admin_keypair['channel_id']
        user_id = admin_keypair['user_id']

        # Add user as member
        member_data = {
            "public_key": user_id,
            "added_at": 12345000,
            "added_by": user_id
        }
        member_b64 = base64.b64encode(json.dumps(member_data).encode()).decode()
        state_store.set_state(
            channel_id,
            f"members/{user_id}",
            member_b64,
            updated_by=user_id,
            updated_at=12345000
        )

        # Create JWT token
        channel = channel_manager.get_channel(channel_id)
        jwt_data = channel.create_jwt(user_id)
        token = jwt_data['token']

        # Connect via WebSocket
        with client.websocket_connect(
            f"/channels/{channel_id}/stream?token={token}"
        ) as websocket:
            # Simulate a broadcast from the server
            import asyncio
            message = {
                "message_hash": "test_hash_123",
                "topic_id": "general",
                "prev_hash": None,
                "encrypted_payload": "test_payload",
                "sender": user_id,
                "signature": "test_signature",
                "server_timestamp": 12345000
            }

            # Broadcast message via channel
            asyncio.run(channel.broadcast_message(message))

            # Receive the broadcast
            data = websocket.receive_text()
            received = json.loads(data)

            assert received['message_hash'] == "test_hash_123"
            assert received['topic_id'] == "general"
            assert received['sender'] == user_id


class TestWebSocketMessageBroadcasting:
    """Test message broadcasting integration"""

    @pytest.mark.asyncio
    async def test_post_message_broadcasts_to_websockets(
        self, message_store, state_store, crypto, authz, admin_keypair
    ):
        """Test that posting a message broadcasts to WebSocket clients"""
        channel_id = admin_keypair['channel_id']
        admin_id = admin_keypair['user_id']
        admin_private = admin_keypair['private']

        # Setup admin member and capabilities
        member_data = {
            "public_key": admin_id,
            "added_at": 12345000,
            "added_by": admin_id
        }
        member_b64 = base64.b64encode(json.dumps(member_data).encode()).decode()
        state_store.set_state(
            channel_id,
            f"members/{admin_id}",
            member_b64,
            updated_by=admin_id,
            updated_at=12345000
        )

        # Grant admin write capability
        admin_cap = {
            "op": "write",
            "path": "{any}",
            "granted_by": admin_id,
            "granted_at": 12345000
        }
        cap_msg = crypto.compute_capability_signature_message(
            channel_id, admin_id, "write", "{any}", 12345000
        )
        admin_cap["signature"] = crypto.base64_encode(admin_private.sign(cap_msg))

        admin_cap_b64 = base64.b64encode(json.dumps(admin_cap).encode()).decode()
        state_store.set_state(
            channel_id,
            f"auth/users/{admin_id}/rights/admin",
            admin_cap_b64,
            updated_by=admin_id,
            updated_at=12345000
        )

        # Create mock WebSocket connections
        ws1 = AsyncMock(spec=WebSocket)
        ws1.send_text = AsyncMock()
        ws2 = AsyncMock(spec=WebSocket)
        ws2.send_text = AsyncMock()

        # Get channel and add connections directly to it
        channel = channel_manager.get_channel(channel_id)
        channel.websockets = {ws1, ws2}

        # Post a message (this should trigger broadcast)
        topic_id = "general-chat"
        encrypted_payload = "encrypted_content"
        msg_hash = crypto.compute_message_hash(
            channel_id, topic_id, None, encrypted_payload, admin_id
        )
        signature = crypto.base64_encode(
            admin_private.sign(msg_hash.encode('utf-8'))
        )

        message_store.add_message(
            channel_id=channel_id,
            topic_id=topic_id,
            message_hash=msg_hash,
            prev_hash=None,
            encrypted_payload=encrypted_payload,
            sender=admin_id,
            signature=signature,
            server_timestamp=12345000
        )

        # Simulate the broadcast that happens in post_message endpoint
        message_dict = {
            "message_hash": msg_hash,
            "topic_id": topic_id,
            "prev_hash": None,
            "encrypted_payload": encrypted_payload,
            "sender": admin_id,
            "signature": signature,
            "server_timestamp": 12345000
        }
        await channel.broadcast_message(message_dict)

        # Verify both connections received the message
        ws1.send_text.assert_called_once()
        ws2.send_text.assert_called_once()

        # Verify the message content
        call_arg = ws1.send_text.call_args[0][0]
        received_message = json.loads(call_arg)
        assert received_message['message_hash'] == msg_hash
        assert received_message['topic_id'] == topic_id
        assert received_message['sender'] == admin_id
