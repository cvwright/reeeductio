"""
End-to-end integration tests
"""
import pytest
import json
import base64
import sys
from pathlib import Path

# Add tests directory to path to import conftest
sys.path.insert(0, str(Path(__file__).parent))

from identifiers import decode_identifier
import conftest
sign_state_entry = conftest.sign_state_entry
sign_and_store_state = conftest.sign_and_store_state

def test_end_to_end_workflow(message_store, state_store, crypto, authz, admin_keypair, user_keypair):
    """Test complete end-to-end workflow"""
    channel_id = admin_keypair['channel_id']
    admin_id = admin_keypair['user_id']
    admin_private = admin_keypair['private']
    user_id = user_keypair['user_id']
    user_private = user_keypair['private']

    # Admin adds user (should work)
    assert authz.check_permission(channel_id, admin_id, "create", f"members/{user_id}")

    user_member_data = {
        "user_id": user_id
    }
    sign_and_store_state(
        state_store=state_store,
        channel_id=channel_id,
        path=f"auth/users/{user_id}",
        contents=user_member_data,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12345000
    )

    # Grant user post capability
    post_cap = {
        "op": "create",
        "path": "topics/{any}/messages/"
    }
    sign_and_store_state(
        state_store=state_store,
        channel_id=channel_id,
        path=f"auth/users/{user_id}/rights/post",
        contents=post_cap,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12346000
    )

    # User posts message
    assert authz.check_permission(channel_id, user_id, "create", "topics/general-chat/messages/")

    # Compute message hash with sender
    msg_hash = crypto.compute_message_hash(
        channel_id, "general-chat", None, "encrypted_content", user_id
    )

    # Sign the message hash (sign the full typed identifier bytes)
    msg_id = decode_identifier(msg_hash)
    msg_signature = user_private.sign(msg_id.to_bytes())

    message_store.add_message(
        channel_id=channel_id,
        topic_id="general-chat",
        message_hash=msg_hash,
        prev_hash=None,
        encrypted_payload="encrypted_content",
        sender=user_id,
        signature=crypto.base64_encode(msg_signature),
        server_timestamp=12347000
    )

    # Verify user can't write to admin areas
    assert not authz.check_permission(channel_id, user_id, "write", "auth/users/someone_else/rights/")

    # Retrieve and verify message
    messages = message_store.get_messages(channel_id, "general-chat")
    assert len(messages) == 1
    assert messages[0]["message_hash"] == msg_hash
    assert messages[0]["sender"] == user_id
