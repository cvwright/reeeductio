"""
End-to-end integration tests
"""
import pytest
import json
import base64

from identifiers import decode_identifier


def test_end_to_end_workflow(message_store, state_store, crypto, authz, admin_keypair, user_keypair):
    """Test complete end-to-end workflow"""
    channel_id = admin_keypair['channel_id']
    admin_id = admin_keypair['user_id']
    admin_private = admin_keypair['private']
    user_id = user_keypair['user_id']
    user_private = user_keypair['private']

    # Add admin as member
    admin_member_data = {
        "public_key": admin_id,
        "added_at": 12345000,
        "added_by": admin_id
    }
    admin_member_b64 = base64.b64encode(json.dumps(admin_member_data).encode()).decode()
    state_store.set_state(
        channel_id,
        f"members/{admin_id}",
        admin_member_b64,
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

    # Admin adds user (should work)
    assert authz.check_permission(channel_id, admin_id, "create", f"members/{user_id}")

    user_member_data = {
        "public_key": user_id,
        "added_at": 12346000,
        "added_by": admin_id
    }
    user_member_b64 = base64.b64encode(json.dumps(user_member_data).encode()).decode()
    state_store.set_state(
        channel_id,
        f"members/{user_id}",
        user_member_b64,
        updated_by=admin_id,
        updated_at=12346000
    )

    # Grant user post capability
    post_cap = {
        "op": "create",
        "path": "topics/{any}/messages/",
        "granted_by": admin_id,
        "granted_at": 12346000
    }
    cap_msg = crypto.compute_capability_signature_message(
        channel_id, user_id, "create", "topics/{any}/messages/", 12346000
    )
    post_cap["signature"] = crypto.base64_encode(admin_private.sign(cap_msg))

    post_cap_b64 = base64.b64encode(json.dumps(post_cap).encode()).decode()
    state_store.set_state(
        channel_id,
        f"auth/users/{user_id}/rights/post",
        post_cap_b64,
        updated_by=admin_id,
        updated_at=12346000
    )

    # User posts message
    assert authz.check_permission(channel_id, user_id, "create", "topics/general-chat/messages/")

    # Compute message hash with sender
    msg_hash = crypto.compute_message_hash(
        channel_id, "general-chat", None, "encrypted_content", user_id
    )

    # Sign the message hash (sign the full typed identifier bytes)
    msg_tid = decode_identifier(msg_hash)
    msg_signature = user_private.sign(msg_tid.to_bytes())

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
