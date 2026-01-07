"""
Tests for chain conflict detection (compare-and-swap)

These tests verify that the message stores properly detect and reject
concurrent write conflicts using chain validation.
"""

import pytest
from exceptions import ChainConflictError


def test_sqlite_chain_conflict_detection(message_store):
    """Test that concurrent writes are detected via chain conflict in SQLite"""
    space_id = "test_space"
    topic_id = "general"

    # Add first message
    message_store.add_message(
        space_id=space_id,
        topic_id=topic_id,
        message_hash="hash_1",
        prev_hash=None,  # First message
        encrypted_payload="data_1",
        sender="U_alice",
        signature="sig_1",
        server_timestamp=1000
    )

    # Try to add another message claiming to be first (wrong prev_hash)
    with pytest.raises(ChainConflictError) as exc_info:
        message_store.add_message(
            space_id=space_id,
            topic_id=topic_id,
            message_hash="hash_2",
            prev_hash=None,  # Wrong! Should be hash_1
            encrypted_payload="data_2",
            sender="U_bob",
            signature="sig_2",
            server_timestamp=2000
        )

    assert "Chain conflict" in str(exc_info.value)
    assert "expected prev_hash=hash_1" in str(exc_info.value)

    # Verify only first message was added
    messages = message_store.get_messages(space_id, topic_id)
    assert len(messages) == 1
    assert messages[0]["message_hash"] == "hash_1"

    # Now add with correct prev_hash
    message_store.add_message(
        space_id=space_id,
        topic_id=topic_id,
        message_hash="hash_2",
        prev_hash="hash_1",  # Correct!
        encrypted_payload="data_2",
        sender="U_bob",
        signature="sig_2",
        server_timestamp=2000
    )

    # Verify both messages are now present
    messages = message_store.get_messages(space_id, topic_id)
    assert len(messages) == 2
    assert messages[0]["message_hash"] == "hash_1"
    assert messages[1]["message_hash"] == "hash_2"


def test_chain_conflict_with_multiple_messages(message_store):
    """Test chain conflict detection in a longer chain"""
    space_id = "test_space"
    topic_id = "general"

    # Build a chain of 3 messages
    message_store.add_message(
        space_id=space_id,
        topic_id=topic_id,
        message_hash="hash_1",
        prev_hash=None,
        encrypted_payload="data_1",
        sender="U_alice",
        signature="sig_1",
        server_timestamp=1000
    )

    message_store.add_message(
        space_id=space_id,
        topic_id=topic_id,
        message_hash="hash_2",
        prev_hash="hash_1",
        encrypted_payload="data_2",
        sender="U_bob",
        signature="sig_2",
        server_timestamp=2000
    )

    message_store.add_message(
        space_id=space_id,
        topic_id=topic_id,
        message_hash="hash_3",
        prev_hash="hash_2",
        encrypted_payload="data_3",
        sender="U_alice",
        signature="sig_3",
        server_timestamp=3000
    )

    # Try to add a message with wrong prev_hash (pointing to hash_1 instead of hash_3)
    with pytest.raises(ChainConflictError) as exc_info:
        message_store.add_message(
            space_id=space_id,
            topic_id=topic_id,
            message_hash="hash_4",
            prev_hash="hash_1",  # Wrong! Should be hash_3
            encrypted_payload="data_4",
            sender="U_bob",
            signature="sig_4",
            server_timestamp=4000
        )

    assert "Chain conflict" in str(exc_info.value)
    assert "expected prev_hash=hash_3" in str(exc_info.value)

    # Verify only 3 messages in chain
    messages = message_store.get_messages(space_id, topic_id)
    assert len(messages) == 3


def test_chain_head_after_conflict(message_store):
    """Test that chain head is correct after a conflict is rejected"""
    space_id = "test_space"
    topic_id = "general"

    # Add first message
    message_store.add_message(
        space_id=space_id,
        topic_id=topic_id,
        message_hash="hash_1",
        prev_hash=None,
        encrypted_payload="data_1",
        sender="U_alice",
        signature="sig_1",
        server_timestamp=1000
    )

    # Verify chain head
    head = message_store.get_chain_head(space_id, topic_id)
    assert head["message_hash"] == "hash_1"

    # Try to add conflicting message
    with pytest.raises(ChainConflictError):
        message_store.add_message(
            space_id=space_id,
            topic_id=topic_id,
            message_hash="hash_2_bad",
            prev_hash=None,  # Conflict!
            encrypted_payload="data_2",
            sender="U_bob",
            signature="sig_2",
            server_timestamp=2000
        )

    # Chain head should still be hash_1
    head = message_store.get_chain_head(space_id, topic_id)
    assert head["message_hash"] == "hash_1"

    # Add correct message
    message_store.add_message(
        space_id=space_id,
        topic_id=topic_id,
        message_hash="hash_2_good",
        prev_hash="hash_1",
        encrypted_payload="data_2",
        sender="U_bob",
        signature="sig_2",
        server_timestamp=2000
    )

    # Chain head should now be hash_2_good
    head = message_store.get_chain_head(space_id, topic_id)
    assert head["message_hash"] == "hash_2_good"
