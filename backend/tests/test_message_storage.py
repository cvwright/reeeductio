"""
Generic tests for message storage backends

These test functions can be used with any MessageStore implementation.
"""
import pytest

from message_store import MessageStore


# ============================================================================
# Generic Test Functions
# ============================================================================

def generic_message_add_and_get(message_store: MessageStore, channel_id: str):
    """Generic test for adding and retrieving messages"""
    message_store.add_message(
        channel_id=channel_id,
        topic_id="general",
        message_hash="hash1",
        prev_hash=None,
        encrypted_payload="encrypted_content",
        sender="alice_key",
        signature="dummy_signature",
        server_timestamp=12346000
    )

    messages = message_store.get_messages(channel_id, "general")
    assert len(messages) == 1
    assert messages[0]["message_hash"] == "hash1"
    assert messages[0]["sender"] == "alice_key"
    assert messages[0]["server_timestamp"] == 12346000


def generic_message_chain(message_store: MessageStore, channel_id: str):
    """Generic test for message chain building"""
    # Add first message
    message_store.add_message(
        channel_id=channel_id,
        topic_id="general",
        message_hash="hash1",
        prev_hash=None,
        encrypted_payload="msg1",
        sender="alice_key",
        signature="sig1",
        server_timestamp=12346000
    )

    # Add second message
    message_store.add_message(
        channel_id=channel_id,
        topic_id="general",
        message_hash="hash2",
        prev_hash="hash1",
        encrypted_payload="msg2",
        sender="bob_key",
        signature="sig2",
        server_timestamp=12347000
    )

    messages = message_store.get_messages(channel_id, "general")
    assert len(messages) == 2


def generic_chain_head_tracking(message_store: MessageStore, channel_id: str):
    """Generic test for chain head tracking"""
    message_store.add_message(
        channel_id=channel_id,
        topic_id="general",
        message_hash="hash1",
        prev_hash=None,
        encrypted_payload="encrypted_content",
        sender="alice_key",
        signature="dummy_signature",
        server_timestamp=12346000
    )

    head = message_store.get_chain_head(channel_id, "general")
    assert head["message_hash"] == "hash1"

    # Add another message
    message_store.add_message(
        channel_id=channel_id,
        topic_id="general",
        message_hash="hash2",
        prev_hash="hash1",
        encrypted_payload="encrypted_content",
        sender="bob_key",
        signature="dummy_signature",
        server_timestamp=12347000
    )

    head = message_store.get_chain_head(channel_id, "general")
    assert head["message_hash"] == "hash2"


def generic_time_based_queries(message_store: MessageStore, channel_id: str):
    """Generic test for message queries with time filters"""
    message_store.add_message(
        channel_id=channel_id,
        topic_id="general",
        message_hash="hash1",
        prev_hash=None,
        encrypted_payload="encrypted_content",
        sender="alice_key",
        signature="dummy_signature",
        server_timestamp=12346000
    )

    # Query within time range
    messages = message_store.get_messages(
        channel_id, "general", from_ts=12340000, to_ts=12350000
    )
    assert len(messages) == 1

    # Query outside time range
    messages = message_store.get_messages(
        channel_id, "general", from_ts=12350000, to_ts=12360000
    )
    assert len(messages) == 0


def generic_message_by_hash_lookup(message_store: MessageStore, channel_id: str):
    """Generic test for direct message lookup by hash"""
    message_store.add_message(
        channel_id=channel_id,
        topic_id="general",
        message_hash="hash1",
        prev_hash=None,
        encrypted_payload="encrypted_content",
        sender="alice_key",
        signature="dummy_signature",
        server_timestamp=12346000
    )

    message = message_store.get_message_by_hash(
        channel_id, "general", "hash1"
    )
    assert message is not None
    assert message["message_hash"] == "hash1"
    assert message["sender"] == "alice_key"

    # Test nonexistent message
    message = message_store.get_message_by_hash(
        channel_id, "general", "nonexistent"
    )
    assert message is None


def generic_message_limit(message_store: MessageStore, channel_id: str):
    """Generic test for message retrieval with limit"""
    # Add 10 messages
    for i in range(10):
        message_store.add_message(
            channel_id=channel_id,
            topic_id="general",
            message_hash=f"hash{i}",
            prev_hash=f"hash{i-1}" if i > 0 else None,
            encrypted_payload=f"msg{i}",
            sender="alice_key",
            signature=f"sig{i}",
            server_timestamp=12346000 + i * 1000
        )

    # Get only 5 messages
    messages = message_store.get_messages(channel_id, "general", limit=5)
    assert len(messages) == 5


def generic_multiple_topics(message_store: MessageStore, channel_id: str):
    """Generic test for message isolation between topics"""
    message_store.add_message(
        channel_id=channel_id,
        topic_id="general",
        message_hash="hash1",
        prev_hash=None,
        encrypted_payload="msg1",
        sender="alice_key",
        signature="sig1",
        server_timestamp=12346000
    )

    message_store.add_message(
        channel_id=channel_id,
        topic_id="announcements",
        message_hash="hash2",
        prev_hash=None,
        encrypted_payload="msg2",
        sender="bob_key",
        signature="sig2",
        server_timestamp=12347000
    )

    general_msgs = message_store.get_messages(channel_id, "general")
    assert len(general_msgs) == 1
    assert general_msgs[0]["message_hash"] == "hash1"

    announcement_msgs = message_store.get_messages(channel_id, "announcements")
    assert len(announcement_msgs) == 1
    assert announcement_msgs[0]["message_hash"] == "hash2"


def generic_multiple_channels(message_store: MessageStore, channel_id: str):
    """Generic test for message isolation between channels"""
    channel1_id = channel_id
    channel2_id = f"{channel_id}-other"

    message_store.add_message(
        channel_id=channel1_id,
        topic_id="general",
        message_hash="hash1",
        prev_hash=None,
        encrypted_payload="msg1",
        sender="alice_key",
        signature="sig1",
        server_timestamp=12346000
    )

    message_store.add_message(
        channel_id=channel2_id,
        topic_id="general",
        message_hash="hash2",
        prev_hash=None,
        encrypted_payload="msg2",
        sender="bob_key",
        signature="sig2",
        server_timestamp=12347000
    )

    channel1_msgs = message_store.get_messages(channel1_id, "general")
    assert len(channel1_msgs) == 1
    assert channel1_msgs[0]["message_hash"] == "hash1"

    channel2_msgs = message_store.get_messages(channel2_id, "general")
    assert len(channel2_msgs) == 1
    assert channel2_msgs[0]["message_hash"] == "hash2"


# ============================================================================
# SQLite-Specific Tests
# ============================================================================

def test_message_storage(message_store):
    """Test message storage operations with SQLite"""
    generic_message_add_and_get(message_store, "channel1")


def test_chain_head_tracking(message_store):
    """Test chain head tracking with SQLite"""
    generic_chain_head_tracking(message_store, "channel1")


def test_time_based_queries(message_store):
    """Test message queries with time filters on SQLite"""
    generic_time_based_queries(message_store, "channel1")
