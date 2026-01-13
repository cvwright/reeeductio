"""
Tests for Firestore storage implementations

These tests run against the Firestore emulator and use the generic test
functions from test_state_storage.py and test_message_storage.py.

Run tests:
    # Automatic mode (uses testcontainers if available)
    pytest backend/tests/test_firestore_stores.py

    # Use docker-compose emulator
    docker-compose up -d firestore-emulator
    pytest backend/tests/test_firestore_stores.py --firestore-emulator=external

    # Force testcontainers
    pytest backend/tests/test_firestore_stores.py --firestore-emulator=testcontainers
"""
import sys
import pytest
from pathlib import Path

# Add tests directory to path to import conftest
sys.path.insert(0, str(Path(__file__).parent))

import conftest
sign_data_entry = conftest.sign_data_entry
sign_and_store_data = conftest.sign_and_store_data

# Import generic test functions
from .test_data_storage import (
    generic_data_set_and_get,
    generic_data_update,
    generic_data_delete,
    generic_data_list_by_prefix,
    generic_data_nonexistent,
    generic_data_multiple_spaces,
)
from .test_message_storage import (
    generic_message_add_and_get,
    generic_message_chain,
    generic_chain_head_tracking,
    generic_time_based_queries,
    generic_message_by_hash_lookup,
    generic_message_limit,
    generic_multiple_topics,
    generic_multiple_spaces,
)


# ============================================================================
# State Storage Tests
# ============================================================================

def test_state_set_and_get(firestore_state_store, unique_space_id, admin_keypair):
    """Test basic state set and get operations"""
    generic_data_set_and_get(firestore_state_store, unique_space_id, admin_keypair)


def test_state_update(firestore_state_store, unique_space_id, admin_keypair, user_keypair):
    """Test updating existing state"""
    generic_data_update(firestore_state_store, unique_space_id, admin_keypair, user_keypair)


def test_state_delete(firestore_state_store, unique_space_id, admin_keypair):
    """Test state deletion"""
    generic_data_delete(firestore_state_store, unique_space_id, admin_keypair)


def test_state_list_by_prefix(firestore_state_store, unique_space_id, admin_keypair):
    """Test listing state by prefix"""
    generic_data_list_by_prefix(firestore_state_store, unique_space_id, admin_keypair)


def test_state_nonexistent(firestore_state_store, unique_space_id):
    """Test getting nonexistent state returns None"""
    generic_data_nonexistent(firestore_state_store, unique_space_id)


def test_state_multiple_spaces(firestore_state_store, unique_space_id, admin_keypair):
    """Test state isolation between spaces"""
    generic_data_multiple_spaces(firestore_state_store, unique_space_id, admin_keypair)


# ============================================================================
# Message Storage Tests
# ============================================================================

def test_message_add_and_get(firestore_message_store, unique_space_id):
    """Test adding and retrieving messages"""
    generic_message_add_and_get(firestore_message_store, unique_space_id)


def test_message_chain(firestore_message_store, unique_space_id):
    """Test message chain building"""
    generic_message_chain(firestore_message_store, unique_space_id)


def test_chain_head_tracking(firestore_message_store, unique_space_id):
    """Test chain head tracking"""
    generic_chain_head_tracking(firestore_message_store, unique_space_id)


def test_time_based_queries(firestore_message_store, unique_space_id):
    """Test message queries with time filters"""
    generic_time_based_queries(firestore_message_store, unique_space_id)


def test_message_by_hash_lookup(firestore_message_store, unique_space_id):
    """Test direct message lookup by hash"""
    generic_message_by_hash_lookup(firestore_message_store, unique_space_id)


def test_message_limit(firestore_message_store, unique_space_id):
    """Test message retrieval with limit"""
    generic_message_limit(firestore_message_store, unique_space_id)


def test_multiple_topics(firestore_message_store, unique_space_id):
    """Test message isolation between topics"""
    generic_multiple_topics(firestore_message_store, unique_space_id)


def test_multiple_spaces(firestore_message_store, unique_space_id):
    """Test message isolation between spaces"""
    generic_multiple_spaces(firestore_message_store, unique_space_id)


def test_chain_conflict_detection(firestore_message_store, unique_space_id):
    """Test that concurrent writes are detected via chain conflict in Firestore"""
    from exceptions import ChainConflictError

    space_id = unique_space_id

    # Add first message
    firestore_message_store.add_message(
        space_id=space_id,
        topic_id="state-events",
        message_hash="hash_1",
        msg_type="/auth/users/U_alice",
        prev_hash=None,  # First message
        data="data_1",
        sender="U_admin",
        signature="sig_1",
        server_timestamp=1000
    )

    # Try to add another message claiming to be first (wrong prev_hash)
    with pytest.raises(ChainConflictError) as exc_info:
        firestore_message_store.add_message(
            space_id=space_id,
            topic_id="state-events",
            message_hash="hash_2",
            msg_type="/auth/users/U_bob",
            prev_hash=None,  # Wrong! Should be hash_1
            data="data_2",
            sender="U_admin",
            signature="sig_2",
            server_timestamp=2000
        )

    assert "Chain conflict" in str(exc_info.value)
    assert "expected prev_hash=hash_1" in str(exc_info.value)

    # Verify only first message was added
    events = firestore_message_store.get_messages(space_id, "state-events")
    assert len(events) == 1
    assert events[0]["message_hash"] == "hash_1"

    # Now add with correct prev_hash
    firestore_message_store.add_message(
        space_id=space_id,
        topic_id="state-events",
        message_hash="hash_2",
        msg_type="/auth/users/U_bob",
        prev_hash="hash_1",  # Correct!
        data="data_2",
        sender="U_admin",
        signature="sig_2",
        server_timestamp=2000
    )

    # Verify both messages are now present
    events = firestore_message_store.get_messages(space_id, "state-events")
    assert len(events) == 2
    assert events[0]["message_hash"] == "hash_1"
    assert events[1]["message_hash"] == "hash_2"
