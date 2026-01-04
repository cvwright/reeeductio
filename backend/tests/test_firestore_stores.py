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
sign_state_entry = conftest.sign_state_entry
sign_and_store_state = conftest.sign_and_store_state

# Import generic test functions
from .test_state_storage import (
    generic_state_set_and_get,
    generic_state_update,
    generic_state_delete,
    generic_state_list_by_prefix,
    generic_state_nonexistent,
    generic_state_multiple_spaces,
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
    generic_state_set_and_get(firestore_state_store, unique_space_id, admin_keypair)


def test_state_update(firestore_state_store, unique_space_id, admin_keypair, user_keypair):
    """Test updating existing state"""
    generic_state_update(firestore_state_store, unique_space_id, admin_keypair, user_keypair)


def test_state_delete(firestore_state_store, unique_space_id, admin_keypair):
    """Test state deletion"""
    generic_state_delete(firestore_state_store, unique_space_id, admin_keypair)


def test_state_list_by_prefix(firestore_state_store, unique_space_id, admin_keypair):
    """Test listing state by prefix"""
    generic_state_list_by_prefix(firestore_state_store, unique_space_id, admin_keypair)


def test_state_nonexistent(firestore_state_store, unique_space_id):
    """Test getting nonexistent state returns None"""
    generic_state_nonexistent(firestore_state_store, unique_space_id)


def test_state_multiple_spaces(firestore_state_store, unique_space_id, admin_keypair):
    """Test state isolation between spaces"""
    generic_state_multiple_spaces(firestore_state_store, unique_space_id, admin_keypair)


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
