"""
Generic tests for state storage backends

These test functions can be used with any StateStore implementation.
"""
import pytest
import json
import base64

from state_store import StateStore


# ============================================================================
# Generic Test Functions
# ============================================================================

def generic_state_set_and_get(state_store: StateStore, channel_id: str):
    """Generic test for basic state set and get operations"""
    data = {"public_key": "alice_key", "added_at": 12345}
    data_json = json.dumps(data)
    data_b64 = base64.b64encode(data_json.encode()).decode()

    state_store.set_state(
        channel_id,
        "members/alice",
        data_b64,
        updated_by="admin",
        updated_at=12345
    )

    state = state_store.get_state(channel_id, "members/alice")
    assert state is not None
    decoded_data = json.loads(base64.b64decode(state["data"]))
    assert decoded_data["public_key"] == "alice_key"
    assert state["updated_by"] == "admin"
    assert state["updated_at"] == 12345


def generic_state_update(state_store: StateStore, channel_id: str):
    """Generic test for updating existing state"""
    data1 = {"value": 1}
    data1_b64 = base64.b64encode(json.dumps(data1).encode()).decode()

    state_store.set_state(
        channel_id,
        "config/setting",
        data1_b64,
        updated_by="alice",
        updated_at=100
    )

    data2 = {"value": 2}
    data2_b64 = base64.b64encode(json.dumps(data2).encode()).decode()

    state_store.set_state(
        channel_id,
        "config/setting",
        data2_b64,
        updated_by="bob",
        updated_at=200
    )

    state = state_store.get_state(channel_id, "config/setting")
    assert state is not None
    decoded_data = json.loads(base64.b64decode(state["data"]))
    assert decoded_data["value"] == 2
    assert state["updated_by"] == "bob"
    assert state["updated_at"] == 200


def generic_state_delete(state_store: StateStore, channel_id: str):
    """Generic test for state deletion"""
    data = {"test": "data"}
    data_b64 = base64.b64encode(json.dumps(data).encode()).decode()

    state_store.set_state(
        channel_id,
        "temp/data",
        data_b64,
        updated_by="alice",
        updated_at=100
    )

    # Verify it exists
    assert state_store.get_state(channel_id, "temp/data") is not None

    # Delete it
    state_store.delete_state(channel_id, "temp/data")

    # Verify it's gone
    assert state_store.get_state(channel_id, "temp/data") is None


def generic_state_list_by_prefix(state_store: StateStore, channel_id: str):
    """Generic test for listing state by prefix"""
    # Create multiple state entries
    for i in range(5):
        data = {"index": i}
        data_b64 = base64.b64encode(json.dumps(data).encode()).decode()
        state_store.set_state(
            channel_id,
            f"members/user{i}",
            data_b64,
            updated_by="admin",
            updated_at=100 + i
        )

    # Add some entries with a different prefix
    for i in range(3):
        data = {"index": i}
        data_b64 = base64.b64encode(json.dumps(data).encode()).decode()
        state_store.set_state(
            channel_id,
            f"config/setting{i}",
            data_b64,
            updated_by="admin",
            updated_at=200 + i
        )

    # List members
    members = state_store.list_state(channel_id, "members/")
    assert len(members) == 5
    for member in members:
        assert member["path"].startswith("members/")

    # List config
    configs = state_store.list_state(channel_id, "config/")
    assert len(configs) == 3
    for config in configs:
        assert config["path"].startswith("config/")


def generic_state_nonexistent(state_store: StateStore, channel_id: str):
    """Generic test for getting nonexistent state"""
    state = state_store.get_state(channel_id, "does/not/exist")
    assert state is None


def generic_state_multiple_channels(state_store: StateStore, channel_id: str):
    """Generic test for state isolation between channels"""
    data = {"test": "data"}
    data_b64 = base64.b64encode(json.dumps(data).encode()).decode()

    state_store.set_state(
        channel_id,
        "config/setting",
        data_b64,
        updated_by="alice",
        updated_at=100
    )

    # Should not be visible in a different channel
    other_channel_id = f"{channel_id}-other"
    assert state_store.get_state(other_channel_id, "config/setting") is None


# ============================================================================
# SQLite-Specific Tests
# ============================================================================

def test_state_storage(state_store):
    """Test state storage operations with SQLite"""
    generic_state_set_and_get(state_store, "channel1")
