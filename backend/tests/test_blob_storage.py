"""
Tests for blob storage backends (filesystem and database)
"""
import pytest

from identifiers import encode_user_id
from blob_store import BlobStore


# ============================================================================
# Generic Test Functions
# ============================================================================

def generic_blob_upload(blob_store: BlobStore, crypto):
    """Generic test for blob upload with reference counting"""
    blob_data = b"This is encrypted blob content"
    blob_id = crypto.compute_blob_id(blob_data)
    channel_id = "test_channel"
    user_id = "test_user"

    blob_store.add_blob(blob_id, blob_data, channel_id, user_id)
    retrieved = blob_store.get_blob(blob_id)

    assert retrieved == blob_data


def generic_blob_duplicate_reference_rejection(blob_store: BlobStore, crypto):
    """Generic test that store rejects duplicate references"""
    blob_data = b"This is encrypted blob content"
    blob_id = crypto.compute_blob_id(blob_data)
    channel_id = "test_channel"
    user_id = "test_user"

    blob_store.add_blob(blob_id, blob_data, channel_id, user_id)

    # Same channel/user reference should be rejected
    with pytest.raises(FileExistsError):
        blob_store.add_blob(blob_id, blob_data, channel_id, user_id)


def generic_blob_invalid_id_rejection(blob_store: BlobStore):
    """Generic test that store rejects invalid blob IDs"""
    # USER type instead of BLOB
    invalid_id = encode_user_id(b"x" * 32)
    blob_data = b"some data"
    channel_id = "test_channel"
    user_id = "test_user"

    with pytest.raises(ValueError, match="BLOB type"):
        blob_store.add_blob(invalid_id, blob_data, channel_id, user_id)


def generic_blob_retrieval_nonexistent(blob_store: BlobStore, crypto):
    """Generic test for retrieval of non-existent blob returns None"""
    non_existent_id = crypto.compute_blob_id(b"different content")
    assert blob_store.get_blob(non_existent_id) is None


def generic_blob_reference_removal(blob_store: BlobStore, crypto):
    """Generic test for blob reference removal"""
    blob_data = b"This is encrypted blob content"
    blob_id = crypto.compute_blob_id(blob_data)
    channel_id = "test_channel"
    user_id = "test_user"

    blob_store.add_blob(blob_id, blob_data, channel_id, user_id)
    # Should return True when blob content is deleted (last reference)
    assert blob_store.remove_blob_reference(blob_id, channel_id, user_id) == True
    assert blob_store.get_blob(blob_id) is None


def generic_blob_deletion_nonexistent(blob_store: BlobStore, crypto):
    """Generic test for removing non-existent blob reference returns False"""
    blob_id = crypto.compute_blob_id(b"nonexistent")
    assert blob_store.remove_blob_reference(blob_id, "channel", "user") == False


def generic_blob_deduplication(blob_store: BlobStore, crypto):
    """Generic test that multiple channels can reference same blob content"""
    blob_data = b"shared content"
    blob_id = crypto.compute_blob_id(blob_data)

    # First channel uploads
    blob_store.add_blob(blob_id, blob_data, "channel1", "user1")

    # Second channel uploads same content (deduplication)
    blob_store.add_blob(blob_id, blob_data, "channel2", "user2")

    # Blob content should still exist
    assert blob_store.get_blob(blob_id) == blob_data

    # Remove first reference - content should remain
    assert blob_store.remove_blob_reference(blob_id, "channel1", "user1") == False
    assert blob_store.get_blob(blob_id) == blob_data

    # Remove second reference - content should be deleted
    assert blob_store.remove_blob_reference(blob_id, "channel2", "user2") == True
    assert blob_store.get_blob(blob_id) is None


# ============================================================================
# Filesystem BlobStore Tests
# ============================================================================

def test_fs_blob_upload(fs_blob_store, crypto):
    """Test filesystem blob upload with reference counting"""
    generic_blob_upload(fs_blob_store, crypto)


def test_fs_blob_duplicate_reference_rejection(fs_blob_store, crypto):
    """Test that filesystem store rejects duplicate references"""
    generic_blob_duplicate_reference_rejection(fs_blob_store, crypto)


def test_fs_blob_invalid_id_rejection(fs_blob_store):
    """Test that filesystem store rejects invalid blob IDs"""
    generic_blob_invalid_id_rejection(fs_blob_store)


def test_fs_blob_retrieval_nonexistent(fs_blob_store, crypto):
    """Test retrieval of non-existent blob returns None"""
    generic_blob_retrieval_nonexistent(fs_blob_store, crypto)


def test_fs_blob_reference_removal(fs_blob_store, crypto):
    """Test filesystem blob reference removal"""
    generic_blob_reference_removal(fs_blob_store, crypto)


def test_fs_blob_deletion_nonexistent(fs_blob_store, crypto):
    """Test removing non-existent blob reference returns False"""
    generic_blob_deletion_nonexistent(fs_blob_store, crypto)


def test_fs_blob_deduplication(fs_blob_store, crypto):
    """Test that multiple channels can reference same blob content"""
    generic_blob_deduplication(fs_blob_store, crypto)


# ============================================================================
# Database BlobStore Tests
# ============================================================================

def test_db_blob_upload(db_blob_store, crypto):
    """Test database blob upload with reference counting"""
    generic_blob_upload(db_blob_store, crypto)


def test_db_blob_duplicate_reference_rejection(db_blob_store, crypto):
    """Test that database store rejects duplicate references"""
    generic_blob_duplicate_reference_rejection(db_blob_store, crypto)


def test_db_blob_invalid_id_rejection(db_blob_store):
    """Test that database store rejects invalid blob IDs"""
    generic_blob_invalid_id_rejection(db_blob_store)


def test_db_blob_retrieval_nonexistent(db_blob_store, crypto):
    """Test retrieval of non-existent blob returns None"""
    generic_blob_retrieval_nonexistent(db_blob_store, crypto)


def test_db_blob_reference_removal(db_blob_store, crypto):
    """Test database blob reference removal"""
    generic_blob_reference_removal(db_blob_store, crypto)


def test_db_blob_deletion_nonexistent(db_blob_store, crypto):
    """Test removing non-existent blob reference from database returns False"""
    generic_blob_deletion_nonexistent(db_blob_store, crypto)


def test_db_blob_deduplication(db_blob_store, crypto):
    """Test that multiple channels can reference same blob content"""
    generic_blob_deduplication(db_blob_store, crypto)
