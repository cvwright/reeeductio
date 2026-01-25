"""
Tests for S3 blob storage backend

Runs against either:
1. MinIO testcontainer (default, requires Docker)
2. Real S3-compatible service (Backblaze B2, AWS S3, etc.) via environment variables

Usage:
    # Auto mode - tries testcontainers, falls back to external
    pytest backend/tests/test_s3_blob_storage.py

    # Force testcontainers (MinIO)
    pytest backend/tests/test_s3_blob_storage.py --s3-emulator=testcontainers

    # Use real S3 service (Backblaze B2, etc.)
    export S3_BUCKET_NAME=my-test-bucket
    export S3_ENDPOINT_URL=https://s3.us-west-004.backblazeb2.com
    export S3_ACCESS_KEY_ID=your-key-id
    export S3_SECRET_ACCESS_KEY=your-secret-key
    pytest backend/tests/test_s3_blob_storage.py --s3-emulator=external
"""
import pytest
import base64
import hashlib
import httpx

from blob_store import BlobStore

# Import generic test functions - these are defined in test_blob_storage.py
# We import them directly here since pytest adds the tests directory to sys.path
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from test_blob_storage import (
    generic_blob_upload,
    generic_blob_duplicate_reference_idempotent,
    generic_blob_invalid_id_rejection,
    generic_blob_retrieval_nonexistent,
    generic_blob_reference_removal,
    generic_blob_deletion_nonexistent,
    generic_blob_deduplication,
)


# ============================================================================
# S3 BlobStore Tests - Core Operations
# ============================================================================

def test_s3_blob_upload(s3_blob_store, crypto):
    """Test S3 blob upload with reference counting"""
    generic_blob_upload(s3_blob_store, crypto)


def test_s3_blob_duplicate_reference_idempotent(s3_blob_store, crypto):
    """Test that S3 store allows duplicate references (idempotent)"""
    generic_blob_duplicate_reference_idempotent(s3_blob_store, crypto)


def test_s3_blob_invalid_id_rejection(s3_blob_store):
    """Test that S3 store rejects invalid blob IDs"""
    generic_blob_invalid_id_rejection(s3_blob_store)


def test_s3_blob_retrieval_nonexistent(s3_blob_store, crypto):
    """Test retrieval of non-existent blob returns None"""
    generic_blob_retrieval_nonexistent(s3_blob_store, crypto)


def test_s3_blob_reference_removal(s3_blob_store, crypto):
    """Test S3 blob reference removal"""
    generic_blob_reference_removal(s3_blob_store, crypto)


def test_s3_blob_deletion_nonexistent(s3_blob_store, crypto):
    """Test removing non-existent blob reference from S3 returns False"""
    generic_blob_deletion_nonexistent(s3_blob_store, crypto)


def test_s3_blob_deduplication(s3_blob_store, crypto):
    """Test that multiple spaces can reference same blob content in S3"""
    generic_blob_deduplication(s3_blob_store, crypto)


# ============================================================================
# S3-Specific Tests - Pre-signed URLs
# ============================================================================

def test_s3_get_upload_url(s3_blob_store, crypto):
    """Test that S3 store generates valid pre-signed upload URLs"""
    blob_data = b"Test content for presigned upload"
    blob_id = crypto.compute_blob_id(blob_data)

    upload_url = s3_blob_store.get_upload_url(blob_id)

    assert upload_url is not None
    assert "X-Amz-Signature" in upload_url or "Signature" in upload_url
    assert s3_blob_store.bucket_name in upload_url


def test_s3_get_upload_url_existing_blob_allows(s3_blob_store, crypto):
    """Test that requesting upload URL for existing blob is allowed"""
    blob_data = b"Existing blob content"
    blob_id = crypto.compute_blob_id(blob_data)

    # First, add the blob
    s3_blob_store.add_blob(blob_id, blob_data, "space1", "user1")

    # Requesting upload URL should succeed
    upload_url = s3_blob_store.get_upload_url(blob_id)
    assert upload_url is not None


def test_s3_get_download_url(s3_blob_store, crypto):
    """Test that S3 store generates valid pre-signed download URLs"""
    blob_data = b"Test content for presigned download"
    blob_id = crypto.compute_blob_id(blob_data)

    # First add the blob
    s3_blob_store.add_blob(blob_id, blob_data, "space1", "user1")

    download_url = s3_blob_store.get_download_url(blob_id)

    assert download_url is not None
    assert "X-Amz-Signature" in download_url or "Signature" in download_url
    assert s3_blob_store.bucket_name in download_url


def test_s3_get_download_url_nonexistent(s3_blob_store, crypto):
    """Test that download URL for non-existent blob returns None"""
    blob_id = crypto.compute_blob_id(b"nonexistent content")

    download_url = s3_blob_store.get_download_url(blob_id)

    assert download_url is None


def test_s3_presigned_download_works(s3_blob_store, crypto):
    """Test that pre-signed download URL actually works"""
    blob_data = b"Content to download via presigned URL"
    blob_id = crypto.compute_blob_id(blob_data)

    # Add the blob
    s3_blob_store.add_blob(blob_id, blob_data, "space1", "user1")

    # Get download URL
    download_url = s3_blob_store.get_download_url(blob_id)

    # Actually fetch the content
    response = httpx.get(download_url)
    assert response.status_code == 200
    assert response.content == blob_data


def test_s3_presigned_upload_works(s3_blob_store, crypto):
    """Test that pre-signed upload URL actually works with correct checksum"""
    blob_data = b"Content to upload via presigned URL"
    blob_id = crypto.compute_blob_id(blob_data)

    # Get upload URL
    upload_url = s3_blob_store.get_upload_url(blob_id)

    # Calculate SHA256 checksum (base64 encoded as S3 expects)
    sha256_hash = hashlib.sha256(blob_data).digest()
    checksum_b64 = base64.b64encode(sha256_hash).decode('ascii')

    # Upload via presigned URL with required headers
    response = httpx.put(
        upload_url,
        content=blob_data,
        headers={
            'Content-Type': 'application/octet-stream',
            'x-amz-checksum-sha256': checksum_b64
        }
    )

    assert response.status_code == 200, f"Upload failed: {response.text}"

    # Verify the content is there (via direct S3 access, not metadata)
    retrieved = s3_blob_store.get_blob(blob_id)
    assert retrieved == blob_data


def test_s3_presigned_upload_wrong_checksum_fails(s3_blob_store, crypto):
    """Test that pre-signed upload fails with wrong checksum"""
    blob_data = b"Content with wrong checksum"
    blob_id = crypto.compute_blob_id(blob_data)

    # Get upload URL
    upload_url = s3_blob_store.get_upload_url(blob_id)

    # Calculate wrong checksum
    wrong_checksum = base64.b64encode(b"wrong" * 8).decode('ascii')

    # Upload should fail due to checksum mismatch
    response = httpx.put(
        upload_url,
        content=blob_data,
        headers={
            'Content-Type': 'application/octet-stream',
            'x-amz-checksum-sha256': wrong_checksum
        }
    )

    # S3 returns 400 Bad Request for checksum mismatch
    assert response.status_code in (400, 403), f"Expected failure, got: {response.status_code}"


# ============================================================================
# S3-Specific Tests - Metadata
# ============================================================================

def test_s3_blob_metadata_persistence(s3_blob_store, crypto):
    """Test that blob metadata is correctly stored and retrieved from S3"""
    blob_data = b"Metadata test content"
    blob_id = crypto.compute_blob_id(blob_data)

    # Add blob with specific metadata
    s3_blob_store.add_blob(blob_id, blob_data, "test_space", "test_user")

    # Retrieve metadata
    metadata = s3_blob_store.get_blob_metadata(blob_id)

    assert metadata is not None
    assert len(metadata.references) == 1
    assert metadata.references[0].space_id == "test_space"
    assert metadata.references[0].uploaded_by == "test_user"
    assert metadata.references[0].uploaded_at > 0


def test_s3_blob_metadata_multiple_references(s3_blob_store, crypto):
    """Test that S3 metadata correctly tracks multiple references"""
    blob_data = b"Multi-ref test content"
    blob_id = crypto.compute_blob_id(blob_data)

    # Add multiple references
    s3_blob_store.add_blob(blob_id, blob_data, "space1", "user1")
    s3_blob_store.add_blob(blob_id, blob_data, "space2", "user2")
    s3_blob_store.add_blob(blob_id, blob_data, "space3", "user3")

    # Retrieve metadata
    metadata = s3_blob_store.get_blob_metadata(blob_id)

    assert metadata is not None
    assert len(metadata.references) == 3

    # Check all references are present
    space_ids = {ref.space_id for ref in metadata.references}
    assert space_ids == {"space1", "space2", "space3"}


def test_s3_blob_metadata_deleted_with_blob(s3_blob_store, crypto):
    """Test that S3 metadata is deleted when last reference is removed"""
    blob_data = b"Cleanup test content"
    blob_id = crypto.compute_blob_id(blob_data)

    # Add and then remove
    s3_blob_store.add_blob(blob_id, blob_data, "space1", "user1")
    s3_blob_store.remove_blob_reference(blob_id, "space1", "user1")

    # Both blob and metadata should be gone
    assert s3_blob_store.get_blob(blob_id) is None
    assert s3_blob_store.get_blob_metadata(blob_id) is None
