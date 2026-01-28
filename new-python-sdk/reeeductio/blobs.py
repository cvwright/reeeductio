"""
Blob storage helpers for reeeductio.

Provides utilities for uploading, downloading, and managing encrypted blobs.
"""

from __future__ import annotations

from io import BytesIO

import httpx

from .crypto import compute_hash, to_blob_id
from .exceptions import BlobError
from .models import BlobCreated


def compute_blob_id(data: bytes) -> str:
    """
    Compute blob identifier from content.

    The blob_id is a content-addressed identifier based on SHA256 hash.

    Args:
        data: Raw blob data

    Returns:
        44-char base64 blob identifier with 'B' prefix
    """
    hash_bytes = compute_hash(data)
    return to_blob_id(hash_bytes)


def upload_blob(
    client: httpx.Client,
    space_id: str,
    data: bytes,
) -> BlobCreated:
    """
    Upload encrypted blob to the space.

    The blob_id is computed from the content hash.

    Args:
        client: Authenticated httpx client
        space_id: Typed space identifier
        data: Encrypted blob data

    Returns:
        BlobCreated with blob_id and size

    Raises:
        BlobError: If upload fails
    """
    # Compute blob ID from content
    blob_id = compute_blob_id(data)

    try:
        response = client.put(
            f"/spaces/{space_id}/blobs/{blob_id}",
            content=data,
            headers={"Content-Type": "application/octet-stream"},
            follow_redirects=False,
        )

        # Handle redirect to S3 (307) before raise_for_status
        if response.status_code == 307:
            # Follow redirect to S3
            redirect_url = response.headers.get("Location")
            if not redirect_url:
                raise BlobError("Received 307 redirect but no Location header")

            # Upload to S3 directly — use a clean client without auth headers
            # Include checksum header required by the pre-signed URL
            import base64 as b64mod
            checksum_b64 = b64mod.b64encode(compute_hash(data)).decode("ascii")
            s3_response = httpx.put(
                redirect_url,
                content=data,
                headers={
                    "Content-Type": "application/octet-stream",
                    "x-amz-checksum-sha256": checksum_b64,
                },
            )
            s3_response.raise_for_status()

            return BlobCreated(blob_id=blob_id, size=len(data))

        response.raise_for_status()

        # Direct upload (201)
        result = response.json()
        return BlobCreated(
            blob_id=result["blob_id"],
            size=result["size"],
        )
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 409:
            # Blob already exists - this is actually fine for content-addressed storage
            return BlobCreated(blob_id=blob_id, size=len(data))
        raise BlobError(f"Failed to upload blob: {e.response.text}") from e
    except Exception as e:
        raise BlobError(f"Failed to upload blob: {e}") from e


async def upload_blob_async(
    client: httpx.AsyncClient,
    space_id: str,
    data: bytes,
) -> BlobCreated:
    """
    Async version of upload_blob.

    Args:
        client: Authenticated async httpx client
        space_id: Typed space identifier
        data: Encrypted blob data

    Returns:
        BlobCreated with blob_id and size

    Raises:
        BlobError: If upload fails
    """
    # Compute blob ID from content
    blob_id = compute_blob_id(data)

    try:
        response = await client.put(
            f"/spaces/{space_id}/blobs/{blob_id}",
            content=data,
            headers={"Content-Type": "application/octet-stream"},
            follow_redirects=False,
        )

        # Handle redirect to S3 (307) before raise_for_status
        if response.status_code == 307:
            # Follow redirect to S3
            redirect_url = response.headers.get("Location")
            if not redirect_url:
                raise BlobError("Received 307 redirect but no Location header")

            # Upload to S3 directly — use a clean client without auth headers
            import base64 as b64mod
            checksum_b64 = b64mod.b64encode(compute_hash(data)).decode("ascii")
            async with httpx.AsyncClient() as s3_client:
                s3_response = await s3_client.put(
                    redirect_url,
                    content=data,
                    headers={
                        "Content-Type": "application/octet-stream",
                        "x-amz-checksum-sha256": checksum_b64,
                    },
                )
                s3_response.raise_for_status()

            return BlobCreated(blob_id=blob_id, size=len(data))

        response.raise_for_status()

        # Direct upload (201)
        result = response.json()
        return BlobCreated(
            blob_id=result["blob_id"],
            size=result["size"],
        )
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 409:
            # Blob already exists - this is actually fine for content-addressed storage
            return BlobCreated(blob_id=blob_id, size=len(data))
        raise BlobError(f"Failed to upload blob: {e.response.text}") from e
    except Exception as e:
        raise BlobError(f"Failed to upload blob: {e}") from e


def download_blob(
    client: httpx.Client,
    space_id: str,
    blob_id: str,
) -> bytes:
    """
    Download encrypted blob from the space.

    Args:
        client: Authenticated httpx client
        space_id: Typed space identifier
        blob_id: Typed blob identifier

    Returns:
        Encrypted blob data

    Raises:
        BlobError: If download fails
    """
    try:
        response = client.get(
            f"/spaces/{space_id}/blobs/{blob_id}",
            follow_redirects=False,
        )

        # Handle redirect to S3 (307) before raise_for_status
        if response.status_code == 307:
            redirect_url = response.headers.get("Location")
            if not redirect_url:
                raise BlobError("Received 307 redirect but no Location header")
            s3_response = httpx.get(redirect_url)
            s3_response.raise_for_status()
            return s3_response.content

        response.raise_for_status()
        return response.content
    except httpx.HTTPStatusError as e:
        raise BlobError(f"Failed to download blob: {e.response.text}") from e
    except Exception as e:
        raise BlobError(f"Failed to download blob: {e}") from e


async def download_blob_async(
    client: httpx.AsyncClient,
    space_id: str,
    blob_id: str,
) -> bytes:
    """
    Async version of download_blob.

    Args:
        client: Authenticated async httpx client
        space_id: Typed space identifier
        blob_id: Typed blob identifier

    Returns:
        Encrypted blob data

    Raises:
        BlobError: If download fails
    """
    try:
        response = await client.get(
            f"/spaces/{space_id}/blobs/{blob_id}",
            follow_redirects=False,
        )

        # Handle redirect to S3 (307) before raise_for_status
        if response.status_code == 307:
            redirect_url = response.headers.get("Location")
            if not redirect_url:
                raise BlobError("Received 307 redirect but no Location header")
            async with httpx.AsyncClient() as s3_client:
                s3_response = await s3_client.get(redirect_url)
                s3_response.raise_for_status()
                return s3_response.content

        response.raise_for_status()
        return response.content
    except httpx.HTTPStatusError as e:
        raise BlobError(f"Failed to download blob: {e.response.text}") from e
    except Exception as e:
        raise BlobError(f"Failed to download blob: {e}") from e


def delete_blob(
    client: httpx.Client,
    space_id: str,
    blob_id: str,
) -> None:
    """
    Delete blob from the space.

    Only the uploader or space admin can delete a blob.

    Args:
        client: Authenticated httpx client
        space_id: Typed space identifier
        blob_id: Typed blob identifier

    Raises:
        BlobError: If deletion fails
    """
    try:
        response = client.delete(f"/spaces/{space_id}/blobs/{blob_id}")
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise BlobError(f"Failed to delete blob: {e.response.text}") from e
    except Exception as e:
        raise BlobError(f"Failed to delete blob: {e}") from e


async def delete_blob_async(
    client: httpx.AsyncClient,
    space_id: str,
    blob_id: str,
) -> None:
    """
    Async version of delete_blob.

    Args:
        client: Authenticated async httpx client
        space_id: Typed space identifier
        blob_id: Typed blob identifier

    Raises:
        BlobError: If deletion fails
    """
    try:
        response = await client.delete(f"/spaces/{space_id}/blobs/{blob_id}")
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise BlobError(f"Failed to delete blob: {e.response.text}") from e
    except Exception as e:
        raise BlobError(f"Failed to delete blob: {e}") from e


class BlobEncryption:
    """
    Helper class for encrypting/decrypting blobs using space key.

    Note: This is a placeholder. Actual encryption implementation depends
    on your chosen symmetric encryption scheme (e.g., AES-GCM, ChaCha20-Poly1305).
    """

    def __init__(self, space_key: bytes):
        """
        Initialize blob encryption.

        Args:
            space_key: Shared symmetric key for the space
        """
        self.space_key = space_key

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt blob content.

        Args:
            plaintext: Unencrypted blob data

        Returns:
            Encrypted blob data

        Note:
            This is a placeholder. Implement with actual encryption
            (e.g., using cryptography library for AES-GCM).
        """
        raise NotImplementedError(
            "Blob encryption not yet implemented. Use a library like 'cryptography' to implement AES-GCM or similar."
        )

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt blob content.

        Args:
            ciphertext: Encrypted blob data

        Returns:
            Decrypted blob data

        Note:
            This is a placeholder. Implement with actual decryption.
        """
        raise NotImplementedError(
            "Blob decryption not yet implemented. Use a library like 'cryptography' to implement AES-GCM or similar."
        )
