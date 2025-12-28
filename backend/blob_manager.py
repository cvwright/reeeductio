"""
Blob storage abstraction layer for E2EE messaging system

Provides a base BlobManager interface and concrete implementations for
storing encrypted blobs in different backends (database, filesystem, etc.)
"""

from abc import ABC, abstractmethod
from typing import Optional


class BlobManager(ABC):
    """Abstract base class for blob storage backends"""

    @abstractmethod
    def add_blob(self, blob_id: str, data: bytes) -> None:
        """
        Store a blob

        Args:
            blob_id: Content-addressed identifier for the blob
            data: Raw binary blob data (typically encrypted)
        """
        pass

    @abstractmethod
    def get_blob(self, blob_id: str) -> Optional[bytes]:
        """
        Retrieve a blob by its ID

        Args:
            blob_id: Content-addressed identifier for the blob

        Returns:
            Blob data if found, None otherwise
        """
        pass

    @abstractmethod
    def delete_blob(self, blob_id: str) -> bool:
        """
        Delete a blob

        Args:
            blob_id: Content-addressed identifier for the blob

        Returns:
            True if blob was deleted, False if it didn't exist
        """
        pass
