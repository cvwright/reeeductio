"""
Database-backed blob storage implementation

Stores encrypted blobs in SQLite database.
"""

import sqlite3
import time
from typing import Optional
from contextlib import contextmanager

from blob_store import BlobStore


class SqliteBlobStore(BlobStore):
    """Store blobs in SQLite database"""

    def __init__(self, db_path: str):
        """
        Initialize database blob storage

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._init_schema()

    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self):
        """Initialize blob storage schema"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Blobs table - content-addressed binary storage
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blobs (
                    blob_id TEXT NOT NULL PRIMARY KEY,
                    data BLOB NOT NULL,
                    size INTEGER NOT NULL,
                    uploaded_at INTEGER NOT NULL
                )
            """)

            conn.commit()

    def add_blob(self, blob_id: str, data: bytes) -> None:
        """Store a blob in the database"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO blobs
                (blob_id, data, size, uploaded_at)
                VALUES (?, ?, ?, ?)
            """, (blob_id, data, len(data), int(time.time() * 1000)))

    def get_blob(self, blob_id: str) -> Optional[bytes]:
        """Retrieve a blob from the database"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT data FROM blobs WHERE blob_id = ?
            """, (blob_id,))

            row = cursor.fetchone()
            return row["data"] if row else None

    def delete_blob(self, blob_id: str) -> bool:
        """Delete a blob from the database"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM blobs WHERE blob_id = ?
            """, (blob_id,))
            return cursor.rowcount > 0
