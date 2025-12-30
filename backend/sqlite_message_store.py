"""
SQLite implementation of MessageStore

Stores messages in a SQLite database with blockchain-style message chains
"""

import sqlite3
from contextlib import contextmanager
from sql_message_store import SqlMessageStore
from lru_cache import LRUCache


class SqliteMessageStore(SqlMessageStore):
    """Store messages in SQLite database"""

    def __init__(self, db_path: str, cache_size: int = 1000):
        """
        Initialize SQLite message storage

        Args:
            db_path: Path to SQLite database file
            cache_size: Maximum number of items to cache (default: 1000)
        """
        super().__init__()
        self.db_path = db_path

        # Initialize LRU cache for local SQLite storage
        # Safe because SQLite is local to this process
        self._cache = LRUCache(max_size=cache_size)

        self._init_db()

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

    def _get_placeholder(self, position: int = 0) -> str:
        """SQLite uses ? for parameter placeholders"""
        return "?"
