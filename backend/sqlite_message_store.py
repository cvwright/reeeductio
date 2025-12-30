"""
SQLite implementation of MessageStore

Stores messages in a SQLite database with blockchain-style message chains
"""

import sqlite3
from contextlib import contextmanager
from sql_message_store import SqlMessageStore


class SqliteMessageStore(SqlMessageStore):
    """Store messages in SQLite database"""

    def __init__(self, db_path: str):
        """
        Initialize SQLite message storage

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
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
