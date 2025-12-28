"""
Database layer for E2EE messaging system using SQLite
"""

import sqlite3
import json
from typing import Optional, List, Dict, Any, Union
from contextlib import contextmanager


class Database:
    """SQLite database for storing messages, state, and blobs"""
    
    def __init__(self, db_path: str):
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
    
    def _init_db(self):
        """Initialize database schema"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # State table - stores all channel state (members, capabilities, metadata)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS state (
                    channel_id TEXT NOT NULL,
                    path TEXT NOT NULL,
                    data TEXT NOT NULL,
                    encrypted BOOLEAN NOT NULL,
                    updated_by TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (channel_id, path)
                )
            """)
            
            # Create index for faster state queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_state_channel 
                ON state(channel_id)
            """)
            
            # Messages table - blockchain-style message chains
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    channel_id TEXT NOT NULL,
                    topic_id TEXT NOT NULL,
                    message_hash TEXT NOT NULL PRIMARY KEY,
                    prev_hash TEXT,
                    encrypted_payload TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    server_timestamp INTEGER NOT NULL
                )
            """)
            
            # Create indexes for message queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_topic 
                ON messages(channel_id, topic_id, server_timestamp)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_timestamp 
                ON messages(channel_id, topic_id, server_timestamp DESC)
            """)
            
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
    
    # ========================================================================
    # State Operations
    # ========================================================================
    
    def get_state(
        self,
        channel_id: str,
        path: str
    ) -> Optional[Dict[str, Any]]:
        """Get state value by path"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT data, encrypted, updated_by, updated_at
                FROM state
                WHERE channel_id = ? AND path = ?
            """, (channel_id, path))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            # Parse data (JSON if not encrypted, string if encrypted)
            data = row["data"]
            if not row["encrypted"]:
                try:
                    data = json.loads(data)
                except json.JSONDecodeError:
                    pass  # Keep as string if not valid JSON
            
            return {
                "data": data,
                "encrypted": bool(row["encrypted"]),
                "updated_by": row["updated_by"],
                "updated_at": row["updated_at"]
            }
    
    def set_state(
        self,
        channel_id: str,
        path: str,
        data: Union[Dict, str],
        encrypted: bool,
        updated_by: str,
        updated_at: int
    ):
        """Set state value"""
        # Serialize data
        if isinstance(data, dict):
            data_str = json.dumps(data)
        else:
            data_str = data
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO state 
                (channel_id, path, data, encrypted, updated_by, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (channel_id, path, data_str, encrypted, updated_by, updated_at))
    
    def delete_state(self, channel_id: str, path: str) -> bool:
        """Delete state value"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM state
                WHERE channel_id = ? AND path = ?
            """, (channel_id, path))
            return cursor.rowcount > 0
    
    def list_state(
        self,
        channel_id: str,
        prefix: str
    ) -> List[Dict[str, Any]]:
        """List all state entries matching a prefix"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT path, data, encrypted, updated_by, updated_at
                FROM state
                WHERE channel_id = ? AND path LIKE ?
                ORDER BY path
            """, (channel_id, f"{prefix}%"))
            
            results = []
            for row in cursor.fetchall():
                data = row["data"]
                if not row["encrypted"]:
                    try:
                        data = json.loads(data)
                    except json.JSONDecodeError:
                        pass
                
                results.append({
                    "path": row["path"],
                    "data": data,
                    "encrypted": bool(row["encrypted"]),
                    "updated_by": row["updated_by"],
                    "updated_at": row["updated_at"]
                })
            
            return results
    
    # ========================================================================
    # Message Operations
    # ========================================================================
    
    def add_message(
        self,
        channel_id: str,
        topic_id: str,
        message_hash: str,
        prev_hash: Optional[str],
        encrypted_payload: str,
        sender: str,
        signature: str,
        server_timestamp: int
    ):
        """Add a new message to a topic"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO messages
                (channel_id, topic_id, message_hash, prev_hash,
                 encrypted_payload, sender, signature, server_timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                channel_id, topic_id, message_hash, prev_hash,
                encrypted_payload, sender, signature, server_timestamp
            ))
    
    def get_messages(
        self,
        channel_id: str,
        topic_id: str,
        from_ts: Optional[int] = None,
        to_ts: Optional[int] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Query messages with time-based filtering"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            query = """
                SELECT message_hash, topic_id, prev_hash,
                       encrypted_payload, sender, signature, server_timestamp
                FROM messages
                WHERE channel_id = ? AND topic_id = ?
            """
            params = [channel_id, topic_id]
            
            if from_ts is not None:
                query += " AND server_timestamp >= ?"
                params.append(from_ts)
            
            if to_ts is not None:
                query += " AND server_timestamp <= ?"
                params.append(to_ts)
            
            query += " ORDER BY server_timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            
            messages = []
            for row in cursor.fetchall():
                messages.append({
                    "message_hash": row["message_hash"],
                    "topic_id": row["topic_id"],
                    "prev_hash": row["prev_hash"],
                    "encrypted_payload": row["encrypted_payload"],
                    "sender": row["sender"],
                    "signature": row["signature"],
                    "server_timestamp": row["server_timestamp"]
                })
            
            # Reverse to get chronological order
            messages.reverse()
            return messages
    
    def get_message_by_hash(
        self,
        channel_id: str,
        message_hash: str
    ) -> Optional[Dict[str, Any]]:
        """Get a specific message by its hash"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT message_hash, topic_id, prev_hash,
                       encrypted_payload, sender, signature, server_timestamp
                FROM messages
                WHERE channel_id = ? AND message_hash = ?
            """, (channel_id, message_hash))

            row = cursor.fetchone()
            if not row:
                return None

            return {
                "message_hash": row["message_hash"],
                "topic_id": row["topic_id"],
                "prev_hash": row["prev_hash"],
                "encrypted_payload": row["encrypted_payload"],
                "sender": row["sender"],
                "signature": row["signature"],
                "server_timestamp": row["server_timestamp"]
            }
    
    def get_chain_head(
        self,
        channel_id: str,
        topic_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get the most recent message in a topic (chain head)"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT message_hash
                FROM messages
                WHERE channel_id = ? AND topic_id = ?
                ORDER BY server_timestamp DESC
                LIMIT 1
            """, (channel_id, topic_id))

            row = cursor.fetchone()
            if not row:
                return None

            return {
                "message_hash": row["message_hash"]
            }
    
    # ========================================================================
    # Blob Operations
    # ========================================================================
    
    def add_blob(self, blob_id: str, data: bytes):
        """Store a blob"""
        import time
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO blobs
                (blob_id, data, size, uploaded_at)
                VALUES (?, ?, ?, ?)
            """, (blob_id, data, len(data), int(time.time() * 1000)))
    
    def get_blob(self, blob_id: str) -> Optional[bytes]:
        """Retrieve a blob"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT data FROM blobs WHERE blob_id = ?
            """, (blob_id,))
            
            row = cursor.fetchone()
            return row["data"] if row else None
    
    def delete_blob(self, blob_id: str) -> bool:
        """Delete a blob"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM blobs WHERE blob_id = ?
            """, (blob_id,))
            return cursor.rowcount > 0
