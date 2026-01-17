"""
High-level Space client for reeeductio.

Provides convenient methods for interacting with spaces, handling
authentication, messages, state, blobs, and data.
"""

from __future__ import annotations

import base64

import httpx

from . import blobs, kvdata, messages, state
from .auth import AuthSession
from .crypto import Ed25519KeyPair, decrypt_aes_gcm, encrypt_aes_gcm, derive_key
from .exceptions import NotFoundError, ValidationError
from .models import BlobCreated, DataEntry, Message, MessageCreated


class Space:
    """
    High-level client for interacting with a reeeductio space.

    Handles authentication, state management, messaging, blob storage, and key-value data.
    Uses httpx for HTTP operations with support for both sync usage.

    Attributes:
        space_id: Typed space identifier
        keypair: Ed25519 key pair for authentication and signing
        symmetric_root: 256-bit root key for HKDF derivation
        message_key: Derived key for message encryption (32 bytes)
        blob_key: Derived key for blob encryption (32 bytes)
        state_key: Derived key for state encryption (32 bytes)
        data_key: Derived key for data encryption (32 bytes)
        base_url: Base URL of the reeeductio server
        auth: Authentication session manager
    """

    def __init__(
        self,
        space_id: str,
        keypair: Ed25519KeyPair,
        symmetric_root: bytes,
        base_url: str = "http://localhost:8000",
        auto_authenticate: bool = True,
    ):
        """
        Initialize Space client.

        Args:
            space_id: Typed space identifier (44-char base64)
            keypair: Ed25519 key pair for authentication and signing
            symmetric_root: 256-bit (32-byte) root key for HKDF key derivation
            base_url: Base URL of the reeeductio server
            auto_authenticate: Whether to authenticate automatically on first request

        Raises:
            ValueError: If symmetric_root is not exactly 32 bytes
        """
        if len(symmetric_root) != 32:
            raise ValueError(f"symmetric_root must be exactly 32 bytes, got {len(symmetric_root)}")

        self.space_id = space_id
        self.keypair = keypair
        self.symmetric_root = symmetric_root
        self.base_url = base_url
        self._auto_authenticate = auto_authenticate

        # Derive encryption keys from symmetric_root using HKDF
        # Include space_id in info for domain separation (prevents key reuse across spaces)
        self.message_key = derive_key(symmetric_root, f"message key | {space_id}")
        self.blob_key = derive_key(symmetric_root, f"blob key | {space_id}")
        self.data_key = derive_key(symmetric_root, f"data key | {space_id}")
        # State key is actually just a topic key for the "state" topic
        self.state_key = derive_key(self.message_key, "topic key | state")
        # Keys for other topics can be derived as `topic_key = derive_key(self.message_key, f"topic key | {topic_id}")`

        # Create authentication session
        self.auth = AuthSession(
            space_id=space_id,
            public_key_typed=keypair.to_user_id(),
            private_key=keypair.private_key,
            base_url=base_url,
        )

        self._client: httpx.Client | None = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close client."""
        self.close()

    def close(self):
        """Close the HTTP client."""
        if self._client:
            self._client.close()
            self._client = None

    @property
    def client(self) -> httpx.Client:
        """
        Get authenticated HTTP client, ensuring valid authentication.

        Returns:
            Authenticated httpx.Client

        Raises:
            AuthenticationError: If authentication fails
        """
        if self._auto_authenticate:
            token = self.auth.ensure_authenticated()
        elif self.auth.token:
            token = self.auth.token
        else:
            raise ValueError("Not authenticated. Call authenticate() or set auto_authenticate=True")

        # Create or update client with current token
        if not self._client:
            self._client = httpx.Client(
                base_url=self.base_url,
                headers={"Authorization": f"Bearer {token}"},
            )
        else:
            # Update token if changed
            self._client.headers["Authorization"] = f"Bearer {token}"

        return self._client

    def authenticate(self) -> str:
        """
        Perform authentication.

        Returns:
            JWT bearer token
        """
        return self.auth.authenticate()

    # ============================================================
    # State Management
    # ============================================================
    
    def get_plaintext_state(self, path: str) -> str:
        """
        Get current state value at path.

        Args:
            path: State path (e.g., "auth/users/U_abc123", "profiles/alice")

        Returns:
            Message containing the current state at this path

        Raises:
            NotFoundError: If no state exists at this path
        """
        message = state.get_state(self.client, self.space_id, path)
        return message.data
    
    def get_encrypted_state(self, path: str) -> str:
        """
        Get encrypted state value at path and decrypt it.

        The state data is stored as base64-encoded AES-GCM-256 encrypted data.
        Format: IV (12 bytes) + ciphertext + tag (16 bytes)

        Args:
            path: State path (e.g., "auth/users/U_abc123", "profiles/alice")

        Returns:
            Decrypted plaintext string

        Raises:
            NotFoundError: If no state exists at this path
            ValueError: If decryption fails (invalid format)
        """
        message = state.get_state(self.client, self.space_id, path)

        encrypted_b64 = message.data
        if len(encrypted_b64) == 0:
            return ""

        # Base64 decode
        encrypted_bytes = base64.b64decode(encrypted_b64)

        # Decrypt using state key
        plaintext_bytes = decrypt_aes_gcm(encrypted_bytes, self.state_key)

        # Convert to string
        return plaintext_bytes.decode("utf-8")

    def set_plaintext_state(self, path: str, data: str, prev_hash: str | None = None) -> MessageCreated:
        """
        Set plaintext state value at path.

        The data is stored as-is without encryption.

        Args:
            path: State path (e.g., "profiles/alice", "config/settings")
            data: Plaintext string data to store
            prev_hash: Previous message hash in state topic (optional, fetched if not provided)

        Returns:
            MessageCreated with message_hash and server_timestamp

        Note:
            If prev_hash is not provided, this will fetch the current chain head.
            This may cause conflicts if multiple clients are writing concurrently.
        """
        # Convert string to bytes and store directly
        data_bytes = data.encode("utf-8")
        return self._set_state(path, data_bytes, prev_hash)

    def set_encrypted_state(self, path: str, data: str, prev_hash: str | None = None) -> MessageCreated:
        """
        Set encrypted state value at path.

        The data is encrypted using AES-GCM-256 with the state key, then base64-encoded.
        Format: IV (12 bytes) + ciphertext + tag (16 bytes)

        Args:
            path: State path (e.g., "auth/users/U_abc123", "profiles/alice")
            data: Plaintext string data to encrypt and store
            prev_hash: Previous message hash in state topic (optional, fetched if not provided)

        Returns:
            MessageCreated with message_hash and server_timestamp

        Note:
            If prev_hash is not provided, this will fetch the current chain head.
            This may cause conflicts if multiple clients are writing concurrently.
        """
        # Convert string to bytes
        plaintext_bytes = data.encode("utf-8")

        # Encrypt using state key
        encrypted_bytes = encrypt_aes_gcm(plaintext_bytes, self.state_key)

        # Base64 encode
        encrypted_b64 = base64.b64encode(encrypted_bytes).decode("ascii")

        # Store as bytes
        data_bytes = encrypted_b64.encode("utf-8")
        return self._set_state(path, data_bytes, prev_hash)

    def _set_state(self, path: str, data: bytes, prev_hash: str | None = None) -> MessageCreated:
        """
        Set state value at path.

        State is stored as messages in the "state" topic with the path in the 'type' field.

        Args:
            path: State path (e.g., "profiles/alice")
            data: Encrypted state data
            prev_hash: Previous message hash in state topic (optional, fetched if not provided)

        Returns:
            MessageCreated with message_hash and server_timestamp

        Note:
            If prev_hash is not provided, this will fetch the current chain head.
            This may cause conflicts if multiple clients are writing concurrently.
        """
        # Fetch prev_hash if not provided
        if prev_hash is None:
            msgs = self.get_messages("state", limit=1)
            prev_hash = msgs[0].message_hash if msgs else None

        return state.set_state(
            client=self.client,
            space_id=self.space_id,
            path=path,
            data=data,
            prev_hash=prev_hash,
            sender_public_key_typed=self.keypair.to_user_id(),
            sender_private_key=self.keypair.private_key,
        )

    def get_state_history(
        self,
        from_timestamp: int | None = None,
        to_timestamp: int | None = None,
        limit: int = 100,
    ) -> list[Message]:
        """
        Get all state change messages (event log).

        Args:
            from_timestamp: Optional start timestamp (milliseconds)
            to_timestamp: Optional end timestamp (milliseconds)
            limit: Maximum number of messages to return

        Returns:
            List of state change messages
        """
        return state.get_state_history(
            self.client,
            self.space_id,
            from_timestamp,
            to_timestamp,
            limit,
        )

    # ============================================================
    # Message Management
    # ============================================================

    def get_messages(
        self,
        topic_id: str,
        from_timestamp: int | None = None,
        to_timestamp: int | None = None,
        limit: int = 100,
    ) -> list[Message]:
        """
        Get messages from a topic.

        Args:
            topic_id: Topic identifier
            from_timestamp: Optional start timestamp (milliseconds)
            to_timestamp: Optional end timestamp (milliseconds)
            limit: Maximum number of messages to return

        Returns:
            List of messages
        """
        try:
            params = {"limit": limit}
            if from_timestamp is not None:
                params["from"] = from_timestamp
            if to_timestamp is not None:
                params["to"] = to_timestamp

            response = self.client.get(f"/spaces/{self.space_id}/topics/{topic_id}/messages", params=params)
            response.raise_for_status()
            data = response.json()
            message_list = data.get("messages", [])
            return [Message(**msg) for msg in message_list]
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return []
            raise ValidationError(f"Failed to get messages: {e.response.text}") from e
        except Exception as e:
            raise ValidationError(f"Failed to get messages: {e}") from e

    def get_message(self, topic_id: str, message_hash: str) -> Message:
        """
        Get a specific message by hash.

        Args:
            topic_id: Topic identifier
            message_hash: Typed message identifier (44-char base64)

        Returns:
            Message

        Raises:
            NotFoundError: If message not found
        """
        try:
            response = self.client.get(f"/spaces/{self.space_id}/topics/{topic_id}/messages/{message_hash}")
            response.raise_for_status()
            data = response.json()
            return Message(**data)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                raise NotFoundError(f"Message not found: {message_hash}") from e
            raise ValidationError(f"Failed to get message: {e.response.text}") from e
        except Exception as e:
            raise ValidationError(f"Failed to get message: {e}") from e

    def post_message(
        self,
        topic_id: str,
        msg_type: str,
        data: bytes,
        prev_hash: str | None = None,
    ) -> MessageCreated:
        """
        Post a message to a topic.

        Args:
            topic_id: Topic identifier
            msg_type: Message type/category
            data: Encrypted message data
            prev_hash: Hash of previous message (optional, fetched if not provided)

        Returns:
            MessageCreated with message_hash and server_timestamp

        Note:
            If prev_hash is not provided, this will fetch the current chain head.
        """
        # Fetch prev_hash if not provided
        if prev_hash is None:
            msgs = self.get_messages(topic_id, limit=1)
            prev_hash = msgs[0].message_hash if msgs else None

        return messages.post_message(
            client=self.client,
            space_id=self.space_id,
            topic_id=topic_id,
            msg_type=msg_type,
            data=data,
            prev_hash=prev_hash,
            sender_public_key_typed=self.keypair.to_user_id(),
            sender_private_key=self.keypair.private_key,
        )

    # ============================================================
    # Blob Management
    # ============================================================

    def upload_plaintext_blob(self, data: bytes) -> BlobCreated:
        """
        Upload plaintext blob.

        The blob_id is computed from the content hash.

        Args:
            data: Plaintext blob data

        Returns:
            BlobCreated with blob_id and size
        """
        return blobs.upload_blob(self.client, self.space_id, data)

    def encrypt_and_upload_blob(self, data: bytes) -> BlobCreated:
        """
        Encrypt and upload a blob.

        The data is encrypted using AES-GCM-256 with the blob key before upload.
        The blob_id is computed from the encrypted content hash.

        Args:
            data: Plaintext blob data to encrypt and upload

        Returns:
            BlobCreated with blob_id and size
        """
        # Encrypt using blob key
        encrypted_data = encrypt_aes_gcm(data, self.blob_key)
        return blobs.upload_blob(self.client, self.space_id, encrypted_data)

    def download_plaintext_blob(self, blob_id: str) -> bytes:
        """
        Download plaintext blob.

        Args:
            blob_id: Typed blob identifier

        Returns:
            Plaintext blob data
        """
        return blobs.download_blob(self.client, self.space_id, blob_id)

    def download_and_decrypt_blob(self, blob_id: str) -> bytes:
        """
        Download and decrypt encrypted blob.

        The blob is decrypted using AES-GCM-256 with the blob key.

        Args:
            blob_id: Typed blob identifier

        Returns:
            Decrypted plaintext blob data

        Raises:
            cryptography.exceptions.InvalidTag: If decryption fails (wrong key or corrupted data)
        """
        # Download encrypted data
        encrypted_data = blobs.download_blob(self.client, self.space_id, blob_id)

        # Decrypt using blob key
        plaintext_data = decrypt_aes_gcm(encrypted_data, self.blob_key)

        return plaintext_data

    def delete_blob(self, blob_id: str) -> None:
        """
        Delete blob.

        Args:
            blob_id: Typed blob identifier
        """
        blobs.delete_blob(self.client, self.space_id, blob_id)

    # ============================================================
    # Key-Value Data Management
    # ============================================================

    def get_plaintext_data(self, path: str) -> bytes:
        """
        Get plaintext data value at path.

        Args:
            path: Data path (e.g., "profiles/alice", "settings/theme")

        Returns:
            Plaintext data bytes

        Raises:
            NotFoundError: If no data exists at this path
        """
        entry = kvdata.get_data(self.client, self.space_id, path)

        # Data is stored as base64-encoded
        return base64.b64decode(entry.data)

    def get_encrypted_data(self, path: str) -> bytes:
        """
        Get encrypted data value at path and decrypt it.

        The data is stored as base64-encoded AES-GCM-256 encrypted data.
        Format: IV (12 bytes) + ciphertext + tag (16 bytes)

        Args:
            path: Data path (e.g., "profiles/alice", "settings/theme")

        Returns:
            Decrypted plaintext data bytes

        Raises:
            NotFoundError: If no data exists at this path
            cryptography.exceptions.InvalidTag: If decryption fails (wrong key or corrupted data)
        """
        entry = kvdata.get_data(self.client, self.space_id, path)

        # Base64 decode
        encrypted_bytes = base64.b64decode(entry.data)

        # Decrypt using data key
        plaintext_bytes = decrypt_aes_gcm(encrypted_bytes, self.data_key)

        return plaintext_bytes

    def set_plaintext_data(self, path: str, data: bytes) -> int:
        """
        Set plaintext data value at path.

        The data is base64-encoded but not encrypted.

        Args:
            path: Data path (e.g., "profiles/alice", "settings/theme")
            data: Plaintext data bytes to store

        Returns:
            Timestamp when the data was signed (milliseconds)
        """
        return self._set_data(path, data)

    def set_encrypted_data(self, path: str, data: bytes) -> int:
        """
        Set encrypted data value at path.

        The data is encrypted using AES-GCM-256 with the data key, then base64-encoded.
        Format: IV (12 bytes) + ciphertext + tag (16 bytes)

        Args:
            path: Data path (e.g., "profiles/alice", "settings/theme")
            data: Plaintext data bytes to encrypt and store

        Returns:
            Timestamp when the data was signed (milliseconds)
        """
        # Encrypt using data key
        encrypted_bytes = encrypt_aes_gcm(data, self.data_key)

        return self._set_data(path, encrypted_bytes)


    def _set_data(self, path: str, data: bytes) -> int:
        """
        Set data value at path.

        Args:
            path: Data path
            data: Data bytes to store (will be base64-encoded)

        Returns:
            Timestamp when the data was signed (milliseconds)
        """
        return kvdata.set_data(
            client=self.client,
            space_id=self.space_id,
            path=path,
            data=data,
            signed_by=self.keypair.to_user_id(),
            private_key=self.keypair.private_key,
        )
