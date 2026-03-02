# reeeductio Python SDK

A clean, modern Python SDK for the [reeeductio Spaces API](https://github.com/cvwright/reeeductio) - an end-to-end encrypted messaging system with capability-based authorization.

## Features

- **End-to-end encryption**: Zero-knowledge server design
- **Blockchain-like message chains**: Cryptographic integrity verification
- **Capability-based authorization**: Granular, signed permissions
- **Multiple storage types**:
  - Messages: Append-only topic streams
  - State: Event-sourced key-value store
  - Data: Simple signed key-value store
  - Blobs: Content-addressed binary storage
- **Real-time streaming**: WebSocket support (coming soon)
- **Async support**: Built on httpx for both sync and async usage
- **Type-safe**: Full type hints and dataclass models

## Installation

```bash
pip install reeeductio
```

Or install from source:

```bash
cd python-sdk
pip install -e .
```

## Quick Start

```python
from reeeductio import Space, generate_keypair
import os

# Generate a key pair
keypair = generate_keypair()
member_id = keypair.to_user_id()  # 44-char typed user identifier starting with 'U'

# Generate or retrieve the space's symmetric root key (32 bytes)
symmetric_root = os.urandom(32)  # In practice, derive from space key or shared secret

# Connect to a space
# The Space client automatically derives encryption keys on init:
#   - message_key (for encrypting messages)
#   - state_key (for encrypting state)
#   - data_key (for encrypting KV data)
with Space(
    space_id="Sabc123...",       # 44-char space ID
    member_id=member_id,         # typed user/tool identifier
    private_key=keypair.private_key,  # raw 32-byte Ed25519 private key
    symmetric_root=symmetric_root,    # 256-bit root key for encryption
    base_url="http://localhost:8000"
) as space:
    # Keys are available as space.message_key, space.state_key, space.data_key
    # Post a message
    result = space.post_message(
        topic_id="general",
        msg_type="chat",
        data=b"Hello, world!"  # Should be encrypted before passing
    )
    print(f"Posted message: {result.message_hash}")

    # Get messages
    messages = space.get_messages("general", limit=10)
    for msg in messages:
        print(f"{msg.sender}: {msg.data}")

    # Upload an encrypted blob
    blob = space.encrypt_and_upload_blob(b"file contents")
    print(f"Uploaded blob: {blob.blob_id}")

    # Set state
    space.set_state("profiles/alice", b'{"name": "Alice"}')

    # Get state
    state_msg = space.get_state("profiles/alice")
    print(f"State: {state_msg.data}")
```

## Architecture

### Components

- **Space**: High-level client for interacting with a space
- **Topics**: Blockchain-style append-only message streams
- **State**: Event-sourced key-value store (stored as messages in the special `state` topic)
- **Data**: Simple signed key-value store
- **Blobs**: Content-addressed encrypted file storage
- **Auth**: Challenge-response authentication with Ed25519 signatures

### Cryptography

All identifiers use typed base64 encoding with a header byte:
- User IDs start with `U` (e.g., `Uabc123...`)
- Space IDs start with `S` (e.g., `Sabc123...`)
- Message IDs start with `M` (e.g., `Mabc123...`)
- Blob IDs start with `B` (e.g., `Babc123...`)
- Tool IDs start with `T` (e.g., `Tabc123...`)

### Message Chains

Messages form blockchain-like chains with hash pointers:

```
Message 1 → Message 2 → Message 3
  (M_abc)    (M_def)     (M_ghi)
              ↑            ↑
         prev_hash    prev_hash
```

Each message hash is computed over: `topic_id|type|prev_hash|data|sender`

### Key Derivation

The Space client uses **HKDF-SHA256** to derive encryption keys from the `symmetric_root`:

```python
space = Space(space_id, keypair, symmetric_root)

# Automatically derived on initialization (scoped to space_id):
space.message_key  # HKDF(symmetric_root, info="message key | {space_id}") → 32 bytes
space.data_key     # HKDF(symmetric_root, info="data key | {space_id}") → 32 bytes
space.state_key    # HKDF(message_key, info="topic key | state") → 32 bytes
```

**Security Benefits:**
- Single shared secret (`symmetric_root`) per space
- Cryptographically independent keys for each data type
- **Domain separation**: Keys are scoped to `space_id` to prevent cross-space key reuse
- Deterministic: same root + same space always produces same keys
- Forward-compatible for key rotation

**Usage:**
```python
from reeeductio import derive_key

# Manual key derivation if needed
custom_key = derive_key(symmetric_root, "custom context", length=32)
```

## API Reference

### Space Client

```python
class Space:
    def __init__(
        self,
        space_id: str,
        member_id: str,             # typed user/tool identifier (e.g. keypair.to_user_id())
        private_key: bytes,         # raw 32-byte Ed25519 private key
        symmetric_root: bytes,      # 256-bit (32-byte) root key for HKDF
        base_url: str = "http://localhost:8000",
        auto_authenticate: bool = True,
        local_store: LocalMessageStore | None = None,
        user_symmetric_key: bytes | None = None,  # optional user-private key
    )

    # Authentication
    def authenticate(self) -> str

    # Messages
    def post_message(self, topic_id: str, msg_type: str, data: bytes, prev_hash: str | None = None) -> MessageCreated
    def get_messages(self, topic_id: str, from_timestamp: int | None = None, to_timestamp: int | None = None, limit: int = 100, use_cache: bool = True, validate_chain: bool = True) -> list[Message]
    def get_message(self, topic_id: str, message_hash: str, use_cache: bool = True) -> Message

    # State
    def get_state(self, path: str) -> Message
    def set_state(self, path: str, data: bytes, prev_hash: str | None = None) -> MessageCreated
    def get_state_history(self, from_timestamp: int | None = None, to_timestamp: int | None = None, limit: int = 100) -> list[Message]

    # Data (KV)
    def get_data(self, path: str) -> DataEntry
    def set_data(self, path: str, data: bytes) -> int

    # Blobs
    def upload_plaintext_blob(self, data: bytes) -> BlobCreated
    def encrypt_and_upload_blob(self, data: bytes) -> EncryptedBlobCreated
    def download_plaintext_blob(self, blob_id: str) -> bytes
    def download_and_decrypt_blob(self, blob_id: str, key: bytes) -> bytes
    def delete_blob(self, blob_id: str) -> None
```

### Crypto Utilities

```python
from reeeductio import generate_keypair, sign_data, compute_hash

# Generate keys
keypair = generate_keypair()
user_id = keypair.to_user_id()
space_id = keypair.to_space_id()

# Sign data
signature = sign_data(b"data to sign", keypair.private_key)

# Hash data
hash_bytes = compute_hash(b"data to hash")
```

## Development Status

### Implemented
- ✅ Core models (Message, Capability, etc.)
- ✅ Cryptography (Ed25519 signing, HKDF key derivation, AES-GCM encryption)
- ✅ Authentication (challenge-response)
- ✅ Message posting and retrieval
- ✅ State management
- ✅ Data (KV) storage
- ✅ Blob upload/download (plaintext and encrypted)
- ✅ Sync API (`Space`) using httpx
- ✅ Async API (`AsyncSpace`) with WebSocket streaming
- ✅ Local message cache (`LocalMessageStore`)
- ✅ Comprehensive test suite (pytest)

### Coming Soon
- ⏳ Additional examples

## Testing

Run the test suite:

```bash
# Install dev dependencies
uv pip install -e ".[dev]"

# Run all tests (19 tests total)
uv run pytest

# Run with verbose output
uv run pytest -v

# Run specific test file
uv run pytest tests/test_key_derivation.py  # 18 key derivation tests
uv run pytest tests/test_smoke.py           # 1 comprehensive API smoke test
```

The test suite includes:
- **test_smoke.py**: Comprehensive smoke test validating the entire public API surface
- **test_key_derivation.py**: 18 tests covering HKDF key derivation, domain separation, and security properties

See [tests/README.md](tests/README.md) for more details.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
