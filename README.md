# E2EE PubSub Messaging System

A capability-based, end-to-end encrypted messaging system designed as a foundational layer for building secure applications.

## Architecture Overview

### Core Concepts

**Channels**: The primary access control boundary. Each channel has:
- A unique Ed25519 public key as its identifier (the channel creator holds the private key)
- A shared symmetric key for encrypting message content
- Independent state storage for members, capabilities, and metadata

**Topics**: Message streams within a channel. Each topic maintains:
- A blockchain-style hash chain of messages (each message links to the previous via `prev_hash`)
- Independent message sequences
- Linear ordering verified by the server

**State**: A flexible key-value store within each channel that can hold:
- **Plaintext state**: Member lists, capabilities, topic metadata (server can read for authorization)
- **Encrypted state**: User preferences, private data (server stores as opaque blobs)

**Capabilities**: Granular, signed permissions that control access:
- Each capability specifies an operation (`read`, `create`, `write`) and a path pattern
- Capabilities are individually signed by the granter
- Stored at `/state/members/{public_key}/rights/{capability_id}`

### Security Model

1. **Zero-knowledge server**: The server never sees plaintext message content
2. **End-to-end encryption**: Messages are encrypted with the channel's symmetric key
3. **Capability-based authorization**: All operations require signed capabilities
4. **Message integrity**: Hash chains ensure messages cannot be tampered with
5. **Signed capabilities**: Prevents privilege escalation and provides audit trail

## API Endpoints

### Authentication

```
POST /channels/{channel_id}/auth/challenge
POST /channels/{channel_id}/auth/verify
POST /channels/{channel_id}/auth/refresh
```

Authentication uses challenge-response with Ed25519 signatures:
1. Client requests challenge with their public key
2. Client signs the challenge with their private key
3. Server verifies signature and issues JWT token

### State Management

```
GET    /channels/{channel_id}/state/{path}
PUT    /channels/{channel_id}/state/{path}
DELETE /channels/{channel_id}/state/{path}
```

All channel data is stored as state:
- `/state/members/{public_key}` - Member identity
- `/state/members/{public_key}/rights/{capability_id}` - Individual capabilities
- `/state/topics/{topic_id}/metadata` - Topic information
- `/state/user/{public_key}/*` - User-specific encrypted data

### Messages

```
GET  /channels/{channel_id}/topics/{topic_id}/messages?from=&to=&limit=
POST /channels/{channel_id}/topics/{topic_id}/messages
GET  /channels/{channel_id}/messages/{message_hash}
```

Messages form a blockchain-style chain:
- Each message includes `prev_hash` pointing to the previous message
- Server validates chain integrity
- Queries are time-based (using server timestamps) for efficiency

### Blobs

```
POST   /blobs
GET    /blobs/{blob_id}
DELETE /blobs/{blob_id}
```

Content-addressed storage for encrypted files/attachments.

## Capability System

### Operations

- **`read`**: Can GET state at matching paths
- **`create`**: Can PUT state that doesn't exist yet
- **`write`**: Can PUT state (both create and update) - superset of `create`

### Path Patterns

Capabilities use path patterns with wildcards:
- `*` matches one path segment
- Trailing `/` indicates prefix match

Examples:
- `/state/members/*/rights/` - Can access any member's rights
- `/state/topics/*/messages/` - Can post to any topic
- `/state/user/{self}/` - Special variable for user's own path

### Capability Structure

```json
{
  "op": "create",
  "path": "/state/topics/*/messages/",
  "granted_by": "base64-granter-public-key",
  "granted_at": 1234567890,
  "signature": "base64-ed25519-signature"
}
```

### Granting Capabilities

To grant a capability to another user:

1. **Have permission to grant**: Must have `create` capability on `/state/members/*/rights/`
2. **Have the capability being granted**: Cannot grant what you don't have (prevents privilege escalation)
3. **Sign the capability**: Signature proves authenticity

The server verifies:
- Signature is valid
- Granter has permission to grant capabilities
- Granter has a superset of the capability being granted

## Bootstrap Process

### Creating a Channel

1. Generate channel Ed25519 keypair (channel public key = channel_id)
2. Use channel private key to add initial state:
   - Add channel creator as first member
   - Grant creator admin capabilities
3. Create join key with limited capabilities
4. Package QR code with: `channel_id`, `symmetric_key`, `join_private_key`

### Joining a Channel

1. Scan QR code to get channel credentials
2. Generate personal Ed25519 keypair
3. Use join key to add yourself as a member:
   ```
   PUT /state/members/{your_public_key}
   ```
4. Use join key to grant yourself basic capabilities:
   ```
   PUT /state/members/{your_public_key}/rights/post_messages
   ```
5. Authenticate with your own keypair

## Installation & Setup

### Prerequisites

- Python 3.9+
- uv (install with: `curl -LsSf https://astral.sh/uv/install.sh | sh`)

### Install Dependencies

```bash
uv venv
uv pip install -e .
```

### Run the Server

```bash
.venv/bin/python backend/main.py
```

Server will start on `http://localhost:8000`

### API Documentation

Once running, visit:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Database Schema

SQLite database with three main tables:

### `state`
```sql
CREATE TABLE state (
    channel_id TEXT NOT NULL,
    path TEXT NOT NULL,
    data TEXT NOT NULL,
    encrypted BOOLEAN NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (channel_id, path)
)
```

### `messages`
```sql
CREATE TABLE messages (
    channel_id TEXT NOT NULL,
    topic_id TEXT NOT NULL,
    message_hash TEXT NOT NULL PRIMARY KEY,
    prev_hash TEXT,
    sequence INTEGER NOT NULL,
    encrypted_payload TEXT NOT NULL,
    client_timestamp INTEGER,
    server_timestamp INTEGER NOT NULL,
    UNIQUE(channel_id, topic_id, sequence)
)
```

### `blobs`
```sql
CREATE TABLE blobs (
    blob_id TEXT NOT NULL PRIMARY KEY,
    data BLOB NOT NULL,
    size INTEGER NOT NULL,
    uploaded_at INTEGER NOT NULL
)
```

## Security Considerations

### What the Server Knows

The server can see:
- Channel IDs (public keys)
- Member public keys
- Capabilities and permissions (stored as plaintext state)
- Message metadata (timestamps, hashes, chain structure)
- Topic IDs

### What the Server Cannot See

- Message content (encrypted with channel symmetric key)
- User preferences and private state (encrypted client-side)
- Channel symmetric keys
- User private keys

### Threat Model

Protected against:
- **Compromised server**: Can't decrypt messages or impersonate users
- **Privilege escalation**: Can't grant capabilities you don't have
- **Message tampering**: Hash chains detect modifications
- **Replay attacks**: Challenges expire, signatures are unique

Not protected against:
- **Network analysis**: Server sees communication patterns
- **Compromised channel key**: Anyone with the QR code can decrypt messages
- **Compromised user key**: Can impersonate that user

## Example Usage

### Python Client Example

```python
import requests
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
import hashlib

# Generate keypair
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)
public_key_b64 = base64.b64encode(public_key_bytes).decode('utf-8')

# Request challenge
response = requests.post(
    f"http://localhost:8000/channels/{channel_id}/auth/challenge",
    json={"public_key": public_key_b64}
)
challenge = response.json()["challenge"]

# Sign challenge
challenge_bytes = base64.b64decode(challenge)
signature = private_key.sign(challenge_bytes)
signature_b64 = base64.b64encode(signature).decode('utf-8')

# Verify and get token
response = requests.post(
    f"http://localhost:8000/channels/{channel_id}/auth/verify",
    json={
        "public_key": public_key_b64,
        "signature": signature_b64,
        "challenge": challenge
    }
)
token = response.json()["token"]

# Use token for authenticated requests
headers = {"Authorization": f"Bearer {token}"}
response = requests.get(
    f"http://localhost:8000/channels/{channel_id}/topics/general/messages",
    headers=headers
)
messages = response.json()
```

## Design Decisions

### Why Capability-Based?

Traditional access control (ACLs, RBAC) centralizes power in administrators. Capability-based security allows:
- **Delegation**: Users can grant subset of their capabilities
- **Least privilege**: Each key/token only has exact permissions needed
- **Auditability**: All capabilities are signed and traceable
- **Decentralization**: No single admin, channel creator can bootstrap but not monopolize

### Why Blockchain-Style Message Chains?

Hash chains provide:
- **Integrity**: Any tampering breaks the chain
- **Ordering**: Clear happens-before relationships
- **Verification**: Clients can verify history independently
- **Simplicity**: No complex consensus, just append-only logs

### Why Separate Channels from Topics?

- **Channels** = Trust boundary (who has the symmetric key)
- **Topics** = Organizational convenience (separate conversation threads)
- Single key for entire channel simplifies key distribution
- All members can read all history (good for transparency)
- Removal requires new channel (clean security model)

## Future Enhancements

- WebSocket implementation for real-time message streaming
- Message deletion/editing (with cryptographic proofs)
- Channel key rotation (re-encryption of history)
- Hierarchical capabilities (delegate with automatic revocation)
- Multi-device support (device keys derived from master key)
- Forward secrecy (per-message keys derived from ratchet)

## License

This is a reference implementation. Use at your own risk.

## Contributing

This is a design exercise. Feel free to fork and adapt for your use case!
