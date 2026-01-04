# rEEEductio: An absurdly simple end-to-end encrypted (EEE) messaging layer

rEEEductio is an end-to-end encrypted messaging system designed as a foundational layer for building secure applications.

rEEEductio is not intended to be a replacement for an app like Signal.  Instead, it's more like an encrypted pub-sub system that lets apps safely share data and save it to the cloud.

## Architecture Overview

### Core Concepts

**Spaces**: The primary access control boundary. Each space has:
- A unique Ed25519 public key as its identifier (the space creator holds the private key)
- A shared symmetric key for encrypting message content
- Independent state storage for members, capabilities, and metadata

**Topics**: Message streams within a space. Each topic maintains:
- A blockchain-style hash chain of messages (each message links to the previous via `prev_hash`)
- Independent message sequences
- Linear ordering verified by the server

**State**: A flexible key-value store within each space that can hold:
- **Plaintext state**: User identities, roles, capabilities, tools, topic metadata (server can read for authorization)
- **Encrypted state**: User preferences, private data (server stores as opaque blobs)
- **All state entries must be signed**: Each entry includes signature, signed_by (user ID), and signed_at (timestamp)
- Data is stored as base64. Interpretation is up to the application, and format is determined by the path of the state entry, ie the "key" in the key-value store.

**Capabilities**: Granular, signed permissions that control access:
- Each capability specifies an operation (`read`, `create`, `write`) and a path pattern
- Path patterns support wildcards: `{self}`, `{any}`, `{other}`, `{...}` (recursive)
- Capabilities can be granted directly to users or via roles
- User capabilities: `/state/auth/users/{user_id}/rights/{capability_id}`
- Role capabilities: `/state/auth/roles/{role_id}/rights/{capability_id}`
- Tool capabilities: `/state/auth/tools/{tool_id}/rights/{capability_id}`

**Roles**: Reusable permission sets for RBAC:
- Roles are defined at `/state/auth/roles/{role_id}` with associated capabilities
- Users are granted roles at `/state/auth/users/{user_id}/roles/{role_id}`
- Users inherit all capabilities from their assigned roles
- Role grants can have optional expiration times

**Tools**: Limited-use keys with no ambient authority:
- Tools are Ed25519 keypairs identified by `T_` prefix
- Stored at `/state/auth/tools/{tool_id}`
- Can only perform actions explicitly granted via capabilities
- Optional `use_limit` restricts total number of state writes
- Tool usage is tracked separately from regular users

### Security Model

1. **Zero-knowledge server**: The server never sees plaintext message content
2. **End-to-end encryption**: Messages are encrypted with the space's symmetric key
3. **Capability-based authorization**: All operations require explicit capabilities (users, roles, and tools)
4. **Message integrity**: Hash chains ensure messages cannot be tampered with
5. **Signed state**: All state entries are cryptographically signed, preventing tampering and providing audit trail
6. **RBAC support**: Role-based access control allows flexible permission management
7. **Limited-use tools**: Tools can be restricted to a fixed number of operations, enabling secure automation

## API Endpoints

### Authentication

```
POST /spaces/{space_id}/auth/challenge
POST /spaces/{space_id}/auth/verify
POST /spaces/{space_id}/auth/refresh
```

Authentication uses challenge-response with Ed25519 signatures:
1. Client requests challenge with their public key
2. Client signs the challenge with their private key
3. Server verifies signature and issues JWT token

### State Management

```
GET    /spaces/{space_id}/state/{path}
PUT    /spaces/{space_id}/state/{path}
DELETE /spaces/{space_id}/state/{path}
```

All space data is stored as signed state entries:
- `/state/auth/users/{user_id}` - User identity
- `/state/auth/users/{user_id}/rights/{capability_id}` - User capabilities
- `/state/auth/users/{user_id}/roles/{role_id}` - Role grants to users
- `/state/auth/roles/{role_id}` - Role definitions
- `/state/auth/roles/{role_id}/rights/{capability_id}` - Role capabilities
- `/state/auth/tools/{tool_id}` - Tool definitions (with optional use_limit)
- `/state/auth/tools/{tool_id}/rights/{capability_id}` - Tool capabilities
- `/state/topics/{topic_id}/metadata` - Topic information
- `/state/user/{user_id}/*` - User-specific encrypted data

Each state entry includes:
- `data` - Base64-encoded content
- `signature` - Ed25519 signature over `space_id|path|data|signed_at`
- `signed_by` - User ID who created the entry
- `signed_at` - Unix timestamp in milliseconds

### Messages

```
GET  /spaces/{space_id}/topics/{topic_id}/messages?from=&to=&limit=
POST /spaces/{space_id}/topics/{topic_id}/messages
GET  /spaces/{space_id}/messages/{message_hash}
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
- `{any}` - Matches any single path segment
- `{self}` - Matches the acting user's own ID
- `{other}` - Matches any ID except the acting user
- `{...}` - Matches any remaining path segments (recursive)
- Trailing `/` indicates prefix match (deprecated, use `{...}` instead)

Examples:
- `auth/users/{any}/rights/{...}` - Can access any user's rights at any depth
- `topics/{any}/messages/{...}` - Can post to messages in any topic at any depth
- `auth/users/{self}/` - Can only access user's own data
- `auth/users/{other}/banned` - Can ban other users (but not self)

### Capability Structure

```json
{
  "op": "create",
  "path": "topics/{any}/messages/{...}"
}
```

Note: The `granted_by`, `granted_at`, and `signature` fields are added automatically by the state storage system when a capability is created.

### Granting Capabilities

**Direct capability grants** to users or tools:

1. **Have permission to grant**: Must have `create` capability on the target path
2. **Have the capability being granted**: Cannot grant what you don't have (prevents privilege escalation)
3. **Sign the state entry**: All state entries must be signed

**Role-based capability grants**:

1. Create a role with capabilities at `/state/auth/roles/{role_id}/rights/{capability_id}`
2. Grant the role to users at `/state/auth/users/{user_id}/roles/{role_id}`
3. Users inherit all capabilities from their roles
4. Granter must have superset of all role capabilities

The server verifies:
- All state entries have valid signatures
- Granter has permission to create the state entry
- For capability grants: Granter has a superset of the capability being granted
- For role grants: Granter has a superset of all capabilities in the role

## Bootstrap Process

### Creating a Space

1. Generate space Ed25519 keypair (space public key = space_id)
2. Space creator has full admin authority (no need to explicitly add to state)
3. Creator can define roles for common permission sets:
   ```
   PUT /state/auth/roles/user
   PUT /state/auth/roles/user/rights/{capability_id}
   ```
4. Create join tool with limited capabilities (e.g., can only create new users and grant "user" role)
5. Package QR code with: `space_id`, `symmetric_key`, `join_tool_private_key`

### Joining a Space

1. Scan QR code to get space credentials
2. Generate personal Ed25519 keypair
3. Use join tool to add yourself as a user:
   ```
   PUT /state/auth/users/{your_user_id}
   ```
4. Use join tool to grant yourself the basic user role:
   ```
   PUT /state/auth/users/{your_user_id}/roles/user
   ```
5. Authenticate with your own keypair
6. Join tool's usage is tracked and can be limited via `use_limit`

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

SQLite database with four main tables:

### `state`
```sql
CREATE TABLE state (
    space_id TEXT NOT NULL,
    path TEXT NOT NULL,
    data TEXT NOT NULL,
    signature TEXT NOT NULL,
    signed_by TEXT NOT NULL,
    signed_at INTEGER NOT NULL,
    PRIMARY KEY (space_id, path)
)
```

All state entries are cryptographically signed. The signature is computed over `space_id|path|data|signed_at`.

### `tool_usage`
```sql
CREATE TABLE tool_usage (
    space_id TEXT NOT NULL,
    tool_id TEXT NOT NULL,
    use_count INTEGER NOT NULL DEFAULT 0,
    last_used_at INTEGER,
    PRIMARY KEY (space_id, tool_id)
)
```

Tracks usage counts for tools with `use_limit` restrictions.

### `messages`
```sql
CREATE TABLE messages (
    space_id TEXT NOT NULL,
    topic_id TEXT NOT NULL,
    message_hash TEXT NOT NULL PRIMARY KEY,
    prev_hash TEXT,
    sequence INTEGER NOT NULL,
    encrypted_payload TEXT NOT NULL,
    client_timestamp INTEGER,
    server_timestamp INTEGER NOT NULL,
    UNIQUE(space_id, topic_id, sequence)
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
- Space IDs (public keys)
- User and tool public keys (from typed identifiers)
- Roles, capabilities, and permissions (stored as plaintext state)
- State entry signatures and who signed them
- Message metadata (timestamps, hashes, chain structure)
- Topic IDs
- Tool usage counts

### What the Server Cannot See

- Message content (encrypted with space symmetric key)
- User preferences and private state (encrypted client-side)
- Space symmetric keys
- User or tool private keys

### Threat Model

Protected against:
- **Compromised server**: Can't decrypt messages or impersonate users/tools
- **Privilege escalation**: Can't grant capabilities you don't have (applies to roles too)
- **Message tampering**: Hash chains detect modifications
- **State tampering**: All state entries are signed and verified
- **Replay attacks**: Challenges expire, signatures are unique
- **Tool abuse**: Use limits prevent unlimited operations by compromised tools

Not protected against:
- **Network analysis**: Server sees communication patterns and timing
- **Compromised space key**: Anyone with the QR code can decrypt messages
- **Compromised user key**: Can impersonate that user
- **Compromised tool key**: Can use tool's capabilities (up to use_limit)
- **Malicious space creator**: Creator has full admin authority

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
    f"http://localhost:8000/spaces/{space_id}/auth/challenge",
    json={"public_key": public_key_b64}
)
challenge = response.json()["challenge"]

# Sign challenge
challenge_bytes = base64.b64decode(challenge)
signature = private_key.sign(challenge_bytes)
signature_b64 = base64.b64encode(signature).decode('utf-8')

# Verify and get token
response = requests.post(
    f"http://localhost:8000/spaces/{space_id}/auth/verify",
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
    f"http://localhost:8000/spaces/{space_id}/topics/general/messages",
    headers=headers
)
messages = response.json()
```

## Design Decisions

### Why Capability-Based with RBAC?

Pure capability-based systems provide fine-grained control but can be complex to manage. This system combines capabilities with RBAC:
- **Capabilities**: Fine-grained, delegatable permissions with wildcard patterns
- **Roles**: Reusable permission sets for common access patterns
- **Delegation**: Users can grant subset of their capabilities (directly or via roles)
- **Least privilege**: Each key/token only has exact permissions needed
- **Auditability**: All state entries (including capabilities) are signed and traceable
- **Flexibility**: Choose direct capabilities for specific needs, roles for common patterns

### Why Tools?

Tools are limited-use keys designed for automation and integration:
- **No ambient authority**: Tools can only do what they're explicitly granted
- **Use limits**: Optional restrictions prevent runaway automation
- **Revocable**: Delete the tool's state entry to revoke access
- **Auditable**: Tool usage is tracked separately from users
- **Secure delegation**: Share tool keys for specific tasks without sharing user keys

### Why Blockchain-Style Message Chains?

Hash chains provide:
- **Integrity**: Any tampering breaks the chain
- **Ordering**: Clear happens-before relationships
- **Verification**: Clients can verify history independently
- **Simplicity**: No complex consensus, just append-only logs

### Why Separate Spaces from Topics?

- **Spaces** = Trust boundary (who has the symmetric key)
- **Topics** = Organizational convenience (separate conversation threads)
- Single key for entire space simplifies key distribution
- All members can read all history (good for transparency)
- Removal requires new space (clean security model)

## Future Enhancements

- WebSocket implementation for real-time message streaming
- Message deletion/editing (with cryptographic proofs)
- Space key rotation (re-encryption of history)
- Hierarchical capabilities (delegate with automatic revocation)
- Multi-device support (device keys derived from master key)
- Forward secrecy (per-message keys derived from ratchet)

## License

This is a reference implementation. Use at your own risk.

## Contributing

This is a design exercise. Feel free to fork and adapt for your use case!
