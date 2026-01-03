# E2EE Messaging System - Project Structure

## Files Overview

```
e2ee-messaging/
├── README.md                  # Complete documentation
├── openapi.yaml              # OpenAPI 3.0 specification (shared)
├── pyproject.toml            # Python project metadata and dependencies
├── start.sh                  # Quick start script
│
├── backend/                  # Backend implementation
│   ├── main.py               # FastAPI application entry point
│   ├── channel.py            # Channel management and API logic
│   ├── crypto.py             # Cryptographic utilities (Ed25519, SHA256)
│   ├── authorization.py      # Capability-based authorization with RBAC
│   ├── identifiers.py        # Typed identifier utilities
│   ├── path_validation.py    # Path wildcard matching ({any}, {self}, {other}, {...})
│   ├── capability.py         # Capability data structures
│   │
│   ├── state_store.py        # StateStore interface
│   ├── sqlite_state_store.py # SQLite StateStore implementation
│   ├── firestore_state_store.py # Firestore StateStore implementation
│   │
│   ├── message_store.py      # MessageStore interface
│   ├── sqlite_message_store.py # SQLite MessageStore implementation
│   ├── firestore_message_store.py # Firestore MessageStore implementation
│   │
│   ├── blob_store.py         # BlobStore interface
│   ├── filesystem_blob_store.py # Filesystem BlobStore implementation
│   ├── sqlite_blob_store.py  # SQLite BlobStore implementation
│   │
│   └── tests/                # Test suite
│       ├── conftest.py       # Shared fixtures and test utilities
│       ├── test_authorization.py    # Authorization tests
│       ├── test_rbac.py      # Role-based access control tests
│       ├── test_tools.py     # Tool authorization and use limit tests
│       ├── test_crypto.py    # Cryptographic function tests
│       ├── test_identifiers.py # Typed identifier tests
│       ├── test_state_storage.py # Generic state storage tests
│       ├── test_message_storage.py # Message storage tests
│       ├── test_blob_storage.py # Blob storage tests
│       ├── test_blob_auth.py # Blob authorization tests
│       ├── test_path_validation.py # Path wildcard validation tests
│       ├── test_path_validation_integration.py # Path validation integration tests
│       ├── test_integration.py # End-to-end integration tests
│       ├── test_firestore_stores.py # Firestore backend tests
│       └── test_websocket.py # WebSocket tests
│
├── client/                   # Client implementation
│   └── example_client.py     # Client usage examples
│
└── Generated at runtime:
    └── messaging.db          # SQLite database file
```

## Quick Start

### 1. Install Dependencies
```bash
# Install uv if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create virtual environment and install dependencies
uv venv
uv pip install -e .
```

### 2. Run Tests
```bash
uv run pytest
# or run specific tests
uv run pytest backend/tests/test_rbac.py
uv run pytest backend/tests/test_tools.py
```

### 3. Start Server
```bash
.venv/bin/python backend/main.py
```

Or use the convenience script:
```bash
./start.sh
```

### 4. Access API Documentation
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### 5. Run Examples
```bash
.venv/bin/python client/example_client.py
```

## File Descriptions

### Core Backend Files

**backend/main.py**
- FastAPI application entry point
- HTTP endpoint definitions
- JWT authentication middleware
- Request/response validation

**backend/channel.py**
- Channel management logic
- State and message operations
- Authentication (challenge/verify/JWT)
- Authorization checks via AuthorizationEngine

**backend/crypto.py**
- Ed25519 signature verification
- SHA256 hash computation
- Message and blob ID generation
- Base64 encoding/decoding utilities

**backend/authorization.py**
- Capability-based access control with RBAC
- Role management and validation
- Tool authorization and use limits
- Path pattern matching via PathValidator
- Permission checking (read/create/write)
- Capability subset validation
- Privilege escalation prevention

**backend/path_validation.py**
- Path wildcard pattern matching
- Supports {any}, {self}, {other}, {...} wildcards
- Used by authorization engine

**backend/identifiers.py**
- Typed identifier encoding/decoding
- Supports Channel (C_), User (U_), Tool (T_), Message (M_), Blob (B_)
- 264-bit format (44-char URL-safe base64)
- Type validation

### Storage Layer

**State Storage**
- `state_store.py` - StateStore interface
- `sqlite_state_store.py` - SQLite implementation with tool usage tracking
- `firestore_state_store.py` - Firestore implementation
- All state entries are signed (signature, signed_by, signed_at)

**Message Storage**
- `message_store.py` - MessageStore interface
- `sqlite_message_store.py` - SQLite implementation
- `firestore_message_store.py` - Firestore implementation
- Hash chain validation

**Blob Storage**
- `blob_store.py` - BlobStore interface
- `filesystem_blob_store.py` - Filesystem implementation
- `sqlite_blob_store.py` - SQLite implementation
- Content-addressed storage

### Configuration Files

**openapi.yaml**
- Complete API specification
- Request/response schemas
- Authentication schemes
- Example payloads
- Can be imported into Postman, Insomnia, etc.

**pyproject.toml**
- Project metadata and build configuration
- FastAPI and Uvicorn (web framework)
- Pydantic (data validation)
- PyJWT (JWT tokens)
- Cryptography (Ed25519 signatures)

### Documentation

**README.md**
- Architecture overview
- Security model
- API documentation
- Setup instructions
- Usage examples
- Design decisions

### Client Files

**client/example_client.py**
- Channel bootstrap example
- User join workflow
- Message posting and retrieval
- Cryptographic operations
- Capability management

### Test Files

**backend/tests/conftest.py**
- Shared pytest fixtures (temp_db_path, state_store, crypto, authz, etc.)
- Keypair fixtures (admin_keypair, user_keypair, tool_keypair)
- Helper functions (sign_state_entry, sign_and_store_state, set_channel_state)
- Firestore emulator setup

**backend/tests/test_authorization.py**
- Basic capability authorization tests
- Permission checking tests
- Capability subset validation

**backend/tests/test_rbac.py**
- Role-based access control tests
- Role grant validation
- Multiple role inheritance
- Expired role handling
- Privilege escalation prevention

**backend/tests/test_tools.py**
- Tool typed identifier tests
- Tool capability authorization
- Tool use limit enforcement
- Tool authentication
- Privilege escalation prevention for tools

**backend/tests/test_crypto.py**
- Ed25519 signature verification
- SHA256 hash computation
- Base64 encoding/decoding

**backend/tests/test_identifiers.py**
- Typed identifier encoding/decoding
- Type validation
- URL-safety verification

**backend/tests/test_state_storage.py**
- Generic state storage tests (work with any StateStore)
- SQLite-specific tests
- Signed state entry validation

**backend/tests/test_message_storage.py**
- Message storage and retrieval
- Hash chain validation

**backend/tests/test_blob_storage.py**
- Blob storage backends (filesystem and SQLite)
- Content-addressed storage

**backend/tests/test_blob_auth.py**
- Blob authorization tests

**backend/tests/test_path_validation.py**
- Path wildcard pattern matching
- {any}, {self}, {other}, {...} validation

**backend/tests/test_path_validation_integration.py**
- Integration tests for path validation with authorization

**backend/tests/test_integration.py**
- End-to-end workflow tests

**backend/tests/test_firestore_stores.py**
- Firestore StateStore and MessageStore tests

**backend/tests/test_websocket.py**
- WebSocket functionality tests

## Development Workflow

### 1. Modify API
Edit `openapi.yaml` first to define the contract, then update `backend/main.py` to implement it.

### 2. Add Features
- Add storage methods in appropriate store implementation
- Add crypto operations in `backend/crypto.py`
- Add authorization logic in `backend/authorization.py`
- Add path validation patterns in `backend/path_validation.py`
- Wire everything together in `backend/channel.py` and `backend/main.py`

### 3. Test
- Add tests to appropriate test file in `backend/tests/`
- Run all tests: `uv run pytest`
- Run specific test file: `uv run pytest backend/tests/test_rbac.py`
- Run with coverage: `uv run pytest --cov=backend --cov-report=html`

### 4. Document
- Update README.md with new features
- Add examples to `client/example_client.py`

## Production Considerations

This is a reference implementation. Before production use:

1. **Security**
   - Replace in-memory challenge storage with Redis
   - Add rate limiting
   - Implement proper message encryption (AES-GCM)
   - Add TLS/HTTPS
   - Implement proper key derivation

2. **Scalability**
   - Move to PostgreSQL from SQLite
   - Add database indexes for your query patterns
   - Implement message pagination
   - Add caching (Redis)

3. **Reliability**
   - Add comprehensive error handling
   - Implement retry logic
   - Add health checks
   - Monitor database connections
   - Add logging and metrics

4. **Features**
   - Implement WebSocket for real-time updates
   - Add message editing/deletion
   - Implement file upload progress
   - Add batch operations

## Architecture Decisions

### Why FastAPI?
- Fast, modern Python web framework
- Automatic OpenAPI documentation
- Built-in request validation
- Async support for WebSockets

### Why SQLite?
- Simple, embedded database
- No separate server needed
- Perfect for development and demos
- Easy to migrate to PostgreSQL later

### Why Ed25519?
- Fast signature verification
- Small key sizes (32 bytes)
- Modern, secure algorithm
- Well-supported in cryptography libraries

### Why Capability-Based Authorization?
- Fine-grained permissions
- Delegation support
- Audit trail (signed capabilities)
- Prevents privilege escalation
- Decentralized control

## Next Steps

1. Implement WebSocket `/stream` endpoint
2. Add proper message encryption (AES-GCM)
3. Build a simple web client
4. Add multi-device support
5. Implement channel key rotation
6. Add forward secrecy (message ratcheting)
