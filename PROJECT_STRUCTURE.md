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
│   ├── main.py               # FastAPI application
│   ├── database.py           # SQLite database layer
│   ├── crypto.py             # Cryptographic utilities
│   ├── authorization.py      # Capability-based authorization
│   ├── identifiers.py        # Typed identifier utilities
│   ├── test_backend.py       # Backend test suite
│   └── test_identifiers.py   # Identifier tests
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
.venv/bin/python backend/test_backend.py
.venv/bin/python backend/test_identifiers.py
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
- FastAPI application with all HTTP endpoints
- JWT authentication middleware
- Request/response validation
- Integrates database, crypto, and authorization modules

**backend/database.py**
- SQLite database abstraction
- State storage (members, capabilities, metadata)
- Message storage with chain tracking
- Blob storage (content-addressed)
- Transaction management

**backend/crypto.py**
- Ed25519 signature verification
- Message hash computation
- Capability signature verification
- Base64 encoding/decoding utilities

**backend/authorization.py**
- Capability-based access control
- Path pattern matching with wildcards
- Permission checking (read/create/write)
- Capability subset validation
- Privilege escalation prevention

**backend/identifiers.py**
- Type-safe identifier classes
- Validation and serialization
- ID generation utilities

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

**backend/test_backend.py**
- Database operation tests
- Cryptographic function tests
- Authorization engine tests
- End-to-end integration tests

**backend/test_identifiers.py**
- Typed identifier validation tests
- Serialization/deserialization tests
- ID generation tests

## Development Workflow

### 1. Modify API
Edit `openapi.yaml` first to define the contract, then update `backend/main.py` to implement it.

### 2. Add Features
- Add database methods in `backend/database.py`
- Add crypto operations in `backend/crypto.py`
- Add authorization logic in `backend/authorization.py`
- Wire everything together in `backend/main.py`

### 3. Test
- Add tests to `backend/test_backend.py`
- Run: `.venv/bin/python backend/test_backend.py`
- Run: `.venv/bin/python backend/test_identifiers.py`

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
