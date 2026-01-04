# Server Admin Interface
The server provides an API under /admin for managing server-level users (above the level of individual spaces) and for creating spaces.

Top-level users of the server can create and delete spaces, and server admins can also delete blobs (and maybe messages).

Like users within individual spaces, users at the server level are identified only by their public key.  In fact, the admin interface stores all of its data in a special-purpose space, which can also be used through the normal space API to manage the server state.

## Admin Space Membership Model

The admin space has two tiers of membership:

### Server Users (Space Creators)
- **Purpose**: Authentication only
- **Admin space membership**: YES (under `auth/users/{user_id}`)
- **Capabilities in admin space**: None - they exist for authentication but have no roles or capabilities
- **What they CAN do**: Authenticate to get JWT tokens, then use `/admin` endpoints
- **What they CAN'T do via normal space API**: Cannot read/write any state in the admin space, cannot send messages
- **Admin API powers**: Create spaces (via `PUT /admin/spaces/{space_id}`)

### Server Admins
- **Purpose**: Full server management
- **Admin space membership**: YES (under `auth/users/{user_id}`)
- **Capabilities in admin space**: Full access via `server-admin` role
- **What they CAN do**: Manage all admin space state via normal space API or `/admin` endpoints
- **Admin API powers**: All admin operations including user management

## Example admin functions

### Creating spaces and top-level users
* `PUT /admin/auth/users/{user_id}`
* `PUT /admin/spaces/{space_id}`

### Getting information
* `GET /admin/auth/users/{user_id}`
* `GET /admin/spaces/{space_id}`
* `GET /admin/blobs/{blob_id}`

### Deleting spaces, users, and blobs (and messages?)
* `DELETE /admin/auth/users/{user_id}`
* `DELETE /admin/spaces/{space_id}`
* `DELETE /admin/blobs/{blob_id}`
* `DELETE /admin/spaces/{space_id}/messages/{message_id}`

## The Admin Space
The server uses a space to store its top-level admin data.

The admin private key for this special space must be included in the server's configuration.

If the server owner also keeps a local copy of the admin private key, then they can manage the server remotely via the space's regular API interface.

### Admin Space State Structure

The admin space uses the following state hierarchy:

#### Server Users
Information on each server-level user is stored at `users/{user_id}`:
```json
{
  "user_id": "U_abc123...",
  "can_create_spaces": true,
  "max_spaces": 10,
  "created_at": 1234567890
}
```

This is application-level metadata used by the `/admin` API for quota enforcement. Note that this is separate from the user's authentication entry at `auth/users/{user_id}`, which may have no roles or capabilities.

#### Space Registry
The canonical registry of all spaces is stored at `spaces/{space_id}`:
```json
{
  "space_id": "C_abc123...",
  "created_by": "U_xyz789...",
  "created_at": 1234567890,
  "signature": "user_signature",
  "space_signature": "space_signature"
}
```

This registry serves as the single source of truth for space existence and prevents duplicate space creation.

#### User Space Index
For each user, their spaces are indexed at `users/{user_id}/spaces/{space_id}`:
```json
{
  "space_id": "C_abc123..."
}
```

This enables efficient "list spaces created by user" queries for quota enforcement.

## Authentication
The admin API's authentication and authorization scheme are exactly the same as for the admin space.  Any member of the admin space can authenticate to the admin API using the same Ed25519 keys and JWT tokens that they use with the admin space.

The admin API exposes the `GET /admin/auth/challenge` and `POST /admin/auth/verify` endpoints for convenience, so clients do not need to know or remember the admin space id.

## Authorization

Admin API calls are authorized based on the authenticated user's permissions and server-level metadata.

### Space Creation Flow

When user U1 calls `PUT /admin/spaces/{space_id}`, the following validation occurs:

1. **JWT Authentication**: User must have a valid JWT token for the admin space
2. **User Permissions**: User's entry at `users/{user_id}` must have `can_create_spaces: true`
3. **Quota Check**: If `max_spaces` is set, count spaces where `created_by == user_id` and ensure limit not exceeded
4. **Duplicate Prevention**: Verify no entry exists at `spaces/{space_id}`
5. **Space Ownership Proof**: Verify the `space_signature` in the request body

The request body must contain:
```json
{
    "space_id": "C_abc123...",
    "created_by": "U_xyz789...",
    "created_at": 1234567890,
    "signature": "user_signature_over_this_object",
    "space_signature": "space_key_signature_proving_ownership"
}
```

**Two signatures are required:**
- **User signature**: The user signs the entire JSON object to prove they intend to create this space
- **Space signature**: The space private key signs `{space_id, created_by, created_at}` to prove ownership and consent

### Server Writes State on User's Behalf

Importantly, the `/admin` API endpoints do **not** write to the admin space state as the authenticated user. Instead, the server validates the user's request and then writes the state entries using the **admin space creator private key** (from server configuration).

This means:
- Server users do not need any write capabilities in the admin space
- All admin space state modifications are signed by the server (admin space creator)
- The user's signed data is embedded in the state entry's data payload for audit purposes

When the server processes `PUT /admin/spaces/{space_id}`, it:
1. Validates the user's request (authentication, permissions, signatures, quota)
2. Writes to `spaces/{space_id}` **as the admin space creator**
3. Writes to `users/{user_id}/spaces/{space_id}` **as the admin space creator**
4. Initializes the actual space in the space manager

### Roles and Permissions

The admin space defines two conceptual roles, but they work differently:

#### Server Users (Space Creators)
Server users are members of the admin space but have **no capabilities** assigned. Their permissions are defined purely by application-level metadata at `users/{user_id}`:
- `can_create_spaces`: Whether user can create spaces via `/admin/spaces`
- `max_spaces`: Optional quota limit

Server users authenticate to the admin space to get JWT tokens, but cannot read or write any admin space state via the normal space API. They can only operate through the `/admin` endpoints, which validate their permissions and write state on their behalf.

#### Server Admins
Server admins have the `server-admin` role with full capabilities:

**Role: `auth/roles/server-admin`**
- `{ op: "write", path: "auth/{...}" }` - Manage admin space membership and roles
- `{ op: "write", path: "spaces/{...}" }` - Manage space registry
- `{ op: "write", path: "users/{...}" }` - Manage user metadata and quotas
- `{ op: "delete", path: "spaces/{...}" }` - Delete spaces

Server admins can manage the server either through `/admin` endpoints or by directly interacting with the admin space's state using the normal space API.

## Implementation Notes

### Space Creation Validation

The `/admin/spaces/{space_id}` endpoint must validate:

1. **Space signature verification**: Extract the public key from `space_id`, verify the signature over `{space_id, created_by, created_at}` matches
2. **User signature verification**: Verify the user's signature over the entire request body
3. **Consistency checks**:
   - `space_id` in body matches URL parameter
   - `created_by` in body matches authenticated user from JWT
4. **Duplicate check**: Query admin space state for `spaces/{space_id}` - return 409 Conflict if exists
5. **Quota enforcement**: If user has `max_spaces` set, count existing spaces and reject if quota exceeded

### Error Responses

| Status Code | Condition |
|-------------|-----------|
| 400 Bad Request | Invalid space_id format, missing required fields, signature verification failed |
| 401 Unauthorized | Missing or invalid JWT token |
| 403 Forbidden | User's `can_create_spaces` is false, or quota exceeded |
| 409 Conflict | Space already exists in registry |
| 500 Internal Server Error | Failed to write to admin space state or initialize space |

### Space Deletion

When deleting a space via `DELETE /admin/spaces/{space_id}`:
1. Remove entry from `spaces/{space_id}`
2. Find and remove entry from `users/{created_by}/spaces/{space_id}`
3. Delete the actual space data (state store, message store)
4. Optionally delete associated blobs (if not shared with other spaces)

### Bootstrap Procedure

On first server startup:
1. Check if admin space exists; if not, create it using the admin space ID and creator private key from config
2. Initialize admin space with the `server-admin` role definition
3. Create the first server admin user entry (bootstrap admin from config)
4. Grant bootstrap admin the `server-admin` role

### Security Considerations

- The admin space creator private key is highly sensitive - compromise allows full server control
- Consider encrypting the admin private key in config with a passphrase required at server startup
- Server users cannot bypass `/admin` validation by writing directly to admin space (they have no capabilities)
- All space creations are non-repudiable (both user and space signatures preserved in state)

# Extension ideas

## Managing S3 Buckets
We could have different S3 buckets for different server-level users.  Then when user U1 creates a space, that space's blobs are stored in user U1's bucket.

Bucket information could be stored under `server/buckets/{bucket_id}` or under `server/users/{user_id}/buckets/{bucket_id}`.

This might be nice because then the server admin can let their friends bring their own buckets (heh BYOB) and pay for their own storage.