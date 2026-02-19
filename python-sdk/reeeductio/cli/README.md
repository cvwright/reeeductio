# reeeductio-admin CLI

Command-line tool for administering [reeeductio](https://github.com/cvwright/reeeductio) spaces.

## Installation

```bash
pip install reeeductio-client
```

The `reeeductio-admin` command is installed automatically.

## Global Options

```
reeeductio-admin [OPTIONS] COMMAND [ARGS]...

Options:
  -u, --base-url TEXT        Base URL of the reeeductio server  [default: http://localhost:8000]
  -o, --output [text|json]   Output format  [default: text]
  --version                  Show version and exit.
  --help                     Show this message and exit.
```

## Commands

### `key` — Key generation and management

#### `key generate`
Generate a new Ed25519 keypair and print the derived identifiers.

```bash
reeeductio-admin key generate [--output-format text|json]
```

#### `key info`
Show the type of a typed identifier.

```bash
reeeductio-admin key info <IDENTIFIER>
```

`IDENTIFIER` is a 44-character typed identifier (User, Space, Tool, Message, or Blob).

---

### `space` — Space management

#### `space generate`
Generate new space credentials locally (keypair + symmetric root) without creating anything on the server.

```bash
reeeductio-admin space generate [--output-format text|json]
```

#### `space create`
Create a new space on the server.

```bash
reeeductio-admin space create \
  --private-key <HEX> \
  [--symmetric-root <HEX>] \
  [--output-format text|json]
```

Options:
- `-k / --private-key` (required) — Ed25519 private key for the new space owner (64 hex chars)
- `-s / --symmetric-root` — Symmetric root key (64 hex chars); generated randomly if omitted

#### `space info`
Derive the Space ID, User ID, and Tool ID from a private key.

```bash
reeeductio-admin space info --private-key <HEX>
```

---

### `auth` — Authentication

#### `auth test`
Verify that an admin keypair can authenticate to the server.

```bash
reeeductio-admin auth test --private-key <HEX>
```

---

### `user` — User management

All `user` subcommands require the space owner's private key (`-k`) and the space's symmetric root (`-s`).

#### `user add`
Authorize a user to access the space.

```bash
reeeductio-admin user add <USER_ID> \
  --space-key <HEX> \
  --symmetric-root <HEX>
```

`USER_ID` is a 44-character identifier starting with `U`.

#### `user remove`
Revoke a user's access to the space.

```bash
reeeductio-admin user remove <USER_ID> \
  --space-key <HEX> \
  --symmetric-root <HEX>
```

#### `user list`
List all currently authorized users in the space.

```bash
reeeductio-admin user list \
  --space-key <HEX> \
  --symmetric-root <HEX> \
  [--output-format text|json]
```

#### `user grant`
Grant a specific capability to a user.

```bash
reeeductio-admin user grant <USER_ID> \
  --space-key <HEX> \
  --symmetric-root <HEX> \
  --cap-id <CAP_ID> \
  --op read|create|modify|delete|write \
  --path <RESOURCE_PATH>
```

#### `user assign-role`
Assign a named role to a user.

```bash
reeeductio-admin user assign-role <USER_ID> \
  --space-key <HEX> \
  --symmetric-root <HEX> \
  --role <ROLE_NAME>
```

---

### `tool` — Tool management

All `tool` subcommands require the space owner's private key (`-k`) and the space's symmetric root (`-s`).

#### `tool add`
Authorize a tool to access the space.

```bash
reeeductio-admin tool add <TOOL_ID> \
  --space-key <HEX> \
  --symmetric-root <HEX>
```

`TOOL_ID` is a 44-character identifier starting with `T`.

#### `tool remove`
Revoke a tool's access to the space.

```bash
reeeductio-admin tool remove <TOOL_ID> \
  --space-key <HEX> \
  --symmetric-root <HEX>
```

#### `tool list`
List all currently authorized tools in the space.

```bash
reeeductio-admin tool list \
  --space-key <HEX> \
  --symmetric-root <HEX> \
  [--output-format text|json]
```

#### `tool grant`
Grant a specific capability to a tool.

```bash
reeeductio-admin tool grant <TOOL_ID> \
  --space-key <HEX> \
  --symmetric-root <HEX> \
  --cap-id <CAP_ID> \
  --op read|create|modify|delete|write \
  --path <RESOURCE_PATH>
```

---

### `role` — Role management

#### `role create`
Create a named role in the space.

```bash
reeeductio-admin role create <ROLE_NAME> \
  --space-key <HEX> \
  --symmetric-root <HEX> \
  [--description <TEXT>]
```

#### `role grant`
Grant a capability to a role (all users/tools assigned that role inherit it).

```bash
reeeductio-admin role grant <ROLE_NAME> \
  --space-key <HEX> \
  --symmetric-root <HEX> \
  --cap-id <CAP_ID> \
  --op read|create|modify|delete|write \
  --path <RESOURCE_PATH>
```

---

### `opaque` — Password authentication

#### `opaque enable`
Enable OPAQUE password-based authentication for the space. Must be run once before users can register passwords.

```bash
reeeductio-admin opaque enable \
  --space-key <HEX> \
  --symmetric-root <HEX>
```

#### `opaque register`
Register OPAQUE credentials (username + password) for a user so they can recover their keypair by logging in.

```bash
reeeductio-admin opaque register \
  --space-key <HEX> \
  --symmetric-root <HEX> \
  --username <USERNAME> \
  [--password <PASSWORD>]
```

If `--password` is omitted, the password is prompted interactively (with confirmation).

---

### `blob` — Blob management (admin)

#### `blob delete`
Delete a blob from server storage.

```bash
reeeductio-admin blob delete <BLOB_ID> --private-key <HEX>
```

`BLOB_ID` is a 44-character identifier starting with `B`.

---

## Common Patterns

### Bootstrap a new space

```bash
# 1. Generate credentials for the space owner
reeeductio-admin space generate --output-format json > owner-creds.json

OWNER_KEY=$(jq -r .private_key_hex owner-creds.json)
SYM_ROOT=$(jq -r .symmetric_root_hex owner-creds.json)

# 2. Create the space on the server
reeeductio-admin space create --private-key $OWNER_KEY

# 3. Enable OPAQUE password login
reeeductio-admin opaque enable --space-key $OWNER_KEY --symmetric-root $SYM_ROOT

# 4. Add a user
reeeductio-admin user add <USER_ID> --space-key $OWNER_KEY --symmetric-root $SYM_ROOT
```

### Point to a non-default server

```bash
reeeductio-admin --base-url https://my-server.example.com space info --private-key <HEX>
```

### Get machine-readable output

Most commands support `--output-format json` (or the global `-o json` flag where applicable):

```bash
reeeductio-admin key generate --output-format json
reeeductio-admin user list --space-key <HEX> --symmetric-root <HEX> --output-format json
```
