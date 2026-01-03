# Server Admin Interface
The server provides an API under /admin for managing server-level users (above the level of individual channels) and for creating channels.

Top-level users of the server can create and delete channels, and server admins can also delete blobs (and maybe messages).

Like users within individual channels, users at the server level are identified only by their public key.  In fact, the admin interface stores all of its data in a special-purpose channel.

## Example admin functions

### Creating channels and top-level users
* `PUT /admin/users/{user_id}`
* `PUT /admin/channels/{channel_id}`

### Getting information
* `GET /admin/users/{user_id}`
* `GET /admin/channels/{channel_id}`
* `GET /admin/blobs/{blob_id}`

### Deleting channels, users, and blobs (and messages?)
* `DELETE /admin/users/{user_id}`
* `DELETE /admin/channels/{channel_id}`
* `DELETE /admin/blobs/{blob_id}`
* `DELETE /admin/channels/{channel_id}/messages/{message_id}`

# Admin Channel
The server uses a channel to store its top-level admin data.

The admin private key for this special channel must be included in the server's configuration.

## Server-level Users
Information on each server-level user is stored in the admin channel state at `server/users/{user_id}`.

The content of each user's state entry looks like this:

```json
{
    "user_id": "Uabc123xyz....",
    "can_create_channels": true,
    "max_channels": 10
}
```

Note that users at the server level are NOT necessarily also members of the admin room, and that their state is kept under the `server/` prefix rather than under `auth/`.  The only reason for a server user to be a member of the admin room (with an entry under `auth/users/{user_id}`) is to be a server admin who can add or remove server-level users.

## Tracking Users' Channels

The admin channel stores information on the channels created by each user in `server/users/{user_id}/channels/{channel_id}`.  The contents are a JSON object that looks like this:

```json
{
    "channel_id": "C12345abcde...",
    "created_by": "Uabc123xyz...",
    "created_at": 1234567890,
    "signature": "zyxwvuts..."  // Signed by Uabc123xyz...
}
```

This object is created when the channel is created and contains essentially the contents of the `PUT /channels` request.

When the server receives a `PUT /channels` request, it looks up the info for the creating user.  If the user has a limit on the number of their channels, the server lists its state under `server/users/{user_id}/channels` to see how many channels the user already has.  The server channel creator (ie the "server admin") is always authorized to create channels.

Note: The `server/` state hierarchy is owned and managed by the server admin.  The `{user_id}` paths are not controlled by the individual users of the server; they are just for the admin's own bookkeeping.

# Extension ideas

## Managing S3 Buckets
We could have different S3 buckets for different server-level users.  Then when user U1 creates a channel, that channel's blobs are stored in user U1's bucket.

Bucket information could be stored under `server/buckets/{bucket_id}` or under `server/users/{user_id}/buckets/{bucket_id}`.

This might be nice because then the server admin can let their friends bring their own buckets (heh BYOB) and pay for their own storage.