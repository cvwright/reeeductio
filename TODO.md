1. Per-topic message encryption keys, so we could provide some users with limited access to only certain topics.  topic_key = HKDF(symmetric_root, topic_id)
2. Change "channel" to "queue" everywhere to emphasize the "encrypted pubsub" approach, and to sound less like a Telegram/Signal/Matrix/IRC competitor
3. Role-based access control.  Add state under roles/{role_name}/rights/ with the rights for that role.
4. Figure out a plan for /create/{channel_id}
   - Request needs to be signed by some trusted key, which must be loaded from config or some database.
   - Maybe config has a master public key that defines an admin channel/queue that contains all the other authorizations ???
5. Figure out a plan for /login
   - Maybe this uses a special queue too, with public key given in the config