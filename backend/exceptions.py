"""
Custom exceptions for the messaging system
"""


class SpaceNotFoundError(Exception):
    """
    Raised when a space is requested but has not been registered in the admin space.

    Client should register the space in the admin space before attempting to use it.
    """
    pass


class ChainConflictError(Exception):
    """
    Raised when a message's prev_hash doesn't match the current chain head.

    This indicates a concurrent write conflict - another message was added
    to the topic between when the client got the chain head and when they
    tried to add their message.

    Client should:
    1. Get the new chain head
    2. Re-validate their operation against current state
    3. Retry with the new prev_hash
    """
    pass
