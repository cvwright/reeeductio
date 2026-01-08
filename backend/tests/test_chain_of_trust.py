"""
Tests for chain-of-trust validation

These tests verify that the system properly validates the chain of trust
from any user or tool back to the space admin, preventing database tampering
attacks where an adversary inserts unauthorized keys directly into storage.
"""
import pytest
import json
import base64
import sys
from pathlib import Path

# Add tests directory to path to import conftest
sys.path.insert(0, str(Path(__file__).parent))

import conftest
sign_state_entry = conftest.sign_state_entry
sign_and_store_state = conftest.sign_and_store_state


def test_space_admin_always_valid(authz, admin_keypair):
    """Test that space admin always has valid chain (root of trust)"""
    space_id = admin_keypair['space_id']
    admin_id = admin_keypair['user_id']

    # Admin is the root of trust - always valid
    assert authz.verify_chain_of_trust(space_id, admin_id)


def test_user_created_by_admin_valid(state_store, authz, admin_keypair, user_keypair):
    """Test that a user created by admin has valid chain"""
    space_id = admin_keypair['space_id']
    admin_id = admin_keypair['user_id']
    admin_private = admin_keypair['private']
    user_id = user_keypair['user_id']

    # Admin creates a user
    user_info = {"user_id": user_id}
    sign_and_store_state(
        state_store=state_store,
        space_id=space_id,
        path=f"auth/users/{user_id}",
        contents=user_info,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12345000
    )

    # User has valid chain: user -> admin (root)
    assert authz.verify_chain_of_trust(space_id, user_id)


def test_user_created_by_user_valid(state_store, authz, crypto, admin_keypair, user_keypair):
    """Test that a user created by another user has valid chain"""
    space_id = admin_keypair['space_id']
    admin_id = admin_keypair['user_id']
    admin_private = admin_keypair['private']
    user_id = user_keypair['user_id']
    user_private = user_keypair['private']

    # Create second user keypair
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from identifiers import encode_user_id
    user2_private = Ed25519PrivateKey.generate()
    user2_public = user2_private.public_key().public_bytes_raw()
    user2_id = encode_user_id(user2_public)

    # Admin creates first user
    user_info = {"user_id": user_id}
    sign_and_store_state(
        state_store=state_store,
        space_id=space_id,
        path=f"auth/users/{user_id}",
        contents=user_info,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12345000
    )

    # First user creates second user
    user2_info = {"user_id": user2_id}
    sign_and_store_state(
        state_store=state_store,
        space_id=space_id,
        path=f"auth/users/{user2_id}",
        contents=user2_info,
        signer_private_key=user_private,
        signer_user_id=user_id,
        signed_at=12346000
    )

    # Second user has valid chain: user2 -> user1 -> admin (root)
    assert authz.verify_chain_of_trust(space_id, user2_id)


def test_tool_created_by_admin_valid(state_store, authz, admin_keypair):
    """Test that a tool created by admin has valid chain"""
    space_id = admin_keypair['space_id']
    admin_id = admin_keypair['user_id']
    admin_private = admin_keypair['private']

    # Create tool keypair
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from identifiers import encode_tool_id
    tool_private = Ed25519PrivateKey.generate()
    tool_public = tool_private.public_key().public_bytes_raw()
    tool_id = encode_tool_id(tool_public)

    # Admin creates tool
    tool_info = {"tool_id": tool_id, "use_limit": 100}
    sign_and_store_state(
        state_store=state_store,
        space_id=space_id,
        path=f"auth/tools/{tool_id}",
        contents=tool_info,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12345000
    )

    # Tool has valid chain: tool -> admin (root)
    assert authz.verify_chain_of_trust(space_id, tool_id)


def test_unauthorized_user_insertion_rejected(state_store, authz, admin_keypair):
    """
    Test that a user inserted directly into database (not signed by admin/user)
    is rejected by chain validation

    This simulates a database tampering attack
    """
    space_id = admin_keypair['space_id']

    # Create attacker keypair
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from identifiers import encode_user_id
    attacker_private = Ed25519PrivateKey.generate()
    attacker_public = attacker_private.public_key().public_bytes_raw()
    attacker_id = encode_user_id(attacker_public)

    # Attacker signs their own user entry (database tampering simulation)
    attacker_info = {"user_id": attacker_id}
    sign_and_store_state(
        state_store=state_store,
        space_id=space_id,
        path=f"auth/users/{attacker_id}",
        contents=attacker_info,
        signer_private_key=attacker_private,  # Self-signed!
        signer_user_id=attacker_id,
        signed_at=12345000
    )

    # Attacker's chain is invalid: attacker -> attacker (circular, not admin)
    assert not authz.verify_chain_of_trust(space_id, attacker_id)


def test_capabilities_rejected_for_untrusted_user(state_store, authz, crypto, admin_keypair):
    """
    Test that capabilities are not loaded for a user without valid chain

    This ensures the read path is protected against database tampering
    """
    space_id = admin_keypair['space_id']

    # Create attacker keypair
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from identifiers import encode_user_id
    attacker_private = Ed25519PrivateKey.generate()
    attacker_public = attacker_private.public_key().public_bytes_raw()
    attacker_id = encode_user_id(attacker_public)

    # Attacker inserts themselves into database
    attacker_info = {"user_id": attacker_id}
    sign_and_store_state(
        state_store=state_store,
        space_id=space_id,
        path=f"auth/users/{attacker_id}",
        contents=attacker_info,
        signer_private_key=attacker_private,
        signer_user_id=attacker_id,
        signed_at=12345000
    )

    # Attacker grants themselves god-mode capability
    capability = {"op": "write", "path": "{...}"}
    sign_and_store_state(
        state_store=state_store,
        space_id=space_id,
        path=f"auth/users/{attacker_id}/rights/god_mode",
        contents=capability,
        signer_private_key=attacker_private,
        signer_user_id=attacker_id,
        signed_at=12345000
    )

    # Capabilities should NOT be loaded (chain validation fails)
    capabilities = authz._load_user_capabilities(space_id, attacker_id)
    assert len(capabilities) == 0

    # Permission check should fail
    assert not authz.check_permission(space_id, attacker_id, "write", "anything")


def test_tool_capabilities_rejected_for_untrusted_tool(state_store, authz, admin_keypair):
    """
    Test that tool capabilities are not loaded for a tool without valid chain
    """
    space_id = admin_keypair['space_id']

    # Create attacker tool keypair
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from identifiers import encode_tool_id
    attacker_tool_private = Ed25519PrivateKey.generate()
    attacker_tool_public = attacker_tool_private.public_key().public_bytes_raw()
    attacker_tool_id = encode_tool_id(attacker_tool_public)

    # Attacker inserts tool into database
    tool_info = {"tool_id": attacker_tool_id}
    sign_and_store_state(
        state_store=state_store,
        space_id=space_id,
        path=f"auth/tools/{attacker_tool_id}",
        contents=tool_info,
        signer_private_key=attacker_tool_private,
        signer_user_id=attacker_tool_id,
        signed_at=12345000
    )

    # Attacker grants tool a capability
    capability = {"op": "write", "path": "{...}"}
    sign_and_store_state(
        state_store=state_store,
        space_id=space_id,
        path=f"auth/tools/{attacker_tool_id}/rights/evil",
        contents=capability,
        signer_private_key=attacker_tool_private,
        signer_user_id=attacker_tool_id,
        signed_at=12345000
    )

    # Tool capabilities should NOT be loaded (chain validation fails)
    capabilities = authz._load_tool_capabilities(space_id, attacker_tool_id)
    assert len(capabilities) == 0

    # Permission check should fail
    assert not authz.check_permission(space_id, attacker_tool_id, "write", "anything")


def test_chain_cache_works(state_store, authz, admin_keypair, user_keypair):
    """Test that chain validation cache improves performance"""
    space_id = admin_keypair['space_id']
    admin_id = admin_keypair['user_id']
    admin_private = admin_keypair['private']
    user_id = user_keypair['user_id']

    # Create user
    user_info = {"user_id": user_id}
    sign_and_store_state(
        state_store=state_store,
        space_id=space_id,
        path=f"auth/users/{user_id}",
        contents=user_info,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12345000
    )

    # First validation should populate cache
    assert authz.verify_chain_of_trust(space_id, user_id, skip_cache=False)

    # Check cache is populated
    cache_key = (space_id, user_id)
    assert cache_key in authz._chain_validation_cache
    assert authz._chain_validation_cache[cache_key] == True

    # Second validation should use cache (we can't directly verify this,
    # but we can verify the result is correct)
    assert authz.verify_chain_of_trust(space_id, user_id, skip_cache=False)


def test_chain_cache_invalidation(state_store, authz, admin_keypair, user_keypair):
    """Test that chain cache is properly invalidated"""
    space_id = admin_keypair['space_id']
    admin_id = admin_keypair['user_id']
    admin_private = admin_keypair['private']
    user_id = user_keypair['user_id']

    # Create user
    user_info = {"user_id": user_id}
    sign_and_store_state(
        state_store=state_store,
        space_id=space_id,
        path=f"auth/users/{user_id}",
        contents=user_info,
        signer_private_key=admin_private,
        signer_user_id=admin_id,
        signed_at=12345000
    )

    # Populate cache
    assert authz.verify_chain_of_trust(space_id, user_id)
    cache_key = (space_id, user_id)
    assert cache_key in authz._chain_validation_cache

    # Invalidate cache for this user
    authz.invalidate_chain_cache(space_id, user_id)
    assert cache_key not in authz._chain_validation_cache

    # Can still verify (will repopulate cache)
    assert authz.verify_chain_of_trust(space_id, user_id)
    assert cache_key in authz._chain_validation_cache


def test_invalid_signature_on_user_entry_rejected(state_store, authz, crypto, admin_keypair):
    """Test that a user entry with invalid signature is rejected"""
    space_id = admin_keypair['space_id']
    admin_id = admin_keypair['user_id']

    # Create user keypair
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from identifiers import encode_user_id
    user_private = Ed25519PrivateKey.generate()
    user_public = user_private.public_key().public_bytes_raw()
    user_id = encode_user_id(user_public)

    # Create user entry
    user_info = {"user_id": user_id}
    user_data_b64 = crypto.base64_encode_object(user_info)

    # Sign with WRONG key (user signs instead of admin)
    message = f"{space_id}|auth/users/{user_id}|{user_data_b64}|12345000".encode('utf-8')
    signature = user_private.sign(message)  # User signs, claims admin signed
    signature_b64 = crypto.base64_encode(signature)

    # Store with INCORRECT signer (claims admin signed, but user actually signed)
    state_store.set_state(
        space_id=space_id,
        path=f"auth/users/{user_id}",
        data=user_data_b64,
        signature=signature_b64,
        signed_by=admin_id,  # Claims admin signed
        signed_at=12345000
    )

    # Chain validation should fail (signature verification fails)
    assert not authz.verify_chain_of_trust(space_id, user_id)


def test_nonexistent_user_rejected(authz, admin_keypair):
    """Test that a user with no database entry is rejected"""
    space_id = admin_keypair['space_id']

    # Create user keypair but don't store in database
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from identifiers import encode_user_id
    user_private = Ed25519PrivateKey.generate()
    user_public = user_private.public_key().public_bytes_raw()
    user_id = encode_user_id(user_public)

    # User doesn't exist in database
    assert not authz.verify_chain_of_trust(space_id, user_id)
