"""
Test script for typed identifiers

Verifies that the new 264-bit (33-byte, 44-char base64) typed identifier
format works correctly with Ed25519 keys and SHA256 hashes.
"""

import secrets
from identifiers import (
    TypedIdentifier, IdType,
    encode_channel_id, encode_user_id, encode_message_id, encode_blob_id,
    extract_public_key, extract_hash, decode_identifier
)
from crypto import CryptoUtils


def test_basic_encoding_decoding():
    """Test basic encoding and decoding of typed identifiers"""
    print("Testing basic encoding/decoding...")

    # Generate some test data (32 bytes)
    test_key = secrets.token_bytes(32)
    test_hash = secrets.token_bytes(32)

    # Test channel ID
    channel_id = encode_channel_id(test_key)
    print(f"  Channel ID: {channel_id}")
    print(f"  Length: {len(channel_id)} chars (expected 44)")
    assert len(channel_id) == 44, "Channel ID should be 44 characters"

    decoded = decode_identifier(channel_id)
    assert decoded.id_type == IdType.CHANNEL
    assert decoded.data == test_key
    assert decoded.version == 0

    # Test user ID
    user_id = encode_user_id(test_key)
    print(f"  User ID: {user_id}")
    assert len(user_id) == 44
    decoded = decode_identifier(user_id)
    assert decoded.id_type == IdType.USER

    # Test message ID
    message_id = encode_message_id(test_hash)
    print(f"  Message ID: {message_id}")
    assert len(message_id) == 44
    decoded = decode_identifier(message_id)
    assert decoded.id_type == IdType.MESSAGE

    # Test blob ID
    blob_id = encode_blob_id(test_hash)
    print(f"  Blob ID: {blob_id}")
    assert len(blob_id) == 44
    decoded = decode_identifier(blob_id)
    assert decoded.id_type == IdType.BLOB

    print("  ✓ Basic encoding/decoding passed\n")


def test_extract_functions():
    """Test extraction of raw bytes from typed identifiers"""
    print("Testing extraction functions...")

    test_key = secrets.token_bytes(32)
    test_hash = secrets.token_bytes(32)

    # Test extracting public key
    channel_id = encode_channel_id(test_key)
    extracted_key = extract_public_key(channel_id)
    assert extracted_key == test_key
    print("  ✓ Public key extraction works")

    # Test extracting hash
    message_id = encode_message_id(test_hash)
    extracted_hash = extract_hash(message_id)
    assert extracted_hash == test_hash
    print("  ✓ Hash extraction works\n")


def test_type_validation():
    """Test that extraction functions validate types correctly"""
    print("Testing type validation...")

    test_key = secrets.token_bytes(32)
    test_hash = secrets.token_bytes(32)

    channel_id = encode_channel_id(test_key)
    message_id = encode_message_id(test_hash)

    # Should work
    extract_public_key(channel_id)

    # Should fail - message ID is not a public key type
    try:
        extract_public_key(message_id)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        print(f"  ✓ Correctly rejected wrong type: {e}")

    # Should work
    extract_hash(message_id)

    # Should fail - channel ID is not a hash type
    try:
        extract_hash(channel_id)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        print(f"  ✓ Correctly rejected wrong type: {e}\n")


def test_crypto_integration():
    """Test that CryptoUtils works with typed identifiers"""
    print("Testing crypto integration...")

    crypto = CryptoUtils()

    # Test blob ID computation
    test_data = b"Hello, World!"
    blob_id = crypto.compute_blob_id(test_data)
    print(f"  Blob ID: {blob_id}")
    assert len(blob_id) == 44

    # Verify it's the correct type
    decoded = decode_identifier(blob_id)
    assert decoded.id_type == IdType.BLOB
    print("  ✓ Blob ID computation works")

    # Test message hash computation
    channel_id = encode_channel_id(secrets.token_bytes(32))
    sender_id = encode_user_id(secrets.token_bytes(32))
    topic = "test-topic"
    payload = crypto.base64_encode(b"encrypted payload")

    message_hash = crypto.compute_message_hash(
        channel_id,
        topic,
        None,  # First message
        payload,
        sender_id
    )
    print(f"  Message hash: {message_hash}")
    assert len(message_hash) == 44

    decoded = decode_identifier(message_hash)
    assert decoded.id_type == IdType.MESSAGE
    print("  ✓ Message hash computation works\n")


def test_no_padding():
    """Verify that base64 encoding produces no padding"""
    print("Testing base64 padding...")

    # 33 bytes should encode to exactly 44 chars with no '=' padding
    test_data = secrets.token_bytes(32)
    channel_id = encode_channel_id(test_data)

    assert '=' not in channel_id, "Base64 should have no padding"
    assert len(channel_id) == 44
    print(f"  ✓ No padding in base64: {channel_id}\n")


def test_url_safe():
    """Verify that identifiers are URL-safe (no + or /)"""
    print("Testing URL-safe encoding...")

    # Generate many identifiers to increase chance of getting + or / if not URL-safe
    for _ in range(100):
        test_data = secrets.token_bytes(32)
        channel_id = encode_channel_id(test_data)
        user_id = encode_user_id(test_data)
        message_id = encode_message_id(test_data)
        blob_id = encode_blob_id(test_data)

        for identifier in [channel_id, user_id, message_id, blob_id]:
            assert '+' not in identifier, f"Found non-URL-safe '+' in {identifier}"
            assert '/' not in identifier, f"Found non-URL-safe '/' in {identifier}"
            # Should only contain A-Z, a-z, 0-9, -, _
            assert all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' for c in identifier)

    print("  ✓ All identifiers are URL-safe (using - and _ instead of + and /)\n")


def test_different_types_different_ids():
    """Verify that the same data produces different IDs for different types"""
    print("Testing type differentiation...")

    test_data = secrets.token_bytes(32)

    channel_id = encode_channel_id(test_data)
    user_id = encode_user_id(test_data)
    message_id = encode_message_id(test_data)
    blob_id = encode_blob_id(test_data)

    # All should be different despite same underlying data
    ids = {channel_id, user_id, message_id, blob_id}
    assert len(ids) == 4, "All typed IDs should be different"

    print(f"  Channel: {channel_id[:8]}...")
    print(f"  User:    {user_id[:8]}...")
    print(f"  Message: {message_id[:8]}...")
    print(f"  Blob:    {blob_id[:8]}...")
    print("  ✓ Different types produce different IDs\n")


def main():
    print("=" * 60)
    print("Typed Identifier Test Suite")
    print("=" * 60)
    print()

    test_basic_encoding_decoding()
    test_extract_functions()
    test_type_validation()
    test_crypto_integration()
    test_no_padding()
    test_url_safe()
    test_different_types_different_ids()

    print("=" * 60)
    print("All tests passed! ✓")
    print("=" * 60)


if __name__ == "__main__":
    main()
