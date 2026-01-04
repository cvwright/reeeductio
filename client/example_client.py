#!/usr/bin/env python3
"""
Example client for E2EE messaging system

Demonstrates:
- Space creation (offline)
- User authentication
- Capability management
- Message posting and retrieval
"""

import base64
import hashlib
import json
import time
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


class Ed25519KeyPair:
    """Wrapper for Ed25519 keypair"""
    
    def __init__(self, private_key: Optional[ed25519.Ed25519PrivateKey] = None):
        if private_key is None:
            self.private_key = ed25519.Ed25519PrivateKey.generate()
        else:
            self.private_key = private_key
        
        self.public_key = self.private_key.public_key()
    
    def public_key_bytes(self) -> bytes:
        """Get raw public key bytes"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def public_key_b64(self) -> str:
        """Get base64-encoded public key"""
        return base64.b64encode(self.public_key_bytes()).decode('utf-8')
    
    def sign(self, message: bytes) -> bytes:
        """Sign a message"""
        return self.private_key.sign(message)
    
    def sign_b64(self, message: bytes) -> str:
        """Sign and return base64-encoded signature"""
        return base64.b64encode(self.sign(message)).decode('utf-8')


class SpaceBootstrap:
    """Bootstrap a new space with initial state"""
    
    def __init__(self):
        # Generate space keypair
        self.space_keypair = Ed25519KeyPair()
        self.space_id = self.space_keypair.public_key_b64()
        
        # Generate symmetric key for message encryption
        import secrets
        self.symmetric_key = secrets.token_bytes(32)
        self.symmetric_key_b64 = base64.b64encode(self.symmetric_key).decode('utf-8')
        
        # Generate join keypair
        self.join_keypair = Ed25519KeyPair()
        
        print(f"Space created!")
        print(f"Space ID: {self.space_id}")
        print(f"Symmetric Key: {self.symmetric_key_b64}")
        print(f"Join Key Public: {self.join_keypair.public_key_b64()}")
    
    def create_member_state(self, public_key: str) -> dict:
        """Create member state object"""
        return {
            "public_key": public_key,
            "added_at": int(time.time() * 1000),  # milliseconds
            "added_by": self.space_id
        }
    
    def create_capability(
        self,
        recipient_public_key: str,
        op: str,
        path: str,
        granter_keypair: Ed25519KeyPair
    ) -> dict:
        """Create a signed capability"""
        granted_at = int(time.time() * 1000)  # milliseconds
        
        # Construct message to sign
        message = (
            f"{self.space_id}|{recipient_public_key}|"
            f"{op}|{path}|{granted_at}"
        )
        
        signature = granter_keypair.sign_b64(message.encode('utf-8'))
        
        return {
            "op": op,
            "path": path,
            "granted_by": granter_keypair.public_key_b64(),
            "granted_at": granted_at,
            "signature": signature
        }
    
    def generate_initial_state(self) -> dict:
        """
        Generate initial space state to be uploaded to server
        
        This would normally be done via API calls, but we're showing
        the structure here for educational purposes.
        """
        # Add space creator as member
        creator_member = self.create_member_state(self.space_id)
        
        # Grant space creator admin rights
        creator_admin_cap = self.create_capability(
            self.space_id,
            "write",
            "/state/*",
            self.space_keypair
        )
        
        # Add join key as member
        join_member = self.create_member_state(self.join_keypair.public_key_b64())
        
        # Grant join key ability to add members
        join_add_member_cap = self.create_capability(
            self.join_keypair.public_key_b64(),
            "create",
            "/state/members/",
            self.space_keypair
        )
        
        # Grant join key ability to grant basic capabilities
        join_grant_cap = self.create_capability(
            self.join_keypair.public_key_b64(),
            "create",
            "/state/members/*/rights/",
            self.space_keypair
        )
        
        # Also grant join key the capabilities it will grant to new members
        # (so subset check passes)
        join_read_cap = self.create_capability(
            self.join_keypair.public_key_b64(),
            "read",
            "/state/*",
            self.space_keypair
        )
        
        join_post_cap = self.create_capability(
            self.join_keypair.public_key_b64(),
            "create",
            "/state/topics/*/messages/",
            self.space_keypair
        )
        
        return {
            "members": {
                self.space_id: creator_member,
                self.join_keypair.public_key_b64(): join_member
            },
            "capabilities": {
                "creator_admin": creator_admin_cap,
                "join_add_member": join_add_member_cap,
                "join_grant_caps": join_grant_cap,
                "join_read": join_read_cap,
                "join_post": join_post_cap
            }
        }
    
    def generate_qr_data(self) -> dict:
        """Generate data to encode in QR code for joining"""
        return {
            "space_id": self.space_id,
            "symmetric_key": self.symmetric_key_b64,
            "join_private_key": base64.b64encode(
                self.join_keypair.private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )
            ).decode('utf-8')
        }


class MessageClient:
    """Client for posting and reading messages"""
    
    def __init__(self, space_id: str, symmetric_key: bytes):
        self.space_id = space_id
        self.symmetric_key = symmetric_key
    
    def compute_message_hash(
        self,
        topic_id: str,
        prev_hash: Optional[str],
        encrypted_payload: str,
        sender: str
    ) -> str:
        """Compute message hash (must match server's computation)"""
        prev_hash_str = prev_hash if prev_hash else "null"

        message_data = (
            f"{self.space_id}|{topic_id}|{prev_hash_str}|{encrypted_payload}|{sender}"
        )

        hash_bytes = hashlib.sha256(message_data.encode('utf-8')).digest()
        return hash_bytes.hex()
    
    def encrypt_message(self, plaintext: str) -> str:
        """
        Encrypt message with space symmetric key
        
        Note: This is a simplified example. In production, use proper
        authenticated encryption (e.g., AES-GCM) and derive per-message
        keys from the space key + message context.
        """
        # For demo purposes, just base64 encode
        # In production: use AES-GCM or ChaCha20-Poly1305
        return base64.b64encode(plaintext.encode('utf-8')).decode('utf-8')
    
    def decrypt_message(self, encrypted_payload: str) -> str:
        """Decrypt message"""
        # For demo purposes
        return base64.b64decode(encrypted_payload).decode('utf-8')
    
    def create_message(
        self,
        keypair: Ed25519KeyPair,
        topic_id: str,
        content: str,
        prev_hash: Optional[str]
    ) -> dict:
        """Create a message ready to post"""
        encrypted_payload = self.encrypt_message(content)
        sender = keypair.public_key_b64()

        message_hash = self.compute_message_hash(
            topic_id,
            prev_hash,
            encrypted_payload,
            sender
        )

        # Sign the message hash
        signature = keypair.sign_b64(bytes.fromhex(message_hash))

        return {
            "prev_hash": prev_hash,
            "encrypted_payload": encrypted_payload,
            "message_hash": message_hash,
            "signature": signature
        }


def example_bootstrap():
    """Example: Bootstrap a new space"""
    print("=" * 60)
    print("EXAMPLE: Space Bootstrap")
    print("=" * 60)
    
    # Create space
    space = SpaceBootstrap()
    
    # Generate initial state
    initial_state = space.generate_initial_state()
    print("\nInitial state structure:")
    print(json.dumps(initial_state, indent=2))
    
    # Generate QR code data
    qr_data = space.generate_qr_data()
    print("\nQR Code data (share this to invite users):")
    print(json.dumps(qr_data, indent=2))
    
    return space


def example_join_space(qr_data: dict):
    """Example: Join a space using QR code data"""
    print("\n" + "=" * 60)
    print("EXAMPLE: Joining Space")
    print("=" * 60)
    
    space_id = qr_data["space_id"]
    symmetric_key = base64.b64decode(qr_data["symmetric_key"])
    join_private_key_bytes = base64.b64decode(qr_data["join_private_key"])
    
    # Recreate join keypair
    join_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
        join_private_key_bytes
    )
    join_keypair = Ed25519KeyPair(join_private_key)
    
    # Generate personal keypair
    personal_keypair = Ed25519KeyPair()
    print(f"Generated personal keypair")
    print(f"Public key: {personal_keypair.public_key_b64()}")
    
    # Create member state (to be uploaded to server)
    member_state = {
        "public_key": personal_keypair.public_key_b64(),
        "added_at": int(time.time() * 1000),  # milliseconds
        "added_by": join_keypair.public_key_b64()
    }

    print(f"\nMember state to upload:")
    print(json.dumps(member_state, indent=2))

    # Create capabilities for new member (signed by join key)
    now = int(time.time() * 1000)  # milliseconds
    
    # Read capability
    read_cap_message = (
        f"{space_id}|{personal_keypair.public_key_b64()}|"
        f"read|*|{now}"
    )
    read_cap = {
        "op": "read",
        "path": "*",
        "granted_by": join_keypair.public_key_b64(),
        "granted_at": now,
        "signature": join_keypair.sign_b64(read_cap_message.encode('utf-8'))
    }

    # Post messages capability
    post_cap_message = (
        f"{space_id}|{personal_keypair.public_key_b64()}|"
        f"create|topics/*/messages/|{now}"
    )
    post_cap = {
        "op": "create",
        "path": "topics/*/messages/",
        "granted_by": join_keypair.public_key_b64(),
        "granted_at": now,
        "signature": join_keypair.sign_b64(post_cap_message.encode('utf-8'))
    }
    
    print(f"\nCapabilities to upload:")
    print(json.dumps({"read": read_cap, "post": post_cap}, indent=2))
    
    return personal_keypair, space_id, symmetric_key


def example_post_message(
    keypair: Ed25519KeyPair,
    space_id: str,
    symmetric_key: bytes
):
    """Example: Post a message to a topic"""
    print("\n" + "=" * 60)
    print("EXAMPLE: Posting Message")
    print("=" * 60)
    
    client = MessageClient(space_id, symmetric_key)

    # Create first message
    message1 = client.create_message(
        keypair=keypair,
        topic_id="general",
        content="Hello, world!",
        prev_hash=None
    )

    print("First message:")
    print(json.dumps(message1, indent=2))

    # Create second message (links to first)
    message2 = client.create_message(
        keypair=keypair,
        topic_id="general",
        content="This is the second message",
        prev_hash=message1["message_hash"]
    )
    
    print("\nSecond message:")
    print(json.dumps(message2, indent=2))
    
    # Decrypt to verify
    print(f"\nDecrypted content 1: {client.decrypt_message(message1['encrypted_payload'])}")
    print(f"Decrypted content 2: {client.decrypt_message(message2['encrypted_payload'])}")


if __name__ == "__main__":
    # Run examples
    space = example_bootstrap()
    qr_data = space.generate_qr_data()
    
    personal_keypair, space_id, symmetric_key = example_join_space(qr_data)
    
    example_post_message(personal_keypair, space_id, symmetric_key)
    
    print("\n" + "=" * 60)
    print("Examples complete!")
    print("=" * 60)
    print("\nIn a real application, you would:")
    print("1. Upload initial state to server via PUT /state/* endpoints")
    print("2. Use POST /auth/challenge and /auth/verify for authentication")
    print("3. Use POST /messages endpoint to publish messages")
    print("4. Use GET /messages to retrieve message history")
