"""
Authorization engine for capability-based access control

Implements:
- Capability loading and verification
- Path pattern matching with wildcards
- Permission checking (read/create/write)
- Capability subset validation (prevent privilege escalation)
"""

from typing import Optional, List, Dict, Any
from state_store import StateStore
from crypto import CryptoUtils
from identifiers import extract_public_key
from path_validation import validate_capability_path, PathValidationError
import fnmatch
import base64
import json


class AuthorizationEngine:
    """Capability-based authorization with signed permissions"""

    def __init__(self, state_store: StateStore, crypto: CryptoUtils):
        self.state_store = state_store
        self.crypto = crypto
    
    def check_permission(
        self,
        channel_id: str,
        user_public_key: str,
        operation: str,
        state_path: str
    ) -> bool:
        """
        Check if user has permission for an operation on a state path
        
        Args:
            channel_id: Channel identifier
            user_public_key: User's public key
            operation: 'read', 'create', or 'write'
            state_path: State path being accessed
        
        Returns:
            True if user has permission
        """
        # Channel creator (channel_id as public key) has god mode
        # Compare underlying public keys (channel and user IDs have different type prefixes)
        try:
            channel_pubkey = extract_public_key(channel_id)
            user_pubkey = extract_public_key(user_public_key)
            if channel_pubkey == user_pubkey:
                return True
        except ValueError:
            # If extraction fails, fall through to capability check
            pass
        
        # Load all capabilities for this user
        capabilities = self._load_user_capabilities(channel_id, user_public_key)

        # Check if any capability grants permission
        for cap in capabilities:
            if self._capability_grants_permission(cap, operation, state_path, user_public_key):
                return True

        return False
    
    def _load_user_capabilities(
        self,
        channel_id: str,
        user_public_key: str
    ) -> List[Dict[str, Any]]:
        """
        Load all capabilities for a user from state

        Capabilities are stored at state path:
        members/{public_key}/rights/{capability_id}

        Data is base64-encoded JSON, so we need to decode it.
        """
        prefix = f"members/{user_public_key}/rights/"
        capability_states = self.state_store.list_state(channel_id, prefix)

        capabilities = []
        for state in capability_states:
            # Decode base64 data and parse JSON
            try:
                decoded = base64.b64decode(state["data"])
                cap = json.loads(decoded)

                # Verify capability signature
                if self._verify_capability(channel_id, user_public_key, cap):
                    capabilities.append(cap)
            except Exception as e:
                # Skip invalid capability entries
                print(f"Failed to decode capability: {e}")
                continue

        return capabilities
    
    def _verify_capability(
        self,
        channel_id: str,
        recipient_public_key: str,
        capability: dict
    ) -> bool:
        """
        Verify that a capability is validly signed

        Args:
            channel_id: Typed channel identifier
            recipient_public_key: Typed user identifier receiving the capability
            capability: Capability dict with signature

        Returns:
            True if signature is valid
        """
        required_fields = ["op", "path", "granted_by", "granted_at", "signature"]
        if not all(field in capability for field in required_fields):
            return False

        try:
            signature = self.crypto.base64_decode(capability["signature"])
            # Extract raw public key from typed identifier
            granter_key = extract_public_key(capability["granted_by"])

            return self.crypto.verify_capability_signature(
                channel_id,
                recipient_public_key,
                capability,
                signature,
                granter_key
            )
        except Exception as e:
            print(f"Capability verification failed: {e}")
            return False
    
    def _capability_grants_permission(
        self,
        capability: dict,
        operation: str,
        state_path: str,
        user_public_key: Optional[str] = None
    ) -> bool:
        """
        Check if a capability grants permission for an operation on a path

        Args:
            capability: Capability dict with 'op' and 'path'
            operation: 'read', 'create', or 'write'
            state_path: State path being accessed
            user_public_key: User's public key for {self} wildcard resolution

        Returns:
            True if capability grants permission
        """
        cap_op = capability["op"]
        cap_path = capability["path"]

        # Check if path matches
        if not self._path_matches(cap_path, state_path, user_public_key):
            return False
        
        # Check if operation is allowed
        # write >= create > (nothing)
        # read is separate
        if cap_op == "write":
            # write grants both write and create
            return operation in ["read", "create", "write"]
        elif cap_op == "create":
            # create only grants create (not write to existing)
            return operation == "create"
        elif cap_op == "read":
            return operation == "read"
        
        return False
    
    def _path_matches(self, pattern: str, path: str, user_public_key: Optional[str] = None) -> bool:
        """
        Check if a path matches a pattern with wildcards

        Patterns:
        - {any} matches one path segment
        - {self} resolves to user_public_key
        - {other} matches any segment except user_public_key
        - Trailing '/' indicates prefix match

        Examples:
          pattern="members/{any}", path="members/alice", user="U_alice" → True
          pattern="profiles/{self}/", path="profiles/U_alice/", user="U_alice" → True
          pattern="profiles/{self}/", path="profiles/U_bob/", user="U_alice" → False
          pattern="members/", path="members/alice/rights/cap1" → True

        Args:
            pattern: Pattern with optional wildcards
            path: Path to match
            user_public_key: User's public key for {self} wildcard resolution

        Returns:
            True if path matches pattern
        """
        # Normalize paths - remove leading/trailing slashes
        pattern = pattern.strip('/')
        path = path.strip('/')

        # Handle empty pattern (matches everything)
        if pattern == '':
            return True

        # Split into segments
        pattern_parts = pattern.split('/')
        path_parts = path.split('/')

        # Pattern cannot have more segments than path
        if len(pattern_parts) > len(path_parts):
            return False

        # Check each segment in the pattern
        for i, pattern_part in enumerate(pattern_parts):
            if pattern_part == '{any}':
                # {any} wildcard matches any single segment
                continue
            elif pattern_part == '{self}':
                # {self} resolves to user's public key
                if user_public_key is None:
                    # Cannot match {self} without user context
                    return False
                if path_parts[i] != user_public_key:
                    return False
            elif pattern_part == '{other}':
                # {other} matches any segment EXCEPT user's public key
                if user_public_key is not None and path_parts[i] == user_public_key:
                    return False
                # Otherwise matches
                continue
            elif pattern_part != path_parts[i]:
                # Literal segment must match exactly
                return False

        # All pattern segments matched
        return True
    
    def is_capability_path(self, path: str) -> bool:
        """
        Check if a state path is for capability grants
        
        Capability paths: members/{public_key}/rights/{capability_id}
        """
        parts = path.strip('/').split('/')
        return (
            len(parts) >= 4 and
            parts[0] == 'members' and
            parts[2] == 'rights'
        )
    
    def verify_capability_grant(
        self,
        channel_id: str,
        path: str,
        capability_data: dict,
        granter_public_key: str,
        signature_b64: str
    ) -> bool:
        """
        Verify that a capability grant is valid

        Checks:
        1. Capability path pattern is valid (no unknown wildcards)
        2. Signature is valid
        3. Granter exists (or is channel_id)
        4. Granter has the capability they're trying to grant

        Args:
            channel_id: Typed channel identifier
            path: State path where capability is being stored
            capability_data: The capability being granted
            granter_public_key: Typed user identifier of granter
            signature_b64: Base64-encoded signature

        Returns:
            True if grant is valid
        """
        # Validate the capability path pattern
        capability_path = capability_data.get("path", "")
        try:
            validate_capability_path(capability_path)
        except PathValidationError as e:
            print(f"Invalid capability path pattern '{capability_path}': {e}")
            return False

        # Extract recipient public key from path
        # Path format: members/{recipient_key}/rights/{cap_id}
        parts = path.strip('/').split('/')
        if len(parts) < 2:
            return False

        recipient_key = parts[1]

        # Verify signature
        try:
            signature = self.crypto.base64_decode(signature_b64)
            # Extract raw public key from typed identifier
            granter_key_bytes = extract_public_key(granter_public_key)

            if not self.crypto.verify_capability_signature(
                channel_id,
                recipient_key,
                capability_data,
                signature,
                granter_key_bytes
            ):
                return False
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False
        
        # Channel creator can grant anything
        if granter_public_key == channel_id:
            return True
        
        # Load granter's capabilities
        granter_caps = self._load_user_capabilities(channel_id, granter_public_key)
        
        # Check if granter has permission to grant capabilities
        can_grant = False
        for cap in granter_caps:
            if self._capability_grants_permission(
                cap,
                "create",
                "members/{any}/rights/",
                granter_public_key
            ):
                can_grant = True
                break
        
        if not can_grant:
            return False
        
        # Check if granter has the capability they're trying to grant (subset check)
        return self._has_capability_superset(
            granter_caps,
            [capability_data]
        )
    
    def _has_capability_superset(
        self,
        granter_caps: List[dict],
        requested_caps: List[dict]
    ) -> bool:
        """
        Check if granter has a superset of the requested capabilities
        
        This prevents privilege escalation - you can't grant what you don't have.
        
        Args:
            granter_caps: Capabilities the granter has
            requested_caps: Capabilities being requested
        
        Returns:
            True if granter has all requested capabilities (or stronger)
        """
        for req_cap in requested_caps:
            req_op = req_cap["op"]
            req_path = req_cap["path"]
            
            # Check if granter has matching or stronger capability
            has_capability = False
            
            for grant_cap in granter_caps:
                grant_op = grant_cap["op"]
                grant_path = grant_cap["path"]
                
                # Path must match or be a superset
                # grant_path="/state/*" covers req_path="/state/members/"
                if not self._path_covers(grant_path, req_path):
                    continue
                
                # Operation must be equal or stronger
                if grant_op == "write":
                    # write covers everything
                    has_capability = True
                    break
                elif grant_op == "create" and req_op == "create":
                    has_capability = True
                    break
                elif grant_op == "read" and req_op == "read":
                    has_capability = True
                    break
            
            if not has_capability:
                return False
        
        return True
    
    def _path_covers(self, grant_path: str, req_path: str) -> bool:
        """
        Check if grant_path pattern covers (is more general than) req_path pattern

        This is pattern-to-pattern comparison for capability subset validation,
        NOT runtime path matching. We're checking if the granter's capability
        pattern subsumes the requested capability pattern.

        Wildcard subsumption rules:
        - {any} subsumes everything ({any}, {self}, {other}, literals)
        - {self} only subsumes {self}
        - {other} only subsumes {other}
        - Literals only subsume identical literals

        Examples:
          grant="profiles/{any}/" covers req="profiles/{self}/" → True
          grant="profiles/{self}/" covers req="profiles/{any}/" → False
          grant="members/" covers req="members/" → True
          grant="members/" covers req="topics/" → False
          grant="members/" covers req="members/alice/" → True (prefix)
        """
        # Exact match
        if grant_path == req_path:
            return True

        # Normalize
        grant_norm = grant_path.strip('/')
        req_norm = req_path.strip('/')

        # Split into segments
        grant_parts = grant_norm.split('/')
        req_parts = req_norm.split('/')

        # For prefix matching: grant must not have more segments than req
        # unless grant ends with trailing slash (which was stripped)
        if grant_path.endswith('/'):
            # Prefix match: grant_path covers any path starting with it
            if len(grant_parts) > len(req_parts):
                return False

            # Check each segment with wildcard subsumption
            for i, grant_seg in enumerate(grant_parts):
                req_seg = req_parts[i]
                if not self._wildcard_subsumes(grant_seg, req_seg):
                    return False
            return True
        else:
            # Exact match required (already checked above)
            return False

    def _wildcard_subsumes(self, granter_seg: str, requested_seg: str) -> bool:
        """
        Check if granter's path segment subsumes requested segment.

        {any} subsumes everything, otherwise must match exactly.
        """
        if granter_seg == '{any}':
            return True
        return granter_seg == requested_seg
