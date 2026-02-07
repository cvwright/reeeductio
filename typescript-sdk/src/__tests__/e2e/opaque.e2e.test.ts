/**
 * E2E tests for OPAQUE password-based key recovery.
 *
 * Run with: npm run test:e2e
 * Requires: docker-compose -f backend/docker-compose.e2e.yml up -d
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { Space } from '../../client.js';
import { generateKeyPair, toSpaceId, toUserId, bytesToString } from '../../crypto.js';
import {
  OPAQUE_SERVER_SETUP_PATH,
  OPAQUE_USER_ROLE_ID,
  OPAQUE_USER_CAP_ID,
} from '../../opaque.js';
import { E2E_BACKEND_URL, waitForBackend, randomUsername } from './setup.js';

describe('E2E: OPAQUE', () => {
  beforeAll(async () => {
    await waitForBackend();
  }, 60000);

  describe('enableOpaque', () => {
    it('should create server setup, role, and capability on first call', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(1);

      const space = new Space({
        spaceId,
        keyPair,
        symmetricRoot,
        baseUrl: E2E_BACKEND_URL,
      });

      // Enable OPAQUE
      const result = await space.enableOpaque();

      expect(result.serverSetupCreated).toBe(true);
      expect(result.roleCreated).toBe(true);
      expect(result.capabilityCreated).toBe(true);

      // Verify server setup was stored
      const serverSetup = await space.getPlaintextData(OPAQUE_SERVER_SETUP_PATH);
      expect(serverSetup).toBeInstanceOf(Uint8Array);
      expect(serverSetup.length).toBeGreaterThan(0);

      // Verify role was created
      const roleData = await space.getPlaintextState(`auth/roles/${OPAQUE_USER_ROLE_ID}`);
      const role = JSON.parse(bytesToString(roleData));
      expect(role.role_id).toBe(OPAQUE_USER_ROLE_ID);

      // Verify capability was created
      const capData = await space.getPlaintextState(
        `auth/roles/${OPAQUE_USER_ROLE_ID}/rights/${OPAQUE_USER_CAP_ID}`
      );
      const cap = JSON.parse(bytesToString(capData));
      expect(cap.op).toBe('create');
      expect(cap.path).toBe('data/opaque/users/{any}');
    });

    it('should be idempotent on second call', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(2);

      const space = new Space({
        spaceId,
        keyPair,
        symmetricRoot,
        baseUrl: E2E_BACKEND_URL,
      });

      // First call - should create everything
      const result1 = await space.enableOpaque();
      expect(result1.serverSetupCreated).toBe(true);
      expect(result1.roleCreated).toBe(true);
      expect(result1.capabilityCreated).toBe(true);

      // Second call - should find everything already exists
      const result2 = await space.enableOpaque();
      expect(result2.serverSetupCreated).toBe(false);
      expect(result2.roleCreated).toBe(false);
      expect(result2.capabilityCreated).toBe(false);
    });
  });

  describe('OPAQUE registration and login', () => {
    it('should register and login with OPAQUE credentials', async () => {

      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32);
      // Fill with random bytes for a realistic symmetric root
      for (let i = 0; i < 32; i++) {
        symmetricRoot[i] = Math.floor(Math.random() * 256);
      }

      const space = new Space({
        spaceId,
        keyPair,
        symmetricRoot,
        baseUrl: E2E_BACKEND_URL,
      });

      // Enable OPAQUE first
      await space.enableOpaque();

      // Register OPAQUE credentials
      const username = randomUsername();
      const password = 'test-password-123!';

      const regResult = await space.opaqueRegister(username, password);

      expect(regResult.username).toBe(username);
      expect(regResult.publicKey).toBe(toUserId(keyPair.publicKey));

      // Now login with OPAQUE to recover credentials
      const recoveredSpace = await Space.fromOpaqueLogin({
        baseUrl: E2E_BACKEND_URL,
        spaceId,
        username,
        password,
      });

      // Verify the recovered space has the same credentials
      expect(recoveredSpace.getUserId()).toBe(space.getUserId());

      // Verify the recovered space can perform operations
      // Set some state with the recovered space
      const testPath = `test/opaque/${Date.now()}`;
      const testData = new TextEncoder().encode('Hello from recovered space!');
      await recoveredSpace.setPlaintextState(testPath, testData);

      // Read it back
      const retrieved = await recoveredSpace.getPlaintextState(testPath);
      expect(new TextDecoder().decode(retrieved)).toBe('Hello from recovered space!');
    });

    it('should register a new keypair with opaqueRegisterNewKeypair', async () => {
      const adminKeyPair = await generateKeyPair();
      const spaceId = toSpaceId(adminKeyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(4);

      const adminSpace = new Space({
        spaceId,
        keyPair: adminKeyPair,
        symmetricRoot,
        baseUrl: E2E_BACKEND_URL,
      });

      // Enable OPAQUE
      await adminSpace.enableOpaque();

      // Register a new keypair (e.g., for a tool or invited user)
      const username = randomUsername();
      const password = 'new-user-password-456!';

      const { keyPair: newKeyPair, result } = await adminSpace.opaqueRegisterNewKeypair(
        username,
        password
      );

      expect(result.username).toBe(username);
      expect(result.publicKey).toBe(toUserId(newKeyPair.publicKey));

      // The new user should be able to login with OPAQUE
      const newUserSpace = await Space.fromOpaqueLogin({
        baseUrl: E2E_BACKEND_URL,
        spaceId,
        username,
        password,
      });

      expect(newUserSpace.getUserId()).toBe(toUserId(newKeyPair.publicKey));
    });

    it('should fail login with wrong password', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(5);

      const space = new Space({
        spaceId,
        keyPair,
        symmetricRoot,
        baseUrl: E2E_BACKEND_URL,
      });

      // Enable OPAQUE and register
      await space.enableOpaque();

      const username = randomUsername();
      const password = 'correct-password';

      await space.opaqueRegister(username, password);

      // Try to login with wrong password
      await expect(
        Space.fromOpaqueLogin({
          baseUrl: E2E_BACKEND_URL,
          spaceId,
          username,
          password: 'wrong-password',
        })
      ).rejects.toThrow();
    });

    it('should fail login with non-existent username', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(6);

      const space = new Space({
        spaceId,
        keyPair,
        symmetricRoot,
        baseUrl: E2E_BACKEND_URL,
      });

      // Enable OPAQUE (but don't register any user)
      await space.enableOpaque();

      // Try to login with non-existent username
      await expect(
        Space.fromOpaqueLogin({
          baseUrl: E2E_BACKEND_URL,
          spaceId,
          username: 'non-existent-user',
          password: 'any-password',
        })
      ).rejects.toThrow();
    });
  });

  describe('authorization utilities', () => {
    it('should create and manage roles', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(7);

      const space = new Space({
        spaceId,
        keyPair,
        symmetricRoot,
        baseUrl: E2E_BACKEND_URL,
      });

      // Create a role
      const roleName = `test-role-${Date.now()}`;
      const result = await space.createRole(roleName, 'Test role description');

      expect(result.message_hash).toBeDefined();
      expect(result.message_hash[0]).toBe('M');

      // Verify the role was created
      const roleData = await space.getPlaintextState(`auth/roles/${roleName}`);
      const role = JSON.parse(bytesToString(roleData));
      expect(role.role_id).toBe(roleName);
      expect(role.description).toBe('Test role description');
    });

    it('should create and manage users', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(8);

      const space = new Space({
        spaceId,
        keyPair,
        symmetricRoot,
        baseUrl: E2E_BACKEND_URL,
      });

      // Create a user entry
      const userId = toUserId(keyPair.publicKey);
      const result = await space.createUser(userId, 'Test user');

      expect(result.message_hash).toBeDefined();

      // Verify the user was created
      const userData = await space.getPlaintextState(`auth/users/${userId}`);
      const user = JSON.parse(bytesToString(userData));
      expect(user.user_id).toBe(userId);
      expect(user.description).toBe('Test user');
    });

    it('should grant capabilities to roles', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(9);

      const space = new Space({
        spaceId,
        keyPair,
        symmetricRoot,
        baseUrl: E2E_BACKEND_URL,
      });

      // Create a role
      const roleName = `cap-test-role-${Date.now()}`;
      await space.createRole(roleName);

      // Grant a capability to the role
      await space.grantCapabilityToRole(roleName, 'read_all', {
        op: 'read',
        path: 'state/{...}',
      });

      // Verify the capability was granted
      const capData = await space.getPlaintextState(
        `auth/roles/${roleName}/rights/read_all`
      );
      const cap = JSON.parse(bytesToString(capData));
      expect(cap.op).toBe('read');
      expect(cap.path).toBe('state/{...}');
    });

    it('should assign roles to users', async () => {
      const keyPair = await generateKeyPair();
      const spaceId = toSpaceId(keyPair.publicKey);
      const symmetricRoot = new Uint8Array(32).fill(10);

      const space = new Space({
        spaceId,
        keyPair,
        symmetricRoot,
        baseUrl: E2E_BACKEND_URL,
      });

      // Create a role
      const roleName = `assign-test-role-${Date.now()}`;
      await space.createRole(roleName);

      // Create a user
      const userId = toUserId(keyPair.publicKey);
      await space.createUser(userId);

      // Assign the role to the user
      await space.assignRoleToUser(userId, roleName);

      // Verify the role was assigned
      const roleAssignment = await space.getPlaintextState(
        `auth/users/${userId}/roles/${roleName}`
      );
      const assignment = JSON.parse(bytesToString(roleAssignment));
      expect(assignment.role_id).toBe(roleName);
    });
  });
});
