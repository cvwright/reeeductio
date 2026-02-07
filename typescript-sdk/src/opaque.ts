/**
 * OPAQUE password-based key recovery for reeeductio.
 *
 * OPAQUE is an asymmetric PAKE (Password Authenticated Key Exchange) protocol
 * that enables password-based login without exposing passwords or derived keys
 * to the server.
 *
 * Key design points:
 * - OPAQUE is for key recovery only, not authentication
 * - Ed25519 keypairs are randomly generated, not derived from passwords
 * - Password changes re-wrap the same keypair; public keys never change
 * - Credentials are wrapped using OPAQUE's export_key with HKDF + AES-GCM
 */

import * as opaque from '@serenity-kit/opaque';
import {
  deriveKey,
  encryptAesGcm,
  decryptAesGcm,
  encodeBase64,
  decodeBase64,
  concatBytes,
  stringToBytes,
  toUserId,
  generateKeyPair,
} from './crypto.js';
import { createApiError, OpaqueError } from './exceptions.js';
import type {
  ApiError,
  KeyPair,
  OpaqueRegisterInitResponse,
  OpaqueRegisterFinishResponse,
  OpaqueLoginInitResponse,
  OpaqueLoginFinishResponse,
  OpaqueUserRecord,
  OpaqueCredentials,
  OpaqueRegistrationResult,
} from './types.js';

/** Info string for HKDF when deriving credential wrapping key */
const CREDENTIAL_WRAP_INFO = 'reeeductio-credential-wrap';

// ============================================================
// Base64 Format Conversion Helpers
// ============================================================

/**
 * Convert URL-safe base64 (without padding) to standard base64 (with padding).
 * The @serenity-kit/opaque library uses URL-safe base64 without padding,
 * but the Python opaque_snake library expects standard base64 with padding.
 */
function urlSafeToStandardBase64(urlSafe: string): string {
  // Replace URL-safe characters with standard base64 characters
  let standard = urlSafe.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding if needed
  const padding = 4 - (standard.length % 4);
  if (padding !== 4) {
    standard += '='.repeat(padding);
  }
  return standard;
}

/**
 * Convert standard base64 (with padding) to URL-safe base64 (without padding).
 */
function standardToUrlSafeBase64(standard: string): string {
  // Remove padding and replace standard characters with URL-safe ones
  return standard.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

// ============================================================
// OPAQUE Setup Constants
// ============================================================

/** Data path for OPAQUE server setup */
export const OPAQUE_SERVER_SETUP_PATH = 'opaque/server/setup';

/** Role ID for users who can register OPAQUE credentials */
export const OPAQUE_USER_ROLE_ID = 'opaque-user';

/** Capability ID for creating OPAQUE user records */
export const OPAQUE_USER_CAP_ID = 'cap_create_opaque_user';

// ============================================================
// Credential Wrapping/Unwrapping
// ============================================================

/**
 * Wrap credentials (privateKey + symmetricRoot) using OPAQUE's export_key.
 *
 * @param exportKey - 64-byte export key from OPAQUE registration/login
 * @param privateKey - 32-byte Ed25519 private key
 * @param symmetricRoot - 32-byte symmetric root key
 * @returns Encrypted credentials blob (nonce + ciphertext + tag)
 */
export function wrapCredentials(
  exportKey: Uint8Array,
  privateKey: Uint8Array,
  symmetricRoot: Uint8Array
): Uint8Array {
  if (privateKey.length !== 32) {
    throw new OpaqueError(`Private key must be 32 bytes, got ${privateKey.length}`);
  }
  if (symmetricRoot.length !== 32) {
    throw new OpaqueError(`Symmetric root must be 32 bytes, got ${symmetricRoot.length}`);
  }

  // Derive wrapping key from export_key
  const wrapKey = deriveKey(exportKey, CREDENTIAL_WRAP_INFO);

  // Concatenate privateKey and symmetricRoot (64 bytes total)
  const plaintext = concatBytes(privateKey, symmetricRoot);

  // Encrypt with AES-256-GCM
  return encryptAesGcm(plaintext, wrapKey);
}

/**
 * Unwrap credentials using OPAQUE's export_key.
 *
 * @param exportKey - 64-byte export key from OPAQUE login
 * @param encryptedCredentials - Encrypted credentials blob
 * @returns Object with privateKey and symmetricRoot
 */
export function unwrapCredentials(
  exportKey: Uint8Array,
  encryptedCredentials: Uint8Array
): { privateKey: Uint8Array; symmetricRoot: Uint8Array } {
  // Derive wrapping key from export_key
  const wrapKey = deriveKey(exportKey, CREDENTIAL_WRAP_INFO);

  // Decrypt
  const plaintext = decryptAesGcm(encryptedCredentials, wrapKey);

  if (plaintext.length !== 64) {
    throw new OpaqueError(`Decrypted credentials must be 64 bytes, got ${plaintext.length}`);
  }

  return {
    privateKey: plaintext.slice(0, 32),
    symmetricRoot: plaintext.slice(32, 64),
  };
}

// ============================================================
// Low-level API Functions
// ============================================================

/**
 * Create OPAQUE server setup on the backend.
 *
 * This endpoint generates a new OPAQUE server setup using the opaque_snake
 * library on the backend. The client receives the base64-encoded setup bytes
 * and is responsible for signing and storing them via the /data API.
 *
 * @param fetchFn - Fetch implementation
 * @param baseUrl - API base URL
 * @param token - JWT bearer token (admin required)
 * @param spaceId - Space identifier
 * @returns OPAQUE server setup (base64-encoded)
 */
export async function createOpaqueSetup(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string
): Promise<string> {
  const url = `${baseUrl}/spaces/${spaceId}/opaque/setup`;

  const response = await fetchFn(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    let error: ApiError | undefined;
    try {
      error = (await response.json()) as ApiError;
    } catch {
      // Ignore JSON parse errors
    }
    throw createApiError(response.status, error);
  }

  const result = await response.json() as { server_setup: string };
  return result.server_setup;
}

/**
 * Start OPAQUE registration (step 1 of 2).
 *
 * @param fetchFn - Fetch implementation
 * @param baseUrl - API base URL
 * @param token - JWT bearer token (required for registration)
 * @param spaceId - Space identifier
 * @param username - Username to register
 * @param registrationRequest - OPAQUE RegistrationRequest (base64)
 * @returns OPAQUE RegistrationResponse (base64)
 */
export async function opaqueRegisterInit(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string,
  username: string,
  registrationRequest: string
): Promise<OpaqueRegisterInitResponse> {
  const url = `${baseUrl}/spaces/${spaceId}/opaque/register/init`;

  const response = await fetchFn(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify({
      username,
      registration_request: registrationRequest,
    }),
  });

  if (!response.ok) {
    let error: ApiError | undefined;
    try {
      error = (await response.json()) as ApiError;
    } catch {
      // Ignore JSON parse errors
    }
    throw createApiError(response.status, error);
  }

  return response.json() as Promise<OpaqueRegisterInitResponse>;
}

/**
 * Complete OPAQUE registration (step 2 of 2).
 *
 * @param fetchFn - Fetch implementation
 * @param baseUrl - API base URL
 * @param token - JWT bearer token (required for registration)
 * @param spaceId - Space identifier
 * @param username - Username (must match init)
 * @param registrationRecord - OPAQUE RegistrationRecord (base64)
 * @returns OPAQUE PasswordFile (base64)
 */
export async function opaqueRegisterFinish(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string,
  username: string,
  registrationRecord: string
): Promise<OpaqueRegisterFinishResponse> {
  const url = `${baseUrl}/spaces/${spaceId}/opaque/register/finish`;

  const response = await fetchFn(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify({
      username,
      registration_record: registrationRecord,
    }),
  });

  if (!response.ok) {
    let error: ApiError | undefined;
    try {
      error = (await response.json()) as ApiError;
    } catch {
      // Ignore JSON parse errors
    }
    throw createApiError(response.status, error);
  }

  return response.json() as Promise<OpaqueRegisterFinishResponse>;
}

/**
 * Start OPAQUE login (step 1 of 2).
 *
 * @param fetchFn - Fetch implementation
 * @param baseUrl - API base URL
 * @param spaceId - Space identifier
 * @param username - Username to log in
 * @param credentialRequest - OPAQUE CredentialRequest (base64)
 * @returns OPAQUE CredentialResponse (base64)
 */
export async function opaqueLoginInit(
  fetchFn: typeof fetch,
  baseUrl: string,
  spaceId: string,
  username: string,
  credentialRequest: string
): Promise<OpaqueLoginInitResponse> {
  const url = `${baseUrl}/spaces/${spaceId}/opaque/login/init`;

  const response = await fetchFn(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      username,
      credential_request: credentialRequest,
    }),
  });

  if (!response.ok) {
    let error: ApiError | undefined;
    try {
      error = (await response.json()) as ApiError;
    } catch {
      // Ignore JSON parse errors
    }
    throw createApiError(response.status, error);
  }

  return response.json() as Promise<OpaqueLoginInitResponse>;
}

/**
 * Complete OPAQUE login (step 2 of 2).
 *
 * @param fetchFn - Fetch implementation
 * @param baseUrl - API base URL
 * @param spaceId - Space identifier
 * @param username - Username (must match init)
 * @param credentialFinalization - OPAQUE CredentialFinalization (base64)
 * @returns Encrypted credentials and public key
 */
export async function opaqueLoginFinish(
  fetchFn: typeof fetch,
  baseUrl: string,
  spaceId: string,
  username: string,
  credentialFinalization: string
): Promise<OpaqueLoginFinishResponse> {
  const url = `${baseUrl}/spaces/${spaceId}/opaque/login/finish`;

  const response = await fetchFn(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      username,
      credential_finalization: credentialFinalization,
    }),
  });

  if (!response.ok) {
    let error: ApiError | undefined;
    try {
      error = (await response.json()) as ApiError;
    } catch {
      // Ignore JSON parse errors
    }
    throw createApiError(response.status, error);
  }

  return response.json() as Promise<OpaqueLoginFinishResponse>;
}

// ============================================================
// High-level Registration Flow
// ============================================================

/**
 * Perform full OPAQUE registration for a user.
 *
 * This function:
 * 1. Generates a new Ed25519 keypair (or uses provided one)
 * 2. Performs the OPAQUE registration protocol
 * 3. Wraps credentials with the export key
 * 4. Stores the OPAQUE record via the /data API
 *
 * @param options - Registration options
 * @returns Registration result with username and public key
 */
export async function performOpaqueRegistration(options: {
  fetchFn: typeof fetch;
  baseUrl: string;
  token: string;
  spaceId: string;
  username: string;
  password: string;
  /** Optional keypair to register (generates new one if not provided) */
  keyPair?: KeyPair;
  /** The 32-byte symmetric root for this space */
  symmetricRoot: Uint8Array;
  /** Signing key for storing the OPAQUE record */
  signingPrivateKey: Uint8Array;
  /** Public key of the signer (for signed_by field) */
  signerId: string;
}): Promise<OpaqueRegistrationResult> {
  const {
    fetchFn,
    baseUrl,
    token,
    spaceId,
    username,
    password,
    symmetricRoot,
    signingPrivateKey,
    signerId,
  } = options;

  // Generate keypair if not provided
  const keyPair = options.keyPair ?? await generateKeyPair();
  const publicKey = toUserId(keyPair.publicKey);

  // Step 1: Create client registration state
  const clientRegistration = opaque.client.startRegistration({ password });

  // Step 2: Send registration request to server
  // Convert from URL-safe base64 (client) to standard base64 (server)
  const initResponse = await opaqueRegisterInit(
    fetchFn,
    baseUrl,
    token,
    spaceId,
    username,
    urlSafeToStandardBase64(clientRegistration.registrationRequest)
  );

  // Step 3: Finish registration on client side
  // Convert server response from standard base64 to URL-safe for client library
  const registrationResult = opaque.client.finishRegistration({
    password,
    registrationResponse: standardToUrlSafeBase64(initResponse.registration_response),
    clientRegistrationState: clientRegistration.clientRegistrationState,
  });

  // Step 4: Send registration record to server
  // Convert from URL-safe base64 (client) to standard base64 (server)
  const finishResponse = await opaqueRegisterFinish(
    fetchFn,
    baseUrl,
    token,
    spaceId,
    username,
    urlSafeToStandardBase64(registrationResult.registrationRecord)
  );

  // Step 5: Wrap credentials with export key
  // The export key from the client library is URL-safe base64
  const exportKey = decodeBase64(urlSafeToStandardBase64(registrationResult.exportKey));
  const encryptedCredentials = wrapCredentials(
    exportKey,
    keyPair.privateKey,
    symmetricRoot
  );

  // Step 6: Create OPAQUE user record
  const record: OpaqueUserRecord = {
    password_file: finishResponse.password_file,
    encrypted_credentials: encodeBase64(encryptedCredentials),
    public_key: publicKey,
  };

  // Step 7: Store via /data API (signed by the registering user)
  const recordJson = JSON.stringify(record);
  const recordData = stringToBytes(recordJson);

  // Import setData function dynamically to avoid circular dependency
  const { setData } = await import('./kvdata.js');

  await setData(
    fetchFn,
    baseUrl,
    token,
    spaceId,
    `opaque/users/${username}`,
    recordData,
    signerId,
    signingPrivateKey
  );

  return {
    username,
    publicKey,
  };
}

// ============================================================
// High-level Login Flow
// ============================================================

/**
 * Perform full OPAQUE login to recover credentials.
 *
 * This function:
 * 1. Performs the OPAQUE login protocol
 * 2. Unwraps credentials with the export key
 * 3. Returns the recovered keypair and symmetric root
 *
 * After calling this, use the recovered credentials to authenticate
 * via the standard Ed25519 challenge-response flow.
 *
 * @param options - Login options
 * @returns Recovered credentials (privateKey, symmetricRoot, publicKey)
 */
export async function performOpaqueLogin(options: {
  fetchFn: typeof fetch;
  baseUrl: string;
  spaceId: string;
  username: string;
  password: string;
}): Promise<OpaqueCredentials> {
  const { fetchFn, baseUrl, spaceId, username, password } = options;

  // Step 1: Create client login state
  const clientLogin = opaque.client.startLogin({ password });

  // Step 2: Send credential request to server
  // Convert from URL-safe base64 (client) to standard base64 (server)
  const initResponse = await opaqueLoginInit(
    fetchFn,
    baseUrl,
    spaceId,
    username,
    urlSafeToStandardBase64(clientLogin.startLoginRequest)
  );

  // Step 3: Finish login on client side
  // Convert server response from standard base64 to URL-safe for client library
  const loginResult = opaque.client.finishLogin({
    password,
    loginResponse: standardToUrlSafeBase64(initResponse.credential_response),
    clientLoginState: clientLogin.clientLoginState,
  });

  if (!loginResult) {
    throw new OpaqueError('OPAQUE login failed: invalid password or protocol error');
  }

  // Step 4: Send credential finalization to server
  // Convert from URL-safe base64 (client) to standard base64 (server)
  const finishResponse = await opaqueLoginFinish(
    fetchFn,
    baseUrl,
    spaceId,
    username,
    urlSafeToStandardBase64(loginResult.finishLoginRequest)
  );

  // Step 5: Unwrap credentials with export key
  // The export key from the client library is URL-safe base64
  const exportKey = decodeBase64(urlSafeToStandardBase64(loginResult.exportKey));
  const encryptedCredentials = decodeBase64(finishResponse.encrypted_credentials);

  const { privateKey, symmetricRoot } = unwrapCredentials(exportKey, encryptedCredentials);

  return {
    privateKey,
    symmetricRoot,
    publicKey: finishResponse.public_key,
  };
}

/**
 * Login with OPAQUE and create a Space client.
 *
 * This is a convenience function that performs OPAQUE login, recovers
 * credentials, and returns a fully initialized Space client.
 *
 * @param options - Login options
 * @returns A Space client authenticated with the recovered credentials
 */
export async function loginWithOpaque(options: {
  baseUrl: string;
  spaceId: string;
  username: string;
  password: string;
  fetch?: typeof fetch;
}): Promise<{
  credentials: OpaqueCredentials;
  keyPair: KeyPair;
}> {
  const fetchFn = options.fetch ?? fetch;

  const credentials = await performOpaqueLogin({
    fetchFn,
    baseUrl: options.baseUrl,
    spaceId: options.spaceId,
    username: options.username,
    password: options.password,
  });

  // Reconstruct keypair from recovered private key
  // The public key is verified against the one returned by the server
  const { extractPublicKey } = await import('./crypto.js');
  const expectedPublicKey = extractPublicKey(credentials.publicKey);

  // Derive public key from private key to verify
  const ed = await import('@noble/ed25519');
  const derivedPublicKey = await ed.getPublicKeyAsync(credentials.privateKey);

  // Verify the public key matches
  if (derivedPublicKey.length !== expectedPublicKey.length ||
      !derivedPublicKey.every((v, i) => v === expectedPublicKey[i])) {
    throw new OpaqueError('Public key mismatch: recovered credentials do not match server record');
  }

  const keyPair: KeyPair = {
    privateKey: credentials.privateKey,
    publicKey: derivedPublicKey,
  };

  return { credentials, keyPair };
}
