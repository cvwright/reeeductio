/**
 * Simple key-value data store helpers for reeeductio.
 *
 * Provides utilities for reading and writing signed data entries.
 */

import {
  signData,
  encodeBase64,
  stringToBytes,
  concatBytes,
} from './crypto.js';
import type {
  DataEntry,
  DataSetResponse,
  ApiError,
} from './types.js';
import { createApiError, NotFoundError } from './exceptions.js';

/**
 * Compute signature for data entry.
 *
 * Signature is over: space_id|path|data|signed_at
 *
 * @param spaceId - Typed space identifier
 * @param path - Data path
 * @param data - Data bytes
 * @param signedAt - Unix timestamp in milliseconds
 * @param privateKey - Signer's Ed25519 private key
 * @returns 64-byte signature
 */
export async function computeDataSignature(
  spaceId: string,
  path: string,
  data: Uint8Array,
  signedAt: number,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  // Signature is over: space_id|path|data|signed_at
  const prefix = stringToBytes(`${spaceId}|${path}|`);
  const suffix = stringToBytes(`|${signedAt}`);
  const sigInput = concatBytes(prefix, data, suffix);
  return signData(sigInput, privateKey);
}

/**
 * Get data value at path.
 *
 * @param fetchFn - Fetch function
 * @param baseUrl - API base URL
 * @param token - JWT bearer token
 * @param spaceId - Typed space identifier
 * @param path - Data path (e.g., "profiles/alice", "settings/theme")
 * @returns DataEntry with the stored data
 */
export async function getData(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string,
  path: string
): Promise<DataEntry> {
  const url = `${baseUrl}/spaces/${spaceId}/data/${path}`;

  const response = await fetchFn(url, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    if (response.status === 404) {
      throw new NotFoundError(`No data found at path: ${path}`);
    }
    const error = await parseError(response);
    throw createApiError(response.status, error);
  }

  return (await response.json()) as DataEntry;
}

/**
 * Set data value at path with cryptographic signature.
 *
 * @param fetchFn - Fetch function
 * @param baseUrl - API base URL
 * @param token - JWT bearer token
 * @param spaceId - Typed space identifier
 * @param path - Data path
 * @param data - Data to store
 * @param signedBy - Typed user/tool identifier of signer
 * @param privateKey - Signer's Ed25519 private key
 * @returns DataSetResponse with the path and timestamp
 */
export async function setData(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string,
  path: string,
  data: Uint8Array,
  signedBy: string,
  privateKey: Uint8Array
): Promise<DataSetResponse> {
  // Current timestamp in milliseconds
  const signedAt = Date.now();

  // Compute signature
  const signature = await computeDataSignature(
    spaceId,
    path,
    data,
    signedAt,
    privateKey
  );

  // Create request body
  const body = {
    data: encodeBase64(data),
    signature: encodeBase64(signature),
    signed_by: signedBy,
    signed_at: signedAt,
  };

  const url = `${baseUrl}/spaces/${spaceId}/data/${path}`;
  const response = await fetchFn(url, {
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const error = await parseError(response);
    throw createApiError(response.status, error);
  }

  return (await response.json()) as DataSetResponse;
}

/**
 * Parse error response from API.
 */
async function parseError(response: Response): Promise<ApiError | undefined> {
  try {
    return (await response.json()) as ApiError;
  } catch {
    return undefined;
  }
}
