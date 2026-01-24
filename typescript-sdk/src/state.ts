/**
 * State management helpers for reeeductio.
 *
 * State is stored as messages in the "state" topic with paths in the type field.
 * This module provides helpers for reading and writing state.
 */

import { postMessage } from './messages.js';
import type {
  Message,
  MessageCreated,
  MessageQuery,
  MessagesResponse,
  ApiError,
} from './types.js';
import { createApiError, NotFoundError } from './exceptions.js';

/**
 * Get current state value at path.
 *
 * The server computes this by replaying state messages to find the latest value.
 *
 * @param fetchFn - Fetch function
 * @param baseUrl - API base URL
 * @param token - JWT bearer token
 * @param spaceId - Typed space identifier
 * @param path - State path (e.g., "auth/users/U_abc123", "profiles/alice")
 * @returns Message containing the current state at this path
 */
export async function getState(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string,
  path: string
): Promise<Message> {
  const url = `${baseUrl}/spaces/${spaceId}/state/${path}`;

  const response = await fetchFn(url, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    if (response.status === 404) {
      throw new NotFoundError(`No state found at path: ${path}`);
    }
    const error = await parseError(response);
    throw createApiError(response.status, error);
  }

  return (await response.json()) as Message;
}

/**
 * Set state value at path by posting a message to the "state" topic.
 *
 * State changes are stored as messages with the path in the type field.
 *
 * @param fetchFn - Fetch function
 * @param baseUrl - API base URL
 * @param token - JWT bearer token
 * @param spaceId - Typed space identifier
 * @param path - State path (becomes the message type field)
 * @param data - Encrypted state data
 * @param prevHash - Hash of previous message in state topic (null for first message)
 * @param senderPublicKeyTyped - Typed sender public key
 * @param senderPrivateKey - Sender's private key for signing
 * @returns MessageCreated with message_hash and server_timestamp
 */
export async function setState(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string,
  path: string,
  data: Uint8Array,
  prevHash: string | null,
  senderPublicKeyTyped: string,
  senderPrivateKey: Uint8Array
): Promise<MessageCreated> {
  return postMessage(
    fetchFn,
    baseUrl,
    token,
    spaceId,
    'state',  // State is stored in the "state" topic
    path,     // Path becomes the message type
    data,
    prevHash,
    senderPublicKeyTyped,
    senderPrivateKey
  );
}

/**
 * Get all state change messages (the event log).
 *
 * This retrieves messages from the "state" topic.
 *
 * @param fetchFn - Fetch function
 * @param baseUrl - API base URL
 * @param token - JWT bearer token
 * @param spaceId - Typed space identifier
 * @param query - Optional query parameters (from, to, limit)
 * @returns List of state change messages
 */
export async function getStateHistory(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string,
  query?: MessageQuery
): Promise<MessagesResponse> {
  const params = new URLSearchParams();
  if (query?.from !== undefined) {
    params.set('from', query.from.toString());
  }
  if (query?.to !== undefined) {
    params.set('to', query.to.toString());
  }
  if (query?.limit !== undefined) {
    params.set('limit', query.limit.toString());
  }

  const queryString = params.toString();
  const url = `${baseUrl}/spaces/${spaceId}/state${queryString ? `?${queryString}` : ''}`;

  const response = await fetchFn(url, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    const error = await parseError(response);
    throw createApiError(response.status, error);
  }

  return (await response.json()) as MessagesResponse;
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
