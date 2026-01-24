/**
 * Message handling helpers for reeeductio.
 *
 * Provides utilities for message hash computation, signing, and API operations.
 */

import {
  computeHash,
  toMessageId,
  decodeUrlSafeBase64,
  encodeBase64,
  signData,
  stringToBytes,
  concatBytes,
} from './crypto.js';
import type {
  Message,
  MessageCreated,
  MessageQuery,
  MessagesResponse,
  ApiError,
} from './types.js';
import { createApiError } from './exceptions.js';

/**
 * Compute message hash for chain validation.
 *
 * Hash is computed over: topic_id|type|prev_hash|data|sender
 *
 * @param topicId - Topic identifier
 * @param msgType - Message type/category (or state path for state messages)
 * @param prevHash - Typed hash of previous message (null for first message)
 * @param data - Encrypted message data (raw bytes)
 * @param sender - Typed sender identifier
 * @returns Typed message hash (44-char base64 starting with 'M')
 */
export function computeMessageHash(
  topicId: string,
  msgType: string,
  prevHash: string | null,
  data: Uint8Array,
  sender: string
): string {
  // Hash is over: topic_id|type|prev_hash|data|sender
  const prevHashStr = prevHash ?? '';
  const prefix = stringToBytes(`${topicId}|${msgType}|${prevHashStr}|`);
  const suffix = stringToBytes(`|${sender}`);
  const hashInput = concatBytes(prefix, data, suffix);

  const hashBytes = computeHash(hashInput);
  return toMessageId(hashBytes);
}

/**
 * Post a message to a topic.
 *
 * @param fetchFn - Fetch function
 * @param baseUrl - API base URL
 * @param token - JWT bearer token
 * @param spaceId - Typed space identifier
 * @param topicId - Topic identifier
 * @param msgType - Message type/category
 * @param data - Encrypted message data
 * @param prevHash - Hash of previous message (null for first)
 * @param senderPublicKeyTyped - Typed sender public key
 * @param senderPrivateKey - Sender's private key for signing
 * @returns Message creation result
 */
export async function postMessage(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string,
  topicId: string,
  msgType: string,
  data: Uint8Array,
  prevHash: string | null,
  senderPublicKeyTyped: string,
  senderPrivateKey: Uint8Array
): Promise<MessageCreated> {
  // Compute message hash
  const messageHash = computeMessageHash(
    topicId,
    msgType,
    prevHash,
    data,
    senderPublicKeyTyped
  );

  // Sign the message hash (sign the typed identifier bytes)
  const messageHashBytes = decodeUrlSafeBase64(messageHash);
  const signature = await signData(messageHashBytes, senderPrivateKey);

  // Create request body
  const body = {
    type: msgType,
    prev_hash: prevHash,
    data: encodeBase64(data),
    message_hash: messageHash,
    signature: encodeBase64(signature),
  };

  // Post message
  const url = `${baseUrl}/spaces/${spaceId}/topics/${topicId}/messages`;
  const response = await fetchFn(url, {
    method: 'POST',
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

  return (await response.json()) as MessageCreated;
}

/**
 * Get messages from a topic.
 *
 * @param fetchFn - Fetch function
 * @param baseUrl - API base URL
 * @param token - JWT bearer token
 * @param spaceId - Typed space identifier
 * @param topicId - Topic identifier
 * @param query - Optional query parameters
 * @returns Messages response with messages array and has_more flag
 */
export async function getMessages(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string,
  topicId: string,
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
  const url = `${baseUrl}/spaces/${spaceId}/topics/${topicId}/messages${queryString ? `?${queryString}` : ''}`;

  const response = await fetchFn(url, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    if (response.status === 404) {
      return { messages: [], has_more: false };
    }
    const error = await parseError(response);
    throw createApiError(response.status, error);
  }

  return (await response.json()) as MessagesResponse;
}

/**
 * Get a specific message by hash.
 *
 * @param fetchFn - Fetch function
 * @param baseUrl - API base URL
 * @param token - JWT bearer token
 * @param spaceId - Typed space identifier
 * @param topicId - Topic identifier
 * @param messageHash - Typed message identifier
 * @returns The message
 */
export async function getMessage(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string,
  topicId: string,
  messageHash: string
): Promise<Message> {
  const url = `${baseUrl}/spaces/${spaceId}/topics/${topicId}/messages/${messageHash}`;

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

  return (await response.json()) as Message;
}

/**
 * Validate that a list of messages forms a valid chain.
 *
 * @param messages - List of Message objects in chronological order
 * @returns True if chain is valid, False otherwise
 */
export function validateMessageChain(messages: Message[]): boolean {
  let prevHash: string | null = null;

  for (const msg of messages) {
    // Check that prev_hash matches
    if (msg.prev_hash !== prevHash) {
      return false;
    }

    // Skip validation if data is missing
    if (!msg.data) {
      prevHash = msg.message_hash;
      continue;
    }

    // Verify message hash
    const dataBytes = decodeUrlSafeBase64(msg.data);
    const expectedHash = computeMessageHash(
      msg.topic_id,
      msg.type,
      msg.prev_hash,
      dataBytes,
      msg.sender
    );

    if (msg.message_hash !== expectedHash) {
      return false;
    }

    prevHash = msg.message_hash;
  }

  return true;
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
