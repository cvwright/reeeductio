/**
 * Local message store for client-side caching.
 *
 * Provides offline access and reduces network requests by caching
 * messages fetched from the server.
 */

import type { Message } from './types.js';

/**
 * Query options for retrieving messages from the store.
 */
export interface MessageStoreQuery {
  /** Start timestamp (inclusive, milliseconds) */
  fromTimestamp?: number;
  /** End timestamp (inclusive, milliseconds) */
  toTimestamp?: number;
  /** Maximum number of messages to return */
  limit?: number;
  /** Message type filter */
  type?: string;
}

/**
 * Abstract interface for local message storage.
 *
 * Implement this interface to provide custom persistence backends
 * (e.g., IndexedDB for browsers, SQLite for Node.js).
 */
export interface MessageStore {
  /**
   * Store a message in the local cache.
   *
   * @param spaceId - Space the message belongs to
   * @param message - Message to store
   */
  putMessage(spaceId: string, message: Message): Promise<void>;

  /**
   * Store multiple messages in the local cache.
   *
   * @param spaceId - Space the messages belong to
   * @param messages - Messages to store
   */
  putMessages(spaceId: string, messages: Message[]): Promise<void>;

  /**
   * Get a specific message by hash.
   *
   * @param spaceId - Space identifier
   * @param topicId - Topic identifier
   * @param messageHash - Message hash to look up
   * @returns Message if found, null otherwise
   */
  getMessage(
    spaceId: string,
    topicId: string,
    messageHash: string
  ): Promise<Message | null>;

  /**
   * Get messages from a topic with optional filtering.
   *
   * @param spaceId - Space identifier
   * @param topicId - Topic identifier
   * @param query - Optional query parameters
   * @returns List of messages, ordered by timestamp
   */
  getMessages(
    spaceId: string,
    topicId: string,
    query?: MessageStoreQuery
  ): Promise<Message[]>;

  /**
   * Get the most recent message in a topic.
   *
   * @param spaceId - Space identifier
   * @param topicId - Topic identifier
   * @param type - Optional message type filter
   * @returns Most recent message, or null if topic is empty
   */
  getLatestMessage(
    spaceId: string,
    topicId: string,
    type?: string
  ): Promise<Message | null>;

  /**
   * Get the timestamp of the most recent cached message.
   *
   * Useful for fetching only newer messages from the server.
   *
   * @param spaceId - Space identifier
   * @param topicId - Topic identifier
   * @returns Timestamp in milliseconds, or null if no messages cached
   */
  getLatestTimestamp(spaceId: string, topicId: string): Promise<number | null>;

  /**
   * Delete cached messages.
   *
   * @param spaceId - Space identifier
   * @param topicId - Optional topic filter (delete all topics if undefined)
   * @param beforeTimestamp - Optional timestamp filter (delete older messages)
   * @returns Number of messages deleted
   */
  deleteMessages(
    spaceId: string,
    topicId?: string,
    beforeTimestamp?: number
  ): Promise<number>;

  /**
   * Delete all cached messages.
   */
  clear(): Promise<void>;

  /**
   * Count cached messages.
   *
   * @param spaceId - Optional space filter
   * @returns Number of messages in cache
   */
  countMessages(spaceId?: string): Promise<number>;
}

/**
 * Composite key for message lookup.
 */
function messageKey(spaceId: string, topicId: string, messageHash: string): string {
  return `${spaceId}|${topicId}|${messageHash}`;
}

/**
 * In-memory message store implementation.
 *
 * This is a lightweight implementation that works in both browser and Node.js
 * environments. Messages are stored in memory and will be lost when the
 * process exits.
 *
 * For persistent storage, implement the MessageStore interface with your
 * preferred backend (IndexedDB, SQLite, etc.).
 *
 * @example
 * ```typescript
 * const store = new InMemoryMessageStore();
 *
 * // Store messages fetched from server
 * await store.putMessages(spaceId, messages);
 *
 * // Retrieve cached messages
 * const cached = await store.getMessages(spaceId, topicId, { limit: 100 });
 *
 * // Check latest timestamp for incremental sync
 * const lastTs = await store.getLatestTimestamp(spaceId, topicId);
 * ```
 */
export class InMemoryMessageStore implements MessageStore {
  /** Messages indexed by composite key */
  private messages = new Map<string, Message & { _spaceId: string }>();

  async putMessage(spaceId: string, message: Message): Promise<void> {
    const key = messageKey(spaceId, message.topic_id, message.message_hash);
    this.messages.set(key, { ...message, _spaceId: spaceId });
  }

  async putMessages(spaceId: string, messages: Message[]): Promise<void> {
    for (const message of messages) {
      const key = messageKey(spaceId, message.topic_id, message.message_hash);
      this.messages.set(key, { ...message, _spaceId: spaceId });
    }
  }

  async getMessage(
    spaceId: string,
    topicId: string,
    messageHash: string
  ): Promise<Message | null> {
    const key = messageKey(spaceId, topicId, messageHash);
    const stored = this.messages.get(key);
    if (!stored) return null;

    // Return without internal _spaceId field
    const { _spaceId, ...message } = stored;
    return message;
  }

  async getMessages(
    spaceId: string,
    topicId: string,
    query?: MessageStoreQuery
  ): Promise<Message[]> {
    const { fromTimestamp, toTimestamp, limit = 100, type } = query ?? {};

    // Determine sort order based on timestamp range
    const reverseOrder =
      fromTimestamp !== undefined &&
      toTimestamp !== undefined &&
      fromTimestamp > toTimestamp;

    const rangeStart = reverseOrder ? toTimestamp : fromTimestamp;
    const rangeEnd = reverseOrder ? fromTimestamp : toTimestamp;

    // Filter messages
    const results: Message[] = [];
    for (const stored of this.messages.values()) {
      if (stored._spaceId !== spaceId) continue;
      if (stored.topic_id !== topicId) continue;

      if (type !== undefined && stored.type !== type) continue;

      if (rangeStart !== undefined && stored.server_timestamp < rangeStart) continue;
      if (rangeEnd !== undefined && stored.server_timestamp > rangeEnd) continue;

      const { _spaceId, ...message } = stored;
      results.push(message);
    }

    // Sort by timestamp
    results.sort((a, b) => {
      const diff = a.server_timestamp - b.server_timestamp;
      return reverseOrder ? -diff : diff;
    });

    // Apply limit
    return results.slice(0, limit);
  }

  async getLatestMessage(
    spaceId: string,
    topicId: string,
    type?: string
  ): Promise<Message | null> {
    let latest: (Message & { _spaceId: string }) | null = null;

    for (const stored of this.messages.values()) {
      if (stored._spaceId !== spaceId) continue;
      if (stored.topic_id !== topicId) continue;
      if (type !== undefined && stored.type !== type) continue;

      if (!latest || stored.server_timestamp > latest.server_timestamp) {
        latest = stored;
      }
    }

    if (!latest) return null;

    const { _spaceId, ...message } = latest;
    return message;
  }

  async getLatestTimestamp(
    spaceId: string,
    topicId: string
  ): Promise<number | null> {
    let maxTimestamp: number | null = null;

    for (const stored of this.messages.values()) {
      if (stored._spaceId !== spaceId) continue;
      if (stored.topic_id !== topicId) continue;

      if (maxTimestamp === null || stored.server_timestamp > maxTimestamp) {
        maxTimestamp = stored.server_timestamp;
      }
    }

    return maxTimestamp;
  }

  async deleteMessages(
    spaceId: string,
    topicId?: string,
    beforeTimestamp?: number
  ): Promise<number> {
    let deleted = 0;

    for (const [key, stored] of this.messages.entries()) {
      if (stored._spaceId !== spaceId) continue;
      if (topicId !== undefined && stored.topic_id !== topicId) continue;
      if (beforeTimestamp !== undefined && stored.server_timestamp >= beforeTimestamp) continue;

      this.messages.delete(key);
      deleted++;
    }

    return deleted;
  }

  async clear(): Promise<void> {
    this.messages.clear();
  }

  async countMessages(spaceId?: string): Promise<number> {
    if (spaceId === undefined) {
      return this.messages.size;
    }

    let count = 0;
    for (const stored of this.messages.values()) {
      if (stored._spaceId === spaceId) {
        count++;
      }
    }
    return count;
  }
}
