/**
 * IndexedDB message store for browser-based persistence.
 *
 * Provides persistent offline storage for messages in browser environments.
 * This module should only be imported in browser contexts.
 */

import type { Message } from './types.js';
import type { MessageStore, MessageStoreQuery } from './local_store.js';

/** IndexedDB database name */
const DB_NAME = 'reeeductio-messages';
/** Database version - increment when schema changes */
const DB_VERSION = 1;
/** Object store name for messages */
const STORE_NAME = 'messages';

/**
 * Stored message with space_id included for indexing.
 */
interface StoredMessage extends Message {
  /** Composite primary key: space_id|topic_id|message_hash */
  _key: string;
  /** Space identifier for indexing */
  _spaceId: string;
}

/**
 * IndexedDB-based message store for browser persistence.
 *
 * Messages are stored in IndexedDB and persist across browser sessions.
 * Supports multiple spaces and topics with efficient querying by
 * space, topic, timestamp, and message type.
 *
 * @example
 * ```typescript
 * // Create store (opens/creates database)
 * const store = new IndexedDBMessageStore();
 * await store.open();
 *
 * // Store messages fetched from server
 * await store.putMessages(spaceId, messages);
 *
 * // Retrieve cached messages
 * const cached = await store.getMessages(spaceId, topicId, { limit: 100 });
 *
 * // Check latest timestamp for incremental sync
 * const lastTs = await store.getLatestTimestamp(spaceId, topicId);
 *
 * // Close when done (optional, but recommended)
 * store.close();
 * ```
 */
export class IndexedDBMessageStore implements MessageStore {
  private db: IDBDatabase | null = null;
  private dbName: string;
  private openPromise: Promise<void> | null = null;

  /**
   * Create an IndexedDB message store.
   *
   * @param dbName - Database name (default: 'reeeductio-messages')
   */
  constructor(dbName: string = DB_NAME) {
    this.dbName = dbName;
  }

  /**
   * Open the database connection.
   *
   * This is called automatically on first operation, but can be called
   * explicitly to handle initialization errors upfront.
   */
  async open(): Promise<void> {
    if (this.db) return;
    if (this.openPromise) return this.openPromise;

    this.openPromise = this.initDatabase();
    await this.openPromise;
  }

  /**
   * Close the database connection.
   */
  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
    this.openPromise = null;
  }

  private async initDatabase(): Promise<void> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, DB_VERSION);

      request.onerror = () => {
        reject(new Error(`Failed to open IndexedDB: ${request.error?.message}`));
      };

      request.onsuccess = () => {
        this.db = request.result;
        resolve();
      };

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;

        // Create messages object store
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          const store = db.createObjectStore(STORE_NAME, { keyPath: '_key' });

          // Index for querying by space + topic + timestamp
          store.createIndex('space_topic_time', ['_spaceId', 'topic_id', 'server_timestamp']);

          // Index for querying by space + topic + type
          store.createIndex('space_topic_type', ['_spaceId', 'topic_id', 'type']);

          // Index for counting by space
          store.createIndex('space', '_spaceId');
        }
      };
    });
  }

  private async ensureOpen(): Promise<IDBDatabase> {
    await this.open();
    if (!this.db) {
      throw new Error('Database not initialized');
    }
    return this.db;
  }

  private messageKey(spaceId: string, topicId: string, messageHash: string): string {
    return `${spaceId}|${topicId}|${messageHash}`;
  }

  async putMessage(spaceId: string, message: Message): Promise<void> {
    const db = await this.ensureOpen();

    const stored: StoredMessage = {
      ...message,
      _key: this.messageKey(spaceId, message.topic_id, message.message_hash),
      _spaceId: spaceId,
    };

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);

      const request = store.put(stored);
      request.onerror = () => reject(new Error(`Failed to store message: ${request.error?.message}`));

      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(new Error(`Transaction failed: ${tx.error?.message}`));
    });
  }

  async putMessages(spaceId: string, messages: Message[]): Promise<void> {
    if (messages.length === 0) return;

    const db = await this.ensureOpen();

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);

      for (const message of messages) {
        const stored: StoredMessage = {
          ...message,
          _key: this.messageKey(spaceId, message.topic_id, message.message_hash),
          _spaceId: spaceId,
        };
        store.put(stored);
      }

      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(new Error(`Transaction failed: ${tx.error?.message}`));
    });
  }

  async getMessage(
    spaceId: string,
    topicId: string,
    messageHash: string
  ): Promise<Message | null> {
    const db = await this.ensureOpen();
    const key = this.messageKey(spaceId, topicId, messageHash);

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const request = store.get(key);

      request.onsuccess = () => {
        const stored = request.result as StoredMessage | undefined;
        if (!stored) {
          resolve(null);
          return;
        }

        // Remove internal fields
        const { _key, _spaceId, ...message } = stored;
        resolve(message);
      };

      request.onerror = () => reject(new Error(`Failed to get message: ${request.error?.message}`));
    });
  }

  async getMessages(
    spaceId: string,
    topicId: string,
    query?: MessageStoreQuery
  ): Promise<Message[]> {
    const db = await this.ensureOpen();
    const { fromTimestamp, toTimestamp, limit = 100, type } = query ?? {};

    // Determine sort order based on timestamp range
    const reverseOrder =
      fromTimestamp !== undefined &&
      toTimestamp !== undefined &&
      fromTimestamp > toTimestamp;

    const rangeStart = reverseOrder ? toTimestamp : fromTimestamp;
    const rangeEnd = reverseOrder ? fromTimestamp : toTimestamp;

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const index = store.index('space_topic_time');

      // Build key range for the index [spaceId, topicId, timestamp]
      let range: IDBKeyRange;
      if (rangeStart !== undefined && rangeEnd !== undefined) {
        range = IDBKeyRange.bound(
          [spaceId, topicId, rangeStart],
          [spaceId, topicId, rangeEnd]
        );
      } else if (rangeStart !== undefined) {
        range = IDBKeyRange.bound(
          [spaceId, topicId, rangeStart],
          [spaceId, topicId, Number.MAX_SAFE_INTEGER]
        );
      } else if (rangeEnd !== undefined) {
        range = IDBKeyRange.bound(
          [spaceId, topicId, 0],
          [spaceId, topicId, rangeEnd]
        );
      } else {
        range = IDBKeyRange.bound(
          [spaceId, topicId, 0],
          [spaceId, topicId, Number.MAX_SAFE_INTEGER]
        );
      }

      const direction: IDBCursorDirection = reverseOrder ? 'prev' : 'next';
      const request = index.openCursor(range, direction);
      const results: Message[] = [];

      request.onsuccess = () => {
        const cursor = request.result;
        if (!cursor || results.length >= limit) {
          resolve(results);
          return;
        }

        const stored = cursor.value as StoredMessage;

        // Apply type filter if specified
        if (type === undefined || stored.type === type) {
          const { _key, _spaceId, ...message } = stored;
          results.push(message);
        }

        cursor.continue();
      };

      request.onerror = () => reject(new Error(`Failed to get messages: ${request.error?.message}`));
    });
  }

  async getLatestMessage(
    spaceId: string,
    topicId: string,
    type?: string
  ): Promise<Message | null> {
    const db = await this.ensureOpen();

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);

      if (type !== undefined) {
        // Use type index and find max timestamp
        const index = store.index('space_topic_type');
        const range = IDBKeyRange.only([spaceId, topicId, type]);
        const request = index.openCursor(range, 'prev');

        // Need to iterate to find max timestamp since index doesn't include it
        let latest: StoredMessage | null = null;

        request.onsuccess = () => {
          const cursor = request.result;
          if (!cursor) {
            if (!latest) {
              resolve(null);
            } else {
              const { _key, _spaceId, ...message } = latest;
              resolve(message);
            }
            return;
          }

          const stored = cursor.value as StoredMessage;
          if (!latest || stored.server_timestamp > latest.server_timestamp) {
            latest = stored;
          }
          cursor.continue();
        };

        request.onerror = () => reject(new Error(`Failed to get latest message: ${request.error?.message}`));
      } else {
        // Use timestamp index and get last entry
        const index = store.index('space_topic_time');
        const range = IDBKeyRange.bound(
          [spaceId, topicId, 0],
          [spaceId, topicId, Number.MAX_SAFE_INTEGER]
        );
        const request = index.openCursor(range, 'prev');

        request.onsuccess = () => {
          const cursor = request.result;
          if (!cursor) {
            resolve(null);
            return;
          }

          const stored = cursor.value as StoredMessage;
          const { _key, _spaceId, ...message } = stored;
          resolve(message);
        };

        request.onerror = () => reject(new Error(`Failed to get latest message: ${request.error?.message}`));
      }
    });
  }

  async getLatestTimestamp(
    spaceId: string,
    topicId: string
  ): Promise<number | null> {
    const latest = await this.getLatestMessage(spaceId, topicId);
    return latest?.server_timestamp ?? null;
  }

  async deleteMessages(
    spaceId: string,
    topicId?: string,
    beforeTimestamp?: number
  ): Promise<number> {
    const db = await this.ensureOpen();

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const index = store.index('space_topic_time');

      let deleted = 0;

      // Build range based on filters
      let range: IDBKeyRange;
      if (topicId !== undefined) {
        if (beforeTimestamp !== undefined) {
          range = IDBKeyRange.bound(
            [spaceId, topicId, 0],
            [spaceId, topicId, beforeTimestamp],
            false,
            true // exclude upper bound
          );
        } else {
          range = IDBKeyRange.bound(
            [spaceId, topicId, 0],
            [spaceId, topicId, Number.MAX_SAFE_INTEGER]
          );
        }
      } else {
        // All topics in space - need to iterate by space index
        const spaceIndex = store.index('space');
        const spaceRange = IDBKeyRange.only(spaceId);
        const request = spaceIndex.openCursor(spaceRange);

        request.onsuccess = () => {
          const cursor = request.result;
          if (!cursor) {
            return;
          }

          const stored = cursor.value as StoredMessage;
          if (beforeTimestamp === undefined || stored.server_timestamp < beforeTimestamp) {
            cursor.delete();
            deleted++;
          }
          cursor.continue();
        };

        request.onerror = () => reject(new Error(`Failed to delete messages: ${request.error?.message}`));

        tx.oncomplete = () => resolve(deleted);
        tx.onerror = () => reject(new Error(`Transaction failed: ${tx.error?.message}`));
        return;
      }

      const request = index.openCursor(range);

      request.onsuccess = () => {
        const cursor = request.result;
        if (!cursor) {
          return;
        }

        cursor.delete();
        deleted++;
        cursor.continue();
      };

      request.onerror = () => reject(new Error(`Failed to delete messages: ${request.error?.message}`));

      tx.oncomplete = () => resolve(deleted);
      tx.onerror = () => reject(new Error(`Transaction failed: ${tx.error?.message}`));
    });
  }

  async clear(): Promise<void> {
    const db = await this.ensureOpen();

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const request = store.clear();

      request.onerror = () => reject(new Error(`Failed to clear store: ${request.error?.message}`));
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(new Error(`Transaction failed: ${tx.error?.message}`));
    });
  }

  async countMessages(spaceId?: string): Promise<number> {
    const db = await this.ensureOpen();

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);

      if (spaceId === undefined) {
        const request = store.count();
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(new Error(`Failed to count messages: ${request.error?.message}`));
      } else {
        const index = store.index('space');
        const range = IDBKeyRange.only(spaceId);
        const request = index.count(range);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(new Error(`Failed to count messages: ${request.error?.message}`));
      }
    });
  }

  /**
   * Delete the entire database.
   *
   * Use this for complete cleanup. The store should not be used after calling this.
   */
  async deleteDatabase(): Promise<void> {
    this.close();

    return new Promise((resolve, reject) => {
      const request = indexedDB.deleteDatabase(this.dbName);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(new Error(`Failed to delete database: ${request.error?.message}`));
    });
  }
}
