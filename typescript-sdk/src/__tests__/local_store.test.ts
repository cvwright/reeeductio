import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import 'fake-indexeddb/auto';
import { InMemoryMessageStore } from '../local_store.js';
import { IndexedDBMessageStore } from '../local_store_idb.js';
import type { MessageStore } from '../local_store.js';
import type { Message } from '../types.js';

// Helper to create test messages
function createMessage(overrides: Partial<Message> = {}): Message {
  return {
    message_hash: 'M' + Math.random().toString(36).substring(2, 45).padEnd(43, 'x'),
    topic_id: 'test-topic',
    type: 'text',
    prev_hash: null,
    data: 'SGVsbG8gV29ybGQh', // "Hello World!" base64
    sender: 'U' + 'a'.repeat(43),
    signature: 'sig' + Math.random().toString(36).substring(2),
    server_timestamp: Date.now(),
    ...overrides,
  };
}

// Create a chain of messages with proper prev_hash links
function createMessageChain(count: number, topicId = 'test-topic'): Message[] {
  const messages: Message[] = [];
  let prevHash: string | null = null;
  const baseTimestamp = Date.now() - count * 1000;

  for (let i = 0; i < count; i++) {
    const msg = createMessage({
      topic_id: topicId,
      prev_hash: prevHash,
      server_timestamp: baseTimestamp + i * 1000,
    });
    prevHash = msg.message_hash;
    messages.push(msg);
  }

  return messages;
}

// Test suite that runs against any MessageStore implementation
function testMessageStore(name: string, createStore: () => Promise<MessageStore>, cleanup?: () => Promise<void>) {
  describe(name, () => {
    let store: MessageStore;
    const spaceId = 'S' + 'a'.repeat(43);

    beforeEach(async () => {
      store = await createStore();
    });

    afterEach(async () => {
      await store.clear();
      if (cleanup) {
        await cleanup();
      }
    });

    describe('putMessage / getMessage', () => {
      it('should store and retrieve a single message', async () => {
        const msg = createMessage();

        await store.putMessage(spaceId, msg);
        const retrieved = await store.getMessage(spaceId, msg.topic_id, msg.message_hash);

        expect(retrieved).not.toBeNull();
        expect(retrieved!.message_hash).toBe(msg.message_hash);
        expect(retrieved!.data).toBe(msg.data);
        expect(retrieved!.sender).toBe(msg.sender);
      });

      it('should return null for non-existent message', async () => {
        const result = await store.getMessage(spaceId, 'topic', 'M' + 'x'.repeat(43));
        expect(result).toBeNull();
      });

      it('should overwrite existing message with same hash', async () => {
        const msg = createMessage();
        await store.putMessage(spaceId, msg);

        const updatedMsg = { ...msg, data: 'bmV3IGRhdGE=' };
        await store.putMessage(spaceId, updatedMsg);

        const retrieved = await store.getMessage(spaceId, msg.topic_id, msg.message_hash);
        expect(retrieved!.data).toBe('bmV3IGRhdGE=');
      });
    });

    describe('putMessages', () => {
      it('should store multiple messages at once', async () => {
        const messages = createMessageChain(5);

        await store.putMessages(spaceId, messages);

        for (const msg of messages) {
          const retrieved = await store.getMessage(spaceId, msg.topic_id, msg.message_hash);
          expect(retrieved).not.toBeNull();
          expect(retrieved!.message_hash).toBe(msg.message_hash);
        }
      });

      it('should handle empty array', async () => {
        await store.putMessages(spaceId, []);
        const count = await store.countMessages(spaceId);
        expect(count).toBe(0);
      });
    });

    describe('getMessages', () => {
      it('should retrieve messages by topic', async () => {
        const topic1Messages = createMessageChain(3, 'topic1');
        const topic2Messages = createMessageChain(2, 'topic2');

        await store.putMessages(spaceId, [...topic1Messages, ...topic2Messages]);

        const result = await store.getMessages(spaceId, 'topic1');
        expect(result).toHaveLength(3);
        expect(result.every(m => m.topic_id === 'topic1')).toBe(true);
      });

      it('should filter by timestamp range', async () => {
        const baseTime = 1000000;
        const messages = [
          createMessage({ server_timestamp: baseTime }),
          createMessage({ server_timestamp: baseTime + 1000 }),
          createMessage({ server_timestamp: baseTime + 2000 }),
          createMessage({ server_timestamp: baseTime + 3000 }),
          createMessage({ server_timestamp: baseTime + 4000 }),
        ];

        await store.putMessages(spaceId, messages);

        const result = await store.getMessages(spaceId, 'test-topic', {
          fromTimestamp: baseTime + 1000,
          toTimestamp: baseTime + 3000,
        });

        expect(result).toHaveLength(3);
        expect(result.every(m =>
          m.server_timestamp >= baseTime + 1000 &&
          m.server_timestamp <= baseTime + 3000
        )).toBe(true);
      });

      it('should respect limit parameter', async () => {
        const messages = createMessageChain(10);
        await store.putMessages(spaceId, messages);

        const result = await store.getMessages(spaceId, 'test-topic', { limit: 5 });
        expect(result).toHaveLength(5);
      });

      it('should return messages in ascending order by default', async () => {
        const messages = createMessageChain(5);
        // Shuffle before storing
        const shuffled = [...messages].sort(() => Math.random() - 0.5);
        await store.putMessages(spaceId, shuffled);

        const result = await store.getMessages(spaceId, 'test-topic');

        for (let i = 1; i < result.length; i++) {
          expect(result[i].server_timestamp).toBeGreaterThanOrEqual(result[i - 1].server_timestamp);
        }
      });

      it('should return messages in descending order when from > to', async () => {
        const baseTime = 1000000;
        const messages = [
          createMessage({ server_timestamp: baseTime }),
          createMessage({ server_timestamp: baseTime + 1000 }),
          createMessage({ server_timestamp: baseTime + 2000 }),
        ];
        await store.putMessages(spaceId, messages);

        const result = await store.getMessages(spaceId, 'test-topic', {
          fromTimestamp: baseTime + 2000,
          toTimestamp: baseTime,
        });

        expect(result).toHaveLength(3);
        for (let i = 1; i < result.length; i++) {
          expect(result[i].server_timestamp).toBeLessThanOrEqual(result[i - 1].server_timestamp);
        }
      });

      it('should filter by type when specified', async () => {
        const messages = [
          createMessage({ type: 'text' }),
          createMessage({ type: 'image' }),
          createMessage({ type: 'text' }),
        ];
        await store.putMessages(spaceId, messages);

        const result = await store.getMessages(spaceId, 'test-topic', { type: 'text' });
        expect(result).toHaveLength(2);
        expect(result.every(m => m.type === 'text')).toBe(true);
      });

      it('should return empty array for non-existent topic', async () => {
        const result = await store.getMessages(spaceId, 'non-existent-topic');
        expect(result).toHaveLength(0);
      });
    });

    describe('getLatestMessage', () => {
      it('should return the most recent message', async () => {
        const messages = createMessageChain(5);
        await store.putMessages(spaceId, messages);

        const latest = await store.getLatestMessage(spaceId, 'test-topic');

        expect(latest).not.toBeNull();
        expect(latest!.message_hash).toBe(messages[messages.length - 1].message_hash);
      });

      it('should return null for empty topic', async () => {
        const result = await store.getLatestMessage(spaceId, 'empty-topic');
        expect(result).toBeNull();
      });

      it('should filter by type', async () => {
        const baseTime = 1000000;
        const messages = [
          createMessage({ type: 'text', server_timestamp: baseTime }),
          createMessage({ type: 'image', server_timestamp: baseTime + 1000 }),
          createMessage({ type: 'text', server_timestamp: baseTime + 2000 }),
        ];
        await store.putMessages(spaceId, messages);

        const latest = await store.getLatestMessage(spaceId, 'test-topic', 'image');
        expect(latest).not.toBeNull();
        expect(latest!.type).toBe('image');
        expect(latest!.server_timestamp).toBe(baseTime + 1000);
      });
    });

    describe('getLatestTimestamp', () => {
      it('should return the timestamp of the most recent message', async () => {
        const messages = createMessageChain(3);
        await store.putMessages(spaceId, messages);

        const timestamp = await store.getLatestTimestamp(spaceId, 'test-topic');
        expect(timestamp).toBe(messages[messages.length - 1].server_timestamp);
      });

      it('should return null for empty topic', async () => {
        const result = await store.getLatestTimestamp(spaceId, 'empty-topic');
        expect(result).toBeNull();
      });
    });

    describe('deleteMessages', () => {
      it('should delete all messages in a space', async () => {
        const messages = createMessageChain(5);
        await store.putMessages(spaceId, messages);

        const deleted = await store.deleteMessages(spaceId);
        expect(deleted).toBe(5);

        const count = await store.countMessages(spaceId);
        expect(count).toBe(0);
      });

      it('should delete messages by topic', async () => {
        const topic1Messages = createMessageChain(3, 'topic1');
        const topic2Messages = createMessageChain(2, 'topic2');
        await store.putMessages(spaceId, [...topic1Messages, ...topic2Messages]);

        const deleted = await store.deleteMessages(spaceId, 'topic1');
        expect(deleted).toBe(3);

        const remaining = await store.getMessages(spaceId, 'topic2');
        expect(remaining).toHaveLength(2);
      });

      it('should delete messages before timestamp', async () => {
        const baseTime = 1000000;
        const messages = [
          createMessage({ server_timestamp: baseTime }),
          createMessage({ server_timestamp: baseTime + 1000 }),
          createMessage({ server_timestamp: baseTime + 2000 }),
        ];
        await store.putMessages(spaceId, messages);

        const deleted = await store.deleteMessages(spaceId, undefined, baseTime + 1500);
        expect(deleted).toBe(2);

        const remaining = await store.getMessages(spaceId, 'test-topic');
        expect(remaining).toHaveLength(1);
        expect(remaining[0].server_timestamp).toBe(baseTime + 2000);
      });

      it('should not affect other spaces', async () => {
        const space2 = 'S' + 'b'.repeat(43);
        const space1Messages = createMessageChain(2);
        const space2Messages = createMessageChain(3);

        await store.putMessages(spaceId, space1Messages);
        await store.putMessages(space2, space2Messages);

        await store.deleteMessages(spaceId);

        expect(await store.countMessages(spaceId)).toBe(0);
        expect(await store.countMessages(space2)).toBe(3);
      });
    });

    describe('clear', () => {
      it('should delete all messages', async () => {
        const space2 = 'S' + 'b'.repeat(43);
        await store.putMessages(spaceId, createMessageChain(5));
        await store.putMessages(space2, createMessageChain(3));

        await store.clear();

        expect(await store.countMessages()).toBe(0);
      });
    });

    describe('countMessages', () => {
      it('should count all messages', async () => {
        await store.putMessages(spaceId, createMessageChain(5));

        const count = await store.countMessages();
        expect(count).toBe(5);
      });

      it('should count messages by space', async () => {
        const space2 = 'S' + 'b'.repeat(43);
        await store.putMessages(spaceId, createMessageChain(5));
        await store.putMessages(space2, createMessageChain(3));

        expect(await store.countMessages(spaceId)).toBe(5);
        expect(await store.countMessages(space2)).toBe(3);
        expect(await store.countMessages()).toBe(8);
      });
    });

    describe('space isolation', () => {
      it('should isolate messages between spaces', async () => {
        const space2 = 'S' + 'b'.repeat(43);
        const space1Messages = createMessageChain(2);
        const space2Messages = createMessageChain(3);

        await store.putMessages(spaceId, space1Messages);
        await store.putMessages(space2, space2Messages);

        const space1Result = await store.getMessages(spaceId, 'test-topic');
        const space2Result = await store.getMessages(space2, 'test-topic');

        expect(space1Result).toHaveLength(2);
        expect(space2Result).toHaveLength(3);
      });

      it('should not find message from different space', async () => {
        const space2 = 'S' + 'b'.repeat(43);
        const msg = createMessage();
        await store.putMessage(spaceId, msg);

        const result = await store.getMessage(space2, msg.topic_id, msg.message_hash);
        expect(result).toBeNull();
      });
    });
  });
}

// Run tests for InMemoryMessageStore
testMessageStore(
  'InMemoryMessageStore',
  async () => new InMemoryMessageStore()
);

// Run tests for IndexedDBMessageStore
let idbStore: IndexedDBMessageStore | null = null;

testMessageStore(
  'IndexedDBMessageStore',
  async () => {
    idbStore = new IndexedDBMessageStore('test-reeeductio-messages');
    await idbStore.open();
    return idbStore;
  },
  async () => {
    if (idbStore) {
      await idbStore.deleteDatabase();
      idbStore = null;
    }
  }
);

// Additional IndexedDB-specific tests
describe('IndexedDBMessageStore specific', () => {
  let store: IndexedDBMessageStore;
  const spaceId = 'S' + 'a'.repeat(43);

  beforeEach(async () => {
    store = new IndexedDBMessageStore('test-idb-specific');
    await store.open();
  });

  afterEach(async () => {
    await store.deleteDatabase();
  });

  it('should auto-open on first operation', async () => {
    const autoOpenStore = new IndexedDBMessageStore('test-auto-open');
    // Don't call open() explicitly

    const msg = createMessage();
    await autoOpenStore.putMessage(spaceId, msg);

    const retrieved = await autoOpenStore.getMessage(spaceId, msg.topic_id, msg.message_hash);
    expect(retrieved).not.toBeNull();

    await autoOpenStore.deleteDatabase();
  });

  it('should handle close and reopen', async () => {
    const msg = createMessage();
    await store.putMessage(spaceId, msg);

    store.close();

    // Reopen by calling open() again
    await store.open();

    const retrieved = await store.getMessage(spaceId, msg.topic_id, msg.message_hash);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.message_hash).toBe(msg.message_hash);
  });

  it('should persist data across store instances', async () => {
    const dbName = 'test-persistence';
    const store1 = new IndexedDBMessageStore(dbName);
    await store1.open();

    const msg = createMessage();
    await store1.putMessage(spaceId, msg);
    store1.close();

    // Create new instance with same db name
    const store2 = new IndexedDBMessageStore(dbName);
    await store2.open();

    const retrieved = await store2.getMessage(spaceId, msg.topic_id, msg.message_hash);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.message_hash).toBe(msg.message_hash);

    await store2.deleteDatabase();
  });

  it('should delete database completely', async () => {
    const msg = createMessage();
    await store.putMessage(spaceId, msg);

    await store.deleteDatabase();

    // Create new store with same name - should be empty
    const newStore = new IndexedDBMessageStore('test-idb-specific');
    await newStore.open();

    const count = await newStore.countMessages();
    expect(count).toBe(0);

    await newStore.deleteDatabase();
  });
});
