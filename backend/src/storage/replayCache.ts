// backend/src/storage/replayCache.ts

// Simple in-memory replay cache.
// Keyed by `${sessionId}:${signature}`
// Marks a request as replayed if seen again within WINDOW_MS.

const WINDOW_MS = 5 * 60 * 1000; // 5 minutes
const MAX_ENTRIES = 10000;

type Entry = {
  firstSeenAt: number;
};

const replayMap = new Map<string, Entry>();

function cleanup(now: number) {
  if (replayMap.size <= MAX_ENTRIES) return;

  for (const [key, entry] of replayMap.entries()) {
    if (now - entry.firstSeenAt > WINDOW_MS) {
      replayMap.delete(key);
    }
  }
}

export function isReplayAndRecord(sessionId: string, signature: string): boolean {
  const key = `${sessionId}:${signature}`;
  const now = Date.now();

  const existing = replayMap.get(key);

  if (existing && now - existing.firstSeenAt <= WINDOW_MS) {
    // Seen before in our window => replay
    return true;
  }

  // First time we see this combo (or older than window) => record it
  replayMap.set(key, { firstSeenAt: now });

  // occasional cleanup
  if (replayMap.size > MAX_ENTRIES) {
    cleanup(now);
  }

  return false;
}
