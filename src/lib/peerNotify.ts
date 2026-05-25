/**
 * Fire-and-forget desktop notification helper for `stamp pr listen` (AGT-432).
 *
 * Uses `osascript -e 'display notification ...'` via `spawn` to deliver a
 * macOS desktop notification. All errors are swallowed — a notification failure
 * must never crash or stall the listener loop.
 *
 * No new runtime dependencies — `node-notifier` is NOT in the dep tree.
 */

import { spawn } from "node:child_process";

// ─── Types ────────────────────────────────────────────────────────────

export interface PeerNotifyInput {
  title: string;
  body: string;
  /**
   * Test-only injection seam: replace the real `osascript` spawn.
   * Receives (title, body) and returns void (or throws — both are swallowed).
   */
  _notifyForTest?: (title: string, body: string) => void;
}

// ─── Implementation ──────────────────────────────────────────────────

/**
 * Fire a macOS desktop notification with the given title and body.
 *
 * Fire-and-forget: returns immediately without waiting for `osascript` to
 * complete. Swallows all errors (spawn failure, non-zero exit, etc.).
 */
export function firePeerNotification(input: PeerNotifyInput): void {
  // Test seam: use injected notifier instead of real osascript.
  if (input._notifyForTest) {
    try {
      input._notifyForTest(input.title, input.body);
    } catch {
      // Swallow — notification failures must never crash the listener.
    }
    return;
  }

  // Production: fire-and-forget osascript invocation.
  // Escape single-quotes in title and body so they don't break the AppleScript string.
  const safeTitle = input.title.replace(/'/g, "\\'");
  const safeBody = input.body.replace(/'/g, "\\'");
  const script = `display notification "${safeBody}" with title "${safeTitle}"`;

  try {
    const child = spawn("osascript", ["-e", script], {
      stdio: "ignore",
      detached: false,
    });
    // Swallow spawn errors and non-zero exits silently.
    child.on("error", () => { /* intentionally ignored */ });
  } catch {
    // spawn() itself can throw synchronously on some platforms — swallow.
  }
}
