/**
 * Peer-watch triplet logger for `stamp pr listen` (AGT-430).
 *
 * Appends a newline-delimited JSON record
 * `{ ts, repo, pr_url, rules_hash, event_payload, decision }`
 * to `~/.stamp/peer-watch.log` after each triage call (AC #6).
 *
 * Best-effort: a log-write failure logs `✗` to stderr but never aborts the
 * listener loop (crash-safety requirement, AC #2).
 *
 * Injection seam: `_appendForTest` replaces real `appendFileSync` in tests.
 */

import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { TriageDecision } from "./peerTriage.js";
import { peerWatchLogPath } from "./paths.js";

// ─── Types ────────────────────────────────────────────────────────────

export interface TripletRecord {
  /** ISO-8601 timestamp. */
  ts: string;
  /** `owner/repo` string from the event payload. */
  repo: string;
  /** Full GitHub PR URL. */
  pr_url: string;
  /** SHA-256 hex digest of the peer-watch.md bytes used for this call. */
  rules_hash: string;
  /** The raw event payload (untrusted but logged as-is for replay). */
  event_payload: Record<string, unknown>;
  /** The triage decision that was returned. */
  decision: TriageDecision;
}

export interface AppendTripletInput extends TripletRecord {
  /**
   * Test-only injection seam: replace real `appendFileSync`.
   * Receives (path, line) where `line` is the NDJSON string including trailing newline.
   */
  _appendForTest?: (path: string, line: string) => void;
}

// ─── Append ──────────────────────────────────────────────────────────

/**
 * Append one NDJSON record to `~/.stamp/peer-watch.log`.
 *
 * Creates the parent directory if needed. Silently swallows write errors
 * (logged to stderr with `✗` prefix) so the listener loop never crashes
 * from a log failure.
 */
export function appendTriplet(input: AppendTripletInput): void {
  const record: TripletRecord = {
    ts: input.ts,
    repo: input.repo,
    pr_url: input.pr_url,
    rules_hash: input.rules_hash,
    event_payload: input.event_payload,
    decision: input.decision,
  };

  const line = JSON.stringify(record) + "\n";
  const logPath = peerWatchLogPath();

  try {
    if (input._appendForTest) {
      input._appendForTest(logPath, line);
    } else {
      // Ensure the parent dir exists before writing.
      mkdirSync(dirname(logPath), { recursive: true });
      appendFileSync(logPath, line, "utf8");
    }
  } catch (err) {
    process.stderr.write(
      `✗ peer-watch.log write failed: ${err instanceof Error ? err.message : String(err)}\n`,
    );
  }
}
