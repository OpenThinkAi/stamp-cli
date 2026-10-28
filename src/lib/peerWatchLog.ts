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

import { createHash } from "node:crypto";
import { appendFileSync, chmodSync, mkdirSync, renameSync, statSync } from "node:fs";
import { dirname } from "node:path";
import type { TriageDecision } from "./peerTriage.js";
import { peerWatchLogPath } from "./paths.js";

// ─── Rotation policy ──────────────────────────────────────────────────

/**
 * Rotate `peer-watch.log` once it reaches this many bytes. Keeps the
 * operator log bounded so a stuck/hot listener loop can't exhaust disk
 * (a 7.9 GB file was observed in the wild — OpenThinkAi/stamp-cli#47).
 */
export const PEER_WATCH_LOG_MAX_BYTES = 50 * 1024 * 1024; // 50 MB

/** Number of rotated archives to keep: `peer-watch.log.1` … `.KEEP`. */
export const PEER_WATCH_LOG_KEEP = 3;

/**
 * Size-based rotation. If `logPath` is at/over `maxBytes`, shift the
 * archives down (`.2`→`.3`, `.1`→`.2`) and rename the live log to `.1`,
 * dropping the oldest. Best-effort: any fs error is swallowed so the
 * listener loop never crashes from rotation (matches the append contract).
 */
function rotateIfNeeded(logPath: string, maxBytes: number): void {
  let size: number;
  try {
    size = statSync(logPath).size;
  } catch {
    return; // no log yet (or unstattable) — nothing to rotate
  }
  if (size < maxBytes) return;

  // Shift archives down so `.1` is free, dropping the oldest via overwrite.
  for (let i = PEER_WATCH_LOG_KEEP - 1; i >= 1; i--) {
    try {
      renameSync(`${logPath}.${i}`, `${logPath}.${i + 1}`);
    } catch {
      /* missing source archive is fine */
    }
  }
  try {
    renameSync(logPath, `${logPath}.1`);
  } catch {
    /* best-effort: leave the live log in place if the rename fails */
  }
}

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
  /**
   * The event payload. `appendTriplet` writes it through
   * `summarizeEventPayload` (AGT-2249): routing fields are kept, the PR's
   * title/body/changed paths are replaced by hashes and counts so another
   * author's PR content does not accumulate on this machine.
   */
  event_payload: Record<string, unknown>;
  /** The triage decision that was returned. */
  decision: TriageDecision;
  /**
   * Optional event-kind tag (AGT-431). "re-review" distinguishes a
   * `re-review-requested` triage from a fresh `pr-opened` triage in the
   * triplet log. Absent for pr-opened events (for backwards compatibility).
   */
  kind?: string;
  /**
   * Optional override reason (AGT-432). Present when the listener overrides
   * the triage decision — e.g. "daily cap hit" when the cost cap is reached.
   */
  reason?: string;
}

export interface AppendTripletInput extends TripletRecord {
  /**
   * Test-only injection seam: replace real `appendFileSync`.
   * Receives (path, line) where `line` is the NDJSON string including trailing newline.
   */
  _appendForTest?: (path: string, line: string) => void;
  /** Test-only: override the log path (default: `peerWatchLogPath()`). */
  _logPathForTest?: string;
  /** Test-only: override the rotation threshold (default: `PEER_WATCH_LOG_MAX_BYTES`). */
  _maxBytesForTest?: number;
}

// ─── Payload summary (AGT-2249) ───────────────────────────────────────

/** Payload keys whose content is another author's PR text. */
const CONTENT_KEYS = ["title", "body"] as const;

function sha256Hex(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

/**
 * Reduce an event payload to what debugging a triage decision needs without
 * keeping another author's PR content: every routing field (repo, patch_id,
 * SHAs, fingerprints, pr_url, ...) is kept; `title`/`body` become
 * `<key>_sha256` + `<key>_length`; `paths_changed` becomes
 * `paths_changed_count` + `paths_changed_sha256`; `pubkey` and `signature`
 * are dropped (bulky, and the fingerprint is kept).
 */
export function summarizeEventPayload(
  payload: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(payload)) {
    if (k === "pubkey" || k === "signature") continue;
    if ((CONTENT_KEYS as readonly string[]).includes(k) && typeof v === "string") {
      out[`${k}_sha256`] = sha256Hex(v);
      out[`${k}_length`] = v.length;
      continue;
    }
    if (k === "paths_changed" && Array.isArray(v)) {
      out["paths_changed_count"] = v.length;
      out["paths_changed_sha256"] = sha256Hex(JSON.stringify(v));
      continue;
    }
    if (v !== null && typeof v === "object") continue; // nested content: drop
    out[k] = v;
  }
  return out;
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
    event_payload: summarizeEventPayload(input.event_payload),
    decision: input.decision,
    ...(input.kind !== undefined ? { kind: input.kind } : {}),
    ...(input.reason !== undefined ? { reason: input.reason } : {}),
  };

  const line = JSON.stringify(record) + "\n";
  const logPath = input._logPathForTest ?? peerWatchLogPath();

  try {
    if (input._appendForTest) {
      input._appendForTest(logPath, line);
    } else {
      // Ensure the parent dir exists before writing. AGT-2249: the log
      // names other people's PRs, so it is owner-only (0600 in a 0700
      // dir), re-applied on every append for logs created before this.
      mkdirSync(dirname(logPath), { recursive: true, mode: 0o700 });
      // Bound total size before appending (OpenThinkAi/stamp-cli#47).
      rotateIfNeeded(logPath, input._maxBytesForTest ?? PEER_WATCH_LOG_MAX_BYTES);
      appendFileSync(logPath, line, { encoding: "utf8", mode: 0o600 });
      chmodSync(logPath, 0o600);
    }
  } catch (err) {
    process.stderr.write(
      `✗ peer-watch.log write failed: ${err instanceof Error ? err.message : String(err)}\n`,
    );
  }
}
