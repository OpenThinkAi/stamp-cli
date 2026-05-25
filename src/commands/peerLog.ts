/**
 * `stamp peer log` — stream/page `~/.stamp/peer-watch.log` (AGT-432 AC #7).
 *
 * Reads the NDJSON triplet log and outputs colorized or raw entries to stdout.
 *
 * Exit codes:
 *   0   — success; at least one record output
 *   1   — log file missing or empty (message to stderr)
 *   2   — arg-parse error (Commander only; not set by this command)
 *   3   — I/O error reading the log file
 */

import { readFileSync } from "node:fs";
import type { TripletRecord } from "../lib/peerWatchLog.js";
import { peerWatchLogPath } from "../lib/paths.js";

// ─── ANSI color codes ────────────────────────────────────────────────

const ANSI_RESET = "\x1b[0m";
const ANSI_DIM = "\x1b[2m";
const ANSI_CYAN = "\x1b[36m";
const ANSI_YELLOW = "\x1b[33m";
const ANSI_RED = "\x1b[31m";
const ANSI_BOLD = "\x1b[1m";

/** Map claim_seat outcome to a color prefix/suffix. */
function colorForClaimSeat(claimSeat: string): { pre: string; post: string } {
  switch (claimSeat) {
    case "skip": return { pre: ANSI_DIM, post: ANSI_RESET };
    case "if_available": return { pre: ANSI_CYAN, post: ANSI_RESET };
    case "always": return { pre: ANSI_YELLOW, post: ANSI_RESET };
    default: return { pre: "", post: "" };
  }
}

// ─── Input types ─────────────────────────────────────────────────────

export interface PeerLogOptions {
  /**
   * Show last N triplets only (0 = all).
   * Primary/canonical flag name (reviewer renamed from --last during stamp review).
   */
  limit?: number;
  /**
   * Alias for `limit` — intentional AC-7 contract alias.
   * AC-7 specifies `--last <n>`; the product reviewer renamed it to `--limit` during stamp review.
   * Both are supported so the AC contract and the review decision hold simultaneously.
   * When both are supplied to the CLI, Commander last-one-wins applies; the resolved value
   * is passed to whichever field was set by the last option parsed.
   */
  last?: number;
  /** Output uncolorized raw JSON. */
  raw?: boolean;
  /**
   * Test-only: override the log file path.
   */
  _logPathForTest?: string;
  /**
   * Test-only: override process.exit so tests can catch the exit code.
   */
  _exitForTest?: (code: number) => never;
  /**
   * Test-only: capture stdout writes.
   */
  _stdoutWriteForTest?: (line: string) => void;
  /**
   * Test-only: capture stderr writes.
   */
  _stderrWriteForTest?: (line: string) => void;
}

// ─── Implementation ──────────────────────────────────────────────────

/**
 * Core implementation of `stamp peer log`.
 */
export function runPeerLog(opts: PeerLogOptions): void {
  const exitFn = opts._exitForTest ?? ((code: number) => process.exit(code) as never);
  const stdoutWrite = opts._stdoutWriteForTest ?? ((s: string) => { process.stdout.write(s); });
  const stderrWrite = opts._stderrWriteForTest ?? ((s: string) => { process.stderr.write(s); });

  const logPath = opts._logPathForTest ?? peerWatchLogPath();

  // ─── Read log file ────────────────────────────────────────────────
  let rawContent: string;
  try {
    rawContent = readFileSync(logPath, "utf8");
  } catch (err) {
    const isNotFound =
      err instanceof Error && "code" in err && (err as NodeJS.ErrnoException).code === "ENOENT";
    if (isNotFound) {
      stderrWrite(`error: no peer-watch.log found at ${logPath}\n`);
      exitFn(1);
      return;
    }
    stderrWrite(
      `error: failed to read peer-watch.log: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    exitFn(3);
    return;
  }

  // ─── Parse NDJSON lines ───────────────────────────────────────────
  const lines = rawContent.split("\n").filter((l) => l.trim().length > 0);
  if (lines.length === 0) {
    stderrWrite(`error: no peer-watch.log found at ${logPath}\n`);
    exitFn(1);
    return;
  }

  // Parse valid lines; silently skip malformed.
  const records: TripletRecord[] = [];
  for (const line of lines) {
    try {
      const parsed = JSON.parse(line) as TripletRecord;
      records.push(parsed);
    } catch {
      // Skip malformed lines.
    }
  }

  if (records.length === 0) {
    stderrWrite(`error: no peer-watch.log found at ${logPath}\n`);
    exitFn(1);
    return;
  }

  // ─── Apply --limit / --last filter ───────────────────────────────
  // --last is an alias for --limit (AC-7 contract; see PeerLogOptions comment).
  // If both are supplied, last-one-wins as Commander parses them; we pick whichever is set.
  const limitN = opts.last ?? opts.limit ?? 0;
  const toShow = limitN > 0 ? records.slice(-limitN) : records;

  // ─── Output ───────────────────────────────────────────────────────
  const raw = opts.raw ?? false;

  for (const rec of toShow) {
    if (raw) {
      stdoutWrite(JSON.stringify(rec) + "\n");
    } else {
      const claimSeat = rec.decision.claim_seat;
      const isCapHit = rec.reason === "daily cap hit";
      const { pre, post } = colorForClaimSeat(claimSeat);

      // Build a human-readable summary line, highlighted if cap-hit.
      const capHitMark = isCapHit ? ` ${ANSI_RED}${ANSI_BOLD}[daily cap hit]${ANSI_RESET}` : "";
      const line =
        `${pre}${rec.ts}  ${rec.repo}  ${rec.pr_url}  ${claimSeat}${post}${capHitMark}\n`;
      stdoutWrite(line);
    }
  }

  exitFn(0);
}
