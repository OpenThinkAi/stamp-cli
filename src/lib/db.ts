import { chmodSync, existsSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { dirname } from "node:path";
import { ensureDir } from "./paths.js";

export type Verdict = "approved" | "changes_requested" | "denied";

export interface ReviewRow {
  id: number;
  reviewer: string;
  base_sha: string;
  head_sha: string;
  verdict: Verdict;
  issues: string | null;
  /** JSON-encoded ToolCall[] (see lib/toolCalls.ts), or null for reviews
   *  recorded before Step 4 shipped or where no tools were invoked. */
  tool_calls: string | null;
  created_at: string;
}

export interface RecordReviewInput {
  reviewer: string;
  base_sha: string;
  head_sha: string;
  verdict: Verdict;
  issues?: string | null;
  /** JSON-encoded ToolCall[] or null. See lib/toolCalls.ts. */
  tool_calls?: string | null;
}

export function openDb(path: string): DatabaseSync {
  // Tighten parent directory to 0700 so peer users on shared/dev machines
  // can't enter `.git/stamp/` to read state.db (or its WAL sidecars). Done
  // before opening the DB so a brand-new file inherits the locked-down
  // ancestor. Idempotent: chmodSync runs on every open even if ensureDir
  // no-oped, which tightens an already-existing 0755 dir from prior versions.
  const dir = dirname(path);
  ensureDir(dir, 0o700);
  chmodSync(dir, 0o700);

  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL");
  db.exec("PRAGMA foreign_keys = ON");
  initSchema(db);

  // Tighten state.db itself plus the WAL sidecars (if SQLite has created
  // them — `-wal` and `-shm` only exist while WAL writes are in flight or
  // recently flushed). chmodSync targets the inode, not any open fd, so
  // this is idempotent across opens; an in-flight write keeps its old fd
  // mode but the on-disk bits flip immediately.
  chmodSync(path, 0o600);
  for (const sidecar of [`${path}-wal`, `${path}-shm`]) {
    if (existsSync(sidecar)) chmodSync(sidecar, 0o600);
  }

  return db;
}

function initSchema(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS reviews (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      reviewer    TEXT    NOT NULL,
      base_sha    TEXT    NOT NULL,
      head_sha    TEXT    NOT NULL,
      verdict     TEXT    NOT NULL CHECK (verdict IN ('approved','changes_requested','denied')),
      issues      TEXT,
      tool_calls  TEXT,
      created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_reviews_shas
      ON reviews(base_sha, head_sha, reviewer);
  `);

  // Migration for DBs created before Step 4 shipped — tool_calls column
  // wasn't in the original schema. PRAGMA table_info lists columns; if
  // tool_calls is absent, add it. Idempotent: repeat opens no-op.
  const cols = db.prepare("PRAGMA table_info(reviews)").all() as Array<{ name: string }>;
  if (!cols.some((c) => c.name === "tool_calls")) {
    db.exec("ALTER TABLE reviews ADD COLUMN tool_calls TEXT");
  }
}

export function recordReview(
  db: DatabaseSync,
  input: RecordReviewInput,
): number {
  const stmt = db.prepare(
    `INSERT INTO reviews (reviewer, base_sha, head_sha, verdict, issues, tool_calls)
     VALUES (?, ?, ?, ?, ?, ?)`,
  );
  const result = stmt.run(
    input.reviewer,
    input.base_sha,
    input.head_sha,
    input.verdict,
    input.issues ?? null,
    input.tool_calls ?? null,
  );
  return Number(result.lastInsertRowid);
}

export interface LatestVerdict {
  reviewer: string;
  verdict: Verdict;
}

export interface LatestReview {
  id: number;
  reviewer: string;
  verdict: Verdict;
  issues: string | null;
  tool_calls: string | null;
}

const LATEST_VERDICTS_SQL = `
  SELECT id, reviewer, verdict, issues, tool_calls
  FROM (
    SELECT
      id,
      reviewer,
      verdict,
      issues,
      tool_calls,
      ROW_NUMBER() OVER (
        PARTITION BY reviewer
        ORDER BY created_at DESC, id DESC
      ) AS rn
    FROM reviews
    WHERE base_sha = ? AND head_sha = ?
  )
  WHERE rn = 1
`;

/**
 * For a given (base_sha, head_sha), return the latest verdict per reviewer.
 * Uses ROW_NUMBER() window function with (created_at DESC, id DESC) ordering
 * so same-second inserts tiebreak on insertion order.
 */
export function latestVerdicts(
  db: DatabaseSync,
  base_sha: string,
  head_sha: string,
): LatestVerdict[] {
  const stmt = db.prepare(LATEST_VERDICTS_SQL);
  return stmt.all(base_sha, head_sha) as unknown as LatestVerdict[];
}

/**
 * Same as latestVerdicts but also returns prose (for computing review_sha
 * during attestation, or for display).
 */
export function latestReviews(
  db: DatabaseSync,
  base_sha: string,
  head_sha: string,
): LatestReview[] {
  const stmt = db.prepare(LATEST_VERDICTS_SQL);
  return stmt.all(base_sha, head_sha) as unknown as LatestReview[];
}

export function reviewHistory(
  db: DatabaseSync,
  opts: { limit?: number } = {},
): ReviewRow[] {
  const limit = opts.limit ?? 50;
  const stmt = db.prepare(`
    SELECT id, reviewer, base_sha, head_sha, verdict, issues, created_at
    FROM reviews
    ORDER BY created_at DESC, id DESC
    LIMIT ?
  `);
  return stmt.all(limit) as unknown as ReviewRow[];
}

export interface ReviewerStats {
  reviewer: string;
  total: number;
  approved: number;
  changes_requested: number;
  denied: number;
  first_seen: string | null;
  last_seen: string | null;
}

export function reviewerStats(
  db: DatabaseSync,
  reviewer: string,
): ReviewerStats {
  const stmt = db.prepare(`
    SELECT
      COUNT(*) AS total,
      SUM(CASE WHEN verdict = 'approved'          THEN 1 ELSE 0 END) AS approved,
      SUM(CASE WHEN verdict = 'changes_requested' THEN 1 ELSE 0 END) AS changes_requested,
      SUM(CASE WHEN verdict = 'denied'            THEN 1 ELSE 0 END) AS denied,
      MIN(created_at) AS first_seen,
      MAX(created_at) AS last_seen
    FROM reviews
    WHERE reviewer = ?
  `);
  const row = stmt.get(reviewer) as {
    total: number;
    approved: number | null;
    changes_requested: number | null;
    denied: number | null;
    first_seen: string | null;
    last_seen: string | null;
  };
  return {
    reviewer,
    total: row.total ?? 0,
    approved: row.approved ?? 0,
    changes_requested: row.changes_requested ?? 0,
    denied: row.denied ?? 0,
    first_seen: row.first_seen,
    last_seen: row.last_seen,
  };
}

export function recentReviewsByReviewer(
  db: DatabaseSync,
  reviewer: string,
  limit: number,
): ReviewRow[] {
  const stmt = db.prepare(`
    SELECT id, reviewer, base_sha, head_sha, verdict, issues, created_at
    FROM reviews
    WHERE reviewer = ?
    ORDER BY created_at DESC, id DESC
    LIMIT ?
  `);
  return stmt.all(reviewer, limit) as unknown as ReviewRow[];
}

export interface PrunePerReviewer {
  reviewer: string;
  count: number;
}

export interface PrunePeekResult {
  total: number;
  perReviewer: PrunePerReviewer[];
}

/**
 * Count rows older than `now − sqliteModifier` per reviewer, without
 * deleting. Mirrors the row set that `pruneReviews` would delete given the
 * same modifier. Used by `--dry-run` and to compute the "reviewers affected"
 * count surfaced in non-dry-run output.
 *
 * `sqliteModifier` is a string suitable for SQLite's `datetime('now', ?)`
 * (e.g. `-30 days`, `-12 hours`); produced by parseRetentionDuration so the
 * cutoff is computed inside SQLite — avoids any wall-clock fencepost
 * between JS `Date.now()` and the `created_at` strings written via
 * `datetime('now')` at insert time.
 */
export function peekPrunable(
  db: DatabaseSync,
  sqliteModifier: string,
): PrunePeekResult {
  const stmt = db.prepare(`
    SELECT reviewer, COUNT(*) AS count
    FROM reviews
    WHERE created_at < datetime('now', ?)
    GROUP BY reviewer
    ORDER BY reviewer
  `);
  const rows = stmt.all(sqliteModifier) as unknown as PrunePerReviewer[];
  const total = rows.reduce((sum, r) => sum + r.count, 0);
  return { total, perReviewer: rows };
}

/**
 * Delete rows older than `now − sqliteModifier`. Returns the same shape as
 * peekPrunable but with the actual deleted-row counts. The DELETE runs in
 * a single statement; callers must run VACUUM separately (and outside any
 * transaction) to actually shrink the file.
 */
export function pruneReviews(
  db: DatabaseSync,
  sqliteModifier: string,
): PrunePeekResult {
  const peek = peekPrunable(db, sqliteModifier);
  if (peek.total === 0) return peek;
  const del = db.prepare(
    "DELETE FROM reviews WHERE created_at < datetime('now', ?)",
  );
  del.run(sqliteModifier);
  return peek;
}
