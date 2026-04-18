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
  created_at: string;
}

export interface RecordReviewInput {
  reviewer: string;
  base_sha: string;
  head_sha: string;
  verdict: Verdict;
  issues?: string | null;
}

export function openDb(path: string): DatabaseSync {
  ensureDir(dirname(path));
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL");
  db.exec("PRAGMA foreign_keys = ON");
  initSchema(db);
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
      created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_reviews_shas
      ON reviews(base_sha, head_sha, reviewer);
  `);
}

export function recordReview(
  db: DatabaseSync,
  input: RecordReviewInput,
): number {
  const stmt = db.prepare(
    `INSERT INTO reviews (reviewer, base_sha, head_sha, verdict, issues)
     VALUES (?, ?, ?, ?, ?)`,
  );
  const result = stmt.run(
    input.reviewer,
    input.base_sha,
    input.head_sha,
    input.verdict,
    input.issues ?? null,
  );
  return Number(result.lastInsertRowid);
}

export interface LatestVerdict {
  reviewer: string;
  verdict: Verdict;
}

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
  const stmt = db.prepare(`
    SELECT reviewer, verdict
    FROM (
      SELECT
        reviewer,
        verdict,
        ROW_NUMBER() OVER (
          PARTITION BY reviewer
          ORDER BY created_at DESC, id DESC
        ) AS rn
      FROM reviews
      WHERE base_sha = ? AND head_sha = ?
    )
    WHERE rn = 1
  `);
  return stmt.all(base_sha, head_sha) as LatestVerdict[];
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
  return stmt.all(limit) as ReviewRow[];
}
