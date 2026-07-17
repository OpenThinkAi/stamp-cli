/**
 * Issue #59: the verdict cache must be bound to the head TREE the reviewer
 * evaluated, not just the (diff bytes, prompt bytes) pair.
 *
 * Reviewers read the working tree through their tools (Read/Grep/Glob, and
 * Bash when opted in), so the diff + prompt bytes alone do not determine the
 * LLM's input. The observed failure: a feature branch was reviewed while
 * `main` had advanced past its fork point (verdict: changes_requested,
 * influenced by tree state the branch never touched); after `git rebase
 * main` the merge-base-scoped diff bytes were unchanged, so the cache
 * replayed the stale verdict against a materially different tree. A
 * `--no-cache` fresh run approved.
 *
 * The fix keys the cache on (reviewer, diff_hash, prompt_hash, tree_sha)
 * where tree_sha = `head^{tree}`. These tests pin:
 *
 *   1. Same tuple + same tree → cache hit (anti-treadmill reuse intact:
 *      message-only amends and squashes preserve the tree).
 *   2. Same tuple + different tree → cache MISS (the #59 regression).
 *   3. Legacy rows (tree_sha NULL, recorded before the column existed)
 *      never serve from cache — fail-safe toward a fresh review.
 *   4. The additive migration gives a pre-tree_sha DB the column with
 *      NULL for existing rows, preserving row data.
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, it } from "node:test";

import { findCachedVerdict, openDb, recordReview } from "../src/lib/db.ts";

const REVIEWER = "security";
const DIFF_HASH = "d".repeat(64);
const PROMPT_HASH = "p".repeat(64);
const TREE_A = "a".repeat(40);
const TREE_B = "b".repeat(40);

describe("issue #59: verdict cache is tree-scoped", () => {
  let tmp: string;
  let dbPath: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "stamp-tree-cache-"));
    dbPath = join(tmp, "state.db");
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("hits on an identical (reviewer, diff, prompt, tree) tuple", () => {
    const db = openDb(dbPath);
    try {
      recordReview(db, {
        reviewer: REVIEWER,
        base_sha: "1".repeat(40),
        head_sha: "2".repeat(40),
        verdict: "approved",
        diff_hash: DIFF_HASH,
        prompt_hash: PROMPT_HASH,
        tree_sha: TREE_A,
      });
      assert.equal(
        findCachedVerdict(db, REVIEWER, DIFF_HASH, PROMPT_HASH, TREE_A)
          ?.verdict,
        "approved",
        "identical input incl. tree must reuse the stored verdict",
      );
    } finally {
      db.close();
    }
  });

  it("misses when only the tree differs — the post-rebase #59 repro", () => {
    const db = openDb(dbPath);
    try {
      // Pre-rebase review: changes_requested, recorded against TREE_A.
      recordReview(db, {
        reviewer: REVIEWER,
        base_sha: "1".repeat(40),
        head_sha: "2".repeat(40),
        verdict: "changes_requested",
        issues: "stale finding about code the branch never touched",
        diff_hash: DIFF_HASH,
        prompt_hash: PROMPT_HASH,
        tree_sha: TREE_A,
      });
      // Post-rebase lookup: same diff bytes (merge-base-scoped diff survived
      // the rebase byte-identical), same prompt, but the head tree now
      // includes the moved base's content. Must run fresh, not replay.
      assert.equal(
        findCachedVerdict(db, REVIEWER, DIFF_HASH, PROMPT_HASH, TREE_B),
        null,
        "a different head tree is a different review input — no cache hit",
      );
    } finally {
      db.close();
    }
  });

  it("never serves legacy rows whose tree_sha is NULL", () => {
    const db = openDb(dbPath);
    try {
      // Simulate a row recorded by a binary that predates the column:
      // recordReview without tree_sha persists NULL.
      recordReview(db, {
        reviewer: REVIEWER,
        base_sha: "1".repeat(40),
        head_sha: "2".repeat(40),
        verdict: "approved",
        diff_hash: DIFF_HASH,
        prompt_hash: PROMPT_HASH,
      });
      assert.equal(
        findCachedVerdict(db, REVIEWER, DIFF_HASH, PROMPT_HASH, TREE_A),
        null,
        "NULL-tree legacy rows are cache-ineligible (fail toward fresh)",
      );
    } finally {
      db.close();
    }
  });

  it("additive migration: a pre-tree_sha DB gains the column, existing rows read NULL", () => {
    // Hand-build the immediately-prior schema shape: reviews WITH
    // diff_hash/prompt_hash but WITHOUT tree_sha.
    {
      const raw = new DatabaseSync(dbPath);
      raw.exec(`
        CREATE TABLE reviews (
          id          INTEGER PRIMARY KEY AUTOINCREMENT,
          reviewer    TEXT    NOT NULL,
          base_sha    TEXT    NOT NULL,
          head_sha    TEXT    NOT NULL,
          verdict     TEXT    NOT NULL CHECK (verdict IN ('approved','changes_requested','denied')),
          issues      TEXT,
          tool_calls  TEXT,
          diff_hash   TEXT,
          prompt_hash TEXT,
          created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        );
      `);
      raw
        .prepare(
          `INSERT INTO reviews (reviewer, base_sha, head_sha, verdict, diff_hash, prompt_hash)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .run(
          REVIEWER,
          "1".repeat(40),
          "2".repeat(40),
          "changes_requested",
          DIFF_HASH,
          PROMPT_HASH,
        );
      raw.close();
    }

    const db = openDb(dbPath); // runs the migration
    try {
      const cols = db
        .prepare("PRAGMA table_info(reviews)")
        .all() as Array<{ name: string }>;
      assert.ok(
        cols.some((c) => c.name === "tree_sha"),
        "migration must add the tree_sha column",
      );
      const row = db
        .prepare("SELECT reviewer, verdict, tree_sha FROM reviews")
        .get() as { reviewer: string; verdict: string; tree_sha: string | null };
      assert.equal(row.reviewer, REVIEWER, "seeded row survives the ALTER");
      assert.equal(row.verdict, "changes_requested");
      assert.equal(row.tree_sha, null, "pre-existing rows read NULL tree_sha");
      // And, per the #59 fix, that surviving row must not cache-serve.
      assert.equal(
        findCachedVerdict(db, REVIEWER, DIFF_HASH, PROMPT_HASH, TREE_A),
        null,
      );
    } finally {
      db.close();
    }
  });
});
