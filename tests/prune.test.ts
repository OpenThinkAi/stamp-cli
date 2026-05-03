/**
 * Tests for AGT-044 — chmod posture on openDb + the new `stamp prune`
 * retention command.
 *
 * Two threads, both via the lib + command surface (no spawn-the-CLI dance):
 *
 *   - openDb chmod posture: state.db → 0600, parent dir → 0700, idempotent
 *     across opens (existing-DB tightening, not just create-time).
 *   - runPrune: deterministic via raw INSERTs that bypass `DEFAULT
 *     (datetime('now'))` and write fixed `created_at` strings, so the
 *     "older than 7d" cutoff is wall-clock-independent.
 *
 * AC #7 is cross-checked by re-querying recentReviewsByReviewer after the
 * prune to confirm the `issues` column is still readable on surviving rows
 * (no schema migration crept in).
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import { runPrune } from "../src/commands/prune.ts";
import {
  openDb,
  peekPrunable,
  pruneReviews,
  recentReviewsByReviewer,
} from "../src/lib/db.ts";
import { parseRetentionDuration } from "../src/lib/duration.ts";
import { stampStateDbPath } from "../src/lib/paths.ts";

function git(args: string[], cwd: string): void {
  execFileSync("git", args, { cwd, stdio: "pipe" });
}

/**
 * Insert a review with an explicit `created_at` string. Bypasses the
 * schema's `DEFAULT (datetime('now'))` so tests are deterministic — a
 * "10-day-old" row will still be 10 days old next year.
 */
function insertAt(
  dbPath: string,
  reviewer: string,
  createdAt: string,
): void {
  const db = openDb(dbPath);
  try {
    const stmt = db.prepare(
      `INSERT INTO reviews (reviewer, base_sha, head_sha, verdict, issues, tool_calls, created_at)
       VALUES (?, 'b'||?, 'h'||?, 'approved', 'sample prose', NULL, ?)`,
    );
    // Tag base/head_sha with a counter so the (base,head,reviewer) index
    // doesn't conflate distinct rows; the test doesn't care which counter,
    // just that the rows are uniquely keyed.
    const id = `${reviewer}-${createdAt.replace(/[: -]/g, "")}`;
    stmt.run(reviewer, id, id, createdAt);
  } finally {
    db.close();
  }
}

describe("openDb chmod posture (AGT-044 / audit-L8)", () => {
  let tmp: string;

  beforeEach(() => {
    tmp = realpathSync(mkdtempSync(join(tmpdir(), "stamp-prune-")));
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("creates state.db at 0600 and parent dir at 0700", () => {
    const dbPath = join(tmp, "stamp", "state.db");
    const db = openDb(dbPath);
    db.close();
    assert.equal(statSync(dbPath).mode & 0o777, 0o600);
    assert.equal(statSync(join(tmp, "stamp")).mode & 0o777, 0o700);
  });

  it("tightens an existing 0644 DB and 0755 dir on re-open (idempotency)", () => {
    const stampDir = join(tmp, "stamp");
    mkdirSync(stampDir, { recursive: true, mode: 0o755 });
    chmodSync(stampDir, 0o755);

    const dbPath = join(stampDir, "state.db");
    // First open creates the DB; second open is the idempotency check —
    // chmod the file back to 0644 between opens, then re-open and assert
    // it's been re-tightened.
    let db = openDb(dbPath);
    db.close();
    chmodSync(dbPath, 0o644);
    chmodSync(stampDir, 0o755);

    db = openDb(dbPath);
    db.close();
    assert.equal(statSync(dbPath).mode & 0o777, 0o600);
    assert.equal(statSync(stampDir).mode & 0o777, 0o700);
  });

  it("tightens WAL sidecars to 0600 when SQLite has flushed them to disk", () => {
    const dbPath = join(tmp, "stamp", "state.db");
    const db = openDb(dbPath);
    // Force WAL pages to disk so -wal/-shm exist as inodes we can stat.
    // INSERT then PRAGMA wal_checkpoint(FULL) is the documented pattern.
    db.exec(
      `INSERT INTO reviews (reviewer, base_sha, head_sha, verdict)
       VALUES ('r', 'b', 'h', 'approved')`,
    );
    db.exec("PRAGMA wal_checkpoint(FULL)");
    db.close();

    // Re-open to trip the chmod-existing-sidecars branch.
    const db2 = openDb(dbPath);
    db2.close();

    for (const sidecar of [`${dbPath}-wal`, `${dbPath}-shm`]) {
      if (existsSync(sidecar)) {
        assert.equal(
          statSync(sidecar).mode & 0o777,
          0o600,
          `expected ${sidecar} to be 0600`,
        );
      }
    }
  });
});

describe("parseRetentionDuration (AGT-044)", () => {
  it("accepts <n>d / <n>h / <n>m and emits SQLite-modifier strings", () => {
    assert.deepEqual(parseRetentionDuration("30d"), {
      sqliteModifier: "-30 days",
      humanLabel: "30d",
    });
    assert.deepEqual(parseRetentionDuration("12h"), {
      sqliteModifier: "-12 hours",
      humanLabel: "12h",
    });
    assert.deepEqual(parseRetentionDuration("90m"), {
      sqliteModifier: "-90 minutes",
      humanLabel: "90m",
    });
  });

  it("rejects whitespace, leading +, zero, negatives, bare numbers, unknown units", () => {
    for (const bad of [
      "",
      " 30d",
      "30d ",
      "+30d",
      "0d",
      "-30d",
      "30",
      "30s",
      "1.5d",
      "30days",
      "thirty",
      "nope",
    ]) {
      assert.throws(
        () => parseRetentionDuration(bad),
        /invalid duration/,
        `expected "${bad}" to be rejected`,
      );
    }
  });
});

describe("pruneReviews / runPrune (AGT-044)", () => {
  let tmp: string;
  let repo: string;
  let dbPath: string;
  let prevCwd: string;

  beforeEach(() => {
    prevCwd = process.cwd();
    tmp = realpathSync(mkdtempSync(join(tmpdir(), "stamp-prune-cmd-")));
    repo = join(tmp, "repo");
    mkdirSync(repo);
    git(["init", "-q", "-b", "main", repo], tmp);
    // Set a local git identity so the `--allow-empty` commit below works on
    // CI runners that don't have a global identity configured. Same pattern
    // as tests/git.test.ts and tests/post-receive.test.ts.
    git(["config", "user.email", "t@example.com"], repo);
    git(["config", "user.name", "Test"], repo);
    git(["commit", "--allow-empty", "-q", "-m", "init"], repo);
    dbPath = stampStateDbPath(repo);
  });

  afterEach(() => {
    process.chdir(prevCwd);
    rmSync(tmp, { recursive: true, force: true });
  });

  it("deletes only rows older than the cutoff and leaves recent rows intact", () => {
    insertAt(dbPath, "security", "2024-01-01 00:00:00");
    insertAt(dbPath, "security", "2024-06-15 00:00:00");
    insertAt(dbPath, "standards", "2024-01-02 00:00:00");
    // Recent: tomorrow-ish — well within any reasonable cutoff.
    const recent = new Date(Date.now() + 60_000)
      .toISOString()
      .replace("T", " ")
      .slice(0, 19);
    insertAt(dbPath, "security", recent);

    const db = openDb(dbPath);
    try {
      const { sqliteModifier } = parseRetentionDuration("7d");
      const result = pruneReviews(db, sqliteModifier);
      assert.equal(result.total, 3);
      assert.equal(result.perReviewer.length, 2);
      // Lexicographic ordering: security < standards.
      assert.deepEqual(
        result.perReviewer.map((r) => r.reviewer),
        ["security", "standards"],
      );
      assert.equal(
        result.perReviewer.find((r) => r.reviewer === "security")!.count,
        2,
      );

      // AC #7: surviving row's `issues` column must still be readable.
      const surviving = recentReviewsByReviewer(db, "security", 10);
      assert.equal(surviving.length, 1);
      assert.equal(surviving[0]!.issues, "sample prose");
    } finally {
      db.close();
    }
  });

  it("dry-run leaves all rows in place and reports the same row set", () => {
    insertAt(dbPath, "security", "2024-01-01 00:00:00");
    insertAt(dbPath, "standards", "2024-01-02 00:00:00");

    const db = openDb(dbPath);
    let peek;
    try {
      const { sqliteModifier } = parseRetentionDuration("7d");
      peek = peekPrunable(db, sqliteModifier);
    } finally {
      db.close();
    }
    assert.equal(peek.total, 2);

    // Re-open and confirm the rows are still there.
    const db2 = openDb(dbPath);
    try {
      const sec = recentReviewsByReviewer(db2, "security", 10);
      const std = recentReviewsByReviewer(db2, "standards", 10);
      assert.equal(sec.length, 1);
      assert.equal(std.length, 1);
    } finally {
      db2.close();
    }
  });

  it("runPrune: invalid duration throws with a clear message and writes nothing", () => {
    insertAt(dbPath, "security", "2024-01-01 00:00:00");
    process.chdir(repo);
    assert.throws(
      () => runPrune({ olderThan: "nope" }),
      /invalid duration "nope"/,
    );
    // Row count unchanged.
    const db = openDb(dbPath);
    try {
      const sec = recentReviewsByReviewer(db, "security", 10);
      assert.equal(sec.length, 1);
    } finally {
      db.close();
    }
  });

  it("runPrune: no-ops cleanly when state.db doesn't exist", () => {
    process.chdir(repo);
    // No prior insertAt — state.db never created. runPrune should print
    // and return without throwing.
    const stdout = captureStdout(() =>
      runPrune({ olderThan: "30d" }),
    );
    // `note: ` prefix is the established convention for advisory no-ops
    // (matches commands/server.ts:79,98). Pinning the prefix so a future
    // refactor doesn't drop it.
    assert.match(stdout, /^note: .*state\.db does not exist/m);
    assert.ok(!existsSync(dbPath));
  });

  it("runPrune: bad duration throws even when state.db doesn't exist", () => {
    process.chdir(repo);
    // Regression for the AC #3 vs AC #6 ambiguity: a typo'd `--older-than`
    // on a fresh repo (state.db missing) must still surface the parse error
    // rather than being silently swallowed by the "nothing to prune" no-op.
    // Pins parse-before-existsSync ordering in runPrune.
    assert.ok(!existsSync(dbPath));
    assert.throws(
      () => runPrune({ olderThan: "nope" }),
      /invalid duration "nope"/,
    );
    // No state.db materialised as a side effect either.
    assert.ok(!existsSync(dbPath));
  });

  it("runPrune --dry-run emits the per-reviewer breakdown without modifying", () => {
    insertAt(dbPath, "security", "2024-01-01 00:00:00");
    insertAt(dbPath, "security", "2024-01-02 00:00:00");
    insertAt(dbPath, "standards", "2024-01-02 00:00:00");
    process.chdir(repo);

    const stdout = captureStdout(() =>
      runPrune({ olderThan: "7d", dryRun: true }),
    );
    // Dry-run uses the trailing `(dry run — no changes made)` marker
    // (matches bootstrap.ts:155 / provision.ts:113,441), not a `[dry-run]`
    // line prefix. Both shapes are agent-parseable, but only one of them
    // is the established convention.
    assert.match(stdout, /^would prune 3 rows/m);
    assert.match(stdout, /\(dry run — no changes made\)/);
    // Per-reviewer breakdown uses padEnd-aligned columns (matches
    // log.ts:165 / reviewers.ts:471). The space between name and count
    // must be at least 2 chars so the regex below tolerates the actual
    // padded width.
    assert.match(stdout, /  security {2,} 2 rows/);
    // count===1 must use the singular form. Older copies of this code
    // hardcoded "rows" at both call sites, producing "1 rows" — pin
    // the pluralisation fix on the singular case explicitly.
    assert.match(stdout, /  standards {2,} 1 row\b/);
    assert.doesNotMatch(stdout, /1 rows/);

    // Rows still present.
    const db = openDb(dbPath);
    try {
      assert.equal(recentReviewsByReviewer(db, "security", 10).length, 2);
      assert.equal(recentReviewsByReviewer(db, "standards", 10).length, 1);
    } finally {
      db.close();
    }
  });

  it("runPrune (non-dry-run): deletes, VACUUMs, and reports size delta", () => {
    insertAt(dbPath, "security", "2024-01-01 00:00:00");
    insertAt(dbPath, "standards", "2024-01-02 00:00:00");
    process.chdir(repo);

    const stdout = captureStdout(() =>
      runPrune({ olderThan: "7d" }),
    );
    assert.match(stdout, /^2 rows pruned \(2 reviewers affected\); db size \d+ → \d+ bytes/m);
    // count===1 in the live-path per-reviewer breakdown must use the
    // singular form AND the padEnd-aligned column shape. Pins both the
    // pluralisation fix and the convention alignment.
    assert.match(stdout, /  security {2,} 1 row\b/);
    assert.match(stdout, /  standards {2,} 1 row\b/);
    assert.doesNotMatch(stdout, /1 rows/);

    // Rows actually gone.
    const db = openDb(dbPath);
    try {
      assert.equal(recentReviewsByReviewer(db, "security", 10).length, 0);
      assert.equal(recentReviewsByReviewer(db, "standards", 10).length, 0);
    } finally {
      db.close();
    }
  });

  it("runPrune: prints 'nothing to prune' when no rows match", () => {
    // Recent only.
    const recent = new Date(Date.now() + 60_000)
      .toISOString()
      .replace("T", " ")
      .slice(0, 19);
    insertAt(dbPath, "security", recent);
    process.chdir(repo);

    const stdout = captureStdout(() =>
      runPrune({ olderThan: "7d" }),
    );
    // `note: ` prefix is the established advisory-no-op convention.
    assert.match(stdout, /^note: nothing to prune \(no rows older than 7d\)/m);
    // Row still there (no delete, no VACUUM).
    const db = openDb(dbPath);
    try {
      assert.equal(recentReviewsByReviewer(db, "security", 10).length, 1);
    } finally {
      db.close();
    }
  });
});

function captureStdout(fn: () => void): string {
  const chunks: string[] = [];
  const original = process.stdout.write.bind(process.stdout);
  process.stdout.write = ((chunk: string | Uint8Array): boolean => {
    chunks.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
    return true;
  }) as typeof process.stdout.write;
  try {
    fn();
  } finally {
    process.stdout.write = original;
  }
  return chunks.join("");
}
