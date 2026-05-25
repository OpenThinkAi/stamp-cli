/**
 * AGT-112 — retention advisory + auto-prune for `stamp review`.
 *
 * Covers AC-5:
 *   - config round-trip: accept valid retention blocks, reject invalid
 *     duration strings and non-boolean auto_prune, default-omit when absent
 *   - advisory fires when threshold exceeded (reviews + spools)
 *   - advisory does NOT fire when retention is unset or threshold not exceeded
 *   - advisory is suppressed by STAMP_SUPPRESS_LLM_NOTICE=1
 *   - auto_prune: true actually deletes overdue rows (and doesn't print advisory)
 *
 * Pattern mirrors tests/dataFlow.test.ts: `captureStderr` helper + deterministic
 * raw-INSERT rows with fixed `created_at` (the technique prune.test.ts uses
 * for wall-clock-independent cutoffs).
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import { parseConfigFromYaml } from "../src/lib/config.ts";
import type { RetentionConfig } from "../src/lib/config.ts";
import {
  formatRetentionAdvisory,
  printRetentionAdvisory,
} from "../src/commands/retentionAdvisory.ts";
import { openDb, peekPrunable, recentReviewsByReviewer } from "../src/lib/db.ts";
import { stampStateDbPath } from "../src/lib/paths.ts";

function git(args: string[], cwd: string): void {
  execFileSync("git", args, { cwd, stdio: "pipe" });
}

// Capture everything written to process.stderr during `fn`.
function captureStderr(fn: () => void): string {
  const orig = process.stderr.write.bind(process.stderr);
  let out = "";
  // @ts-expect-error narrow override of the write signature for the test
  process.stderr.write = (chunk: string | Uint8Array): boolean => {
    out += typeof chunk === "string" ? chunk : Buffer.from(chunk).toString();
    return true;
  };
  try {
    fn();
  } finally {
    process.stderr.write = orig;
  }
  return out;
}

/**
 * Insert a review with an explicit `created_at` string. Bypasses the
 * schema's DEFAULT (datetime('now')) so tests are deterministic.
 */
function insertAt(dbPath: string, reviewer: string, createdAt: string): void {
  const db = openDb(dbPath);
  try {
    const stmt = db.prepare(
      `INSERT INTO reviews (reviewer, base_sha, head_sha, verdict, issues, tool_calls, created_at)
       VALUES (?, 'b'||?, 'h'||?, 'approved', 'sample prose', NULL, ?)`,
    );
    const id = `${reviewer}-${createdAt.replace(/[: -]/g, "")}`;
    stmt.run(reviewer, id, id, createdAt);
  } finally {
    db.close();
  }
}

const BASE_CONFIG = `
branches:
  main:
    required: [security]
reviewers:
  security:
    prompt: .stamp/reviewers/security.md
`;

// ─── Config round-trip ────────────────────────────────────────────────────────

describe("retention config parsing (AC-5 round-trip)", () => {
  it("absence leaves retention undefined (additive / back-compat)", () => {
    const cfg = parseConfigFromYaml(BASE_CONFIG);
    assert.equal(cfg.retention, undefined);
  });

  it("parses reviews + spools + auto_prune when all present", () => {
    const cfg = parseConfigFromYaml(
      BASE_CONFIG +
        `
retention:
  reviews: 90d
  spools: 30d
  auto_prune: true
`,
    );
    assert.deepEqual(cfg.retention, {
      reviews: "90d",
      spools: "30d",
      auto_prune: true,
    });
  });

  it("parses partial block — reviews only", () => {
    const cfg = parseConfigFromYaml(
      BASE_CONFIG + `\nretention:\n  reviews: 7d\n`,
    );
    assert.deepEqual(cfg.retention, { reviews: "7d" });
  });

  it("parses partial block — spools only", () => {
    const cfg = parseConfigFromYaml(
      BASE_CONFIG + `\nretention:\n  spools: 14d\n`,
    );
    assert.deepEqual(cfg.retention, { spools: "14d" });
  });

  it("round-trips with hours and minutes", () => {
    const cfg = parseConfigFromYaml(
      BASE_CONFIG + `\nretention:\n  reviews: 12h\n  spools: 90m\n`,
    );
    assert.deepEqual(cfg.retention, { reviews: "12h", spools: "90m" });
  });

  it("rejects non-object retention", () => {
    assert.throws(
      () => parseConfigFromYaml(BASE_CONFIG + `\nretention: "nope"\n`),
      /config\.retention must be an object/,
    );
  });

  it("rejects invalid duration in reviews", () => {
    assert.throws(
      () => parseConfigFromYaml(BASE_CONFIG + `\nretention:\n  reviews: "0d"\n`),
      /config\.retention\.reviews.*invalid duration/,
    );
    assert.throws(
      () =>
        parseConfigFromYaml(BASE_CONFIG + `\nretention:\n  reviews: "forever"\n`),
      /config\.retention\.reviews.*invalid duration/,
    );
  });

  it("rejects invalid duration in spools", () => {
    assert.throws(
      () =>
        parseConfigFromYaml(BASE_CONFIG + `\nretention:\n  spools: "-5d"\n`),
      /config\.retention\.spools.*invalid duration/,
    );
  });

  it("rejects non-boolean auto_prune", () => {
    assert.throws(
      () =>
        parseConfigFromYaml(
          BASE_CONFIG + `\nretention:\n  reviews: 30d\n  auto_prune: "yes"\n`,
        ),
      /config\.retention\.auto_prune must be a boolean/,
    );
  });

  it("rejects non-string reviews / spools", () => {
    assert.throws(
      () =>
        parseConfigFromYaml(BASE_CONFIG + `\nretention:\n  reviews: 30\n`),
      /config\.retention\.reviews must be a string/,
    );
    assert.throws(
      () =>
        parseConfigFromYaml(BASE_CONFIG + `\nretention:\n  spools: 30\n`),
      /config\.retention\.spools must be a string/,
    );
  });

  it("omit-on-unset: auto_prune absent → no auto_prune key in parsed object", () => {
    const cfg = parseConfigFromYaml(
      BASE_CONFIG + `\nretention:\n  reviews: 30d\n`,
    );
    assert.ok(!("auto_prune" in (cfg.retention ?? {})));
  });
});

// ─── formatRetentionAdvisory (pure) ──────────────────────────────────────────

describe("formatRetentionAdvisory (pure formatter)", () => {
  it("returns empty array when count is 0", () => {
    assert.deepEqual(formatRetentionAdvisory(0, "reviews", "90d"), []);
    assert.deepEqual(formatRetentionAdvisory(0, "spools", "30d"), []);
  });

  it("singular review", () => {
    const lines = formatRetentionAdvisory(1, "reviews", "90d");
    assert.equal(lines.length, 1);
    assert.match(lines[0]!, /1 review older than 90d/);
    assert.match(lines[0]!, /stamp prune --older-than 90d/);
  });

  it("plural reviews", () => {
    const lines = formatRetentionAdvisory(5, "reviews", "30d");
    assert.equal(lines.length, 1);
    assert.match(lines[0]!, /5 reviews older than 30d/);
  });

  it("singular spool file", () => {
    const lines = formatRetentionAdvisory(1, "spools", "7d");
    assert.equal(lines.length, 1);
    assert.match(lines[0]!, /1 spool file older than 7d/);
  });

  it("plural spool files", () => {
    const lines = formatRetentionAdvisory(3, "spools", "14d");
    assert.equal(lines.length, 1);
    assert.match(lines[0]!, /3 spool files older than 14d/);
  });

  it("advisory lines lead with 'note:'", () => {
    const lines = formatRetentionAdvisory(2, "reviews", "90d");
    assert.match(lines[0]!, /^note:/);
  });
});

// ─── printRetentionAdvisory (integration with db + spool dirs) ───────────────

describe("printRetentionAdvisory (integration)", () => {
  let tmp: string;
  let repo: string;
  let dbPath: string;
  let savedSuppress: string | undefined;
  let prevCwd: string;

  beforeEach(() => {
    prevCwd = process.cwd();
    savedSuppress = process.env.STAMP_SUPPRESS_LLM_NOTICE;
    delete process.env.STAMP_SUPPRESS_LLM_NOTICE;

    tmp = realpathSync(mkdtempSync(join(tmpdir(), "stamp-retention-")));
    repo = join(tmp, "repo");
    mkdirSync(repo);
    git(["init", "-q", "-b", "main", repo], tmp);
    git(["config", "user.email", "t@example.com"], repo);
    git(["config", "user.name", "Test"], repo);
    git(["commit", "--allow-empty", "-q", "-m", "init"], repo);
    dbPath = stampStateDbPath(repo);
    process.chdir(repo);
  });

  afterEach(() => {
    process.chdir(prevCwd);
    if (savedSuppress === undefined)
      delete process.env.STAMP_SUPPRESS_LLM_NOTICE;
    else process.env.STAMP_SUPPRESS_LLM_NOTICE = savedSuppress;
    rmSync(tmp, { recursive: true, force: true });
  });

  it("no-ops when retention is undefined", () => {
    const db = openDb(dbPath);
    try {
      const out = captureStderr(() =>
        printRetentionAdvisory(db, repo, undefined),
      );
      assert.equal(out, "");
    } finally {
      db.close();
    }
  });

  it("no-ops when retention block has no thresholds set", () => {
    const db = openDb(dbPath);
    try {
      const out = captureStderr(() =>
        printRetentionAdvisory(db, repo, {} as RetentionConfig),
      );
      assert.equal(out, "");
    } finally {
      db.close();
    }
  });

  it("advisory fires for reviews when threshold is exceeded", () => {
    // Insert an old row
    insertAt(dbPath, "security", "2024-01-01 00:00:00");
    const db = openDb(dbPath);
    try {
      const out = captureStderr(() =>
        printRetentionAdvisory(db, repo, { reviews: "7d" }),
      );
      assert.match(out, /note:/);
      assert.match(out, /1 review older than 7d/);
      assert.match(out, /stamp prune --older-than 7d/);
    } finally {
      db.close();
    }
  });

  it("advisory does NOT fire when no rows exceed the threshold", () => {
    // Insert a fresh row (future timestamp)
    const future = new Date(Date.now() + 60_000)
      .toISOString()
      .replace("T", " ")
      .slice(0, 19);
    insertAt(dbPath, "security", future);
    const db = openDb(dbPath);
    try {
      const out = captureStderr(() =>
        printRetentionAdvisory(db, repo, { reviews: "7d" }),
      );
      assert.equal(out, "");
    } finally {
      db.close();
    }
  });

  it("advisory does NOT fire when retention.reviews is unset (even with old rows)", () => {
    insertAt(dbPath, "security", "2024-01-01 00:00:00");
    const db = openDb(dbPath);
    try {
      // Only spools is set, no reviews threshold
      const out = captureStderr(() =>
        printRetentionAdvisory(db, repo, { spools: "7d" }),
      );
      // spools dir doesn't exist → advisory for spools won't fire either
      assert.equal(out, "");
    } finally {
      db.close();
    }
  });

  it("advisory fires for spools when threshold is exceeded", () => {
    // Stage an old spool file
    const spoolDir = join(repo, ".git", "stamp", "failed-parses");
    mkdirSync(spoolDir, { recursive: true });
    const spoolFile = join(spoolDir, "old-spool.txt");
    writeFileSync(spoolFile, "fake raw model output");
    // Set mtime to 30 days ago
    const mtimeSec = (Date.now() - 30 * 86_400_000) / 1000;
    utimesSync(spoolFile, mtimeSec, mtimeSec);

    const db = openDb(dbPath);
    try {
      const out = captureStderr(() =>
        printRetentionAdvisory(db, repo, { spools: "7d" }),
      );
      assert.match(out, /note:/);
      assert.match(out, /1 spool file older than 7d/);
      assert.match(out, /stamp prune --older-than 7d/);
    } finally {
      db.close();
    }
  });

  it("advisory fires for both reviews and spools when both configured and exceeded", () => {
    insertAt(dbPath, "security", "2024-01-01 00:00:00");
    const spoolDir = join(repo, ".git", "stamp", "failed-parses");
    mkdirSync(spoolDir, { recursive: true });
    const spoolFile = join(spoolDir, "old-spool.txt");
    writeFileSync(spoolFile, "fake spool");
    const mtimeSec = (Date.now() - 30 * 86_400_000) / 1000;
    utimesSync(spoolFile, mtimeSec, mtimeSec);

    const db = openDb(dbPath);
    try {
      const out = captureStderr(() =>
        printRetentionAdvisory(db, repo, { reviews: "7d", spools: "7d" }),
      );
      assert.match(out, /1 review older than 7d/);
      assert.match(out, /1 spool file older than 7d/);
    } finally {
      db.close();
    }
  });

  it("advisory is suppressed by STAMP_SUPPRESS_LLM_NOTICE=1", () => {
    process.env.STAMP_SUPPRESS_LLM_NOTICE = "1";
    insertAt(dbPath, "security", "2024-01-01 00:00:00");
    const db = openDb(dbPath);
    try {
      const out = captureStderr(() =>
        printRetentionAdvisory(db, repo, { reviews: "7d" }),
      );
      assert.equal(out, "");
    } finally {
      db.close();
    }
  });

  it("reviews advisory skips structurally when db is null; spools advisory still fires", () => {
    // When db is null, the reviews advisory skip is a structural null check,
    // not a suppress-based skip. The spools advisory still runs independently.
    const spoolDir = join(repo, ".git", "stamp", "failed-parses");
    mkdirSync(spoolDir, { recursive: true });
    const spoolFile = join(spoolDir, "old-spool.txt");
    writeFileSync(spoolFile, "fake spool");
    const mtimeSec = (Date.now() - 30 * 86_400_000) / 1000;
    utimesSync(spoolFile, mtimeSec, mtimeSec);

    // null db → reviews advisory skipped, spools advisory still runs
    const out = captureStderr(() =>
      printRetentionAdvisory(null, repo, { reviews: "7d", spools: "7d" }),
    );
    assert.match(out, /1 spool file older than 7d/);
    // No reviews advisory since db is null
    assert.doesNotMatch(out, /review older than/);
  });

  it("auto_prune: true deletes overdue rows instead of advising", () => {
    insertAt(dbPath, "security", "2024-01-01 00:00:00");
    insertAt(dbPath, "standards", "2024-06-01 00:00:00");

    // Confirm 2 old rows exist before auto-prune
    const dbBefore = openDb(dbPath);
    try {
      const { sqliteModifier } = { sqliteModifier: "-7 days" };
      const peek = peekPrunable(dbBefore, sqliteModifier);
      assert.equal(peek.total, 2);
    } finally {
      dbBefore.close();
    }

    // Auto-prune: open a new db handle and call the advisory
    const db = openDb(dbPath);
    let stderrOut = "";
    try {
      stderrOut = captureStderr(() =>
        printRetentionAdvisory(db, repo, { reviews: "7d", auto_prune: true }),
      );
    } finally {
      db.close();
    }

    // No advisory line (auto-prune mode emits runPrune's stdout, not advisory)
    assert.doesNotMatch(stderrOut, /note:.*review older than/);

    // Rows actually deleted
    const dbAfter = openDb(dbPath);
    try {
      assert.equal(recentReviewsByReviewer(dbAfter, "security", 10).length, 0);
      assert.equal(recentReviewsByReviewer(dbAfter, "standards", 10).length, 0);
    } finally {
      dbAfter.close();
    }
  });

  it("auto_prune: dual thresholds — both reviews and spools honored independently", () => {
    // When reviews and spools differ, auto_prune must honour both. Stage an
    // old review row (> 7d) and an old spool file (> 3d) — then configure
    // reviews: 7d, spools: 3d, auto_prune: true. Both should be deleted.
    insertAt(dbPath, "security", "2024-01-01 00:00:00");
    const spoolDir = join(repo, ".git", "stamp", "failed-parses");
    mkdirSync(spoolDir, { recursive: true });
    const spoolFile = join(spoolDir, "old-spool.txt");
    writeFileSync(spoolFile, "fake raw output");
    // 5 days old — older than 3d threshold but younger than 7d threshold
    const mtimeSec = (Date.now() - 5 * 86_400_000) / 1000;
    utimesSync(spoolFile, mtimeSec, mtimeSec);

    const db = openDb(dbPath);
    try {
      captureStderr(() =>
        printRetentionAdvisory(db, repo, {
          reviews: "7d",
          spools: "3d",
          auto_prune: true,
        }),
      );
    } finally {
      db.close();
    }

    // Review row deleted by the reviews threshold (7d pass)
    const dbAfter = openDb(dbPath);
    try {
      assert.equal(recentReviewsByReviewer(dbAfter, "security", 10).length, 0);
    } finally {
      dbAfter.close();
    }
    // Spool file deleted by the spools threshold (3d pass)
    assert.ok(!existsSync(spoolFile));
  });

  it("auto_prune: false (explicit) uses advisory-only path", () => {
    insertAt(dbPath, "security", "2024-01-01 00:00:00");
    const db = openDb(dbPath);
    try {
      const out = captureStderr(() =>
        printRetentionAdvisory(db, repo, {
          reviews: "7d",
          auto_prune: false,
        }),
      );
      // Advisory fires, row not deleted
      assert.match(out, /note:/);
    } finally {
      db.close();
    }

    // Row still present
    const dbCheck = openDb(dbPath);
    try {
      assert.equal(recentReviewsByReviewer(dbCheck, "security", 10).length, 1);
    } finally {
      dbCheck.close();
    }
  });

  it("no-ops cleanly when db is null and no spool dirs exist", () => {
    // Fresh state — no state.db, no spool dirs
    const out = captureStderr(() =>
      printRetentionAdvisory(null, repo, { reviews: "7d", spools: "7d" }),
    );
    assert.equal(out, "");
  });
});
