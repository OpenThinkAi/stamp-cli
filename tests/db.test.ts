/**
 * Tests for the AGT-333 stamp 2.x DB schema extension: server-attested
 * approval columns on `reviews` (Shape A — additive columns, matching
 * the pre-existing `tool_calls` / `diff_hash` / `prompt_hash` migration
 * pattern in `db.ts`).
 *
 * Three concerns, in order of load-bearing-ness:
 *
 *   1. **1.x fixture survival (the AC4 test).** Hand-build a SQLite file
 *      with the literal 1.x base-shape `reviews` table (no `tool_calls`,
 *      no `diff_hash`, no `prompt_hash`, no server-attestation columns),
 *      seed it with rows, then open it through `openDb` and assert
 *      every row still reads back with the new columns surfacing as
 *      NULL. This is the structural proof that the migration is
 *      forward-only and data-preserving. Without this test the AC is
 *      unverified; with it, any future refactor that breaks it fails
 *      loudly. See the design contract in `db.ts` `initSchema` comments
 *      for what guarantees this rests on.
 *
 *   2. **Round-trip writer/reader for a server-attested row.** Insert
 *      via `recordReview` with `serverAttestation` populated; read back
 *      via `reviewHistory` and `serverApprovalsFor`; assert all three
 *      server fields are present and the row's `schema_version` is
 *      `REVIEW_ROW_SCHEMA_V4`. Locks in the AGT-334 read interface.
 *
 *   3. **All-or-nothing writer invariant.** A row recorded WITHOUT a
 *      `serverAttestation` writes NULL to all three columns AND NULL to
 *      `schema_version`. Conversely, the typed input shape (single
 *      object holding all three fields) makes half-populated input
 *      impossible at the call site; this test pins the behavior so a
 *      future refactor that loosens the type catches the regression.
 *
 * Pin-test: a literal-integer check that `REVIEW_ROW_SCHEMA_V4` matches
 * `CURRENT_V4_SCHEMA_VERSION` from `attestationV4.ts`. The two integers
 * are not linked at the module level (db.ts avoids importing v4 to keep
 * its dep graph leaf-ish), so a bump on one without the other would
 * silently desync rows stored in the DB from envelopes verified by the
 * pre-receive hook. This test is the bridge.
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, it } from "node:test";

import { CURRENT_V4_SCHEMA_VERSION } from "../src/lib/attestationV4.ts";
import {
  openDb,
  recordReview,
  reviewHistory,
  REVIEW_ROW_SCHEMA_V4,
  serverApprovalsFor,
} from "../src/lib/db.ts";

/**
 * Hand-build a SQLite file with the literal 1.x `reviews` table shape —
 * the schema as it existed before ANY of the additive ALTERs in
 * `initSchema`. We're not asserting against the 1.x BINARY here (the 1.x
 * binary isn't a dev dep); we're asserting against the 1.x SCHEMA, which
 * is the durable contract that defines what existing 1.x DBs in the
 * field look like on first 2.x boot.
 *
 * Crucial: do NOT include `tool_calls`, `diff_hash`, `prompt_hash`, or
 * any of the AGT-333 server-attestation columns. That's the whole point
 * — the migration has to add them and leave the seeded rows intact.
 */
function seedLegacyOneXDb(dbPath: string): void {
  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA journal_mode = WAL");
  db.exec(`
    CREATE TABLE reviews (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      reviewer    TEXT    NOT NULL,
      base_sha    TEXT    NOT NULL,
      head_sha    TEXT    NOT NULL,
      verdict     TEXT    NOT NULL CHECK (verdict IN ('approved','changes_requested','denied')),
      issues      TEXT,
      created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX idx_reviews_shas ON reviews(base_sha, head_sha, reviewer);
  `);
  // Two seed rows so the count assertion has signal.
  db.prepare(
    `INSERT INTO reviews (reviewer, base_sha, head_sha, verdict, issues)
     VALUES (?, ?, ?, ?, ?)`,
  ).run("security", "a".repeat(40), "b".repeat(40), "approved", "looks good");
  db.prepare(
    `INSERT INTO reviews (reviewer, base_sha, head_sha, verdict, issues)
     VALUES (?, ?, ?, ?, ?)`,
  ).run(
    "standards",
    "a".repeat(40),
    "b".repeat(40),
    "changes_requested",
    "rename foo to bar",
  );
  db.close();
}

describe("AGT-333: schema_version constant alignment", () => {
  it("REVIEW_ROW_SCHEMA_V4 matches CURRENT_V4_SCHEMA_VERSION", () => {
    // db.ts deliberately avoids importing the v4 module — keeps db.ts
    // a leaf in the import graph. The cost is that a bump on one
    // constant without the other would desync persisted rows from
    // envelope verification. This test is the bridge; if it fails,
    // someone bumped one and not the other.
    assert.equal(REVIEW_ROW_SCHEMA_V4, CURRENT_V4_SCHEMA_VERSION);
  });
});

describe("AGT-333: migration preserves 1.x reviews rows", () => {
  let tmp: string;
  let dbPath: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "stamp-agt333-mig-"));
    dbPath = join(tmp, "state.db");
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("opens a 1.x fixture DB without dropping rows and surfaces new columns as NULL (the AC4 test)", () => {
    seedLegacyOneXDb(dbPath);

    // Sanity: confirm the fixture is in the 1.x base shape with the seed
    // rows. If THIS fails, the fixture itself is wrong.
    {
      const raw = new DatabaseSync(dbPath);
      const colsBefore = raw
        .prepare("PRAGMA table_info(reviews)")
        .all() as Array<{ name: string }>;
      const namesBefore = new Set(colsBefore.map((c) => c.name));
      assert.ok(
        !namesBefore.has("server_approval_json"),
        "fixture should be pre-AGT-333 (no server_approval_json yet)",
      );
      assert.ok(
        !namesBefore.has("tool_calls"),
        "fixture should be the literal 1.x base shape (no tool_calls yet)",
      );
      const seedCount = (raw.prepare("SELECT COUNT(*) AS n FROM reviews").get() as {
        n: number;
      }).n;
      assert.equal(seedCount, 2);
      raw.close();
    }

    // openDb runs initSchema, which ALTERs the missing columns in.
    const db = openDb(dbPath);
    try {
      const colsAfter = db
        .prepare("PRAGMA table_info(reviews)")
        .all() as Array<{ name: string; type: string; notnull: number; dflt_value: unknown }>;
      const after = new Map(colsAfter.map((c) => [c.name, c]));

      // The four AGT-333 columns must now exist.
      for (const col of [
        "server_approval_json",
        "server_signature_b64",
        "server_key_id",
        "schema_version",
      ]) {
        assert.ok(after.has(col), `expected ${col} to exist after migration`);
      }

      // None of them may be NOT NULL or carry a default — that's what
      // makes the legacy rows survive untouched. A future change that
      // tightens these constraints would break the AC; pin it
      // structurally here.
      for (const col of [
        "server_approval_json",
        "server_signature_b64",
        "server_key_id",
        "schema_version",
      ]) {
        const meta = after.get(col)!;
        assert.equal(meta.notnull, 0, `${col} must remain nullable`);
        assert.equal(
          meta.dflt_value,
          null,
          `${col} must have no DEFAULT (legacy rows must read as NULL)`,
        );
      }

      // The load-bearing assertion: the seeded 1.x rows survive the
      // migration with their original data intact and the new columns
      // surfacing as NULL.
      const rows = db
        .prepare(
          `SELECT id, reviewer, verdict, issues,
                  tool_calls, diff_hash, prompt_hash,
                  server_approval_json, server_signature_b64, server_key_id,
                  schema_version
           FROM reviews ORDER BY id ASC`,
        )
        .all() as Array<{
        id: number;
        reviewer: string;
        verdict: string;
        issues: string | null;
        tool_calls: string | null;
        diff_hash: string | null;
        prompt_hash: string | null;
        server_approval_json: string | null;
        server_signature_b64: string | null;
        server_key_id: string | null;
        schema_version: number | null;
      }>;

      assert.equal(rows.length, 2, "both 1.x rows must survive the migration");
      assert.equal(rows[0]!.reviewer, "security");
      assert.equal(rows[0]!.verdict, "approved");
      assert.equal(rows[0]!.issues, "looks good");
      assert.equal(rows[1]!.reviewer, "standards");
      assert.equal(rows[1]!.verdict, "changes_requested");
      assert.equal(rows[1]!.issues, "rename foo to bar");

      // Every new column on every legacy row must be NULL.
      for (const r of rows) {
        assert.equal(r.tool_calls, null);
        assert.equal(r.diff_hash, null);
        assert.equal(r.prompt_hash, null);
        assert.equal(r.server_approval_json, null);
        assert.equal(r.server_signature_b64, null);
        assert.equal(r.server_key_id, null);
        assert.equal(r.schema_version, null);
      }
    } finally {
      db.close();
    }
  });

  it("re-opening the migrated DB is a no-op (PRAGMA-guarded ALTERs are idempotent)", () => {
    seedLegacyOneXDb(dbPath);
    // First open performs the ALTERs.
    openDb(dbPath).close();
    // Second open must not re-run ALTER (would throw "duplicate column").
    // If it didn't crash on the first attempt, this is the proof that
    // the PRAGMA-table_info guard works for repeat-safe migration.
    const db = openDb(dbPath);
    try {
      const count = (db
        .prepare("SELECT COUNT(*) AS n FROM reviews")
        .get() as { n: number }).n;
      assert.equal(count, 2);
    } finally {
      db.close();
    }
  });

  it("legacy rows render via reviewHistory with NULL server fields (the stamp log marker input)", () => {
    seedLegacyOneXDb(dbPath);
    const db = openDb(dbPath);
    try {
      const rows = reviewHistory(db);
      assert.equal(rows.length, 2);
      for (const r of rows) {
        // These are the two fields the SIGNED-BY marker in
        // `stamp log --reviews` reads to distinguish 1.x from 2.x rows.
        assert.equal(
          r.server_key_id,
          null,
          "legacy row server_key_id must be NULL so the marker renders as (unsigned)",
        );
        assert.equal(r.schema_version, null);
      }
    } finally {
      db.close();
    }
  });
});

describe("AGT-333: server-attested row round-trip", () => {
  let tmp: string;
  let dbPath: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "stamp-agt333-rt-"));
    dbPath = join(tmp, "state.db");
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("inserts a server-attested row and reads back all four AGT-333 fields", () => {
    const db = openDb(dbPath);
    try {
      const approval = {
        reviewer: "security",
        verdict: "approved",
        prompt_sha256: "p".repeat(64),
        diff_sha256: "d".repeat(64),
        base_sha: "a".repeat(40),
        head_sha: "b".repeat(40),
        issued_at: "2026-05-17T18:42:13Z",
        server_key_id: `sha256:${"e".repeat(64)}`,
      };
      const approvalJson = JSON.stringify(approval);
      recordReview(db, {
        reviewer: "security",
        base_sha: approval.base_sha,
        head_sha: approval.head_sha,
        verdict: "approved",
        issues: "looks good",
        serverAttestation: {
          approval_json: approvalJson,
          signature_b64: "ZmFrZS1zaWc=", // base64 placeholder; verification is out of scope here
          server_key_id: approval.server_key_id,
        },
      });

      const rows = reviewHistory(db);
      assert.equal(rows.length, 1);
      const row = rows[0]!;
      assert.equal(row.server_approval_json, approvalJson);
      assert.equal(row.server_signature_b64, "ZmFrZS1zaWc=");
      assert.equal(row.server_key_id, approval.server_key_id);
      assert.equal(row.schema_version, REVIEW_ROW_SCHEMA_V4);
    } finally {
      db.close();
    }
  });

  it("serverApprovalsFor surfaces only server-attested rows for the (base, head) pair", () => {
    const db = openDb(dbPath);
    try {
      const base = "a".repeat(40);
      const head = "b".repeat(40);

      // Legacy-style row (no serverAttestation) — must be SKIPPED by
      // serverApprovalsFor; it's not eligible input to a v4 envelope.
      recordReview(db, {
        reviewer: "legacy",
        base_sha: base,
        head_sha: head,
        verdict: "approved",
        issues: "old-school",
      });

      // Server-attested row — must appear.
      const approval = {
        reviewer: "security",
        verdict: "approved",
        prompt_sha256: "p".repeat(64),
        diff_sha256: "d".repeat(64),
        base_sha: base,
        head_sha: head,
        issued_at: "2026-05-17T18:42:13Z",
        server_key_id: `sha256:${"e".repeat(64)}`,
      };
      recordReview(db, {
        reviewer: "security",
        base_sha: base,
        head_sha: head,
        verdict: "approved",
        issues: "looks good",
        serverAttestation: {
          approval_json: JSON.stringify(approval),
          signature_b64: "c2ln",
          server_key_id: approval.server_key_id,
        },
      });

      // Different (base, head) — must NOT be returned.
      recordReview(db, {
        reviewer: "standards",
        base_sha: base,
        head_sha: "c".repeat(40),
        verdict: "approved",
        issues: "different head",
        serverAttestation: {
          approval_json: JSON.stringify({ ...approval, reviewer: "standards", head_sha: "c".repeat(40) }),
          signature_b64: "c2ln",
          server_key_id: approval.server_key_id,
        },
      });

      const found = serverApprovalsFor(db, base, head);
      assert.equal(found.length, 1, "only the server-attested (base, head) match returns");
      assert.equal(found[0]!.reviewer, "security");
      assert.equal(found[0]!.approval_json, JSON.stringify(approval));
      assert.equal(found[0]!.server_key_id, approval.server_key_id);
    } finally {
      db.close();
    }
  });

  it("serverApprovalsFor picks the latest row per reviewer (ties broken by id)", () => {
    const db = openDb(dbPath);
    try {
      const base = "a".repeat(40);
      const head = "b".repeat(40);
      const baseApproval = {
        reviewer: "security",
        verdict: "approved",
        prompt_sha256: "p".repeat(64),
        diff_sha256: "d".repeat(64),
        base_sha: base,
        head_sha: head,
        issued_at: "2026-05-17T18:42:13Z",
        server_key_id: `sha256:${"e".repeat(64)}`,
      };

      // First row — should be superseded.
      recordReview(db, {
        reviewer: "security",
        base_sha: base,
        head_sha: head,
        verdict: "approved",
        issues: "first",
        serverAttestation: {
          approval_json: JSON.stringify({ ...baseApproval, issued_at: "first" }),
          signature_b64: "c2ln",
          server_key_id: baseApproval.server_key_id,
        },
      });
      // Second row — should win.
      recordReview(db, {
        reviewer: "security",
        base_sha: base,
        head_sha: head,
        verdict: "approved",
        issues: "second (latest)",
        serverAttestation: {
          approval_json: JSON.stringify({ ...baseApproval, issued_at: "second" }),
          signature_b64: "c2ln",
          server_key_id: baseApproval.server_key_id,
        },
      });

      const found = serverApprovalsFor(db, base, head);
      assert.equal(found.length, 1);
      const parsed = JSON.parse(found[0]!.approval_json) as { issued_at: string };
      assert.equal(parsed.issued_at, "second");
    } finally {
      db.close();
    }
  });
});

describe("AGT-333: stamp log --reviews SIGNED-BY marker", () => {
  // The marker rendering logic lives in `printReviewHistory` inside
  // `src/commands/log.ts`. That function writes to console.log directly
  // (no return value to inspect), so this test captures stdout. The
  // mixed-table case is the load-bearing one: one legacy row + one
  // server-attested row, side-by-side in the same output, with each
  // marked according to the 1.x-vs-2.x distinction the AC mandates.
  //
  // We invoke `runLog` rather than `printReviewHistory` directly so the
  // test exercises the same `loadConfig`-then-render path operators
  // hit in production. That means we need a minimal .stamp/config.yml
  // alongside the state.db, which `runLog` resolves from
  // `findRepoRoot(cwd)`. Set `process.chdir` to a scratch git repo to
  // keep the test self-contained.
  let tmp: string;
  let savedCwd: string;
  let captured: string[];
  let originalLog: typeof console.log;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "stamp-agt333-log-"));
    savedCwd = process.cwd();
    captured = [];
    originalLog = console.log;
    console.log = (...args: unknown[]): void => {
      captured.push(args.map((a) => String(a)).join(" "));
    };
  });

  afterEach(() => {
    console.log = originalLog;
    process.chdir(savedCwd);
    rmSync(tmp, { recursive: true, force: true });
  });

  it("marks unsigned rows as (unsigned — no server attestation) and 2.x server-signed rows as signed-by server:<key8> in the same output", async () => {
    // Minimal git repo + .stamp scaffold + state.db. Keep this in lock-
    // step with what `runLog` reads; if `runLog` later acquires new
    // dependencies, this setup may need to grow, but today the floor is:
    // a .stamp/config.yml so loadConfig is happy + a state.db at the
    // canonical path.
    const { execFileSync } = await import("node:child_process");
    const { mkdirSync, writeFileSync } = await import("node:fs");

    execFileSync("git", ["init", "-q", "-b", "main"], { cwd: tmp });
    execFileSync("git", ["config", "user.email", "test@example.com"], { cwd: tmp });
    execFileSync("git", ["config", "user.name", "Test"], { cwd: tmp });
    mkdirSync(join(tmp, ".stamp"), { recursive: true });
    // Minimal valid config: one branch rule, no required reviewers
    // needed for the log path. `loadConfig` is permissive about empty
    // branches sections; the only requirement is the file exists and
    // parses as YAML.
    // The minimum valid config shape: `branches.<name>.required` (array
    // of reviewer names — empty is fine for this test, the log path
    // doesn't enforce reviewers) and `reviewers` (object, may be
    // empty). See `validateConfig` in `src/lib/config.ts`.
    writeFileSync(
      join(tmp, ".stamp", "config.yml"),
      "branches:\n  main:\n    required: []\nreviewers: {}\n",
    );
    // Seed an initial commit so currentBranch / commit-list paths
    // wouldn't fail if `runLog` were called without --reviews. Cheap
    // insurance; doesn't affect the --reviews path.
    writeFileSync(join(tmp, "README.md"), "scratch\n");
    execFileSync("git", ["add", "README.md"], { cwd: tmp });
    execFileSync("git", ["commit", "-q", "-m", "init"], { cwd: tmp });

    // Seed the DB at the canonical path with one legacy row and one
    // server-attested row.
    const dbPath = join(tmp, ".git", "stamp", "state.db");
    const { openDb: openDbInner, recordReview: recordReviewInner } = await import(
      "../src/lib/db.ts"
    );
    const db = openDbInner(dbPath);
    try {
      // Legacy row: no serverAttestation.
      recordReviewInner(db, {
        reviewer: "legacy-reviewer",
        base_sha: "a".repeat(40),
        head_sha: "b".repeat(40),
        verdict: "approved",
        issues: "legacy prose",
      });
      // Server-attested row.
      const approval = {
        reviewer: "security",
        verdict: "approved",
        prompt_sha256: "p".repeat(64),
        diff_sha256: "d".repeat(64),
        base_sha: "a".repeat(40),
        head_sha: "c".repeat(40),
        issued_at: "2026-05-17T18:42:13Z",
        server_key_id: `sha256:${"e".repeat(64)}`,
      };
      recordReviewInner(db, {
        reviewer: "security",
        base_sha: approval.base_sha,
        head_sha: approval.head_sha,
        verdict: "approved",
        issues: "v2 prose",
        serverAttestation: {
          approval_json: JSON.stringify(approval),
          signature_b64: "c2ln",
          server_key_id: approval.server_key_id,
        },
      });
    } finally {
      db.close();
    }

    process.chdir(tmp);
    const { runLog } = await import("../src/commands/log.ts");
    runLog({ limit: 10, reviews: true });

    const out = captured.join("\n");
    // Unsigned-row marker. Note: the label is deliberately version-
    // agnostic ("unsigned" not "unsigned 1.x") — a 2.x local-only row
    // is indistinguishable from a 1.x legacy row at the DB level, and
    // claiming "1.x" would mislabel every fresh 2.x local-only row
    // (see the comment on the else-branch in src/commands/log.ts for
    // the full rationale; this assertion is the pin that catches a
    // future regression that re-adds the version claim).
    assert.match(
      out,
      /signed-by: \(unsigned — no server attestation\)/,
      "expected unsigned row to render the (unsigned — no server attestation) marker",
    );
    assert.doesNotMatch(
      out,
      /unsigned 1\.x/,
      "marker must not claim '1.x' (would mislabel 2.x local-only rows)",
    );
    // Server-attested row marker — first 8 hex chars of "e".repeat(64)
    // is "eeeeeeee". Pin the literal so a future change to the short-
    // key length surfaces here.
    assert.match(
      out,
      /signed-by: server:eeeeeeee/,
      "expected 2.x row to render the signed-by: server:<key8> marker",
    );
    // Both rows must appear (sanity: marker assertions wouldn't catch
    // accidental row-drop).
    assert.match(out, /legacy-reviewer/);
    assert.match(out, /security/);
  });
});

describe("AGT-333: writer all-or-nothing invariant", () => {
  let tmp: string;
  let dbPath: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "stamp-agt333-inv-"));
    dbPath = join(tmp, "state.db");
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("a row recorded WITHOUT serverAttestation writes NULL to all four AGT-333 columns", () => {
    const db = openDb(dbPath);
    try {
      recordReview(db, {
        reviewer: "security",
        base_sha: "a".repeat(40),
        head_sha: "b".repeat(40),
        verdict: "approved",
        issues: "local-only mode",
      });
      const rows = reviewHistory(db);
      assert.equal(rows.length, 1);
      const r = rows[0]!;
      assert.equal(r.server_approval_json, null);
      assert.equal(r.server_signature_b64, null);
      assert.equal(r.server_key_id, null);
      assert.equal(
        r.schema_version,
        null,
        "schema_version stamped only when a serverAttestation rides with the row",
      );
    } finally {
      db.close();
    }
  });
});
