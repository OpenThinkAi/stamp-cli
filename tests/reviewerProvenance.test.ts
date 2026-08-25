/**
 * AGT-1137: reviewer provenance — which backend kind, which model, which
 * endpoint produced each verdict.
 *
 * Five concerns, in order of load-bearing-ness:
 *
 *   1. **Pre-provenance row survival (AC1).** Hand-build a SQLite file at
 *      the immediately-prior `reviews` shape (every column through `branch`,
 *      none of the three provenance columns), seed it, open it through
 *      `openDb`, and assert the rows survive with the new columns NULL and
 *      render as `unknown`. Never crash, never back-fill a guess — a row
 *      written before this shipped genuinely does not know what reviewed it.
 *
 *   2. **Cross-backend cache isolation (AC6).** The verdict cache IS the
 *      `reviews` table (`findCachedVerdict` queries it by reviewer + hashes),
 *      so this is a property of that query, not of a separate cache module.
 *      A verdict minted by one backend/model/endpoint must never be replayed
 *      for a review requested against a different one.
 *
 *   3. **Backend → provenance derivation.** `backendProvenance` is the single
 *      place the resolver's `ReviewerBackend` becomes a stored record, so the
 *      endpoint-default resolution (an unset `local_endpoint` still records
 *      the URL that will actually be hit) is pinned here.
 *
 *   4. **Attestation compatibility (AC4).** The payload field is additive and
 *      optional: `CURRENT_PAYLOAD_VERSION` does NOT move, an attestation
 *      minted before the field still parses and reads as `unknown`, and one
 *      carrying the field round-trips through the base64 trailer.
 *
 *   5. **`stamp log --reviews` rendering (AC2).** A provenance row and a
 *      pre-provenance row side by side in one output, each marked honestly.
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, it } from "node:test";

import {
  CURRENT_PAYLOAD_VERSION,
  parseCommitAttestation,
  formatTrailers,
  type AttestationPayload,
} from "../src/lib/attestation.ts";
import {
  findCachedVerdict,
  openDb,
  recordReview,
  reviewHistory,
} from "../src/lib/db.ts";
import { LOCAL_DEFAULT_BASE_URL } from "../src/lib/localReviewClient.ts";
import {
  backendProvenance,
  formatAttestedProvenance,
  formatProvenance,
  provenanceForAttestation,
  provenanceFromRow,
  PROVENANCE_KIND_ANTHROPIC,
  PROVENANCE_KIND_OPENAI_COMPATIBLE,
  PROVENANCE_KIND_SERVER,
  serverReviewProvenance,
  type ReviewProvenance,
} from "../src/lib/provenance.ts";

const REVIEWER = "security";
const DIFF_HASH = "d".repeat(64);
const PROMPT_HASH = "p".repeat(64);
const TREE_SHA = "t".repeat(40);
const BASE_SHA = "1".repeat(40);
const HEAD_SHA = "2".repeat(40);
const BRANCH = "feature-x";

const ANTHROPIC: ReviewProvenance = {
  backend_kind: PROVENANCE_KIND_ANTHROPIC,
  backend_model: "claude-opus-5",
  backend_endpoint: null,
};
const LOCAL_QWEN: ReviewProvenance = {
  backend_kind: PROVENANCE_KIND_OPENAI_COMPATIBLE,
  backend_model: "qwen3-coder-30b",
  backend_endpoint: "http://localhost:8000/v1",
};

/**
 * Hand-build a `reviews` table at the immediately-prior shape: every column
 * the schema had before AGT-1137, and none of the three it adds. We're
 * asserting against the SCHEMA rather than a prior binary — that schema is
 * the durable contract describing what DBs in the field look like on first
 * boot of a provenance-aware stamp.
 */
function seedPreProvenanceDb(dbPath: string): void {
  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA journal_mode = WAL");
  db.exec(`
    CREATE TABLE reviews (
      id                   INTEGER PRIMARY KEY AUTOINCREMENT,
      reviewer             TEXT    NOT NULL,
      base_sha             TEXT    NOT NULL,
      head_sha             TEXT    NOT NULL,
      verdict              TEXT    NOT NULL CHECK (verdict IN ('approved','changes_requested','denied')),
      issues               TEXT,
      tool_calls           TEXT,
      diff_hash            TEXT,
      prompt_hash          TEXT,
      tree_sha             TEXT,
      branch               TEXT,
      server_approval_json TEXT,
      server_signature_b64 TEXT,
      server_key_id        TEXT,
      schema_version       INTEGER,
      mcp_servers_at_init  TEXT,
      created_at           TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX idx_reviews_shas ON reviews(base_sha, head_sha, reviewer);
  `);
  db.prepare(
    `INSERT INTO reviews
       (reviewer, base_sha, head_sha, verdict, issues,
        diff_hash, prompt_hash, tree_sha, branch)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    REVIEWER,
    BASE_SHA,
    HEAD_SHA,
    "approved",
    "pre-provenance prose",
    DIFF_HASH,
    PROMPT_HASH,
    TREE_SHA,
    BRANCH,
  );
  db.close();
}

describe("AGT-1137: migration preserves pre-provenance rows (AC1)", () => {
  let tmp: string;
  let dbPath: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "stamp-agt1137-mig-"));
    dbPath = join(tmp, "state.db");
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("adds three nullable columns and leaves existing rows intact", () => {
    seedPreProvenanceDb(dbPath);

    // Sanity: the fixture really is pre-provenance. If THIS fails the
    // fixture is wrong and every assertion below is meaningless.
    {
      const raw = new DatabaseSync(dbPath);
      const names = new Set(
        (raw.prepare("PRAGMA table_info(reviews)").all() as Array<{ name: string }>)
          .map((c) => c.name),
      );
      assert.ok(!names.has("backend_kind"), "fixture must predate backend_kind");
      raw.close();
    }

    const db = openDb(dbPath); // runs initSchema, i.e. the migration
    try {
      const cols = new Map(
        (
          db.prepare("PRAGMA table_info(reviews)").all() as Array<{
            name: string;
            notnull: number;
            dflt_value: unknown;
          }>
        ).map((c) => [c.name, c]),
      );
      for (const col of ["backend_kind", "backend_model", "backend_endpoint"]) {
        assert.ok(cols.has(col), `expected ${col} to exist after migration`);
        // Nullable + no DEFAULT is exactly what makes the pre-existing rows
        // survive untouched. A future change that tightens either constraint
        // would break AC1; pin it structurally rather than by behaviour.
        assert.equal(cols.get(col)!.notnull, 0, `${col} must remain nullable`);
        assert.equal(
          cols.get(col)!.dflt_value,
          null,
          `${col} must have no DEFAULT (legacy rows must read NULL)`,
        );
      }

      const rows = reviewHistory(db);
      assert.equal(rows.length, 1, "the seeded row must survive the migration");
      const row = rows[0]!;
      assert.equal(row.reviewer, REVIEWER);
      assert.equal(row.verdict, "approved");
      assert.equal(row.issues, "pre-provenance prose", "original data intact");
      assert.equal(row.backend_kind, null);
      assert.equal(row.backend_model, null);
      assert.equal(row.backend_endpoint, null);

      // ...and it reports as `unknown`, not as a guess.
      assert.equal(provenanceFromRow(row), null);
      assert.equal(formatProvenance(provenanceFromRow(row)), "unknown");
    } finally {
      db.close();
    }
  });

  it("re-opening the migrated DB is a no-op (PRAGMA-guarded ALTERs are idempotent)", () => {
    seedPreProvenanceDb(dbPath);
    openDb(dbPath).close();
    // A second ALTER of the same column would throw "duplicate column name".
    const db = openDb(dbPath);
    try {
      assert.equal(
        (db.prepare("SELECT COUNT(*) AS n FROM reviews").get() as { n: number }).n,
        1,
      );
    } finally {
      db.close();
    }
  });

  it("round-trips provenance written by recordReview, and stores NULLs when omitted", () => {
    const db = openDb(dbPath);
    try {
      recordReview(db, {
        reviewer: REVIEWER,
        base_sha: BASE_SHA,
        head_sha: HEAD_SHA,
        verdict: "approved",
        provenance: LOCAL_QWEN,
      });
      recordReview(db, {
        reviewer: "standards",
        base_sha: BASE_SHA,
        head_sha: HEAD_SHA,
        verdict: "approved",
      });
      const byReviewer = new Map(
        reviewHistory(db).map((r) => [r.reviewer, r]),
      );
      const withProv = byReviewer.get(REVIEWER)!;
      assert.deepEqual(provenanceFromRow(withProv), LOCAL_QWEN);
      assert.equal(
        formatProvenance(provenanceFromRow(withProv)),
        // AGT-1138: stored kind stays `local`; the DISPLAY label is the
        // renamed, provider-neutral one.
        "openai-compatible / qwen3-coder-30b @ http://localhost:8000/v1",
      );
      const without = byReviewer.get("standards")!;
      assert.equal(without.backend_kind, null);
      assert.equal(without.backend_model, null);
      assert.equal(without.backend_endpoint, null);
    } finally {
      db.close();
    }
  });
});

describe("AGT-1137: the verdict cache never serves a cross-backend hit (AC6)", () => {
  let tmp: string;
  let dbPath: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "stamp-agt1137-cache-"));
    dbPath = join(tmp, "state.db");
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  /** Seed one approved verdict minted by `provenance`. */
  function seed(db: DatabaseSync, provenance: ReviewProvenance): void {
    recordReview(db, {
      reviewer: REVIEWER,
      base_sha: BASE_SHA,
      head_sha: HEAD_SHA,
      verdict: "approved",
      issues: "approved by the seeding backend",
      diff_hash: DIFF_HASH,
      prompt_hash: PROMPT_HASH,
      tree_sha: TREE_SHA,
      branch: BRANCH,
      provenance,
    });
  }

  const lookup = (
    db: DatabaseSync,
    provenance: ReviewProvenance,
  ): ReturnType<typeof findCachedVerdict> =>
    findCachedVerdict(
      db,
      REVIEWER,
      DIFF_HASH,
      PROMPT_HASH,
      TREE_SHA,
      HEAD_SHA,
      BRANCH,
      provenance,
    );

  it("hits when the same backend, model and endpoint ask again", () => {
    const db = openDb(dbPath);
    try {
      seed(db, LOCAL_QWEN);
      assert.equal(
        lookup(db, LOCAL_QWEN)?.verdict,
        "approved",
        "the anti-treadmill reuse must survive the new conjunct",
      );
    } finally {
      db.close();
    }
  });

  it("misses when only the backend kind differs — the AC6 repro", () => {
    const db = openDb(dbPath);
    try {
      // A local 30B model approved. Re-run with STAMP_REVIEWER_BACKEND
      // flipped to anthropic: the frontier model must actually be asked,
      // not handed the local model's opinion.
      seed(db, LOCAL_QWEN);
      assert.equal(
        lookup(db, ANTHROPIC),
        null,
        "a verdict from one backend must not open the gate for another",
      );
    } finally {
      db.close();
    }
  });

  it("misses when only the model differs", () => {
    const db = openDb(dbPath);
    try {
      seed(db, ANTHROPIC);
      assert.equal(
        lookup(db, { ...ANTHROPIC, backend_model: "claude-sonnet-4-6" }),
        null,
        "a Sonnet review must not replay an Opus verdict (or vice versa)",
      );
    } finally {
      db.close();
    }
  });

  it("misses when only the endpoint differs", () => {
    const db = openDb(dbPath);
    try {
      seed(db, LOCAL_QWEN);
      assert.equal(
        lookup(db, { ...LOCAL_QWEN, backend_endpoint: "https://api.example.com/v1" }),
        null,
        "same model id at a different endpoint is not the same model",
      );
    } finally {
      db.close();
    }
  });

  it("misses an unpinned-model row when a model is pinned, and vice versa", () => {
    const db = openDb(dbPath);
    try {
      // NULL model = "the agent SDK chose". NULL-safe `IS` comparison means
      // that only ever matches another unpinned run.
      seed(db, { ...ANTHROPIC, backend_model: null });
      assert.equal(lookup(db, ANTHROPIC), null);
      assert.equal(
        lookup(db, { ...ANTHROPIC, backend_model: null })?.verdict,
        "approved",
      );
    } finally {
      db.close();
    }
  });

  it("never serves a pre-provenance row (fail toward a fresh review)", () => {
    const db = openDb(dbPath);
    try {
      // recordReview without `provenance` writes NULLs — the same shape a
      // row migrated in from a pre-AGT-1137 DB has.
      recordReview(db, {
        reviewer: REVIEWER,
        base_sha: BASE_SHA,
        head_sha: HEAD_SHA,
        verdict: "approved",
        diff_hash: DIFF_HASH,
        prompt_hash: PROMPT_HASH,
        tree_sha: TREE_SHA,
        branch: BRANCH,
      });
      assert.equal(
        lookup(db, ANTHROPIC),
        null,
        "a row that doesn't say what produced it can't be replayed to anyone",
      );
    } finally {
      db.close();
    }
  });
});

describe("AGT-1137: backendProvenance derives the stored record", () => {
  it("maps the agent-SDK backend with a pinned model", () => {
    assert.deepEqual(backendProvenance({ kind: "anthropic", model: "claude-opus-5" }), {
      backend_kind: "anthropic",
      backend_model: "claude-opus-5",
      backend_endpoint: null,
    });
  });

  it("maps an unpinned agent-SDK backend to a null model, never a guess", () => {
    const p = backendProvenance({ kind: "anthropic", model: null });
    assert.equal(p.backend_model, null);
    assert.equal(formatProvenance(p), "anthropic / (sdk default)");
  });

  it("records the EFFECTIVE endpoint when none is configured", () => {
    // The adapter falls back to LM Studio's URL when the configured endpoint
    // and STAMP_OPENAI_COMPATIBLE_ENDPOINT / STAMP_LOCAL_ENDPOINT are all unset. Recording the configured value
    // (undefined) would leave the record unable to answer "which endpoint",
    // which is the whole point of the column.
    const p = backendProvenance({
      kind: "openai-compatible",
      model: "qwen3-coder-30b",
      endpoint: undefined,
      enableTools: false,
    });
    assert.equal(p.backend_kind, "local");
    assert.equal(p.backend_endpoint, LOCAL_DEFAULT_BASE_URL);
  });

  it("keeps an explicitly configured endpoint", () => {
    const p = backendProvenance({
      kind: "openai-compatible",
      model: "qwen3-coder-30b",
      endpoint: "http://localhost:8000/v1",
      enableTools: true,
    });
    assert.deepEqual(p, LOCAL_QWEN);
  });

  it("marks a server-attested review with the server URL and an unknown model", () => {
    const p = serverReviewProvenance("ssh://stamp@example.com/org/repo");
    assert.equal(p.backend_kind, PROVENANCE_KIND_SERVER);
    assert.equal(
      p.backend_model,
      null,
      "the server does not report which model it used",
    );
    assert.equal(
      formatProvenance(p),
      "server / (model unknown) @ ssh://stamp@example.com/org/repo",
    );
  });

  it("stores the backend kind AGT-1137 shipped, which AGT-1138 aliases on read", () => {
    // AGT-1138 renamed the concept to `openai-compatible` — and deliberately
    // did NOT rewrite this value. Rows already in the field keep saying
    // `local`; the rename lives entirely on the read side
    // (`provenanceKindLabel`), so there is no second data migration.
    assert.equal(PROVENANCE_KIND_OPENAI_COMPATIBLE, "local");
  });
});

describe("AGT-1137: attestation payload compatibility (AC4)", () => {
  it("does not bump the payload schema version", () => {
    // The field is additive and optional, exactly like `mcp_servers_at_init`
    // before it. Bumping the version would make every verifier on the
    // current line reject attestations it should still accept.
    assert.equal(CURRENT_PAYLOAD_VERSION, 3);
  });

  it("omits null model/endpoint rather than emitting them", () => {
    assert.deepEqual(
      provenanceForAttestation({
        backend_kind: "anthropic",
        backend_model: null,
        backend_endpoint: null,
      }),
      { backend: "anthropic" },
    );
    assert.deepEqual(provenanceForAttestation(LOCAL_QWEN), {
      backend: "local",
      model: "qwen3-coder-30b",
      endpoint: "http://localhost:8000/v1",
    });
    assert.equal(
      provenanceForAttestation(null),
      undefined,
      "a pre-provenance row contributes no field at all",
    );
  });

  it("round-trips provenance through the base64 commit trailer", () => {
    const payload: AttestationPayload = {
      schema_version: CURRENT_PAYLOAD_VERSION,
      base_sha: BASE_SHA,
      head_sha: HEAD_SHA,
      target_branch: "main",
      approvals: [
        {
          reviewer: REVIEWER,
          verdict: "approved",
          review_sha: "r".repeat(64),
          provenance: provenanceForAttestation(LOCAL_QWEN)!,
        },
      ],
      checks: [],
      signer_key_id: `sha256:${"f".repeat(64)}`,
    };
    const message = `some merge\n\n${formatTrailers(payload, "c2ln")}`;
    const parsed = parseCommitAttestation(message);
    assert.ok(parsed, "trailer must parse");
    assert.deepEqual(parsed.payload.approvals[0]!.provenance, {
      backend: "local",
      model: "qwen3-coder-30b",
      endpoint: "http://localhost:8000/v1",
    });
  });

  it("still accepts an attestation that predates the field, reading it as unknown", () => {
    // The compatibility AC: absent ≠ invalid. This is the exact shape a v3
    // attestation minted before AGT-1137 has.
    const payload: AttestationPayload = {
      schema_version: CURRENT_PAYLOAD_VERSION,
      base_sha: BASE_SHA,
      head_sha: HEAD_SHA,
      target_branch: "main",
      approvals: [
        { reviewer: REVIEWER, verdict: "approved", review_sha: "r".repeat(64) },
      ],
      checks: [],
      signer_key_id: `sha256:${"f".repeat(64)}`,
    };
    const parsed = parseCommitAttestation(
      `old merge\n\n${formatTrailers(payload, "c2ln")}`,
    );
    assert.ok(parsed, "a pre-provenance attestation must still parse");
    const approval = parsed.payload.approvals[0]!;
    assert.equal(approval.provenance, undefined);
    assert.equal(formatAttestedProvenance(approval.provenance), "unknown");
  });
});

describe("AGT-1137: stamp log --reviews shows the backend per verdict (AC2)", () => {
  // Mirrors the AGT-333 signed-by marker test: `printReviewHistory` writes
  // straight to console.log, so capture stdout and drive the real `runLog`
  // entry point from a scratch repo rather than the private renderer.
  let tmp: string;
  let savedCwd: string;
  let captured: string[];
  let originalLog: typeof console.log;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "stamp-agt1137-log-"));
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

  it("renders backend/model for a provenance row and `unknown` for a legacy one", async () => {
    const { execFileSync } = await import("node:child_process");
    const { mkdirSync, writeFileSync } = await import("node:fs");

    execFileSync("git", ["init", "-q", "-b", "main"], { cwd: tmp });
    execFileSync("git", ["config", "user.email", "test@example.com"], { cwd: tmp });
    execFileSync("git", ["config", "user.name", "Test"], { cwd: tmp });
    mkdirSync(join(tmp, ".stamp"), { recursive: true });
    writeFileSync(
      join(tmp, ".stamp", "config.yml"),
      "branches:\n  main:\n    required: []\nreviewers: {}\n",
    );
    writeFileSync(join(tmp, "README.md"), "scratch\n");
    execFileSync("git", ["add", "README.md"], { cwd: tmp });
    execFileSync("git", ["commit", "-q", "-m", "init"], { cwd: tmp });

    const db = openDb(join(tmp, ".git", "stamp", "state.db"));
    try {
      recordReview(db, {
        reviewer: "legacy-reviewer",
        base_sha: BASE_SHA,
        head_sha: HEAD_SHA,
        verdict: "approved",
        issues: "recorded before provenance shipped",
      });
      recordReview(db, {
        reviewer: "local-reviewer",
        base_sha: BASE_SHA,
        head_sha: HEAD_SHA,
        verdict: "approved",
        issues: "reviewed by a local model",
        provenance: LOCAL_QWEN,
      });
      recordReview(db, {
        reviewer: "sdk-reviewer",
        base_sha: BASE_SHA,
        head_sha: HEAD_SHA,
        verdict: "approved",
        issues: "reviewed by the agent SDK",
        provenance: ANTHROPIC,
      });
    } finally {
      db.close();
    }

    process.chdir(tmp);
    const { runLog } = await import("../src/commands/log.ts");
    runLog({ limit: 10, reviews: true });

    const out = captured.join("\n");
    assert.match(
      out,
      /backend: {3}openai-compatible \/ qwen3-coder-30b @ http:\/\/localhost:8000\/v1/,
      "the openai-compatible row must name its model AND its endpoint",
    );
    assert.match(
      out,
      /backend: {3}anthropic \/ claude-opus-5/,
      "the agent-SDK row must name its model",
    );
    assert.match(
      out,
      /backend: {3}unknown/,
      "a pre-provenance row must say unknown, not guess",
    );
    // The two provenance rows must be visibly different — that's AC5's
    // demonstrable-difference property at the rendering seam.
    assert.notEqual(
      out.match(/backend: {3}openai-compatible \/ [^\n]+/)?.[0],
      out.match(/backend: {3}anthropic \/ [^\n]+/)?.[0],
    );
  });
});
