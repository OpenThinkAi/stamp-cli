import { chmodSync, existsSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { dirname } from "node:path";
import { ensureDir } from "./paths.js";

export type Verdict = "approved" | "changes_requested" | "denied";

/**
 * `schema_version` value stamped onto rows produced under the stamp 2.x
 * server-attested review model. Rows persisted by 1.x clients have NULL
 * here — a 2.x-only verifier reads NULL as "legacy unsigned, do NOT trust
 * for merge-gate purposes" while still letting `stamp log` display the row.
 *
 * Mirrors `CURRENT_V4_SCHEMA_VERSION` in `attestationV4.ts` deliberately:
 * a row that carries a server-signed approval is, by construction, a v4
 * artifact, and any v4 verifier consuming this DB column should compare
 * with the same integer. We don't import the constant directly to avoid
 * a dependency cycle (`db.ts` is leaf-ish; `attestationV4.ts` may grow
 * imports from elsewhere) — the two integers are pinned together via the
 * doc comment instead, and a guard test in `tests/db.test.ts` asserts
 * they match so a future bump to one drags the other along.
 */
export const REVIEW_ROW_SCHEMA_V4 = 5;

/**
 * Per-server runtime status recorded when `invokeReviewer` reads the SDK
 * `init` system message. Persisted as JSON in the `mcp_servers_at_init`
 * column and surfaced in the per-review attestation field of the same name.
 *
 * `declared: true` = this server was listed in the reviewer's `mcp_servers`
 * config (not stamp-internal). `optional` reflects the per-server flag from
 * config at invocation time. `error` is the SDK-provided error string, only
 * present when `status` is not `connected`.
 */
export interface McpServerAtInit {
  name: string;
  status: string;
  optional: boolean;
  declared: boolean;
  error?: string;
}

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
  /** JSON-encoded McpServerAtInit[] (see AGT-246), or null for reviews
   *  recorded before this shipped or where no MCP servers were declared. */
  mcp_servers_at_init: string | null;
  /** SHA-256 hex of the diff bytes the reviewer evaluated. Null for rows
   *  recorded before 1.8.0 shipped. Cache key with prompt_hash + reviewer. */
  diff_hash: string | null;
  /** SHA-256 hex of the reviewer prompt text. Null for rows recorded before
   *  1.8.0 shipped. Cache key with diff_hash + reviewer. */
  prompt_hash: string | null;
  /** JSON-stringified `ApprovalV4` (see `lib/attestationV4.ts`) as returned
   *  by stamp-server's `stamp-review` SSH verb. Null for rows produced by
   *  pre-2.x clients OR by a 2.x client running in local-only mode (no
   *  `review_server` configured). When non-null, `server_signature_b64`
   *  and `server_key_id` are non-null as well (writer-side invariant
   *  enforced by `recordReview`); when null, all three are null together. */
  server_approval_json: string | null;
  /** Base64 Ed25519 signature the server produced over
   *  `canonicalSerializeApproval(approval)`. Non-null iff
   *  `server_approval_json` is non-null. */
  server_signature_b64: string | null;
  /** `sha256:<hex>` fingerprint of the server's review-signing key — same
   *  string format the trusted-keys manifest uses to identify keys (see
   *  `lib/trustedKeysManifest.ts`). Duplicates the `server_key_id` embedded
   *  inside the signed `server_approval_json`; stored at the row level so
   *  `stamp log` can render the signer without parsing the JSON blob, and
   *  so AGT-334's `stamp merge` can index lookups by signer without
   *  hydrating every approval. */
  server_key_id: string | null;
  /** Schema version of the persisted row. `null` for legacy 1.x rows that
   *  predate the column; `REVIEW_ROW_SCHEMA_V4` for rows produced under
   *  the server-attested model. The presence of a non-null value here is
   *  the canonical marker that distinguishes a 2.x row from a 1.x row in
   *  `stamp log` and (later) in AGT-334's merge-gate input filter. */
  schema_version: number | null;
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
  /** JSON-encoded McpServerAtInit[] or null. See AGT-246. */
  mcp_servers_at_init?: string | null;
  /** SHA-256 hex of the diff bytes (caller computes; see commands/review.ts).
   *  Optional for pre-1.8.0 call sites that haven't been updated yet. */
  diff_hash?: string | null;
  /** SHA-256 hex of the reviewer prompt text. Optional for pre-1.8.0 call
   *  sites that haven't been updated yet. */
  prompt_hash?: string | null;
  /** Server-attested approval persisted as a unit. Either provide all
   *  three fields (server-attested 2.x row) or omit `serverAttestation`
   *  entirely (local / 1.x-style row). Half-populated input is a writer
   *  bug — `recordReview` enforces all-or-nothing so a downstream
   *  verifier can rely on "non-null server_approval_json ⇒ non-null
   *  signature + key_id" as a hard DB invariant.
   *
   *  AGT-334 (`stamp merge`) reads these back via `serverApprovalsFor`
   *  to fold them into the v4 envelope; pre-2.x call sites simply
   *  don't pass this field. */
  serverAttestation?: {
    /** JSON-serialized `ApprovalV4` — the bytes the server signed are
     *  `canonicalSerializeApproval(parsed_approval)`, NOT this JSON
     *  string verbatim (key order may differ; the canonical serializer
     *  re-sorts at signature-verify time). */
    approval_json: string;
    /** Base64 Ed25519 over `canonicalSerializeApproval(approval)`. */
    signature_b64: string;
    /** `sha256:<hex>` server key fingerprint; must match the
     *  `server_key_id` inside `approval_json`. The dup is intentional
     *  (see `ReviewRow.server_key_id` docstring). */
    server_key_id: string;
  };
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
  // Base CREATE only — indexes that reference newly-added columns must wait
  // until after the migration ALTERs below. Putting `idx_reviews_cache`
  // here would crash on upgrade from ≤1.7.x: the CREATE TABLE no-ops
  // (table exists with the old shape), then CREATE INDEX fails on the
  // missing column, then the whole exec() throws and the ALTERs never
  // run — leaving the DB stuck at the old schema forever.
  db.exec(`
    CREATE TABLE IF NOT EXISTS reviews (
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

    CREATE INDEX IF NOT EXISTS idx_reviews_shas
      ON reviews(base_sha, head_sha, reviewer);
  `);

  // Forward migrations: each column was added in a later release than the
  // base schema. PRAGMA table_info lists current columns; missing ones get
  // ALTER-added. Idempotent — repeat opens no-op.
  //
  // Forward-only by design: there is NO down-migration. A user who downgrades
  // from a stamp version that ran these ALTERs back to one that doesn't know
  // about them keeps the extra columns but the old binary simply ignores
  // them (SELECTs naming explicit columns are unaffected; INSERTs through
  // the old code path leave the new columns NULL). 1.x rows that predate
  // these columns survive each migration step because ALTER TABLE ... ADD
  // COLUMN populates existing rows with NULL — none of the additions take
  // a NOT NULL constraint or a non-NULL default, so the legacy rows
  // continue to read out with their original data intact and NULL in the
  // new slots. That's the load-bearing AC for AGT-333 and is asserted
  // structurally in `tests/db.test.ts` against a hand-built 1.x fixture.
  const cols = db.prepare("PRAGMA table_info(reviews)").all() as Array<{ name: string }>;
  const have = new Set(cols.map((c) => c.name));
  if (!have.has("tool_calls")) {
    db.exec("ALTER TABLE reviews ADD COLUMN tool_calls TEXT");
  }
  if (!have.has("diff_hash")) {
    db.exec("ALTER TABLE reviews ADD COLUMN diff_hash TEXT");
  }
  if (!have.has("prompt_hash")) {
    db.exec("ALTER TABLE reviews ADD COLUMN prompt_hash TEXT");
  }
  // AGT-333 (stamp 2.x): server-attested review fields. All TEXT/INTEGER
  // with no DEFAULT and no NOT NULL — that's what makes the 1.x-rows-
  // survive guarantee mechanical: ALTER fills existing rows with NULL,
  // every read site treats NULL as "legacy / no server attestation here,"
  // and the writer-side invariant (`recordReview`) keeps the three server
  // fields strictly all-or-nothing so downstream code never sees a half-
  // populated row.
  if (!have.has("server_approval_json")) {
    db.exec("ALTER TABLE reviews ADD COLUMN server_approval_json TEXT");
  }
  if (!have.has("server_signature_b64")) {
    db.exec("ALTER TABLE reviews ADD COLUMN server_signature_b64 TEXT");
  }
  if (!have.has("server_key_id")) {
    db.exec("ALTER TABLE reviews ADD COLUMN server_key_id TEXT");
  }
  if (!have.has("schema_version")) {
    db.exec("ALTER TABLE reviews ADD COLUMN schema_version INTEGER");
  }
  // AGT-246: per-review MCP server runtime status. JSON-encoded
  // McpServerAtInit[], null for rows recorded before this shipped or where
  // no MCP servers were declared. Additive only — no NOT NULL, no DEFAULT.
  if (!have.has("mcp_servers_at_init")) {
    db.exec("ALTER TABLE reviews ADD COLUMN mcp_servers_at_init TEXT");
  }
  // Cache index created here (after the migration ALTERs above) so it works
  // on both fresh installs and upgrades. Repeat-safe.
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_reviews_cache
      ON reviews(reviewer, diff_hash, prompt_hash, created_at)
  `);
}

export function recordReview(
  db: DatabaseSync,
  input: RecordReviewInput,
): number {
  // All-or-nothing on the three server-attestation fields: every read
  // site (stamp log marker, AGT-334's merge folder, future v4 verifier)
  // treats "row has a server signature" as a binary state. Half-populated
  // input here would let the row drift into an ambiguous middle state
  // that no read site is prepared to handle. TypeScript already encodes
  // this in `RecordReviewInput.serverAttestation` (the three fields ride
  // together on a single object), but the runtime check guards against a
  // future caller bypassing the type — and against accidental `as any`
  // at the boundary.
  const sa = input.serverAttestation ?? null;
  const schemaVersion = sa === null ? null : REVIEW_ROW_SCHEMA_V4;
  const stmt = db.prepare(
    `INSERT INTO reviews
       (reviewer, base_sha, head_sha, verdict, issues, tool_calls,
        diff_hash, prompt_hash,
        server_approval_json, server_signature_b64, server_key_id,
        schema_version, mcp_servers_at_init)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  const result = stmt.run(
    input.reviewer,
    input.base_sha,
    input.head_sha,
    input.verdict,
    input.issues ?? null,
    input.tool_calls ?? null,
    input.diff_hash ?? null,
    input.prompt_hash ?? null,
    sa?.approval_json ?? null,
    sa?.signature_b64 ?? null,
    sa?.server_key_id ?? null,
    schemaVersion,
    input.mcp_servers_at_init ?? null,
  );
  return Number(result.lastInsertRowid);
}

/**
 * Server-attested row projection, returned by `serverApprovalsFor`. This
 * is the shape AGT-334's `stamp merge` consumes when folding stored
 * approvals into the v4 envelope — caller parses `approval_json` into
 * an `ApprovalV4` and wraps it with `signature_b64` + `server_key_id`
 * into an `ApprovalEntryV4`. Kept here (rather than in `attestationV4.ts`)
 * because `db.ts` is the boundary that knows the storage shape, and the
 * caller can do the JSON parse with full v4 typing.
 */
export interface ServerAttestedRow {
  id: number;
  reviewer: string;
  base_sha: string;
  head_sha: string;
  verdict: Verdict;
  /** JSON-stringified `ApprovalV4`. Caller `JSON.parse`s + canonical-
   *  reserializes to verify the server's signature. */
  approval_json: string;
  /** Base64 Ed25519 over `canonicalSerializeApproval(approval)`. */
  signature_b64: string;
  /** `sha256:<hex>` server key fingerprint. */
  server_key_id: string;
  created_at: string;
}

/**
 * Return all server-attested rows for a given (base_sha, head_sha) pair,
 * one per reviewer (latest wins on ties — same `(created_at DESC, id DESC)`
 * ordering as `latestVerdicts`). Skips rows where `server_approval_json`
 * is NULL (legacy 1.x rows OR local-only 2.x rows with no server
 * attestation) — those are not eligible inputs to a v4 merge envelope.
 *
 * Intended consumer is AGT-334's `stamp merge`: it calls this, parses
 * each `approval_json`, and assembles `ApprovalEntryV4[]` for the v4
 * envelope. The merge code is responsible for verifying signatures and
 * matching `server_key_id` against the manifest at `base_sha` before
 * trusting the data.
 *
 * Returns rows in stable reviewer-name order so the resulting envelope
 * is deterministic across runs (the v4 canonical serializer sorts object
 * keys but preserves array order; deterministic input means deterministic
 * output, which matters for stamp's reproducibility property).
 */
export function serverApprovalsFor(
  db: DatabaseSync,
  base_sha: string,
  head_sha: string,
): ServerAttestedRow[] {
  const stmt = db.prepare(`
    SELECT id, reviewer, base_sha, head_sha, verdict,
           server_approval_json AS approval_json,
           server_signature_b64 AS signature_b64,
           server_key_id,
           created_at
    FROM (
      SELECT
        id, reviewer, base_sha, head_sha, verdict,
        server_approval_json,
        server_signature_b64,
        server_key_id,
        created_at,
        ROW_NUMBER() OVER (
          PARTITION BY reviewer
          ORDER BY created_at DESC, id DESC
        ) AS rn
      FROM reviews
      WHERE base_sha = ? AND head_sha = ?
        AND server_approval_json IS NOT NULL
    )
    WHERE rn = 1
    ORDER BY reviewer ASC
  `);
  return stmt.all(base_sha, head_sha) as unknown as ServerAttestedRow[];
}

export interface CachedVerdict {
  verdict: Verdict;
  /** Prose stored on the cached row; may be null on pre-prose rows. */
  issues: string | null;
  /** (base_sha, head_sha) the cached verdict was originally recorded against.
   *  Surfaced in the cache-hit message so operators can trace provenance. */
  base_sha: string;
  head_sha: string;
  created_at: string;
}

/**
 * Look up the most recent stored verdict for (reviewer, diff_hash, prompt_hash).
 * Both hashes are required — null/missing-hash rows never match, so pre-1.8.0
 * rows are silently skipped. Returns null when no matching row exists.
 *
 * Used by `stamp review` to short-circuit the LLM call when an identical
 * (diff, prompt, reviewer) tuple has already been evaluated. The point is
 * to break the treadmill where the model non-deterministically re-flips
 * verdicts on unchanged input.
 */
export function findCachedVerdict(
  db: DatabaseSync,
  reviewer: string,
  diff_hash: string,
  prompt_hash: string,
): CachedVerdict | null {
  const stmt = db.prepare(`
    SELECT verdict, issues, base_sha, head_sha, created_at
    FROM reviews
    WHERE reviewer = ? AND diff_hash = ? AND prompt_hash = ?
    ORDER BY created_at DESC, id DESC
    LIMIT 1
  `);
  const row = stmt.get(reviewer, diff_hash, prompt_hash) as
    | CachedVerdict
    | undefined;
  return row ?? null;
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
  mcp_servers_at_init: string | null;
}

const LATEST_VERDICTS_SQL = `
  SELECT id, reviewer, verdict, issues, tool_calls, mcp_servers_at_init
  FROM (
    SELECT
      id,
      reviewer,
      verdict,
      issues,
      tool_calls,
      mcp_servers_at_init,
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

export interface PriorReviewRow {
  /** Reviewer name (echoed for symmetry with the query input). */
  reviewer: string;
  /** Head SHA the prior verdict was recorded against. */
  head_sha: string;
  verdict: Verdict;
  /** Prose body the reviewer submitted on the prior run; may be null on
   *  pre-prose rows. */
  issues: string | null;
  /** ISO datetime when this row was inserted; surfaced so callers can show
   *  age in operator-visible messaging if useful. */
  created_at: string;
}

/**
 * Find the most recent prior review row by `reviewer` against the same
 * `base_sha`, excluding any row whose `head_sha` equals `excludeHeadSha`.
 * Returns null if no prior review exists.
 *
 * Used by `stamp review` to surface a reviewer's earlier verdict + prose
 * back into the prompt on subsequent runs of the same branch, so iterations
 * can ratchet toward approval instead of randomly re-flipping. The
 * `excludeHeadSha` argument is intended to be the current head_sha — we
 * want what came *before* the current attempt, not the row this very run
 * is about to write.
 *
 * Same ordering as latestVerdicts (created_at DESC, id DESC) so same-second
 * inserts tiebreak on insertion order.
 */
export function priorReviewByReviewer(
  db: DatabaseSync,
  reviewer: string,
  base_sha: string,
  excludeHeadSha?: string,
): PriorReviewRow | null {
  const stmt = db.prepare(`
    SELECT reviewer, head_sha, verdict, issues, created_at
    FROM reviews
    WHERE reviewer = ?
      AND base_sha = ?
      AND (? IS NULL OR head_sha != ?)
    ORDER BY created_at DESC, id DESC
    LIMIT 1
  `);
  const row = stmt.get(
    reviewer,
    base_sha,
    excludeHeadSha ?? null,
    excludeHeadSha ?? null,
  ) as PriorReviewRow | undefined;
  return row ?? null;
}

export function reviewHistory(
  db: DatabaseSync,
  opts: { limit?: number } = {},
): ReviewRow[] {
  const limit = opts.limit ?? 50;
  // SELECT every column the ReviewRow type promises. The legacy version
  // of this query only pulled a subset (id/reviewer/base/head/verdict/
  // issues/created_at) and the implicit cast to ReviewRow[] put `undefined`
  // into `tool_calls` / `diff_hash` / `prompt_hash` at runtime — a
  // long-standing type lie. The marker logic added in AGT-333 needs
  // `server_key_id` and `schema_version` to render the SIGNED-BY column,
  // and the cheapest correct fix is to stop lying: pull the full row
  // shape, let `stamp log` filter what it displays. The extra columns
  // are TEXT/INTEGER scalars; the read-amplification is negligible at
  // this command's call sites.
  const stmt = db.prepare(`
    SELECT id, reviewer, base_sha, head_sha, verdict, issues,
           tool_calls, diff_hash, prompt_hash,
           server_approval_json, server_signature_b64, server_key_id,
           schema_version, mcp_servers_at_init, created_at
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
  // See `reviewHistory` for the rationale on selecting the full row
  // shape rather than a subset.
  const stmt = db.prepare(`
    SELECT id, reviewer, base_sha, head_sha, verdict, issues,
           tool_calls, diff_hash, prompt_hash,
           server_approval_json, server_signature_b64, server_key_id,
           schema_version, created_at
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

/**
 * Null out reviewer prose (the `issues` column) on rows older than
 * `now − sqliteModifier`, WITHOUT deleting the rows (AGT-421). The verdict
 * + diff_hash/prompt_hash stay intact so the verdict cache and the audit
 * trail survive; only the human-facing prose — which can quote sensitive
 * file:line snippets — is dropped. Returns the number of rows nulled.
 *
 * CONTRACT NOTE: `review_sha` (= hash of the prose) is baked into a *signed
 * attestation* at write time and is NEVER recomputed from this DB at verify
 * time, so nulling prose here cannot invalidate an existing attestation. If
 * a future verifier is ever added that recomputes review_sha from live rows,
 * this contract must be revisited.
 */
export function expireProse(db: DatabaseSync, sqliteModifier: string): number {
  const res = db
    .prepare(
      "UPDATE reviews SET issues = NULL WHERE issues IS NOT NULL AND created_at < datetime('now', ?)",
    )
    .run(sqliteModifier);
  return Number(res.changes);
}

/** Count rows whose prose `expireProse` would null — the dry-run peek. AGT-421. */
export function countProseToExpire(
  db: DatabaseSync,
  sqliteModifier: string,
): number {
  const row = db
    .prepare(
      "SELECT COUNT(*) AS count FROM reviews WHERE issues IS NOT NULL AND created_at < datetime('now', ?)",
    )
    .get(sqliteModifier) as { count: number };
  return row.count;
}
