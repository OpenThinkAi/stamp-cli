/**
 * Membership sqlite for the stamp server.
 *
 * Lives on the persistent volume at /srv/git/.stamp-state/users.db. Holds:
 *   - users: SSH pubkey → role (owner/admin/member), optional stamp signing
 *     pubkey, source provenance (env / bootstrap / invite / manual)
 *   - invites: single-use, time-bounded tokens an admin mints to onboard
 *     a teammate (phase 2)
 *   - peer_review_patches: one row per broadcast PR (AGT-427)
 *   - peer_review_events: append-only event log for peer-agentic reviews
 *     (AGT-427)
 *
 * Two access modes:
 *   - Writable (boot-time seed, admin operations): opens the DB read/write,
 *     ensures schema, tightens perms on the file and parent dir.
 *   - Read-only (sshd's AuthorizedKeysCommand): opens with readOnly:true so
 *     the resolver process holds no write fd; lets us run the resolver as
 *     an unprivileged user against a root:git 0640 DB without enabling
 *     WAL-mode sidecars.
 *
 * Roles and invite roles are CHECK-constrained in the schema so a future
 * code-level bug introducing a typo'd role string fails at insert rather
 * than silently corrupting authorization data.
 */

import { chmodSync, existsSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { dirname } from "node:path";
import { ensureDir } from "./paths.js";

export type Role = "owner" | "admin" | "member";
export type UserSource = "env" | "bootstrap" | "invite" | "manual";
export type InviteRole = "admin" | "member";

export interface UserRow {
  id: number;
  short_name: string;
  ssh_pubkey: string;
  ssh_fp: string;
  stamp_pubkey: string | null;
  role: Role;
  source: UserSource;
  invited_by: number | null;
  created_at: number;
  last_seen_at: number | null;
}

export interface InviteRow {
  token: string;
  role: InviteRole;
  invited_by: number;
  created_at: number;
  expires_at: number;
  consumed_at: number | null;
  consumed_by: number | null;
}

/** Default on-server path. Tests pass an explicit `path` instead. */
export const DEFAULT_SERVER_DB_PATH = "/srv/git/.stamp-state/users.db";

/**
 * Resolve the effective DB path. Precedence:
 *   1. Explicit `opts.path` (tests, future config)
 *   2. STAMP_SERVER_DB_PATH env var (CLI-spawning tests; also a relief
 *      valve for operators who want to relocate the DB on the volume)
 *   3. DEFAULT_SERVER_DB_PATH (production)
 */
export function resolveServerDbPath(explicit?: string): string {
  if (explicit) return explicit;
  const envPath = process.env["STAMP_SERVER_DB_PATH"];
  if (envPath && envPath.length > 0) return envPath;
  return DEFAULT_SERVER_DB_PATH;
}

export interface OpenServerDbOpts {
  /** Override the on-disk location. Required for tests. */
  path?: string;
  /** Open read-only. Skips schema init, skips chmod, and constructs the
   *  DatabaseSync with readOnly:true. Used by the AuthorizedKeysCommand
   *  resolver. */
  readOnly?: boolean;
  /** Skip filesystem-perm tightening of the DB file + parent dir. The
   *  on-server boot path wants tightening; tests on tmpfs do not. */
  skipChmod?: boolean;
}

export function openServerDb(opts: OpenServerDbOpts = {}): DatabaseSync {
  const path = resolveServerDbPath(opts.path);
  const readOnly = opts.readOnly ?? false;

  if (!readOnly) {
    const dir = dirname(path);
    ensureDir(dir, 0o1770);
    if (!opts.skipChmod) {
      // 0o1770 = sticky bit (1) + rwx for owner + rwx for group + nothing
      // for other. Matches the chmod entrypoint.sh sets, intentionally:
      //   - The 0o770 portion is required for sqlite to write its
      //     `-journal` sidecar in this dir on every transaction (the
      //     git user that runs the HTTP server and SSH wrappers needs
      //     CREATE access). At 0o750 sqlite silently demotes the
      //     connection to read-only and every UPDATE throws "attempt
      //     to write a readonly database".
      //   - The sticky bit prevents the git-group from renaming or
      //     deleting files in this dir that ARE NOT owned by git —
      //     so any future root-owned state file landing here is
      //     protected from a git-shell-escapee even though the dir
      //     is otherwise group-writable.
      // We must mirror the sticky bit here (not just rely on
      // entrypoint.sh) because seed-users.ts opens the DB writable
      // (no skipChmod) as root at boot, and a chmod 0o770 here
      // would silently STRIP the sticky bit entrypoint just set.
      // ensureDir no-ops on an existing directory, so this explicit
      // chmod is what re-applies sticky+770 on a redeploy where the
      // dir was created at an earlier looser mode.
      chmodSync(dir, 0o1770);
    }
  }

  const db = new DatabaseSync(path, { readOnly });

  // Each SSH verb is its own process with its own connection to the same DB
  // file. busy_timeout makes a concurrent BEGIN IMMEDIATE (e.g. the AGT-420
  // rate-limit transaction) WAIT for the write lock instead of failing fast
  // with SQLITE_BUSY — the held region is microseconds, so writers serialize
  // cleanly under contention rather than erroring out.
  db.exec("PRAGMA busy_timeout = 5000");

  if (!readOnly) {
    db.exec("PRAGMA foreign_keys = ON");
    initSchema(db);
    if (!opts.skipChmod && existsSync(path)) {
      // root:git 0660. The HTTP server (git user) writes new user rows
      // on invite-accept; the AuthorizedKeysCommand resolver also runs
      // as git but opens readOnly:true so the write bit is dormant on
      // its path. Chown is the operator's responsibility (entrypoint.sh
      // sets root:git after each boot); we only set the mode bits.
      //
      // Callers running as the git user (mint-invite, http-server) must
      // pass skipChmod:true — only the file owner can chmod on Linux,
      // and entrypoint.sh has already tightened perms by the time those
      // callers run.
      chmodSync(path, 0o660);
    }
  }

  return db;
}

function initSchema(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      short_name    TEXT NOT NULL UNIQUE,
      ssh_pubkey    TEXT NOT NULL,
      ssh_fp        TEXT NOT NULL UNIQUE,
      stamp_pubkey  TEXT,
      role          TEXT NOT NULL CHECK (role IN ('owner','admin','member')),
      source        TEXT NOT NULL DEFAULT 'invite' CHECK (source IN ('env','bootstrap','invite','manual')),
      invited_by    INTEGER REFERENCES users(id),
      created_at    INTEGER NOT NULL,
      last_seen_at  INTEGER
    );

    CREATE INDEX IF NOT EXISTS idx_users_ssh_fp ON users(ssh_fp);

    CREATE TABLE IF NOT EXISTS invites (
      token         TEXT PRIMARY KEY,
      role          TEXT NOT NULL CHECK (role IN ('admin','member')),
      invited_by    INTEGER NOT NULL REFERENCES users(id),
      created_at    INTEGER NOT NULL,
      expires_at    INTEGER NOT NULL,
      consumed_at   INTEGER,
      consumed_by   INTEGER REFERENCES users(id)
    );

    CREATE INDEX IF NOT EXISTS idx_invites_expires ON invites(expires_at);

    -- AGT-420: per-(caller, action) token-bucket rate-limit state. Lazy
    -- refill (computed on read), so no cron is needed. Brand-new table;
    -- additive, never ALTERed here.
    CREATE TABLE IF NOT EXISTS rate_limits (
      subject_id  INTEGER NOT NULL,
      action      TEXT NOT NULL,
      tokens      REAL NOT NULL,
      updated_at  INTEGER NOT NULL,
      PRIMARY KEY (subject_id, action)
    );

    -- AGT-420: server-side verdict cache, symmetric to the client's local
    -- reviews cache (lib/db.ts findCachedVerdict). Keyed on the same triple
    -- (reviewer, diff_sha256, prompt_sha256); one row per key (upserted).
    CREATE TABLE IF NOT EXISTS server_verdicts (
      reviewer      TEXT NOT NULL,
      diff_sha256   TEXT NOT NULL,
      prompt_sha256 TEXT NOT NULL,
      verdict       TEXT NOT NULL,
      prose         TEXT NOT NULL,
      created_at    INTEGER NOT NULL,
      PRIMARY KEY (reviewer, diff_sha256, prompt_sha256)
    );

    -- AGT-427: peer-agentic review patches. One row per broadcast PR.
    -- seat_N_holder is the fingerprint of the agent that claimed the seat;
    -- seat_N_claimed_at is the unix-second timestamp of the last heartbeat
    -- (or original claim), used by the seat-TTL sweep (future ticket).
    CREATE TABLE IF NOT EXISTS peer_review_patches (
      patch_id          TEXT PRIMARY KEY,
      requested_by_fp   TEXT NOT NULL,
      base_sha          TEXT NOT NULL,
      head_sha          TEXT NOT NULL,
      repo              TEXT NOT NULL,
      broadcast_at      INTEGER NOT NULL,
      seat_1_holder     TEXT,
      seat_2_holder     TEXT,
      seat_1_claimed_at INTEGER,
      seat_2_claimed_at INTEGER
    );

    CREATE INDEX IF NOT EXISTS idx_pr_patches_repo
      ON peer_review_patches(repo);

    -- AGT-427: append-only event log for peer-agentic review lifecycle.
    -- payload is the full event JSON for future audit/replay.
    -- NOTE: no row-level TTL sweep is scoped to this ticket; the
    -- event log is unbounded in this release. A future ticket adds a sweep.
    CREATE TABLE IF NOT EXISTS peer_review_events (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      patch_id    TEXT NOT NULL,
      event_type  TEXT NOT NULL,
      actor_fp    TEXT NOT NULL,
      occurred_at INTEGER NOT NULL,
      payload     TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_pr_events_patch_id
      ON peer_review_events(patch_id);
  `);

  // AGT-431: additive boot-safe column — pr_url on peer_review_patches.
  // SQLite lacks ADD COLUMN IF NOT EXISTS, so we guard with PRAGMA table_info.
  // Pre-existing rows keep NULL pr_url; new pr-opened broadcasts populate it.
  const cols = db.prepare("PRAGMA table_info(peer_review_patches)").all() as Array<{ name: string }>;
  const hasPrUrl = cols.some((c) => c.name === "pr_url");
  if (!hasPrUrl) {
    db.exec("ALTER TABLE peer_review_patches ADD COLUMN pr_url TEXT");
  }
}

// ─── Peer-review patch helpers (AGT-427) ────────────────────────────

export interface PeerReviewPatchRow {
  patch_id: string;
  requested_by_fp: string;
  base_sha: string;
  head_sha: string;
  repo: string;
  broadcast_at: number;
  /** PR URL stored at broadcast time (AGT-431). NULL for rows predating AGT-431. */
  pr_url: string | null;
  seat_1_holder: string | null;
  seat_2_holder: string | null;
  seat_1_claimed_at: number | null;
  seat_2_claimed_at: number | null;
}

export interface InsertPatchInput {
  patch_id: string;
  requested_by_fp: string;
  base_sha: string;
  head_sha: string;
  repo: string;
  /** PR URL to persist alongside the patch row (AGT-431). */
  pr_url?: string | null;
  broadcast_at?: number;
}

/** Insert a new peer-review patch row. Throws on duplicate patch_id. */
export function insertPatch(
  db: DatabaseSync,
  input: InsertPatchInput,
  now: number = Date.now(),
): void {
  db.prepare(
    `INSERT INTO peer_review_patches
       (patch_id, requested_by_fp, base_sha, head_sha, repo, broadcast_at, pr_url)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    input.patch_id,
    input.requested_by_fp,
    input.base_sha,
    input.head_sha,
    input.repo,
    input.broadcast_at ?? Math.floor(now / 1000),
    input.pr_url ?? null,
  );
}

/** Fetch a patch row by patch_id. Returns null when not found. */
export function findPatch(
  db: DatabaseSync,
  patch_id: string,
): PeerReviewPatchRow | null {
  const row = db
    .prepare(
      `SELECT patch_id, requested_by_fp, base_sha, head_sha, repo,
              broadcast_at, pr_url, seat_1_holder, seat_2_holder,
              seat_1_claimed_at, seat_2_claimed_at
       FROM peer_review_patches WHERE patch_id = ?`,
    )
    .get(patch_id) as PeerReviewPatchRow | undefined;
  return row
    ? {
        patch_id: row.patch_id,
        requested_by_fp: row.requested_by_fp,
        base_sha: row.base_sha,
        head_sha: row.head_sha,
        repo: row.repo,
        broadcast_at: row.broadcast_at,
        pr_url: row.pr_url ?? null,
        seat_1_holder: row.seat_1_holder ?? null,
        seat_2_holder: row.seat_2_holder ?? null,
        seat_1_claimed_at: row.seat_1_claimed_at ?? null,
        seat_2_claimed_at: row.seat_2_claimed_at ?? null,
      }
    : null;
}

/** Append a row to the peer_review_events table. */
export function appendEvent(
  db: DatabaseSync,
  patch_id: string,
  event_type: string,
  actor_fp: string,
  payload: object,
  now: number = Date.now(),
): void {
  db.prepare(
    `INSERT INTO peer_review_events (patch_id, event_type, actor_fp, occurred_at, payload)
     VALUES (?, ?, ?, ?, ?)`,
  ).run(
    patch_id,
    event_type,
    actor_fp,
    Math.floor(now / 1000),
    JSON.stringify(payload),
  );
}

export type ClaimSeatError =
  | { ok: false; error: "patch_not_found" }
  | { ok: false; error: "author_cannot_claim_own_pr" }
  | { ok: false; error: "already_holds_other_seat" }
  | { ok: false; error: "seats_full" };

export type ClaimSeatResult =
  | ClaimSeatError
  | { ok: true; seat: 1 | 2 };

/**
 * Atomically claim a seat on a peer-review patch (AGT-427).
 *
 * Runs entirely inside a BEGIN IMMEDIATE transaction (the write lock is
 * acquired at the SELECT) so concurrent callers from different SSH-verb
 * processes serialize rather than racing past the seat-count check.
 * Caller must NOT already be inside a transaction.
 *
 * Rejection conditions (in evaluation order):
 *   1. patch not found → patch_not_found
 *   2. claimant fp === requested_by_fp → author_cannot_claim_own_pr
 *   3. claimant fp already holds the OTHER seat → already_holds_other_seat
 *   4. both seats occupied → seats_full
 *   5. success → returns { ok: true, seat: 1 | 2 }
 */
export function claimSeatTx(
  db: DatabaseSync,
  patch_id: string,
  claimant_fp: string,
  now: number = Date.now(),
): ClaimSeatResult {
  db.exec("BEGIN IMMEDIATE");
  try {
    const row = db
      .prepare(
        `SELECT requested_by_fp, seat_1_holder, seat_2_holder
         FROM peer_review_patches WHERE patch_id = ?`,
      )
      .get(patch_id) as
      | { requested_by_fp: string; seat_1_holder: string | null; seat_2_holder: string | null }
      | undefined;

    if (!row) {
      db.exec("ROLLBACK");
      return { ok: false, error: "patch_not_found" };
    }

    if (claimant_fp === row.requested_by_fp) {
      db.exec("ROLLBACK");
      return { ok: false, error: "author_cannot_claim_own_pr" };
    }

    const s1 = row.seat_1_holder ?? null;
    const s2 = row.seat_2_holder ?? null;

    // Self-collision: already holds the other seat
    if ((s1 === claimant_fp) || (s2 === claimant_fp)) {
      db.exec("ROLLBACK");
      return { ok: false, error: "already_holds_other_seat" };
    }

    const nowSec = Math.floor(now / 1000);

    if (!s1) {
      db.prepare(
        `UPDATE peer_review_patches
         SET seat_1_holder = ?, seat_1_claimed_at = ?
         WHERE patch_id = ?`,
      ).run(claimant_fp, nowSec, patch_id);
      db.exec("COMMIT");
      return { ok: true, seat: 1 };
    }

    if (!s2) {
      db.prepare(
        `UPDATE peer_review_patches
         SET seat_2_holder = ?, seat_2_claimed_at = ?
         WHERE patch_id = ?`,
      ).run(claimant_fp, nowSec, patch_id);
      db.exec("COMMIT");
      return { ok: true, seat: 2 };
    }

    db.exec("ROLLBACK");
    return { ok: false, error: "seats_full" };
  } catch (err) {
    try { db.exec("ROLLBACK"); } catch { /* already rolled back */ }
    throw err;
  }
}

/** Release a held seat (clear the column). Returns true when a seat was
 *  cleared; false when the claimant holds no seat on this patch. */
export function releaseSeat(
  db: DatabaseSync,
  patch_id: string,
  claimant_fp: string,
): boolean {
  // No transaction needed: each SSH-verb process is the sole writer for this
  // patch when it reaches release (seats serialize on claim, not release).
  const row = db
    .prepare(
      `SELECT seat_1_holder, seat_2_holder FROM peer_review_patches WHERE patch_id = ?`,
    )
    .get(patch_id) as
    | { seat_1_holder: string | null; seat_2_holder: string | null }
    | undefined;

  if (!row) return false;

  if (row.seat_1_holder === claimant_fp) {
    db.prepare(
      `UPDATE peer_review_patches SET seat_1_holder = NULL, seat_1_claimed_at = NULL WHERE patch_id = ?`,
    ).run(patch_id);
    return true;
  }

  if (row.seat_2_holder === claimant_fp) {
    db.prepare(
      `UPDATE peer_review_patches SET seat_2_holder = NULL, seat_2_claimed_at = NULL WHERE patch_id = ?`,
    ).run(patch_id);
    return true;
  }

  return false;
}

/** Refresh the seat_N_claimed_at timestamp for a heartbeat. Returns the
 *  seat number (1 or 2) that was refreshed; null when the claimant holds
 *  no seat on this patch (404 case). */
export function touchHeartbeat(
  db: DatabaseSync,
  patch_id: string,
  claimant_fp: string,
  now: number = Date.now(),
): 1 | 2 | null {
  const row = db
    .prepare(
      `SELECT seat_1_holder, seat_2_holder FROM peer_review_patches WHERE patch_id = ?`,
    )
    .get(patch_id) as
    | { seat_1_holder: string | null; seat_2_holder: string | null }
    | undefined;

  if (!row) return null;

  const nowSec = Math.floor(now / 1000);

  if (row.seat_1_holder === claimant_fp) {
    db.prepare(
      `UPDATE peer_review_patches SET seat_1_claimed_at = ? WHERE patch_id = ?`,
    ).run(nowSec, patch_id);
    return 1;
  }

  if (row.seat_2_holder === claimant_fp) {
    db.prepare(
      `UPDATE peer_review_patches SET seat_2_claimed_at = ? WHERE patch_id = ?`,
    ).run(nowSec, patch_id);
    return 2;
  }

  return null;
}

/**
 * Sweep expired seats from `peer_review_patches` (AGT-454, G3).
 *
 * Clears `seat_N_holder` / `seat_N_claimed_at` for any seat whose last
 * heartbeat timestamp is older than `ttlSeconds` seconds. This bounds
 * seat-squat attacks where a member claims both seats and never releases
 * them — the TTL ensures they are freed automatically.
 *
 * Safe to run at any cadence; skips seats that are already NULL.
 * Returns the number of individual seat columns cleared (0–2× patches swept).
 *
 * `now` is injectable for deterministic tests.
 */
export function sweepExpiredSeats(
  db: DatabaseSync,
  ttlSeconds: number,
  now: number = Date.now(),
): number {
  const cutoffSec = Math.floor(now / 1000) - ttlSeconds;
  let cleared = 0;

  // Clear seat_1_holder on rows where seat 1 is held but the heartbeat expired.
  const r1 = db.prepare(
    `UPDATE peer_review_patches
     SET seat_1_holder = NULL, seat_1_claimed_at = NULL
     WHERE seat_1_holder IS NOT NULL
       AND seat_1_claimed_at IS NOT NULL
       AND seat_1_claimed_at < ?`,
  ).run(cutoffSec) as { changes: number };
  cleared += r1.changes;

  // Clear seat_2_holder on rows where seat 2 is held but the heartbeat expired.
  const r2 = db.prepare(
    `UPDATE peer_review_patches
     SET seat_2_holder = NULL, seat_2_claimed_at = NULL
     WHERE seat_2_holder IS NOT NULL
       AND seat_2_claimed_at IS NOT NULL
       AND seat_2_claimed_at < ?`,
  ).run(cutoffSec) as { changes: number };
  cleared += r2.changes;

  return cleared;
}

/**
 * Token-bucket rate limit keyed on `(subjectId, action)` (AGT-420). Lazy
 * refill: tokens accrue at `capPerHour/3600` per second since the last
 * touch, capped at `capPerHour`. Consumes one token and returns true when
 * allowed, false when the bucket is empty. Always persists the recomputed
 * tokens + timestamp so the accounting is correct across calls. `now` is
 * injectable for deterministic tests.
 */
export function checkAndConsumeToken(
  db: DatabaseSync,
  subjectId: number,
  action: string,
  capPerHour: number,
  now: number = Date.now(),
): boolean {
  const nowSec = Math.floor(now / 1000);
  // The read-modify-write MUST be atomic: each SSH verb is its own process
  // with its own connection, so without a transaction two concurrent callers
  // can both SELECT tokens=1, both decide allowed, and both write 0 — letting
  // a flood exceed the cap by ~1 per racing pair (the exact spend-amplification
  // this bounds). BEGIN IMMEDIATE takes the write lock at the SELECT, so
  // concurrent callers serialize (busy_timeout makes them wait, not error).
  // Caller must NOT already be inside a transaction. AGT-420 security review.
  db.exec("BEGIN IMMEDIATE");
  try {
    const row = db
      .prepare(
        `SELECT tokens, updated_at FROM rate_limits WHERE subject_id = ? AND action = ?`,
      )
      .get(subjectId, action) as
      | { tokens: number; updated_at: number }
      | undefined;

    let tokens: number;
    if (!row) {
      tokens = capPerHour; // first call for this subject/action: full bucket
    } else {
      const elapsed = Math.max(0, nowSec - row.updated_at);
      tokens = Math.min(capPerHour, row.tokens + elapsed * (capPerHour / 3600));
    }

    const allowed = tokens >= 1;
    if (allowed) tokens -= 1;

    db.prepare(
      `INSERT INTO rate_limits (subject_id, action, tokens, updated_at)
         VALUES (?, ?, ?, ?)
       ON CONFLICT(subject_id, action)
         DO UPDATE SET tokens = excluded.tokens, updated_at = excluded.updated_at`,
    ).run(subjectId, action, tokens, nowSec);

    db.exec("COMMIT");
    return allowed;
  } catch (err) {
    try {
      db.exec("ROLLBACK");
    } catch {
      // already rolled back / no active txn — nothing to do
    }
    throw err;
  }
}

export interface CachedServerVerdict {
  verdict: string;
  prose: string;
}

/** Look up a cached server verdict for an identical (reviewer, diff, prompt)
 * triple (AGT-420). Mirrors lib/db.ts findCachedVerdict. */
export function findCachedServerVerdict(
  db: DatabaseSync,
  reviewer: string,
  diff_sha256: string,
  prompt_sha256: string,
): CachedServerVerdict | null {
  const row = db
    .prepare(
      `SELECT verdict, prose FROM server_verdicts
        WHERE reviewer = ? AND diff_sha256 = ? AND prompt_sha256 = ?`,
    )
    .get(reviewer, diff_sha256, prompt_sha256) as
    | CachedServerVerdict
    | undefined;
  // Reconstruct as a plain object — node:sqlite `.get()` returns a
  // null-prototype row, which trips deepStrictEqual and is awkward for
  // callers. Return a clean { verdict, prose } or null.
  return row ? { verdict: row.verdict, prose: row.prose } : null;
}

/** Persist a server verdict for future cache hits (AGT-420). Upsert: the
 * latest successful evaluation for a triple wins. Callers MUST NOT record
 * an API-error-path verdict — only a real model response. */
export function recordServerVerdict(
  db: DatabaseSync,
  reviewer: string,
  diff_sha256: string,
  prompt_sha256: string,
  verdict: string,
  prose: string,
): void {
  db.prepare(
    `INSERT INTO server_verdicts (reviewer, diff_sha256, prompt_sha256, verdict, prose, created_at)
       VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(reviewer, diff_sha256, prompt_sha256)
       DO UPDATE SET verdict = excluded.verdict, prose = excluded.prose, created_at = excluded.created_at`,
  ).run(
    reviewer,
    diff_sha256,
    prompt_sha256,
    verdict,
    prose,
    Math.floor(Date.now() / 1000),
  );
}

/** Defensive positive-int env reader: bad/absent value → default, never
 * throws (a typo must not crash the boot/request path — AGT-420). */
function positiveIntEnv(name: string, def: number): number {
  const raw = process.env[name];
  if (!raw) return def;
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 ? n : def;
}

/** Per-hour review cap by role (AGT-420). `member` (broadly granted by
 * single-use invite — the spend-amplification blast radius) uses
 * MAX_REVIEWS_PER_HOUR (default 30); admin/owner get 5× headroom so the
 * operator isn't throttled while a compromised elevated key stays bounded. */
export function resolveReviewRateCap(role: Role): number {
  const base = positiveIntEnv("MAX_REVIEWS_PER_HOUR", 30);
  return role === "member" ? base : base * 5;
}

/** Per-admin invite cap (AGT-420). MAX_INVITES_PER_HOUR, default 10. */
export function resolveInviteRateCap(): number {
  return positiveIntEnv("MAX_INVITES_PER_HOUR", 10);
}

export interface InsertUserInput {
  short_name: string;
  ssh_pubkey: string;
  ssh_fp: string;
  stamp_pubkey?: string | null;
  role: Role;
  source: UserSource;
  invited_by?: number | null;
}

/** Insert a user. Throws if short_name or ssh_fp collide. */
export function insertUser(db: DatabaseSync, input: InsertUserInput): number {
  const stmt = db.prepare(
    `INSERT INTO users (short_name, ssh_pubkey, ssh_fp, stamp_pubkey, role, source, invited_by, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  const result = stmt.run(
    input.short_name,
    input.ssh_pubkey,
    input.ssh_fp,
    input.stamp_pubkey ?? null,
    input.role,
    input.source,
    input.invited_by ?? null,
    Math.floor(Date.now() / 1000),
  );
  return Number(result.lastInsertRowid);
}

/**
 * Idempotent insert keyed on ssh_fp. Returns the row id (newly-inserted or
 * pre-existing) and a `created` flag. Does NOT mutate role/short_name of an
 * existing row — the env-sync path runs on every boot, and we don't want
 * a manual admin demotion in the DB to be silently re-promoted by an
 * env-var entry that's still hanging around.
 *
 * If the caller's proposed short_name collides with an existing row that
 * has a DIFFERENT fingerprint, this throws. The seed-users entrypoint
 * handles that by appending a numeric suffix.
 */
export function upsertUserByFingerprint(
  db: DatabaseSync,
  input: InsertUserInput,
): { id: number; created: boolean } {
  const existing = findUserBySshFingerprint(db, input.ssh_fp);
  if (existing) return { id: existing.id, created: false };
  const id = insertUser(db, input);
  return { id, created: true };
}

export function findUserBySshFingerprint(
  db: DatabaseSync,
  ssh_fp: string,
): UserRow | null {
  const stmt = db.prepare(
    `SELECT id, short_name, ssh_pubkey, ssh_fp, stamp_pubkey, role, source,
            invited_by, created_at, last_seen_at
     FROM users WHERE ssh_fp = ?`,
  );
  const row = stmt.get(ssh_fp) as UserRow | undefined;
  return row ?? null;
}

/**
 * Look up an enrolled user by their stamp (Ed25519) public key in SPKI PEM
 * form. Used by the SSE `/peer/events` authorization step: a key that signed a
 * valid challenge is only authorized if it belongs to an enrolled user.
 *
 * PEM whitespace is normalized on both sides of the compare so that a key sent
 * with CRLF line endings, a trailing newline, or no trailing newline still
 * matches the canonical form stored at enrollment time. The base64 body is
 * what carries the identity; surrounding whitespace is not significant.
 */
export function findUserByStampPubkey(
  db: DatabaseSync,
  stamp_pubkey_pem: string,
): UserRow | null {
  const target = normalizePemWhitespace(stamp_pubkey_pem);
  if (!target) return null;
  const stmt = db.prepare(
    `SELECT id, short_name, ssh_pubkey, ssh_fp, stamp_pubkey, role, source,
            invited_by, created_at, last_seen_at
     FROM users WHERE stamp_pubkey IS NOT NULL`,
  );
  const rows = stmt.all() as unknown as UserRow[];
  for (const row of rows) {
    if (row.stamp_pubkey && normalizePemWhitespace(row.stamp_pubkey) === target) {
      return row;
    }
  }
  return null;
}

/** Collapse PEM whitespace (CRLF→LF, strip blank lines, trim) for comparison. */
function normalizePemWhitespace(pem: string): string {
  return pem
    .replace(/\r\n/g, "\n")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .join("\n");
}

export function findUserByShortName(
  db: DatabaseSync,
  short_name: string,
): UserRow | null {
  const stmt = db.prepare(
    `SELECT id, short_name, ssh_pubkey, ssh_fp, stamp_pubkey, role, source,
            invited_by, created_at, last_seen_at
     FROM users WHERE short_name = ?`,
  );
  const row = stmt.get(short_name) as UserRow | undefined;
  return row ?? null;
}

export function listUsers(db: DatabaseSync): UserRow[] {
  const stmt = db.prepare(
    `SELECT id, short_name, ssh_pubkey, ssh_fp, stamp_pubkey, role, source,
            invited_by, created_at, last_seen_at
     FROM users
     ORDER BY id`,
  );
  return stmt.all() as unknown as UserRow[];
}

export function countByRole(db: DatabaseSync, role: Role): number {
  const stmt = db.prepare(`SELECT COUNT(*) AS n FROM users WHERE role = ?`);
  const row = stmt.get(role) as { n: number };
  return row.n;
}

/**
 * Stamp `users.last_seen_at` (unix seconds) for a user on every
 * authenticated invocation (AGT-422). The column already existed in the
 * schema but was never written; this is the writer. `now` is injectable for
 * tests. Call from the writable verb paths (stamp-review / mint-invite /
 * users-cli) — NOT the read-only per-handshake AuthorizedKeysCommand
 * resolver, which fires far more often and opens the DB read-only.
 */
export function touchLastSeen(
  db: DatabaseSync,
  userId: number,
  now: number = Date.now(),
): void {
  db.prepare(`UPDATE users SET last_seen_at = ? WHERE id = ?`).run(
    Math.floor(now / 1000),
    userId,
  );
}

/**
 * Generate a short_name that doesn't collide with any existing row. If
 * `desired` is free, returns it; otherwise appends `-2`, `-3`, ... until
 * a free slot is found. Used by the env-sync path where the proposed
 * short_name is derived from the SSH key's comment (often "user@host"),
 * which can collide if two keys share the same comment.
 */
export function suggestUniqueShortName(
  db: DatabaseSync,
  desired: string,
): string {
  if (!findUserByShortName(db, desired)) return desired;
  for (let i = 2; i < 10000; i++) {
    const candidate = `${desired}-${i}`;
    if (!findUserByShortName(db, candidate)) return candidate;
  }
  throw new Error(
    `could not find a unique short_name for "${desired}" after 10000 attempts`,
  );
}
