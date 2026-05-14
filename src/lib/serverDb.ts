/**
 * Membership sqlite for the stamp server.
 *
 * Lives on the persistent volume at /srv/git/.stamp-state/users.db. Holds:
 *   - users: SSH pubkey → role (owner/admin/member), optional stamp signing
 *     pubkey, source provenance (env / bootstrap / invite / manual)
 *   - invites: single-use, time-bounded tokens an admin mints to onboard
 *     a teammate (phase 2)
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
    ensureDir(dir, 0o750);
    if (!opts.skipChmod) {
      // ensureDir no-ops on an existing directory, so this explicit
      // chmod is what tightens perms on a redeploy where the dir was
      // created at a looser mode by an earlier image version.
      chmodSync(dir, 0o750);
    }
  }

  const db = new DatabaseSync(path, { readOnly });

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
  `);
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
