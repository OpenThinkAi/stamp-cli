/**
 * Invite token mint / consume operations against the membership sqlite.
 *
 * Tokens are 32 bytes of cryptographically random data, base64url-encoded
 * (no padding) — 43 ASCII characters that survive copy-paste through
 * Slack/iMessage/wormhole/etc. without losing the trailing `=` padding
 * that several chat clients silently trim.
 *
 * TTL is 15 minutes. Tokens are single-use: consume marks `consumed_at`
 * and refuses subsequent consumption of the same token. Expiry is enforced
 * at consume time (the row stays in the DB for audit until phase 5 prune
 * support sweeps stale rows).
 *
 * The invite role is constrained to 'admin' or 'member' by the schema —
 * minting an owner-via-invite is not supported (owners are promoted via
 * the phase-3 self-promote path against an existing admin/member account).
 */

import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import type { InviteRole, InviteRow } from "./serverDb.js";

export const INVITE_TTL_SECONDS = 15 * 60;
export const TOKEN_BYTES = 32;
export const TOKEN_LENGTH_CHARS = 43; // ceil(32 * 4 / 3) with no padding

/** Generate a fresh single-use invite token: 32 bytes, base64url, no padding. */
export function generateInviteToken(): string {
  return randomBytes(TOKEN_BYTES).toString("base64url");
}

export interface MintInviteInput {
  role: InviteRole;
  invited_by: number;
  /** Override the wall-clock for deterministic tests. Seconds since epoch. */
  now?: number;
  /** Override the TTL for tests. Defaults to INVITE_TTL_SECONDS. */
  ttl_seconds?: number;
}

export interface MintedInvite {
  token: string;
  expires_at: number;
}

export function mintInvite(
  db: DatabaseSync,
  input: MintInviteInput,
): MintedInvite {
  const token = generateInviteToken();
  const now = input.now ?? Math.floor(Date.now() / 1000);
  const ttl = input.ttl_seconds ?? INVITE_TTL_SECONDS;
  const expires_at = now + ttl;

  const stmt = db.prepare(
    `INSERT INTO invites (token, role, invited_by, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?)`,
  );
  stmt.run(token, input.role, input.invited_by, now, expires_at);

  return { token, expires_at };
}

export type ConsumeResult =
  | { ok: true; row: InviteRow }
  | { ok: false; reason: "not_found" | "expired" | "already_consumed" };

/**
 * Atomically look up + consume a token in a single transaction. The atomic
 * read-then-write under SQLITE_BEGIN IMMEDIATE prevents two concurrent
 * accept requests from both succeeding on the same token — the second
 * sees `already_consumed` on its UPDATE.
 *
 * Caller is expected to ALSO write the user row inside the same DB call
 * sequence — but we expose consume as a separate primitive so the caller
 * can perform the user insert against the role from this invite without
 * carrying it through opaquely.
 */
export function consumeInviteToken(
  db: DatabaseSync,
  token: string,
  now?: number,
): ConsumeResult {
  const wallclock = now ?? Math.floor(Date.now() / 1000);
  db.exec("BEGIN IMMEDIATE");
  try {
    const selectStmt = db.prepare(`SELECT * FROM invites WHERE token = ?`);
    const row = selectStmt.get(token) as InviteRow | undefined;
    if (!row) {
      db.exec("ROLLBACK");
      return { ok: false, reason: "not_found" };
    }
    if (row.consumed_at !== null) {
      db.exec("ROLLBACK");
      return { ok: false, reason: "already_consumed" };
    }
    if (row.expires_at < wallclock) {
      db.exec("ROLLBACK");
      return { ok: false, reason: "expired" };
    }

    // Mark consumed. consumed_by is set later by the caller once the user
    // row is inserted and we know its id.
    db.prepare(
      `UPDATE invites SET consumed_at = ? WHERE token = ? AND consumed_at IS NULL`,
    ).run(wallclock, token);

    db.exec("COMMIT");
    return { ok: true, row };
  } catch (e) {
    try {
      db.exec("ROLLBACK");
    } catch {
      // ignore — propagate the original error
    }
    throw e;
  }
}

/** Set the consumed_by user id on an already-consumed invite. */
export function markInviteConsumer(
  db: DatabaseSync,
  token: string,
  user_id: number,
): void {
  db.prepare(`UPDATE invites SET consumed_by = ? WHERE token = ?`).run(
    user_id,
    token,
  );
}

export function findInvite(db: DatabaseSync, token: string): InviteRow | null {
  const row = db
    .prepare(`SELECT * FROM invites WHERE token = ?`)
    .get(token) as InviteRow | undefined;
  return row ?? null;
}
