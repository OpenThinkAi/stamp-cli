/**
 * Per-user repo authorization for the stamp server (AGT-2252).
 *
 * Before this module, the `--org` / `--repo` a caller passed to the
 * `stamp-review` SSH verb were only shape-checked. They pick which
 * per-repo prompt override (`<cacheRoot>/<org>/<repo>/<reviewer>.md`)
 * the server reviews under, and the signed `ApprovalV4` does not record
 * them — so any enrolled member could review their diff under another
 * repo's (possibly lenient) override and fold the signed approval into
 * an envelope for a different repo.
 *
 * The fix binds the caller-chosen org/repo to the caller's
 * authorization, stored in the `user_repo_grants` table:
 *
 *   - owners / admins are the server operators: always authorized.
 *   - a member with a grant for `<org>/<repo>` (or `<org>/*`) is
 *     authorized for that pair; per-repo overrides apply.
 *   - a member with grants, none matching, is DENIED — the verb refuses.
 *   - a member with no grants at all is UNSCOPED (the pre-AGT-2252
 *     single-tenant shape): they may still request reviews under the
 *     server's default prompts, but a per-repo override is never applied
 *     for them — the verb refuses when one exists for the requested pair
 *     instead of silently swapping prompts.
 *
 * Org-level helpers (`isCallerAuthorizedForOrg`) are exported for the
 * SSE subscription binding (AGT-2256), which filters `?org=` lists
 * against the same grants.
 *
 * All org/repo comparisons are case-insensitive (GitHub slugs are);
 * values are stored lowercased.
 */

import type { DatabaseSync } from "node:sqlite";

import type { UserRow } from "./serverDb.js";

/** Same shape the `stamp-review` verb enforces for `--org` / `--repo`. */
export const REPO_SLUG_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,99}$/;

/** The repo value in a grant row that covers every repo in the org. */
export const ORG_WILDCARD = "*";

export interface RepoGrant {
  org: string;
  /** Lowercased repo slug, or `*` for an org-wide grant. */
  repo: string;
  granted_by: number | null;
  created_at: number;
}

/**
 * The outcome of checking a caller against an `<org>/<repo>` pair.
 *
 *   - `operator`: owner/admin; unrestricted.
 *   - `granted`:  member holding a matching grant.
 *   - `unscoped`: member with no grants at all (legacy single-tenant).
 *   - `denied`:   member with grants, none of which match.
 */
export type RepoAccess = "operator" | "granted" | "unscoped" | "denied";

function isOperator(caller: Pick<UserRow, "role">): boolean {
  return caller.role === "owner" || caller.role === "admin";
}

/**
 * Parse `<org>/<repo>` (repo may be `*`) into a lowercased pair.
 * Returns null on any shape the verb would reject.
 */
export function parseRepoSpec(spec: string): { org: string; repo: string } | null {
  const parts = spec.split("/");
  if (parts.length !== 2) return null;
  const [org, repo] = parts as [string, string];
  if (!REPO_SLUG_RE.test(org)) return null;
  if (repo !== ORG_WILDCARD && !REPO_SLUG_RE.test(repo)) return null;
  return { org: org.toLowerCase(), repo: repo.toLowerCase() };
}

export function listRepoGrants(db: DatabaseSync, userId: number): RepoGrant[] {
  return db
    .prepare(
      `SELECT org, repo, granted_by, created_at FROM user_repo_grants
        WHERE user_id = ? ORDER BY org, repo`,
    )
    .all(userId) as unknown as RepoGrant[];
}

/** Insert a grant. Returns false when the exact grant already existed. */
export function addRepoGrant(
  db: DatabaseSync,
  userId: number,
  org: string,
  repo: string,
  grantedBy: number | null,
): boolean {
  const res = db
    .prepare(
      `INSERT OR IGNORE INTO user_repo_grants (user_id, org, repo, granted_by, created_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
    .run(userId, org.toLowerCase(), repo.toLowerCase(), grantedBy, Math.floor(Date.now() / 1000));
  return Number(res.changes) > 0;
}

/** Delete a grant. Returns false when no such grant existed. */
export function removeRepoGrant(
  db: DatabaseSync,
  userId: number,
  org: string,
  repo: string,
): boolean {
  const res = db
    .prepare(`DELETE FROM user_repo_grants WHERE user_id = ? AND org = ? AND repo = ?`)
    .run(userId, org.toLowerCase(), repo.toLowerCase());
  return Number(res.changes) > 0;
}

/**
 * Decide whether `caller` may act on `<org>/<repo>`. See the module
 * header for the four outcomes.
 */
export function resolveRepoAccess(
  db: DatabaseSync,
  caller: Pick<UserRow, "id" | "role">,
  org: string,
  repo: string,
): RepoAccess {
  if (isOperator(caller)) return "operator";
  const grants = listRepoGrants(db, caller.id);
  if (grants.length === 0) return "unscoped";
  const o = org.toLowerCase();
  const r = repo.toLowerCase();
  const match = grants.some((g) => g.org === o && (g.repo === ORG_WILDCARD || g.repo === r));
  return match ? "granted" : "denied";
}

/**
 * Whether `caller` holds ANY grant inside `org` (operators: always).
 * Unscoped members (no grants) return false — callers that want the
 * legacy "no grants means unrestricted" behaviour must check
 * `listRepoGrants(...).length === 0` themselves, so the permissive
 * fallback is an explicit choice at each call site.
 */
export function isCallerAuthorizedForOrg(
  db: DatabaseSync,
  caller: Pick<UserRow, "id" | "role">,
  org: string,
): boolean {
  if (isOperator(caller)) return true;
  const row = db
    .prepare(`SELECT 1 AS ok FROM user_repo_grants WHERE user_id = ? AND org = ? LIMIT 1`)
    .get(caller.id, org.toLowerCase());
  return row !== undefined;
}
