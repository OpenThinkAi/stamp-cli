/**
 * User-management operations against the membership sqlite, with the
 * role authority matrix and last-owner guard enforced in one place.
 *
 * Authority matrix:
 *
 *   - Owner: full control. May change anyone's role to anything (subject
 *     to the last-owner guard) and remove anyone (subject to the same).
 *   - Admin: may manage MEMBERS only. May not modify admins or owners,
 *     and may not promote anyone to admin/owner. Bootstrap exception:
 *     when no owners exist anywhere in the table, an admin may promote
 *     THEMSELVES to owner — exactly once per server lifetime, since
 *     after that promotion the no-owners precondition no longer holds.
 *   - Member: no user-management surface at all.
 *
 * Last-owner guard: any operation that would leave zero owners (demoting
 * the last owner, or removing the last owner) is refused with a
 * `last_owner_would_be_lost` reason. Operators are expected to promote a
 * successor first.
 *
 * These rules are server-side and authoritative; the CLI sends the
 * caller's request and the server decides. Putting them in a lib module
 * (not the SSH wrapper) so unit tests can exercise the full matrix
 * without spawning subprocesses.
 */

import { DatabaseSync } from "node:sqlite";
import {
  countByRole,
  findUserByShortName,
  type Role,
  type UserRow,
} from "./serverDb.js";

export type SetRoleDenial =
  | "target_not_found"
  | "caller_lacks_authority"
  | "last_owner_would_be_lost"
  | "invalid_target_role";

export type SetRoleResult =
  | { ok: true; old_role: Role; new_role: Role; no_change: boolean }
  | { ok: false; reason: SetRoleDenial };

const VALID_ROLES: ReadonlySet<Role> = new Set(["owner", "admin", "member"]);

/**
 * Decide whether `caller` may change `target`'s role to `newRole`.
 * Returns null on approval, or the denial reason string.
 *
 * Authority is checked BEFORE the last-owner guard so a non-authoritative
 * caller gets a generic `caller_lacks_authority` rather than a
 * `last_owner_would_be_lost` reason that would leak "target is the last
 * owner" downstream. The guard still applies to authoritative callers
 * (e.g. a sole owner attempting to demote themselves).
 */
function checkSetRoleAuthority(
  caller: UserRow,
  target: UserRow,
  newRole: Role,
  ownerCount: number,
): SetRoleDenial | null {
  // Authority check first.
  let authority_ok = false;
  if (caller.role === "owner") {
    // Owners may set any target to any role.
    authority_ok = true;
  } else if (caller.role === "admin") {
    // Bootstrap: zero owners exist and admin is promoting THEMSELVES to
    // owner. This is the chicken-and-egg escape — without it, a server
    // seeded only from AUTHORIZED_KEYS (everyone admin, no owner) has
    // no path to a first owner.
    if (
      ownerCount === 0 &&
      newRole === "owner" &&
      target.id === caller.id
    ) {
      authority_ok = true;
    } else if (target.role === "member" && newRole === "member") {
      // Admins may manage members. Promotion to admin/owner is
      // owner-only; touching admins/owners is also owner-only.
      authority_ok = true;
    }
  }
  if (!authority_ok) return "caller_lacks_authority";

  // Last-owner guard runs after authority. By construction, only owners
  // can reach this branch with a target that is currently owner.
  if (target.role === "owner" && newRole !== "owner" && ownerCount <= 1) {
    return "last_owner_would_be_lost";
  }

  return null;
}

/**
 * Set `target_short_name`'s role to `newRole`, gated by the authority
 * matrix above. Returns a tagged result so callers can map specific
 * denial reasons to specific HTTP statuses / CLI exit codes.
 */
export function setUserRole(
  db: DatabaseSync,
  caller: UserRow,
  target_short_name: string,
  newRole: Role,
): SetRoleResult {
  if (!VALID_ROLES.has(newRole)) {
    return { ok: false, reason: "invalid_target_role" };
  }
  const target = findUserByShortName(db, target_short_name);
  if (!target) return { ok: false, reason: "target_not_found" };

  const ownerCount = countByRole(db, "owner");
  const denial = checkSetRoleAuthority(caller, target, newRole, ownerCount);
  if (denial) return { ok: false, reason: denial };

  const old_role = target.role;
  if (old_role === newRole) {
    // No-change is still an approved outcome — the caller had authority
    // for the transition, the row simply already holds the requested
    // role. Reported separately so CLI prose can call it out without
    // pretending a change happened.
    return { ok: true, old_role, new_role: newRole, no_change: true };
  }

  db.prepare(`UPDATE users SET role = ? WHERE id = ?`).run(newRole, target.id);
  return { ok: true, old_role, new_role: newRole, no_change: false };
}

export type RemoveUserDenial =
  | "target_not_found"
  | "caller_lacks_authority"
  | "last_owner_would_be_lost"
  | "cannot_remove_self";

export type RemoveUserResult =
  | { ok: true; removed: UserRow }
  | { ok: false; reason: RemoveUserDenial };

export function removeUser(
  db: DatabaseSync,
  caller: UserRow,
  target_short_name: string,
): RemoveUserResult {
  const target = findUserByShortName(db, target_short_name);
  if (!target) return { ok: false, reason: "target_not_found" };

  // Self-removal is explicitly disallowed. Operators who want to leave
  // a server should have another admin remove their row — prevents the
  // foot-gun of an admin accidentally deleting themselves mid-session
  // and losing access to fix it.
  if (target.id === caller.id) return { ok: false, reason: "cannot_remove_self" };

  // Authority first (same reason as setUserRole): a non-authoritative
  // caller gets a generic denial rather than a leak that the target is
  // the last owner.
  if (caller.role === "owner") {
    // Owners may remove anyone except via the guards above/below.
  } else if (caller.role === "admin") {
    // Admins may remove members only.
    if (target.role !== "member") {
      return { ok: false, reason: "caller_lacks_authority" };
    }
  } else {
    return { ok: false, reason: "caller_lacks_authority" };
  }

  // Last-owner guard. With authority already enforced, only owners can
  // reach this branch with a target that is currently owner; combined
  // with the self-removal block above, the guard is structurally
  // shadowed today (an owner can never remove "the last owner" who is
  // someone else, because if only one owner exists, the caller IS that
  // owner and was caught above). Kept for defense in depth — a future
  // code path that bypasses cannot_remove_self would otherwise zero out
  // ownership.
  const ownerCount = countByRole(db, "owner");
  if (target.role === "owner" && ownerCount <= 1) {
    return { ok: false, reason: "last_owner_would_be_lost" };
  }

  db.prepare(`DELETE FROM users WHERE id = ?`).run(target.id);
  return { ok: true, removed: target };
}

export type ListUsersDenial = "caller_lacks_authority";

export type ListUsersResult =
  | { ok: true; users: UserRow[] }
  | { ok: false; reason: ListUsersDenial };

/**
 * List all users. Everyone authenticated (member, admin, owner) may
 * call this. The data exposed (short_name, role, ssh pubkey comments)
 * is the same set teammates would see in any other multi-user
 * collaboration tool; keeping the list freely readable lowers the
 * coordination cost ("who else has access here?") without revealing
 * anything sensitive.
 */
export function listUsersForCaller(
  db: DatabaseSync,
  caller: UserRow,
): ListUsersResult {
  // The schema-level CHECK on role already ensures caller has a valid
  // role; this branch is here so a future "guest" or "read-only" tier
  // can be added without forgetting to gate the list path.
  if (
    caller.role !== "owner" &&
    caller.role !== "admin" &&
    caller.role !== "member"
  ) {
    return { ok: false, reason: "caller_lacks_authority" };
  }
  const rows = db
    .prepare(
      `SELECT id, short_name, ssh_pubkey, ssh_fp, stamp_pubkey, role, source,
              invited_by, created_at, last_seen_at
       FROM users
       ORDER BY
         CASE role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END,
         short_name`,
    )
    .all() as unknown as UserRow[];
  return { ok: true, users: rows };
}
