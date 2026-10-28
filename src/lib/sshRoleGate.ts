/**
 * Role gate for SSH-invoked server verbs (AGT-423, AGT-2259).
 *
 * Resolves the caller from sshd's SSH_USER_AUTH (ExposeAuthInfo) against
 * the membership DB and decides whether their role permits an
 * operator-class action. Every SSH user maps to the one Unix user `git`,
 * so this lookup is the only thing that tells an enrolled `member` apart
 * from an `admin`/`owner` — filesystem permissions can't.
 *
 * Shared by the Node verbs (purge-trash) and by the `stamp-require-role`
 * helper the shell verbs (new/delete/restore-stamp-repo) call before they
 * touch /srv/git.
 */

import {
  findUserBySshFingerprint,
  openServerDb,
  touchLastSeen,
  type Role,
} from "./serverDb.js";
import { readAuthenticatedPubkey } from "./sshUserAuth.js";

/** Minimum role an action needs. `admin` admits admin and owner. */
export type MinRole = "admin" | "owner";

export type RoleGateResult =
  | { ok: true }
  /** No authenticated identity, or the key isn't enrolled. Exit 1. */
  | { ok: false; kind: "identity"; message: string }
  /** Enrolled, but the role is below `min`. Exit 3. */
  | { ok: false; kind: "denied"; message: string };

const RANK: Record<Role, number> = { member: 0, admin: 1, owner: 2 };

/**
 * Check the SSH caller's role against `min`. `action` is operator prose
 * for the denial message ("delete repo 'foo'"). Records last_seen on success,
 * matching the other authenticated verbs (AGT-422).
 *
 * Absence of an identity is never a green light: a missing/unreadable
 * SSH_USER_AUTH or an unenrolled fingerprint is refused.
 */
export function checkCallerRole(min: MinRole, action: string): RoleGateResult {
  const caller = readAuthenticatedPubkey();
  if (!caller) {
    return {
      ok: false,
      kind: "identity",
      message:
        "could not determine authenticated identity (SSH_USER_AUTH unset or has no " +
        "publickey entry). Server may be missing 'ExposeAuthInfo yes' in sshd_config.",
    };
  }
  const db = openServerDb({ skipChmod: true });
  try {
    const row = findUserBySshFingerprint(db, caller.fingerprint);
    if (!row) {
      return {
        ok: false,
        kind: "identity",
        message: `caller fingerprint ${caller.fingerprint} is not in the membership DB.`,
      };
    }
    if (RANK[row.role] < RANK[min]) {
      const need = min === "owner" ? "owner" : "owner or admin";
      return {
        ok: false,
        kind: "denied",
        message:
          `role ${row.role} is not permitted to ${action}; need ${need}. ` +
          `Ask an ${need} to run it.`,
      };
    }
    touchLastSeen(db, row.id);
    return { ok: true };
  } finally {
    db.close();
  }
}
