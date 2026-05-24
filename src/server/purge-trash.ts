/**
 * SSH verb: permanently purge soft-deleted bare repos older than a TTL
 * (AGT-423).
 *
 * Reachable as `git@<host> purge-trash --older-than <N>d`; the
 * `stamp server-repos purge` client wraps it.
 *
 * AUTHORIZATION (AGT-423 security review): this is an IRREVERSIBLE
 * mass-delete — unlike its reversible soft-delete sibling, there is no
 * recovery path once trash is purged. So it gates on role ≥ admin (owner or
 * admin), matching the operator-only authority class of `stamp invites
 * mint`. A bare enrolled member (push/review access) must NOT be able to
 * destroy server-side history. (The pre-existing soft-delete script's own
 * role posture is out of scope here; this verb does not loosen it.)
 *
 * All purge logic + the destructive-delete containment lives in
 * trashPurge.ts (shared with the in-process sweep worker). This file is the
 * argv + auth + output shell.
 *
 * Exit codes (consumed by the client for operator prose):
 *   0 — success (purged 0+ entries)
 *   1 — server-side config / identity-binding error
 *   2 — usage error (bad/missing --older-than)
 *   3 — authority denial (caller's role doesn't permit purge)
 */

import {
  findUserBySshFingerprint,
  openServerDb,
  touchLastSeen,
} from "../lib/serverDb.js";
import { readAuthenticatedPubkey } from "../lib/sshUserAuth.js";
import {
  DEFAULT_TRASH_DIR,
  purgeTrash,
  resolveTrashTtlDays,
} from "./trashPurge.js";

function fail(message: string, code: number): never {
  process.stderr.write(`error: ${message}\n`);
  process.exit(code);
}

/** Parse `--older-than <N>d`; fall back to STAMP_TRASH_TTL_DAYS when absent.
 *  `0d` is the documented "purge all" escape. */
function parseOlderThanDays(argv: string[]): number {
  let spec: string | null = null;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--older-than") {
      const next = argv[i + 1];
      if (next === undefined) fail("'--older-than' requires a value (e.g. 30d)", 2);
      spec = next;
      i++;
    } else {
      fail(`unexpected argument: ${a}`, 2);
    }
  }
  if (spec === null) return resolveTrashTtlDays();
  const m = /^(\d+)d$/.exec(spec);
  if (!m) {
    fail(
      `--older-than must be '<N>d' (whole days, e.g. 30d; 0d purges all) — got ${JSON.stringify(spec)}`,
      2,
    );
  }
  return Number(m[1]);
}

/** Resolve + authorize the caller: must be an enrolled owner/admin. */
function authorizeOperator(): void {
  const caller = readAuthenticatedPubkey();
  if (!caller) {
    fail(
      "could not determine authenticated identity (SSH_USER_AUTH unset or has no " +
        "publickey entry). Server may be missing 'ExposeAuthInfo yes' in sshd_config.",
      1,
    );
  }
  const db = openServerDb({ skipChmod: true });
  try {
    const callerRow = findUserBySshFingerprint(db, caller.fingerprint);
    if (!callerRow) {
      fail(
        `caller fingerprint ${caller.fingerprint} is not in the membership DB.`,
        1,
      );
    }
    if (callerRow.role !== "owner" && callerRow.role !== "admin") {
      fail(
        `role ${callerRow.role} is not permitted to purge trash — this is an ` +
          `irreversible mass-delete; need owner or admin.`,
        3,
      );
    }
    // Authenticated operator invocation — record activity (AGT-422).
    touchLastSeen(db, callerRow.id);
  } finally {
    db.close();
  }
}

function main(): void {
  // Parse argv first (cheap usage errors before touching the DB), then
  // authorize, then act.
  const ttlDays = parseOlderThanDays(process.argv.slice(2));
  authorizeOperator();

  const trashDir = process.env["STAMP_TRASH_DIR"] || DEFAULT_TRASH_DIR;
  const { purged, skipped } = purgeTrash(trashDir, ttlDays);

  if (purged.length === 0) {
    process.stderr.write(`note: no trashed repos older than ${ttlDays}d to purge\n`);
  } else {
    process.stderr.write(
      `note: purged ${purged.length} trashed repo${purged.length === 1 ? "" : "s"} older than ${ttlDays}d: ${purged.join(", ")}\n`,
    );
  }
  if (skipped.length > 0) {
    process.stderr.write(
      `note: skipped ${skipped.length} entr${skipped.length === 1 ? "y" : "ies"} that failed a containment check: ${skipped.join(", ")}\n`,
    );
  }
  // Write op → no stdout payload (matches the trash-script convention).
}

main();
