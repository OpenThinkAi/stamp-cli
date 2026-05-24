/**
 * SSH verb: purge soft-deleted bare repos older than a TTL (AGT-423).
 *
 * Reachable as `git@<host> purge-trash --older-than <N>d`; the
 * `stamp server-repos purge` client wraps it. Like its sibling trash
 * scripts (delete / restore / list) it is SSH-access-gated only — no
 * membership role check; holding an AUTHORIZED_KEYS / enrolled SSH key is
 * the bar, same as the soft-delete it complements.
 *
 * All purge logic + the destructive-delete containment lives in
 * trashPurge.ts (shared with the in-process sweep worker). This file is the
 * thin argv + output shell.
 *
 * Exit codes (consumed by the client for operator prose):
 *   0 — success (purged 0+ entries)
 *   2 — usage error (bad/missing --older-than)
 */

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

function main(): void {
  const ttlDays = parseOlderThanDays(process.argv.slice(2));
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
