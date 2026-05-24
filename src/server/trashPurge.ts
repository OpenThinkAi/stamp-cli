/**
 * Trash retention (AGT-423). Soft-deleted bare repos live at
 * `/srv/git/.trash/<YYYYMMDDTHHMMSSZ>-<name>.git` (see server/delete-stamp-repo)
 * with full git history + any accidentally-committed PII intact. Nothing
 * GC'd them, so an operator who "deleted" a repo to erase sensitive content
 * left it sitting on the server forever.
 *
 * This module is the single source of purge logic, shared by:
 *   - the in-process sweep worker in http-server.ts (periodic, automatic), and
 *   - the on-demand `purge-trash` SSH verb (`stamp server-repos purge`).
 *
 * The deletion instant is encoded in the entry NAME (set by
 * delete-stamp-repo's `date -u +%Y%m%dT%H%M%SZ`), so age is decodable from
 * the name alone — no reliance on mtime (which the boot `chown -R` +
 * hook-refresh churn). We deliberately do the age math + `rm -rf` here in
 * TypeScript rather than in the sibling POSIX-sh trash scripts: epoch/date
 * arithmetic on the container's busybox `date` is fragile, and getting a
 * destructive recursive delete right is worth the unit-test coverage.
 */

import { readdirSync, realpathSync, rmSync, statSync } from "node:fs";
import path from "node:path";

export const DEFAULT_TRASH_DIR = "/srv/git/.trash";

// Trash entry shape: <YYYYMMDD>T<HHMMSS>Z-<repo-name>.git. The repo-name part
// matches the same grammar delete-stamp-repo validates. Anchored so a
// non-conforming dir under .trash/ (an operator's manual file, a partial
// move) is never a purge candidate.
const TRASH_ENTRY_RE =
  /^(\d{8})T(\d{6})Z-[A-Za-z0-9_][A-Za-z0-9._-]*\.git$/;

/**
 * Parse the UTC timestamp prefix of a trash entry name to epoch ms, or null
 * when the name doesn't match the trash shape (caller leaves such entries
 * untouched).
 */
export function parseTrashTimestamp(name: string): number | null {
  const m = TRASH_ENTRY_RE.exec(name);
  if (!m) return null;
  const d = m[1]!; // YYYYMMDD
  const t = m[2]!; // HHMMSS
  const iso = `${d.slice(0, 4)}-${d.slice(4, 6)}-${d.slice(6, 8)}T${t.slice(0, 2)}:${t.slice(2, 4)}:${t.slice(4, 6)}Z`;
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? null : ms;
}

/**
 * Pure: of the given trash entry names, return those older than
 * `nowMs - ttlDays`. Names that don't parse as trash entries are skipped
 * (never purged). `ttlDays === 0` purges everything with a parseable
 * timestamp at/under `nowMs` (the documented "purge all" escape).
 */
export function computeTrashEntriesToPurge(
  names: string[],
  nowMs: number,
  ttlDays: number,
): string[] {
  const cutoff = nowMs - ttlDays * 86_400_000;
  const out: string[] = [];
  for (const name of names) {
    const ts = parseTrashTimestamp(name);
    if (ts === null) continue;
    if (ts < cutoff) out.push(name);
  }
  return out;
}

export interface PurgeTrashResult {
  purged: string[];
  /** Candidates that were NOT removed by a containment check (symlink
   *  escape, shape mismatch, non-directory, fs error) — surfaced so a
   *  refusal is visible rather than silent. */
  skipped: string[];
}

/**
 * Remove trash entries older than `ttlDays` from `trashDir`, with layered
 * containment for the destructive `rm -rf`:
 *   1. name must match the strict trash-entry shape;
 *   2. its realpath must be a DIRECT child of the realpath of trashDir
 *      (defeats a symlinked entry pointing outside the trash dir);
 *   3. never the trash dir itself; must be a directory.
 * Missing trashDir → no-op.
 */
export function purgeTrash(
  trashDir: string,
  ttlDays: number,
  nowMs: number = Date.now(),
): PurgeTrashResult {
  const purged: string[] = [];
  const skipped: string[] = [];

  let names: string[];
  try {
    names = readdirSync(trashDir);
  } catch {
    return { purged, skipped }; // trash dir doesn't exist yet → nothing to do
  }

  let canonRoot: string;
  try {
    canonRoot = realpathSync(trashDir);
  } catch {
    return { purged, skipped };
  }

  for (const name of computeTrashEntriesToPurge(names, nowMs, ttlDays)) {
    // Re-assert the shape (defense in depth; compute already filtered).
    if (!TRASH_ENTRY_RE.test(name)) {
      skipped.push(name);
      continue;
    }
    const full = path.join(trashDir, name);
    let canon: string;
    try {
      canon = realpathSync(full);
    } catch {
      skipped.push(name);
      continue;
    }
    // Must be a direct child of the trash dir and not the dir itself.
    if (canon === canonRoot || path.dirname(canon) !== canonRoot) {
      skipped.push(name);
      continue;
    }
    try {
      if (!statSync(canon).isDirectory()) {
        skipped.push(name);
        continue;
      }
      rmSync(canon, { recursive: true, force: true });
      purged.push(name);
    } catch {
      skipped.push(name);
    }
  }
  return { purged, skipped };
}

/**
 * STAMP_TRASH_TTL_DAYS (default 30). Defensive parse — a bad value falls
 * back to the default and never throws, so a typo can't crash the
 * self-deploying server's boot or sweep worker (the AGT-411 discipline).
 */
export function resolveTrashTtlDays(): number {
  const raw = process.env["STAMP_TRASH_TTL_DAYS"];
  if (!raw) return 30;
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 ? n : 30;
}
