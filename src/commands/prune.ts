import { existsSync, readdirSync, statSync, unlinkSync } from "node:fs";
import { join } from "node:path";

import { openDb, peekPrunable, pruneReviews } from "../lib/db.js";
import { parseRetentionDuration } from "../lib/duration.js";
import { findRepoRoot, gitCommonDir, stampStateDbPath } from "../lib/paths.js";

export interface PruneOptions {
  /** Duration string: `<n>d`, `<n>h`, or `<n>m`. Required. */
  olderThan: string;
  /** Print what would be deleted without modifying the DB. */
  dryRun?: boolean;
}

/**
 * stamp prune --older-than <duration> [--dry-run]
 *
 * Two cleanup passes, both gated by the same duration:
 *
 * 1. Delete rows from `<repoRoot>/.git/stamp/state.db`'s `reviews` table
 *    whose `created_at` is older than now − duration, then VACUUM so the
 *    file actually shrinks. The `issues` column (verbatim reviewer prose)
 *    is kept intact for surviving rows — `stamp reviewers show` and
 *    `stamp log --reviews` still depend on it.
 *
 * 2. Walk `<gitCommonDir>/stamp/failed-parses/` and `failed-runs/` and
 *    unlink files whose `mtime` is older than now − duration. v4 audit
 *    L-PR1 (failed-parses): the spool directory was never auto-pruned,
 *    so on a noisy reviewer (LLM rate limiting, prompt drift) raw model
 *    output accumulates indefinitely despite the per-file mode-0600
 *    protection. The failed-runs/ sibling carries structured turn traces
 *    for cap-hit / aborted reviewer subprocesses (issue #26) and follows
 *    the same retention policy.
 *
 * `--dry-run` peeks both passes and prints what would be removed without
 * deleting anything or running VACUUM.
 *
 * No-ops cleanly when neither state.db nor either spool dir exists.
 */
export function runPrune(opts: PruneOptions): void {
  // Parse the duration first — before any short-circuit — so a typo'd
  // `--older-than` on a fresh repo still surfaces a parse error instead
  // of being silently swallowed by a "nothing to prune" no-op.
  const { sqliteModifier, humanLabel, durationMs } = parseRetentionDuration(
    opts.olderThan,
  );

  const repoRoot = findRepoRoot();
  const dbPath = stampStateDbPath(repoRoot);

  // Spool prune is independent of state.db existence — a fresh repo can
  // have a failed parse without ever recording an approved verdict, so
  // gate each spool pass on its own existsSync check below.
  const parsesDir = join(gitCommonDir(repoRoot), "stamp", "failed-parses");
  const runsDir = join(gitCommonDir(repoRoot), "stamp", "failed-runs");
  const spoolCutoffMs = Date.now() - durationMs;

  if (!existsSync(dbPath) && !existsSync(parsesDir) && !existsSync(runsDir)) {
    // Surface the absolute paths so an operator debugging "where is
    // stamp looking?" doesn't have to grep source. Both dirs route
    // through gitCommonDir so they show the worktree-correct location.
    console.log(
      `note: nothing to prune (none of ${dbPath}, ${parsesDir}, ${runsDir} exist — all are created on first \`stamp review\`)`,
    );
    return;
  }

  const db = existsSync(dbPath) ? openDb(dbPath) : null;
  try {
    if (opts.dryRun) {
      let any = false;
      if (db) {
        const peek = peekPrunable(db, sqliteModifier);
        if (peek.total > 0) {
          console.log(
            `would prune ${peek.total} review row${peek.total === 1 ? "" : "s"} older than ${humanLabel} (${peek.perReviewer.length} reviewer${peek.perReviewer.length === 1 ? "" : "s"} affected):`,
          );
          printPerReviewer(peek.perReviewer);
          any = true;
        }
      }
      for (const [label, dir] of [
        ["failed-parse", parsesDir],
        ["failed-run", runsDir],
      ] as const) {
        const peek = peekSpools(dir, spoolCutoffMs);
        if (peek.length > 0) {
          if (any) console.log("");
          console.log(
            `would prune ${peek.length} ${label} spool file${peek.length === 1 ? "" : "s"} older than ${humanLabel}:`,
          );
          for (const f of peek) console.log(`  ${f}`);
          any = true;
        }
      }
      if (!any) {
        console.log(`note: nothing to prune (no rows or spools older than ${humanLabel})`);
      } else {
        console.log("\n(dry run — no changes made)");
      }
      return;
    }

    let any = false;
    if (db) {
      const sizeBefore = statSync(dbPath).size;
      const result = pruneReviews(db, sqliteModifier);
      if (result.total > 0) {
        // VACUUM rewrites the whole file; must run outside any
        // transaction. Run it before reading the after-size so the
        // on-disk size reflects the post-VACUUM state, not the pre-
        // VACUUM (page-tombstoned) state.
        db.exec("VACUUM");
        const sizeAfter = statSync(dbPath).size;
        console.log(
          `${result.total} review row${result.total === 1 ? "" : "s"} pruned (${result.perReviewer.length} reviewer${result.perReviewer.length === 1 ? "" : "s"} affected); db size ${sizeBefore} → ${sizeAfter} bytes`,
        );
        printPerReviewer(result.perReviewer);
        any = true;
      }
    }
    for (const [label, dir] of [
      ["failed-parse", parsesDir],
      ["failed-run", runsDir],
    ] as const) {
      const deleted = pruneSpools(dir, spoolCutoffMs);
      if (deleted > 0) {
        if (any) console.log("");
        console.log(
          `${deleted} ${label} spool file${deleted === 1 ? "" : "s"} pruned`,
        );
        any = true;
      }
    }
    if (!any) {
      console.log(`note: nothing to prune (no rows or spools older than ${humanLabel})`);
    }
  } finally {
    db?.close();
  }
}

/**
 * List spool files under `<commondir>/stamp/<kind>/` whose mtime is older
 * than `cutoffMs` (a Unix-millis cutoff: files with mtime less than this
 * are old enough to prune). Used for both `failed-parses/` (raw model
 * output spools) and `failed-runs/` (structured turn traces). Returns
 * absolute paths so the caller can print or unlink without re-joining.
 * No-ops cleanly if the dir doesn't exist.
 */
function peekSpools(spoolDir: string, cutoffMs: number): string[] {
  if (!existsSync(spoolDir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(spoolDir)) {
    const filepath = join(spoolDir, entry);
    let stat;
    try {
      stat = statSync(filepath);
    } catch {
      // Concurrent removal or unreadable entry — skip silently; the
      // visible state on next run will reflect reality.
      continue;
    }
    if (!stat.isFile()) continue;
    if (stat.mtimeMs < cutoffMs) out.push(filepath);
  }
  return out.sort();
}

function pruneSpools(spoolDir: string, cutoffMs: number): number {
  const targets = peekSpools(spoolDir, cutoffMs);
  let deleted = 0;
  for (const filepath of targets) {
    try {
      unlinkSync(filepath);
      deleted++;
    } catch {
      // ENOENT (raced with another writer) is benign; other errors
      // surface on the next run since the file's still there.
    }
  }
  return deleted;
}

/**
 * Render the per-reviewer breakdown with `padEnd`-aligned name columns,
 * matching the established convention in `commands/log.ts:165` and
 * `commands/reviewers.ts:471`. Width is computed from the longest name in
 * this batch (clamped to 16 to match log.ts when names are short), so
 * mixed-width reviewer slugs line up.
 */
function printPerReviewer(rows: Array<{ reviewer: string; count: number }>): void {
  const maxNameLen = Math.max(16, ...rows.map((r) => r.reviewer.length));
  for (const row of rows) {
    console.log(
      `  ${row.reviewer.padEnd(maxNameLen)}  ${row.count} row${row.count === 1 ? "" : "s"}`,
    );
  }
}
