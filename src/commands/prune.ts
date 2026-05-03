import { existsSync, statSync } from "node:fs";

import { openDb, peekPrunable, pruneReviews } from "../lib/db.js";
import { parseRetentionDuration } from "../lib/duration.js";
import { findRepoRoot, stampStateDbPath } from "../lib/paths.js";

export interface PruneOptions {
  /** Duration string: `<n>d`, `<n>h`, or `<n>m`. Required. */
  olderThan: string;
  /** Print what would be deleted without modifying the DB. */
  dryRun?: boolean;
}

/**
 * stamp prune --older-than <duration> [--dry-run]
 *
 * Delete rows from `<repoRoot>/.git/stamp/state.db`'s `reviews` table whose
 * `created_at` is older than now − duration, then VACUUM so the file
 * actually shrinks. The `issues` column (verbatim reviewer prose) is kept
 * intact for surviving rows — `stamp reviewers show` and `stamp log
 * --reviews` still depend on it.
 *
 * `--dry-run` peeks the same row set and prints the per-reviewer breakdown
 * without deleting or running VACUUM.
 *
 * No-ops cleanly when state.db doesn't exist (matching `reviewersShow`).
 */
export function runPrune(opts: PruneOptions): void {
  const repoRoot = findRepoRoot();
  const dbPath = stampStateDbPath(repoRoot);

  if (!existsSync(dbPath)) {
    console.log(
      `note: ${dbPath} does not exist; nothing to prune (state.db is created on first \`stamp review\`)`,
    );
    return;
  }

  // Parse before opening the DB so a bad duration doesn't even touch
  // state.db (preserves the AC #3 contract: "no DB writes" on parse error).
  const { sqliteModifier, humanLabel } = parseRetentionDuration(opts.olderThan);

  const sizeBefore = statSync(dbPath).size;

  const db = openDb(dbPath);
  try {
    if (opts.dryRun) {
      const peek = peekPrunable(db, sqliteModifier);
      if (peek.total === 0) {
        console.log(`note: nothing to prune (no rows older than ${humanLabel})`);
        return;
      }
      console.log(
        `would prune ${peek.total} row${peek.total === 1 ? "" : "s"} older than ${humanLabel} (${peek.perReviewer.length} reviewer${peek.perReviewer.length === 1 ? "" : "s"} affected):`,
      );
      printPerReviewer(peek.perReviewer);
      console.log("\n(dry run — no changes made)");
      return;
    }

    const result = pruneReviews(db, sqliteModifier);
    if (result.total === 0) {
      console.log(`note: nothing to prune (no rows older than ${humanLabel})`);
      return;
    }
    // VACUUM rewrites the whole file; must run outside any transaction. Run
    // it before reading the after-size so the on-disk size reflects the
    // post-VACUUM state, not the pre-VACUUM (page-tombstoned) state.
    db.exec("VACUUM");
    const sizeAfter = statSync(dbPath).size;
    console.log(
      `${result.total} row${result.total === 1 ? "" : "s"} pruned (${result.perReviewer.length} reviewer${result.perReviewer.length === 1 ? "" : "s"} affected); db size ${sizeBefore} → ${sizeAfter} bytes`,
    );
    printPerReviewer(result.perReviewer);
  } finally {
    db.close();
  }
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
