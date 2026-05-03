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
    console.log("state.db does not exist; nothing to prune");
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
        console.log(`nothing to prune (no rows older than ${humanLabel})`);
        return;
      }
      console.log(
        `[dry-run] would prune ${peek.total} row${peek.total === 1 ? "" : "s"} older than ${humanLabel} (${peek.perReviewer.length} reviewer${peek.perReviewer.length === 1 ? "" : "s"} affected):`,
      );
      for (const row of peek.perReviewer) {
        console.log(`  ${row.reviewer}: ${row.count} row${row.count === 1 ? "" : "s"}`);
      }
      return;
    }

    const result = pruneReviews(db, sqliteModifier);
    if (result.total === 0) {
      console.log(`nothing to prune (no rows older than ${humanLabel})`);
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
    for (const row of result.perReviewer) {
      console.log(`  ${row.reviewer}: ${row.count} row${row.count === 1 ? "" : "s"}`);
    }
  } finally {
    db.close();
  }
}
