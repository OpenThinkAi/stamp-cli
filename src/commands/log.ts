import { existsSync } from "node:fs";
import { openDb, reviewHistory, type ReviewRow } from "../lib/db.js";
import { resolveDiff } from "../lib/git.js";
import {
  findRepoRoot,
  stampConfigFile,
  stampStateDbPath,
} from "../lib/paths.js";

export interface LogOptions {
  limit: number;
  diff?: string;
}

/**
 * Print review history in prose form. With --diff, filter to a specific
 * (base_sha, head_sha) pair. Otherwise show the most recent reviews across
 * all diffs.
 */
export function runLog(opts: LogOptions): void {
  const repoRoot = findRepoRoot();
  const configPath = stampConfigFile(repoRoot);
  if (!existsSync(configPath)) {
    throw new Error(
      `no .stamp/config.yml at ${configPath}. Run \`stamp init\` first.`,
    );
  }

  const dbPath = stampStateDbPath(repoRoot);
  if (!existsSync(dbPath)) {
    console.log("No reviews recorded yet.");
    return;
  }

  const db = openDb(dbPath);
  let rows: ReviewRow[];
  try {
    if (opts.diff) {
      const resolved = resolveDiff(opts.diff, repoRoot);
      rows = reviewHistory(db, { limit: opts.limit }).filter(
        (r) =>
          r.base_sha === resolved.base_sha && r.head_sha === resolved.head_sha,
      );
    } else {
      rows = reviewHistory(db, { limit: opts.limit });
    }
  } finally {
    db.close();
  }

  if (rows.length === 0) {
    console.log(opts.diff ? `No reviews for ${opts.diff}.` : "No reviews yet.");
    return;
  }

  for (const row of rows) {
    const bar = "─".repeat(72);
    const mark =
      row.verdict === "approved"
        ? "✓"
        : row.verdict === "changes_requested"
          ? "⟳"
          : "✗";
    console.log(bar);
    console.log(
      `#${row.id}  ${mark} ${row.reviewer.padEnd(16)} ${row.verdict.padEnd(18)} ` +
        `${row.base_sha.slice(0, 8)} → ${row.head_sha.slice(0, 8)}   ${row.created_at}`,
    );
    if (row.issues) {
      console.log(bar);
      console.log(row.issues);
    }
  }
  console.log("─".repeat(72));
  console.log(
    `${rows.length} review${rows.length === 1 ? "" : "s"} shown` +
      (opts.diff ? ` for ${opts.diff}` : ""),
  );
}
