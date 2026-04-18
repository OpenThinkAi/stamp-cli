import { existsSync } from "node:fs";
import { loadConfig } from "../lib/config.js";
import { openDb, recordReview } from "../lib/db.js";
import { resolveDiff } from "../lib/git.js";
import { invokeReviewer } from "../lib/reviewer.js";
import {
  findRepoRoot,
  stampConfigFile,
  stampStateDbPath,
} from "../lib/paths.js";

export interface ReviewOptions {
  diff: string;
  only?: string;
}

export async function runReview(opts: ReviewOptions): Promise<void> {
  const repoRoot = findRepoRoot();
  const configPath = stampConfigFile(repoRoot);
  if (!existsSync(configPath)) {
    throw new Error(
      `no .stamp/config.yml at ${configPath}. Run \`stamp init\` first.`,
    );
  }
  const config = loadConfig(configPath);

  const resolved = resolveDiff(opts.diff, repoRoot);
  if (!resolved.diff.trim()) {
    console.log(`No changes between ${resolved.base_sha.slice(0, 8)} and ${resolved.head_sha.slice(0, 8)}.`);
    return;
  }

  const reviewerNames = chooseReviewers(config, opts.only);
  if (reviewerNames.length === 0) {
    throw new Error(
      `no reviewers to run (config has ${Object.keys(config.reviewers).length} configured)`,
    );
  }

  if (reviewerNames.length > 1) {
    // Parallel fan-out is Phase 1.C. For 1.B, require --only.
    throw new Error(
      `multiple reviewers configured; for now pass --only <reviewer> to run one at a time. ` +
        `(Parallel fan-out lands in Phase 1.C.)`,
    );
  }

  const db = openDb(stampStateDbPath(repoRoot));
  try {
    for (const name of reviewerNames) {
      const result = await invokeReviewer({
        reviewer: name,
        config,
        repoRoot,
        diff: resolved.diff,
        base_sha: resolved.base_sha,
        head_sha: resolved.head_sha,
      });

      recordReview(db, {
        reviewer: name,
        base_sha: resolved.base_sha,
        head_sha: resolved.head_sha,
        verdict: result.verdict,
        issues: result.prose,
      });

      printReview(result, resolved.base_sha, resolved.head_sha);
    }
  } finally {
    db.close();
  }
}

function chooseReviewers(
  config: { reviewers: Record<string, unknown> },
  only?: string,
): string[] {
  if (only) {
    if (!(only in config.reviewers)) {
      throw new Error(
        `reviewer "${only}" is not configured. Available: ${Object.keys(config.reviewers).join(", ") || "(none)"}`,
      );
    }
    return [only];
  }
  return Object.keys(config.reviewers);
}

function printReview(
  result: { reviewer: string; prose: string; verdict: string },
  base_sha: string,
  head_sha: string,
): void {
  const bar = "─".repeat(72);
  console.log(bar);
  console.log(
    `reviewer: ${result.reviewer}   base: ${base_sha.slice(0, 8)} → head: ${head_sha.slice(0, 8)}`,
  );
  console.log(bar);
  console.log(result.prose);
  console.log(bar);
  console.log(`verdict: ${result.verdict}`);
  console.log(bar);
}
