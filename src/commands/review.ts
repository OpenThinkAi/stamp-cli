import { existsSync } from "node:fs";
import { loadConfig, type StampConfig } from "../lib/config.js";
import { openDb, recordReview } from "../lib/db.js";
import { resolveDiff, type ResolvedDiff } from "../lib/git.js";
import { invokeReviewer, type ReviewerInvocation } from "../lib/reviewer.js";
import {
  findRepoRoot,
  stampConfigFile,
  stampStateDbPath,
} from "../lib/paths.js";
import {
  checkReviewerDrift,
  formatDriftReport,
  LOCK_DRIFT_EXIT,
} from "../lib/reviewerLock.js";
import { serializeToolCalls } from "../lib/toolCalls.js";

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
    console.log(
      `No changes between ${resolved.base_sha.slice(0, 8)} and ${resolved.head_sha.slice(0, 8)}.`,
    );
    return;
  }

  const reviewerNames = chooseReviewers(config, opts.only);
  if (reviewerNames.length === 0) {
    throw new Error(
      `no reviewers to run (config has ${Object.keys(config.reviewers).length} configured)`,
    );
  }

  // Pre-flight: for any reviewer with a lock file, confirm the committed
  // prompt + tool + mcp config still matches what was fetched. Drift means
  // silent tampering somewhere between `stamp reviewers fetch` and now;
  // refuse to run a review we can't faithfully attribute to a known config.
  // Exit code LOCK_DRIFT_EXIT is distinct from the general exit 1 so agent
  // loops can route "re-fetch / reconcile" vs "reviewer rejected the diff".
  const driftReports: string[] = [];
  for (const name of reviewerNames) {
    const def = config.reviewers[name]!;
    const drift = checkReviewerDrift(repoRoot, name, def);
    if (drift.hasLock && drift.mismatches.length > 0) {
      driftReports.push(formatDriftReport(name, drift));
    }
  }
  if (driftReports.length > 0) {
    for (const report of driftReports) {
      console.error(report);
      console.error();
    }
    process.exit(LOCK_DRIFT_EXIT);
  }

  console.log(
    `running ${reviewerNames.length} reviewer${reviewerNames.length === 1 ? "" : "s"} in parallel: ${reviewerNames.join(", ")}`,
  );
  console.log(
    `  diff: ${opts.diff} (${resolved.base_sha.slice(0, 8)} → ${resolved.head_sha.slice(0, 8)})`,
  );
  console.log();

  const db = openDb(stampStateDbPath(repoRoot));
  try {
    const results = await Promise.allSettled(
      reviewerNames.map((name) =>
        invokeReviewer({
          reviewer: name,
          config,
          repoRoot,
          diff: resolved.diff,
          base_sha: resolved.base_sha,
          head_sha: resolved.head_sha,
        }),
      ),
    );

    let anyFailed = false;
    for (let i = 0; i < reviewerNames.length; i++) {
      const name = reviewerNames[i]!;
      const outcome = results[i]!;
      if (outcome.status === "fulfilled") {
        recordReview(db, {
          reviewer: name,
          base_sha: resolved.base_sha,
          head_sha: resolved.head_sha,
          verdict: outcome.value.verdict,
          issues: outcome.value.prose,
          tool_calls: serializeToolCalls(outcome.value.tool_calls),
        });
        printReview(outcome.value, resolved.base_sha, resolved.head_sha);
      } else {
        anyFailed = true;
        printError(name, outcome.reason);
      }
    }

    if (anyFailed) {
      process.exitCode = 1;
    }
  } finally {
    db.close();
  }
}

function chooseReviewers(config: StampConfig, only?: string): string[] {
  if (only) {
    if (!(only in config.reviewers)) {
      throw new Error(
        `reviewer "${only}" is not configured. Available: ${
          Object.keys(config.reviewers).join(", ") || "(none)"
        }`,
      );
    }
    return [only];
  }
  return Object.keys(config.reviewers);
}

function printReview(
  result: ReviewerInvocation,
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
  console.log();
}

function printError(reviewer: string, err: unknown): void {
  const bar = "─".repeat(72);
  const message = err instanceof Error ? err.message : String(err);
  console.error(bar);
  console.error(`reviewer: ${reviewer}   FAILED`);
  console.error(bar);
  console.error(message);
  console.error(bar);
  console.error();
}

// Re-export types for callers who want them
export type { ResolvedDiff };
