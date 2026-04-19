import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { ReviewerDef } from "./config.js";
import { hashMcpServers, hashPromptBytes, hashTools } from "./reviewerHash.js";

/**
 * Reviewer lock files (plan Step 3) pin a reviewer's prompt + tool + MCP
 * config to the hashes of what was originally fetched from a canonical
 * source. `stamp review` enforces these at runtime: if the committed
 * prompt drifts from the lock, the review refuses to run with exit code
 * LOCK_DRIFT_EXIT so agent loops can distinguish config-drift from a
 * genuine "review rejected" failure (exit 1).
 */

export const LOCK_FILE_VERSION = 1;

/** Exit code reserved for lock-file drift. Distinct from exit 1 (general
 *  failure / review rejected) and exit 2 (commander usage errors). */
export const LOCK_DRIFT_EXIT = 3;

export interface LockFile {
  /** Lock format version; bump on structural changes. */
  version: number;
  /** `<owner>/<repo>` shorthand or full git URL the content was fetched from. */
  source: string;
  /** Git ref (tag / branch / commit) at the source. */
  ref: string;
  /** Reviewer name; matches the key in .stamp/config.yml's reviewers map. */
  reviewer: string;
  prompt_sha256: string;
  tools_sha256: string;
  mcp_sha256: string;
  /** ISO-8601 UTC timestamp of the fetch that wrote this lock. */
  fetched_at: string;
}

export function lockFilePath(repoRoot: string, reviewerName: string): string {
  return join(repoRoot, ".stamp", "reviewers", `${reviewerName}.lock.json`);
}

// Throws on malformed lock files so the pre-flight check fails loudly rather
// than silently pretending the reviewer is unpinned. merge.ts reads lock
// files with its own silent-catch path (see readReviewerSource) because a
// corrupt lock at merge time should degrade gracefully (drop reviewer_source)
// rather than blow up the merge — different tolerance, deliberate.
export function readLockFile(
  repoRoot: string,
  reviewerName: string,
): LockFile | null {
  const path = lockFilePath(repoRoot, reviewerName);
  if (!existsSync(path)) return null;
  try {
    const raw = readFileSync(path, "utf8");
    const parsed = JSON.parse(raw) as LockFile;
    if (
      typeof parsed.version !== "number" ||
      typeof parsed.source !== "string" ||
      typeof parsed.ref !== "string" ||
      typeof parsed.reviewer !== "string" ||
      typeof parsed.prompt_sha256 !== "string" ||
      typeof parsed.tools_sha256 !== "string" ||
      typeof parsed.mcp_sha256 !== "string"
    ) {
      throw new Error(`malformed lock file at ${path}`);
    }
    return parsed;
  } catch (err) {
    throw new Error(
      `failed to read lock file ${path}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

export function writeLockFile(
  repoRoot: string,
  reviewerName: string,
  lock: LockFile,
): void {
  const path = lockFilePath(repoRoot, reviewerName);
  writeFileSync(path, JSON.stringify(lock, null, 2) + "\n", "utf8");
}

export interface DriftMismatch {
  /** Which hash diverged. */
  field: "prompt" | "tools" | "mcp_servers";
  /** Hash from the lock file (what the reviewer was fetched as). */
  expected: string;
  /** Hash of the current on-disk state. */
  observed: string;
}

/**
 * Discriminated union — branch on `hasLock` to get typed access to `lock`
 * without a non-null assertion. An unpinned reviewer has `hasLock: false`
 * and no mismatches; a pinned reviewer has `hasLock: true` and a LockFile.
 */
export type DriftResult =
  | { hasLock: false; lock: null; mismatches: [] }
  | { hasLock: true; lock: LockFile; mismatches: DriftMismatch[] };

/**
 * Compare a reviewer's current prompt + tool + MCP config against its lock
 * file (if any). Reads the prompt from disk (not the git index) because this
 * is the pre-merge check — we want to catch drift before `stamp review` fans
 * reviewers out.
 */
export function checkReviewerDrift(
  repoRoot: string,
  reviewerName: string,
  def: ReviewerDef,
): DriftResult {
  const lock = readLockFile(repoRoot, reviewerName);
  if (!lock) {
    return unpinnedResult();
  }

  const promptPath = join(repoRoot, def.prompt);
  if (!existsSync(promptPath)) {
    throw new Error(
      `reviewer "${reviewerName}" has a lock file but its prompt "${def.prompt}" does not exist on disk. ` +
        `Re-run 'stamp reviewers fetch ${reviewerName} --from ${lock.source}@${lock.ref}' to restore it, ` +
        `or delete the lock file to un-pin the reviewer.`,
    );
  }
  const promptBytes = readFileSync(promptPath);
  const observedPrompt = hashPromptBytes(promptBytes);
  const observedTools = hashTools(def.tools);
  const observedMcp = hashMcpServers(def.mcp_servers);

  const mismatches: DriftMismatch[] = [];
  if (observedPrompt !== lock.prompt_sha256) {
    mismatches.push({
      field: "prompt",
      expected: lock.prompt_sha256,
      observed: observedPrompt,
    });
  }
  if (observedTools !== lock.tools_sha256) {
    mismatches.push({
      field: "tools",
      expected: lock.tools_sha256,
      observed: observedTools,
    });
  }
  if (observedMcp !== lock.mcp_sha256) {
    mismatches.push({
      field: "mcp_servers",
      expected: lock.mcp_sha256,
      observed: observedMcp,
    });
  }
  return { hasLock: true, lock, mismatches };
}

export function unpinnedResult(): DriftResult {
  return { hasLock: false, lock: null, mismatches: [] };
}

/** Format a drift report as a prose block ready for stderr. Matches the
 *  shape documented in docs/plans/verified-reviewer-configs.md Step 3. */
export function formatDriftReport(
  reviewerName: string,
  result: DriftResult,
): string {
  if (!result.hasLock || result.mismatches.length === 0) {
    return `reviewer "${reviewerName}" is clean against its lock file.`;
  }
  const { lock } = result;
  const lines: string[] = [];
  for (const m of result.mismatches) {
    lines.push(`error: reviewer '${reviewerName}' ${m.field} hash mismatch`);
    lines.push(
      `  expected: sha256:${m.expected.slice(0, 16)}...  (from ${lockFileRelative(reviewerName)}, source=${lock.source}@${lock.ref})`,
    );
    lines.push(
      `  observed: sha256:${m.observed.slice(0, 16)}...  (current config)`,
    );
    lines.push(
      `  fix: re-run 'stamp reviewers fetch ${reviewerName} --from ${lock.source}@${lock.ref}' or update the lock file deliberately`,
    );
  }
  return lines.join("\n");
}

function lockFileRelative(reviewerName: string): string {
  return `.stamp/reviewers/${reviewerName}.lock.json`;
}
