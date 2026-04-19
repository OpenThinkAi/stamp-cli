import { spawnSync } from "node:child_process";
import {
  existsSync,
  readFileSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import {
  EXAMPLE_REVIEWER_PROMPT,
  loadConfig,
  stringifyConfig,
} from "../lib/config.js";
import {
  openDb,
  recentReviewsByReviewer,
  reviewerStats,
  type ReviewerStats,
} from "../lib/db.js";
import { resolveDiff } from "../lib/git.js";
import { invokeReviewer } from "../lib/reviewer.js";
import {
  findRepoRoot,
  stampConfigFile,
  stampReviewersDir,
  stampStateDbPath,
} from "../lib/paths.js";

export function reviewersList(): void {
  const repoRoot = findRepoRoot();
  const config = loadConfig(stampConfigFile(repoRoot));

  const names = Object.keys(config.reviewers);
  if (names.length === 0) {
    console.log("No reviewers configured in .stamp/config.yml.");
    return;
  }

  const bar = "─".repeat(72);
  console.log(bar);
  console.log("configured reviewers");
  console.log(bar);

  const maxNameLen = Math.max(...names.map((n) => n.length));
  for (const name of names) {
    const def = config.reviewers[name]!;
    const abs = resolve(repoRoot, def.prompt);
    let annotation = "";
    if (!existsSync(abs)) {
      annotation = "  MISSING";
    } else {
      const size = statSync(abs).size;
      annotation = `  (${size} bytes)`;
    }
    console.log(`  ${name.padEnd(maxNameLen)}   ${def.prompt}${annotation}`);
  }

  console.log(bar);
  console.log("branch rules:");
  for (const [branch, rule] of Object.entries(config.branches)) {
    console.log(`  ${branch}  required: [${rule.required.join(", ")}]`);
  }
  console.log(bar);
}

export function reviewersEdit(name: string): void {
  const repoRoot = findRepoRoot();
  const config = loadConfig(stampConfigFile(repoRoot));

  const def = config.reviewers[name];
  if (!def) {
    throw new Error(
      `reviewer "${name}" is not configured. Run \`stamp reviewers list\` to see available reviewers.`,
    );
  }

  const target = resolve(repoRoot, def.prompt);
  launchEditor(target);
}

export function reviewersAdd(name: string, opts: { noEdit?: boolean } = {}): void {
  const repoRoot = findRepoRoot();
  const configPath = stampConfigFile(repoRoot);
  const config = loadConfig(configPath);

  if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
    throw new Error(
      `reviewer name "${name}" must be alphanumeric (letters, digits, - and _)`,
    );
  }
  if (config.reviewers[name]) {
    throw new Error(
      `reviewer "${name}" already exists. Use \`stamp reviewers edit ${name}\` to change its prompt.`,
    );
  }

  const promptRel = `.stamp/reviewers/${name}.md`;
  const promptAbs = resolve(repoRoot, promptRel);

  if (existsSync(promptAbs)) {
    // A stale file without a config entry. Prefer not to stomp — prompt the user.
    throw new Error(
      `${promptRel} already exists on disk but is not in config. Either delete the file or add it to config manually.`,
    );
  }

  writeFileSync(
    promptAbs,
    `# ${name}\n\n${EXAMPLE_REVIEWER_PROMPT.split("\n").slice(2).join("\n")}`,
  );

  config.reviewers[name] = { prompt: promptRel };
  writeFileSync(configPath, stringifyConfig(config));

  console.log(`reviewer "${name}" added.`);
  console.log(`  prompt file: ${promptRel}`);
  console.log(`  registered in .stamp/config.yml`);
  console.log();
  console.log(
    "Next: customize the prompt, then add this reviewer to a branch's `required` list",
  );
  console.log("if you want it to gate merges.");

  if (!opts.noEdit) {
    console.log(`\nOpening ${promptRel} in $EDITOR...`);
    launchEditor(promptAbs);
  }
}

export function reviewersRemove(
  name: string,
  opts: { deleteFile?: boolean } = {},
): void {
  const repoRoot = findRepoRoot();
  const configPath = stampConfigFile(repoRoot);
  const config = loadConfig(configPath);

  const def = config.reviewers[name];
  if (!def) {
    throw new Error(
      `reviewer "${name}" is not configured. Nothing to remove.`,
    );
  }

  // Warn if the reviewer is referenced by any branch rule.
  const referencedBy: string[] = [];
  for (const [branch, rule] of Object.entries(config.branches)) {
    if (rule.required.includes(name)) referencedBy.push(branch);
  }
  if (referencedBy.length > 0) {
    throw new Error(
      `reviewer "${name}" is required by branch(es): ${referencedBy.join(", ")}. ` +
        `Remove it from those branches' \`required\` list in .stamp/config.yml before removing.`,
    );
  }

  delete config.reviewers[name];
  writeFileSync(configPath, stringifyConfig(config));
  console.log(`reviewer "${name}" removed from .stamp/config.yml`);

  if (opts.deleteFile) {
    const promptAbs = resolve(repoRoot, def.prompt);
    if (existsSync(promptAbs)) {
      unlinkSync(promptAbs);
      console.log(`deleted ${def.prompt}`);
    }
  } else {
    console.log(
      `(prompt file ${def.prompt} kept; pass --delete-file to remove it too)`,
    );
  }
}

export async function reviewersTest(
  name: string,
  diff: string,
): Promise<void> {
  const repoRoot = findRepoRoot();
  const config = loadConfig(stampConfigFile(repoRoot));

  if (!config.reviewers[name]) {
    throw new Error(
      `reviewer "${name}" is not configured. Run \`stamp reviewers list\`.`,
    );
  }

  const resolved = resolveDiff(diff, repoRoot);
  if (!resolved.diff.trim()) {
    console.log("No changes in diff; nothing to test.");
    return;
  }

  const bar = "─".repeat(72);
  console.log(`testing "${name}" against ${diff} (not recorded to DB)`);
  console.log(
    `  diff: ${resolved.base_sha.slice(0, 8)} → ${resolved.head_sha.slice(0, 8)}`,
  );
  console.log();

  const result = await invokeReviewer({
    reviewer: name,
    config,
    repoRoot,
    diff: resolved.diff,
    base_sha: resolved.base_sha,
    head_sha: resolved.head_sha,
  });

  console.log(bar);
  console.log(`reviewer: ${result.reviewer}`);
  console.log(bar);
  console.log(result.prose);
  console.log(bar);
  console.log(`verdict: ${result.verdict}  (test run — not recorded)`);
  console.log(bar);
}

export function reviewersShow(name: string, opts: { limit: number }): void {
  const repoRoot = findRepoRoot();
  const config = loadConfig(stampConfigFile(repoRoot));

  if (!config.reviewers[name]) {
    throw new Error(
      `reviewer "${name}" is not configured. Run \`stamp reviewers list\`.`,
    );
  }

  const dbPath = stampStateDbPath(repoRoot);
  if (!existsSync(dbPath)) {
    console.log("No reviews recorded yet (no state.db).");
    return;
  }

  const db = openDb(dbPath);
  let stats: ReviewerStats;
  let recent;
  try {
    stats = reviewerStats(db, name);
    recent = recentReviewsByReviewer(db, name, opts.limit);
  } finally {
    db.close();
  }

  const bar = "─".repeat(72);
  console.log(bar);
  console.log(`reviewer: ${name}`);
  console.log(`prompt:   ${config.reviewers[name]!.prompt}`);
  console.log(bar);
  if (stats.total === 0) {
    console.log("  no verdicts recorded yet");
  } else {
    console.log(`  total verdicts:     ${stats.total}`);
    console.log(
      `  approved:           ${stats.approved}  (${pct(stats.approved, stats.total)}%)`,
    );
    console.log(
      `  changes_requested:  ${stats.changes_requested}  (${pct(stats.changes_requested, stats.total)}%)`,
    );
    console.log(
      `  denied:             ${stats.denied}  (${pct(stats.denied, stats.total)}%)`,
    );
    console.log(`  first seen:         ${stats.first_seen}`);
    console.log(`  last seen:          ${stats.last_seen}`);
  }
  if (recent.length > 0) {
    console.log(bar);
    console.log(`last ${recent.length} verdict${recent.length === 1 ? "" : "s"}:`);
    for (const r of recent) {
      const mark =
        r.verdict === "approved"
          ? "✓"
          : r.verdict === "changes_requested"
            ? "⟳"
            : "✗";
      console.log(
        `  ${mark} ${r.verdict.padEnd(18)} ${r.base_sha.slice(0, 8)} → ${r.head_sha.slice(0, 8)}   ${r.created_at}`,
      );
    }
  }
  console.log(bar);
}

function pct(n: number, total: number): number {
  if (total === 0) return 0;
  return Math.round((n / total) * 100);
}

function launchEditor(path: string): void {
  const editor =
    process.env["EDITOR"] ??
    process.env["VISUAL"] ??
    (process.platform === "win32" ? "notepad" : "vi");
  const result = spawnSync(editor, [path], { stdio: "inherit" });
  if (result.error) {
    throw new Error(
      `failed to launch editor "${editor}": ${result.error.message}`,
    );
  }
  if (result.status !== 0 && result.status !== null) {
    process.exit(result.status);
  }
}

// Keep the old name for backward compatibility in case any external code imports.
export { launchEditor as _launchEditor };
// Silence unused helper import warnings; readFileSync is reserved for future
// features like validating prompt-file syntax. Keep the import surface small.
void readFileSync;
