import { existsSync } from "node:fs";
import { loadConfig, type StampConfig } from "../lib/config.js";
import { latestVerdicts, openDb, type Verdict } from "../lib/db.js";
import { resolveDiff } from "../lib/git.js";
import {
  findRepoRoot,
  stampConfigFile,
  stampStateDbPath,
} from "../lib/paths.js";

export interface StatusOptions {
  diff: string;
  /** Override which branch's rule to check. Default: inferred from diff base. */
  into?: string;
}

export interface GateResult {
  gateOpen: boolean;
  target: string;
  required: string[];
  /** Reviewer → current verdict (or null if no review exists at this SHA pair) */
  current: Record<string, Verdict | null>;
}

/**
 * Evaluate the gate for a (base_sha, head_sha) pair against a target branch's
 * required reviewers. Prints a prose status report and exits 0 if open, 1 if closed.
 */
export function runStatus(opts: StatusOptions): void {
  const repoRoot = findRepoRoot();
  const configPath = stampConfigFile(repoRoot);
  if (!existsSync(configPath)) {
    throw new Error(
      `no .stamp/config.yml at ${configPath}. Run \`stamp init\` first.`,
    );
  }
  const config = loadConfig(configPath);
  const resolved = resolveDiff(opts.diff, repoRoot);

  const target = opts.into ?? inferTarget(opts.diff);
  const rule = config.branches[target];
  if (!rule) {
    throw new Error(
      `no branch rule for "${target}" in .stamp/config.yml. ` +
        `Configured branches: ${Object.keys(config.branches).join(", ") || "(none)"}. ` +
        `Use --into <target> to override.`,
    );
  }

  const db = openDb(stampStateDbPath(repoRoot));
  let result: GateResult;
  try {
    const verdicts = latestVerdicts(db, resolved.base_sha, resolved.head_sha);
    const verdictByReviewer = new Map(verdicts.map((v) => [v.reviewer, v.verdict]));

    const current: Record<string, Verdict | null> = {};
    let gateOpen = true;
    for (const r of rule.required) {
      const v = verdictByReviewer.get(r) ?? null;
      current[r] = v;
      if (v !== "approved") gateOpen = false;
    }

    result = { gateOpen, target, required: rule.required, current };
  } finally {
    db.close();
  }

  printGate(result, resolved.base_sha, resolved.head_sha);

  if (!result.gateOpen) {
    process.exit(1);
  }
}

/**
 * Extract the base ref from a "<base>..<head>" revspec. This is the target
 * branch in most agent-driven workflows: you review diffs against the branch
 * you intend to merge into.
 */
function inferTarget(revspec: string): string {
  const parts = revspec.split("..");
  if (parts.length !== 2 || !parts[0]) {
    throw new Error(
      `cannot infer target branch from revspec "${revspec}". Pass --into <target>.`,
    );
  }
  return parts[0];
}

function printGate(
  result: GateResult,
  base_sha: string,
  head_sha: string,
): void {
  const bar = "─".repeat(72);
  console.log(bar);
  console.log(
    `target: ${result.target}   base: ${base_sha.slice(0, 8)} → head: ${head_sha.slice(0, 8)}`,
  );
  console.log(bar);

  if (result.required.length === 0) {
    console.log("  (no reviewers required for this branch)");
  } else {
    const maxNameLen = Math.max(...result.required.map((r) => r.length));
    for (const r of result.required) {
      const v = result.current[r];
      const mark = v === "approved" ? "✓" : "✗";
      const status = v ?? "no review";
      console.log(`  ${mark}  ${r.padEnd(maxNameLen)}   ${status}`);
    }
  }

  console.log(bar);
  console.log(`gate: ${result.gateOpen ? "OPEN" : "CLOSED"}`);
  console.log(bar);
}
