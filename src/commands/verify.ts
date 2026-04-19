import { execFileSync } from "node:child_process";
import { parse as parseYaml } from "yaml";
import {
  parseCommitAttestation,
  type AttestationPayload,
} from "../lib/attestation.js";
import type { BranchRule, StampConfig, CheckDef } from "../lib/config.js";
import { findTrustedKey } from "../lib/keys.js";
import { findRepoRoot } from "../lib/paths.js";
import {
  hashMcpServers,
  hashPromptBytes,
  hashTools,
  readReviewersFromYaml,
} from "../lib/reviewerHash.js";
import { verifyBytes } from "../lib/signing.js";

/**
 * Load just enough of .stamp/config.yml from the given commit's tree to
 * verify an attestation — branches (required + required_checks) and
 * reviewers (for hash recomputation). Tolerates missing config cleanly
 * for the "no rule for this branch" pass-through at the caller.
 */
function loadConfigAtSha(sha: string, repoRoot: string): StampConfig {
  let raw: string;
  try {
    raw = execFileSync("git", ["show", `${sha}:.stamp/config.yml`], {
      cwd: repoRoot,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    });
  } catch {
    return { branches: {}, reviewers: {} };
  }
  const parsed = (parseYaml(raw) ?? {}) as Record<string, unknown>;
  const branches: Record<string, BranchRule> = {};
  const rawBranches = parsed.branches;
  if (rawBranches && typeof rawBranches === "object") {
    for (const [name, rule] of Object.entries(rawBranches)) {
      if (!rule || typeof rule !== "object") continue;
      const r = rule as Record<string, unknown>;
      if (!Array.isArray(r.required)) continue;
      const required_checks: CheckDef[] = [];
      if (Array.isArray(r.required_checks)) {
        for (const c of r.required_checks) {
          if (c && typeof c === "object") {
            const cc = c as Record<string, unknown>;
            if (typeof cc.name === "string" && typeof cc.run === "string") {
              required_checks.push({ name: cc.name, run: cc.run });
            }
          }
        }
      }
      branches[name] = {
        required: r.required.map(String),
        ...(required_checks.length > 0 ? { required_checks } : {}),
      };
    }
  }
  const reviewers = readReviewersFromYaml(raw);
  return { branches, reviewers: reviewers as StampConfig["reviewers"] };
}

export interface VerifyResult {
  valid: boolean;
  reason?: string;
}

/**
 * Verify a merge commit's attestation locally. Runs the same checks the
 * server-side hook will run. Exit 0 on success, 1 on failure. Prints a
 * prose report in either case.
 */
export function runVerify(sha: string): void {
  const repoRoot = findRepoRoot();
  // Load config from the merge commit's OWN tree, not the working directory.
  // A commit must satisfy the rules it itself declares — current-main config
  // can have drifted since the commit was made, and verifying against drifted
  // rules produces false positives/negatives. Matches the semantics the
  // post-fix `stamp merge` uses when choosing which required_checks to run.
  const config = loadConfigAtSha(sha, repoRoot);

  // 1. Read the commit message and parse trailers.
  const commitMessage = git(["show", "-s", "--format=%B", sha], repoRoot);
  const parsed = parseCommitAttestation(commitMessage);
  if (!parsed) {
    fail(
      sha,
      "commit has no Stamp-Payload / Stamp-Verified trailers",
    );
  }

  const { payload, payloadBytes, signatureBase64 } = parsed;

  // 2. Look up the signer's public key in .stamp/trusted-keys/ by fingerprint.
  const trustedKey = findTrustedKey(repoRoot, payload.signer_key_id);
  if (!trustedKey) {
    fail(
      sha,
      `signer key ${payload.signer_key_id} is not in .stamp/trusted-keys/`,
    );
  }

  // 3. Verify signature.
  const sigValid = verifyBytes(trustedKey, payloadBytes, signatureBase64);
  if (!sigValid) {
    fail(sha, "Ed25519 signature does not verify against the signer's trusted key");
  }

  // 4. Check base_sha / head_sha against the commit's actual parents.
  // For a --no-ff merge: parents are [target_tip, branch_tip].
  // head_sha == parents[1], base_sha == merge-base(parents[0], parents[1]).
  const parents = git(["rev-list", "--parents", "-n", "1", sha], repoRoot)
    .trim()
    .split(/\s+/)
    .slice(1); // first token is the commit itself

  if (parents.length !== 2) {
    fail(
      sha,
      `not a merge commit: expected 2 parents, got ${parents.length}. ` +
        `stamp merges must use --no-ff.`,
    );
  }

  const [parent0, parent1] = parents as [string, string];
  if (parent1 !== payload.head_sha) {
    fail(
      sha,
      `commit's second parent (${parent1.slice(0, 8)}) does not match payload.head_sha (${payload.head_sha.slice(0, 8)})`,
    );
  }

  const actualMergeBase = git(
    ["merge-base", parent0, parent1],
    repoRoot,
  ).trim();
  if (actualMergeBase !== payload.base_sha) {
    fail(
      sha,
      `computed merge-base(${parent0.slice(0, 8)}, ${parent1.slice(0, 8)}) = ${actualMergeBase.slice(0, 8)}, ` +
        `does not match payload.base_sha (${payload.base_sha.slice(0, 8)})`,
    );
  }

  // 5. Check approvals satisfy config for target branch.
  const rule = config.branches[payload.target_branch];
  if (!rule) {
    fail(
      sha,
      `no branch rule for target "${payload.target_branch}" in .stamp/config.yml`,
    );
  }

  const approvedReviewers = new Set(
    payload.approvals
      .filter((a) => a.verdict === "approved")
      .map((a) => a.reviewer),
  );
  const missing = rule.required.filter((r) => !approvedReviewers.has(r));
  if (missing.length > 0) {
    fail(
      sha,
      `missing approvals for required reviewer(s): ${missing.join(", ")}`,
    );
  }

  // 6. Check that attested checks cover every required_check in config,
  //    and that each recorded an exit code of 0.
  const requiredChecks = rule.required_checks ?? [];
  const attestedByName = new Map(
    (payload.checks ?? []).map((c) => [c.name, c]),
  );
  const missingChecks: string[] = [];
  const failingChecks: string[] = [];
  for (const req of requiredChecks) {
    const attested = attestedByName.get(req.name);
    if (!attested) {
      missingChecks.push(req.name);
      continue;
    }
    if (attested.exit_code !== 0) {
      failingChecks.push(`${req.name} (exit ${attested.exit_code})`);
    }
  }
  if (missingChecks.length > 0) {
    fail(
      sha,
      `attestation is missing required check(s): ${missingChecks.join(", ")}`,
    );
  }
  if (failingChecks.length > 0) {
    fail(
      sha,
      `attestation records failing check(s): ${failingChecks.join(", ")}`,
    );
  }

  // 7. v2+: verify per-reviewer prompt/tools/mcp hashes against the merge
  //    commit's .stamp/ tree. Legacy (v1) attestations skip this step.
  if ((payload.schema_version ?? 1) >= 2) {
    verifyReviewerHashes(sha, payload, repoRoot);
  }

  // All checks passed.
  printSuccess(sha, payload);
}

function verifyReviewerHashes(
  sha: string,
  payload: AttestationPayload,
  repoRoot: string,
): void {
  const configYaml = tryGitShow(`${sha}:.stamp/config.yml`, repoRoot);
  if (!configYaml) {
    fail(
      sha,
      `v2 attestation: cannot read .stamp/config.yml from the merge commit's tree. Commit the config and re-run merge.`,
    );
  }
  const reviewers = readReviewersFromYaml(configYaml);

  for (const approval of payload.approvals) {
    const missing: string[] = [];
    if (!approval.prompt_sha256) missing.push("prompt_sha256");
    if (!approval.tools_sha256) missing.push("tools_sha256");
    if (!approval.mcp_sha256) missing.push("mcp_sha256");
    if (missing.length > 0) {
      fail(
        sha,
        `v2 attestation: approval for "${approval.reviewer}" is missing ${missing.join(", ")}`,
      );
    }
    const def = reviewers[approval.reviewer];
    if (!def) {
      fail(
        sha,
        `v2 attestation: reviewer "${approval.reviewer}" is in payload but not defined in config.reviewers at the merge commit`,
      );
    }
    const promptBytes = tryGitShow(`${sha}:${def.prompt}`, repoRoot);
    if (promptBytes === null) {
      fail(
        sha,
        `v2 attestation: reviewer "${approval.reviewer}" prompt file "${def.prompt}" missing from the merge commit's tree`,
      );
    }
    checkHash(sha, approval.reviewer, "prompt", hashPromptBytes(Buffer.from(promptBytes, "utf8")), approval.prompt_sha256!);
    checkHash(sha, approval.reviewer, "tools", hashTools(def.tools), approval.tools_sha256!);
    checkHash(sha, approval.reviewer, "mcp_servers", hashMcpServers(def.mcp_servers), approval.mcp_sha256!);
  }
}

function checkHash(
  sha: string,
  reviewer: string,
  field: string,
  computed: string,
  expected: string,
): void {
  if (computed === expected) return;
  fail(
    sha,
    `v2 attestation: reviewer "${reviewer}" ${field} hash mismatch ` +
      `(expected ${expected.slice(0, 16)}..., committed tree has ${computed.slice(0, 16)}...). ` +
      `The committed config differs from what the attestation claims; re-run stamp merge or revert the change.`,
  );
}

function tryGitShow(treeRef: string, repoRoot: string): string | null {
  try {
    return execFileSync("git", ["show", treeRef], {
      cwd: repoRoot,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    });
  } catch {
    return null;
  }
}

function fail(sha: string, reason: string): never {
  console.error(`✗ ${sha.slice(0, 8)}: ${reason}`);
  process.exit(1);
}

function printSuccess(
  sha: string,
  payload: {
    target_branch: string;
    base_sha: string;
    head_sha: string;
    signer_key_id: string;
    approvals: { reviewer: string; verdict: string }[];
    checks?: { name: string; exit_code: number }[];
  },
): void {
  const bar = "─".repeat(72);
  console.log(bar);
  console.log(`✓ ${sha.slice(0, 12)}: attestation valid`);
  console.log(bar);
  console.log(`  target:     ${payload.target_branch}`);
  console.log(
    `  base→head:  ${payload.base_sha.slice(0, 8)} → ${payload.head_sha.slice(0, 8)}`,
  );
  console.log(`  signer:     ${payload.signer_key_id}`);
  console.log(`  approvals:`);
  for (const a of payload.approvals) {
    const mark = a.verdict === "approved" ? "✓" : "✗";
    console.log(`    ${mark} ${a.reviewer}   ${a.verdict}`);
  }
  if (payload.checks && payload.checks.length > 0) {
    console.log(`  checks:`);
    for (const c of payload.checks) {
      const mark = c.exit_code === 0 ? "✓" : "✗";
      console.log(`    ${mark} ${c.name}   exit ${c.exit_code}`);
    }
  }
  console.log(bar);
}

function git(args: string[], cwd: string): string {
  try {
    return execFileSync("git", args, {
      cwd,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    });
  } catch (err) {
    throw new Error(
      `git ${args.join(" ")} failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}
