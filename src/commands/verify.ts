import { execFileSync } from "node:child_process";
import { parseCommitAttestation } from "../lib/attestation.js";
import { loadConfig } from "../lib/config.js";
import { findTrustedKey } from "../lib/keys.js";
import { findRepoRoot, stampConfigFile } from "../lib/paths.js";
import { verifyBytes } from "../lib/signing.js";

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
  const config = loadConfig(stampConfigFile(repoRoot));

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

  // All checks passed.
  printSuccess(sha, payload);
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
