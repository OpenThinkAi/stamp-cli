import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { loadConfig } from "../lib/config.js";
import { latestReviews, openDb } from "../lib/db.js";
import { resolveDiff } from "../lib/git.js";
import { ensureUserKeypair } from "../lib/keys.js";
import {
  findRepoRoot,
  stampConfigFile,
  stampStateDbPath,
} from "../lib/paths.js";
import {
  formatTrailers,
  type AttestationPayload,
  type Approval,
} from "../lib/attestation.js";
import { signBytes } from "../lib/signing.js";
import { serializePayload } from "../lib/attestation.js";

export interface MergeOptions {
  branch: string;
  into: string;
}

export function runMerge(opts: MergeOptions): void {
  const repoRoot = findRepoRoot();
  const config = loadConfig(stampConfigFile(repoRoot));

  // 1. Pre-flight: must be on target branch, working tree must be clean.
  const currentBranch = git(
    ["rev-parse", "--abbrev-ref", "HEAD"],
    repoRoot,
  ).trim();
  if (currentBranch !== opts.into) {
    throw new Error(
      `must be on target branch "${opts.into}" to merge into it (currently on "${currentBranch}"). Run \`git checkout ${opts.into}\` first.`,
    );
  }

  const dirty = git(["status", "--porcelain"], repoRoot).trim();
  if (dirty) {
    throw new Error(
      `working tree is not clean. Commit or stash changes before running \`stamp merge\`.`,
    );
  }

  // 2. Resolve diff and verify gate is open against the target branch rule.
  const revspec = `${opts.into}..${opts.branch}`;
  const resolved = resolveDiff(revspec, repoRoot);

  const rule = config.branches[opts.into];
  if (!rule) {
    throw new Error(
      `no branch rule for "${opts.into}" in .stamp/config.yml`,
    );
  }

  const db = openDb(stampStateDbPath(repoRoot));
  let approvals: Approval[];
  try {
    const reviews = latestReviews(
      db,
      resolved.base_sha,
      resolved.head_sha,
    );
    const byReviewer = new Map(reviews.map((r) => [r.reviewer, r]));

    // Gate check: every required reviewer must have an approved verdict.
    const missing: string[] = [];
    for (const r of rule.required) {
      const rev = byReviewer.get(r);
      if (!rev || rev.verdict !== "approved") {
        missing.push(r);
      }
    }
    if (missing.length > 0) {
      throw new Error(
        `gate CLOSED: missing approved verdicts for: ${missing.join(", ")}. ` +
          `Run \`stamp status --diff ${revspec}\` to inspect, then \`stamp review --diff ${revspec}\` to review.`,
      );
    }

    // Build approvals list from required reviewers (not all reviewers — only
    // those the target branch requires). This keeps the payload minimal and
    // binds the attestation to the exact rule that authorized the merge.
    approvals = rule.required.map((name) => {
      const rev = byReviewer.get(name)!;
      return {
        reviewer: rev.reviewer,
        verdict: rev.verdict,
        review_sha: hashPart(rev.issues ?? ""),
      };
    });
  } finally {
    db.close();
  }

  // 3. Load signing key.
  const { keypair } = ensureUserKeypair();

  // 4. Do the git merge --no-ff with a simple title; we'll amend the message
  //    with trailers next.
  const title = `Merge branch '${opts.branch}' into ${opts.into}`;
  try {
    git(
      ["merge", "--no-ff", "--no-edit", "-m", title, opts.branch],
      repoRoot,
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(
      `git merge failed. Working tree may be in a conflict state — run \`git merge --abort\` to reset. (${msg})`,
    );
  }

  // 5. Build payload, sign, amend the merge commit with trailers.
  const payload: AttestationPayload = {
    base_sha: resolved.base_sha,
    head_sha: resolved.head_sha,
    target_branch: opts.into,
    approvals,
    signer_key_id: keypair.fingerprint,
  };
  const payloadBytes = serializePayload(payload);
  const signature = signBytes(keypair.privateKeyPem, payloadBytes);
  const trailers = formatTrailers(payload, signature);
  const fullMessage = `${title}\n\n${trailers}\n`;

  git(["commit", "--amend", "-m", fullMessage, "--no-edit"], repoRoot);

  const mergeSha = git(["rev-parse", "HEAD"], repoRoot).trim();

  // 6. Report.
  const bar = "─".repeat(72);
  console.log(bar);
  console.log(`merged '${opts.branch}' into '${opts.into}'`);
  console.log(bar);
  console.log(`  commit:     ${mergeSha}`);
  console.log(
    `  base→head:  ${resolved.base_sha.slice(0, 8)} → ${resolved.head_sha.slice(0, 8)}`,
  );
  console.log(`  signed by:  ${keypair.fingerprint}`);
  console.log(`  approvals:  ${approvals.map((a) => a.reviewer).join(", ")}`);
  console.log(bar);
  console.log(
    `\nVerify locally:    stamp verify ${mergeSha.slice(0, 12)}`,
  );
  console.log(`Push to origin:    stamp push ${opts.into}   (Phase 1.E)`);
}

function hashPart(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
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
