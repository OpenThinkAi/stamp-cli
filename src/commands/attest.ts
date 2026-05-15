/**
 * `stamp attest [<branch>] --into <target>`
 *
 * PR-check-mode counterpart to `stamp merge`. Validates the same review
 * gate against the same `(base_sha, head_sha)` pair, builds an
 * Approval[] from the local review DB, signs an attestation envelope
 * with the operator's stamp key, and writes it to a content-addressed
 * git ref under `refs/stamp/attestations/<patch-id>`.
 *
 * Differences from `stamp merge`:
 *   - No actual git merge. The merge happens later, via GitHub's UI,
 *     after the verifier Action confirms this attestation exists.
 *   - The artifact is a JSON blob in a separate ref, NOT a trailer on
 *     a merge commit — there's no merge commit to amend.
 *   - The artifact is keyed on `patch-id` (content of the diff), not
 *     `(base_sha, head_sha)`. Survives squash, rebase, and
 *     merge-commit on the GitHub side without invalidation.
 *   - No required_checks runner: GitHub PR checks are typically wired
 *     up separately and run the same build/test against a real
 *     pre-merge tree, so duplicating that on the local side would
 *     produce a weaker signal at twice the cost. (Server-gated mode
 *     keeps the merged-tree check because there's no external CI in
 *     that path.) `checks: []` is recorded for forward-compat.
 *
 * Reviewer-hash sourcing matches `stamp merge` exactly: prompt / tools
 * / mcp_servers SHAs come from the merge-BASE tree, not the feature
 * branch's tree, so a malicious feature branch can't self-review by
 * editing its own reviewer prompt. Same v3 schema, same security
 * boundary.
 */

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { type Approval } from "../lib/attestation.js";
import { findBranchRule, loadConfig } from "../lib/config.js";
import { latestReviews, openDb } from "../lib/db.js";
import { pathExistsAtRef, resolveDiff, runGit, showAtRef } from "../lib/git.js";
import { ensureUserKeypair } from "../lib/keys.js";
import {
  findRepoRoot,
  stampConfigFile,
  stampStateDbPath,
} from "../lib/paths.js";
import { patchIdForSpan } from "../lib/patchId.js";
import {
  PR_ATTESTATION_SCHEMA_VERSION,
  serializePayload,
  writeAttestationRef,
  type PrAttestationPayload,
} from "../lib/prAttestation.js";
import {
  hashMcpServers,
  hashPromptBytes,
  hashTools,
  readReviewersFromYaml,
} from "../lib/reviewerHash.js";
import {
  parseToolCalls,
  redactToolCallsForAttestation,
} from "../lib/toolCalls.js";
import { signBytes } from "../lib/signing.js";

export interface AttestOptions {
  /** Feature branch to attest. Defaults to current HEAD. */
  branch?: string;
  /** Target branch — provides the branch rule and is recorded in the
   *  attestation so the verifier knows which rule to evaluate against. */
  into: string;
  /**
   * If set, after writing the attestation ref locally, push the current
   * branch + the attestation ref to this remote in a single atomic
   * `git push`. Spares the operator from typing the patch-id-bearing
   * ref name themselves. Set to `null`/undefined to skip the push and
   * leave the operator to do it manually.
   */
  pushTo?: string;
}

export function runAttest(opts: AttestOptions): void {
  const repoRoot = findRepoRoot();

  // Pre-flight: working-tree-clean check is NOT required here (unlike
  // stamp merge). The attestation references commit SHAs, not the
  // working tree; uncommitted local edits don't change what's being
  // attested. Operators routinely have unrelated edits in flight when
  // they finalize a feature branch for PR review.

  const config = loadConfig(stampConfigFile(repoRoot));
  const rule = findBranchRule(config.branches, opts.into);
  if (!rule) {
    throw new Error(
      `no branch rule for "${opts.into}" in .stamp/config.yml. ` +
        `Configured branches: ${Object.keys(config.branches).join(", ") || "(none)"}.`,
    );
  }

  const branchRef = opts.branch ?? "HEAD";
  const revspec = `${opts.into}..${branchRef}`;
  const resolved = resolveDiff(revspec, repoRoot);

  // Gate check: every required reviewer must have an approved verdict
  // for this exact (base_sha, head_sha). Reuses the same predicate
  // stamp merge uses; identical wording on failure so operators see
  // one error pattern across both modes.
  const db = openDb(stampStateDbPath(repoRoot));
  let approvals: Approval[];
  try {
    const reviews = latestReviews(db, resolved.base_sha, resolved.head_sha);
    const byReviewer = new Map(reviews.map((r) => [r.reviewer, r]));

    const missing: string[] = [];
    for (const r of rule.required) {
      const rev = byReviewer.get(r);
      if (!rev || rev.verdict !== "approved") missing.push(r);
    }
    if (missing.length > 0) {
      throw new Error(
        `gate CLOSED: missing approved verdicts for: ${missing.join(", ")}. ` +
          `Run \`stamp status --diff ${revspec}\` to inspect, then ` +
          `\`stamp review --diff ${revspec}\` to review.`,
      );
    }

    approvals = rule.required.map((name) => {
      const rev = byReviewer.get(name)!;
      const toolCalls = redactToolCallsForAttestation(
        parseToolCalls(rev.tool_calls),
      );
      return {
        reviewer: rev.reviewer,
        verdict: rev.verdict,
        review_sha: hashHex(rev.issues ?? ""),
        ...(toolCalls.length > 0 ? { tool_calls: toolCalls } : {}),
      };
    });
  } finally {
    db.close();
  }

  // Per-reviewer prompt/tools/mcp hashes from the MERGE-BASE tree (v3
  // security boundary, same as stamp merge). The reviewer that
  // approved is the one that existed at base_sha — the version BEFORE
  // the diff. Hashing the head tree would let a feature branch edit
  // its own reviewer prompt and still verify cleanly.
  const baseConfigYaml = showAtRef(
    resolved.base_sha,
    ".stamp/config.yml",
    repoRoot,
  );
  const baseReviewers = readReviewersFromYaml(baseConfigYaml);

  approvals = approvals.map((a) => {
    const def = baseReviewers[a.reviewer];
    if (!def) {
      throw new Error(
        `reviewer "${a.reviewer}" approved the diff but is not defined in ` +
          `.stamp/config.yml at base ${resolved.base_sha.slice(0, 8)}. This ` +
          `shouldn't happen — runReview reads from the same base. File a bug ` +
          `at https://github.com/OpenThinkAi/stamp-cli/issues.`,
      );
    }
    const promptText = showAtRef(resolved.base_sha, def.prompt, repoRoot);
    const source = readReviewerSource(a.reviewer, repoRoot);
    return {
      ...a,
      prompt_sha256: hashPromptBytes(Buffer.from(promptText, "utf8")),
      tools_sha256: hashTools(def.tools),
      mcp_sha256: hashMcpServers(def.mcp_servers),
      ...(source ? { reviewer_source: source } : {}),
    };
  });

  // Compute the content hash (patch-id) — this is what the artifact
  // is keyed on. Same patch-id across rebase / squash / merge-commit
  // on the GitHub side, so the attestation survives all three.
  const patch_id = patchIdForSpan(resolved.base_sha, resolved.head_sha, repoRoot);

  // Sign + build envelope. Schema version is independent of the
  // server-gated trailer schema (PR_ATTESTATION_SCHEMA_VERSION = 1
  // here) but the per-Approval fields below mirror
  // CURRENT_PAYLOAD_VERSION's v3 shape exactly so a future verifier
  // can treat them uniformly.
  const { keypair } = ensureUserKeypair();
  const payload: PrAttestationPayload = {
    schema_version: PR_ATTESTATION_SCHEMA_VERSION,
    patch_id,
    base_sha: resolved.base_sha,
    head_sha: resolved.head_sha,
    target_branch: opts.into,
    approvals,
    checks: [], // Phase-1 deliberate omission — see file-level comment.
    signer_key_id: keypair.fingerprint,
  };
  const signature = signBytes(keypair.privateKeyPem, serializePayload(payload));
  const { ref, blob_sha } = writeAttestationRef(
    { payload, signature },
    repoRoot,
  );

  const bar = "─".repeat(72);
  console.log(bar);
  console.log(`attested ${branchRef} for merge into '${opts.into}'`);
  console.log(bar);
  console.log(`  patch-id:   ${patch_id}`);
  console.log(
    `  base→head:  ${resolved.base_sha.slice(0, 8)} → ${resolved.head_sha.slice(0, 8)}`,
  );
  console.log(`  signed by:  ${keypair.fingerprint}`);
  console.log(`  approvals:  ${approvals.map((a) => a.reviewer).join(", ")}`);
  console.log(`  ref:        ${ref}`);
  console.log(`  blob:       ${blob_sha.slice(0, 12)}`);
  console.log(bar);

  if (opts.pushTo) {
    pushBranchAndAttestation(opts.pushTo, ref, repoRoot);
    console.log(
      `\n✓ pushed branch + attestation ref to ${opts.pushTo}. Open the PR; ` +
        `stamp/verify-attestation@v1 will look up refs/stamp/attestations/<patch-id> ` +
        `from your head SHA's diff against the base.`,
    );
  } else {
    console.log(
      `\nNext: push the branch + attestation ref to your remote, open a PR, and ` +
        `let stamp/verify-attestation@v1 (the GH Action) confirm it. To do both ` +
        `pushes in one shot:\n\n` +
        `    git push <remote> HEAD ${ref}\n\n` +
        `Or re-run with --push <remote> next time.`,
    );
  }
}

/**
 * Push the current branch + the attestation ref to `remote` in a single
 * `git push` invocation. Atomic by git semantics — if either ref's
 * remote-side update is rejected (force-push protection on the branch,
 * pre-receive hook, etc.), neither ref lands. That's the right shape:
 * a half-pushed state where the branch advanced but the attestation
 * didn't would silently break PR-check verification on the next CI run.
 *
 * `--atomic` is passed explicitly for that property; without it, git
 * 2.x falls back to per-ref behavior on some transports (file:// in
 * particular). Passing it is a no-op on transports that already imply
 * atomicity (https/ssh to most servers).
 *
 * Stdio inherits so the operator sees git's normal push prose
 * (counting objects, writing, hook output) live, matching what `git
 * push` directly would look like — minus the ref names, which we
 * already printed in the summary block above.
 */
function pushBranchAndAttestation(
  remote: string,
  attestationRef: string,
  repoRoot: string,
): void {
  const result = spawnSync(
    "git",
    ["push", "--atomic", remote, "HEAD", attestationRef],
    { cwd: repoRoot, stdio: "inherit" },
  );
  // Spawn-level error (git binary not found, EACCES on the cwd, etc.)
  // surfaces with the underlying message rather than "exit null" — the
  // null status case is genuinely "we never got an exit code from git."
  if (result.error) throw result.error;
  if (result.status !== 0) {
    // result.status is null when git is killed by a signal; preserve
    // that distinction in the prose so it's debuggable.
    const exit = result.status === null ? "(killed by signal)" : `exit ${result.status}`;
    throw new Error(
      `git push --atomic ${remote} HEAD ${attestationRef} failed (${exit}). ` +
        `The attestation ref is still in the local repo at ${attestationRef} — ` +
        `re-run with --push ${remote} after fixing the cause, or push manually.`,
    );
  }
}

function hashHex(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

function readReviewerSource(
  reviewerName: string,
  repoRoot: string,
): { source: string; ref: string } | null {
  // Deliberate exception to "everything reviewer-related sources from
  // resolved.base_sha". reviewer_source is informational metadata
  // (where this reviewer was fetched from + at what version) and is
  // NOT covered by any cryptographic hash in the attestation —
  // prompt_sha256 / tools_sha256 / mcp_sha256 are the trust-bearing
  // fields and they ALL come from base_sha. Reading the lock file
  // from HEAD here matches what stamp merge does (audit trail
  // reflects the merged tree's lock state) and is safe because no
  // verifier should derive trust from this field. If a future change
  // promotes reviewer_source to a trust input, switch this read to
  // resolved.base_sha first.
  const path = `.stamp/reviewers/${reviewerName}.lock.json`;
  if (!pathExistsAtRef("HEAD", path, repoRoot)) return null;
  const raw = runGit(["show", `HEAD:${path}`], repoRoot);
  try {
    const parsed = JSON.parse(raw) as { source?: string; ref?: string };
    if (typeof parsed.source === "string" && typeof parsed.ref === "string") {
      return { source: parsed.source, ref: parsed.ref };
    }
  } catch {
    // malformed lock → treat as absent rather than blow up
  }
  return null;
}
