import { createHash } from "node:crypto";
import { allPassed, runChecks } from "../lib/checks.js";
import { loadConfig } from "../lib/config.js";
import { latestReviews, openDb } from "../lib/db.js";
import { resolveDiff, runGit, showAtRef } from "../lib/git.js";
import { ensureUserKeypair } from "../lib/keys.js";
import {
  findRepoRoot,
  stampConfigFile,
  stampStateDbPath,
} from "../lib/paths.js";
import {
  CURRENT_PAYLOAD_VERSION,
  formatTrailers,
  serializePayload,
  type Approval,
  type AttestationPayload,
  type CheckAttestation,
} from "../lib/attestation.js";
import {
  hashMcpServers,
  hashPromptBytes,
  hashTools,
  readReviewersFromYaml,
} from "../lib/reviewerHash.js";
import { parseToolCalls } from "../lib/toolCalls.js";
import { signBytes } from "../lib/signing.js";

export interface MergeOptions {
  branch: string;
  into: string;
}

export function runMerge(opts: MergeOptions): void {
  const repoRoot = findRepoRoot();
  // Branch-rule lookup uses the WORKING TREE config (the operator's local
  // .stamp/config.yml at merge time, which is on the target branch since
  // the pre-flight below requires that). This is correct: the branch rule
  // determines "which reviewers must have approved this diff" and the
  // operator's local view of the rules is what governs their merge action.
  // Reviewer prompts and attestation hashes are SEPARATELY sourced from
  // the merge-base tree (see step 6a) — that's the security boundary.
  // Don't conflate the two reads.
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

  // Check for modified/staged tracked files only — untracked build artifacts
  // (dist/, .vite/, node_modules/ on a freshly checked-out target branch)
  // shouldn't block the merge.
  const dirty = git(
    ["status", "--porcelain", "--untracked-files=no"],
    repoRoot,
  ).trim();
  if (dirty) {
    throw new Error(
      `working tree has uncommitted changes to tracked files. ` +
        `Commit or stash before running \`stamp merge\`.`,
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

    // Build the skeletal approvals list from required reviewers (not all
    // reviewers — only those the target branch requires). Hashes for the
    // reviewer prompt + tools + mcp config are added post-merge, sourced
    // from the merge commit's own tree so merge-time and verify-time hashes
    // agree even on platforms with core.autocrlf or .gitattributes filters.
    approvals = rule.required.map((name) => {
      const rev = byReviewer.get(name)!;
      const toolCalls = parseToolCalls(rev.tool_calls);
      return {
        reviewer: rev.reviewer,
        verdict: rev.verdict,
        review_sha: hashPart(rev.issues ?? ""),
        ...(toolCalls.length > 0 ? { tool_calls: toolCalls } : {}),
      };
    });
  } finally {
    db.close();
  }

  // 3. Load signing key (do this before git merge so we can fail fast if
  //    there's a key problem — no rollback needed).
  const { keypair } = ensureUserKeypair();

  // 4. Do the git merge --no-ff with a simple title; we'll amend the message
  //    with trailers once checks pass.
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

  // From here on the working tree contains the merge commit. Any failure —
  // checks, post-merge config validation, missing reviewer definitions,
  // signing — must roll back HEAD~1 so the user is left exactly where they
  // started. Without this wrapper, partial failures left a stale non-stamp
  // merge commit on the target branch.
  //
  // mergeSha + checkAttestations are hoisted so the success-summary code
  // after the try-block can read them once the post-merge phase succeeds.
  let mergeSha: string;
  const checkAttestations: CheckAttestation[] = [];

  try {
    // 5. Re-load config from the working tree NOW (post-merge) rather than
    //    using the pre-merge `rule`. If the feature branch added new
    //    required_checks, the merge commit's own tree declares them; the
    //    attestation must cover them or `stamp verify` (which reads the
    //    merge commit's tree) will correctly reject.
    //
    //    Gate check (required reviewers) above still uses pre-merge `rule`
    //    because adding a new *reviewer* is a different bootstrap problem
    //    (chicken-and-egg: the new reviewer has no prior verdict for this
    //    diff). That case still needs the documented two-phase workaround
    //    (or `stamp bootstrap` for the placeholder→real swap).
    const postMergeConfig = loadConfig(stampConfigFile(repoRoot));
    const postMergeRule = postMergeConfig.branches[opts.into];
    if (!postMergeRule) {
      throw new Error(
        `.stamp/config.yml in the merged tree has no rule for branch "${opts.into}" — ` +
          `the feature branch dropped 'branches.${opts.into}' from .stamp/config.yml. ` +
          `Restore it on the feature branch before merging, or target a different branch with --into.`,
      );
    }
    const requiredChecks = postMergeRule.required_checks ?? [];
    if (requiredChecks.length > 0) {
      console.log(
        `running ${requiredChecks.length} required check${requiredChecks.length === 1 ? "" : "s"} against merged tree: ${requiredChecks.map((c) => c.name).join(", ")}`,
      );
      const results = runChecks(requiredChecks, repoRoot);
      for (const r of results) {
        const mark = r.exit_code === 0 ? "✓" : "✗";
        console.log(
          `  ${mark} ${r.name.padEnd(16)} exit=${r.exit_code}  ${r.duration_ms}ms`,
        );
        checkAttestations.push({
          name: r.name,
          command: r.command,
          exit_code: r.exit_code,
          output_sha: r.output_sha,
        });
      }
      if (!allPassed(results)) {
        const failed = results.filter((r) => r.exit_code !== 0);
        const bar = "─".repeat(72);
        for (const f of failed) {
          console.error(bar);
          console.error(`FAILED: ${f.name} (${f.command})`);
          console.error(bar);
          if (f.tail) console.error(f.tail);
        }
        console.error(bar);
        throw new Error(
          `pre-merge checks failed: ${failed.map((f) => f.name).join(", ")}. Merge rolled back. Fix and re-run.`,
        );
      }
    }

    // 6a. Compute per-reviewer prompt/tools/mcp hashes from the *merge-base*
    //     tree (NOT the merge commit's own tree). v3 attestation security
    //     boundary: the reviewer that approved is the one that existed at
    //     base_sha — the version BEFORE the diff. Hashing the post-merge
    //     tree (v2) was broken because a feature branch could modify a
    //     reviewer prompt and the resulting hash would match the modified
    //     prompt, allowing a self-reviewing merge to verify cleanly.
    //
    //     reviewer_source comes from the on-disk lock file (which at this
    //     point IS the merge-commit tree, since we just made the merge).
    //     It's audit metadata, not part of the trust boundary — if a diff
    //     swaps the lock file, the prompt_sha256 hash mismatch (computed
    //     from the *base* tree below) is what would catch it.
    const baseConfigYaml = showAtRef(resolved.base_sha, ".stamp/config.yml", repoRoot);
    const baseReviewers = readReviewersFromYaml(baseConfigYaml);

    approvals = approvals.map((a) => {
      const def = baseReviewers[a.reviewer];
      if (!def) {
        throw new Error(
          `reviewer "${a.reviewer}" approved the diff but is not defined in .stamp/config.yml at base ${resolved.base_sha.slice(0, 8)}. ` +
            `This shouldn't happen — runReview reads from the same base. ` +
            `File a bug at https://github.com/OpenThinkAi/stamp-cli/issues. ` +
            `Merge rolled back.`,
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

    // 6b. Build payload, sign, amend the merge commit with trailers.
    const payload: AttestationPayload = {
      schema_version: CURRENT_PAYLOAD_VERSION,
      base_sha: resolved.base_sha,
      head_sha: resolved.head_sha,
      target_branch: opts.into,
      approvals,
      checks: checkAttestations,
      signer_key_id: keypair.fingerprint,
    };
    const payloadBytes = serializePayload(payload);
    const signature = signBytes(keypair.privateKeyPem, payloadBytes);
    const trailers = formatTrailers(payload, signature);
    const fullMessage = `${title}\n\n${trailers}\n`;

    git(["commit", "--amend", "-m", fullMessage, "--no-edit"], repoRoot);

    mergeSha = git(["rev-parse", "HEAD"], repoRoot).trim();
  } catch (err) {
    // Roll back the merge commit so the repo ends up exactly as it was
    // before `stamp merge` was called. Best-effort — if reset itself fails
    // (extremely unlikely on a freshly-made HEAD~1), the original error
    // still propagates; user can recover manually with `git reset --hard`.
    try {
      git(["reset", "--hard", "HEAD~1"], repoRoot);
    } catch {
      // best-effort; original throw below still surfaces the real cause
    }
    throw err;
  }

  // 7. Report.
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
  if (checkAttestations.length > 0) {
    console.log(
      `  checks:     ${checkAttestations.map((c) => `${c.name}=exit${c.exit_code}`).join(", ")}`,
    );
  }
  console.log(bar);
  console.log(`\nVerify locally:    stamp verify ${mergeSha.slice(0, 12)}`);
  console.log(`Push to origin:    stamp push ${opts.into}`);
}

function hashPart(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

function readReviewerSource(
  reviewerName: string,
  repoRoot: string,
): { source: string; ref: string } | null {
  // Read the committed lock file (not the on-disk copy) so the attestation
  // reflects what's in the merge commit's tree. Absence is not an error —
  // unpinned reviewers just produce no reviewer_source field.
  let raw: string;
  try {
    raw = git(["show", `HEAD:.stamp/reviewers/${reviewerName}.lock.json`], repoRoot);
  } catch {
    return null;
  }
  try {
    const parsed = JSON.parse(raw) as { source?: string; ref?: string };
    if (typeof parsed.source === "string" && typeof parsed.ref === "string") {
      return { source: parsed.source, ref: parsed.ref };
    }
  } catch {
    // malformed lock → treat as absent rather than blow up the merge
  }
  return null;
}

// Local alias so the existing call sites stay terse. The actual implementation
// (with stderr capture, etc.) lives in lib/git.ts as runGit() — shared with
// commands/bootstrap.ts. Some readReviewerSource probes here are *expected* to
// fail on missing paths; runGit's stderr capture stops those from leaking.
const git = runGit;
