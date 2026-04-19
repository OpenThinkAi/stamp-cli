import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { allPassed, runChecks } from "../lib/checks.js";
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

  // 5. Run required checks on the POST-merge tree. This is the state that
  //    would land on the remote, so it's the correct thing to verify. If a
  //    check fails, roll back the merge commit and abort.
  //
  //    Critically: we re-load config from the working tree NOW (post-merge)
  //    rather than using the pre-merge `rule`. If the feature branch added
  //    new required_checks, the merge commit's own tree declares them; the
  //    attestation must cover them or `stamp verify` (which reads the merge
  //    commit's tree) will correctly reject. Using pre-merge `rule` here
  //    was the bug reported in issue #1 — the merge succeeded but produced
  //    an attestation that its own commit's config declared invalid.
  //
  //    Gate check (required reviewers) above still uses pre-merge `rule`
  //    because adding a new *reviewer* is a different bootstrap problem
  //    (chicken-and-egg: the new reviewer has no prior verdict for this
  //    diff). That case still needs the documented two-phase workaround.
  const postMergeConfig = loadConfig(stampConfigFile(repoRoot));
  const postMergeRule = postMergeConfig.branches[opts.into];
  if (!postMergeRule) {
    throw new Error(
      `.stamp/config.yml in the merged tree has no rule for branch "${opts.into}"`,
    );
  }
  const checkAttestations: CheckAttestation[] = [];
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

      // Roll back the merge commit so the repo ends up exactly as it was
      // before `stamp merge` was called.
      try {
        git(["reset", "--hard", "HEAD~1"], repoRoot);
      } catch {
        // Best-effort; caller can recover manually if this somehow fails.
      }

      throw new Error(
        `pre-merge checks failed: ${failed.map((f) => f.name).join(", ")}. Merge rolled back. Fix and re-run.`,
      );
    }
  }

  // 6a. Compute per-reviewer prompt/tools/mcp hashes from the merge commit's
  //     own tree. Reads via `git show HEAD:<path>` so merge-time bytes are
  //     identical to what verifiers see via the same command — avoids EOL /
  //     .gitattributes divergence between working directory and committed
  //     blob. Config is also read from HEAD so we see the merged reviewers
  //     section, in case the feature branch modified .stamp/config.yml.
  //
  //     If a reviewer has a committed lock file, carry its (source, ref)
  //     into the attestation as reviewer_source — lets auditors ask "was
  //     this reviewer fetched from an approved manifest?" without trusting
  //     the operator's local state.
  const committedConfigYaml = git(["show", "HEAD:.stamp/config.yml"], repoRoot);
  const committedReviewers = readReviewersFromYaml(committedConfigYaml);
  approvals = approvals.map((a) => {
    const def = committedReviewers[a.reviewer];
    if (!def) {
      throw new Error(
        `reviewer "${a.reviewer}" is required by branch rule "${opts.into}" but not defined in the merged .stamp/config.yml`,
      );
    }
    const promptText = git(["show", `HEAD:${def.prompt}`], repoRoot);
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

  const mergeSha = git(["rev-parse", "HEAD"], repoRoot).trim();

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
