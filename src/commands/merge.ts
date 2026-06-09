import { createHash } from "node:crypto";
import {
  allPassed,
  detectVitestForkPoolFlake,
  runChecks,
  VITEST_FORK_POOL_FLAKE_DIAGNOSTIC,
} from "../lib/checks.js";
import { findBranchRule, loadConfig } from "../lib/config.js";
import { latestReviews, openDb, serverApprovalsFor, type McpServerAtInit } from "../lib/db.js";
import {
  listFilesAtRef,
  pathExistsAtRef,
  resolveDiff,
  runGit,
  showAtRef,
} from "../lib/git.js";
import { ensureUserKeypair } from "../lib/keys.js";
import {
  parseManifest,
  resolveCapability,
  snapshotSha256,
} from "../lib/trustedKeysManifest.js";
import { buildPubkeyMap } from "../lib/sshReviewClient.js";
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
  CURRENT_V4_SCHEMA_VERSION,
  canonicalSerializeApproval,
  canonicalSerializePayload,
  formatTrailers as formatTrailersV4,
  type ApprovalEntryV4,
  type ApprovalV4,
  type AttestationPayloadV4,
  type CheckAttestationV4,
} from "../lib/attestationV4.js";
import {
  collectTrustAnchorSignatures,
  type CollectTrustAnchorResult,
} from "../lib/trustAnchorCollection.js";
import {
  hashMcpServers,
  hashPromptBytes,
  hashTools,
  readReviewersFromYaml,
} from "../lib/reviewerHash.js";
import { parseToolCalls, redactToolCallsForAttestation } from "../lib/toolCalls.js";
import { signBytes, verifyBytes } from "../lib/signing.js";
import { requireHumanMerge } from "../lib/humanMerge.js";
import { maybePrintDeprecationNotice } from "../lib/deprecationNotice.js";

export interface MergeOptions {
  branch: string;
  into: string;
  /**
   * Skip the human-merge confirmation prompt for this invocation. Equivalent
   * to STAMP_REQUIRE_HUMAN_MERGE=0 but scoped to one command. Audit H1.
   */
  yes?: boolean;
}

export function runMerge(opts: MergeOptions): void {
  // Bridge-release deprecation banner (AGT-346). Printed once per merge
  // invocation, before any of merge's own output, so the operator sees the
  // pointer to the migration guide regardless of how their shell pipes
  // stdout. Suppress with STAMP_SUPPRESS_DEPRECATION=1 (intended for CI).
  maybePrintDeprecationNotice();

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

  const rule = findBranchRule(config.branches, opts.into);
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

    // Audit H1 — operator confirmation gate. Runs *after* the reviewer gate
    // and the dirty-tree pre-flight (no point asking if we'd refuse anyway)
    // and *before* the signing key is loaded or any git ref moves. Throws
    // on cancel or no-TTY-without-opt-out; the throw bubbles to the caller
    // before any state changes, so no rollback is needed.

    // AC#2: compute git diff --stat for display in the confirm prompt.
    // Best-effort: if git fails (e.g. detached HEAD edge case), skip
    // the stat block rather than aborting a valid merge. The stat shows
    // filenames + churn counts (not diff content), so it's low injection
    // risk when printed as plain text.
    let diffStat: string | undefined;
    try {
      diffStat = runGit(
        ["diff", "--stat", `${resolved.base_sha}..${resolved.head_sha}`],
        repoRoot,
      );
    } catch {
      diffStat = undefined;
    }

    requireHumanMerge({
      target: opts.into,
      source: opts.branch,
      base_sha: resolved.base_sha,
      head_sha: resolved.head_sha,
      branchRule: rule,
      yes: opts.yes ?? false,
      diffStat,
    });

    // Build the skeletal approvals list from required reviewers (not all
    // reviewers — only those the target branch requires). Hashes for the
    // reviewer prompt + tools + mcp config are added post-merge, sourced
    // from the merge commit's own tree so merge-time and verify-time hashes
    // agree even on platforms with core.autocrlf or .gitattributes filters.
    approvals = rule.required.map((name) => {
      const rev = byReviewer.get(name)!;
      const toolCalls = redactToolCallsForAttestation(parseToolCalls(rev.tool_calls));
      const mcpAtInit = parseMcpServersAtInit(rev.mcp_servers_at_init);
      return {
        reviewer: rev.reviewer,
        verdict: rev.verdict,
        review_sha: hashPart(rev.issues ?? ""),
        ...(toolCalls.length > 0 ? { tool_calls: toolCalls } : {}),
        ...(mcpAtInit.length > 0 ? { mcp_servers_at_init: mcpAtInit } : {}),
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

  // Capture the pre-merge HEAD SHA before touching the ref. The rollback
  // catch below resets to this exact SHA rather than HEAD~1, which is
  // more explicit and safe: HEAD~1 would be wrong if the merge somehow
  // produced a non-standard reflog entry, whereas the pre-merge SHA is
  // always exactly where we want to land on failure.
  const preMergeSha = git(["rev-parse", "HEAD"], repoRoot).trim();

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
  // signing — must roll back to preMergeSha so the user is left exactly
  // where they started. Without this wrapper, partial failures left a
  // stale non-stamp merge commit on the target branch.
  //
  // mergeSha + checkAttestations are hoisted so the success-summary code
  // after the try-block can read them once the post-merge phase succeeds.
  let mergeSha: string;
  const checkAttestations: CheckAttestation[] = [];
  // v4 `CheckAttestationV4` is structurally identical to v3
  // `CheckAttestation` (same four fields: name, command, exit_code,
  // output_sha). Capturing into the v3-shaped list and shaping into a
  // v4 list inside `buildV4Trailers` keeps the checks runner above
  // schema-agnostic.
  // Hoisted so the banner code after the try-block can read it (AC#4).
  let matchedPathRules: Array<{
    pattern: string;
    minimum_signatures: number;
    qualifying_count: number;
  }> = [];

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
    const postMergeRule = findBranchRule(postMergeConfig.branches, opts.into);
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
          // AGT-470: surface a clear diagnostic when the failure bears the
          // vitest fork-pool worker-startup-timeout signature so operators
          // can distinguish a macOS syspolicyd ExecPolicy DB bloat flake
          // from a real test failure.
          if (detectVitestForkPoolFlake(f.tail)) {
            console.error(VITEST_FORK_POOL_FLAKE_DIAGNOSTIC);
          }
        }
        console.error(bar);
        throw new Error(
          `pre-merge checks failed: ${failed.map((f) => f.name).join(", ")}. Merge rolled back. Fix and re-run.`,
        );
      }
    }

    // Dispatch — server-attested v4 vs. legacy v3.
    //
    // The branch rule's `review_server` field is the v4 trigger: if the
    // operator configured a stamp-server review URL for this branch, the
    // merge MUST fold real server-signed approvals into a v4 envelope.
    // Missing/stale server signatures fail loudly; we never silently fall
    // back to v3 here because doing so would let a misconfigured server
    // (or a stale DB) downgrade the trust property without the operator
    // noticing.
    //
    // v3 (legacy) is preserved for repos without `review_server` — they
    // continue to ship operator-signed-only attestations as today.
    //
    // v4 produces two outputs (trailers + matchedPathRules for the banner);
    // use if/else so both can be assigned cleanly without an IIFE closure.
    let trailers: string;
    if (rule.review_server) {
      const v4Result = buildV4Trailers({
        repoRoot,
        revspec,
        baseSha: resolved.base_sha,
        headSha: resolved.head_sha,
        diff: resolved.diff,
        targetBranch: opts.into,
        requiredReviewers: rule.required,
        checks: checkAttestations,
        operatorPrivateKeyPem: keypair.privateKeyPem,
        operatorFingerprint: keypair.fingerprint,
      });
      matchedPathRules = v4Result.matchedPathRules;
      trailers = v4Result.trailers;
    } else {
      trailers = buildV3Trailers({
        repoRoot,
        baseSha: resolved.base_sha,
        headSha: resolved.head_sha,
        approvals,
        checks: checkAttestations,
        targetBranch: opts.into,
        operatorPrivateKeyPem: keypair.privateKeyPem,
        operatorFingerprint: keypair.fingerprint,
      });
    }

    const fullMessage = `${title}\n\n${trailers}\n`;

    git(["commit", "--amend", "-m", fullMessage, "--no-edit"], repoRoot);

    mergeSha = git(["rev-parse", "HEAD"], repoRoot).trim();
  } catch (err) {
    // Roll back to the pre-merge SHA so the repo ends up exactly as it was
    // before `stamp merge` was called. We reset to the explicit preMergeSha
    // (captured before `git merge --no-ff`) rather than HEAD~1 so the
    // rollback target is unambiguous regardless of reflog edge cases.
    //
    // If the reset itself fails (disk full, locked ref, etc.) we compose the
    // reset error with the original error and surface both loudly — the
    // operator needs to know about the orphaned unsigned merge commit and how
    // to recover manually.
    const unsignedSha = (() => {
      try {
        return git(["rev-parse", "HEAD"], repoRoot).trim();
      } catch {
        return "(unknown — git rev-parse failed)";
      }
    })();

    try {
      git(["reset", "--hard", preMergeSha], repoRoot);
    } catch (resetErr) {
      const resetMsg =
        resetErr instanceof Error ? resetErr.message : String(resetErr);
      const origMsg = err instanceof Error ? err.message : String(err);
      throw new Error(
        `stamp merge failed AND the rollback reset to ${preMergeSha} also failed. ` +
          `An unsigned merge commit (${unsignedSha}) is now on the target branch. ` +
          `Recover manually: git reset --hard ${preMergeSha}\n` +
          `Original error: ${origMsg}\n` +
          `Reset error: ${resetMsg}`,
      );
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
  // AC#4: one line per matched path_rule, v4 path only, silent when none.
  for (const pr of matchedPathRules) {
    console.log(
      `  path_rules: ${pr.pattern} (${pr.qualifying_count}/${pr.minimum_signatures} admin sigs)`,
    );
  }
  console.log(bar);
  console.log(`\nVerify locally:    stamp verify ${mergeSha.slice(0, 12)}`);
  console.log(`Push to origin:    stamp push ${opts.into}`);
}

function hashPart(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

/**
 * Parse the JSON-encoded McpServerAtInit[] from the DB column. Returns an
 * empty array for null/invalid inputs (pre-AGT-246 rows or reviewers with
 * no MCP servers).
 */
function parseMcpServersAtInit(raw: string | null): McpServerAtInit[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed as McpServerAtInit[];
    return [];
  } catch {
    return [];
  }
}

/**
 * Build the v3 (operator-signed-only, legacy) trailer block.
 *
 * Preserves the pre-AGT-334 behavior verbatim: per-reviewer
 * prompt/tools/mcp hashes are sourced from the merge-base tree (NOT the
 * merge commit's own tree). That's the v3 security boundary — the
 * reviewer that approved is the one that existed at `base_sha`, the
 * version BEFORE the diff. Hashing the post-merge tree (v2) was broken
 * because a feature branch could modify a reviewer prompt and the
 * resulting hash would match the modified prompt, allowing a self-
 * reviewing merge to verify cleanly.
 *
 * reviewer_source comes from the on-disk lock file (which at this point
 * IS the merge-commit tree, since we just made the merge). It's audit
 * metadata, not part of the trust boundary — if a diff swaps the lock
 * file, the prompt_sha256 mismatch (computed from the *base* tree) is
 * what would catch it.
 */
function buildV3Trailers(input: {
  repoRoot: string;
  baseSha: string;
  headSha: string;
  approvals: Approval[];
  checks: CheckAttestation[];
  targetBranch: string;
  operatorPrivateKeyPem: string;
  operatorFingerprint: string;
}): string {
  const baseConfigYaml = showAtRef(
    input.baseSha,
    ".stamp/config.yml",
    input.repoRoot,
  );
  const baseReviewers = readReviewersFromYaml(baseConfigYaml);

  const approvalsWithHashes: Approval[] = input.approvals.map((a) => {
    const def = baseReviewers[a.reviewer];
    if (!def) {
      throw new Error(
        `reviewer "${a.reviewer}" approved the diff but is not defined in .stamp/config.yml at base ${input.baseSha.slice(0, 8)}. ` +
          `This shouldn't happen — runReview reads from the same base. ` +
          `File a bug at https://github.com/OpenThinkAi/stamp-cli/issues. ` +
          `Merge rolled back.`,
      );
    }
    if (def.prompt === undefined) {
      // v3 trailers are produced for the LEGACY (no review_server) merge
      // path. A reviewer with no `prompt:` is a Shape 4 entry that should
      // be paired with `review_server:` on the branch rule — in which
      // case `buildV4Trailers` would have run instead. Reaching here
      // means the operator configured Shape 4 reviewers but no
      // review_server on the branch rule, which is incoherent.
      throw new Error(
        `reviewer "${a.reviewer}": no \`prompt:\` configured and no \`review_server:\` on branch rule — ` +
          `set \`reviewers.${a.reviewer}.prompt\` in .stamp/config.yml or configure a \`review_server:\` for server-attested mode. ` +
          `Merge rolled back.`,
      );
    }
    const promptText = showAtRef(input.baseSha, def.prompt, input.repoRoot);
    const source = readReviewerSource(a.reviewer, input.repoRoot);
    return {
      ...a,
      prompt_sha256: hashPromptBytes(Buffer.from(promptText, "utf8")),
      tools_sha256: hashTools(def.tools),
      mcp_sha256: hashMcpServers(def.mcp_servers),
      ...(source ? { reviewer_source: source } : {}),
    };
  });

  const payload: AttestationPayload = {
    schema_version: CURRENT_PAYLOAD_VERSION,
    base_sha: input.baseSha,
    head_sha: input.headSha,
    target_branch: input.targetBranch,
    approvals: approvalsWithHashes,
    checks: input.checks,
    signer_key_id: input.operatorFingerprint,
  };
  const payloadBytes = serializePayload(payload);
  const signature = signBytes(input.operatorPrivateKeyPem, payloadBytes);
  return formatTrailers(payload, signature);
}

/**
 * Build the v4 (server-attested) trailer block.
 *
 * Validates that every required reviewer has a server-signed approval
 * row in the local DB for `(baseSha, headSha)`, fails loudly on missing
 * or stale rows, and assembles the v4 envelope with operator signature
 * over the canonical payload bytes.
 *
 * Failure modes (all rollback-triggering):
 *   - no server-signed row for a required reviewer → "missing server
 *     signature"
 *   - `approval.diff_sha256` doesn't match sha256(diff) → "stale server
 *     signature"
 *   - `approval.base_sha` / `head_sha` / `reviewer` mismatch → "server
 *     signature for wrong target"
 *   - `approval.verdict !== 'approved'` → "non-approval verdict"
 *
 * Each error message names the actionable next step (re-run `stamp
 * review --diff <revspec>`).
 */
/**
 * Matched path_rules info returned alongside the v4 trailer string.
 * Used by runMerge to print the banner lines (AC#4).
 * Aliased from CollectTrustAnchorResult so the shape stays in one place.
 */
type MatchedPathRuleBanner = CollectTrustAnchorResult["matchedPathRules"][number];

function buildV4Trailers(input: {
  repoRoot: string;
  revspec: string;
  baseSha: string;
  headSha: string;
  diff: string;
  targetBranch: string;
  requiredReviewers: string[];
  checks: CheckAttestation[];
  operatorPrivateKeyPem: string;
  operatorFingerprint: string;
}): { trailers: string; matchedPathRules: MatchedPathRuleBanner[] } {
  // Compute the canonical diff_sha256 over the same bytes the server
  // hashed. resolveDiff returned `diff` as a utf-8 string; encode the
  // same way the SSH client did when it streamed bytes to the server.
  const diffBytes = Buffer.from(input.diff, "utf8");
  const diffSha256 = createHash("sha256").update(diffBytes).digest("hex");

  // Load the trusted-keys manifest + pubkey set at base_sha.
  //
  // Defense-in-depth (AGT-334 security review #1): the SSH client
  // verified every server signature at write time, but DB tampering
  // or a writer-side bug could plant a row with a plausible-looking
  // approval body and an invalid signature. Re-verifying at merge
  // time means a corrupted DB row can NEVER produce a signed merge
  // commit — the operator's local trust chain stays intact even when
  // the DB is hostile. This closes the "AGT-335 will catch it" gap:
  // a fault detected here surfaces at merge time with a clear local
  // recovery path, not at push time after a permanent commit has
  // already landed.
  //
  // Sourced from base_sha (same boundary as `stamp review`): a
  // feature branch shipping a permissive manifest cannot have that
  // manifest trust its own additions — the verifier reads the
  // manifest as it existed BEFORE the diff.
  let manifestYaml: string;
  try {
    manifestYaml = showAtRef(
      input.baseSha,
      ".stamp/trusted-keys/manifest.yml",
      input.repoRoot,
    );
  } catch (err) {
    throw new Error(
      `review_server is configured but .stamp/trusted-keys/manifest.yml is missing ` +
        `at base ${input.baseSha.slice(0, 8)}: ` +
        `${err instanceof Error ? err.message : String(err)}. ` +
        `Server-attested merges require the manifest in the merge-base tree so ` +
        `each approval's server signature can be checked against the keys the repo ` +
        `trusted at attestation time. Commit a manifest with capabilities: [server] ` +
        `entries for the review server before merging.`,
    );
  }
  const manifest = parseManifest(manifestYaml);
  if (!manifest) {
    throw new Error(
      `.stamp/trusted-keys/manifest.yml at base ${input.baseSha.slice(0, 8)} ` +
        `failed to parse as a valid trusted-keys manifest. Fix the YAML ` +
        `(syntax error, duplicate fingerprint, unknown capability, etc.) ` +
        `and re-merge.`,
    );
  }
  const pubFilenames = listFilesAtRef(
    input.baseSha,
    ".stamp/trusted-keys",
    input.repoRoot,
  );
  const pubkeyByFingerprint = buildPubkeyMap(pubFilenames, (relPath) =>
    showAtRef(input.baseSha, relPath, input.repoRoot),
  );

  // Query server-signed approval rows for this (base, head) pair.
  const db = openDb(stampStateDbPath(input.repoRoot));
  let entries: ApprovalEntryV4[];
  try {
    const rows = serverApprovalsFor(db, input.baseSha, input.headSha);
    const byReviewer = new Map(rows.map((r) => [r.reviewer, r]));

    entries = input.requiredReviewers.map((reviewerName) => {
      const row = byReviewer.get(reviewerName);
      if (!row) {
        throw new Error(
          `missing server signature for reviewer "${reviewerName}" at base→head ${input.baseSha.slice(0, 8)}→${input.headSha.slice(0, 8)}. ` +
            `Server-attested mode requires every required reviewer to have a stamp-server-signed approval in the local DB. ` +
            `Run \`stamp review --diff ${input.revspec}\` to populate server signatures, then re-run \`stamp merge\`.`,
        );
      }

      // Parse the JSON-stringified ApprovalV4 the SSH client persisted.
      // The bytes the server signed are
      // `canonicalSerializeApproval(parsed)`, NOT this JSON string
      // verbatim — JSON.parse + re-stringify doesn't preserve key order
      // and the canonical serializer re-sorts before signature checks.
      //
      // `JSON.parse` is typed as `any`; we narrow to `ApprovalV4` only
      // after the field-by-field shape check below validates every
      // string-typed field we care about. A row that parses to `null`,
      // an array, or an object missing a required string field surfaces
      // as a clean "malformed row" error rather than `Cannot read
      // property of null` further down.
      let parsedJson: unknown;
      try {
        parsedJson = JSON.parse(row.approval_json);
      } catch (err) {
        throw new Error(
          `server approval row for reviewer "${reviewerName}" has malformed JSON in server_approval_json — DB corruption or a writer-side bug. ` +
            `Re-run \`stamp review --diff ${input.revspec}\` to write a fresh row. ` +
            `(parse error: ${err instanceof Error ? err.message : String(err)})`,
        );
      }
      if (
        !parsedJson ||
        typeof parsedJson !== "object" ||
        Array.isArray(parsedJson)
      ) {
        throw new Error(
          `server approval row for reviewer "${reviewerName}" parsed to a non-object value — DB corruption or a writer-side bug. ` +
            `Re-run \`stamp review --diff ${input.revspec}\` to write a fresh row.`,
        );
      }
      const obj = parsedJson as Record<string, unknown>;
      for (const field of [
        "reviewer",
        "verdict",
        "prompt_sha256",
        "diff_sha256",
        "base_sha",
        "head_sha",
        "issued_at",
        "server_key_id",
      ]) {
        if (typeof obj[field] !== "string") {
          throw new Error(
            `server approval row for reviewer "${reviewerName}" is missing required field "${field}" (or it isn't a string) — DB corruption or a writer-side bug. ` +
              `Re-run \`stamp review --diff ${input.revspec}\` to write a fresh row.`,
          );
        }
      }
      const approval = parsedJson as ApprovalV4;

      // Cross-check the parsed approval body against the inputs. The
      // SSH client already enforces these on write, but verifying again
      // here keeps the merge-time invariant explicit: the row we're
      // about to fold into a trust-bearing envelope describes THIS
      // merge, not some other one.
      if (approval.reviewer !== reviewerName) {
        throw new Error(
          `server approval row for reviewer "${reviewerName}" carries approval.reviewer="${approval.reviewer}" — DB row drifted. ` +
            `Re-run \`stamp review --diff ${input.revspec}\`.`,
        );
      }
      if (approval.base_sha !== input.baseSha) {
        throw new Error(
          `server approval for "${reviewerName}" was signed against base_sha ${approval.base_sha.slice(0, 8)} but we're merging from ${input.baseSha.slice(0, 8)} — stale signature. ` +
            `Re-run \`stamp review --diff ${input.revspec}\` to refresh.`,
        );
      }
      if (approval.head_sha !== input.headSha) {
        throw new Error(
          `server approval for "${reviewerName}" was signed against head_sha ${approval.head_sha.slice(0, 8)} but we're merging head ${input.headSha.slice(0, 8)} — stale signature. ` +
            `Re-run \`stamp review --diff ${input.revspec}\` to refresh.`,
        );
      }
      if (approval.diff_sha256 !== diffSha256) {
        throw new Error(
          `server approval for "${reviewerName}" was signed against diff_sha256 ${approval.diff_sha256.slice(0, 12)}… but the current diff hashes to ${diffSha256.slice(0, 12)}… — stale signature. ` +
            `The diff content drifted between review and merge (rebased base, modified head). ` +
            `Re-run \`stamp review --diff ${input.revspec}\`.`,
        );
      }
      if (approval.verdict !== "approved") {
        throw new Error(
          `server approval for "${reviewerName}" carries verdict "${approval.verdict}", not "approved". ` +
            `Re-run \`stamp review --diff ${input.revspec}\` so the server signs the current approved verdict.`,
        );
      }

      // Re-verify the server's Ed25519 signature over the canonical
      // approval bytes. The SSH client already did this at write
      // time, but the operator's local trust chain MUST NOT depend
      // on that — a DB row is only as trustworthy as the bytes we
      // can verify right now. Failure here means either the DB was
      // tampered with after the SSH client wrote, the manifest /
      // pubkey set at base_sha doesn't include the signing key, or
      // the row drifted by writer-side bug. All three are merge-
      // blocking; recovery is a fresh `stamp review`.
      //
      // Trust-key lookup uses the INNER signed payload's
      // server_key_id (settled architectural decision #9), not the
      // row's denormalized column.
      const caps = resolveCapability(manifest, approval.server_key_id);
      if (caps === null) {
        throw new Error(
          `server approval for "${reviewerName}" was signed by ${approval.server_key_id}, ` +
            `but that key isn't listed in .stamp/trusted-keys/manifest.yml at base ${input.baseSha.slice(0, 8)}. ` +
            `Either the server's signing key changed (commit the new fingerprint to the manifest with capabilities: [server]) ` +
            `or this row was written by a server the repo no longer trusts. ` +
            `Re-run \`stamp review --diff ${input.revspec}\` after fixing the manifest.`,
        );
      }
      if (!caps.includes("server")) {
        throw new Error(
          `server approval for "${reviewerName}" was signed by ${approval.server_key_id}, ` +
            `but that key's capabilities in .stamp/trusted-keys/manifest.yml at base ${input.baseSha.slice(0, 8)} are [${caps.join(", ")}] — ` +
            `missing the required 'server' capability. Update the manifest entry and re-merge.`,
        );
      }
      const serverPubPem = pubkeyByFingerprint.get(approval.server_key_id);
      if (!serverPubPem) {
        throw new Error(
          `server approval for "${reviewerName}" was signed by ${approval.server_key_id}, ` +
            `but no .pub file in .stamp/trusted-keys/ at base ${input.baseSha.slice(0, 8)} matches that fingerprint. ` +
            `Commit the server's public key alongside its manifest entry and re-merge.`,
        );
      }
      const sigOk = verifyBytes(
        serverPubPem,
        canonicalSerializeApproval(approval),
        row.signature_b64,
      );
      if (!sigOk) {
        throw new Error(
          `server signature for "${reviewerName}" failed Ed25519 verification against key ${approval.server_key_id}. ` +
            `The DB row's signature does not match the canonical bytes of its approval body — ` +
            `either the row was tampered with or the writer was buggy. ` +
            `Re-run \`stamp review --diff ${input.revspec}\` to refresh the signed row.`,
        );
      }

      // Trust-lookup is derived from the INNER signed payload's
      // server_key_id, not the row's denormalized column (settled
      // architectural decision #9: the column is for display/indexing
      // only; the signed payload's server_key_id is authoritative).
      // The SSH client already verified the inner signature against the
      // manifest at base_sha before writing this row; we re-export that
      // server_key_id into the envelope here so downstream verifiers
      // can re-resolve against the manifest themselves.
      return {
        approval,
        server_attestation: {
          server_key_id: approval.server_key_id,
          signature: row.signature_b64,
        },
      };
    });
  } finally {
    db.close();
  }

  // v4 checks share the field set with v3 (name, command, exit_code,
  // output_sha) but live under a distinct type. Shape-cast — no field
  // rename needed.
  const v4Checks: CheckAttestationV4[] = input.checks.map((c) => ({
    name: c.name,
    command: c.command,
    exit_code: c.exit_code,
    output_sha: c.output_sha,
  }));

  // Trust-anchor signatures (AGT-337). If the diff touches paths
  // matched by any `path_rules` entry at base_sha, read collected admin
  // signatures from the notes-ref keyed by the feature-branch head SHA.
  // Each note signature is verified against the SAME bytes the
  // pre-receive verifier will check (`canonicalSerializePayload` of
  // this payload with `trust_anchor_signatures: []`). Verifying entries
  // are folded into the envelope; if the count is below the matched
  // rule's `minimum_signatures`, we fail with an actionable message
  // BEFORE signing the operator's outer envelope — no point producing
  // a trailer the server will reject on push.
  // AGT-370: operator computes manifest_snapshot_sha256 from the
  // manifest at base_sha and binds it into the outer envelope. The
  // server no longer reads the manifest at all; the verifier checks
  // this single envelope-level value against snapshotSha256() of the
  // manifest it reads from base_sha. Lifted from the per-approval
  // slot in v4 (ApprovalV4.trusted_keys_snapshot_sha256, now removed).
  // Computed BEFORE collectTrustAnchorSignatures so admin sigs and the
  // operator's outer sig commit to the same value through the shared
  // `trustAnchorSigningBytes` builder.
  const manifestSnapshot = snapshotSha256(manifest);

  const trustAnchorResult = collectTrustAnchorSignatures({
    repoRoot: input.repoRoot,
    baseSha: input.baseSha,
    headSha: input.headSha,
    targetBranch: input.targetBranch,
    diffSha256,
    manifestSnapshotSha256: manifestSnapshot,
    approvals: entries,
    checks: v4Checks,
    operatorFingerprint: input.operatorFingerprint,
    manifest,
    pubkeyByFingerprint,
  });
  const trustAnchorSigs = trustAnchorResult.signatures;

  const payload: AttestationPayloadV4 = {
    schema_version: CURRENT_V4_SCHEMA_VERSION,
    base_sha: input.baseSha,
    head_sha: input.headSha,
    target_branch: input.targetBranch,
    diff_sha256: diffSha256,
    manifest_snapshot_sha256: manifestSnapshot,
    approvals: entries,
    checks: v4Checks,
    trust_anchor_signatures: trustAnchorSigs,
    signer_key_id: input.operatorFingerprint,
  };

  // Operator's Ed25519 over the canonical payload bytes. The bytes that
  // land in the Stamp-Verified trailer are produced by
  // `canonicalSerializePayload`; trailerValueToPayloadBytes(b64) pulls
  // the same bytes back out on the verify side, so the signature target
  // is byte-stable across serialize → trailer-encode → trailer-decode.
  const payloadBytes = canonicalSerializePayload(payload);
  const signature = signBytes(input.operatorPrivateKeyPem, payloadBytes);
  return {
    trailers: formatTrailersV4(payload, signature),
    matchedPathRules: trustAnchorResult.matchedPathRules,
  };
}

function readReviewerSource(
  reviewerName: string,
  repoRoot: string,
): { source: string; ref: string } | null {
  // Read the committed lock file (not the on-disk copy) so the attestation
  // reflects what's in the merge commit's tree. Absence is the documented
  // un-pinned default and produces no reviewer_source field — check
  // existence first so a real `git show` failure (corrupted object, etc.)
  // still propagates and rolls the merge back rather than masquerading as
  // "unpinned."
  const path = `.stamp/reviewers/${reviewerName}.lock.json`;
  if (!pathExistsAtRef("HEAD", path, repoRoot)) {
    return null;
  }
  const raw = git(["show", `HEAD:${path}`], repoRoot);
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

const git = runGit;
