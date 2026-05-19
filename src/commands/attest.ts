/**
 * `stamp attest [<branch>] --into <target>`
 *
 * PR-check-mode counterpart to `stamp merge`. Validates the same review
 * gate against the same `(base_sha, head_sha)` pair, builds an
 * approvals list from the local review DB, signs an attestation
 * envelope with the operator's stamp key, and writes it to a
 * content-addressed git ref under `refs/stamp/attestations/<patch-id>`.
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
 * editing its own reviewer prompt.
 *
 * Schema dispatch (AGT-355):
 *   - When the branch rule declares a `review_server` AND the local DB
 *     has server-signed approvals for every required reviewer at this
 *     (base, head) pair → produce a v3 PR-attestation envelope:
 *     per-approval entries carry the server's Ed25519 signature
 *     (`ApprovalEntryV4`), top-level `diff_sha256` binds the operator's
 *     outer signature to the actual diff, `trust_anchor_signatures` is
 *     populated when the diff touches `.stamp/**`. Mirrors the v4
 *     commit-trailer envelope `stamp merge` produces, plus the
 *     PR-mode-only `patch_id` / `target_branch_tip_sha` fields. This is
 *     the canonical 2.x Shape 2 (server-attested PR mode) path.
 *   - When the branch rule has no `review_server` (or the DB lacks
 *     server signatures) → produce a legacy v2 envelope at
 *     `LEGACY_CLIENT_PR_ATTESTATION_SCHEMA_VERSION`. This is the 1.6.0
 *     PR-check-mode path: approvals are bare `Approval[]` (no
 *     per-approval server signature), operator signs the outer
 *     envelope, no v4 trust fields. The 2.x verifier rejects v2
 *     envelopes with an actionable "schema_version too old" error —
 *     operators that need the trust property must configure a
 *     `review_server` (Shape 2).
 *
 * The dispatch mirrors `stamp merge`'s v3-vs-v4 dispatch verbatim. The
 * branch rule's `review_server` field is the operator's declared intent
 * to use server-attested reviews; missing-but-required server
 * signatures fail loudly rather than silently downgrading to v2.
 */

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { type Approval } from "../lib/attestation.js";
import {
  canonicalSerializeApproval,
  type ApprovalEntryV4,
  type ApprovalV4,
} from "../lib/attestationV4.js";
import { findBranchRule, loadConfig } from "../lib/config.js";
import { latestReviews, openDb, serverApprovalsFor } from "../lib/db.js";
import {
  listFilesAtRef,
  pathExistsAtRef,
  resolveDiff,
  runGit,
  showAtRef,
} from "../lib/git.js";
import { ensureUserKeypair } from "../lib/keys.js";
import {
  findRepoRoot,
  stampConfigFile,
  stampStateDbPath,
} from "../lib/paths.js";
import { patchIdForSpan } from "../lib/patchId.js";
import {
  LEGACY_CLIENT_PR_ATTESTATION_SCHEMA_VERSION,
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
import { signBytes, verifyBytes } from "../lib/signing.js";
import { buildPubkeyMap } from "../lib/sshReviewClient.js";
import {
  parseManifest,
  resolveCapability,
} from "../lib/trustedKeysManifest.js";

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

  // Compute the content hash (patch-id) — this is what the artifact
  // is keyed on. Same patch-id across rebase / squash / merge-commit
  // on the GitHub side, so the attestation survives all three.
  const patch_id = patchIdForSpan(resolved.base_sha, resolved.head_sha, repoRoot);

  // Also record the TIP of the target branch at attest time, distinct
  // from resolved.base_sha (which is the merge-base). Verifiers with
  // strict_base:true compare this against the current tip — any
  // advancement of main since attest time fails verification, even
  // when the cumulative diff content is unchanged. resolveDiff above
  // already validated opts.into resolves, so rev-parse here can't fail
  // on the same machine for the same name.
  const target_branch_tip_sha = runGit(
    ["rev-parse", `${opts.into}^{commit}`],
    repoRoot,
  ).trim();

  const { keypair } = ensureUserKeypair();

  // Dispatch — v3 (server-attested) vs. v2 (legacy / operator-only).
  //
  // Same trigger as `stamp merge`'s v4/v3 dispatch: the branch rule's
  // `review_server` field is the operator's declared intent to use
  // server-attested reviews. When set, we MUST fold real server-signed
  // approvals into a v3 PR-attestation envelope; missing/stale server
  // signatures fail loudly rather than silently degrading to v2 (which
  // the 2.x verifier rejects).
  //
  // When `review_server` is absent, this is the 1.6.0 PR-check-mode
  // flow: produce a v2 envelope with bare `Approval[]`, operator-signs-
  // outer-only. The 2.x verifier rejects v2 with a schema-too-old
  // actionable error pointing operators at the `review_server`-driven
  // path; the v2 path remains for repos pinning the GH Action to a
  // 1.x stamp-version during the bridge window. AGT-355 ships the
  // producer side so post-2.0.1 the bridge window is no longer needed.
  const result = rule.review_server
    ? buildV3Envelope({
        repoRoot,
        revspec,
        baseSha: resolved.base_sha,
        headSha: resolved.head_sha,
        diff: resolved.diff,
        targetBranch: opts.into,
        targetBranchTipSha: target_branch_tip_sha,
        patchId: patch_id,
        requiredReviewers: rule.required,
        operatorPrivateKeyPem: keypair.privateKeyPem,
        operatorFingerprint: keypair.fingerprint,
      })
    : buildV2Envelope({
        repoRoot,
        revspec,
        baseSha: resolved.base_sha,
        headSha: resolved.head_sha,
        targetBranch: opts.into,
        targetBranchTipSha: target_branch_tip_sha,
        patchId: patch_id,
        requiredReviewers: rule.required,
        operatorPrivateKeyPem: keypair.privateKeyPem,
        operatorFingerprint: keypair.fingerprint,
      });

  const { ref, blob_sha } = writeAttestationRef(
    { payload: result.payload, signature: result.signature },
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
  console.log(`  approvals:  ${result.reviewerNames.join(", ")}`);
  console.log(
    `  schema:     v${result.payload.schema_version}${result.payload.schema_version === PR_ATTESTATION_SCHEMA_VERSION ? " (server-attested)" : " (legacy)"}`,
  );
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
 * Common shape for both v2 and v3 envelope builders: returns the
 * payload + outer signature + the list of reviewer names that landed
 * in the approvals array. The caller writes the envelope to the ref
 * and prints a summary; both paths share that scaffolding.
 */
interface EnvelopeBuildResult {
  payload: PrAttestationPayload;
  signature: string;
  reviewerNames: string[];
}

interface V3BuildInput {
  repoRoot: string;
  revspec: string;
  baseSha: string;
  headSha: string;
  diff: string;
  targetBranch: string;
  targetBranchTipSha: string;
  patchId: string;
  requiredReviewers: string[];
  operatorPrivateKeyPem: string;
  operatorFingerprint: string;
}

/**
 * Build the v3 PR-attestation envelope for server-attested PR mode
 * (AGT-355). Mirrors `stamp merge`'s `buildV4Trailers` shape exactly —
 * same trust validation, same canonical signature targets, same
 * stale-signature rejections — adapted to the PR-attestation envelope
 * (patch_id + target_branch_tip_sha + JSON blob instead of base64
 * commit trailer).
 *
 * The server signed `canonicalSerializeApproval(approval)` for each
 * reviewer (per AGT-331); the SSH client (`requestServerReview`)
 * already verified that signature at write time, and `stamp merge`'s
 * defense-in-depth pattern re-verifies at fold time. We follow the
 * same belt-and-suspenders approach here: a corrupted DB row CANNOT
 * produce a signed v3 envelope — the local trust chain stays intact
 * even when the DB is hostile.
 */
function buildV3Envelope(input: V3BuildInput): EnvelopeBuildResult {
  // Hash the diff the same way the server did when it streamed bytes
  // over SSH — `Buffer.from(diff, "utf8")` then sha256. Byte identity
  // here is the contract: a mismatch between our hash and the server's
  // signed `diff_sha256` indicates the diff content drifted between
  // review and attest.
  const diffBytes = Buffer.from(input.diff, "utf8");
  const diffSha256 = createHash("sha256").update(diffBytes).digest("hex");

  // Load trust artifacts at base_sha (same boundary as stamp review +
  // stamp merge). A feature branch shipping a permissive manifest
  // cannot have that manifest trust its own additions — the verifier
  // reads the manifest as it existed BEFORE the diff.
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
        `Server-attested PR mode requires the manifest in the merge-base tree so ` +
        `each approval's server signature can be checked against the keys the repo ` +
        `trusted at attestation time. Commit a manifest with capabilities: [server] ` +
        `entries for the review server before attesting.`,
    );
  }
  const manifest = parseManifest(manifestYaml);
  if (!manifest) {
    throw new Error(
      `.stamp/trusted-keys/manifest.yml at base ${input.baseSha.slice(0, 8)} ` +
        `failed to parse as a valid trusted-keys manifest. Fix the YAML ` +
        `(syntax error, duplicate fingerprint, unknown capability, etc.) ` +
        `and re-run \`stamp attest\`.`,
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
  // Same code path stamp merge uses; the rows were written by AGT-332
  // (`requestServerReview` → `recordReview` with serverAttestation).
  const db = openDb(stampStateDbPath(input.repoRoot));
  let entries: ApprovalEntryV4[];
  try {
    const rows = serverApprovalsFor(db, input.baseSha, input.headSha);
    const byReviewer = new Map(rows.map((r) => [r.reviewer, r]));

    entries = input.requiredReviewers.map((reviewerName) => {
      const row = byReviewer.get(reviewerName);
      if (!row) {
        throw new Error(
          `missing server signature for reviewer "${reviewerName}" at base→head ` +
            `${input.baseSha.slice(0, 8)}→${input.headSha.slice(0, 8)}. ` +
            `Server-attested PR mode requires every required reviewer to have a ` +
            `stamp-server-signed approval in the local DB. Possible causes:\n` +
            `  • the stamp-server is older than 2.0.1 and doesn't produce ` +
            `PR-attestation v3 payloads (upgrade the server)\n` +
            `  • \`stamp review --diff ${input.revspec}\` hasn't been run against ` +
            `this exact (base, head) pair yet\n` +
            `  • the review was run in local-mode (no \`review_server\` configured at ` +
            `review time)\n` +
            `Run \`stamp review --diff ${input.revspec}\` to populate the signed row, ` +
            `then re-run \`stamp attest\`.`,
        );
      }

      // Parse the JSON-stringified ApprovalV4 the SSH client persisted.
      // The bytes the server signed are
      // `canonicalSerializeApproval(parsed)`, NOT this JSON string
      // verbatim — JSON.parse + re-stringify doesn't preserve key
      // order and the canonical serializer re-sorts before signature
      // checks.
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
        "trusted_keys_snapshot_sha256",
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

      // Cross-check the parsed approval body against the inputs — same
      // pattern as stamp merge's buildV4Trailers. The SSH client
      // already enforces these on write, but verifying again here
      // keeps the attest-time invariant explicit: the row we're about
      // to fold into a trust-bearing envelope describes THIS attest,
      // not some other one.
      if (approval.reviewer !== reviewerName) {
        throw new Error(
          `server approval row for reviewer "${reviewerName}" carries approval.reviewer="${approval.reviewer}" — DB row drifted. ` +
            `Re-run \`stamp review --diff ${input.revspec}\`.`,
        );
      }
      if (approval.base_sha !== input.baseSha) {
        throw new Error(
          `server approval for "${reviewerName}" was signed against base_sha ${approval.base_sha.slice(0, 8)} but we're attesting from ${input.baseSha.slice(0, 8)} — stale signature. ` +
            `Re-run \`stamp review --diff ${input.revspec}\` to refresh.`,
        );
      }
      if (approval.head_sha !== input.headSha) {
        throw new Error(
          `server approval for "${reviewerName}" was signed against head_sha ${approval.head_sha.slice(0, 8)} but we're attesting head ${input.headSha.slice(0, 8)} — stale signature. ` +
            `Re-run \`stamp review --diff ${input.revspec}\` to refresh.`,
        );
      }
      if (approval.diff_sha256 !== diffSha256) {
        throw new Error(
          `server approval for "${reviewerName}" was signed against diff_sha256 ${approval.diff_sha256.slice(0, 12)}… but the current diff hashes to ${diffSha256.slice(0, 12)}… — stale signature. ` +
            `The diff content drifted between review and attest (rebased base, modified head). ` +
            `Re-run \`stamp review --diff ${input.revspec}\`.`,
        );
      }
      if (approval.verdict !== "approved") {
        throw new Error(
          `server approval for "${reviewerName}" carries verdict "${approval.verdict}", not "approved". ` +
            `Re-run \`stamp review --diff ${input.revspec}\` so the server signs the current approved verdict.`,
        );
      }

      // Re-verify the server's Ed25519 signature over canonical
      // approval bytes — same defense-in-depth pattern as
      // buildV4Trailers in merge.ts. The SSH client did this at
      // write time, but DB tampering could plant a row with a
      // plausible-looking approval body and an invalid signature.
      // Re-verifying at attest time means a corrupted DB row can
      // NEVER produce a signed v3 envelope.
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
            `missing the required 'server' capability. Update the manifest entry and re-attest.`,
        );
      }
      const serverPubPem = pubkeyByFingerprint.get(approval.server_key_id);
      if (!serverPubPem) {
        throw new Error(
          `server approval for "${reviewerName}" was signed by ${approval.server_key_id}, ` +
            `but no .pub file in .stamp/trusted-keys/ at base ${input.baseSha.slice(0, 8)} matches that fingerprint. ` +
            `Commit the server's public key alongside its manifest entry and re-attest.`,
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

      // Trust-lookup uses the INNER signed payload's server_key_id
      // (settled architectural decision #9 from AGT-334): the row's
      // denormalized column is for display/indexing only; the signed
      // payload's server_key_id is authoritative.
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

  // Trust-anchor signatures (AGT-337). For the v3 PR-attestation, the
  // path-rules guard is structurally identical to server-gated mode:
  // when the diff touches `.stamp/**`, the matched path_rule's
  // `minimum_signatures` count of admin counter-signatures must be
  // present. This path is OUT OF SCOPE for AGT-355 (the producer-side
  // happy path for path-touching diffs lands in a follow-up: today's
  // `stamp attest` doesn't collect admin signatures from the
  // notes-ref the way `stamp merge` does). For non-`.stamp/**` diffs
  // — the overwhelmingly common case — this is correctly empty and
  // the verifier's `verifyV4StampPathsGuard` no-ops.
  //
  // If the operator's diff touches `.stamp/**`, the verifier will
  // reject the envelope at `verifyV4StampPathsGuard` with the same
  // actionable "needs N admin signatures" error stamp merge surfaces.
  // The operator's recovery is: collect admin signatures via
  // `stamp admin sign` (AGT-337's tooling), then re-run `stamp
  // attest` — once the AGT-355 follow-up wires the collection path
  // into attest.
  const trustAnchorSignatures: never[] = [];

  const payload: PrAttestationPayload = {
    schema_version: PR_ATTESTATION_SCHEMA_VERSION,
    patch_id: input.patchId,
    base_sha: input.baseSha,
    head_sha: input.headSha,
    target_branch: input.targetBranch,
    target_branch_tip_sha: input.targetBranchTipSha,
    diff_sha256: diffSha256,
    approvals: entries,
    checks: [], // Phase-1 deliberate omission — see file-level comment.
    trust_anchor_signatures: trustAnchorSignatures,
    signer_key_id: input.operatorFingerprint,
  };

  // Operator-signs-outer-envelope contract from AGT-338: the outer
  // signature is operator-side (covers diff_sha256, approvals,
  // trust_anchor_signatures, base/head/patch). verifyV4OuterSignature
  // + verifyV4SignerTrust confirm the signer has `operator` capability
  // in the base-sha manifest. The inner per-approval signatures rode
  // in `entries` above (signed by the server, verified at fold time
  // here and re-verified by the GH Action at PR-check time).
  const signature = signBytes(
    input.operatorPrivateKeyPem,
    serializePayload(payload),
  );

  return {
    payload,
    signature,
    reviewerNames: input.requiredReviewers,
  };
}

interface V2BuildInput {
  repoRoot: string;
  revspec: string;
  baseSha: string;
  headSha: string;
  targetBranch: string;
  targetBranchTipSha: string;
  patchId: string;
  requiredReviewers: string[];
  operatorPrivateKeyPem: string;
  operatorFingerprint: string;
}

/**
 * Build the legacy v2 PR-attestation envelope (the 1.6.0 PR-check-mode
 * flow). Approvals are bare `Approval[]` with no per-approval server
 * signature; operator signs the outer envelope. The 2.x verifier
 * rejects this envelope shape with a schema-too-old actionable error
 * — operators that want the trust property must configure
 * `review_server` and use the v3 path above. v2 stays in the
 * producer for repos using a 1.x-pinned GH Action during the bridge
 * window OR for advisory-only PR check setups that don't run a
 * stamp-server.
 */
function buildV2Envelope(input: V2BuildInput): EnvelopeBuildResult {
  const db = openDb(stampStateDbPath(input.repoRoot));
  let approvals: Approval[];
  try {
    const reviews = latestReviews(db, input.baseSha, input.headSha);
    const byReviewer = new Map(reviews.map((r) => [r.reviewer, r]));

    const missing: string[] = [];
    for (const r of input.requiredReviewers) {
      const rev = byReviewer.get(r);
      if (!rev || rev.verdict !== "approved") missing.push(r);
    }
    if (missing.length > 0) {
      throw new Error(
        `gate CLOSED: missing approved verdicts for: ${missing.join(", ")}. ` +
          `Run \`stamp status --diff ${input.revspec}\` to inspect, then ` +
          `\`stamp review --diff ${input.revspec}\` to review.`,
      );
    }

    approvals = input.requiredReviewers.map((name) => {
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
    input.baseSha,
    ".stamp/config.yml",
    input.repoRoot,
  );
  const baseReviewers = readReviewersFromYaml(baseConfigYaml);

  approvals = approvals.map((a) => {
    const def = baseReviewers[a.reviewer];
    if (!def) {
      throw new Error(
        `reviewer "${a.reviewer}" approved the diff but is not defined in ` +
          `.stamp/config.yml at base ${input.baseSha.slice(0, 8)}. This ` +
          `shouldn't happen — runReview reads from the same base. File a bug ` +
          `at https://github.com/OpenThinkAi/stamp-cli/issues.`,
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

  const payload: PrAttestationPayload = {
    schema_version: LEGACY_CLIENT_PR_ATTESTATION_SCHEMA_VERSION,
    patch_id: input.patchId,
    base_sha: input.baseSha,
    head_sha: input.headSha,
    target_branch: input.targetBranch,
    target_branch_tip_sha: input.targetBranchTipSha,
    approvals,
    checks: [], // Phase-1 deliberate omission — see file-level comment.
    signer_key_id: input.operatorFingerprint,
  };
  const signature = signBytes(
    input.operatorPrivateKeyPem,
    serializePayload(payload),
  );

  return {
    payload,
    signature,
    reviewerNames: approvals.map((a) => a.reviewer),
  };
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
