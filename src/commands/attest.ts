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
import { parse as parseYaml } from "yaml";
import { type Approval } from "../lib/attestation.js";
import {
  canonicalSerializeApproval,
  type ApprovalEntryV4,
  type ApprovalV4,
  type AttestationPayloadV4,
  type TrustAnchorSignatureV4,
} from "../lib/attestationV4.js";
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
  snapshotSha256,
} from "../lib/trustedKeysManifest.js";
import {
  bootstrapAdminSigningBytes,
  validateShape4ActivationDiff,
  type MigrationBootstrapMarker,
} from "../lib/migrationBootstrap.js";
import { collectTrustAnchorSignatures } from "../lib/trustAnchorCollection.js";
import { parsePathRules, pathMatchesAny, type PathRule } from "../lib/v4Trust.js";

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
  /**
   * AGT-398: when true, produce a Shape 4 migration-bootstrap envelope
   * (empty `server_signatures`, bootstrap marker in the operator-signed
   * payload, admin-capability counter-signature in
   * `trust_anchor_signatures`). The flag is only valid on a narrow
   * Shape-4-activation diff (adding `review_server:` to a branch rule
   * + adding `[server]`+`role_source:server` trust-anchor entries +
   * adding the corresponding `*.pub` files). Refused on any other diff.
   *
   * See `src/lib/migrationBootstrap.ts` for the rationale and the
   * verifier acceptance conditions.
   */
  migrateExisting?: boolean;
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

  // Dispatch — bootstrap (AGT-398) vs. v3 (server-attested) vs. v2
  // (legacy / operator-only).
  //
  // `--migrate-existing` short-circuits the normal dispatch: the
  // Shape 4 migration commit can't have server signatures (review at
  // base_sha runs locally because base doesn't yet have `review_server`).
  // The bootstrap envelope captures the operator's intent + an
  // admin-capability counter-signature to compensate. See
  // `src/lib/migrationBootstrap.ts` for the trust model.
  //
  // Same trigger as `stamp merge`'s v4/v3 dispatch otherwise: the
  // branch rule's `review_server` field is the operator's declared
  // intent to use server-attested reviews. When set, we MUST fold real
  // server-signed approvals into a v3 PR-attestation envelope;
  // missing/stale server signatures fail loudly rather than silently
  // degrading to v2 (which the 2.x verifier rejects).
  //
  // When `review_server` is absent, this is the 1.6.0 PR-check-mode
  // flow: produce a v2 envelope with bare `Approval[]`, operator-signs-
  // outer-only. The 2.x verifier rejects v2 with a schema-too-old
  // actionable error pointing operators at the `review_server`-driven
  // path; the v2 path remains for repos pinning the GH Action to a
  // 1.x stamp-version during the bridge window. AGT-355 ships the
  // producer side so post-2.0.1 the bridge window is no longer needed.
  const result = opts.migrateExisting
    ? buildBootstrapEnvelope({
        repoRoot,
        revspec,
        baseSha: resolved.base_sha,
        headSha: resolved.head_sha,
        diff: resolved.diff,
        targetBranch: opts.into,
        targetBranchTipSha: target_branch_tip_sha,
        patchId: patch_id,
        operatorPrivateKeyPem: keypair.privateKeyPem,
        operatorPublicKeyPem: keypair.publicKeyPem,
        operatorFingerprint: keypair.fingerprint,
      })
    : rule.review_server
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
  console.log(`  approvals:  ${result.reviewerNames.length > 0 ? result.reviewerNames.join(", ") : "(none — bootstrap envelope)"}`);
  const schemaLabel = result.payload.migration_bootstrap
    ? " (Shape 4 migration bootstrap)"
    : result.payload.schema_version === PR_ATTESTATION_SCHEMA_VERSION
      ? " (server-attested)"
      : " (legacy)";
  console.log(`  schema:     v${result.payload.schema_version}${schemaLabel}`);
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

  // AGT-370: operator-side manifest snapshot binding. The server no
  // longer reads the manifest; the operator (who already has the repo
  // checked out) computes this from the manifest at base_sha and the
  // verifier checks it once against snapshotSha256() of the manifest
  // it reads at the same ref. Computed BEFORE the trust-anchor
  // collection so admin sigs and the operator's outer sig commit to
  // the same value through the shared `trustAnchorSigningBytes` builder.
  const manifestSnapshot = snapshotSha256(manifest);

  // Trust-anchor signatures (AGT-337 / WS1). Collected from
  // `refs/notes/stamp-trust-anchor-sigs` via the shared
  // `collectTrustAnchorSignatures` helper — the same call site
  // `stamp merge` uses, so PR-mode and commit-trailer mode agree
  // byte-for-byte on the signing target. For non-`.stamp/**` diffs
  // (the overwhelmingly common case) this is correctly empty and the
  // verifier's `verifyV4StampPathsGuard` no-ops. When the diff
  // touches a path_rules glob, the helper throws an actionable
  // "needs N admin signature(s)" error pointing at `stamp admin sign
  // --pending <head>` for the recovery path.
  // PR-mode discards matchedPathRules — there's no merge banner in attest.
  const { signatures: trustAnchorSignatures } = collectTrustAnchorSignatures({
    repoRoot: input.repoRoot,
    baseSha: input.baseSha,
    headSha: input.headSha,
    targetBranch: input.targetBranch,
    diffSha256,
    manifestSnapshotSha256: manifestSnapshot,
    approvals: entries,
    checks: [], // PR-mode is checks-less by design — see file-level comment.
    operatorFingerprint: input.operatorFingerprint,
    manifest,
    pubkeyByFingerprint,
    errorContext: { command: "stamp attest" },
    // PR-mode envelope's payload carries schema_version=3; the verifier
    // reconstructs admin signing bytes from that wire value. Without
    // matching it here the signing target diverges between producer
    // and verifier. See trustAnchorPayload.ts on the schemaVersion field.
    signingSchemaVersion: PR_ATTESTATION_SCHEMA_VERSION,
  });

  const payload: PrAttestationPayload = {
    schema_version: PR_ATTESTATION_SCHEMA_VERSION,
    patch_id: input.patchId,
    base_sha: input.baseSha,
    head_sha: input.headSha,
    target_branch: input.targetBranch,
    target_branch_tip_sha: input.targetBranchTipSha,
    diff_sha256: diffSha256,
    manifest_snapshot_sha256: manifestSnapshot,
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
      const mcpAtInit = parseMcpServersAtInitAttest(rev.mcp_servers_at_init);
      return {
        reviewer: rev.reviewer,
        verdict: rev.verdict,
        review_sha: hashHex(rev.issues ?? ""),
        ...(toolCalls.length > 0 ? { tool_calls: toolCalls } : {}),
        ...(mcpAtInit.length > 0 ? { mcp_servers_at_init: mcpAtInit } : {}),
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
    if (def.prompt === undefined) {
      // v2 envelopes are the LEGACY PR-check-mode path (no review_server).
      // A reviewer with no `prompt:` is a Shape 4 entry that should be
      // paired with `review_server:` on the branch rule — in which case
      // `buildV3Envelope` would have run instead. Reaching here means
      // the operator configured Shape 4 reviewers but no review_server.
      throw new Error(
        `reviewer "${a.reviewer}": no \`prompt:\` configured and no \`review_server:\` on branch rule — ` +
          `set \`reviewers.${a.reviewer}.prompt\` in .stamp/config.yml or configure a \`review_server:\` for server-attested PR mode.`,
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

interface BootstrapBuildInput {
  repoRoot: string;
  revspec: string;
  baseSha: string;
  headSha: string;
  diff: string;
  targetBranch: string;
  targetBranchTipSha: string;
  patchId: string;
  operatorPrivateKeyPem: string;
  operatorPublicKeyPem: string;
  operatorFingerprint: string;
}

/**
 * AGT-398: build a Shape 4 migration-bootstrap envelope.
 *
 * Constraints enforced at attest time (re-validated at verify time):
 *
 *   1. The diff matches the Shape 4 activation whitelist (per
 *      `validateShape4ActivationDiff`). Anything outside the whitelist
 *      — file outside `.stamp/`, modified-not-added trust-anchor entry,
 *      branch-rule change other than `review_server:` addition — fails
 *      with an actionable error.
 *
 *   2. The WORKING TREE config has `path_rules` covering every touched
 *      path with `bypass_review_cycle: true`. Without this gate, the
 *      bootstrap path would let a Shape 4 migration sneak through a
 *      reviewer cycle that hasn't actually run.
 *
 *   3. The operator's local stamp key carries `admin` capability per
 *      the WORKING TREE manifest. The operator's signature over the
 *      bootstrap signing-bytes lands in `trust_anchor_signatures` —
 *      same machinery the existing path_rules admin-sig flow uses.
 *
 *   4. The working-tree `path_rules`' `minimum_signatures` for the
 *      matched path-rule must be 1 (this bootstrap path collects a
 *      single self-admin signature; multi-admin collection for an
 *      envelope is outside the scope of this surface — operators with
 *      `minimum_signatures > 1` should temporarily relax that to 1 for
 *      the migration PR or use the standard admin-sign flow against
 *      the eventual landed commit).
 *
 * The marker is part of the operator-signed payload bytes via
 * `serializePayload(payload)`, so the operator's outer signature
 * commits to "this is a bootstrap envelope".
 */
function buildBootstrapEnvelope(
  input: BootstrapBuildInput,
): EnvelopeBuildResult {
  // (1) — diff whitelist.
  const validation = validateShape4ActivationDiff({
    repoRoot: input.repoRoot,
    baseSha: input.baseSha,
    headSha: input.headSha,
  });
  if (!validation.ok) {
    throw new Error(
      `--migrate-existing refused: ${validation.reason}\n\n` +
        `The bootstrap flag accepts ONLY a narrow Shape 4 activation diff: adding ` +
        `\`review_server:\` to a branch rule in .stamp/config.yml, adding new ` +
        `[server]+role_source:server entries to .stamp/trusted-keys/manifest.yml, ` +
        `and adding the corresponding new .pub files. Land any unrelated changes ` +
        `through the normal \`stamp attest\` flow AFTER the bootstrap PR merges.`,
    );
  }
  const activatedPaths = validation.activatedPaths;

  // (2) — base path_rules coverage. We deliberately read BASE here
  // (not the working tree) for two reasons:
  //   - the whitelist (validateShape4ActivationDiff) refuses any change
  //     to path_rules, so working-tree path_rules ≡ base path_rules by
  //     construction;
  //   - reading base aligns the attest-time check with the verifier-time
  //     check (which MUST read base — see `verifyBootstrapEnvelope`
  //     and the AC: "path_rules at BASE SHA's .stamp/config.yml").
  //     Single source of truth keeps attest-side and verifier-side
  //     from drifting on this check.
  const baseConfigYaml = readAtBaseSha(
    input.repoRoot,
    input.baseSha,
    ".stamp/config.yml",
  );
  if (baseConfigYaml === null) {
    throw new Error(
      `--migrate-existing refused: .stamp/config.yml is missing at base ` +
        `${input.baseSha.slice(0, 8)}. Bootstrap requires the config file in the ` +
        `merge-base tree (the activation diff modifies it).`,
    );
  }
  const baseRules = extractPathRulesFromYaml(baseConfigYaml);
  if (baseRules.length === 0) {
    throw new Error(
      `--migrate-existing refused: no \`path_rules\` configured at base ` +
        `${input.baseSha.slice(0, 8)}. The bootstrap path needs a path_rules entry ` +
        `covering the activated paths with \`bypass_review_cycle: true\` so the ` +
        `verifier knows the reviewer cycle is intentionally skipped for this PR. ` +
        `Add a \`path_rules\` entry for \`.stamp/**\` in a separate prior PR ` +
        `before bootstrapping.`,
    );
  }
  const matchedRule = matchAnyCoveringRule(activatedPaths, baseRules);
  if (!matchedRule) {
    throw new Error(
      `--migrate-existing refused: \`path_rules\` at base ${input.baseSha.slice(0, 8)} ` +
        `does not cover every activated path. Activated: ${activatedPaths.join(", ")}. ` +
        `Configured patterns: ${baseRules.map((r) => `"${r.pattern}"`).join(", ")}. ` +
        `Add or widen a path_rules entry that matches these paths (in a separate ` +
        `prior PR — the bootstrap diff cannot modify path_rules).`,
    );
  }
  if (!matchedRule.bypass_review_cycle) {
    throw new Error(
      `--migrate-existing refused: matched path_rule "${matchedRule.pattern}" at base ` +
        `has \`bypass_review_cycle: false\` — bootstrap requires the rule to ` +
        `\`bypass_review_cycle: true\` (otherwise the reviewer cycle is still ` +
        `nominally required and the bootstrap envelope is structurally invalid).`,
    );
  }
  if (matchedRule.minimum_signatures > 1) {
    throw new Error(
      `--migrate-existing refused: matched path_rule "${matchedRule.pattern}" at base ` +
        `requires \`minimum_signatures: ${matchedRule.minimum_signatures}\` admin signatures, ` +
        `but the bootstrap path only collects a single operator-self admin signature today. ` +
        `Options: (a) temporarily lower the rule to \`minimum_signatures: 1\` in a ` +
        `prior PR; (b) for the migration commit only, use the standard \`stamp admin sign\` ` +
        `flow against the eventual landed commit.`,
    );
  }

  // (3) — operator must hold admin capability per the WORKING TREE
  // manifest. (Base may not yet have the right entry — that's the
  // point of bootstrap. We check working tree at attest time, base at
  // verify time per the verifier's lenient-revocation policy.)
  const workingTreeManifestYaml = readWorkingTreeManifestYaml(input.repoRoot);
  if (workingTreeManifestYaml === null) {
    throw new Error(
      `--migrate-existing refused: .stamp/trusted-keys/manifest.yml is missing from ` +
        `the working tree. Bootstrap requires the working-tree manifest to bind the ` +
        `operator's local stamp key to the \`admin\` capability.`,
    );
  }
  const workingTreeManifest = parseManifest(workingTreeManifestYaml);
  if (!workingTreeManifest) {
    throw new Error(
      `--migrate-existing refused: .stamp/trusted-keys/manifest.yml in the working tree ` +
        `failed to parse (bad YAML, duplicate fingerprint, unknown capability, etc.).`,
    );
  }
  const operatorCaps = resolveCapability(workingTreeManifest, input.operatorFingerprint);
  if (operatorCaps === null) {
    throw new Error(
      `--migrate-existing refused: your local stamp key (${input.operatorFingerprint}) ` +
        `is not listed in the working-tree .stamp/trusted-keys/manifest.yml. ` +
        `Add your key with \`capabilities: [admin]\` (in a separate prior PR) before ` +
        `bootstrapping the Shape 4 migration.`,
    );
  }
  if (!operatorCaps.includes("admin")) {
    throw new Error(
      `--migrate-existing refused: your local stamp key (${input.operatorFingerprint}) ` +
        `has capabilities [${operatorCaps.join(", ")}] in the working-tree manifest — needs ` +
        `\`admin\` for bootstrap. Either grant your key admin capability (in a separate ` +
        `prior PR) or have a different admin run \`stamp attest --migrate-existing\`.`,
    );
  }

  // ── Construct the v3 envelope ─────────────────────────────────────
  // Base-sha manifest snapshot — the operator signs over this just like
  // a normal v3 envelope, so the verifier's
  // `verifyV4ManifestSnapshot` phase still holds. The marker is added
  // BELOW so the operator's outer signature covers it.
  const baseManifestYaml = readAtBaseSha(
    input.repoRoot,
    input.baseSha,
    ".stamp/trusted-keys/manifest.yml",
  );
  if (baseManifestYaml === null) {
    throw new Error(
      `--migrate-existing refused: .stamp/trusted-keys/manifest.yml is missing at ` +
        `base ${input.baseSha.slice(0, 8)}. Bootstrap requires the manifest in the ` +
        `merge-base tree (the operator's outer signature commits to its snapshot ` +
        `hash). Run \`stamp init --migrate-to-server-attested\` first to seed the ` +
        `manifest.`,
    );
  }
  const baseManifest = parseManifest(baseManifestYaml);
  if (!baseManifest) {
    throw new Error(
      `--migrate-existing refused: .stamp/trusted-keys/manifest.yml at base ` +
        `${input.baseSha.slice(0, 8)} failed to parse.`,
    );
  }
  const manifestSnapshot = snapshotSha256(baseManifest);

  // Diff sha256 — same byte computation `verifyV4DiffHash` performs.
  const diffBytes = Buffer.from(input.diff, "utf8");
  const diffSha256 = createHash("sha256").update(diffBytes).digest("hex");

  const marker: MigrationBootstrapMarker = {
    activated_paths: activatedPaths,
  };

  // Build the v4-view payload the admin's signing bytes will be
  // computed over (we keep the v3 PR-payload type for storage but
  // construct an equivalent v4 view for canonical serialization).
  const payloadV4Shape: AttestationPayloadV4 = {
    schema_version: PR_ATTESTATION_SCHEMA_VERSION,
    base_sha: input.baseSha,
    head_sha: input.headSha,
    target_branch: input.targetBranch,
    diff_sha256: diffSha256,
    manifest_snapshot_sha256: manifestSnapshot,
    approvals: [], // bootstrap: no server signatures
    checks: [],
    trust_anchor_signatures: [],
    signer_key_id: input.operatorFingerprint,
  };

  // Admin-capability counter-signature over the canonical
  // bootstrap-signing-bytes (payload-with-marker, trust_anchor_signatures: []).
  // Self-verify before persisting so a key/serialization bug surfaces
  // here rather than at verify time.
  const adminSigningBytes = bootstrapAdminSigningBytes({
    payloadV4: payloadV4Shape,
    marker,
  });
  const adminSignatureB64 = signBytes(input.operatorPrivateKeyPem, adminSigningBytes);
  const selfOk = verifyBytes(
    input.operatorPublicKeyPem,
    adminSigningBytes,
    adminSignatureB64,
  );
  if (!selfOk) {
    throw new Error(
      `internal error: just-produced bootstrap admin signature failed self-verification. ` +
        `Refusing to write a bad envelope. File a bug at ` +
        `https://github.com/OpenThinkAi/stamp-cli/issues.`,
    );
  }
  const trustAnchorSignatures: TrustAnchorSignatureV4[] = [
    {
      signer_key_id: input.operatorFingerprint,
      signature: adminSignatureB64,
    },
  ];

  const payload: PrAttestationPayload = {
    schema_version: PR_ATTESTATION_SCHEMA_VERSION,
    patch_id: input.patchId,
    base_sha: input.baseSha,
    head_sha: input.headSha,
    target_branch: input.targetBranch,
    target_branch_tip_sha: input.targetBranchTipSha,
    diff_sha256: diffSha256,
    manifest_snapshot_sha256: manifestSnapshot,
    approvals: [],
    checks: [],
    trust_anchor_signatures: trustAnchorSignatures,
    signer_key_id: input.operatorFingerprint,
    migration_bootstrap: marker,
  };

  // Operator-signs-outer-envelope: covers the bootstrap marker via
  // `serializePayload(payload)` (plain JSON.stringify includes the
  // marker field). The verifier re-derives the same bytes from the
  // parsed envelope.
  const signature = signBytes(input.operatorPrivateKeyPem, serializePayload(payload));

  return {
    payload,
    signature,
    reviewerNames: [],
  };
}

/** Read the working-tree `.stamp/trusted-keys/manifest.yml`. */
function readWorkingTreeManifestYaml(repoRoot: string): string | null {
  try {
    return showAtRef("HEAD", ".stamp/trusted-keys/manifest.yml", repoRoot);
  } catch {
    return null;
  }
}

/** Read a file from a specific ref (base sha). Returns null on absence. */
function readAtBaseSha(
  repoRoot: string,
  baseSha: string,
  relPath: string,
): string | null {
  try {
    return showAtRef(baseSha, relPath, repoRoot);
  } catch {
    return null;
  }
}

/** Parse `path_rules` out of a YAML blob. */
function extractPathRulesFromYaml(yamlText: string): PathRule[] {
  let parsed: unknown;
  try {
    parsed = parseYaml(yamlText);
  } catch {
    return [];
  }
  if (!parsed || typeof parsed !== "object") return [];
  const { rules } = parsePathRules((parsed as { path_rules?: unknown }).path_rules);
  return rules;
}

/** Return the first `path_rule` that covers every activated path, or
 *  null if no single rule covers all of them. (We intentionally require
 *  ONE rule to cover ALL paths — if the operator has multiple rules,
 *  the bootstrap path picks the most-permissive that covers everything,
 *  to keep the verifier check straightforward.) */
function matchAnyCoveringRule(
  activatedPaths: string[],
  rules: PathRule[],
): PathRule | null {
  for (const rule of rules) {
    const allMatch = activatedPaths.every((p) => pathMatchesAny(p, [rule.pattern]));
    if (allMatch) return rule;
  }
  return null;
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

/**
 * Parse the JSON-encoded McpServerAtInit[] from the DB column. Returns an
 * empty array for null/invalid inputs (pre-AGT-246 rows or reviewers with
 * no MCP servers). Named differently from merge.ts to avoid naming collisions
 * when the two files are read together in tests.
 */
function parseMcpServersAtInitAttest(raw: string | null): McpServerAtInit[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed as McpServerAtInit[];
    return [];
  } catch {
    return [];
  }
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
