/**
 * `stamp verify-pr <head> --base <base> --into <branch>`
 *
 * Consumer side of PR-check mode. Verifies that the diff `base..head` has
 * a valid stamp attestation under `refs/stamp/attestations/<patch-id>`.
 * Wraps the same primitives that `stamp/verify-attestation@v1` (the GH
 * Action) calls into, so operators can run the exact verification path
 * locally as `stamp/verify-attestation` would on a PR.
 *
 * AGT-338: the verifier dispatches on `payload.schema_version`:
 *   - v3+ → run the v4-trust pipeline (the same `verifyV4*` phases
 *     `pre-receive.ts` runs against a commit-trailer envelope). Same
 *     code path, same crypto contract, no logic divergence — the
 *     trust-level checks are identical across server-gated and PR-mode.
 *   - v2 (or lower) → reject with an actionable "schema too old"
 *     error. v2 envelopes lack the per-approval server signature,
 *     top-level `diff_sha256` binding, and `trust_anchor_signatures`
 *     surface the v4 trust model requires. Re-attestation under a 2.x
 *     stamp release is the only forward path.
 *
 * Verification steps (in this order — signature first so payload
 * fields are only acted on after the crypto says "trust this"):
 *   1. Resolve <head> + <base> to SHAs.
 *   2. Compute patch-id of base..head.
 *   3. Read refs/stamp/attestations/<patch-id> — fail if missing.
 *   4. Dispatch on schema_version:
 *        v3+ → assemble PhaseInputV4 (mirroring tests/v4Roundtrip.ts's
 *              buildPhaseInput), then run every v4-trust phase except
 *              verifyV4MergeStructure (no merge commit exists yet in
 *              PR-mode — the integrity binding instead comes from the
 *              patch-id ref-name + diff_sha256 + outer signature).
 *        v2  → reject (see above).
 *   5. After the v4 pipeline passes, run the PR-mode-only checks:
 *      target-branch match against --into and strict_base tip check.
 *
 * Exits 0 on success, 1 on any verification failure. Prints a
 * structured summary either way; a CI consumer can fail the check
 * purely on exit code without parsing prose.
 *
 * AGT-338 BREAKING CHANGES (deliberate; flagged per product review):
 *   - `MIN_ACCEPTED_PR_ATTESTATION_VERSION` raised from 1 to 3. All v1 and
 *     v2 envelopes are rejected with the schema-too-old actionable error.
 *     Matches `pre-receive.ts`'s same-direction bump.
 *   - Success-output format dropped the `trusted-key:` row (single-key
 *     filename was load-bearing under v1/v2; v4-trust resolves through
 *     `.stamp/trusted-keys/manifest.yml` and there's no single filename
 *     to print). The `signer:` row carries the fingerprint, which is the
 *     architecturally correct identifier under v4-trust. Scripts grepping
 *     for `trusted-key:` will not match; switch to `signer:` for the
 *     fingerprint-keyed lookup.
 *   - `readAttestationRef` now returns null for envelopes below
 *     `MIN_ACCEPTED_PR_ATTESTATION_VERSION` (in addition to its existing
 *     "ref missing" null). Callers that need to distinguish "ref absent"
 *     from "ref present but unsupported schema" should use
 *     `readAttestationBlobBytes` + `peekSchemaVersion`, which is the
 *     pattern this verifier follows internally.
 */

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { findBranchRule, parseConfigFromYaml } from "../lib/config.js";
import { resolveDiff, runGit, showAtRef } from "../lib/git.js";
import { findRepoRoot } from "../lib/paths.js";
import { patchIdForSpan } from "../lib/patchId.js";
import {
  MIN_ACCEPTED_PR_ATTESTATION_VERSION,
  parseEnvelope,
  peekSchemaVersion,
  readAttestationBlobBytes,
  serializePayload,
  type PrAttestationEnvelope,
} from "../lib/prAttestation.js";
import type {
  ApprovalEntryV4,
  AttestationPayloadV4,
  CheckAttestationV4,
  TrustAnchorSignatureV4,
} from "../lib/attestationV4.js";
import { buildPubkeyMap } from "../lib/sshReviewClient.js";
import {
  parseManifest,
  resolveCapability,
  snapshotSha256,
  type TrustedKeysManifest,
} from "../lib/trustedKeysManifest.js";
import { verifyBytes } from "../lib/signing.js";
import {
  bootstrapAdminSigningBytes,
  validateShape4ActivationDiff,
} from "../lib/migrationBootstrap.js";
// PR-mode imports the shared v4-trust pipeline from src/lib/v4Trust.ts —
// the same module pre-receive.ts uses. Both verifiers run the SAME
// phase functions against PhaseInputV4 instances. AGT-338 standards
// review round 2 lifted these out of src/hooks/pre-receive.ts so
// src/commands/ no longer imports from src/hooks/ (proper layering:
// commands → lib, hooks → lib, never commands → hooks).
import {
  PR_MODE_PHASES_V4,
  parsePathRules,
  pathMatchesAny,
  type PhaseInputV4,
  type PathRule,
} from "../lib/v4Trust.js";
import { A, colorEnabled, mdCell, paint, table } from "../lib/renderCheck.js";

export interface VerifyPrOptions {
  /** Head ref (commit SHA, branch name, or any rev-parse-able value). */
  head: string;
  /** Base ref. Same shape as head. */
  base: string;
  /** Branch the PR will merge into. The attestation's recorded
   *  `target_branch` must equal this — guards against an attestation
   *  signed for a relaxed branch rule being verified against a stricter
   *  branch's rules. Named `into` to match `stamp merge --into` and
   *  `stamp attest --into`. */
  into: string;
  /** Repo root override; defaults to cwd. */
  repoPath?: string;
}

export function runVerifyPr(opts: VerifyPrOptions): void {
  const repoRoot = opts.repoPath ?? findRepoRoot();

  // resolveDiff insists on a "<base>..<head>" form, which we reconstruct.
  const resolved = resolveDiff(`${opts.base}..${opts.head}`, repoRoot);
  const patch_id = patchIdForSpan(resolved.base_sha, resolved.head_sha, repoRoot);

  // Read the raw blob first so we can distinguish "ref missing" from
  // "ref present but unsupported schema_version" — the v2-rejection
  // error needs to name the version found, which means peeking before
  // parsing through the strict version-floor gate.
  const blobBytes = readAttestationBlobBytes(patch_id, repoRoot);
  if (!blobBytes) {
    // Bridge-window-aware remediation. v3 envelopes are produced ONLY
    // by stamp-server (AGT-355, not landed yet); `stamp attest` in
    // 1.x AND 2.x emits v2, which this verifier rejects. Pointing
    // operators at `stamp attest --into <branch>` (the natural
    // suggestion) sends them on a dead-end loop — they'd produce a
    // v2 envelope and hit the schema-too-old error here. So the
    // error names both ends of the bridge: the "happy path with a
    // 2.x server" answer for after AGT-355 ships, and the
    // "pin to a 1.x verifier via stamp-version" workaround for repos
    // that need to keep operating during the bridge window. Per
    // AGT-338 product reviewer round 1.
    fail(
      `no attestation found at refs/stamp/attestations/${patch_id} ` +
        `(diff ${resolved.base_sha.slice(0, 8)}..${resolved.head_sha.slice(0, 8)}). ` +
        `Production path (post-AGT-355, lands in 2.0.1): the stamp-server signs and ` +
        `publishes the attestation ref on every reviewed PR. ` +
        `Bridge-window workaround (until AGT-355 ships): pin the GitHub Action to a ` +
        `1.x \`stamp-version\` input — 1.x \`stamp attest\` writes a v2 envelope and ` +
        `the 1.x verifier accepts it. See docs/migration-1.x-to-2.x.md for the ` +
        `full bridge-window procedure.`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }

  // Peek schema_version BEFORE running through parseEnvelope's strict
  // version-floor gate. This lets us emit a specific "schema too old"
  // error for v2 envelopes instead of the generic "ref unreadable"
  // prose. Match `pre-receive.ts`'s `MIN_ACCEPTED_PAYLOAD_VERSION = 3`
  // policy — both verifiers reject pre-v3 envelopes with the same
  // actionable upgrade message.
  const claimedVersion = peekSchemaVersion(blobBytes);
  if (claimedVersion === null) {
    fail(
      `attestation at refs/stamp/attestations/${patch_id} is not a valid ` +
        `PR-attestation envelope (malformed JSON, oversized blob, or missing ` +
        `top-level payload/signature fields). Re-run \`stamp attest --into ${opts.into}\` ` +
        `to regenerate.`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }
  if (claimedVersion < MIN_ACCEPTED_PR_ATTESTATION_VERSION) {
    // Bridge-window-aware remediation — same shape as the missing-
    // blob path above. Operators landing here have an attestation
    // ref present but its `schema_version` is below the floor
    // (typically v2 from a 1.x `stamp attest`). The naive "upgrade
    // to 2.x and re-attest" advice is a dead-end loop: 2.x
    // `stamp attest` is INTENTIONALLY frozen at v2 (only stamp-
    // server can fabricate v3 envelopes — that's AGT-355, not yet
    // shipped), so following that advice produces the same v2
    // envelope and lands on the same rejection. Name both ends of
    // the bridge so the operator's next step actually clears the
    // error. Per AGT-338 product reviewer round 2.
    fail(
      `attestation schema_version ${claimedVersion} is no longer accepted ` +
        `(minimum supported is ${MIN_ACCEPTED_PR_ATTESTATION_VERSION}). ` +
        `v${claimedVersion} envelopes pre-date the v4 trust model: they lack ` +
        `per-approval server signatures, top-level diff_sha256 binding, and ` +
        `trust-anchor counter-signature support. ` +
        `Production path (post-AGT-355, lands in 2.0.1): stamp-server signs and ` +
        `publishes v${MIN_ACCEPTED_PR_ATTESTATION_VERSION}+ attestations on every reviewed PR; no client-side ` +
        `re-attestation needed. ` +
        `Bridge-window workaround (until AGT-355 ships): pin the GitHub Action ` +
        `to a 1.x \`stamp-version\` input — 1.x \`stamp attest\` writes the ` +
        `v${claimedVersion} envelope you have here and the 1.x verifier accepts it. ` +
        `See docs/migration-1.x-to-2.x.md for the full bridge-window procedure.`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }

  const envelope = parseEnvelope(blobBytes);
  if (!envelope) {
    // claimedVersion >= MIN here, so a null parse means the v3 shape
    // checks (missing diff_sha256, missing trust_anchor_signatures,
    // missing target_branch_tip_sha, malformed approvals/checks
    // arrays) failed. Surface a specific message rather than the
    // generic "no attestation" so operators can find the bad field.
    fail(
      `attestation at refs/stamp/attestations/${patch_id} claims ` +
        `schema_version ${claimedVersion} but is missing or malformed required ` +
        `fields (diff_sha256, trust_anchor_signatures, target_branch_tip_sha, ` +
        `or per-approval shape). Re-run \`stamp attest --into ${opts.into}\` ` +
        `with a current stamp-cli build.`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }

  // Dispatch by schema_version + bootstrap marker. v3+ envelopes
  // normally run the v4-trust pipeline; envelopes carrying the
  // `migration_bootstrap` marker (AGT-398) take the bootstrap-acceptance
  // path instead, which checks the narrow whitelist + admin sig + base
  // path_rules in lieu of server signatures.
  if (envelope.payload.schema_version >= MIN_ACCEPTED_PR_ATTESTATION_VERSION) {
    if (envelope.payload.migration_bootstrap !== undefined) {
      verifyBootstrapEnvelope(envelope, opts, resolved, patch_id, repoRoot);
      return;
    }
    verifyV3Envelope(envelope, opts, resolved, patch_id, repoRoot);
    return;
  }

  // Unreachable today (version-floor gate above), but keep the
  // explicit-reject branch for any future skew between
  // `peekSchemaVersion` and the dispatch table.
  fail(
    `attestation schema_version ${envelope.payload.schema_version} is below ` +
      `the supported floor (${MIN_ACCEPTED_PR_ATTESTATION_VERSION}). ` +
      `Re-attest with a current stamp-cli build.`,
    patch_id,
    resolved.base_sha,
    resolved.head_sha,
  );
}

/**
 * Run the v4-trust pipeline against a v3+ PR-attestation envelope.
 *
 * Mirrors `verifyCommitV4` in `pre-receive.ts` (the dispatcher for
 * server-gated mode), but adapted to PR-mode:
 *   - No merge commit exists yet — the merge runs on GitHub after this
 *     verifier passes. So we skip `verifyV4MergeStructure` (which
 *     requires a 2-parent merge commit + merge-base check against the
 *     commit's parents). PR-mode's integrity binding comes instead from
 *     (a) the patch-id ref-name (any tampering with base/head changes
 *     the patch-id, which changes the ref the verifier looks up), (b)
 *     `verifyV4DiffHash` re-hashing the actual `base...head` diff, and
 *     (c) the operator's outer signature over the full payload.
 *   - `verifyV4TargetBranch` runs with `branch = opts.into`, the
 *     PR-mode caller-supplied target.
 *   - PR-mode-only checks (strict_base via `target_branch_tip_sha`) run
 *     AFTER the v4 pipeline so payload fields are already crypto-trusted.
 *
 * Construct PhaseInputV4 by reading from `payload.base_sha` exactly as
 * `tests/v4Roundtrip.test.ts`'s `buildPhaseInput` does — the Action
 * runs in a CI checkout where `git show <base_sha>:...` works the same
 * as in tests, mirroring `pre-receive.ts`'s pattern of sourcing all
 * trust artifacts from the merge-base tree.
 */
function verifyV3Envelope(
  envelope: PrAttestationEnvelope,
  opts: VerifyPrOptions,
  resolved: { base_sha: string; head_sha: string },
  patch_id: string,
  repoRoot: string,
): void {
  // Build a v4 payload view from the PR envelope. The fields we need
  // (base_sha, head_sha, target_branch, diff_sha256, approvals, checks,
  // trust_anchor_signatures, signer_key_id, schema_version) are all
  // present on v3 PR-attestation payloads — they're the embedded v4
  // fields per AGT-338's settled decision. Cast the approvals + checks
  // arrays to their v4 element type now that the version-floor gate
  // has confirmed schema_version >= 3.
  const payload: AttestationPayloadV4 = {
    schema_version: envelope.payload.schema_version,
    base_sha: envelope.payload.base_sha,
    head_sha: envelope.payload.head_sha,
    target_branch: envelope.payload.target_branch,
    diff_sha256: envelope.payload.diff_sha256!,
    manifest_snapshot_sha256: envelope.payload.manifest_snapshot_sha256!,
    approvals: envelope.payload.approvals as ApprovalEntryV4[],
    checks: envelope.payload.checks as CheckAttestationV4[],
    trust_anchor_signatures: envelope.payload
      .trust_anchor_signatures as TrustAnchorSignatureV4[],
    signer_key_id: envelope.payload.signer_key_id,
  };

  // Source the trust artifacts at payload.base_sha. Pre-receive does
  // the same in its v4 pipeline — the manifest, the pubkey map, and
  // the path_rules all come from the merge-base tree, never from HEAD
  // or any field the operator could backstuff. Mirrors
  // tests/v4Roundtrip.test.ts:buildPhaseInput exactly so the two test
  // surfaces and the production verifier run identical wiring.
  const manifest = loadManifestAtBase(payload.base_sha, repoRoot);
  if (!manifest) {
    fail(
      `.stamp/trusted-keys/manifest.yml is missing or malformed at base ` +
        `${payload.base_sha.slice(0, 8)}. v3+ PR-attestations require the ` +
        `manifest in the merge-base tree (it's the trust root for both the ` +
        `operator's outer signature and each reviewer's server signature). ` +
        `Run \`stamp init\` against this branch or update the manifest before ` +
        `re-attesting.`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }

  const pubkeyByFingerprint = loadPubkeysAtBase(payload.base_sha, repoRoot);
  const pathRules = loadPathRulesAtBase(payload.base_sha, repoRoot);
  const changedFiles = loadChangedFiles(
    payload.base_sha,
    payload.head_sha,
    repoRoot,
  );

  // Branch rule comes from .stamp/config.yml at base — same source-of-
  // truth as the server-gated verifier. The branch rule's `required`
  // list is what `verifyV4Approvals` enforces.
  let configYaml: string;
  try {
    configYaml = showAtRef(payload.base_sha, ".stamp/config.yml", repoRoot);
  } catch (e) {
    fail(
      `could not read .stamp/config.yml at base ${payload.base_sha.slice(0, 8)}: ` +
        `${(e as Error).message}`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }
  const config = parseConfigFromYaml(configYaml);
  const rule = findBranchRule(config.branches, opts.into);
  if (!rule) {
    fail(
      `no branch rule for "${opts.into}" in .stamp/config.yml at base ` +
        `${payload.base_sha.slice(0, 8)}. Configured branches: ` +
        `${Object.keys(config.branches).join(", ") || "(none)"}.`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }

  // payloadBytes for `verifyV4OuterSignature` is the EXACT bytes the
  // operator signed. The PR envelope uses `serializePayload` (plain
  // JSON.stringify, no canonicalization) — same approach as the v2
  // envelope; the verifier re-derives bytes from the parsed payload
  // because the operator signed the EXACT bytes that landed in the
  // JSON blob. We re-`JSON.stringify` the prAttestation-shape payload
  // here (not the v4 view above) to recover those exact bytes.
  const payloadBytes = Buffer.from(
    JSON.stringify(envelope.payload),
    "utf8",
  );

  const input: PhaseInputV4 = {
    sha: patch_id, // PR-mode: no merge commit; we use the patch-id as the
    //               identity for error-message prefixes. The v4 phases use
    //               this only for diagnostic prose, not for any crypto
    //               check (those are payload.base_sha / payload.head_sha
    //               and the inner approval bodies).
    branch: opts.into,
    rule: { required: rule.required, ...(rule.required_checks ? { required_checks: rule.required_checks } : {}) },
    payload,
    payloadBytes,
    signatureBase64: envelope.signature,
    manifest,
    pubkeyByFingerprint,
    pathRules,
    changedFiles,
  };

  // PR-mode pipeline. Reuses the PR_MODE_PHASES_V4 constant from
  // v4Trust.ts — same pipeline order pre-receive runs, minus
  // `verifyV4MergeStructure` (no merge commit exists yet in PR-mode;
  // patch-id ref + diff_sha256 + outer signature provide the
  // equivalent integrity binding). Sharing the constant means a
  // future reorder of the pipeline lands in one place and applies to
  // both verifiers automatically.
  for (const phase of PR_MODE_PHASES_V4) {
    const result = phase.fn(input);
    if (!result.ok) {
      fail(
        result.reason,
        patch_id,
        resolved.base_sha,
        resolved.head_sha,
      );
    }
  }

  // PR-mode-only checks run AFTER the v4 pipeline so payload fields are
  // crypto-trusted. strict_base catches "main advanced with unrelated
  // commits" — patch-id stays unchanged in that case, so a loose
  // verifier accepts the stale attestation; strict_base via
  // target_branch_tip_sha catches it.
  if (rule.strict_base) {
    if (!envelope.payload.target_branch_tip_sha) {
      // Defense-in-depth: the v3 parse step requires
      // target_branch_tip_sha (it's gated in parseEnvelope), so this
      // is structurally unreachable. Keep the explicit error in case a
      // future schema bump makes the field optional again.
      fail(
        `strict_base check failed: v3 attestation is missing ` +
          `target_branch_tip_sha. Re-attest with a current stamp-cli build.`,
        patch_id,
        resolved.base_sha,
        resolved.head_sha,
      );
    }
    const currentTip = runGit(
      ["rev-parse", `${opts.into}^{commit}`],
      repoRoot,
    ).trim();
    if (envelope.payload.target_branch_tip_sha !== currentTip) {
      fail(
        `strict_base check failed: attestation was signed when ${opts.into} ` +
          `was at ${envelope.payload.target_branch_tip_sha.slice(0, 8)}, but ${opts.into} ` +
          `is now at ${currentTip.slice(0, 8)}. Re-attest with the current tip.`,
        patch_id,
        resolved.base_sha,
        resolved.head_sha,
      );
    }
  }

  printSuccess({
    patch_id,
    base_sha: resolved.base_sha,
    head_sha: resolved.head_sha,
    target_branch: opts.into,
    signer_key_id: payload.signer_key_id,
    approvals: payload.approvals.map((a) => ({
      reviewer: a.approval.reviewer,
      verdict: a.approval.verdict,
    })),
    strict_base: rule.strict_base ?? false,
    schema_version: envelope.payload.schema_version,
  });
}

/**
 * AGT-398: verify a Shape 4 migration-bootstrap envelope.
 *
 * Acceptance requires ALL of:
 *
 *   1. `migration_bootstrap` marker present in the operator-signed
 *      bytes — guaranteed because `serializePayload` includes it and
 *      the operator's outer signature commits to those bytes.
 *      Operator signature verification step below.
 *   2. Diff matches the Shape 4 activation whitelist (re-validated
 *      from base/head trees, NOT trusted from attest-time).
 *   3. `activated_paths` in the marker equals the actual changed files
 *      between base and head (no claim about an empty diff that
 *      smuggles in changes verifier didn't expect).
 *   4. Operator outer signature over the full payload verifies.
 *      Operator must hold `operator` or `admin` capability per the
 *      manifest at base_sha (lenient revocation).
 *   5. Exactly one entry in `trust_anchor_signatures` (multi-admin is
 *      out of scope for the bootstrap flow today — the attest-side
 *      refuses minimum_signatures > 1).
 *   6. The admin signature in `trust_anchor_signatures` verifies
 *      against the bootstrap signing bytes (canonical payload with
 *      marker + trust_anchor_signatures: []).
 *   7. The admin's key holds `admin` capability in the manifest at
 *      base_sha.
 *   8. `path_rules` at base_sha covers every activated path with
 *      `bypass_review_cycle: true`. This is the security boundary:
 *      base must already have committed to bypassing the reviewer
 *      cycle for these paths (typically via a prior Shape 2 migration).
 *   9. `approvals` is empty (a non-empty approvals array is allowed by
 *      the type but rejected here — a bootstrap envelope that also
 *      claims server signatures is structurally invalid and likely a
 *      tampering attempt).
 *
 *  After acceptance, the PR-mode-only `strict_base` check (if
 *  configured on the branch rule) still applies.
 */
function verifyBootstrapEnvelope(
  envelope: PrAttestationEnvelope,
  opts: VerifyPrOptions,
  resolved: { base_sha: string; head_sha: string },
  patch_id: string,
  repoRoot: string,
): void {
  const payload = envelope.payload;
  const marker = payload.migration_bootstrap;
  if (!marker) {
    fail(
      `internal error: bootstrap dispatch with no marker (should be unreachable)`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }

  // (9) — bootstrap envelopes MUST have empty approvals. A non-empty
  // approvals array combined with the bootstrap marker is an inversion
  // of the bootstrap shape; reject explicitly.
  if (payload.approvals.length !== 0) {
    fail(
      `bootstrap envelope has ${payload.approvals.length} approvals — bootstrap envelopes MUST have approvals: []. Non-empty server signatures should go through the normal (non-bootstrap) attest flow.`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }

  // (2) — re-validate the diff whitelist from the merge-base / head
  // trees. We DO NOT trust the attest-side check; the attester could
  // have been tampered with. The validator re-shells out to git show.
  const validation = validateShape4ActivationDiff({
    repoRoot,
    baseSha: payload.base_sha,
    headSha: payload.head_sha,
  });
  if (!validation.ok) {
    fail(
      `bootstrap envelope rejected: diff does not match the Shape 4 activation whitelist — ${validation.reason}`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }

  // (3) — marker's activated_paths must equal the actual changed files.
  const claimed = [...marker.activated_paths].sort();
  const actual = [...validation.activatedPaths].sort();
  if (
    claimed.length !== actual.length ||
    !claimed.every((p, i) => p === actual[i])
  ) {
    fail(
      `bootstrap envelope's migration_bootstrap.activated_paths (${claimed.join(", ")}) does not match the actual changed-files set (${actual.join(", ")}). The marker must declare exactly the paths the bootstrap PR activates.`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }

  // Load the base manifest. Bootstrap requires the manifest in the
  // merge-base tree (the base may already have admin keys + path_rules
  // from a prior migration — that's the scaffolding bootstrap relies on).
  const baseManifest = loadManifestAtBase(payload.base_sha, repoRoot);
  if (!baseManifest) {
    fail(
      `bootstrap envelope rejected: .stamp/trusted-keys/manifest.yml is missing or ` +
        `malformed at base ${payload.base_sha.slice(0, 8)}. Bootstrap requires the ` +
        `manifest in the merge-base tree (it's the trust root for the operator's ` +
        `outer signature and the admin counter-signature).`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }

  // verifyV4ManifestSnapshot equivalent: operator's signature commits
  // to manifest_snapshot_sha256; that must equal the snapshot of the
  // manifest the verifier reads at base_sha.
  if (!payload.manifest_snapshot_sha256) {
    fail(
      `bootstrap envelope is missing manifest_snapshot_sha256 — required for v3+ envelopes`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }
  const computedSnapshot = snapshotSha256(baseManifest);
  if (payload.manifest_snapshot_sha256 !== computedSnapshot) {
    fail(
      `bootstrap envelope manifest_snapshot_sha256 (${payload.manifest_snapshot_sha256.slice(0, 16)}…) does not match the manifest at base ${payload.base_sha.slice(0, 8)} (${computedSnapshot.slice(0, 16)}…)`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }

  // Pubkey resolution off the base tree.
  const pubkeyByFingerprint = loadPubkeysAtBase(payload.base_sha, repoRoot);

  // (4) — operator outer signature. Operator must be in the manifest
  // at base_sha with operator or admin capability.
  const operatorCaps = resolveCapability(baseManifest, payload.signer_key_id);
  if (operatorCaps === null) {
    fail(
      `bootstrap envelope signer ${payload.signer_key_id} is not listed in the manifest at base ${payload.base_sha.slice(0, 8)}`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }
  if (!operatorCaps.includes("operator") && !operatorCaps.includes("admin")) {
    fail(
      `bootstrap envelope signer ${payload.signer_key_id} has capabilities [${operatorCaps.join(", ")}] at base ${payload.base_sha.slice(0, 8)} — needs operator or admin`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }
  const operatorPem = pubkeyByFingerprint.get(payload.signer_key_id);
  if (!operatorPem) {
    fail(
      `bootstrap envelope signer ${payload.signer_key_id} has no matching .pub file in .stamp/trusted-keys/ at base ${payload.base_sha.slice(0, 8)}`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }
  const operatorBytes = serializePayload(payload);
  let operatorSigOk = false;
  try {
    operatorSigOk = verifyBytes(operatorPem, operatorBytes, envelope.signature);
  } catch (err) {
    fail(
      `bootstrap envelope operator-signature verification threw: ${err instanceof Error ? err.message : String(err)}`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }
  if (!operatorSigOk) {
    fail(
      `bootstrap envelope operator signature does not verify against the operator's pubkey ${payload.signer_key_id}`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }

  // (5) + (6) + (7) — admin counter-signature.
  const sigs = payload.trust_anchor_signatures ?? [];
  if (sigs.length !== 1) {
    fail(
      `bootstrap envelope must carry exactly one trust_anchor_signatures entry (got ${sigs.length}) — multi-admin bootstrap collection is not supported by the bootstrap path. Lower path_rules minimum_signatures or use the standard admin-sign flow.`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }
  const adminSig = sigs[0]!;
  const adminCaps = resolveCapability(baseManifest, adminSig.signer_key_id);
  if (adminCaps === null) {
    fail(
      `bootstrap envelope admin signer ${adminSig.signer_key_id} is not listed in the manifest at base ${payload.base_sha.slice(0, 8)}`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }
  if (!adminCaps.includes("admin")) {
    fail(
      `bootstrap envelope admin signer ${adminSig.signer_key_id} has capabilities [${adminCaps.join(", ")}] at base ${payload.base_sha.slice(0, 8)} — needs admin`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }
  const adminPem = pubkeyByFingerprint.get(adminSig.signer_key_id);
  if (!adminPem) {
    fail(
      `bootstrap envelope admin signer ${adminSig.signer_key_id} has no matching .pub file in .stamp/trusted-keys/ at base ${payload.base_sha.slice(0, 8)}`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }

  // Re-build the bootstrap signing bytes from the parsed envelope so a
  // tampered admin sig over different bytes is rejected.
  const v4View: AttestationPayloadV4 = {
    schema_version: payload.schema_version,
    base_sha: payload.base_sha,
    head_sha: payload.head_sha,
    target_branch: payload.target_branch,
    diff_sha256: payload.diff_sha256!,
    manifest_snapshot_sha256: payload.manifest_snapshot_sha256!,
    approvals: [],
    checks: payload.checks as CheckAttestationV4[],
    trust_anchor_signatures: [],
    signer_key_id: payload.signer_key_id,
  };
  const adminBytes = bootstrapAdminSigningBytes({ payloadV4: v4View, marker });
  let adminSigOk = false;
  try {
    adminSigOk = verifyBytes(adminPem, adminBytes, adminSig.signature);
  } catch (err) {
    fail(
      `bootstrap envelope admin-signature verification threw: ${err instanceof Error ? err.message : String(err)}`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }
  if (!adminSigOk) {
    fail(
      `bootstrap envelope admin signature by ${adminSig.signer_key_id} does not verify against the bootstrap signing-bytes (payload-with-marker, trust_anchor_signatures: []).`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }

  // (8) — path_rules at base must cover every activated path with
  // bypass_review_cycle: true. This is the load-bearing condition that
  // compensates for the absent reviewer cycle; if base doesn't already
  // declare these paths as bypass-eligible, the bootstrap envelope is
  // refused.
  const pathRules = loadPathRulesAtBase(payload.base_sha, repoRoot);
  if (pathRules.length === 0) {
    fail(
      `bootstrap envelope rejected: no path_rules configured at base ${payload.base_sha.slice(0, 8)}. The bootstrap path requires path_rules covering the activated paths with bypass_review_cycle: true — typically already in place from a prior Shape 2 migration.`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }
  for (const p of marker.activated_paths) {
    let coveredBy: PathRule | null = null;
    for (const rule of pathRules) {
      if (pathMatchesAny(p, [rule.pattern])) {
        coveredBy = rule;
        break;
      }
    }
    if (!coveredBy) {
      fail(
        `bootstrap envelope rejected: path_rules at base ${payload.base_sha.slice(0, 8)} does not cover activated path "${p}". Configured patterns: ${pathRules.map((r) => `"${r.pattern}"`).join(", ")}.`,
        patch_id,
        resolved.base_sha,
        resolved.head_sha,
      );
    }
    if (!coveredBy.bypass_review_cycle) {
      fail(
        `bootstrap envelope rejected: path_rule "${coveredBy.pattern}" at base ${payload.base_sha.slice(0, 8)} has bypass_review_cycle: false. Bootstrap requires the matched rule to opt out of the reviewer cycle.`,
        patch_id,
        resolved.base_sha,
        resolved.head_sha,
      );
    }
  }

  // Target-branch check (equivalent to verifyV4TargetBranch). The
  // envelope's target_branch must equal the caller-supplied --into.
  if (payload.target_branch !== opts.into) {
    fail(
      `bootstrap envelope target_branch ("${payload.target_branch}") does not match --into ("${opts.into}")`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }

  // Verify diff_sha256 binds to the actual diff (same byte computation
  // as verifyV4DiffHash). Defends against an envelope produced against
  // one diff being replayed onto a different diff.
  if (!payload.diff_sha256) {
    fail(
      `bootstrap envelope is missing diff_sha256 — required for v3+ envelopes`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }
  const actualDiff = spawnSync(
    "git",
    ["diff", `${payload.base_sha}...${payload.head_sha}`],
    { cwd: repoRoot, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
  );
  if (actualDiff.status !== 0) {
    fail(
      `bootstrap envelope rejected: could not compute base...head diff for diff_sha256 check`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }
  const diffText = actualDiff.stdout ?? "";
  const actualDiffSha256 = createHash("sha256")
    .update(Buffer.from(diffText, "utf8"))
    .digest("hex");
  if (actualDiffSha256 !== payload.diff_sha256) {
    fail(
      `bootstrap envelope diff_sha256 mismatch — payload claims ${payload.diff_sha256.slice(0, 12)}… but base...head hashes to ${actualDiffSha256.slice(0, 12)}…. The operator signed against a different diff.`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }

  // PR-mode strict_base check, mirrored from the v3 path. Sourced from
  // base's branch rule for consistency.
  let configYaml: string;
  try {
    configYaml = showAtRef(payload.base_sha, ".stamp/config.yml", repoRoot);
  } catch (e) {
    fail(
      `bootstrap envelope rejected: could not read .stamp/config.yml at base ${payload.base_sha.slice(0, 8)}: ${(e as Error).message}`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }
  const config = parseConfigFromYaml(configYaml);
  const rule = findBranchRule(config.branches, opts.into);
  if (!rule) {
    fail(
      `bootstrap envelope rejected: no branch rule for "${opts.into}" in .stamp/config.yml at base ${payload.base_sha.slice(0, 8)}`,
      patch_id,
      resolved.base_sha,
      resolved.head_sha,
    );
  }
  if (rule.strict_base) {
    const currentTip = runGit(
      ["rev-parse", `${opts.into}^{commit}`],
      repoRoot,
    ).trim();
    if (envelope.payload.target_branch_tip_sha !== currentTip) {
      fail(
        `bootstrap strict_base check failed: attestation was signed when ${opts.into} was at ${envelope.payload.target_branch_tip_sha?.slice(0, 8)}, but ${opts.into} is now at ${currentTip.slice(0, 8)}`,
        patch_id,
        resolved.base_sha,
        resolved.head_sha,
      );
    }
  }

  printSuccess({
    patch_id,
    base_sha: resolved.base_sha,
    head_sha: resolved.head_sha,
    target_branch: opts.into,
    signer_key_id: payload.signer_key_id,
    approvals: [],
    strict_base: rule.strict_base ?? false,
    schema_version: envelope.payload.schema_version,
    bootstrap: true,
    activated_paths: marker.activated_paths,
  });
}

/**
 * Load the trusted-keys manifest at `base_sha` (a git ref), via
 * `git show`. Returns null if the file is missing or malformed —
 * mirrors how `pre-receive.ts:verifyCommitV4` loads the manifest from
 * the merge-base tree. Same source-of-truth, same parser.
 */
function loadManifestAtBase(
  base_sha: string,
  repoRoot: string,
): TrustedKeysManifest | null {
  let yaml: string;
  try {
    yaml = showAtRef(base_sha, ".stamp/trusted-keys/manifest.yml", repoRoot);
  } catch {
    return null;
  }
  return parseManifest(yaml);
}

/**
 * Build a fingerprint → PEM map from `.stamp/trusted-keys/*.pub` at
 * `base_sha`. Reuses `buildPubkeyMap` from sshReviewClient so the
 * verifier and the merge folder index pubkeys the same way (same
 * fingerprint computation, same filename → file-contents mapping).
 *
 * Mirrors `tests/v4Roundtrip.test.ts:buildPhaseInput`'s pubkey wiring:
 *   - `ls-tree --name-only` returns full repo-relative paths
 *     (`.stamp/trusted-keys/foo.pub`). We strip the prefix to get the
 *     basename for the buildPubkeyMap input.
 *   - `buildPubkeyMap`'s callback receives the FULL repo-relative
 *     path (it re-prepends `.stamp/trusted-keys/`), so we pass it
 *     straight to `git show <base>:<path>` without double-prefixing.
 */
function loadPubkeysAtBase(
  base_sha: string,
  repoRoot: string,
): Map<string, string> {
  const lsResult = spawnSync(
    "git",
    ["ls-tree", "--name-only", base_sha, ".stamp/trusted-keys/"],
    { cwd: repoRoot, encoding: "utf8" },
  );
  if (lsResult.status !== 0) return new Map();
  const lsOut = lsResult.stdout ?? "";
  const pubFiles = lsOut
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
    .map((l) => {
      const prefix = ".stamp/trusted-keys/";
      return l.startsWith(prefix) ? l.slice(prefix.length) : l;
    })
    .filter((n) => n.endsWith(".pub"));
  return buildPubkeyMap(pubFiles, (relPath) => {
    // relPath has the `.stamp/trusted-keys/` prefix re-attached by
    // buildPubkeyMap, so the git-show target is just `${base_sha}:${relPath}`.
    const show = spawnSync(
      "git",
      ["show", `${base_sha}:${relPath}`],
      { cwd: repoRoot, encoding: "utf8" },
    );
    if (show.status !== 0) throw new Error(`git show failed for ${relPath}`);
    return show.stdout ?? "";
  });
}

/**
 * Read `path_rules` from `.stamp/config.yml` at `base_sha`. Mirrors
 * `pre-receive.ts:readConfigAt`'s path_rules read path — same parser
 * (`parsePathRules`), same source-of-truth (the merge-base tree),
 * same stderr-surfaced warnings on malformed rules. The
 * `parseConfigFromYaml` helper strips `path_rules` (its job is
 * `branches:` resolution), so we re-parse the raw YAML to recover
 * the rules map.
 */
function loadPathRulesAtBase(
  base_sha: string,
  repoRoot: string,
): PathRule[] {
  let yaml: string;
  try {
    yaml = showAtRef(base_sha, ".stamp/config.yml", repoRoot);
  } catch {
    return [];
  }
  let raw: unknown;
  try {
    raw = parseYaml(yaml);
  } catch {
    return [];
  }
  if (!raw || typeof raw !== "object") return [];
  const parsedRules = parsePathRules((raw as { path_rules?: unknown }).path_rules);
  for (const warning of parsedRules.warnings) {
    // Match pre-receive's stderr surface so an operator deploying a
    // bad config sees the same warning regardless of which verifier
    // catches it.
    process.stderr.write(`stamp-verify: ${warning}\n`);
  }
  return parsedRules.rules;
}

/**
 * Enumerate files changed between `base_sha` and `head_sha` via
 * `git diff -z --name-only base...head`. Same 3-dot diff form
 * `verifyV4DiffHash` hashes; matches `pre-receive.ts:readChangedFiles`
 * including the -z (null-terminated) handling for unicode filenames.
 */
function loadChangedFiles(
  base_sha: string,
  head_sha: string,
  repoRoot: string,
): string[] {
  const result = spawnSync(
    "git",
    ["diff", "-z", "--name-only", `${base_sha}...${head_sha}`],
    { cwd: repoRoot, encoding: "utf8" },
  );
  if (result.status !== 0) return [];
  return (result.stdout ?? "").split("\0").filter((s) => s.length > 0);
}

interface SuccessSummary {
  patch_id: string;
  base_sha: string;
  head_sha: string;
  target_branch: string;
  signer_key_id: string;
  approvals: Array<{ reviewer: string; verdict: string }>;
  strict_base: boolean;
  schema_version: number;
  /** AGT-398: true when verifying a Shape 4 migration-bootstrap envelope.
   *  Surfaces `(bootstrap)` next to the schema line in the success
   *  output and lists `activated_paths` instead of `approvals`. */
  bootstrap?: boolean;
  activated_paths?: string[];
}

function printSuccess(s: SuccessSummary): void {
  // Two surfaces, two renderings (same split as hal9k's trailer-check):
  //   - stdout = the CI step LOG, which renders box-drawing + ANSI but
  //     not markdown → badge banner + tables.
  //   - GITHUB_STEP_SUMMARY = the run's Summary tab, which renders
  //     markdown → alert blockquote + pipe table.
  const color = colorEnabled();
  const p = paint(color);
  const maxWidth = Math.min(process.stdout.columns ?? 100, 100);
  const schemaLabel = s.bootstrap
    ? `v${s.schema_version} (Shape 4 migration bootstrap)`
    : `v${s.schema_version} (v4-trust)`;
  const nApproved = s.approvals.filter((a) => a.verdict === "approved").length;
  const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;
  const banner = s.bootstrap
    ? `admin-signed bootstrap, attestation valid, target ${s.target_branch}`
    : `${plural(nApproved, "reviewer")} approved, attestation valid, target ${s.target_branch}`;

  const out: string[] = [" " + p("stamp attestation check", A.bold)];
  out.push("");
  out.push(" " + p(" VERIFIED ", A.bold, A.black, A.bgGreen) + "  " + banner);
  out.push("");

  const rows: string[][] = [
    [p("diff", A.gray), `${s.base_sha.slice(0, 8)} → ${s.head_sha.slice(0, 8)}`],
    [p("patch-id", A.gray), s.patch_id],
    [p("schema", A.gray), schemaLabel],
    [p("signer", A.gray), s.signer_key_id],
    [p("base mode", A.gray), s.strict_base ? "strict" : "loose"],
  ];
  if (s.bootstrap && s.activated_paths) {
    rows.push([p("activated", A.gray), s.activated_paths.join(", ")]);
  } else {
    for (const a of s.approvals) {
      const ok = a.verdict === "approved";
      rows.push([
        p(a.reviewer, A.gray),
        `${p(ok ? "✓" : "✗", ok ? A.green : A.red)} ${a.verdict}`,
      ]);
    }
  }
  out.push(
    table([{ header: "check" }, { header: "result", flex: true }], rows, {
      color,
      maxWidth,
      indent: " ",
    }),
  );
  out.push("");
  // Keep the bare `result:` line at column 0 — it's the greppable
  // contract older scripts (and the pre-3.2 output format) key on.
  out.push("result: VERIFIED");
  console.log(out.join("\n"));

  writeStepSummary(successMarkdown(s, schemaLabel, banner));
}

/** Markdown twin of printSuccess for the Actions Summary tab. */
function successMarkdown(
  s: SuccessSummary,
  schemaLabel: string,
  banner: string,
): string {
  const out: string[] = [
    "### stamp attestation check",
    "",
    "> [!TIP]",
    `> **Verified** — ${banner}.`,
    "",
    "| check | result |",
    "| :-- | :-- |",
    `| 🎯 target | \`${mdCell(s.target_branch)}\` |`,
    `| 🔀 diff | \`${s.base_sha.slice(0, 8)} → ${s.head_sha.slice(0, 8)}\` |`,
    `| 🧩 patch-id | \`${mdCell(s.patch_id)}\` |`,
    `| 📦 schema | ${mdCell(schemaLabel)} |`,
    `| 🔑 signer | \`${mdCell(s.signer_key_id)}\` |`,
    `| ⚓ base mode | ${s.strict_base ? "strict" : "loose"} |`,
  ];
  if (s.bootstrap && s.activated_paths) {
    out.push(
      `| 🚧 activated | ${s.activated_paths.map((a) => `\`${mdCell(a)}\``).join(", ")} |`,
    );
  } else {
    for (const a of s.approvals) {
      out.push(
        `| ${mdCell(a.reviewer)} | ${a.verdict === "approved" ? "✅" : "❌"} ${mdCell(a.verdict)} |`,
      );
    }
  }
  return out.join("\n");
}

/**
 * Append markdown to the GitHub Actions Summary tab when running in CI.
 * Outside Actions (local debugging) GITHUB_STEP_SUMMARY is unset → no-op.
 * Best-effort: a summary-write failure must never flip the check result.
 */
function writeStepSummary(markdown: string): void {
  const target = process.env.GITHUB_STEP_SUMMARY;
  if (!target) return;
  try {
    appendFileSync(target, markdown + "\n");
  } catch {
    /* the exit code is the contract; the summary is decoration */
  }
}

/**
 * Print a structured failure summary and exit 1. CI consumers can rely
 * on the exit code; the prose is for the operator looking at the
 * action's logs. The `error:` prefix on the cause line matches the
 * stderr-prefix convention used elsewhere in the CLI; agents that
 * grep stderr for `^error:` get the failure cause cleanly.
 */
function fail(
  reason: string,
  patch_id: string,
  base_sha: string,
  head_sha: string,
): never {
  const color = colorEnabled();
  const p = paint(color);
  // fail() writes to stderr, so size against stderr's terminal.
  const maxWidth = Math.min(process.stderr.columns ?? 100, 100);

  const out: string[] = [" " + p("stamp attestation check", A.bold)];
  out.push("");
  out.push(
    " " + p(" FAILED ", A.bold, A.bgRed) + "  attestation did not verify",
  );
  out.push("");
  out.push(
    table(
      [{ header: "context" }, { header: "value", flex: true }],
      [
        [p("diff", A.gray), `${base_sha.slice(0, 8)} → ${head_sha.slice(0, 8)}`],
        [p("patch-id", A.gray), patch_id],
      ],
      { color, maxWidth, indent: " " },
    ),
  );
  out.push("");
  // The `error:` line stays verbatim + unwrapped: it's the greppable
  // contract (agents match `^error:` / reason substrings on stderr).
  out.push(`error: ${reason}`);
  out.push("result: FAILED");
  console.error(out.join("\n"));

  writeStepSummary(
    [
      "### stamp attestation check",
      "",
      "> [!CAUTION]",
      "> **Verification failed** — the attestation did not verify for this PR.",
      "",
      "| context | value |",
      "| :-- | :-- |",
      `| 🔀 diff | \`${base_sha.slice(0, 8)} → ${head_sha.slice(0, 8)}\` |`,
      `| 🧩 patch-id | \`${mdCell(patch_id)}\` |`,
      "",
      "```",
      reason,
      "```",
    ].join("\n"),
  );
  process.exit(1);
}
