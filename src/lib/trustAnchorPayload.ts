/**
 * Trust-anchor signing-target construction (AGT-337).
 *
 * Both `stamp admin sign --pending <sha>` and `stamp merge` need to
 * produce the SAME canonical bytes for the v4 trust-anchor signing
 * target: `canonicalSerializePayload({...v4Payload,
 * trust_anchor_signatures: []})` — the bytes the pre-receive verifier
 * (`verifyV4TrustAnchorSignatures` / `verifyV4StampPathsGuard` in
 * `src/hooks/pre-receive.ts`) checks each admin signature against.
 *
 * --- Why a shared builder ---
 *
 * If `admin sign` and `merge` diverge by even one byte (a key-order
 * miss, an extra-pass through `JSON.parse`, a different default for an
 * absent field), every admin signature collected via `admin sign` fails
 * verification at merge time. That bug class is exactly what the
 * canonical-bytes contract is supposed to prevent — so we centralize
 * the v4-payload-without-trust-anchors construction here and have both
 * call sites import it.
 *
 * --- Predicting the payload before merge ---
 *
 * `stamp admin sign` runs BEFORE the merge commit exists. The full v4
 * payload at merge time depends on:
 *   - base_sha / head_sha / target_branch — deterministic from the
 *     feature branch
 *   - diff_sha256 — deterministic from base..head
 *   - approvals — derived from server-signed DB rows for (base, head)
 *   - checks — empty at sign time (operator hasn't run pre-merge checks
 *     yet; AGT-337 explicitly scopes admin signatures to PRE-CHECKS
 *     state, see "Operational caveat" below)
 *   - signer_key_id — the operator's fingerprint at merge time, which
 *     admins predict using the local user's stamp key by default. All
 *     admins counter-signing one commit must agree on this prediction.
 *
 * `stamp merge` rebuilds these bytes the same way and verifies each
 * note signature against them. If they don't verify, the operator gets
 * an actionable "re-sign after refreshing X" error (see
 * `buildV4Trailers` in `src/commands/merge.ts`).
 *
 * --- Operational caveat (M4 scope) ---
 *
 * Admin signatures are produced with `checks: []` because checks run at
 * merge time, AFTER all admins have signed. This means: a repo with
 * both `required_checks` on the target branch AND `path_rules` gating
 * `.stamp/**` cannot use this M4 admin-sign flow as-is — the admin
 * sigs would fail verification once `stamp merge` populated checks
 * into the payload.
 *
 * In practice the `.stamp/**` rule typically carries `bypass_review_cycle:
 * true`, and the recommended deployment pairs that with no
 * `required_checks` on the branch for the path-rule paths. A follow-up
 * ticket can either (a) skip required_checks for `.stamp/**`-only
 * merges, (b) ship a richer "sign-after-checks" two-pass merge flow,
 * or (c) extend the signing target to deterministically include the
 * declared check NAMES (not results). M4 documents the constraint and
 * defers the fix.
 */

import { createHash } from "node:crypto";
import {
  canonicalSerializePayload,
  CURRENT_V4_SCHEMA_VERSION,
  type ApprovalEntryV4,
  type AttestationPayloadV4,
  type CheckAttestationV4,
} from "./attestationV4.js";

/** Inputs to the trust-anchor signing-target builder. Mirror the
 *  shape `buildV4Trailers` already assembles, minus the trust-anchor
 *  field itself (which we replace with `[]` for the signing target). */
export interface TrustAnchorPayloadInput {
  baseSha: string;
  headSha: string;
  targetBranch: string;
  diffSha256: string;
  /** `sha256:<hex>` of the trusted-keys manifest at base_sha — same
   *  prefixed form `snapshotSha256()` returns. AGT-370 lifted this
   *  binding from the per-approval slot to the outer payload, so admin
   *  trust-anchor signatures must commit to it just like the operator's
   *  outer signature does. Admins predict the value the same way
   *  `stamp merge` will at merge time (parse the manifest at base_sha,
   *  apply `snapshotSha256`). */
  manifestSnapshotSha256: string;
  approvals: ApprovalEntryV4[];
  /** Mirrors `stamp merge`'s pre-checks state — empty when called from
   *  `stamp admin sign` (admins sign before checks run), populated at
   *  `stamp merge` time only when the sign-time prediction is being
   *  re-derived for verification. See module docstring "Operational
   *  caveat" for the M4 constraint. */
  checks: CheckAttestationV4[];
  /** Operator's fingerprint at merge time — `sha256:<hex>`. Admins
   *  predict this using the local user's stamp key. */
  signerKeyId: string;
  /** Envelope-format schema_version baked into the canonical signing
   *  bytes. Default = `CURRENT_V4_SCHEMA_VERSION` (the v4 commit-
   *  trailer envelope's version). PR-mode callers pass
   *  `PR_ATTESTATION_SCHEMA_VERSION` so the producer-side bytes match
   *  what the v3 PR-mode verifier will reconstruct (it reads
   *  `schema_version` from the wire envelope, which carries 3 — see
   *  `src/lib/prAttestation.ts` lines 81-91 on why the two envelopes
   *  hold distinct version-lines). Without this override, an admin
   *  signature produced for v4 commit-trailer mode would fail to
   *  verify against a v3 PR envelope of the same diff (and vice versa);
   *  the field is the smallest change that lets both envelopes share
   *  this builder without divergence.
   *
   *  WS1 follow-up: `stamp admin sign --pending` defaults to v4 and
   *  produces sigs that work for `stamp merge` but NOT for `stamp
   *  attest` PR-mode. Admins coordinating a PR-mode-only repo need a
   *  way to sign for that path explicitly. Tracked as a follow-up to
   *  this WS. */
  schemaVersion?: number;
}

/**
 * Build the v4 attestation payload that admins sign over. The
 * `trust_anchor_signatures` field is `[]` here by construction — admins
 * sign the payload as if no admin had signed yet, matching the
 * verifier's `payloadForAdmins` derivation
 * (`{...payload, trust_anchor_signatures: []}`).
 *
 * Returned payload is the input to `canonicalSerializePayload`; the
 * caller chooses whether to sign or store it.
 */
export function buildTrustAnchorPayload(
  input: TrustAnchorPayloadInput,
): AttestationPayloadV4 {
  return {
    schema_version: input.schemaVersion ?? CURRENT_V4_SCHEMA_VERSION,
    base_sha: input.baseSha,
    head_sha: input.headSha,
    target_branch: input.targetBranch,
    diff_sha256: input.diffSha256,
    manifest_snapshot_sha256: input.manifestSnapshotSha256,
    approvals: input.approvals,
    checks: input.checks,
    trust_anchor_signatures: [],
    signer_key_id: input.signerKeyId,
  };
}

/** Convenience: produce the exact bytes admins sign / merge verifies. */
export function trustAnchorSigningBytes(input: TrustAnchorPayloadInput): Buffer {
  return canonicalSerializePayload(buildTrustAnchorPayload(input));
}

/** SHA-256 of a diff string, hex-encoded — same construction `stamp
 *  merge` uses for `diff_sha256`. Centralized here so admin-sign and
 *  merge agree byte-for-byte on what they hash. */
export function diffSha256Hex(diff: string): string {
  return createHash("sha256").update(Buffer.from(diff, "utf8")).digest("hex");
}
