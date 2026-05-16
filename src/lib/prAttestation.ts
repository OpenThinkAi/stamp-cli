/**
 * PR-check-mode attestation: the artifact `stamp attest` produces and
 * the `stamp/verify-attestation@v1` GitHub Action consumes. Lives in a
 * git ref under `refs/stamp/attestations/<patch-id>` so it survives
 * squash, rebase, and merge-commit on the GitHub side.
 *
 * Wire shape (intentionally JSON, not the base64-trailer form
 * server-gated mode uses, because there's no commit message to embed
 * it in — a ref-pointed blob is plain JSON):
 *
 *   {
 *     "payload": {
 *       "schema_version": 1,
 *       "patch_id": "<40-hex>",                 // content hash of base..head
 *       "base_sha": "<40-hex>",                 // base at attest time (informational +
 *                                               // strict-base lineage check on the
 *                                               // verifier side)
 *       "head_sha": "<40-hex>",                 // head at attest time (informational)
 *       "target_branch": "main",                // which branch rule applied to the gate
 *       "approvals": [...],                     // same Approval shape as AttestationPayload
 *       "checks": [...],                        // same CheckAttestation shape
 *       "signer_key_id": "sha256:<hex>"
 *     },
 *     "signature": "<base64 ed25519 sig over the canonical JSON of payload>"
 *   }
 *
 * Distinct from `AttestationPayload` (server-gated mode) because the
 * key-on field changes from (base_sha, head_sha) to patch_id and the
 * envelope shape is JSON-blob rather than commit trailer. They share
 * `Approval` and `CheckAttestation` though — same reviewer-binding
 * cryptography on both paths so a future verifier can treat them
 * uniformly.
 */

import { spawnSync } from "node:child_process";
import type { Approval, CheckAttestation } from "./attestation.js";

/**
 * Current PR attestation schema version. Bump when fields are added,
 * removed, or get tighter validation. Verifiers gate any version-
 * specific field check on the version number so an older attestation
 * (missing a newer required field) doesn't get silently rejected as
 * "no attestation found" — they get a clear "schema_version too old,
 * re-attest with stamp ≥ X" error instead.
 *
 * Version history:
 *   v1 — initial shape: patch_id, base_sha, head_sha, target_branch,
 *        approvals, checks, signer_key_id. Released only as in-flight
 *        development; never on npm.
 *   v2 — adds `target_branch_tip_sha` so strict_base mode can detect
 *        "main advanced with unrelated commits" (which leaves merge-base
 *        unchanged and would otherwise pass loose-mode verification).
 *        v1 attestations CANNOT verify under strict_base; they verify
 *        under loose mode unchanged.
 */
export const PR_ATTESTATION_SCHEMA_VERSION = 2;
export const MIN_ACCEPTED_PR_ATTESTATION_VERSION = 1;

/** Hard cap on the JSON blob's size — same DoS reasoning as
 *  MAX_TRAILER_BYTES in attestation.ts. The verifier reads the blob
 *  before it validates the signature; without a cap an attacker who
 *  could write to the attestations ref namespace (push access) could
 *  feed the verifier a multi-megabyte parse target. 64KB is generous
 *  for any sane attestation. */
export const MAX_PR_ATTESTATION_BYTES = 64 * 1024;

export interface PrAttestationPayload {
  schema_version: number;
  patch_id: string;
  /** Merge-base of (target_branch, head) at attest time. Same value
   *  the patch-id was computed against. Used by loose-mode verifiers
   *  for the structural sanity log; strict mode uses
   *  `target_branch_tip_sha` instead because base advancement that
   *  doesn't touch the feature's territory leaves merge-base unchanged. */
  base_sha: string;
  head_sha: string;
  target_branch: string;
  /** TIP of `target_branch` at attest time (i.e. `git rev-parse <target>`),
   *  distinct from `base_sha` (the merge-base). When `strict_base` is
   *  set on the branch rule, the verifier requires this to equal the
   *  current tip — any advancement of main since attest time
   *  invalidates the attestation, even when the cumulative diff content
   *  (and therefore patch-id) is unchanged. Operators that want
   *  GitHub's loose semantic ignore this field.
   *
   *  Schema v2+ writes this field; v1 envelopes don't have it. The
   *  parser keeps it optional in the type so v1 records still parse,
   *  and the strict-base verifier surfaces a clear "re-attest with
   *  stamp ≥ v2" error rather than silently accepting/rejecting. */
  target_branch_tip_sha?: string;
  approvals: Approval[];
  checks: CheckAttestation[];
  signer_key_id: string;
}

export interface PrAttestationEnvelope {
  payload: PrAttestationPayload;
  /** Base64 ed25519 signature over `serializePayload(payload)`. */
  signature: string;
}

/**
 * Serialize the payload to the exact bytes that get signed. Same
 * stance as server-gated attestation: we don't canonicalize JSON —
 * the blob the verifier reads is the same blob we wrote, so byte
 * equality is automatic.
 */
export function serializePayload(p: PrAttestationPayload): Buffer {
  return Buffer.from(JSON.stringify(p), "utf8");
}

export function serializeEnvelope(env: PrAttestationEnvelope): Buffer {
  return Buffer.from(JSON.stringify(env), "utf8");
}

/**
 * Parse a blob's bytes into a PR attestation envelope. Bounded by
 * MAX_PR_ATTESTATION_BYTES; rejects oversized blobs without parsing.
 * Returns null on any malformed shape rather than throwing — the
 * verifier's job is to refuse, not to crash.
 */
export function parseEnvelope(bytes: Buffer): PrAttestationEnvelope | null {
  if (bytes.length === 0 || bytes.length > MAX_PR_ATTESTATION_BYTES) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;
  const env = parsed as { payload?: unknown; signature?: unknown };
  if (typeof env.signature !== "string" || !env.signature) return null;
  if (!env.payload || typeof env.payload !== "object") return null;
  // Loose shape check; cryptographic verification comes after and is
  // what actually trusts the contents. We just need enough to know
  // we're holding an envelope-shaped object.
  const p = env.payload as Partial<PrAttestationPayload>;
  if (
    typeof p.schema_version !== "number" ||
    typeof p.patch_id !== "string" ||
    typeof p.base_sha !== "string" ||
    typeof p.head_sha !== "string" ||
    typeof p.target_branch !== "string" ||
    !Array.isArray(p.approvals) ||
    !Array.isArray(p.checks) ||
    typeof p.signer_key_id !== "string"
  ) {
    return null;
  }
  // schema_version-gated fields: rejected at parse time only if the
  // attestation CLAIMS to be at the version that requires them. An
  // older v1 envelope without target_branch_tip_sha parses fine; the
  // verifier separately refuses it for strict_base. A v2-or-newer
  // envelope MUST carry the field — its absence is a real shape error,
  // not just a forward-compat-allowed absence.
  if (p.schema_version >= 2 && typeof p.target_branch_tip_sha !== "string") {
    return null;
  }
  return env as PrAttestationEnvelope;
}

/**
 * The full ref name an attestation lives under. Operators don't have
 * to type this — `stamp attest` writes it, `stamp push` (phase 2)
 * pushes it, the GH Action (phase 3) fetches it. Keeping the
 * convention in one constant so all three sides agree.
 */
export function attestationRefName(patch_id: string): string {
  if (!/^[0-9a-f]{40}$/.test(patch_id)) {
    throw new Error(
      `patch_id must be a 40-char lowercase hex string (got ${JSON.stringify(patch_id)})`,
    );
  }
  return `refs/stamp/attestations/${patch_id}`;
}

/**
 * Write the envelope as a blob in the local repo and point
 * `refs/stamp/attestations/<patch-id>` at it. Returns the blob's SHA.
 * Idempotent — re-writing the same envelope produces the same blob
 * SHA (git hash-object is content-addressed) and update-ref is a
 * no-op when the ref already points there.
 */
export function writeAttestationRef(
  envelope: PrAttestationEnvelope,
  repoRoot: string,
): { ref: string; blob_sha: string } {
  const ref = attestationRefName(envelope.payload.patch_id);
  const bytes = serializeEnvelope(envelope);

  // git hash-object -w --stdin: writes a blob into the object store
  // from stdin and prints its SHA. The blob is unreachable from any
  // ref until update-ref points at it; if the process dies between
  // hash-object and update-ref, git gc eventually collects the orphan
  // — no on-disk corruption risk.
  const hashObject = spawnSync(
    "git",
    ["hash-object", "-w", "--stdin"],
    { cwd: repoRoot, input: bytes, encoding: "utf8" },
  );
  if (hashObject.status !== 0) {
    const stderr = hashObject.stderr ?? "";
    throw new Error(
      `git hash-object failed: ${stderr.trim() || "exit " + hashObject.status}`,
    );
  }
  const blob_sha = (hashObject.stdout ?? "").trim();
  if (!/^[0-9a-f]{40}$/.test(blob_sha)) {
    throw new Error(`unexpected git hash-object output: ${JSON.stringify(blob_sha)}`);
  }

  const updateRef = spawnSync(
    "git",
    ["update-ref", ref, blob_sha],
    { cwd: repoRoot, encoding: "utf8" },
  );
  if (updateRef.status !== 0) {
    const stderr = updateRef.stderr ?? "";
    throw new Error(
      `git update-ref ${ref} failed: ${stderr.trim() || "exit " + updateRef.status}`,
    );
  }

  return { ref, blob_sha };
}

/**
 * Read the envelope at `refs/stamp/attestations/<patch-id>`, or null
 * if the ref doesn't exist. Used by the verifier and by `stamp attest`
 * itself (to detect "this patch-id is already attested" and skip the
 * re-sign + ref update on a re-run).
 */
export function readAttestationRef(
  patch_id: string,
  repoRoot: string,
): PrAttestationEnvelope | null {
  const ref = attestationRefName(patch_id);
  const showRef = spawnSync(
    "git",
    ["show-ref", "--verify", "--quiet", ref],
    { cwd: repoRoot },
  );
  if (showRef.status !== 0) return null;

  const cat = spawnSync(
    "git",
    ["cat-file", "blob", ref],
    { cwd: repoRoot, encoding: "buffer", maxBuffer: MAX_PR_ATTESTATION_BYTES * 2 },
  );
  if (cat.status !== 0) return null;
  return parseEnvelope(cat.stdout);
}
