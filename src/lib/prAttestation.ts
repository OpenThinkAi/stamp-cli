/**
 * PR-check-mode attestation: the artifact the `stamp/verify-attestation@v1`
 * GitHub Action consumes (server-side production lands separately under
 * AGT-355; in 1.x, `stamp attest` produces v2 envelopes that this verifier
 * now refuses — see the version-history block below). Lives in a git ref
 * under `refs/stamp/attestations/<patch-id>` so it survives squash, rebase,
 * and merge-commit on the GitHub side.
 *
 * Wire shape (intentionally JSON, not the base64-trailer form
 * server-gated mode uses, because there's no commit message to embed
 * it in — a ref-pointed blob is plain JSON):
 *
 *   {
 *     "payload": {
 *       "schema_version": 3,
 *       "patch_id": "<40-hex>",                 // content hash of base..head
 *       "base_sha": "<40-hex>",                 // base at attest time (informational +
 *                                               // strict-base lineage check on the
 *                                               // verifier side)
 *       "head_sha": "<40-hex>",                 // head at attest time (informational)
 *       "target_branch": "main",                // which branch rule applied to the gate
 *       "target_branch_tip_sha": "<40-hex>",    // tip of target_branch at attest time
 *       "diff_sha256": "<64-hex>",              // bare-hex sha256 of `git diff base...head`,
 *                                               // matches the v4-trailer top-level field
 *       "approvals": [                          // v4-shape per-approval entries; the
 *                                               // server-signed inner approval + the
 *                                               // server's signature wrapper. Verifier
 *                                               // re-derives bytes via canonicalSerializeApproval.
 *         {
 *           "approval": ApprovalV4,
 *           "server_attestation": ServerAttestationV4
 *         }
 *       ],
 *       "checks": [],                           // CheckAttestationV4[] (Phase 1: empty)
 *       "trust_anchor_signatures": [],          // TrustAnchorSignatureV4[]; populated only
 *                                               // when diff touches a `path_rules` glob
 *       "signer_key_id": "sha256:<hex>"
 *     },
 *     "signature": "<base64 ed25519 sig over JSON.stringify(payload)>"
 *   }
 *
 * Distinct from `AttestationEnvelopeV4` (server-gated mode commit trailer)
 * because the key-on field is patch_id (PR-mode is keyed on diff content,
 * not on a merge commit's parent SHAs — the merge commit doesn't exist
 * until after the verifier passes) and the envelope shape is a JSON blob
 * rather than a base64-encoded commit trailer. The TWO envelopes do share
 * the v4 per-approval + per-trust-anchor types from `attestationV4.ts` so
 * the same `verifyV4*` phase functions verify both — settled decision
 * recorded in AGT-338's brief: "v4-trust fields embedded in PR-attestation
 * match the v4 commit-trailer's per-approval shape (canonical-serializable,
 * same signature bytes)."
 *
 * Version history:
 *   v1 — initial shape: patch_id, base_sha, head_sha, target_branch,
 *        approvals (legacy `Approval` shape), checks, signer_key_id.
 *        Released only as in-flight development; never on npm.
 *   v2 — adds `target_branch_tip_sha` so strict_base mode can detect
 *        "main advanced with unrelated commits" (which leaves merge-base
 *        unchanged and would otherwise pass loose-mode verification).
 *        Produced by stamp 1.x `stamp attest`. v2 reviewers used the
 *        legacy `Approval` shape from `attestation.ts` (no per-approval
 *        server signature) — the same trust model `stamp merge` 1.x's v3
 *        commit-trailer used.
 *   v3 — v4-trust envelope. Per-approval entries carry a server-signed
 *        body (`ApprovalEntryV4`); top-level `diff_sha256` binds the
 *        operator signature to the actual diff; `trust_anchor_signatures`
 *        present when the diff touches `.stamp/**`. Verifier shares the
 *        `verifyV4*` phase functions with the pre-receive hook (no logic
 *        divergence — settled decision #4 from AGT-338 brief).
 *
 * Versioning policy: `MIN_ACCEPTED_PR_ATTESTATION_VERSION` is the floor
 * for both this module's parser AND the action's verifier. v2 envelopes
 * surface a clear "schema_version too old, re-attest with stamp ≥ X"
 * error rather than the generic "no attestation found" prose — same
 * policy `attestation.ts`'s `MIN_ACCEPTED_PAYLOAD_VERSION = 3` enforces
 * for commit-trailer envelopes (post the v2 self-review-attack fix). The
 * two version axes are independent — server-gated commit trailers and
 * PR-mode envelopes evolve on separate cadences — but each axis enforces
 * the "no known-broken older version accepted" rule.
 *
 * Note on `schema_version` integer choice: the v4 commit-trailer envelope
 * uses `4`. We DELIBERATELY stay at `3` here, not `4`, because:
 *   - The two envelopes are different wire formats consumed by different
 *     verifiers — a single integer space across both would falsely imply
 *     they share a schema.
 *   - Picking `4` here would suggest a reader could treat them
 *     interchangeably; they cannot (different signature targets, different
 *     trailer/blob containers, different key-on identity).
 *   - Each axis (`prAttestation.ts` ↑3` and `attestationV4.ts` ↑4`) keeps
 *     its own monotone series; the dispatcher in each verifier reads its
 *     OWN `schema_version` integer and never crosses streams.
 */

import { spawnSync } from "node:child_process";
import type { Approval, CheckAttestation } from "./attestation.js";
import type {
  ApprovalEntryV4,
  CheckAttestationV4,
  TrustAnchorSignatureV4,
} from "./attestationV4.js";

/**
 * Current PR attestation schema version produced by 2.x server-side
 * (AGT-355, not landed yet at AGT-338). The verifier (this module +
 * `verifyPr.ts`) ships at this version *first* so that when AGT-355's
 * producer lands, no client-version skew exists. 1.x `stamp attest` keeps
 * emitting v2 — that production path is the operator-facing producer for
 * existing 1.x installs and remains unchanged. The verifier rejects v2
 * with the actionable error from MIN_ACCEPTED_PR_ATTESTATION_VERSION.
 */
export const PR_ATTESTATION_SCHEMA_VERSION = 3;

/**
 * Schema version `stamp attest` (the 1.x client-side producer) emits.
 * Deliberately frozen at 2 — the 2.x v3 envelope can ONLY be produced by
 * stamp-server (AGT-355, not landed yet) because the v4-trust fields it
 * carries require server-signed per-approval bodies that the local CLI
 * can't fabricate without already being the trust root. Operators that
 * want the new envelope shape need an upgraded stamp-server, and 1.x
 * `stamp attest` keeps producing v2 envelopes that the current verifier
 * rejects with a "schema_version too old" actionable error. The constant
 * sits here (next to `PR_ATTESTATION_SCHEMA_VERSION`) so the divergence
 * between "what the local producer emits" and "what the verifier
 * accepts" is named and grep-able rather than left as a magic `2`
 * literal in `attest.ts`.
 */
export const LEGACY_CLIENT_PR_ATTESTATION_SCHEMA_VERSION = 2;

/**
 * Minimum PR attestation schema version a current verifier will accept.
 * Matches the post-self-review-attack policy `attestation.ts` enforces
 * for commit trailers via `MIN_ACCEPTED_PAYLOAD_VERSION = 3`. v1 + v2 are
 * known-insufficient for the v4 trust model (no per-approval server
 * signature, no diff_sha256 binding, no trust-anchor multi-sig surface).
 *
 * Bumping this is a hard policy change: any envelopes still in flight at
 * the older version get a clear "schema_version too old" error rather
 * than silent acceptance under a partial trust model.
 */
export const MIN_ACCEPTED_PR_ATTESTATION_VERSION = 3;

/** Hard cap on the JSON blob's size — same DoS reasoning as
 *  MAX_TRAILER_BYTES in attestation.ts. The verifier reads the blob
 *  before it validates the signature; without a cap an attacker who
 *  could write to the attestations ref namespace (push access) could
 *  feed the verifier a multi-megabyte parse target. 64KB is generous
 *  for any sane attestation. */
export const MAX_PR_ATTESTATION_BYTES = 64 * 1024;

/**
 * v3+ PR-attestation payload. v3 embeds the v4-trust fields directly so
 * the verifier can run the same `verifyV4*` phases the pre-receive hook
 * runs against the commit-trailer envelope.
 *
 * Inner `approvals[].approval` is the byte-canonical `ApprovalV4` the
 * server signed; `approvals[].server_attestation` is the Ed25519
 * signature wrapper. Both come straight from the v4 module so the
 * verifier (`verifyV4ApprovalSignatures`) computes the same canonical
 * bytes against the same pubkey resolution — no PR-mode-specific
 * cryptography surface.
 */
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
   *  v2+ writes this field; the parser keeps it optional in the type
   *  for v2 carry-over readability, but the parse step refuses any
   *  envelope claiming v2 (or lower) outright — see
   *  MIN_ACCEPTED_PR_ATTESTATION_VERSION. */
  target_branch_tip_sha?: string;
  /** v3+: bare-hex sha256 of `git diff base...head` (3-dot diff form).
   *  Same byte computation `verifyV4DiffHash` performs in the
   *  pre-receive verifier: `Buffer.from(diffText, "utf8")` → sha256 →
   *  hex. Top-level so the operator's outer signature binds to the
   *  whole diff, not just the per-approval `diff_sha256` values that
   *  the server signed independently. Absent on v2 envelopes — the v3
   *  trust model REQUIRES it. */
  diff_sha256?: string;
  /** v2 used `Approval[]` (legacy single-signature shape). v3 uses
   *  `ApprovalEntryV4[]` (server-signed inner approval + signature
   *  wrapper). Schema_version is the discriminator; the parser refuses
   *  any envelope below `MIN_ACCEPTED_PR_ATTESTATION_VERSION` so this
   *  field's runtime shape on a successful parse is always
   *  `ApprovalEntryV4[]`. The dual-type union is here for v2
   *  read-only utilities (e.g. `parseEnvelope` returning a typed value
   *  that can also carry a v2 envelope's `Approval[]` for inspection
   *  paths that don't go through the trust pipeline). */
  approvals: ApprovalEntryV4[] | Approval[];
  checks: CheckAttestationV4[] | CheckAttestation[];
  /** v3+: trust-anchor (admin-capability) counter-signatures over the
   *  payload with `trust_anchor_signatures` set to an empty array. Empty
   *  array (NOT undefined) when the diff doesn't touch any path_rules
   *  glob — same convention `AttestationPayloadV4.trust_anchor_signatures`
   *  uses for server-gated mode. Absent on v2 envelopes. */
  trust_anchor_signatures?: TrustAnchorSignatureV4[];
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
 *
 * Note: the v3 envelope's INNER per-approval bodies carry their own
 * server-signed bytes (via `canonicalSerializeApproval` from
 * `attestationV4.ts`); those bytes are re-derived inside
 * `verifyV4ApprovalSignatures` and are independent of how the OUTER
 * envelope is serialized here. This function only produces the bytes
 * the OUTER (operator) signature is computed over.
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
 *
 * Version-gated shape: v3 envelopes MUST carry `diff_sha256`,
 * `trust_anchor_signatures`, and `approvals` entries shaped as
 * `ApprovalEntryV4`. The parser checks the outer types; the per-
 * approval cryptographic verification happens in
 * `verifyV4ApprovalSignatures` after the parsed envelope is wrapped
 * into a `PhaseInputV4`.
 *
 * Schema version below `MIN_ACCEPTED_PR_ATTESTATION_VERSION` returns
 * `null` here. Callers should detect this case via the
 * `peekSchemaVersion` helper below if they want to emit an actionable
 * "re-attest with stamp ≥ X" error rather than a generic "no
 * attestation found".
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
  const p = env.payload as Partial<PrAttestationPayload>;
  if (
    typeof p.schema_version !== "number" ||
    p.schema_version < MIN_ACCEPTED_PR_ATTESTATION_VERSION ||
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
  // v3+-gated fields: required at parse time. v2 envelopes don't carry
  // these; they reject above via the version floor.
  if (typeof p.diff_sha256 !== "string") return null;
  if (!Array.isArray(p.trust_anchor_signatures)) return null;
  if (typeof p.target_branch_tip_sha !== "string") return null;
  return env as PrAttestationEnvelope;
}

/**
 * Peek at the schema_version of a blob WITHOUT enforcing the version
 * floor. Used by the verifier to distinguish "no attestation found" (ref
 * missing or oversized garbage) from "attestation found but at an
 * unsupported version" — the latter deserves a specific actionable
 * error message. Returns `null` for anything that doesn't look like a
 * PR-attestation envelope at all (oversized, malformed JSON, wrong
 * top-level shape).
 *
 * Distinct from `parseEnvelope` in that this helper does NOT reject
 * below-minimum schema_versions; the caller decides how to surface
 * that. The shape checks remain strict enough to refuse arbitrary
 * blobs: we still require the byte cap, valid JSON, and an integer
 * `schema_version` field.
 */
export function peekSchemaVersion(bytes: Buffer): number | null {
  if (bytes.length === 0 || bytes.length > MAX_PR_ATTESTATION_BYTES) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;
  const env = parsed as { payload?: unknown };
  if (!env.payload || typeof env.payload !== "object") return null;
  const p = env.payload as { schema_version?: unknown };
  return typeof p.schema_version === "number" ? p.schema_version : null;
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
 * if the ref doesn't exist OR the envelope schema is below
 * `MIN_ACCEPTED_PR_ATTESTATION_VERSION`. Use `readAttestationBlobBytes`
 * below if you need to distinguish "ref missing" from "parsed but
 * below floor" (e.g. to emit a specific schema-too-old error).
 */
export function readAttestationRef(
  patch_id: string,
  repoRoot: string,
): PrAttestationEnvelope | null {
  const bytes = readAttestationBlobBytes(patch_id, repoRoot);
  if (!bytes) return null;
  return parseEnvelope(bytes);
}

/**
 * Read the raw blob bytes at `refs/stamp/attestations/<patch-id>`, or
 * null if the ref doesn't exist. Lets callers run their own peek-then-
 * parse logic (e.g. `peekSchemaVersion` + actionable error for older
 * schemas before going through `parseEnvelope`).
 */
export function readAttestationBlobBytes(
  patch_id: string,
  repoRoot: string,
): Buffer | null {
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
  return cat.stdout;
}
