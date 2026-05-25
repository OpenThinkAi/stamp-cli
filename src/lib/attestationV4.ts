/**
 * Attestation envelope for server-attested reviews (stamp 2.x).
 *
 * Companion to `attestation.ts` (legacy v3 commit-trailer payload, kept
 * intact for `stamp log` backward read). This module ships the NEW
 * stamp 2.x envelope at `schema_version: 4` — a major cut, not a minor
 * bump on top of `CURRENT_PAYLOAD_VERSION = 3` in `attestation.ts`. The
 * two are different attestation systems coexisting during the 1.x → 2.x
 * migration; the dispatcher disambiguates by the `schema_version`
 * integer alone (no content sniffing).
 *
 * Why version 4 specifically: the legacy in-code v3 (the 0.5.0
 * merge-base self-review fix) already occupies the v3 integer slot.
 * Picking 4 keeps the disambiguator a single int comparison and avoids
 * any chance of a legacy v3 reader silently misinterpreting a v4
 * envelope (or vice versa) on a downgrade.
 *
 * Why a separate module: legacy v3 deliberately does NOT canonicalize
 * JSON — its signer and verifier both round-trip the same exact bytes
 * via the base64 commit trailer, so determinism falls out for free.
 * v4 has TWO independent signing producers (stamp-server signing each
 * approval, operator signing the envelope) that must agree on the
 * exact bytes fed to Ed25519. The canonical serializer below — sorted
 * object keys, recursive — is the load-bearing piece that makes those
 * two parties produce byte-identical inputs without coordinating
 * beyond "use canonicalSerializeApproval / canonicalSerializePayload".
 *
 * Scope notes:
 * - PR-check mode (`prAttestation.ts`, `PR_ATTESTATION_SCHEMA_VERSION = 2`)
 *   is OUT OF SCOPE here. That envelope continues on its own version
 *   axis; it'll get its own server-attested update separately.
 * - This file ships only the type contract + canonical serializer +
 *   bounded envelope parser. Wire integration (`stamp merge` folding
 *   server signatures into v4, the pre-receive hook verifying v4) lands
 *   in follow-up tickets (AGT-334, AGT-335). The deliberate
 *   separation lets those tickets land against a stable spec.
 */

/**
 * Current v4 envelope version emitted by stamp 2.x clients. Bump when
 * fields are added, removed, or get tighter validation. Verifiers gate
 * version-specific field checks on this integer so that an older v4
 * envelope (missing a newer required field) surfaces a clear "schema
 * too old, re-attest with stamp ≥ X" error rather than a generic
 * shape failure.
 *
 * Version history:
 *   v4 — initial server-attested envelope: per-approval
 *        `server_attestation` (server's Ed25519 over verdict + hashes),
 *        per-approval `trusted_keys_snapshot_sha256` for lenient
 *        revocation, top-level `trust_anchor_signatures` populated when
 *        the diff touches `.stamp/**`, dropped `tools_sha256` /
 *        `mcp_sha256` / `tool_calls` (no tools in Phase 1).
 *   v5 — server-side bare-repo dependency removed (AGT-370). The
 *        manifest-snapshot binding moved OFF each `ApprovalV4`
 *        (`trusted_keys_snapshot_sha256` dropped) and ONTO the outer
 *        `AttestationPayloadV4` as `manifest_snapshot_sha256`, signed
 *        by the operator. The verifier no longer re-hashes
 *        `prompt_sha256` from the merge-base tree — it trusts the
 *        server-signed value via the chain manifest → server key →
 *        signed approval. Server no longer reads the manifest at all.
 *        Breaking shape: v4 envelopes are rejected with a clear
 *        "schema too old, re-attest with stamp ≥ 2.1" error.
 */
export const CURRENT_V4_SCHEMA_VERSION = 5;

/**
 * Minimum v4 schema version a v4-aware verifier will accept. Distinct
 * from `CURRENT_V4_SCHEMA_VERSION` so a future v6 verifier can choose
 * whether to still accept v5 envelopes or refuse them outright.
 *
 * Bumped to 5 with AGT-370: v4 envelopes carry per-approval
 * `trusted_keys_snapshot_sha256` and lack an outer
 * `manifest_snapshot_sha256`. The reshape is breaking by design — no
 * backward-compat shim — so the floor moves in lockstep with the
 * current version.
 *
 * NOTE: this floor is independent of `MIN_ACCEPTED_PAYLOAD_VERSION = 3`
 * in `attestation.ts`. The two envelopes live on different version
 * axes — the dispatcher routes to one or the other based on the raw
 * `schema_version` integer (≤3 → legacy `attestation.ts`, ≥4 → here).
 */
export const MIN_ACCEPTED_V4_SCHEMA_VERSION = 5;

/**
 * Hard cap on the base64 trailer value AND its decoded bytes. Mirrors
 * `MAX_TRAILER_BYTES` in `attestation.ts`: `parseEnvelope` runs in the
 * pre-receive hook BEFORE the Ed25519 signature is checked, so an
 * attacker who can produce a commit (any push attempt) could otherwise
 * force JSON.parse on a multi-megabyte payload before reaching the
 * verification step that would reject it. 64 KB is generous for any
 * sane v4 envelope — even with multi-sig admin signatures over a
 * `.stamp/**` change the real-world size stays well under this.
 */
export const MAX_V4_ENVELOPE_BYTES = 64 * 1024;

/**
 * Server's signed verdict for a single reviewer/diff pair. Produced by
 * stamp-server's `stamp-review` SSH verb (see design.md). The client
 * receives this from the server and folds it into the v4 envelope at
 * `stamp merge` time; the operator does not (and cannot) regenerate
 * the server's signature.
 *
 * `canonicalSerializeApproval` produces the exact bytes the server's
 * Ed25519 was computed over.
 */
export interface ApprovalV4 {
  reviewer: string;
  verdict: "approved" | "changes_requested" | "denied";
  /** Hex sha256 of the reviewer's prompt file at `base_sha`. The server
   *  fetched the prompt from its local bare repo (not from the
   *  operator) — this hash is the verifier's check that the operator
   *  didn't smuggle in a different prompt's hash. */
  prompt_sha256: string;
  /** Hex sha256 of the diff content (base..head) the server reviewed.
   *  Binds the verdict to a specific code change; the verifier rehashes
   *  the actual merge diff and rejects on mismatch. */
  diff_sha256: string;
  base_sha: string;
  head_sha: string;
  /** ISO-8601 UTC timestamp the server assigned at signing time. Part
   *  of the signed bytes; the verifier reads it for audit-log surface
   *  but does not enforce a freshness window in Phase 1. */
  issued_at: string;
  /** Fingerprint of the server's review-signing key, as `sha256:<hex>`.
   *  Resolved against `.stamp/trusted-keys/manifest.yml` at verify
   *  time to find the matching pubkey + confirm its `server`
   *  capability. */
  server_key_id: string;
}

/**
 * The server's signature wrapper attached to an approval in the v4
 * envelope. The approval body itself (`ApprovalV4`) is the signed
 * payload; this struct carries the signature + a redundant copy of
 * the server's key id so the verifier can resolve the pubkey before
 * touching the signed bytes.
 *
 * `server_key_id` duplicates `ApprovalV4.server_key_id` deliberately —
 * the inner one is part of the signed bytes (binds the signature to a
 * specific key), the outer one tells the verifier which key to load
 * before signature verification. Both must match.
 */
export interface ServerAttestationV4 {
  server_key_id: string;
  /** Base64 Ed25519 signature over `canonicalSerializeApproval(approval)`. */
  signature: string;
}

/**
 * One reviewer's approval as it appears in the v4 envelope: the
 * canonical approval body plus the server's signature over it.
 */
export interface ApprovalEntryV4 {
  approval: ApprovalV4;
  server_attestation: ServerAttestationV4;
}

/**
 * Pre-merge mechanical check result, signed indirectly via the
 * envelope's signer signature (no per-check server signature in
 * Phase 1 — checks run on the operator's machine, same trust model
 * as today's `CheckAttestation` in `attestation.ts`).
 */
export interface CheckAttestationV4 {
  name: string;
  command: string;
  exit_code: number;
  output_sha: string;
}

/**
 * Admin-capability signature over the canonical payload, present in
 * `AttestationPayloadV4.trust_anchor_signatures` when the merge
 * modifies any `.stamp/**` path. Multi-sig: the path rule's
 * `minimum_signatures` count must be met, and each signer must hold
 * the `admin` capability per the manifest at `base_sha`.
 *
 * The signature target is `canonicalSerializePayload(payload)` with
 * `trust_anchor_signatures` field set to an empty array — i.e. each
 * admin signs the payload as if their own and other admins'
 * signatures aren't there yet. This avoids a chicken-and-egg
 * "everyone signs what everyone signed" loop while keeping the bytes
 * deterministic.
 */
export interface TrustAnchorSignatureV4 {
  signer_key_id: string;
  /** Base64 Ed25519 over `canonicalSerializePayload(payloadWithoutTrustAnchorSignatures)`. */
  signature: string;
}

/**
 * Full v4 attestation payload (the JSON wrapped by base64 in the
 * `Stamp-Payload` commit trailer for server-gated mode). The operator
 * signs `canonicalSerializePayload(this)` and the result lands in
 * `Stamp-Verified`.
 *
 * Compare against `AttestationPayload` in `attestation.ts`:
 *   - same `base_sha` / `head_sha` / `target_branch` / `checks` /
 *     `signer_key_id` skeleton
 *   - new `diff_sha256` at the top level (binds operator signature to
 *     the actual diff in addition to base/head)
 *   - approvals are wrapped in `ApprovalEntryV4` (carrying the
 *     server's signature) instead of bare `Approval`
 *   - new `trust_anchor_signatures` populated only on `.stamp/**`
 *     touches
 *   - dropped legacy `Approval` fields (`tools_sha256`, `mcp_sha256`,
 *     `tool_calls`, `review_sha`, `reviewer_source`) — see design.md
 *     "Fields explicitly dropped from v2"
 */
export interface AttestationPayloadV4 {
  schema_version: number;
  base_sha: string;
  head_sha: string;
  target_branch: string;
  /** Hex sha256 of the actual merge diff (base..head). Top-level so
   *  the operator signature binds to the whole diff, not just the
   *  per-approval `diff_sha256` values (which the server signed). */
  diff_sha256: string;
  /** `sha256:<hex>` of `.stamp/trusted-keys/manifest.yml` as it
   *  existed at `base_sha`, in the same prefixed form
   *  `snapshotSha256()` in `src/lib/trustedKeysManifest.ts` returns.
   *
   *  Operator-signed at envelope-construction time (see
   *  `buildV4Trailers` in `src/commands/merge.ts` and `buildV3Envelope`
   *  in `src/commands/attest.ts`); the verifier checks it once per
   *  envelope against the manifest the verifier reads at `base_sha`.
   *
   *  Lifted from the per-approval slot in v4 (AGT-370): in v4 the
   *  binding was `ApprovalV4.trusted_keys_snapshot_sha256`, signed by
   *  the SERVER. That required the server to read the manifest at
   *  `base_sha`, which forced the server to maintain a bare clone of
   *  every reviewed repo — a non-starter for private/internal repos.
   *  Moving the binding to the outer envelope lets the operator
   *  (who already has the repo checked out) supply the value and lets
   *  the server stay manifest-blind. The trust chain manifest →
   *  server key → signed approval → prompt_sha256 is unchanged. */
  manifest_snapshot_sha256: string;
  approvals: ApprovalEntryV4[];
  checks: CheckAttestationV4[];
  /** Empty array unless the diff touches a path matching any
   *  `path_rules` glob. When non-empty, each entry must be a
   *  signature from an admin-capability key per the manifest at
   *  `base_sha`, and the count must meet the rule's
   *  `minimum_signatures`. */
  trust_anchor_signatures: TrustAnchorSignatureV4[];
  /** Fingerprint of the operator's key, as `sha256:<hex>`. Resolved
   *  against `.stamp/trusted-keys/manifest.yml` at verify time. */
  signer_key_id: string;
}

/**
 * The envelope that wraps the payload + the operator's signature.
 * What actually lives in the commit trailer is the base64 of
 * `serializeEnvelope(this)`; `payloadToTrailerValue` / `formatTrailers`
 * handle that wrapping for server-gated mode the same way
 * `attestation.ts` does for legacy v3.
 */
export interface AttestationEnvelopeV4 {
  payload: AttestationPayloadV4;
  /** Base64 Ed25519 signature over `canonicalSerializePayload(payload)`. */
  signature: string;
}

// ─── Canonical serialization ────────────────────────────────────────

/**
 * Recursively sort object keys so `JSON.stringify` produces
 * deterministic byte output regardless of how the input object was
 * constructed. Arrays are preserved in their existing order (array
 * order is semantic in v4 — `approvals` ordering matches the order
 * the operator requested verdicts in; `trust_anchor_signatures` order
 * is whatever order admins counter-signed in).
 *
 * Null, primitives, and arrays are returned as-is (with array elements
 * recursed into). Plain objects (typeof === "object", not null, not
 * Array) get a new object with keys inserted in sorted order — the V8
 * JSON serializer respects insertion order for string keys, so this
 * is sufficient to make `JSON.stringify` output deterministic.
 *
 * Loadbearing for the two-signer correctness property: the server
 * signs `canonicalSerializeApproval(approval)` and the operator's
 * verifier later re-canonicalizes the approval-as-parsed to check the
 * signature. Without canonicalization, the verifier's bytes could
 * differ from the server's by key order alone, breaking verification
 * for no semantic reason. Legacy v3 in `attestation.ts` doesn't need
 * this because the operator is the only signer and the verifier
 * round-trips the exact base64'd bytes from the commit trailer.
 */
export function sortKeysDeep(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  const obj = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    out[key] = sortKeysDeep(obj[key]);
  }
  return out;
}

/**
 * Canonical bytes the server's Ed25519 signature is computed over.
 * Deterministic across key-order, whitespace, and any equivalent
 * object construction. The server uses this; the client's verifier
 * uses this to re-derive the same bytes from the parsed approval.
 */
export function canonicalSerializeApproval(a: ApprovalV4): Buffer {
  return Buffer.from(JSON.stringify(sortKeysDeep(a)), "utf8");
}

/**
 * Canonical bytes the operator's Ed25519 signature is computed over.
 * Includes the `trust_anchor_signatures` array as-passed — callers
 * signing the payload must zero out `trust_anchor_signatures` first
 * if they want the "admin signs the payload without admin signatures"
 * shape (see `TrustAnchorSignatureV4` doc). The operator's final
 * signature is over the FULL payload including any collected
 * trust-anchor signatures, so the envelope's signature commits to the
 * exact multi-sig set that landed.
 */
export function canonicalSerializePayload(p: AttestationPayloadV4): Buffer {
  return Buffer.from(JSON.stringify(sortKeysDeep(p)), "utf8");
}

/**
 * Fields of the `pr-opened` broadcast payload that are covered by the
 * client's Ed25519 signature (all fields excluding `signature` itself).
 * Used by `prOpenedClient.ts` to produce the signing target and
 * documented here so a future server-side or WS verifier can match
 * exactly this field set without re-deriving the shape.
 */
export interface PrOpenedPayloadBody {
  repo: string;
  patch_id: string;
  base_sha: string;
  head_sha: string;
  requested_by_fp: string;
  paths_changed: string[];
  title: string;
  body: string;
  pr_url: string;
  /** SPKI PEM of the stamp signing key (AGT-454). Included in canonical signed bytes. */
  pubkey: string;
}

/**
 * Canonical bytes the client's Ed25519 signature is computed over for a
 * `pr-opened` broadcast. Covers all fields in `PrOpenedPayloadBody` (every
 * field of the payload EXCLUDING the `signature` field itself). The signing
 * target is `sortKeysDeep` + `JSON.stringify` over those fields so a future
 * verifier (server-side or WS) can reproduce the bytes without coordinating
 * beyond "apply this function to the payload minus the signature field."
 */
export function canonicalSerializePrOpened(body: PrOpenedPayloadBody): Buffer {
  return Buffer.from(JSON.stringify(sortKeysDeep(body)), "utf8");
}

/**
 * Generic canonical serialization for any peer-review payload body (AGT-434).
 * Covers the seat/ping payload shapes: `claim-seat`, `heartbeat`,
 * `release-seat`, and `re-review-request`. Callers MUST pass the body
 * WITHOUT the `signature` field (omit it before serializing for signing,
 * strip it before serializing for verification).
 *
 * Uses the same `sortKeysDeep` + `JSON.stringify` form as
 * `canonicalSerializePrOpened` so the verifier bytes are identical
 * regardless of which payload shape is being signed.
 */
export function canonicalSerializePeerPayload(body: object): Buffer {
  return Buffer.from(JSON.stringify(sortKeysDeep(body)), "utf8");
}

/**
 * Serialize the full envelope to bytes for storage (e.g. into the
 * commit trailer via `payloadToTrailerValue`). Not the signing target
 * — the signature is over `canonicalSerializePayload(envelope.payload)`,
 * not over the envelope itself.
 *
 * We still apply canonical key sorting here so that re-serializing a
 * parsed envelope produces byte-identical output, which keeps tests
 * simple and lets diagnostic tools rely on stable hashes.
 */
export function serializeEnvelope(env: AttestationEnvelopeV4): Buffer {
  return Buffer.from(JSON.stringify(sortKeysDeep(env)), "utf8");
}

// ─── Trailer wrapping (commit-message integration) ──────────────────

export const STAMP_PAYLOAD_TRAILER_V4 = "Stamp-Payload";
export const STAMP_VERIFIED_TRAILER_V4 = "Stamp-Verified";

/**
 * Base64-encode the canonical payload bytes for embedding in a
 * `Stamp-Payload` commit trailer. The operator's signature in
 * `Stamp-Verified` was computed over the SAME bytes returned by
 * `canonicalSerializePayload(p)` — so the verifier base64-decodes
 * the trailer to obtain the signing target without re-canonicalizing,
 * matching the legacy v3 behavior.
 */
export function payloadToTrailerValue(p: AttestationPayloadV4): string {
  return canonicalSerializePayload(p).toString("base64");
}

/**
 * Inverse of `payloadToTrailerValue`: pull the signing-target bytes
 * back out of the trailer value. Returns raw bytes (not JSON-parsed)
 * because the verifier feeds these directly to Ed25519 — re-parsing
 * and re-serializing through `canonicalSerializePayload` would also
 * work but introduces a needless round-trip surface.
 */
export function trailerValueToPayloadBytes(b64: string): Buffer {
  return Buffer.from(b64, "base64");
}

/**
 * Render the two trailer lines for appending to a commit message
 * body. Mirrors `formatTrailers` in `attestation.ts` so the two
 * envelopes use the same trailer keys; dispatch happens after
 * trailer extraction by inspecting `schema_version` in the decoded
 * payload.
 */
export function formatTrailers(
  p: AttestationPayloadV4,
  signatureBase64: string,
): string {
  return (
    `${STAMP_PAYLOAD_TRAILER_V4}: ${payloadToTrailerValue(p)}\n` +
    `${STAMP_VERIFIED_TRAILER_V4}: ${signatureBase64}`
  );
}

// ─── Envelope parsing ───────────────────────────────────────────────

/**
 * Parse a JSON envelope's bytes into an `AttestationEnvelopeV4`.
 * Bounded by `MAX_V4_ENVELOPE_BYTES`; refuses oversized blobs without
 * parsing. Returns null on any malformed shape rather than throwing —
 * the verifier's job is to refuse, not to crash.
 *
 * Validates structural shape only; cryptographic verification (the
 * operator's envelope signature, the server's per-approval signatures,
 * the trust-anchor signatures) happens after this returns. The point
 * is to fail closed on garbage input before allocating any further
 * verification work.
 */
export function parseEnvelope(bytes: Buffer): AttestationEnvelopeV4 | null {
  if (bytes.length === 0 || bytes.length > MAX_V4_ENVELOPE_BYTES) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const env = parsed as { payload?: unknown; signature?: unknown };
  if (typeof env.signature !== "string" || !env.signature) return null;
  if (!env.payload || typeof env.payload !== "object" || Array.isArray(env.payload)) {
    return null;
  }

  const p = env.payload as Partial<AttestationPayloadV4>;
  if (
    typeof p.schema_version !== "number" ||
    p.schema_version < MIN_ACCEPTED_V4_SCHEMA_VERSION ||
    typeof p.base_sha !== "string" ||
    typeof p.head_sha !== "string" ||
    typeof p.target_branch !== "string" ||
    typeof p.diff_sha256 !== "string" ||
    typeof p.manifest_snapshot_sha256 !== "string" ||
    !Array.isArray(p.approvals) ||
    !Array.isArray(p.checks) ||
    !Array.isArray(p.trust_anchor_signatures) ||
    typeof p.signer_key_id !== "string"
  ) {
    return null;
  }

  for (const entry of p.approvals) {
    if (!isApprovalEntry(entry)) return null;
  }
  for (const check of p.checks) {
    if (!isCheck(check)) return null;
  }
  for (const sig of p.trust_anchor_signatures) {
    if (!isTrustAnchorSignature(sig)) return null;
  }

  return env as AttestationEnvelopeV4;
}

function isApprovalEntry(value: unknown): value is ApprovalEntryV4 {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const e = value as Partial<ApprovalEntryV4>;
  if (!e.approval || typeof e.approval !== "object") return false;
  if (!e.server_attestation || typeof e.server_attestation !== "object") return false;
  const a = e.approval as Partial<ApprovalV4>;
  if (
    typeof a.reviewer !== "string" ||
    (a.verdict !== "approved" &&
      a.verdict !== "changes_requested" &&
      a.verdict !== "denied") ||
    typeof a.prompt_sha256 !== "string" ||
    typeof a.diff_sha256 !== "string" ||
    typeof a.base_sha !== "string" ||
    typeof a.head_sha !== "string" ||
    typeof a.issued_at !== "string" ||
    typeof a.server_key_id !== "string"
  ) {
    return false;
  }
  const s = e.server_attestation as Partial<ServerAttestationV4>;
  if (typeof s.server_key_id !== "string" || typeof s.signature !== "string") {
    return false;
  }
  return true;
}

function isCheck(value: unknown): value is CheckAttestationV4 {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const c = value as Partial<CheckAttestationV4>;
  return (
    typeof c.name === "string" &&
    typeof c.command === "string" &&
    typeof c.exit_code === "number" &&
    typeof c.output_sha === "string"
  );
}

function isTrustAnchorSignature(value: unknown): value is TrustAnchorSignatureV4 {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const t = value as Partial<TrustAnchorSignatureV4>;
  return typeof t.signer_key_id === "string" && typeof t.signature === "string";
}
