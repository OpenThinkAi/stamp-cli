import type { Verdict } from "./db.js";
import type { ToolCall } from "./toolCalls.js";

/**
 * Current attestation payload schema version. v1 (absent field) was the
 * initial shape; v2 adds per-approval prompt/tools/mcp hashes (plan Step 2).
 * Verifiers treat absent/1 as legacy fail-open on hash checks, 2 as
 * fail-closed without hashes.
 */
export const CURRENT_PAYLOAD_VERSION = 2;

export interface Approval {
  reviewer: string;
  verdict: Verdict;
  /** sha256 of the review's prose, hex — lets verifiers tie attestation to a specific DB row */
  review_sha: string;
  /** v2+: sha256 of the reviewer's prompt file at merge time */
  prompt_sha256?: string;
  /** v2+: sha256 of the canonical-form tool allowlist (sorted JSON array) */
  tools_sha256?: string;
  /** v2+: sha256 of the canonical-form mcp_servers config (sorted-key JSON) */
  mcp_sha256?: string;
  /** v2+: canonical source the reviewer was fetched from (if a lock file
   *  existed at merge time). Enables downstream audit: "was this reviewer
   *  fetched from an approved manifest at an approved version?" */
  reviewer_source?: {
    source: string;
    ref: string;
  };
  /** v2+: audit trace of tool calls the reviewer's agent made during review.
   *  Each entry is `{ tool, input_sha256 }`. Not cryptographically verified —
   *  the operator can forge the list — but catches lazy tampering and gives
   *  auditors a concrete signal ("did product call linear.get_issue at all?").
   *  Omitted or empty for reviewers that ran with no tools or where the SDK
   *  version didn't surface tool-use blocks. */
  tool_calls?: ToolCall[];
}

export interface CheckAttestation {
  name: string;
  command: string;
  exit_code: number;
  output_sha: string;
}

export interface AttestationPayload {
  /** Schema version. Absent = v1 (pre-Step-2). Present = v2+. */
  schema_version?: number;
  base_sha: string;
  head_sha: string;
  target_branch: string;
  approvals: Approval[];
  /** Pre-merge checks that ran on the signer's machine and passed.
   * Empty array if the branch has no required_checks configured. */
  checks: CheckAttestation[];
  /** "sha256:<hex>" fingerprint of the signer's public key */
  signer_key_id: string;
}

export const STAMP_PAYLOAD_TRAILER = "Stamp-Payload";
export const STAMP_VERIFIED_TRAILER = "Stamp-Verified";

/**
 * Serialize the payload to the exact bytes that will be signed. We do NOT
 * canonicalize JSON — the signer and verifier both operate on the base64
 * Stamp-Payload trailer value, so whatever bytes we produce here are the
 * same bytes the verifier base64-decodes. Deterministic serialization
 * isn't required for correctness.
 */
export function serializePayload(p: AttestationPayload): Buffer {
  return Buffer.from(JSON.stringify(p), "utf8");
}

export function payloadToTrailerValue(p: AttestationPayload): string {
  return serializePayload(p).toString("base64");
}

export function trailerValueToPayload(b64: string): AttestationPayload {
  const json = Buffer.from(b64, "base64").toString("utf8");
  return JSON.parse(json) as AttestationPayload;
}

export function trailerValueToPayloadBytes(b64: string): Buffer {
  return Buffer.from(b64, "base64");
}

export interface ParsedAttestation {
  payload: AttestationPayload;
  payloadBytes: Buffer;
  signatureBase64: string;
}

/**
 * Extract Stamp-Payload + Stamp-Verified trailers from a commit message.
 * Returns null if either is missing. Matches single-line trailer values.
 */
export function parseCommitAttestation(
  commitMessage: string,
): ParsedAttestation | null {
  const payloadMatch = commitMessage.match(
    new RegExp(`^${STAMP_PAYLOAD_TRAILER}:\\s*(.+)$`, "m"),
  );
  const sigMatch = commitMessage.match(
    new RegExp(`^${STAMP_VERIFIED_TRAILER}:\\s*(.+)$`, "m"),
  );
  if (!payloadMatch || !sigMatch) return null;
  const b64Payload = payloadMatch[1]?.trim();
  const b64Sig = sigMatch[1]?.trim();
  if (!b64Payload || !b64Sig) return null;

  const payloadBytes = trailerValueToPayloadBytes(b64Payload);
  const payload = JSON.parse(payloadBytes.toString("utf8")) as AttestationPayload;
  return { payload, payloadBytes, signatureBase64: b64Sig };
}

/**
 * Format the two trailer lines. Suitable for appending to a commit message
 * body after a blank-line separator.
 */
export function formatTrailers(
  p: AttestationPayload,
  signatureBase64: string,
): string {
  return (
    `${STAMP_PAYLOAD_TRAILER}: ${payloadToTrailerValue(p)}\n` +
    `${STAMP_VERIFIED_TRAILER}: ${signatureBase64}`
  );
}
