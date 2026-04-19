import type { Verdict } from "./db.js";

export interface Approval {
  reviewer: string;
  verdict: Verdict;
  /** sha256 of the review's prose, hex — lets verifiers tie attestation to a specific DB row */
  review_sha: string;
}

export interface CheckAttestation {
  name: string;
  command: string;
  exit_code: number;
  output_sha: string;
}

export interface AttestationPayload {
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
