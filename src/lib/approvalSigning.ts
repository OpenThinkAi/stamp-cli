/**
 * Strict validation of the approval payload the root signing helper
 * (`stamp-sign-approval`, AGT-2263) is asked to sign.
 *
 * Why this exists: the review-signing private key is root:root 0600 and
 * the git user (which runs `stamp-review`) can no longer read it. The
 * git user instead pipes the approval it wants signed to the helper via
 * one sudoers rule. The helper is therefore a signing oracle reachable
 * by anything that runs as git — the internet-facing HTTP listener, the
 * receive hooks, `stamp-review` itself. This module is what keeps that
 * oracle narrow. The helper signs ONLY bytes that:
 *
 *   1. are at most `MAX_APPROVAL_PAYLOAD_BYTES` long;
 *   2. parse as a JSON object with EXACTLY the `ApprovalV4` key set
 *      (including AGT-2272's `repo_id`, which is required here — every
 *      approval this server version produces carries it): no missing
 *      keys, no extra keys;
 *   3. have every field in its exact wire shape (reviewer name regex,
 *      verdict enum, 64-hex sha256s, 40-hex commit shas, second-
 *      precision UTC `issued_at`, `sha256:<hex>` key id, well-formed
 *      `<org>/<repo>`);
 *   4. name the helper's OWN key as `server_key_id` — so a signature
 *      can't be minted that claims some other key id;
 *   5. carry an `issued_at` within `MAX_ISSUED_AT_SKEW_MS` of the
 *      helper's clock — a compromised git user cannot back- or
 *      forward-date an approval;
 *   6. are byte-identical to `canonicalSerializeApproval` of the parsed
 *      object — the helper re-derives the canonical bytes and signs
 *      THOSE, so the key never signs anything but a canonical approval.
 *
 * What that buys: the key is never usable as a general-purpose Ed25519
 * oracle. Every signature it produces verifies only as an approval (the
 * object shape is disjoint from the operator envelope, peer payloads and
 * every other signed format in the codebase), and it can't be exfiltrated,
 * so a git-user foothold no longer yields a key that forges attestations
 * forever, offline, after the foothold is closed.
 *
 * What it deliberately does NOT do: decide whether the verdict is TRUE.
 * The review itself (prompt selection, the model call, verdict parsing)
 * runs as git by design, so while an attacker holds code execution as
 * git they can still obtain fresh, correctly-dated approvals for diffs of
 * their choosing — exactly as they could by tampering with the review
 * process. Moving the whole pipeline (Anthropic call, prompt cache) under
 * root to close that would put far more attack surface in the privileged
 * process than it removes. The residual is bounded: it lasts only as long
 * as the foothold, each signature is timestamped now, and the helper
 * writes one line per signature to the container log (PID 1's stderr,
 * which the git user cannot rewrite) so it is auditable after the fact.
 */

import { isWellFormedRepoId } from "./repoBinding.js";
import { type ApprovalV4, canonicalSerializeApproval } from "./attestationV4.js";

/** Hard cap on helper stdin. A well-formed approval is ~450 bytes. */
export const MAX_APPROVAL_PAYLOAD_BYTES = 4096;

/** How far `issued_at` may sit from the helper's clock, either side.
 *  The pipeline stamps `issued_at` microseconds before invoking the
 *  helper; five minutes absorbs a slow sudo/node start without letting
 *  a caller meaningfully backdate. */
export const MAX_ISSUED_AT_SKEW_MS = 5 * 60 * 1000;

/** The exact key set of an approval this server signs. */
export const APPROVAL_V4_KEYS: readonly string[] = [
  "base_sha",
  "diff_sha256",
  "head_sha",
  "issued_at",
  "prompt_sha256",
  "repo_id",
  "reviewer",
  "server_key_id",
  "verdict",
] as const;

// Same shapes the `stamp-review` verb enforces on its inputs.
const REVIEWER_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/;
const COMMIT_SHA_RE = /^[0-9a-f]{40}$/;
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const KEY_ID_RE = /^sha256:[0-9a-f]{64}$/;
// The pipeline's `issued_at` form: ISO-8601 UTC, second precision, `Z`.
const ISSUED_AT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const VERDICTS = new Set(["approved", "changes_requested", "denied"]);

export class ApprovalPayloadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ApprovalPayloadError";
  }
}

/**
 * Validate `bytes` as an approval the helper may sign under the key
 * whose fingerprint is `expectedKeyId`. Returns the parsed approval and
 * the canonical bytes to sign (identical to the input on success).
 * Throws `ApprovalPayloadError` on anything else.
 */
export function validateApprovalPayload(
  bytes: Buffer,
  opts: { expectedKeyId: string; now?: Date },
): { approval: ApprovalV4; canonical: Buffer } {
  if (bytes.length === 0) throw new ApprovalPayloadError("empty payload");
  if (bytes.length > MAX_APPROVAL_PAYLOAD_BYTES) {
    throw new ApprovalPayloadError(
      `payload is ${bytes.length} bytes; max ${MAX_APPROVAL_PAYLOAD_BYTES}`,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new ApprovalPayloadError("payload is not JSON");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new ApprovalPayloadError("payload is not a JSON object");
  }
  const obj = parsed as Record<string, unknown>;

  const keys = Object.keys(obj).sort();
  if (
    keys.length !== APPROVAL_V4_KEYS.length ||
    keys.some((k, i) => k !== APPROVAL_V4_KEYS[i])
  ) {
    throw new ApprovalPayloadError(
      `payload keys must be exactly [${APPROVAL_V4_KEYS.join(", ")}]; got [${keys.join(", ")}]`,
    );
  }

  const str = (k: string): string => {
    const v = obj[k];
    if (typeof v !== "string") throw new ApprovalPayloadError(`${k} must be a string`);
    return v;
  };
  const check = (k: string, ok: boolean): void => {
    if (!ok) throw new ApprovalPayloadError(`${k} has an invalid shape`);
  };

  const reviewer = str("reviewer");
  check("reviewer", REVIEWER_NAME_RE.test(reviewer));
  const verdict = str("verdict");
  check("verdict", VERDICTS.has(verdict));
  const prompt_sha256 = str("prompt_sha256");
  check("prompt_sha256", SHA256_HEX_RE.test(prompt_sha256));
  const diff_sha256 = str("diff_sha256");
  check("diff_sha256", SHA256_HEX_RE.test(diff_sha256));
  const base_sha = str("base_sha");
  check("base_sha", COMMIT_SHA_RE.test(base_sha));
  const head_sha = str("head_sha");
  check("head_sha", COMMIT_SHA_RE.test(head_sha));
  const repo_id = str("repo_id");
  check("repo_id", isWellFormedRepoId(repo_id));

  const server_key_id = str("server_key_id");
  check("server_key_id", KEY_ID_RE.test(server_key_id));
  if (server_key_id !== opts.expectedKeyId) {
    throw new ApprovalPayloadError(
      `server_key_id ${server_key_id} is not this server's review-signing key (${opts.expectedKeyId})`,
    );
  }

  const issued_at = str("issued_at");
  check("issued_at", ISSUED_AT_RE.test(issued_at));
  const issuedMs = Date.parse(issued_at);
  // Round-trip guards impossible dates the regex admits (e.g. month 13).
  if (
    Number.isNaN(issuedMs) ||
    new Date(issuedMs).toISOString().replace(/\.\d{3}Z$/, "Z") !== issued_at
  ) {
    throw new ApprovalPayloadError("issued_at is not a valid UTC timestamp");
  }
  const nowMs = (opts.now ?? new Date()).getTime();
  if (Math.abs(nowMs - issuedMs) > MAX_ISSUED_AT_SKEW_MS) {
    throw new ApprovalPayloadError(
      `issued_at ${issued_at} is more than ${MAX_ISSUED_AT_SKEW_MS / 1000}s from the signer's clock`,
    );
  }

  const approval: ApprovalV4 = {
    reviewer,
    verdict: verdict as ApprovalV4["verdict"],
    prompt_sha256,
    diff_sha256,
    base_sha,
    head_sha,
    issued_at,
    server_key_id,
    repo_id,
  };
  const canonical = canonicalSerializeApproval(approval);
  if (!canonical.equals(bytes)) {
    throw new ApprovalPayloadError(
      "payload is not in canonical form (canonicalSerializeApproval)",
    );
  }
  return { approval, canonical };
}
