/**
 * Helpers used by the mirror post-receive hook to publish a per-commit
 * `stamp/verified` status to GitHub. Split out from the hook itself so the
 * decision logic — does this commit message represent a stamp-verified
 * commit or not? — is unit-testable without a live git repo or network.
 *
 * Status semantics intentionally mirror the issue text: a commit whose
 * Stamp-Payload + Stamp-Verified trailers parse and whose signature
 * verifies against a key in the ref's trusted-keys set is `success`;
 * anything else is `failure` with a description naming what's missing.
 * Approval-set / merge-base / hash-binding checks belong to pre-receive
 * (which has already accepted the push by the time this runs); duplicating
 * them here would just couple the mirror status to a moving target.
 */

import { parseCommitAttestation } from "./attestation.js";
import { fingerprintFromPem } from "./keys.js";
import { verifyBytes } from "./signing.js";

export type MirrorStatusState = "success" | "failure";

export interface MirrorStatusDecision {
  state: MirrorStatusState;
  description: string;
}

// GitHub caps commit-status descriptions at 140 chars. Anything longer
// is silently rejected with a 422; truncate defensively.
const GITHUB_DESCRIPTION_MAX = 140;

function truncate(s: string): string {
  if (s.length <= GITHUB_DESCRIPTION_MAX) return s;
  return s.slice(0, GITHUB_DESCRIPTION_MAX - 1) + "…";
}

/**
 * Decide whether the commit's message body represents a stamp-verified
 * commit, given the set of trusted public-key PEMs at the ref.
 *
 * Pure function: no git, no network, no filesystem.
 */
export function decideMirrorStatus(
  commitMessage: string,
  trustedKeyPems: readonly string[],
): MirrorStatusDecision {
  const parsed = parseCommitAttestation(commitMessage);
  if (!parsed) {
    return {
      state: "failure",
      description: truncate(
        "no Stamp-Payload / Stamp-Verified trailers — commit not produced via 'stamp merge'",
      ),
    };
  }
  const { payload, payloadBytes, signatureBase64 } = parsed;

  // Build the fingerprint → PEM map. Skip malformed PEMs silently —
  // they're operator config errors, not the verifying commit's fault.
  const trusted = new Map<string, string>();
  for (const pem of trustedKeyPems) {
    try {
      trusted.set(fingerprintFromPem(pem), pem);
    } catch {
      continue;
    }
  }

  const signerPem = trusted.get(payload.signer_key_id);
  if (!signerPem) {
    return {
      state: "failure",
      description: truncate(
        `signer key ${payload.signer_key_id} not in trusted-keys at this ref`,
      ),
    };
  }

  let sigValid = false;
  try {
    sigValid = verifyBytes(signerPem, payloadBytes, signatureBase64);
  } catch (err) {
    return {
      state: "failure",
      description: truncate(
        `signature verification threw — ${err instanceof Error ? err.message : String(err)}`,
      ),
    };
  }
  if (!sigValid) {
    return {
      state: "failure",
      description: truncate(
        "Ed25519 signature does not verify against the signer's trusted key",
      ),
    };
  }

  const approved = payload.approvals
    .filter((a) => a.verdict === "approved")
    .map((a) => a.reviewer);
  const summary =
    approved.length > 0
      ? `signed by ${payload.signer_key_id} (${approved.join(", ")} approved)`
      : `signed by ${payload.signer_key_id}`;
  return {
    state: "success",
    description: truncate(summary),
  };
}

/**
 * Minimal shape of the global `fetch` that we depend on. Lets tests pass
 * a stub without pulling in DOM lib types.
 */
export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body: string },
) => Promise<{ ok: boolean; status: number; statusText: string; text: () => Promise<string> }>;

/**
 * POST a commit status to GitHub. Throws on a non-2xx response so the
 * caller can warn-and-continue without the whole hook unwinding.
 *
 * `fetchImpl` is a seam for tests. Production callers omit it and pick
 * up Node 22's global `fetch`.
 */
export async function postCommitStatus(
  githubRepo: string,
  sha: string,
  decision: MirrorStatusDecision,
  token: string,
  context: string,
  fetchImpl: FetchLike = fetch as unknown as FetchLike,
): Promise<void> {
  const url = `https://api.github.com/repos/${githubRepo}/statuses/${sha}`;
  const body = JSON.stringify({
    state: decision.state,
    context,
    description: decision.description,
  });
  const res = await fetchImpl(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
      "User-Agent": "stamp-cli mirror hook",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    body,
  });
  if (!res.ok) {
    let detail = "";
    try {
      detail = (await res.text()).slice(0, 200);
    } catch {
      // ignore
    }
    throw new Error(
      `HTTP ${res.status} ${res.statusText}${detail ? ` — ${detail}` : ""}`,
    );
  }
}
