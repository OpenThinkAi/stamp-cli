/**
 * Client-side operator verification for the peer-agentic review listener
 * (AGT-454). Verifies that `fingerprint` appears as an `operator` in the
 * `.stamp/trusted-keys/manifest.yml` at `base_sha` of the listener's own
 * local clone.
 *
 * This is the client-side twin of the deleted server-side `verifyOperatorAtBase`
 * — same helper triple (showAtRef / parseManifest / resolveCapability) as
 * `attest.ts:351-383` and `merge.ts:461-491`, but keyed off the listener's
 * own local worktree path rather than a server bare repo.
 *
 * Exported as `verifyOperatorAtBaseLocal` to make the "local clone" semantics
 * explicit at every call site.
 */

import { showAtRef } from "./git.js";
import {
  parseManifest,
  resolveCapability,
  MANIFEST_RELATIVE_PATH,
} from "./trustedKeysManifest.js";

/**
 * Verify that `fingerprint` has `operator` capability in the manifest at
 * `base_sha` in the local git repo at `localRepoPath`.
 *
 * If `base_sha` is not present in the local clone, returns
 * `{ ok: false, reason: "base_sha_not_found: ..." }` immediately. No
 * automatic `git fetch` is performed: post-AGT-454 the server is a GitHub-
 * blind broker and any SSH-registered user can submit events, so an auto-
 * fetch on attacker-controlled `base_sha` would create a DoS amplification
 * path. Listeners are expected to keep their local clones up to date.
 *
 * Returns `{ ok: true }` on success, or `{ ok: false, reason }` on any
 * failure (sha absent, manifest missing/unparseable, fp absent, not operator).
 * Callers should skip the event and log loudly on any non-OK result.
 */
export function verifyOperatorAtBaseLocal(
  localRepoPath: string,
  base_sha: string,
  fingerprint: string,
): { ok: true } | { ok: false; reason: string } {
  // Attempt to read the manifest at base_sha.
  const attempt = readManifestAtSha(localRepoPath, base_sha);
  if (attempt.ok) {
    return checkOperator(attempt.yaml, base_sha, fingerprint);
  }

  // The sha is not accessible locally (absent sha, missing manifest, etc.).
  // Fail closed — do NOT auto-fetch. Post-AGT-454 any SSH-registered user can
  // submit events with an arbitrary base_sha, so triggering a network fetch on
  // attacker-controlled input would create a DoS amplification. The listener
  // must keep its local clone current.
  return {
    ok: false,
    reason: `base_sha_not_found: ${base_sha} is not accessible in local clone at ${localRepoPath} (${attempt.reason}); run git fetch manually`,
  };
}

/**
 * Read the manifest YAML at `base_sha` from the local repo.
 * Returns `{ ok: true, yaml }` or `{ ok: false, reason }`.
 */
function readManifestAtSha(
  localRepoPath: string,
  base_sha: string,
): { ok: true; yaml: string } | { ok: false; reason: string } {
  try {
    const yaml = showAtRef(base_sha, MANIFEST_RELATIVE_PATH, localRepoPath);
    return { ok: true, yaml };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    // Distinguish "sha not found in this repo" from "manifest path doesn't exist at sha".
    if (msg.includes("unknown revision") || msg.includes("bad object") || msg.includes("fatal: not a tree object")) {
      return { ok: false, reason: "sha_not_found" };
    }
    return { ok: false, reason: `manifest not found at ${base_sha}: ${msg}` };
  }
}

/**
 * Parse the manifest YAML and check whether `fingerprint` has `operator` capability.
 */
function checkOperator(
  manifestYaml: string,
  base_sha: string,
  fingerprint: string,
): { ok: true } | { ok: false; reason: string } {
  const manifest = parseManifest(manifestYaml);
  if (!manifest) {
    return { ok: false, reason: `manifest at ${base_sha} failed to parse` };
  }

  const caps = resolveCapability(manifest, fingerprint);
  if (!caps) {
    return {
      ok: false,
      reason: `fingerprint ${fingerprint} is not in manifest at ${base_sha}`,
    };
  }

  if (!caps.includes("operator")) {
    return {
      ok: false,
      reason: `fingerprint ${fingerprint} has capabilities [${caps.join(", ")}] at ${base_sha} — 'operator' required`,
    };
  }

  return { ok: true };
}
