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

import { spawnSync } from "node:child_process";
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
 * If `base_sha` is not present in the local clone, performs one `git fetch`
 * on the configured remote and retries. If still absent after the fetch,
 * returns `{ ok: false, reason: "base_sha_not_found" }`.
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

  // If the sha is not found locally, try one git fetch and retry.
  if (attempt.reason === "sha_not_found") {
    process.stderr.write(
      `note: base_sha ${base_sha} not in local clone at ${localRepoPath}; fetching remote...\n`,
    );
    try {
      const fetchResult = spawnSync("git", ["fetch", "--quiet"], {
        cwd: localRepoPath,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        timeout: 30_000,
      });
      if (fetchResult.status !== 0) {
        process.stderr.write(
          `note: git fetch failed in ${localRepoPath}: ${fetchResult.stderr?.trim() ?? "(no output)"}\n`,
        );
      }
    } catch (err) {
      process.stderr.write(
        `note: git fetch threw in ${localRepoPath}: ${err instanceof Error ? err.message : String(err)}\n`,
      );
    }

    // Retry once after fetch.
    const retryAttempt = readManifestAtSha(localRepoPath, base_sha);
    if (retryAttempt.ok) {
      return checkOperator(retryAttempt.yaml, base_sha, fingerprint);
    }
    return { ok: false, reason: `base_sha_not_found: ${base_sha} absent even after git fetch` };
  }

  return { ok: false, reason: attempt.reason };
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
