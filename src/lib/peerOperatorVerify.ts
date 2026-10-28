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
 *
 * AGT-2241: `base_sha` is supplied by the event's author, so reading the
 * manifest at it alone lets a revoked key cite a pre-revocation commit (or a
 * commit on an unprotected branch whose manifest it edited) and pass. The
 * listener therefore calls `verifyPeerAuthorLocal`, which binds `base_sha` to
 * the protected branch before trusting the manifest read at it.
 */

import { spawnSync } from "node:child_process";
import { isAncestor, showAtRef } from "./git.js";
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

// ─── AGT-2241: bind base_sha to the protected branch ────────────────

/**
 * The ref the listener treats as the protected-branch tip: the local clone's
 * view of the remote default branch. `stamp pr open` computes `base_sha`
 * against `origin/HEAD` too, so an honest event's base is always an ancestor
 * of (or equal to) this ref once the listener has fetched.
 */
export const PROTECTED_TIP_REF = "refs/remotes/origin/HEAD";

/** Full 40-char lowercase hex commit SHA. */
export const FULL_SHA_RE = /^[0-9a-f]{40}$/;

/**
 * Authorize a peer-review event's author against the listener's local clone,
 * with `base_sha` bound to the protected branch (AGT-2241). All must hold:
 *
 *   1. `base_sha` is a full SHA of a commit present in the local clone.
 *   2. `base_sha` is an ancestor of (or equal to) the protected-branch tip
 *      (`origin/HEAD`). A commit on some other branch — where the author may
 *      have edited the manifest — is rejected.
 *   3. The author is an `operator` in the manifest at `base_sha` (the
 *      anti-self-promotion read: a PR cannot authorize itself).
 *   4. The author is an `operator` in the manifest at the protected-branch
 *      tip. This is what makes revocation stick: removing a key on the
 *      protected branch stops its events even if the author cites an older
 *      `base_sha` where the key was still trusted.
 *
 * No fetch is performed (same DoS reasoning as `verifyOperatorAtBaseLocal`);
 * the tip is whatever the listener last fetched. Fail-closed on any error.
 */
export function verifyPeerAuthorLocal(
  localRepoPath: string,
  base_sha: string,
  fingerprint: string,
): { ok: true } | { ok: false; reason: string } {
  if (!FULL_SHA_RE.test(base_sha)) {
    return { ok: false, reason: `base_sha ${JSON.stringify(base_sha)} is not a full 40-char lowercase hex SHA` };
  }

  const tip = resolveCommit(localRepoPath, PROTECTED_TIP_REF);
  if (tip === null) {
    return {
      ok: false,
      reason:
        `protected_tip_not_found: ${PROTECTED_TIP_REF} does not resolve in local clone at ${localRepoPath}; ` +
        `run 'git remote set-head origin --auto' and 'git fetch origin'`,
    };
  }

  if (resolveCommit(localRepoPath, base_sha) === null) {
    return {
      ok: false,
      reason: `base_sha_not_found: ${base_sha} is not a commit in local clone at ${localRepoPath}; run git fetch manually`,
    };
  }

  let onProtected: boolean;
  try {
    onProtected = isAncestor(base_sha, tip, localRepoPath);
  } catch (err) {
    return {
      ok: false,
      reason: `could not check ancestry of ${base_sha}: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  if (!onProtected) {
    return {
      ok: false,
      reason:
        `base_sha_not_on_protected_branch: ${base_sha} is not an ancestor of ${PROTECTED_TIP_REF} (${tip}) ` +
        `in local clone at ${localRepoPath}; if the PR really branches off the default branch, ` +
        `run 'git fetch origin' — otherwise the event cites a base off the protected branch`,
    };
  }

  const atBase = verifyOperatorAtBaseLocal(localRepoPath, base_sha, fingerprint);
  if (!atBase.ok) return atBase;

  if (tip !== base_sha) {
    const atTip = readManifestAtSha(localRepoPath, tip);
    if (!atTip.ok) {
      return {
        ok: false,
        reason: `manifest unreadable at protected tip ${tip} (${atTip.reason})`,
      };
    }
    const tipResult = checkOperator(atTip.yaml, tip, fingerprint);
    if (!tipResult.ok) {
      return { ok: false, reason: `revoked at protected tip: ${tipResult.reason}` };
    }
  }

  return { ok: true };
}

/** Resolve `ref` to a commit SHA in `cwd`, or null when it does not resolve. */
function resolveCommit(cwd: string, ref: string): string | null {
  const r = spawnSync(
    "git",
    ["rev-parse", "--verify", "--quiet", "--end-of-options", `${ref}^{commit}`],
    { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  );
  if (r.status !== 0) return null;
  const sha = (r.stdout ?? "").trim();
  return FULL_SHA_RE.test(sha) ? sha : null;
}
