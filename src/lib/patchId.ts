/**
 * Content-addressed identifier for a cumulative diff. Wraps `git
 * patch-id --stable` so the rest of the codebase has one place to ask
 * "what's the patch-id of base..head in this repo?"
 *
 * Why patch-id (and not the head SHA): in PR-check mode the attestation
 * has to survive squash, rebase, and merge-commit on the GitHub side.
 * SHAs change in all three; the cumulative content of the diff does
 * not. `git patch-id --stable` returns the same hash for any sequence
 * of commits that produces the same source-tree change vs. the same
 * base — even after rebasing onto a new tip, even after squashing
 * three commits into one, even when GitHub's merge re-creates the
 * commits with new authorship metadata.
 *
 * `--stable` is intentional: the default ("unstable") patch-id depends
 * on diff-hunk ordering, which can shift if `git diff`'s internal
 * heuristics change between versions. The stable form is order-
 * independent and is what other tools (e.g. `git rebase --no-fork-point`)
 * key off.
 *
 * Empty diffs are rejected — there's nothing to attest to. Errors are
 * thrown with full context so callers don't have to second-guess "did
 * the git command fail or did I get an empty result?"
 */

import { spawnSync } from "node:child_process";
import { resolveDiff } from "./git.js";

export interface PatchId {
  /** "<40-hex-chars>" — the stable patch-id of base..head. */
  patch_id: string;
  /** Resolved base commit SHA (the merge-base of the original revspec). */
  base_sha: string;
  /** Resolved head commit SHA at attest time. */
  head_sha: string;
}

/**
 * Compute the stable patch-id of the cumulative diff between `base..head`.
 * Both refs are resolved through `git merge-base` / `rev-parse` first so
 * `revspec` may use any of the forms `git diff` accepts.
 */
export function patchIdForRevspec(revspec: string, repoRoot: string): PatchId {
  const resolved = resolveDiff(revspec, repoRoot);
  return {
    patch_id: patchIdForSpan(resolved.base_sha, resolved.head_sha, repoRoot),
    base_sha: resolved.base_sha,
    head_sha: resolved.head_sha,
  };
}

/**
 * Compute the stable patch-id between two already-resolved SHAs. Exposed
 * separately so the verifier (which knows the SHAs from the PR head and
 * the base ref) can compute the same hash without re-running revspec
 * resolution.
 */
export function patchIdForSpan(
  base_sha: string,
  head_sha: string,
  repoRoot: string,
): string {
  // Pipe `git diff` → `git patch-id --stable` in-process via spawnSync
  // input. Avoids `sh -c` (no shell-injection surface even though
  // base_sha/head_sha came from `git rev-parse` and are 40-char hex).
  //
  // git patch-id is technically documented for `git diff-tree` /
  // `git format-patch` output (which include "From <sha>" / "commit
  // <sha>" headers). Bare `git diff A..B` has no headers; git treats
  // the whole diff as one virtual commit and emits a single
  // `<patch-id> 0000...` line. Works in practice and is what we
  // depend on — DO NOT switch to format-patch piping without re-running
  // the squash/rebase stability tests in tests/patchId.test.ts, since
  // format-patch produces per-commit diffs whose cumulative patch-id
  // is computed differently and would silently change the keying
  // behavior for any branch with multiple commits.
  const diff = spawnSync("git", ["diff", `${base_sha}..${head_sha}`], {
    cwd: repoRoot,
    // Buffer because diffs can be large and stable across encodings;
    // patch-id consumes the raw bytes.
    encoding: "buffer",
    maxBuffer: 64 * 1024 * 1024,
  });
  if (diff.status !== 0) {
    const stderr = diff.stderr?.toString("utf8") ?? "";
    throw new Error(
      `git diff ${base_sha}..${head_sha} failed: ${stderr.trim() || "exit " + diff.status}`,
    );
  }
  if (diff.stdout.length === 0) {
    throw new Error(
      `empty diff between ${base_sha.slice(0, 8)}..${head_sha.slice(0, 8)} — nothing to attest`,
    );
  }

  const result = spawnSync("git", ["patch-id", "--stable"], {
    cwd: repoRoot,
    input: diff.stdout,
    encoding: "utf8",
    maxBuffer: 1024,
  });
  if (result.status !== 0) {
    const stderr = result.stderr ?? "";
    throw new Error(
      `git patch-id --stable failed: ${stderr.trim() || "exit " + result.status}`,
    );
  }

  // Output format: "<patch-id> <commit-sha>\n". One line per input
  // commit; for our piped cumulative diff, exactly one line. We only
  // care about the first whitespace-separated token.
  const firstLine = (result.stdout ?? "").trim().split("\n")[0] ?? "";
  const token = firstLine.split(/\s+/)[0];
  if (!token || !/^[0-9a-f]{40}$/.test(token)) {
    throw new Error(
      `unexpected git patch-id output: ${JSON.stringify(result.stdout.slice(0, 200))}`,
    );
  }
  return token;
}
