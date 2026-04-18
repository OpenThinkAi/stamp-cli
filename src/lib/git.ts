import { execFileSync } from "node:child_process";

export interface ResolvedDiff {
  /** Original revspec as passed by the user, e.g. "main..HEAD" */
  revspec: string;
  /** Commit SHA of the merge base (the "base" of the diff) */
  base_sha: string;
  /** Commit SHA of the head being reviewed */
  head_sha: string;
  /** Unified diff text covering the change from base to head */
  diff: string;
}

/**
 * Parse and resolve a git revspec of the form "<base>..<head>".
 * - base_sha is merge-base(<base>, <head>), the point at which <head> diverged
 * - head_sha is the commit SHA that <head> currently points to
 * - diff is `git diff <base>...<head>` — changes introduced by <head>
 *   relative to <base>, ignoring any changes that <base> has since made
 *
 * Throws on invalid revspecs or on git failures.
 */
export function resolveDiff(revspec: string, cwd: string): ResolvedDiff {
  const parts = revspec.split("..");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new Error(
      `invalid revspec "${revspec}": expected form <base>..<head> (two dots)`,
    );
  }
  const [baseRef, headRef] = parts;

  const base_sha = git(["merge-base", baseRef, headRef], cwd).trim();
  const head_sha = git(["rev-parse", "--verify", `${headRef}^{commit}`], cwd).trim();
  const diff = git(["diff", `${baseRef}...${headRef}`], cwd);

  return { revspec, base_sha, head_sha, diff };
}

function git(args: string[], cwd: string): string {
  try {
    return execFileSync("git", args, {
      cwd,
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024, // 64MB; big diffs happen
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`git ${args.join(" ")} failed: ${message}`);
  }
}
