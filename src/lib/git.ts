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

export interface CommitSummary {
  sha: string;
  title: string;
  author: string;
  date: string;
  /** Full commit message body */
  body: string;
  /** Parent SHAs (typically 1 for normal commits, 2 for merges) */
  parents: string[];
}

export function currentBranch(cwd: string): string {
  return git(["rev-parse", "--abbrev-ref", "HEAD"], cwd).trim();
}

/**
 * First-parent commit history on a branch — follows only the branch's linear
 * history, skipping commits that came in via merged feature branches. This
 * matches what the pre-receive hook verifies on push.
 */
export function firstParentCommits(
  branch: string,
  limit: number,
  cwd: string,
): CommitSummary[] {
  const sep = "----stamp-record-end----";
  const fmt = `%H%n%P%n%an <%ae>%n%ai%n%s%n%n%b${sep}`;
  const out = git(
    ["log", "--first-parent", `-${limit}`, `--format=${fmt}`, branch],
    cwd,
  );
  const records = out.split(sep).map((r) => r.trim()).filter(Boolean);
  const commits: CommitSummary[] = [];
  for (const rec of records) {
    const lines = rec.split("\n");
    if (lines.length < 5) continue;
    const [sha, parents, author, date, title, ...rest] = lines as [
      string,
      string,
      string,
      string,
      string,
      ...string[],
    ];
    const body = rest.join("\n").replace(/^\n+/, "").trimEnd();
    commits.push({
      sha,
      parents: parents.split(/\s+/).filter(Boolean),
      author,
      date,
      title,
      body,
    });
  }
  return commits;
}

export function commitMessage(sha: string, cwd: string): string {
  return git(["show", "-s", "--format=%B", sha], cwd);
}

/**
 * Read a file's contents from a specific git tree (commit / tag / branch /
 * tree-ish). Wraps `git show <ref>:<path>`. Throws via runGit's stderr-
 * capturing path if the file doesn't exist at that ref.
 *
 * Used by `stamp review` and `stamp merge` to source reviewer config +
 * prompts from the merge-base tree (rather than the working tree), which is
 * the security boundary that prevents a feature branch from reviewing
 * itself with a reviewer prompt it just modified.
 */
export function showAtRef(ref: string, path: string, cwd: string): string {
  return runGit(["show", `${ref}:${path}`], cwd);
}

export function commitSummary(sha: string, cwd: string): CommitSummary {
  const commits = firstParentCommits(sha, 1, cwd);
  if (commits.length === 0) {
    throw new Error(`commit ${sha} not found`);
  }
  return commits[0]!;
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

/**
 * Shared git-shell helper used by every command that needs to run git
 * subprocesses. Captures stderr (rather than inheriting it) so failures
 * surface via the thrown message — no raw `fatal: ...` lines bleed onto
 * the user's terminal alongside otherwise-successful output. Returns
 * stdout as utf-8.
 *
 * Use this in command modules (commands/*.ts) instead of a local copy.
 */
export function runGit(args: string[], cwd: string): string {
  try {
    return execFileSync("git", args, {
      cwd,
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024, // 64MB; big diffs happen
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    const stderr = (err as { stderr?: Buffer | string } | null)?.stderr;
    const stderrText =
      typeof stderr === "string" ? stderr : stderr?.toString("utf8") ?? "";
    const base = err instanceof Error ? err.message : String(err);
    throw new Error(
      `git ${args.join(" ")} failed: ${stderrText.trim() || base}`,
    );
  }
}

// Local alias so existing callers in this file keep their short name.
const git = runGit;
