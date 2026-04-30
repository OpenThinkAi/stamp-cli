import { existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";

export function findRepoRoot(startFrom: string = process.cwd()): string {
  let current = resolve(startFrom);
  while (true) {
    if (existsSync(join(current, ".git"))) return current;
    const parent = dirname(current);
    if (parent === current) {
      throw new Error(
        `not inside a git repository (searched up from ${startFrom})`,
      );
    }
    current = parent;
  }
}

export function stampConfigDir(repoRoot: string): string {
  return join(repoRoot, ".stamp");
}

export function stampReviewersDir(repoRoot: string): string {
  return join(repoRoot, ".stamp", "reviewers");
}

export function stampTrustedKeysDir(repoRoot: string): string {
  return join(repoRoot, ".stamp", "trusted-keys");
}

export function stampConfigFile(repoRoot: string): string {
  return join(repoRoot, ".stamp", "config.yml");
}

export function stampStateDbPath(repoRoot: string): string {
  return join(gitCommonDir(repoRoot), "stamp", "state.db");
}

/**
 * Resolve the git common directory for `repoRoot`. For a normal checkout this
 * is `<repoRoot>/.git`; for a worktree, `<repoRoot>/.git` is a *file* of the
 * form `gitdir: <path>` and the real common dir lives at `<gitdir>/commondir`
 * (a path relative to gitdir, typically `../..`). Mirrors `git rev-parse
 * --git-common-dir` without spawning git.
 *
 * State that should be shared across every worktree of one repository (review
 * verdicts, the per-machine sqlite db) lives under this common dir, so callers
 * resolve their paths through here rather than hard-coding `<repoRoot>/.git`.
 */
export function gitCommonDir(repoRoot: string): string {
  const dotGit = join(repoRoot, ".git");
  const st = statSync(dotGit);
  if (st.isDirectory()) return dotGit;

  // Worktree (or submodule): `.git` is a file. Parse the `gitdir:` line, then
  // follow the `commondir` pointer from there. Submodules have no `commondir`,
  // so the gitdir itself is the writable common dir — fall through to that.
  const contents = readFileSync(dotGit, "utf8");
  const match = contents.match(/^gitdir:\s*(.+)$/m);
  if (!match || !match[1]) {
    throw new Error(
      `expected '.git' at ${repoRoot} to be a directory or a 'gitdir:' pointer file, got: ${contents.slice(0, 120)}`,
    );
  }
  const gitdirRaw = match[1].trim();
  const gitdir = isAbsolute(gitdirRaw) ? gitdirRaw : resolve(repoRoot, gitdirRaw);

  const commondirPath = join(gitdir, "commondir");
  if (!existsSync(commondirPath)) return gitdir;
  const commondirRaw = readFileSync(commondirPath, "utf8").trim();
  return isAbsolute(commondirRaw) ? commondirRaw : resolve(gitdir, commondirRaw);
}

export function userKeysDir(): string {
  return join(homedir(), ".stamp", "keys");
}

/**
 * Per-user stamp-server config. Holds {host, port, user, repo_root_prefix}
 * so commands like `stamp provision` can reach the operator's stamp server
 * without making the agent guess at SSH endpoints.
 */
export function userServerConfigPath(): string {
  return join(homedir(), ".stamp", "server.yml");
}

export function ensureDir(path: string, mode = 0o755): void {
  if (!existsSync(path)) {
    mkdirSync(path, { recursive: true, mode });
  }
}

export function isFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}
