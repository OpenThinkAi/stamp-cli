/**
 * Tests for git-aware path resolution. The bug these pin:
 *   - stampStateDbPath used to hardcode `<repoRoot>/.git/stamp/state.db`,
 *     which crashes inside a worktree because `.git` is a *file* there, not
 *     a directory — `mkdir .git/stamp` throws ENOTDIR before openDb runs.
 *
 * Each test wires up a real git repo on disk (no mocks; we rely on the actual
 * git layout) so any future regression in worktree handling fails here
 * instead of at runtime in `stamp init`.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import { ensureDir, gitCommonDir, stampStateDbPath } from "../src/lib/paths.ts";

function git(args: string[], cwd: string): void {
  execFileSync("git", args, { cwd, stdio: "pipe" });
}

describe("gitCommonDir / stampStateDbPath", () => {
  let tmpRoot: string;

  beforeEach(() => {
    // realpathSync to dodge macOS's /var → /private/var symlink: git's
    // worktree pointers expand to the canonical path, but tmpdir() returns
    // the symlink form. Without normalizing here, equality assertions on
    // resolved paths spuriously fail on Darwin.
    tmpRoot = realpathSync(mkdtempSync(join(tmpdir(), "stamp-paths-")));
  });

  afterEach(() => {
    rmSync(tmpRoot, { recursive: true, force: true });
  });

  it("resolves to <repoRoot>/.git/... in a normal checkout", () => {
    const repo = join(tmpRoot, "repo");
    mkdirSync(repo);
    git(["init", "-q", "-b", "main", repo], tmpRoot);
    git(["commit", "--allow-empty", "-q", "-m", "init"], repo);

    assert.equal(gitCommonDir(repo), join(repo, ".git"));
    assert.equal(stampStateDbPath(repo), join(repo, ".git", "stamp", "state.db"));
  });

  it("resolves to the main repo's .git from inside a worktree", () => {
    const repo = join(tmpRoot, "repo");
    const wt = join(tmpRoot, "wt");
    mkdirSync(repo);
    git(["init", "-q", "-b", "main", repo], tmpRoot);
    git(["commit", "--allow-empty", "-q", "-m", "init"], repo);
    git(["worktree", "add", "-q", wt], repo);

    // The bug: in a worktree `<repoRoot>/.git` is a file, so naive
    // `join(repoRoot, ".git", "stamp", ...)` would try to mkdir under a file
    // and throw ENOTDIR. The fix routes both through gitCommonDir, which
    // points at the *main* repo's .git.
    const mainGit = join(repo, ".git");
    assert.equal(gitCommonDir(wt), mainGit);
    assert.equal(stampStateDbPath(wt), join(mainGit, "stamp", "state.db"));
  });

  it("ensureDir succeeds on the worktree-resolved state-db parent", () => {
    // Regression guard for the original ENOTDIR crash: prove the resolved
    // dirname is actually mkdirable, not just a string that looks right.
    const repo = join(tmpRoot, "repo");
    const wt = join(tmpRoot, "wt");
    mkdirSync(repo);
    git(["init", "-q", "-b", "main", repo], tmpRoot);
    git(["commit", "--allow-empty", "-q", "-m", "init"], repo);
    git(["worktree", "add", "-q", wt], repo);

    const dbPath = stampStateDbPath(wt);
    ensureDir(join(dbPath, ".."));
    assert.ok(existsSync(join(repo, ".git", "stamp")));
  });
});
