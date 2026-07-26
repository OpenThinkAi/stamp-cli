/**
 * Shell-level tests for server/resync-mirror (issue #64).
 *
 * The verb re-feeds branch tips into a bare repo's post-receive hook so a
 * stranded mirror can catch up without waiting for the next real push.
 * These tests run the actual script against a temp git root (via the
 * STAMP_GIT_ROOT test seam) with a stub hook that records its stdin, and
 * assert both the happy paths (synthesized "<zero> <tip> <ref>" lines,
 * default-branch resolution, multi-branch) and the refusal paths
 * (argument errors exit 2, operational errors exit 1).
 */

import { strict as assert } from "node:assert";
import { execFileSync, spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

const SCRIPT = resolve(import.meta.dirname, "..", "server", "resync-mirror");
const ZERO = "0".repeat(40);

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: "pipe" });
}

describe("server/resync-mirror", () => {
  let gitRoot: string;
  let work: string;
  let bare: string;
  let hookLog: string;

  function run(args: string[]): { status: number | null; stderr: string } {
    const res = spawnSync("sh", [SCRIPT, ...args], {
      encoding: "utf8",
      env: { ...process.env, STAMP_GIT_ROOT: gitRoot },
    });
    return { status: res.status, stderr: res.stderr };
  }

  /** Install a post-receive stub that appends its stdin to hookLog. */
  function installHook(): void {
    writeFileSync(
      join(bare, "hooks", "post-receive"),
      `#!/bin/sh\ncat >> "${hookLog}"\n`,
    );
    chmodSync(join(bare, "hooks", "post-receive"), 0o755);
  }

  beforeEach(() => {
    gitRoot = realpathSync(mkdtempSync(join(tmpdir(), "stamp-resync-root-")));
    work = realpathSync(mkdtempSync(join(tmpdir(), "stamp-resync-work-")));
    bare = join(gitRoot, "myrepo.git");
    hookLog = join(gitRoot, "hook-stdin.log");
    git(["init", "-q", "--bare", bare], gitRoot);
    git(["init", "-q", "-b", "main", work], gitRoot);
    git(["config", "user.email", "t@example.com"], work);
    git(["config", "user.name", "Test"], work);
    writeFileSync(join(work, "f.txt"), "hello\n");
    git(["add", "."], work);
    git(["commit", "-q", "-m", "seed"], work);
    git(["remote", "add", "origin", bare], work);
    git(["push", "-q", "origin", "main"], work);
    git(["symbolic-ref", "HEAD", "refs/heads/main"], bare);
  });

  afterEach(() => {
    rmSync(gitRoot, { recursive: true, force: true });
    rmSync(work, { recursive: true, force: true });
  });

  it("re-feeds a named branch tip into the hook as a zero-oldsha line", () => {
    installHook();
    const tip = git(["rev-parse", "refs/heads/main"], bare).trim();
    const { status, stderr } = run(["myrepo", "main"]);
    assert.equal(status, 0, stderr);
    assert.match(stderr, /re-feeding main/);
    assert.equal(
      readFileSync(hookLog, "utf8"),
      `${ZERO} ${tip} refs/heads/main\n`,
    );
  });

  it("defaults to the HEAD branch when no branch is named", () => {
    // Non-main default, so the test proves symbolic-ref resolution rather
    // than a hardcoded "main".
    git(["branch", "trunk", "main"], bare);
    git(["symbolic-ref", "HEAD", "refs/heads/trunk"], bare);
    installHook();
    const tip = git(["rev-parse", "refs/heads/trunk"], bare).trim();
    const { status } = run(["myrepo"]);
    assert.equal(status, 0);
    assert.equal(
      readFileSync(hookLog, "utf8"),
      `${ZERO} ${tip} refs/heads/trunk\n`,
    );
  });

  it("handles multiple branches, including slash-named ones", () => {
    git(["branch", "release/1.x", "main"], bare);
    installHook();
    const tip = git(["rev-parse", "refs/heads/main"], bare).trim();
    const { status } = run(["myrepo", "main", "release/1.x"]);
    assert.equal(status, 0);
    assert.equal(
      readFileSync(hookLog, "utf8"),
      `${ZERO} ${tip} refs/heads/main\n${ZERO} ${tip} refs/heads/release/1.x\n`,
    );
  });

  it("exits 2 on flag-shaped or path-escaping repo names", () => {
    installHook();
    for (const name of ["-evil", "../escape", "a/b", ".hidden", ""]) {
      const { status } = run([name]);
      assert.equal(status, 2, `name ${JSON.stringify(name)} should exit 2`);
    }
  });

  it("exits 2 on invalid branch names without touching the hook", () => {
    installHook();
    for (const branch of ["-evil", "a..b", "bad name"]) {
      const { status } = run(["myrepo", branch]);
      assert.equal(status, 2, `branch ${JSON.stringify(branch)} should exit 2`);
    }
    assert.throws(() => readFileSync(hookLog), /ENOENT/);
  });

  it("exits 1 when the repo doesn't exist", () => {
    const { status, stderr } = run(["nope"]);
    assert.equal(status, 1);
    assert.match(stderr, /not found/);
  });

  it("exits 1 when the repo has no executable post-receive hook", () => {
    const { status, stderr } = run(["myrepo", "main"]);
    assert.equal(status, 1);
    assert.match(stderr, /no executable post-receive hook/);
  });

  it("exits 1 when the named branch doesn't exist", () => {
    installHook();
    const { status, stderr } = run(["myrepo", "does-not-exist"]);
    assert.equal(status, 1);
    assert.match(stderr, /branch 'does-not-exist' not found/);
  });
});
