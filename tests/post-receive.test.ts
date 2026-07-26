/**
 * Tests for the bare-repo HEAD-branch resolution in the post-receive
 * mirror hook. The hook reads `.stamp/mirror.yml` from the bare repo's
 * default branch when handling tag pushes; pinning the resolution
 * to `git symbolic-ref HEAD` (with a `refs/heads/main` fallback) is
 * what lets stamp-protected repos with non-`main` defaults — `master`,
 * `trunk`, anything — mirror their tag pushes without silently dropping
 * the mirror leg.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import {
  publickeyRepairHint,
  readMirrorConfigFromHeadBranch,
} from "../src/hooks/post-receive.ts";

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: "pipe" });
}

const MIRROR_YML = `github:
  repo: example/mirror
  branches: [main, master, trunk]
  tags: ["v*"]
`;

describe("readMirrorConfigFromHeadBranch", () => {
  let bare: string;
  let work: string;
  let prevCwd: string;

  beforeEach(() => {
    prevCwd = process.cwd();
    bare = realpathSync(mkdtempSync(join(tmpdir(), "stamp-postrecv-bare-")));
    work = realpathSync(mkdtempSync(join(tmpdir(), "stamp-postrecv-work-")));
    git(["init", "-q", "--bare", bare], process.cwd());
  });

  afterEach(() => {
    process.chdir(prevCwd);
    rmSync(bare, { recursive: true, force: true });
    rmSync(work, { recursive: true, force: true });
  });

  function seedBranchWithMirrorYml(branch: string): void {
    git(["init", "-q", "-b", branch, work], process.cwd());
    git(["config", "user.email", "t@example.com"], work);
    git(["config", "user.name", "Test"], work);
    execFileSync("mkdir", ["-p", join(work, ".stamp")], { stdio: "pipe" });
    writeFileSync(join(work, ".stamp", "mirror.yml"), MIRROR_YML);
    git(["add", "."], work);
    git(["commit", "-q", "-m", "seed mirror.yml"], work);
    git(["remote", "add", "origin", bare], work);
    git(["push", "-q", "origin", branch], work);
    git(["symbolic-ref", "HEAD", `refs/heads/${branch}`], bare);
  }

  it("resolves HEAD to the operator's chosen default branch (non-main)", () => {
    // The bug this guards against: hardcoded refs/heads/main meant a bare
    // repo with HEAD → refs/heads/master silently returned null and
    // skipped tag mirroring without a log line. Now the symbolic-ref
    // resolution finds master and reads mirror.yml from there.
    seedBranchWithMirrorYml("master");
    process.chdir(bare);
    const cfg = readMirrorConfigFromHeadBranch();
    assert.ok(cfg, "expected mirror config to be loaded from HEAD branch");
    assert.equal(cfg.github?.repo, "example/mirror");
    assert.deepEqual(cfg.github?.tags, ["v*"]);
  });

  it("still works on the main-default case (back-compat)", () => {
    seedBranchWithMirrorYml("main");
    process.chdir(bare);
    const cfg = readMirrorConfigFromHeadBranch();
    assert.ok(cfg, "expected mirror config to be loaded from main");
    assert.equal(cfg.github?.repo, "example/mirror");
  });

  it("warns and returns null when HEAD points at a non-existent ref", () => {
    // Empty bare repo: HEAD is set (default refs/heads/main) but no
    // commits exist, so rev-parse fails. The helper must warn-and-skip
    // rather than silently return null — that visibility is the second
    // half of the fix (the symbolic-ref switch is the first half).
    process.chdir(bare);
    const captured: string[] = [];
    const originalWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((chunk: string | Uint8Array) => {
      captured.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
      return true;
    }) as typeof process.stderr.write;
    try {
      const cfg = readMirrorConfigFromHeadBranch();
      assert.equal(cfg, null);
    } finally {
      process.stderr.write = originalWrite;
    }
    const out = captured.join("");
    assert.match(out, /mirror:.*doesn't resolve/);
  });
});

describe("publickeyRepairHint", () => {
  it("names the repair when GitHub refuses the key (issue #64)", () => {
    // Real stderr shape from a mirror push against a repo with no deploy
    // key registered. The generic "retry from a host with the deploy key"
    // advice is a dead end here — no host has a key GitHub will accept —
    // so the hint must name --migrate-bypass and the resync flag.
    const stderr =
      `git@github.com: Permission denied (publickey).\n` +
      `fatal: Could not read from remote repository.`;
    const hint = publickeyRepairHint(stderr);
    assert.ok(hint);
    assert.match(hint, /stamp provision --migrate-bypass/);
    assert.match(hint, /--resync-mirror/);
  });

  it("matches case-insensitively", () => {
    assert.ok(publickeyRepairHint("PERMISSION DENIED (PUBLICKEY)"));
  });

  it("stays silent on unrelated push failures", () => {
    assert.equal(
      publickeyRepairHint(
        `! [rejected] main -> main (non-fast-forward)\nerror: failed to push some refs`,
      ),
      null,
    );
    assert.equal(publickeyRepairHint(""), null);
  });
});
