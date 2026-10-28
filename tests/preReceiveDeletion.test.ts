/**
 * End-to-end: the server pre-receive hook refuses to delete protected
 * branches (AGT-2254).
 *
 * On a stamp server the hook is the only gate, and recreating a protected
 * branch by push is rejected by design — so an allowed `git push origin
 * :main` would leave the repo broken until an operator re-seeds it. The
 * hook is bundled the same way the production build does and installed
 * in a scratch bare repo, which is seeded BEFORE the hook is installed
 * (branch creation via push is rejected).
 */

import { strict as assert } from "node:assert";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { buildSync } from "esbuild";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const HOOK_SRC = path.join(HERE, "..", "src", "hooks", "pre-receive.ts");

function git(cwd: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function push(cwd: string, refspec: string): { status: number | null; stderr: string } {
  const r = spawnSync("git", ["push", "origin", refspec], { cwd, encoding: "utf8" });
  return { status: r.status, stderr: r.stderr };
}

function refExists(bare: string, ref: string): boolean {
  return (
    spawnSync("git", ["rev-parse", "--verify", "--quiet", ref], { cwd: bare }).status === 0
  );
}

// main is protected by exact key; release/* by a glob that only the
// default branch's config carries.
const MAIN_CONFIG = [
  "branches:",
  "  main:",
  "    required: [security]",
  "  release/*:",
  "    required: [security]",
  "reviewers:",
  "  security:",
  "    prompt: .stamp/reviewers/security.md",
  "",
].join("\n");

const BARE_CONFIG = [
  "branches:",
  "  main:",
  "    required: [security]",
  "reviewers:",
  "  security:",
  "    prompt: .stamp/reviewers/security.md",
  "",
].join("\n");

describe("pre-receive: protected-branch deletion (AGT-2254)", () => {
  let root: string;
  let bare: string;
  let work: string;

  before(() => {
    root = mkdtempSync(path.join(os.tmpdir(), "stamp-prerecv-del-"));
    bare = path.join(root, "server.git");
    work = path.join(root, "work");

    git(root, ["init", "-q", "--bare", "-b", "main", bare]);
    git(root, ["clone", "-q", bare, work]);
    git(work, ["config", "user.name", "Test"]);
    git(work, ["config", "user.email", "test@example.invalid"]);
    git(work, ["config", "commit.gpgsign", "false"]);
    git(work, ["checkout", "-q", "-b", "main"]);

    mkdirSync(path.join(work, ".stamp", "reviewers"), { recursive: true });
    writeFileSync(path.join(work, ".stamp", "reviewers", "security.md"), "prompt\n");

    // release/1.x is created from a tree whose own config has no
    // release/* rule — only the default branch's config protects it.
    writeFileSync(path.join(work, ".stamp", "config.yml"), BARE_CONFIG);
    git(work, ["add", "-A"]);
    git(work, ["commit", "-q", "-m", "seed"]);
    git(work, ["branch", "release/1.x"]);

    writeFileSync(path.join(work, ".stamp", "config.yml"), MAIN_CONFIG);
    git(work, ["add", "-A"]);
    git(work, ["commit", "-q", "-m", "protect release/*"]);

    git(work, ["branch", "scratch"]);
    git(work, ["push", "-q", "origin", "main", "release/1.x", "scratch"]);

    const hookPath = path.join(bare, "hooks", "pre-receive");
    buildSync({
      entryPoints: [HOOK_SRC],
      bundle: true,
      platform: "node",
      format: "cjs",
      target: "node22",
      outfile: hookPath,
      banner: { js: "#!/usr/bin/env node" },
      logLevel: "silent",
    });
    chmodSync(hookPath, 0o755);
  });

  after(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it("rejects deleting the protected default branch", () => {
    const r = push(work, ":main");
    assert.notEqual(r.status, 0, r.stderr);
    assert.match(r.stderr, /stamp-verify: rejecting refs\/heads\/main/);
    assert.match(r.stderr, /deleting a protected branch is not allowed/);
    assert.ok(refExists(bare, "refs/heads/main"));
  });

  it("rejects deleting a branch protected only by the default branch's glob rule", () => {
    const r = push(work, ":release/1.x");
    assert.notEqual(r.status, 0, r.stderr);
    assert.match(r.stderr, /deleting a protected branch is not allowed/);
    assert.ok(refExists(bare, "refs/heads/release/1.x"));
  });

  it("still allows deleting an unprotected branch", () => {
    const r = push(work, ":scratch");
    assert.equal(r.status, 0, r.stderr);
    assert.ok(!refExists(bare, "refs/heads/scratch"));
  });
});
