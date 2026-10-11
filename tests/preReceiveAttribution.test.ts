/**
 * End-to-end: the server pre-receive hook enforcing the AI-attribution
 * commit-message policy (AGT-1724 / GH#81).
 *
 * Bundles src/hooks/pre-receive.ts the same way the production build
 * does (esbuild → self-contained CJS with a node shebang, the shape
 * server/Dockerfile copies into each bare repo's hooks/), installs it in
 * a scratch bare repo, and drives real `git push`es at it. The toggle is
 * passed through the pushing process's env, which local-transport
 * receive-pack hands to the hook.
 *
 * The bare repo is seeded BEFORE the hook is installed (branch creation
 * via push is rejected by design), including a commit that already
 * carries attribution — so "existing history never blocks a push" is
 * exercised for real.
 */

import { strict as assert } from "node:assert";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { buildSync } from "esbuild";

import { ATTRIBUTION_ENV_VAR } from "../src/lib/attributionPolicy.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const HOOK_SRC = path.join(HERE, "..", "src", "hooks", "pre-receive.ts");

function git(cwd: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function commit(cwd: string, file: string, message: string): string {
  writeFileSync(path.join(cwd, file), `${file} ${Date.now()} ${Math.random()}\n`);
  git(cwd, ["add", "-A"]);
  git(cwd, ["commit", "-q", "-m", message]);
  return git(cwd, ["rev-parse", "HEAD"]).trim();
}

function push(
  cwd: string,
  refspec: string,
  policyEnv: string | undefined,
): { status: number | null; stderr: string } {
  const env = { ...process.env };
  delete env[ATTRIBUTION_ENV_VAR];
  if (policyEnv !== undefined) env[ATTRIBUTION_ENV_VAR] = policyEnv;
  const r = spawnSync("git", ["push", "origin", refspec], {
    cwd,
    env,
    encoding: "utf8",
  });
  return { status: r.status, stderr: r.stderr };
}

const BASE_CONFIG = [
  "branches:",
  "  main:",
  "    required: [security]",
  "reviewers:",
  "  security:",
  "    prompt: .stamp/reviewers/security.md",
  "",
].join("\n");

describe("pre-receive: AI-attribution policy end-to-end (AGT-1724)", () => {
  let root: string;
  let bare: string;
  let work: string;

  before(() => {
    root = mkdtempSync(path.join(os.tmpdir(), "stamp-prerecv-attr-"));
    bare = path.join(root, "server.git");
    work = path.join(root, "work");

    git(root, ["init", "-q", "--bare", "-b", "main", bare]);
    git(root, ["clone", "-q", bare, work]);
    git(work, ["config", "user.name", "Test"]);
    git(work, ["config", "user.email", "test@example.invalid"]);
    git(work, ["config", "commit.gpgsign", "false"]);
    git(work, ["checkout", "-q", "-b", "main"]);

    execFileSync("mkdir", ["-p", path.join(work, ".stamp", "reviewers")]);
    writeFileSync(path.join(work, ".stamp", "config.yml"), BASE_CONFIG);
    writeFileSync(path.join(work, ".stamp", "reviewers", "security.md"), "prompt\n");
    git(work, ["add", "-A"]);
    git(work, ["commit", "-q", "-m", "seed"]);
    // Pre-existing attributed history (landed before the policy existed).
    commit(work, "old.txt", "old work\n\nClaude-Session: https://example.invalid/old\n");
    git(work, ["push", "-q", "origin", "main"]);

    // Unprotected working branch, seeded directly (creation-by-push is
    // rejected by the hook).
    git(work, ["checkout", "-q", "-b", "scratch"]);
    git(work, ["push", "-q", "origin", "scratch"]);

    // A branch whose pre-push config opts out of the policy.
    git(work, ["checkout", "-q", "-b", "optout", "main"]);
    writeFileSync(
      path.join(work, ".stamp", "config.yml"),
      BASE_CONFIG + "commit_policy:\n  forbid_ai_attribution:\n    enabled: false\n",
    );
    git(work, ["add", "-A"]);
    git(work, ["commit", "-q", "-m", "opt out of attribution policy"]);
    git(work, ["push", "-q", "origin", "optout"]);

    // Bundle + install the hook (mirrors tsup's hook build: CJS, deps inlined).
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

  it("rejects a newly pushed attributed commit with a readable error", () => {
    git(work, ["checkout", "-q", "scratch"]);
    const before = git(bare, ["rev-parse", "scratch"]).trim();
    const bad = commit(
      work,
      "a.txt",
      "agent work\n\nCo-Authored-By: Claude <noreply@anthropic.com>\n",
    );
    const r = push(work, "scratch", "1");
    assert.notEqual(r.status, 0, r.stderr);
    assert.match(r.stderr, /stamp-verify: rejecting refs\/heads\/scratch/);
    assert.match(r.stderr, /AI-agent attribution is not allowed/);
    assert.ok(r.stderr.includes(bad.slice(0, 12)), r.stderr);
    assert.match(r.stderr, /\[co-authored-by-claude\]/);
    assert.match(r.stderr, /Fix: reword/);
    assert.equal(git(bare, ["rev-parse", "scratch"]).trim(), before);
    git(work, ["reset", "-q", "--hard", before]);
  });

  it("accepts the same push when the policy is off (default)", () => {
    git(work, ["checkout", "-q", "scratch"]);
    const sha = commit(work, "b.txt", "agent work\n\nClaude-Session: abc\n");
    const r = push(work, "scratch", undefined);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(git(bare, ["rev-parse", "scratch"]).trim(), sha);
  });

  it("accepts a clean push even though existing history carries attribution", () => {
    git(work, ["checkout", "-q", "scratch"]);
    const sha = commit(work, "c.txt", "plain human commit\n");
    const r = push(work, "scratch", "1");
    assert.equal(r.status, 0, r.stderr);
    assert.equal(git(bare, ["rev-parse", "scratch"]).trim(), sha);
  });

  it("checks every introduced commit, not just the tip", () => {
    git(work, ["checkout", "-q", "scratch"]);
    const before = git(bare, ["rev-parse", "scratch"]).trim();
    const bad = commit(work, "d.txt", "x\n\nGenerated with [Claude Code](https://example.invalid)\n");
    commit(work, "e.txt", "clean tip\n");
    const r = push(work, "scratch", "1");
    assert.notEqual(r.status, 0);
    assert.ok(r.stderr.includes(bad.slice(0, 12)), r.stderr);
    git(work, ["reset", "-q", "--hard", before]);
  });

  it("per-repo enabled: false at the pre-push tip overrides the env var", () => {
    git(work, ["checkout", "-q", "optout"]);
    const sha = commit(work, "f.txt", "x\n\nClaude-Session: abc\n");
    const r = push(work, "optout", "1");
    assert.equal(r.status, 0, r.stderr);
    assert.equal(git(bare, ["rev-parse", "optout"]).trim(), sha);
  });

  it("applies to protected branches too, ahead of stamp signature checks", () => {
    git(work, ["checkout", "-q", "main"]);
    const before = git(bare, ["rev-parse", "main"]).trim();
    commit(work, "g.txt", "direct\n\nClaude-Session: abc\n");
    const r = push(work, "main", "1");
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /AI-agent attribution is not allowed/);
    assert.equal(git(bare, ["rev-parse", "main"]).trim(), before);
    git(work, ["reset", "-q", "--hard", before]);
  });
});
