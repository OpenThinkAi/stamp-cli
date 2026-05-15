/**
 * Patch-id stability tests. These pin the load-bearing property that
 * makes PR-check mode work: the same change content produces the same
 * patch-id across squash, rebase, and merge-commit.
 *
 * Builds a small temp git repo per test (real git, no mocks) so the
 * properties we assert are the ones git itself guarantees — not a
 * unit-test imitation of git's behavior. The cost is ~hundreds of ms
 * per test for git subprocess overhead; acceptable for a primitive
 * this load-bearing.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { patchIdForRevspec, patchIdForSpan } from "../src/lib/patchId.ts";

interface Repo {
  path: string;
  cleanup: () => void;
}

function git(repo: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd: repo,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function initRepo(): Repo {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-patchid-"));
  git(dir, ["init", "-q", "-b", "main"]);
  // Deterministic identity so commits don't fail on CI hosts without
  // a global git config, and so the test isn't sensitive to author
  // metadata (patch-id ignores it anyway, but no need to vary).
  git(dir, ["config", "user.name", "Test"]);
  git(dir, ["config", "user.email", "test@example.invalid"]);
  git(dir, ["config", "commit.gpgsign", "false"]);
  // Seed an initial commit so we have a base to diff from.
  writeFileSync(path.join(dir, "README.md"), "initial\n");
  git(dir, ["add", "-A"]);
  git(dir, ["commit", "-q", "-m", "initial"]);
  return { path: dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function writeFile(repo: string, rel: string, contents: string): void {
  const full = path.join(repo, rel);
  mkdirSync(path.dirname(full), { recursive: true });
  writeFileSync(full, contents);
}

function commit(repo: string, message: string): void {
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", message]);
}

describe("patchIdForRevspec", () => {
  it("returns a 40-hex patch-id and resolved base/head SHAs", () => {
    const r = initRepo();
    try {
      git(r.path, ["checkout", "-q", "-b", "feature"]);
      writeFile(r.path, "a.txt", "hello\n");
      commit(r.path, "add a");

      const result = patchIdForRevspec("main..HEAD", r.path);
      assert.match(result.patch_id, /^[0-9a-f]{40}$/);
      assert.match(result.base_sha, /^[0-9a-f]{40}$/);
      assert.match(result.head_sha, /^[0-9a-f]{40}$/);
    } finally {
      r.cleanup();
    }
  });

  it("throws on an empty diff (nothing to attest)", () => {
    const r = initRepo();
    try {
      // main..main has no diff. Empty patch-id input → empty stdout
      // from git patch-id → our guard fires.
      assert.throws(
        () => patchIdForRevspec("main..main", r.path),
        /empty diff/,
      );
    } finally {
      r.cleanup();
    }
  });

  it("throws on an invalid revspec (no `..` separator)", () => {
    const r = initRepo();
    try {
      assert.throws(
        () => patchIdForRevspec("not-a-revspec", r.path),
        /revspec/,
      );
    } finally {
      r.cleanup();
    }
  });
});

describe("patchIdForSpan — stability across history rewrites", () => {
  it("squash: 3 commits collapsed into 1 → same patch-id", () => {
    const r = initRepo();
    try {
      git(r.path, ["checkout", "-q", "-b", "feature"]);
      writeFile(r.path, "a.txt", "line1\n");
      commit(r.path, "add a — line1");
      writeFile(r.path, "a.txt", "line1\nline2\n");
      commit(r.path, "add a — line2");
      writeFile(r.path, "a.txt", "line1\nline2\nline3\n");
      commit(r.path, "add a — line3");

      const beforeSquash = patchIdForRevspec("main..HEAD", r.path);

      // Squash the three commits into one using --soft + amend.
      git(r.path, ["reset", "--soft", "main"]);
      git(r.path, ["commit", "-q", "-m", "add a (squashed)"]);

      const afterSquash = patchIdForRevspec("main..HEAD", r.path);

      assert.equal(
        afterSquash.patch_id,
        beforeSquash.patch_id,
        "squashing the same diff content must not change patch-id",
      );
      // Sanity: the head SHA DID change (different commit), so we
      // know we're not just trivially comparing the same commit.
      assert.notEqual(afterSquash.head_sha, beforeSquash.head_sha);
    } finally {
      r.cleanup();
    }
  });

  it("rebase: same commits replayed on advanced main → same patch-id", () => {
    const r = initRepo();
    try {
      git(r.path, ["checkout", "-q", "-b", "feature"]);
      writeFile(r.path, "feature.txt", "x\n");
      commit(r.path, "add feature.txt");

      const beforeRebase = patchIdForRevspec("main..HEAD", r.path);

      // Advance main with an unrelated commit.
      git(r.path, ["checkout", "-q", "main"]);
      writeFile(r.path, "other.txt", "y\n");
      commit(r.path, "unrelated change on main");
      git(r.path, ["checkout", "-q", "feature"]);

      // Rebase feature onto the new main.
      git(r.path, ["rebase", "-q", "main"]);

      const afterRebase = patchIdForRevspec("main..HEAD", r.path);

      assert.equal(
        afterRebase.patch_id,
        beforeRebase.patch_id,
        "rebasing onto an advanced base with no conflicts must preserve patch-id",
      );
      // The feature's HEAD has a NEW commit SHA (rebase rewrote it).
      assert.notEqual(afterRebase.head_sha, beforeRebase.head_sha);
      // And the base has advanced.
      assert.notEqual(afterRebase.base_sha, beforeRebase.base_sha);
    } finally {
      r.cleanup();
    }
  });

  it("different content → different patch-id (sanity)", () => {
    const r = initRepo();
    try {
      git(r.path, ["checkout", "-q", "-b", "feature-a"]);
      writeFile(r.path, "a.txt", "one\n");
      commit(r.path, "add a");
      const idA = patchIdForRevspec("main..HEAD", r.path).patch_id;

      git(r.path, ["checkout", "-q", "main"]);
      git(r.path, ["checkout", "-q", "-b", "feature-b"]);
      writeFile(r.path, "b.txt", "two\n");
      commit(r.path, "add b");
      const idB = patchIdForRevspec("main..HEAD", r.path).patch_id;

      assert.notEqual(idA, idB, "different changes must produce different patch-ids");
    } finally {
      r.cleanup();
    }
  });

  it("patchIdForSpan accepts pre-resolved SHAs directly", () => {
    const r = initRepo();
    try {
      git(r.path, ["checkout", "-q", "-b", "feature"]);
      writeFile(r.path, "a.txt", "x\n");
      commit(r.path, "add a");

      const base = git(r.path, ["rev-parse", "main"]).trim();
      const head = git(r.path, ["rev-parse", "HEAD"]).trim();

      const direct = patchIdForSpan(base, head, r.path);
      const viaRevspec = patchIdForRevspec("main..HEAD", r.path).patch_id;

      assert.equal(direct, viaRevspec);
    } finally {
      r.cleanup();
    }
  });
});
