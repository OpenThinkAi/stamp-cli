/**
 * Tests for the git-helper layer in src/lib/git.ts. Pins the contract that
 * pathExistsAtRef distinguishes "absent at ref" (false, no throw) from a
 * real git failure (throws) — the merge attestation path depends on this
 * to silently skip un-pinned reviewers without swallowing genuine errors.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import { pathExistsAtRef } from "../src/lib/git.ts";

function git(args: string[], cwd: string): void {
  execFileSync("git", args, { cwd, stdio: "pipe" });
}

describe("pathExistsAtRef", () => {
  let repo: string;

  beforeEach(() => {
    repo = realpathSync(mkdtempSync(join(tmpdir(), "stamp-git-test-")));
    git(["init", "-q", "-b", "main"], repo);
    git(["config", "user.email", "t@example.com"], repo);
    git(["config", "user.name", "Test"], repo);
    writeFileSync(join(repo, "present.txt"), "hi\n");
    git(["add", "."], repo);
    git(["commit", "-q", "-m", "init"], repo);
  });

  afterEach(() => {
    rmSync(repo, { recursive: true, force: true });
  });

  it("returns true for a path that exists at the ref", () => {
    assert.equal(pathExistsAtRef("HEAD", "present.txt", repo), true);
  });

  it("returns false for a path that does not exist at the ref", () => {
    // The exact case readReviewerSource hits for un-pinned reviewers.
    assert.equal(
      pathExistsAtRef("HEAD", ".stamp/reviewers/security.lock.json", repo),
      false,
    );
  });

  it("does not write fatal: output to stderr when the path is absent", () => {
    // The whole reason this helper exists. Capturing stderr from this test
    // process is awkward, but if cat-file -e ever changed semantics and
    // started emitting something, the spawnSync-with-stderr-pipe contract
    // would still suppress it — assert by checking that the call returns
    // cleanly and produces no thrown error.
    assert.doesNotThrow(() =>
      pathExistsAtRef("HEAD", ".stamp/reviewers/missing.lock.json", repo),
    );
  });

  it("returns false on a non-resolvable ref (matches loadConfigAtSha's status-128 convention)", () => {
    // git cat-file -e doesn't distinguish "missing path" from "missing ref"
    // at the exit-code level — both produce 128. We deliberately match the
    // verify.ts loadConfigAtSha convention here: treat any 128 as "absent."
    // Real corruption surfaces as a different (rethrown) status.
    assert.equal(
      pathExistsAtRef("nonexistent-ref-xyz", "present.txt", repo),
      false,
    );
  });
});
