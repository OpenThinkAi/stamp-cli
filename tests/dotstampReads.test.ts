/**
 * Tests for the verdict-↔-trace consistency check on `.stamp/*` changes
 * (audit H1 defense-in-depth follow-on).
 *
 * The threat: a prompt-injected reviewer approves a diff that touches its
 * own trust anchors (`.stamp/config.yml`, `.stamp/reviewers/<name>.md`,
 * `.stamp/trusted-keys/*`) without actually inspecting the modified
 * files. With `enforce_reads_on_dotstamp: true` on the reviewer, an
 * approval that didn't include `Read` calls covering the modified
 * `.stamp/*` paths is overridden to `changes_requested` so the agent
 * loop sees the discrepancy and retries.
 *
 * Tests use a real git repo so `git diff --name-only` reflects what the
 * production helper would see. The reviewer agent itself is not invoked;
 * we test the post-verdict helper (`findMissingDotstampReads`) against
 * controlled `readPaths` sets and assert the override mechanics in a
 * unit-shaped way.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import { findMissingDotstampReads } from "../src/lib/reviewer.ts";
import { parseConfigFromYaml } from "../src/lib/config.ts";

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: "pipe" });
}

describe("findMissingDotstampReads", () => {
  let tmp: string;
  let repo: string;
  let baseSha: string;
  let headSha: string;

  beforeEach(() => {
    tmp = realpathSync(mkdtempSync(join(tmpdir(), "stamp-dotstamp-")));
    repo = join(tmp, "repo");
    mkdirSync(repo);
    git(["init", "-q", "-b", "main", repo], tmp);
    git(["config", "user.email", "t@example.com"], repo);
    git(["config", "user.name", "Test"], repo);

    // Base commit: just a placeholder file.
    writeFileSync(join(repo, "README.md"), "# r");
    git(["add", "."], repo);
    git(["commit", "-q", "-m", "base"], repo);
    baseSha = git(["rev-parse", "HEAD"], repo).trim();

    // Head commit: modify two `.stamp/*` paths and one non-stamp path.
    mkdirSync(join(repo, ".stamp", "reviewers"), { recursive: true });
    writeFileSync(join(repo, ".stamp", "config.yml"), "branches:\n");
    writeFileSync(join(repo, ".stamp", "reviewers", "security.md"), "# sec");
    writeFileSync(join(repo, "src.txt"), "code");
    git(["add", "."], repo);
    git(["commit", "-q", "-m", "head"], repo);
    headSha = git(["rev-parse", "HEAD"], repo).trim();
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("returns empty when the reviewer Read every modified .stamp/* path", () => {
    const readPaths = new Set([
      ".stamp/config.yml",
      ".stamp/reviewers/security.md",
    ]);
    const missing = findMissingDotstampReads(baseSha, headSha, repo, readPaths);
    assert.deepEqual(missing, []);
  });

  it("returns the missing paths when the reviewer skipped some", () => {
    const readPaths = new Set([".stamp/config.yml"]);
    const missing = findMissingDotstampReads(baseSha, headSha, repo, readPaths);
    assert.deepEqual(missing, [".stamp/reviewers/security.md"]);
  });

  it("returns all .stamp/* paths when the reviewer Read nothing", () => {
    const missing = findMissingDotstampReads(baseSha, headSha, repo, new Set());
    assert.deepEqual(missing, [
      ".stamp/config.yml",
      ".stamp/reviewers/security.md",
    ]);
  });

  it("ignores non-.stamp paths in the diff", () => {
    // src.txt is in the diff but doesn't trigger the requirement. Pin
    // so a future broadening of the prefix doesn't silently capture
    // unrelated paths.
    const readPaths = new Set([
      ".stamp/config.yml",
      ".stamp/reviewers/security.md",
    ]);
    const missing = findMissingDotstampReads(baseSha, headSha, repo, readPaths);
    assert.deepEqual(missing, []);
  });

  it("ignores extra Read calls outside .stamp/", () => {
    // Reviewer Read both the .stamp/* paths AND an unrelated source
    // file. The extras don't affect the check; only .stamp/ coverage
    // matters.
    const readPaths = new Set([
      ".stamp/config.yml",
      ".stamp/reviewers/security.md",
      "src.txt",
      "README.md",
    ]);
    const missing = findMissingDotstampReads(baseSha, headSha, repo, readPaths);
    assert.deepEqual(missing, []);
  });

  it("returns empty (fail-open) when git fails", () => {
    // Synthetic SHAs that don't exist in the repo. git diff returns
    // non-zero and runGit throws; the helper must swallow and return
    // empty so a transient git glitch doesn't block an otherwise-fine
    // approval.
    const fakeSha = "0".repeat(40);
    const missing = findMissingDotstampReads(fakeSha, fakeSha, repo, new Set());
    assert.deepEqual(missing, []);
  });

  it("returns empty when the diff doesn't touch .stamp/ at all", () => {
    // New base→head pair where only src.txt changes. .stamp/ untouched
    // → no requirement to have Read anything in .stamp/.
    writeFileSync(join(repo, "src.txt"), "code v2");
    git(["add", "."], repo);
    git(["commit", "-q", "-m", "tweak src"], repo);
    const newHead = git(["rev-parse", "HEAD"], repo).trim();
    const missing = findMissingDotstampReads(headSha, newHead, repo, new Set());
    assert.deepEqual(missing, []);
  });
});

describe("parseConfigFromYaml — enforce_reads_on_dotstamp", () => {
  const cfg = (extra: string) => `
branches:
  main: { required: [r] }
reviewers:
  r:
    prompt: ./r.md${extra}
`;

  it("omits the field when not present", () => {
    const c = parseConfigFromYaml(cfg(""));
    assert.equal(c.reviewers.r!.enforce_reads_on_dotstamp, undefined);
  });

  it("accepts true / false", () => {
    assert.equal(
      parseConfigFromYaml(cfg("\n    enforce_reads_on_dotstamp: true"))
        .reviewers.r!.enforce_reads_on_dotstamp,
      true,
    );
    assert.equal(
      parseConfigFromYaml(cfg("\n    enforce_reads_on_dotstamp: false"))
        .reviewers.r!.enforce_reads_on_dotstamp,
      false,
    );
  });

  it("rejects non-boolean values", () => {
    assert.throws(
      () =>
        parseConfigFromYaml(cfg('\n    enforce_reads_on_dotstamp: "yes"')),
      /enforce_reads_on_dotstamp must be a boolean/,
    );
    assert.throws(
      () => parseConfigFromYaml(cfg("\n    enforce_reads_on_dotstamp: 1")),
      /enforce_reads_on_dotstamp must be a boolean/,
    );
  });
});
