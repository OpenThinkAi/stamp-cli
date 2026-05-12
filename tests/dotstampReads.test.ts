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

  it("excludes deleted .stamp/* paths from the requirement (unsatisfiable otherwise)", () => {
    // A deleted file can't be Read at HEAD — demanding the reviewer
    // Read it would strand the agent in an unsatisfiable retry loop.
    // Trust-anchor *removal* is gated by the operator-confirmation
    // prompt at merge time (audit H1's load-bearing defense); this
    // check is for *modification* coverage. Pin: build a diff that
    // deletes one .stamp/* file and modifies another, and assert
    // only the modified one is required.
    git(["rm", "-q", join(".stamp", "reviewers", "security.md")], repo);
    writeFileSync(join(repo, ".stamp", "config.yml"), "branches: { main: {} }\n");
    git(["add", "."], repo);
    git(["commit", "-q", "-m", "delete one + modify other"], repo);
    const afterDelete = git(["rev-parse", "HEAD"], repo).trim();

    const readPaths = new Set([".stamp/config.yml"]);
    const missing = findMissingDotstampReads(
      headSha,
      afterDelete,
      repo,
      readPaths,
    );
    // Only .stamp/config.yml should be required; the deleted file
    // is filtered out via --diff-filter=AMR.
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

  it("rejects non-boolean values and includes the offending value in the error", () => {
    // The "got <value>" suffix matches the established convention from
    // serverConfig.ts and helps an operator pasting the YAML find the
    // bad line without grep-by-eye.
    assert.throws(
      () =>
        parseConfigFromYaml(cfg('\n    enforce_reads_on_dotstamp: "yes"')),
      /enforce_reads_on_dotstamp must be a boolean.*got "yes"/,
    );
    assert.throws(
      () => parseConfigFromYaml(cfg("\n    enforce_reads_on_dotstamp: 1")),
      /enforce_reads_on_dotstamp must be a boolean.*got 1/,
    );
  });
});

describe("parseConfigFromYaml — per-reviewer budget overrides", () => {
  const cfg = (extra: string) => `
branches:
  main: { required: [r] }
reviewers:
  r:
    prompt: ./r.md${extra}
`;

  it("omits both fields when absent", () => {
    const c = parseConfigFromYaml(cfg(""));
    assert.equal(c.reviewers.r!.max_turns, undefined);
    assert.equal(c.reviewers.r!.timeout_ms, undefined);
  });

  it("accepts positive integers for max_turns and timeout_ms", () => {
    const c = parseConfigFromYaml(
      cfg("\n    max_turns: 20\n    timeout_ms: 600000"),
    );
    assert.equal(c.reviewers.r!.max_turns, 20);
    assert.equal(c.reviewers.r!.timeout_ms, 600000);
  });

  it("rejects zero, negative, non-integer, and non-numeric values", () => {
    for (const [bad, label] of [
      ["0", "zero"],
      ["-1", "negative"],
      ["1.5", "fractional"],
      ['"20"', "string"],
    ] as const) {
      assert.throws(
        () => parseConfigFromYaml(cfg(`\n    max_turns: ${bad}`)),
        /max_turns must be a positive integer/,
        `expected ${label} max_turns (${bad}) to be rejected`,
      );
      assert.throws(
        () => parseConfigFromYaml(cfg(`\n    timeout_ms: ${bad}`)),
        /timeout_ms must be a positive integer/,
        `expected ${label} timeout_ms (${bad}) to be rejected`,
      );
    }
  });
});
