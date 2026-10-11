/**
 * `stamp merge` enforcement of the AI-attribution commit-message policy
 * (AGT-1724 / GH#81).
 *
 * Drives the real `runMerge` against a scratch v3 repo (same harness
 * shape as tests/integration/merge.test.ts): the gate is opened with a
 * seeded approval, so the only thing standing between the branch and a
 * merge commit is the policy.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import { runMerge } from "../src/commands/merge.ts";
import { ATTRIBUTION_ENV_VAR } from "../src/lib/attributionPolicy.ts";
import { openDb, recordReview } from "../src/lib/db.ts";
import { ensureUserKeypair } from "../src/lib/keys.ts";
import { stampStateDbPath } from "../src/lib/paths.ts";

const ATTRIBUTED_MSG =
  "add feature\n\nSome body.\n\nClaude-Session: https://example.invalid/session\n";

function git(repo: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd: repo,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

interface Harness {
  repo: string;
  cleanup: () => void;
}

function setupHarness(opts: {
  featureMessage: string;
  /** Extra YAML appended to .stamp/config.yml. */
  extraConfig?: string;
  /** Commit landed on main BEFORE the feature branch is cut. */
  mainHistoryMessage?: string;
}): Harness {
  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-merge-attr-"));
  const repo = path.join(root, "repo");
  const home = path.join(root, "home");
  mkdirSync(repo, { recursive: true });
  mkdirSync(home, { recursive: true });
  const prevHome = process.env["HOME"];
  process.env["HOME"] = home;

  git(repo, ["init", "-q", "-b", "main"]);
  git(repo, ["config", "user.name", "Test"]);
  git(repo, ["config", "user.email", "test@example.invalid"]);
  git(repo, ["config", "commit.gpgsign", "false"]);
  mkdirSync(path.join(repo, ".stamp", "reviewers"), { recursive: true });
  mkdirSync(path.join(repo, ".stamp", "trusted-keys"), { recursive: true });
  writeFileSync(
    path.join(repo, ".stamp", "config.yml"),
    [
      "branches:",
      "  main:",
      "    required: [security]",
      "reviewers:",
      "  security:",
      "    prompt: .stamp/reviewers/security.md",
      "    tools: []",
      opts.extraConfig ?? "",
      "",
    ].join("\n"),
  );
  writeFileSync(
    path.join(repo, ".stamp", "reviewers", "security.md"),
    "You are the security reviewer.\n",
  );
  const { keypair } = ensureUserKeypair();
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", keypair.fingerprint.replace(/:/g, "_") + ".pub"),
    keypair.publicKeyPem,
  );
  writeFileSync(path.join(repo, "README.md"), "initial\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "initial"]);

  if (opts.mainHistoryMessage) {
    writeFileSync(path.join(repo, "history.txt"), "old\n");
    git(repo, ["add", "-A"]);
    git(repo, ["commit", "-q", "-m", opts.mainHistoryMessage]);
  }

  git(repo, ["checkout", "-q", "-b", "feature"]);
  writeFileSync(path.join(repo, "feature.txt"), "hello\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", opts.featureMessage]);
  git(repo, ["checkout", "-q", "main"]);

  const base = git(repo, ["rev-parse", "main"]).trim();
  const head = git(repo, ["rev-parse", "feature"]).trim();
  const db = openDb(stampStateDbPath(repo));
  try {
    recordReview(db, {
      reviewer: "security",
      base_sha: base,
      head_sha: head,
      verdict: "approved",
      issues: "ok",
    });
  } finally {
    db.close();
  }

  return {
    repo,
    cleanup: () => {
      process.env["HOME"] = prevHome;
      rmSync(root, { recursive: true, force: true });
    },
  };
}

function merge(repo: string): void {
  const prev = process.cwd();
  process.chdir(repo);
  try {
    runMerge({ branch: "feature", into: "main", yes: true });
  } finally {
    process.chdir(prev);
  }
}

function isMergeCommit(repo: string, ref: string): boolean {
  const parents = git(repo, ["rev-list", "--parents", "-n", "1", ref]).trim().split(" ");
  return parents.length === 3;
}

describe("stamp merge: AI-attribution policy (AGT-1724)", () => {
  let prevEnv: string | undefined;
  beforeEach(() => {
    prevEnv = process.env[ATTRIBUTION_ENV_VAR];
    delete process.env[ATTRIBUTION_ENV_VAR];
    process.env["STAMP_REQUIRE_HUMAN_MERGE"] = "0";
  });
  afterEach(() => {
    if (prevEnv === undefined) delete process.env[ATTRIBUTION_ENV_VAR];
    else process.env[ATTRIBUTION_ENV_VAR] = prevEnv;
  });

  it("refuses a branch with a Claude-Session trailer, names the SHA, leaves main untouched", () => {
    process.env[ATTRIBUTION_ENV_VAR] = "1";
    const h = setupHarness({ featureMessage: ATTRIBUTED_MSG });
    try {
      const before = git(h.repo, ["rev-parse", "main"]).trim();
      const offending = git(h.repo, ["rev-parse", "feature"]).trim();
      assert.throws(
        () => merge(h.repo),
        (err: unknown) => {
          const msg = err instanceof Error ? err.message : String(err);
          assert.match(msg, /AI-agent attribution is not allowed/);
          assert.ok(msg.includes(offending.slice(0, 12)), msg);
          assert.match(msg, /\[claude-session-trailer\]/);
          assert.match(msg, /Fix: on feature, reword/);
          return true;
        },
      );
      assert.equal(git(h.repo, ["rev-parse", "main"]).trim(), before);
      assert.equal(git(h.repo, ["status", "--porcelain"]).trim(), "");
    } finally {
      h.cleanup();
    }
  });

  it("merges the same branch when the policy is off (default)", () => {
    const h = setupHarness({ featureMessage: ATTRIBUTED_MSG });
    try {
      merge(h.repo);
      assert.ok(isMergeCommit(h.repo, "main"));
    } finally {
      h.cleanup();
    }
  });

  it("merges a clean branch with the policy on", () => {
    process.env[ATTRIBUTION_ENV_VAR] = "1";
    const h = setupHarness({ featureMessage: "add feature\n\nplain body\n" });
    try {
      merge(h.repo);
      assert.ok(isMergeCommit(h.repo, "main"));
    } finally {
      h.cleanup();
    }
  });

  it("ignores attribution already in the target branch's history", () => {
    process.env[ATTRIBUTION_ENV_VAR] = "1";
    const h = setupHarness({
      featureMessage: "add feature\n",
      mainHistoryMessage: "old commit\n\nCo-Authored-By: Claude <noreply@anthropic.com>\n",
    });
    try {
      merge(h.repo);
      assert.ok(isMergeCommit(h.repo, "main"));
    } finally {
      h.cleanup();
    }
  });

  it("per-repo enabled: true turns it on without the env var", () => {
    const h = setupHarness({
      featureMessage: ATTRIBUTED_MSG,
      extraConfig: "commit_policy:\n  forbid_ai_attribution:\n    enabled: true",
    });
    try {
      assert.throws(() => merge(h.repo), /AI-agent attribution is not allowed/);
    } finally {
      h.cleanup();
    }
  });

  it("per-repo enabled: false overrides the env var", () => {
    process.env[ATTRIBUTION_ENV_VAR] = "1";
    const h = setupHarness({
      featureMessage: ATTRIBUTED_MSG,
      extraConfig: "commit_policy:\n  forbid_ai_attribution:\n    enabled: false",
    });
    try {
      merge(h.repo);
      assert.ok(isMergeCommit(h.repo, "main"));
    } finally {
      h.cleanup();
    }
  });

  it("per-repo extra_patterns are enforced", () => {
    process.env[ATTRIBUTION_ENV_VAR] = "1";
    const h = setupHarness({
      featureMessage: "add feature\n\nAssisted-By: some-agent\n",
      extraConfig:
        "commit_policy:\n  forbid_ai_attribution:\n    extra_patterns:\n      - '^Assisted-By:'",
    });
    try {
      assert.throws(() => merge(h.repo), /extra_patterns\[0\]/);
    } finally {
      h.cleanup();
    }
  });

  it("invalid commit_policy config refuses the merge with a clear error", () => {
    const h = setupHarness({
      featureMessage: "add feature\n",
      extraConfig:
        "commit_policy:\n  forbid_ai_attribution:\n    enabled: 'yes'",
    });
    try {
      assert.throws(() => merge(h.repo), /invalid commit_policy/);
    } finally {
      h.cleanup();
    }
  });
});
