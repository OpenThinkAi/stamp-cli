/**
 * AGT-696 / issue #57: `stamp review` must leave a minted PR-attestation
 * ref (`refs/stamp/attestations/<patch-id>`) whenever it reaches an open
 * gate in attested-pr mode — including AFTER a re-review over a NEW span
 * (local base advanced, so the cumulative diff and therefore the
 * patch-id changed). Before the fix only `stamp attest` minted the ref,
 * so a re-review reopened the gate (verdict cache) while no attestation
 * existed for the new patch-id, and the PR's stamp/verify-attestation
 * check failed with "no attestation found".
 *
 * These tests drive `maybeMintPrAttestation` (the review-tail hook) and
 * `runStatus` directly against a real temp stamp repo — real git
 * commits, real .stamp/config.yml + reviewer, real signing key,
 * pre-seeded verdicts in the local state.db — so no LLM is invoked.
 *
 * v2 envelopes are what a local-key attested-pr repo produces; the 2.x
 * strict `parseEnvelope` rejects v2, so ref existence is asserted via
 * the raw-blob reader (same approach as attest.test.ts).
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { maybeMintPrAttestation } from "../src/commands/review.ts";
import { runStatus } from "../src/commands/status.ts";
import { loadConfig, findBranchRule } from "../src/lib/config.ts";
import { openDb, recordReview } from "../src/lib/db.ts";
import { resolveDiff } from "../src/lib/git.ts";
import { patchIdForSpan } from "../src/lib/patchId.ts";
import { stampConfigFile, stampStateDbPath } from "../src/lib/paths.ts";
import {
  attestationRefName,
  readAttestationBlobBytes,
} from "../src/lib/prAttestation.ts";

function git(repo: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd: repo,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

interface Harness {
  repo: string;
  prevHome: string | undefined;
  cleanup: () => void;
}

/**
 * A local-key attested-pr repo: main requires the `security` reviewer,
 * a reviewer prompt exists at base, and the stamp-verify workflow file
 * is present (the signal that a PR check will look up the attestation
 * ref). `withWorkflow: false` drops the workflow to exercise the
 * mode-gate (no ref expected).
 */
function setupHarness(opts?: {
  withWorkflow?: boolean;
  reviewServer?: boolean;
}): Harness {
  const withWorkflow = opts?.withWorkflow ?? true;
  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-remint-"));
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
  const branchRuleYaml = opts?.reviewServer
    ? [
        "branches:",
        "  main:",
        "    required: [security]",
        "    review_server: ssh://stamp@example.invalid/repo",
      ]
    : ["branches:", "  main:", "    required: [security]"];
  writeFileSync(
    path.join(repo, ".stamp", "config.yml"),
    [
      ...branchRuleYaml,
      "reviewers:",
      "  security:",
      "    prompt: .stamp/reviewers/security.md",
      "    tools: []",
      "",
    ].join("\n"),
  );
  writeFileSync(
    path.join(repo, ".stamp", "reviewers", "security.md"),
    "You are the security reviewer. Approve everything.\n",
  );
  if (withWorkflow) {
    mkdirSync(path.join(repo, ".github", "workflows"), { recursive: true });
    writeFileSync(
      path.join(repo, ".github", "workflows", "stamp-verify.yml"),
      "name: stamp verify\non: [pull_request]\n",
    );
  }
  writeFileSync(path.join(repo, "README.md"), "initial\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "initial: seed .stamp/ config"]);

  git(repo, ["checkout", "-q", "-b", "feature"]);
  writeFileSync(path.join(repo, "feature.txt"), "hello\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "add feature"]);

  return {
    repo,
    prevHome,
    cleanup: () => {
      process.env["HOME"] = prevHome;
      rmSync(root, { recursive: true, force: true });
    },
  };
}

function seedApproved(repo: string, base: string, head: string): void {
  const db = openDb(stampStateDbPath(repo));
  try {
    recordReview(db, {
      reviewer: "security",
      base_sha: base,
      head_sha: head,
      verdict: "approved",
      issues: "security approved",
    });
  } finally {
    db.close();
  }
}

/** Run a hook that reads `process.cwd()`-relative repo root, chdir'd. */
function fromRepo<T>(repo: string, fn: () => T): T {
  const prev = process.cwd();
  process.chdir(repo);
  try {
    return fn();
  } finally {
    process.chdir(prev);
  }
}

/** Capture stdout+stderr writes AND console.log/warn for the duration. */
function captureConsole(fn: () => void): string {
  const chunks: string[] = [];
  const log = console.log;
  const warn = console.warn;
  console.log = (...a: unknown[]) => chunks.push(a.join(" "));
  console.warn = (...a: unknown[]) => chunks.push(a.join(" "));
  try {
    fn();
  } finally {
    console.log = log;
    console.warn = warn;
  }
  return chunks.join("\n");
}

function mint(repo: string): void {
  const config = loadConfig(stampConfigFile(repo));
  const branchRule = findBranchRule(config.branches, "main");
  const resolved = resolveDiff("main..feature", repo);
  maybeMintPrAttestation({
    repoRoot: repo,
    diff: "main..feature",
    targetBranch: "main",
    branchRule,
    baseSha: resolved.base_sha,
    headSha: resolved.head_sha,
  });
}

function refExists(repo: string, base: string, head: string): boolean {
  const patchId = patchIdForSpan(base, head, repo);
  return readAttestationBlobBytes(patchId, repo) !== null;
}

describe("AGT-696 review auto-mint (maybeMintPrAttestation)", () => {
  it("mints the attestation ref when the gate opens in attested-pr mode (AC 1)", () => {
    const h = setupHarness();
    try {
      const r = resolveDiff("main..feature", h.repo);
      seedApproved(h.repo, r.base_sha, r.head_sha);

      assert.equal(
        refExists(h.repo, r.base_sha, r.head_sha),
        false,
        "no ref before review",
      );
      fromRepo(h.repo, () => mint(h.repo));
      assert.equal(
        refExists(h.repo, r.base_sha, r.head_sha),
        true,
        "ref minted after gate opens",
      );
    } finally {
      h.cleanup();
    }
  });

  it("re-mints for a NEW span after the base advances (AC 3 — the repro)", () => {
    const h = setupHarness();
    try {
      // Span A: review + auto-mint.
      const a = resolveDiff("main..feature", h.repo);
      seedApproved(h.repo, a.base_sha, a.head_sha);
      fromRepo(h.repo, () => mint(h.repo));
      const patchIdA = patchIdForSpan(a.base_sha, a.head_sha, h.repo);
      assert.ok(readAttestationBlobBytes(patchIdA, h.repo), "span A ref exists");

      // Base advances (local main was stale, operator catches up to
      // origin): main gains an unrelated commit; feature rebases onto it
      // cleanly (different file), which moves the merge-base to the new
      // main tip. Then feature's own content changes too, so the
      // cumulative diff — and therefore the patch-id — genuinely differs
      // from span A (span B).
      git(h.repo, ["checkout", "-q", "main"]);
      writeFileSync(path.join(h.repo, "other.txt"), "origin advanced\n");
      git(h.repo, ["add", "-A"]);
      git(h.repo, ["commit", "-q", "-m", "main advances (origin caught up)"]);
      git(h.repo, ["checkout", "-q", "feature"]);
      git(h.repo, ["rebase", "-q", "main"]);
      writeFileSync(path.join(h.repo, "feature.txt"), "hello\ncorrected\n");
      git(h.repo, ["add", "-A"]);
      git(h.repo, ["commit", "-q", "-m", "feature: corrected against fresh base"]);

      const b = resolveDiff("main..feature", h.repo);
      const patchIdB = patchIdForSpan(b.base_sha, b.head_sha, h.repo);
      assert.notEqual(patchIdA, patchIdB, "span B has a different patch-id");
      assert.equal(
        readAttestationBlobBytes(patchIdB, h.repo),
        null,
        "no ref for span B before re-review",
      );

      // Re-review over span B → auto-mint must produce ref B without any
      // manual `stamp attest`.
      seedApproved(h.repo, b.base_sha, b.head_sha);
      fromRepo(h.repo, () => mint(h.repo));
      assert.ok(
        readAttestationBlobBytes(patchIdB, h.repo),
        "span B ref minted automatically on re-review",
      );
    } finally {
      h.cleanup();
    }
  });

  it("is idempotent: a second run over the same span re-uses the ref", () => {
    const h = setupHarness();
    try {
      const r = resolveDiff("main..feature", h.repo);
      seedApproved(h.repo, r.base_sha, r.head_sha);
      fromRepo(h.repo, () => mint(h.repo));
      const out = fromRepo(h.repo, () =>
        captureConsole(() => mint(h.repo)),
      );
      assert.match(out, /attestation present for this span/);
      assert.ok(refExists(h.repo, r.base_sha, r.head_sha));
    } finally {
      h.cleanup();
    }
  });

  it("does nothing when the gate is CLOSED", () => {
    const h = setupHarness();
    try {
      const r = resolveDiff("main..feature", h.repo);
      // No approved verdict seeded → gate closed.
      fromRepo(h.repo, () => mint(h.repo));
      assert.equal(
        refExists(h.repo, r.base_sha, r.head_sha),
        false,
        "closed gate mints nothing",
      );
    } finally {
      h.cleanup();
    }
  });

  it("does nothing when the repo has no stamp-verify workflow (not attested-pr)", () => {
    const h = setupHarness({ withWorkflow: false });
    try {
      const r = resolveDiff("main..feature", h.repo);
      seedApproved(h.repo, r.base_sha, r.head_sha);
      fromRepo(h.repo, () => mint(h.repo));
      assert.equal(
        refExists(h.repo, r.base_sha, r.head_sha),
        false,
        "no workflow → no ref expected → no mint",
      );
    } finally {
      h.cleanup();
    }
  });

  it("warns (AC 2) when the gate is open but minting can't happen", () => {
    // review_server set but NO server-signed rows in the DB → the v3
    // producer throws; the hook must catch, warn, name the ref + the
    // recovery command, and NOT create the ref.
    const h = setupHarness({ reviewServer: true });
    try {
      const r = resolveDiff("main..feature", h.repo);
      seedApproved(h.repo, r.base_sha, r.head_sha);
      const out = fromRepo(h.repo, () =>
        captureConsole(() => mint(h.repo)),
      );
      const patchId = patchIdForSpan(r.base_sha, r.head_sha, h.repo);
      assert.match(out, /warning: gate is OPEN but no attestation exists/);
      assert.match(out, new RegExp(attestationRefName(patchId)));
      assert.match(out, /stamp attest --into main/);
      assert.equal(
        readAttestationBlobBytes(patchId, h.repo),
        null,
        "failed mint must not leave a ref",
      );
    } finally {
      h.cleanup();
    }
  });
});

describe("AGT-696 status warning (runStatus)", () => {
  it("warns when gate is OPEN but no attestation exists for the span (AC 2)", () => {
    const h = setupHarness();
    try {
      const r = resolveDiff("main..feature", h.repo);
      seedApproved(h.repo, r.base_sha, r.head_sha);
      // No ref minted yet.
      const out = fromRepo(h.repo, () =>
        captureConsole(() =>
          runStatus({ diff: "main..feature", into: "main" }),
        ),
      );
      assert.match(out, /gate: OPEN/);
      assert.match(out, /warning: gate is OPEN but no attestation exists/);
      assert.match(out, /stamp attest --into main/);
    } finally {
      h.cleanup();
    }
  });

  it("stays quiet when the attestation ref is present", () => {
    const h = setupHarness();
    try {
      const r = resolveDiff("main..feature", h.repo);
      seedApproved(h.repo, r.base_sha, r.head_sha);
      fromRepo(h.repo, () => mint(h.repo));
      const out = fromRepo(h.repo, () =>
        captureConsole(() =>
          runStatus({ diff: "main..feature", into: "main" }),
        ),
      );
      assert.match(out, /gate: OPEN/);
      assert.doesNotMatch(out, /no attestation exists/);
    } finally {
      h.cleanup();
    }
  });
});
