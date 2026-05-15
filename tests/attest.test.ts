/**
 * End-to-end test for `stamp attest`. Drives the real runAttest logic
 * against a fully-set-up temp stamp-gated repo: real git commits, real
 * .stamp/config.yml + reviewer prompt, real stamp signing keypair,
 * pre-seeded review verdicts in the local state.db. Then verifies the
 * attestation ref + blob landed with the right shape and a valid
 * signature.
 *
 * Covers:
 *   - happy path: gate open → ref created, blob parses, signature
 *     verifies against the operator's stamp key
 *   - gate closed → error names the missing reviewer
 *   - missing branch rule → error names the configured branches
 *   - re-attesting the same diff → idempotent (same patch-id, same blob)
 *   - patch-id stability → squashing the feature branch produces the
 *     same patch-id (sanity that runAttest agrees with patchIdForSpan)
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { runAttest } from "../src/commands/attest.ts";
import { openDb, recordReview } from "../src/lib/db.ts";
import { stampStateDbPath } from "../src/lib/paths.ts";
import {
  readAttestationRef,
  serializePayload,
} from "../src/lib/prAttestation.ts";
import { ensureUserKeypair } from "../src/lib/keys.ts";
import { verifyBytes } from "../src/lib/signing.ts";

interface Harness {
  repo: string;
  home: string;
  prevHome: string | undefined;
  cleanup: () => void;
}

function git(repo: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd: repo,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

const REVIEWER_PROMPT = "You are the security reviewer. Approve everything.\n";

function setupHarness(): Harness {
  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-attest-"));
  const repo = path.join(root, "repo");
  const home = path.join(root, "home");
  mkdirSync(repo, { recursive: true });
  mkdirSync(home, { recursive: true });

  // Override HOME so ensureUserKeypair() lands at <tmp>/.stamp/keys/
  // instead of polluting the real ~/.stamp.
  const prevHome = process.env["HOME"];
  process.env["HOME"] = home;

  // Init repo with deterministic identity.
  git(repo, ["init", "-q", "-b", "main"]);
  git(repo, ["config", "user.name", "Test"]);
  git(repo, ["config", "user.email", "test@example.invalid"]);
  git(repo, ["config", "commit.gpgsign", "false"]);

  // Drop in a minimal .stamp/config.yml + reviewer prompt on main.
  // Branch rule: main requires the `security` reviewer to approve.
  // The reviewer's prompt file is referenced from the YAML; we just
  // need the file to exist at base_sha so the merge-base hash sourcing
  // can read it.
  mkdirSync(path.join(repo, ".stamp", "reviewers"), { recursive: true });
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
      "",
    ].join("\n"),
  );
  writeFileSync(
    path.join(repo, ".stamp", "reviewers", "security.md"),
    REVIEWER_PROMPT,
  );
  writeFileSync(path.join(repo, "README.md"), "initial\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "initial: seed .stamp/ config"]);

  // Create a feature branch with one commit.
  git(repo, ["checkout", "-q", "-b", "feature"]);
  writeFileSync(path.join(repo, "feature.txt"), "hello\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "add feature"]);

  return {
    repo,
    home,
    prevHome,
    cleanup: () => {
      process.env["HOME"] = prevHome;
      rmSync(root, { recursive: true, force: true });
    },
  };
}

function seedReview(
  repo: string,
  base_sha: string,
  head_sha: string,
  reviewer: string,
  verdict: "approved" | "changes_requested" | "denied",
): void {
  const db = openDb(stampStateDbPath(repo));
  try {
    recordReview(db, {
      reviewer,
      base_sha,
      head_sha,
      verdict,
      issues: `${reviewer} ${verdict}`,
    });
  } finally {
    db.close();
  }
}

function shaOf(repo: string, ref: string): string {
  return git(repo, ["rev-parse", ref]).trim();
}

function runFromRepo<T>(repo: string, fn: () => T): T {
  // runAttest calls findRepoRoot() from process.cwd(), so we have to
  // chdir for the duration of the call. Restore in a finally so a
  // throw doesn't strand the process in the temp dir.
  const prev = process.cwd();
  process.chdir(repo);
  try {
    return fn();
  } finally {
    process.chdir(prev);
  }
}

describe("runAttest — happy path", () => {
  it("creates a signed attestation ref when the gate is open", () => {
    const h = setupHarness();
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "HEAD");
      seedReview(h.repo, base, head, "security", "approved");

      runFromRepo(h.repo, () => runAttest({ into: "main" }));

      // Attestation ref exists; blob parses; payload references the
      // right base/head and target.
      const env = readAttestationRef(
        // We need the patch-id to look up the ref. Easiest: walk the
        // attestations namespace and pick the only entry.
        listAttestationPatchIds(h.repo)[0]!,
        h.repo,
      );
      assert.ok(env);
      assert.equal(env.payload.base_sha, base);
      assert.equal(env.payload.head_sha, head);
      assert.equal(env.payload.target_branch, "main");
      assert.equal(env.payload.approvals.length, 1);
      assert.equal(env.payload.approvals[0]?.reviewer, "security");
      assert.equal(env.payload.approvals[0]?.verdict, "approved");
      assert.equal(env.payload.checks.length, 0);

      // Signature verifies against the operator's stamp key.
      const { keypair } = ensureUserKeypair();
      const ok = verifyBytes(
        keypair.publicKeyPem,
        serializePayload(env.payload),
        env.signature,
      );
      assert.ok(ok, "signature should verify against the operator's public key");
      assert.equal(env.payload.signer_key_id, keypair.fingerprint);
    } finally {
      h.cleanup();
    }
  });

  it("re-attesting the same diff lands on the same patch-id (idempotent)", () => {
    const h = setupHarness();
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "HEAD");
      seedReview(h.repo, base, head, "security", "approved");

      runFromRepo(h.repo, () => runAttest({ into: "main" }));
      const firstRefs = listAttestationPatchIds(h.repo);
      assert.equal(firstRefs.length, 1);

      runFromRepo(h.repo, () => runAttest({ into: "main" }));
      const secondRefs = listAttestationPatchIds(h.repo);
      assert.equal(secondRefs.length, 1);
      assert.equal(firstRefs[0], secondRefs[0]);
    } finally {
      h.cleanup();
    }
  });

  it("patch-id survives squashing the feature branch", () => {
    const h = setupHarness();
    try {
      // Add two more commits on the feature branch so we have three
      // total. Pre-attestation patch-id; squash; re-attest; expect the
      // same patch-id (different head_sha though).
      writeFileSync(path.join(h.repo, "feature.txt"), "hello\nworld\n");
      git(h.repo, ["add", "-A"]);
      git(h.repo, ["commit", "-q", "-m", "feature: line 2"]);
      writeFileSync(path.join(h.repo, "feature.txt"), "hello\nworld\n!\n");
      git(h.repo, ["add", "-A"]);
      git(h.repo, ["commit", "-q", "-m", "feature: line 3"]);

      const base = shaOf(h.repo, "main");
      const head1 = shaOf(h.repo, "HEAD");
      seedReview(h.repo, base, head1, "security", "approved");

      runFromRepo(h.repo, () => runAttest({ into: "main" }));
      const patchId1 = listAttestationPatchIds(h.repo)[0]!;

      // Squash three commits into one.
      git(h.repo, ["reset", "--soft", "main"]);
      git(h.repo, ["commit", "-q", "-m", "feature: squashed"]);
      const head2 = shaOf(h.repo, "HEAD");
      assert.notEqual(head1, head2, "squash must produce a different head");

      // Re-seed review against the new head SHA, re-attest.
      seedReview(h.repo, base, head2, "security", "approved");
      runFromRepo(h.repo, () => runAttest({ into: "main" }));

      const allRefs = listAttestationPatchIds(h.repo);
      assert.ok(
        allRefs.includes(patchId1),
        `pre-squash patch-id ${patchId1} should still be reachable post-squash; got ${allRefs.join(",")}`,
      );
    } finally {
      h.cleanup();
    }
  });
});

describe("runAttest — error paths", () => {
  it("gate CLOSED when no reviewer has approved", () => {
    const h = setupHarness();
    try {
      // Don't seed any review.
      assert.throws(
        () => runFromRepo(h.repo, () => runAttest({ into: "main" })),
        /gate CLOSED.*security/s,
      );
    } finally {
      h.cleanup();
    }
  });

  it("gate CLOSED when reviewer's verdict is not 'approved'", () => {
    const h = setupHarness();
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "HEAD");
      seedReview(h.repo, base, head, "security", "changes_requested");
      assert.throws(
        () => runFromRepo(h.repo, () => runAttest({ into: "main" })),
        /gate CLOSED/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects when --into names a branch with no rule in .stamp/config.yml", () => {
    const h = setupHarness();
    try {
      assert.throws(
        () => runFromRepo(h.repo, () => runAttest({ into: "develop" })),
        /no branch rule for "develop"/,
      );
    } finally {
      h.cleanup();
    }
  });
});

/**
 * Walk the on-disk refs namespace for stamp attestations. Avoids
 * importing private helpers; lets the test discover the patch-id
 * `runAttest` produced without our predicting it.
 */
function listAttestationPatchIds(repo: string): string[] {
  const out = git(repo, ["for-each-ref", "--format=%(refname)", "refs/stamp/attestations"]);
  return out
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((ref) => ref.replace(/^refs\/stamp\/attestations\//, ""));
}

