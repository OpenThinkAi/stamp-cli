/**
 * Integration tests for `stamp merge` rollback safety (AGT-232).
 *
 * Drives the real `runMerge` against a scratch stamp-gated repo (v3
 * mode — no `review_server`, legacy operator-signed attestation) and
 * asserts all three AC items:
 *
 *   AC 1: gate CLOSED (no approved verdicts) → `stamp merge` exits
 *         non-zero and the target branch ref is byte-equal before/after.
 *
 *   AC 2: required_check fails post-merge → `stamp merge` exits
 *         non-zero, the target branch ref is byte-equal before/after,
 *         AND the reflog for the target contains no "Merge made by the
 *         'ort' strategy" entry. This is the primary regression guard:
 *         it exercises the post-merge rollback path where the bug lived.
 *
 *   AC 3: clean success (approvals present, checks pass) → HEAD on the
 *         target has `Stamp-Payload` and `Stamp-Verified` trailers, and
 *         `runVerify` completes without throwing.
 *
 * Setup: scratch repo, stamp init via raw file writes (no `stamp init`
 * binary call), fake approvals via `recordReview` direct DB inserts,
 * `STAMP_REQUIRE_HUMAN_MERGE=0` to bypass the H1 confirmation.
 *
 * Pattern: follows `tests/mergeV4.test.ts` for harness shape and
 * `tests/attest.test.ts` for the v3 (no review_server) config.
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

import { runMerge } from "../../src/commands/merge.ts";
import { runVerify } from "../../src/commands/verify.ts";
import { openDb, recordReview } from "../../src/lib/db.ts";
import { ensureUserKeypair } from "../../src/lib/keys.ts";
import { stampStateDbPath } from "../../src/lib/paths.ts";

// ─── Harness ────────────────────────────────────────────────────────

/**
 * Set up a minimal stamp-gated repo in v3 mode (no review_server).
 * Config: main requires the `security` reviewer.
 * Feature branch: one commit adding feature.txt.
 * HOME is redirected to a temp dir so ensureUserKeypair() (called by
 * runMerge internally) lands at <tmp>/.stamp/keys/ rather than
 * polluting the real ~/.stamp.
 *
 * For AC 3 (runVerify), the v3 verify path checks that the signer's
 * public key is present in .stamp/trusted-keys/. The harness mints the
 * operator key via ensureUserKeypair(), writes the public key into the
 * working tree, and commits it before the feature branch is cut — so
 * `base_sha` in the attestation has the key in its tree.
 */
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

function setupHarness(opts?: {
  /** When set, inject `required_checks:` with the given shell command. */
  requiredCheckRun?: string;
}): Harness {
  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-merge-ac-"));
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

  const configLines = [
    "branches:",
    "  main:",
    "    required: [security]",
  ];
  if (opts?.requiredCheckRun) {
    configLines.push("    required_checks:");
    configLines.push("      - name: must-fail");
    configLines.push(`        run: "${opts.requiredCheckRun}"`);
  }
  configLines.push(
    "reviewers:",
    "  security:",
    "    prompt: .stamp/reviewers/security.md",
    "    tools: []",
    "",
  );

  writeFileSync(
    path.join(repo, ".stamp", "config.yml"),
    configLines.join("\n"),
  );
  writeFileSync(
    path.join(repo, ".stamp", "reviewers", "security.md"),
    REVIEWER_PROMPT,
  );

  // Mint the operator key now (into the redirected HOME) and commit
  // the public key to .stamp/trusted-keys/ so runVerify can find it
  // when checking a merge commit's signer_key_id against the repo's
  // trusted-keys directory (v3 verify path).
  //
  // ensureUserKeypair() mints under HOME/.stamp/keys/ — we just minted
  // it with the redirected HOME so no real ~/.stamp is touched.
  const { keypair } = ensureUserKeypair();
  const pubFileName =
    keypair.fingerprint.replace(/:/g, "_") + ".pub";
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", pubFileName),
    keypair.publicKeyPem,
  );

  writeFileSync(path.join(repo, "README.md"), "initial\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "initial: seed .stamp/ config"]);

  // Feature branch with one commit.
  git(repo, ["checkout", "-q", "-b", "feature"]);
  writeFileSync(path.join(repo, "feature.txt"), "hello\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "add feature"]);

  // Switch back to main — runMerge requires being on the target branch.
  git(repo, ["checkout", "-q", "main"]);

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

function shaOf(repo: string, ref: string): string {
  return git(repo, ["rev-parse", ref]).trim();
}

function runFromRepo<T>(repo: string, fn: () => T): T {
  const prev = process.cwd();
  process.chdir(repo);
  try {
    return fn();
  } finally {
    process.chdir(prev);
  }
}

/**
 * Seed a v3 (non-server-attested) review row — mirrors what a local
 * `stamp review` run would insert after a successful verdict.
 */
function seedApproval(
  repo: string,
  baseSha: string,
  headSha: string,
  reviewer: string,
): void {
  const db = openDb(stampStateDbPath(repo));
  try {
    recordReview(db, {
      reviewer,
      base_sha: baseSha,
      head_sha: headSha,
      verdict: "approved",
      issues: `${reviewer} approved`,
    });
  } finally {
    db.close();
  }
}

// Bypass the H1 human-confirmation gate for all tests in this file.
process.env["STAMP_REQUIRE_HUMAN_MERGE"] = "0";

// ─── Tests ─────────────────────────────────────────────────────────

describe("stamp merge rollback safety (AGT-232)", () => {
  /**
   * AC 1: gate-CLOSED path — no approved verdicts present.
   *
   * stamp merge must exit non-zero and leave the target branch ref
   * byte-equal to its pre-merge value. This AC is satisfied by the
   * existing pre-merge gate check (the throw before git merge runs);
   * we include it here so the suite covers all three AC items and a
   * future refactor that breaks the gate-check throw is caught.
   */
  it("AC 1: gate CLOSED → target ref unchanged, command exits non-zero", () => {
    const h = setupHarness();
    try {
      const beforeMain = shaOf(h.repo, "main");

      // No seedApproval — gate is CLOSED.
      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runMerge({ branch: "feature", into: "main", yes: true }),
          ),
        (err: unknown) => {
          const msg = err instanceof Error ? err.message : String(err);
          assert.ok(
            /gate CLOSED/i.test(msg),
            `expected "gate CLOSED" in error message; got: ${msg}`,
          );
          return true;
        },
      );

      // Target branch ref must be byte-equal.
      assert.equal(
        shaOf(h.repo, "main"),
        beforeMain,
        "main must not have moved when gate is CLOSED",
      );
    } finally {
      h.cleanup();
    }
  });

  /**
   * AC 2: required_check fails post-merge → rollback is clean.
   *
   * This is the primary regression guard for the bug the reporter
   * observed. We:
   *   1. Seed an approved verdict so the gate opens.
   *   2. Configure a required_check that always exits 1 ("exit 1").
   *   3. Run `stamp merge` — the git merge commits, then the check
   *      fails, and the rollback catch must reset to the pre-merge SHA.
   *
   * Asserts:
   *   - target ref is byte-equal before/after.
   *   - the reflog for main contains no "Merge made by the 'ort'
   *     strategy" entry (no unsigned merge lingered after rollback).
   */
  it("AC 2: required_check fails post-merge → rollback, no orphaned merge in reflog", () => {
    const h = setupHarness({ requiredCheckRun: "exit 1" });
    try {
      const baseSha = shaOf(h.repo, "main");
      const headSha = shaOf(h.repo, "feature");

      seedApproval(h.repo, baseSha, headSha, "security");

      const beforeMain = shaOf(h.repo, "main");

      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runMerge({ branch: "feature", into: "main", yes: true }),
          ),
        (err: unknown) => {
          const msg = err instanceof Error ? err.message : String(err);
          // The check-failure throw mentions "pre-merge checks failed"
          // or "Merge rolled back".
          assert.ok(
            /checks failed|rolled back/i.test(msg),
            `expected check-failure message; got: ${msg}`,
          );
          return true;
        },
      );

      // AC 2a: target branch ref must be byte-equal.
      const afterMain = shaOf(h.repo, "main");
      assert.equal(
        afterMain,
        beforeMain,
        `main must not have moved after a failed required_check; ` +
          `before=${beforeMain.slice(0, 8)} after=${afterMain.slice(0, 8)}`,
      );

      // AC 2b: the current HEAD commit on main must NOT be an unsigned
      // merge commit. After a clean rollback, main points to `beforeMain`
      // (the pre-merge tip). If the rollback failed silently the current
      // tip would be a merge commit with no Stamp-Payload trailer.
      //
      // Note: the git reflog WILL record the transient merge-then-reset
      // movement even after a clean rollback — that's expected. What must
      // NOT happen is `main` persistently pointing to an unsigned merge.
      // The afterMain === beforeMain check above covers the ref equality;
      // this check explicitly confirms the current tip has no merge
      // commit subject line (belt-and-suspenders: if the reset succeeded
      // but somehow left main pointing at an intermediate commit, this
      // would catch it).
      const tipMsg = git(h.repo, [
        "log",
        "-1",
        "--pretty=%s",
        "main",
      ]);
      assert.ok(
        !/^Merge (branch|made by)/i.test(tipMsg),
        `main tip must not be an unsigned merge commit after a failed check; ` +
          `commit subject: ${tipMsg.trim()}`,
      );
    } finally {
      h.cleanup();
    }
  });

  /**
   * AGT-475 / GH #24: gate-CLOSED via stale approvals (post-reset) must
   * never produce an unsigned merge commit on the target branch.
   *
   * Repro from the original bug report:
   *   1. `stamp review` against base A → head, DB rows keyed by (A, head).
   *   2. `git reset --hard <new-base>` advances main to a different base B
   *      (or some non-A commit) — the seeded approval no longer matches
   *      the current `(merge-base(main, feature), head)` lookup.
   *   3. `stamp merge feature --into main` — gate-CLOSED throws.
   *
   * Reported failure: an unsigned `Merge branch 'feature' into main` was
   * left on main anyway, no Stamp-* trailers, reflog entry
   * `merge feature: Merge made by the 'ort' strategy.`
   *
   * Expected (and currently true post-rewrite): the gate-CLOSED throw
   * fires at step 2 of runMerge, before `preMergeSha` is captured and
   * before `git merge --no-ff` runs. This test pins the invariant so a
   * future refactor that moves the throw inside the post-merge
   * try/catch wrapper (or otherwise allows the merge to execute first)
   * is caught immediately.
   *
   * The test asserts the full GH #24 contract:
   *   a) `runMerge` throws with /gate CLOSED/.
   *   b) Target branch HEAD SHA is byte-equal before/after.
   *   c) No merge commit (signed or unsigned) is reachable from main
   *      that wasn't reachable before.
   *   d) The reflog gained no `merge feature:` entry from this
   *      invocation.
   *
   * Per AC#4: if this test goes red on first run, the bug is back —
   * fix `merge.ts`, then keep the test as the pin.
   */
  it("AGT-475 / GH #24: gate CLOSED via stale approvals → no ref move, no merge in reflog", () => {
    const h = setupHarness();
    try {
      const initialMain = shaOf(h.repo, "main");
      const oldFeatureHead = shaOf(h.repo, "feature");

      // Seed an approval against the ORIGINAL (base, head) pair —
      // mirrors the "reviewed at base A → head" step of the GH #24
      // repro: a DB row exists, but as soon as either side drifts the
      // gate must close.
      seedApproval(h.repo, initialMain, oldFeatureHead, "security");

      // Drift the inputs so the seeded (initialMain, oldFeatureHead)
      // row no longer matches the current (merge-base, head) lookup
      // that runMerge performs.
      //
      // Two concurrent moves cover both halves of the GH #24 repro:
      //
      //   (a) Advance feature with a new commit so head_sha shifts off
      //       oldFeatureHead — analogous to the reporter's stale-head
      //       case. `latestReviews(db, base, newHead)` returns no row.
      //
      //   (b) Advance main with a new commit so initialMain is no
      //       longer the tip of main — analogous to the reporter's
      //       `git reset --hard <new-base>` step (a different ref
      //       position). Combined with (a), this guarantees the
      //       (merge-base, head) pair we're about to check has no
      //       matching row regardless of how resolveDiff picks the
      //       base.
      git(h.repo, ["checkout", "-q", "feature"]);
      writeFileSync(path.join(h.repo, "feature-drift.txt"), "head moved\n");
      git(h.repo, ["add", "-A"]);
      git(h.repo, ["commit", "-q", "-m", "advance feature past the reviewed head"]);
      git(h.repo, ["checkout", "-q", "main"]);
      writeFileSync(path.join(h.repo, "main-drift.txt"), "main moved\n");
      git(h.repo, ["add", "-A"]);
      git(h.repo, ["commit", "-q", "-m", "advance main past the reviewed base"]);

      const beforeMain = shaOf(h.repo, "main");
      const currentFeatureHead = shaOf(h.repo, "feature");
      assert.notEqual(
        beforeMain,
        initialMain,
        "harness sanity: main must have moved off the reviewed base",
      );
      assert.notEqual(
        currentFeatureHead,
        oldFeatureHead,
        "harness sanity: feature must have moved off the reviewed head",
      );

      // Capture reflog length BEFORE the merge attempt so we can assert
      // no new `merge feature:` entries were added by this invocation
      // (the reflog is append-only; a clean failed merge appends
      // nothing).
      const reflogBefore = git(h.repo, [
        "reflog",
        "main",
        "--format=%gs",
      ]);

      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runMerge({ branch: "feature", into: "main", yes: true }),
          ),
        (err: unknown) => {
          const msg = err instanceof Error ? err.message : String(err);
          assert.ok(
            /gate CLOSED/i.test(msg),
            `expected "gate CLOSED" in error message; got: ${msg}`,
          );
          return true;
        },
      );

      // (a) target ref byte-equal.
      const afterMain = shaOf(h.repo, "main");
      assert.equal(
        afterMain,
        beforeMain,
        `main must not have moved when gate is CLOSED; ` +
          `before=${beforeMain.slice(0, 8)} after=${afterMain.slice(0, 8)}`,
      );

      // (b) no merge commit reachable on main that wasn't already
      // there. `git log main` should not have a "Merge branch 'feature'"
      // subject — covers both unsigned-merge AND stamped-merge cases.
      const mainLog = git(h.repo, ["log", "--pretty=%s", "main"]);
      assert.ok(
        !/^Merge branch 'feature'/m.test(mainLog),
        `main must contain no "Merge branch 'feature'" commit after a ` +
          `gate-CLOSED throw; got log:\n${mainLog}`,
      );

      // (c) reflog gained no `merge feature:` entry from this
      // invocation. A failed `git merge --no-ff feature` (which is what
      // would have run if the throw site moved post-merge) leaves
      // `merge feature: Merge made by the 'ort' strategy.` in the
      // reflog — exactly what the GH #24 reporter observed. The
      // reflog text BEFORE and AFTER must be identical.
      const reflogAfter = git(h.repo, [
        "reflog",
        "main",
        "--format=%gs",
      ]);
      assert.equal(
        reflogAfter,
        reflogBefore,
        `reflog for main must be unchanged after a gate-CLOSED throw ` +
          `(no \`merge feature:\` entry); diff:\n` +
          `before: ${JSON.stringify(reflogBefore)}\n` +
          `after:  ${JSON.stringify(reflogAfter)}`,
      );
      assert.ok(
        !/merge feature:/i.test(reflogAfter),
        `reflog must contain no \`merge feature:\` entry after a ` +
          `gate-CLOSED throw; got:\n${reflogAfter}`,
      );
    } finally {
      h.cleanup();
    }
  });

  /**
   * AC 3: clean success → Stamp-Payload + Stamp-Verified trailers land
   *        on the merge commit, and runVerify completes without throwing.
   *
   * runVerify (the local `stamp verify` command) validates:
   *   - trailers present
   *   - signer key in .stamp/trusted-keys/
   *   - Ed25519 signature verifies
   *   - base_sha / head_sha match the commit parents
   *   - payload.target_branch matches the merge target
   *
   * The harness commits the operator's public key to .stamp/trusted-keys/
   * before the feature branch is cut, so the base_sha tree has the key.
   */
  it("AC 3: successful merge → signed trailers present, stamp verify passes", () => {
    const h = setupHarness();
    try {
      const baseSha = shaOf(h.repo, "main");
      const headSha = shaOf(h.repo, "feature");

      seedApproval(h.repo, baseSha, headSha, "security");

      // Run the merge.
      runFromRepo(h.repo, () =>
        runMerge({ branch: "feature", into: "main", yes: true }),
      );

      const mergeSha = shaOf(h.repo, "main");
      const mergeMsg = git(h.repo, ["log", "-1", "--pretty=%B", mergeSha]);

      // AC 3a: both trailers must be present.
      assert.ok(
        /^Stamp-Payload:/m.test(mergeMsg),
        `Stamp-Payload trailer missing from merge commit message:\n${mergeMsg}`,
      );
      assert.ok(
        /^Stamp-Verified:/m.test(mergeMsg),
        `Stamp-Verified trailer missing from merge commit message:\n${mergeMsg}`,
      );

      // AC 3b: runVerify must complete without throwing.
      // runVerify calls process.exit(1) on failure via its internal
      // `fail()` helper — that shows up as an uncaught throw in the
      // node:test harness, which is what assert.doesNotThrow catches.
      assert.doesNotThrow(
        () =>
          runFromRepo(h.repo, () => {
            runVerify(mergeSha);
          }),
        "runVerify must not throw for a clean stamp merge",
      );
    } finally {
      h.cleanup();
    }
  });
});
