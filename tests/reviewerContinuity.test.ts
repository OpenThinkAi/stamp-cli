/**
 * Tests for the reviewer-continuity mechanism: the DB lookup, the ancestor
 * gate, and the prompt augmentation that surfaces a prior verdict to a
 * later round of `stamp review` on the same branch.
 *
 * The mechanism's purpose is to stop stateless re-reviews from coin-flipping
 * on iterated branches — once a reviewer says "approved" at SHA X, the next
 * round (HEAD = Y, X is ancestor of Y) sees its prior approval and is
 * constrained by the ratchet rule to only flag genuinely-new concerns.
 *
 * Tests cover three layers in isolation:
 *   - `priorReviewByReviewer` query semantics (most-recent-wins, exclude
 *     current head, per-base scoping).
 *   - `isAncestor` git helper (sanity check; the production gate would
 *     otherwise silently carry sibling-branch verdicts forward).
 *   - `buildUserPrompt` / `augmentSystemPrompt` shape — the prior block is
 *     present iff `priorReview` is set, and the ratchet rule's text differs
 *     between prior-approved and prior-changes_requested.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import { openDb, priorReviewByReviewer, recordReview } from "../src/lib/db.ts";
import { isAncestor } from "../src/lib/git.ts";
import {
  augmentSystemPrompt,
  buildUserPrompt,
  type PriorReviewContext,
} from "../src/lib/reviewer.ts";

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf8" });
}

describe("priorReviewByReviewer (state.db query)", () => {
  let tmp: string;
  let dbPath: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "stamp-prior-"));
    dbPath = join(tmp, "state.db");
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("returns null when no prior review exists", () => {
    const db = openDb(dbPath);
    try {
      const result = priorReviewByReviewer(db, "security", "a".repeat(40));
      assert.equal(result, null);
    } finally {
      db.close();
    }
  });

  it("returns the most recent prior verdict + prose for the reviewer/base", () => {
    const db = openDb(dbPath);
    try {
      const base = "a".repeat(40);
      const earlierHead = "b".repeat(40);
      const laterHead = "c".repeat(40);
      recordReview(db, {
        reviewer: "security",
        base_sha: base,
        head_sha: earlierHead,
        verdict: "changes_requested",
        issues: "early concern",
      });
      recordReview(db, {
        reviewer: "security",
        base_sha: base,
        head_sha: laterHead,
        verdict: "approved",
        issues: "looks good",
      });
      const result = priorReviewByReviewer(db, "security", base);
      assert.ok(result, "expected a prior row");
      assert.equal(result.head_sha, laterHead);
      assert.equal(result.verdict, "approved");
      assert.equal(result.issues, "looks good");
    } finally {
      db.close();
    }
  });

  it("excludes the current head_sha when one is passed", () => {
    const db = openDb(dbPath);
    try {
      const base = "a".repeat(40);
      const earlierHead = "b".repeat(40);
      const currentHead = "c".repeat(40);
      recordReview(db, {
        reviewer: "security",
        base_sha: base,
        head_sha: earlierHead,
        verdict: "approved",
        issues: "first pass",
      });
      recordReview(db, {
        reviewer: "security",
        base_sha: base,
        head_sha: currentHead,
        verdict: "changes_requested",
        issues: "current pass — should be excluded",
      });
      const result = priorReviewByReviewer(db, "security", base, currentHead);
      assert.ok(result);
      assert.equal(result.head_sha, earlierHead);
      assert.equal(result.verdict, "approved");
    } finally {
      db.close();
    }
  });

  it("scopes by base_sha — does not leak a different branch's history", () => {
    const db = openDb(dbPath);
    try {
      const baseA = "a".repeat(40);
      const baseB = "f".repeat(40);
      recordReview(db, {
        reviewer: "security",
        base_sha: baseA,
        head_sha: "b".repeat(40),
        verdict: "approved",
        issues: "branch A",
      });
      recordReview(db, {
        reviewer: "security",
        base_sha: baseB,
        head_sha: "e".repeat(40),
        verdict: "changes_requested",
        issues: "branch B",
      });
      const onA = priorReviewByReviewer(db, "security", baseA);
      assert.equal(onA?.issues, "branch A");
      const onB = priorReviewByReviewer(db, "security", baseB);
      assert.equal(onB?.issues, "branch B");
    } finally {
      db.close();
    }
  });

  it("scopes by reviewer — does not return another reviewer's row", () => {
    const db = openDb(dbPath);
    try {
      const base = "a".repeat(40);
      recordReview(db, {
        reviewer: "standards",
        base_sha: base,
        head_sha: "b".repeat(40),
        verdict: "approved",
        issues: "standards approved",
      });
      const result = priorReviewByReviewer(db, "security", base);
      assert.equal(result, null);
    } finally {
      db.close();
    }
  });
});

describe("isAncestor (git wrapper)", () => {
  let tmp: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "stamp-ancestor-"));
    git(["init", "-q", "-b", "main"], tmp);
    git(["config", "user.email", "test@example.com"], tmp);
    git(["config", "user.name", "Test"], tmp);
    writeFileSync(join(tmp, "a"), "1");
    git(["add", "a"], tmp);
    git(["commit", "-q", "-m", "first"], tmp);
    writeFileSync(join(tmp, "a"), "2");
    git(["commit", "-q", "-am", "second"], tmp);
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("returns true for a parent commit", () => {
    const head = git(["rev-parse", "HEAD"], tmp).trim();
    const parent = git(["rev-parse", "HEAD~1"], tmp).trim();
    assert.equal(isAncestor(parent, head, tmp), true);
  });

  it("returns true for the same commit (equal counts as ancestor)", () => {
    const head = git(["rev-parse", "HEAD"], tmp).trim();
    assert.equal(isAncestor(head, head, tmp), true);
  });

  it("returns false for a sibling commit on a parallel branch", () => {
    // Build a sibling: branch off HEAD~1, make a new commit.
    git(["checkout", "-q", "-b", "sibling", "HEAD~1"], tmp);
    writeFileSync(join(tmp, "b"), "sibling");
    git(["add", "b"], tmp);
    git(["commit", "-q", "-m", "sibling commit"], tmp);
    const sibling = git(["rev-parse", "HEAD"], tmp).trim();
    git(["checkout", "-q", "main"], tmp);
    const mainHead = git(["rev-parse", "HEAD"], tmp).trim();
    assert.equal(isAncestor(sibling, mainHead, tmp), false);
  });
});

describe("buildUserPrompt with priorReview", () => {
  const baseParams = {
    diff: "+const x = 1;\n",
    base_sha: "a".repeat(40),
    head_sha: "b".repeat(40),
  };
  const fenceHex = "deadbeef".repeat(4);

  it("omits the PRIOR-REVIEW block when priorReview is absent", () => {
    const prompt = buildUserPrompt(baseParams, fenceHex);
    assert.ok(!prompt.includes("PRIOR-REVIEW"));
    assert.ok(!prompt.includes("already reviewed"));
  });

  it("includes the PRIOR-REVIEW block and the prior verdict when set", () => {
    const prior: PriorReviewContext = {
      head_sha: "c".repeat(40),
      verdict: "approved",
      prose: "earlier prose",
    };
    const prompt = buildUserPrompt({ ...baseParams, priorReview: prior }, fenceHex);
    assert.ok(prompt.includes(`<<<PRIOR-REVIEW-${fenceHex}>>>`));
    assert.ok(prompt.includes(`<<<END-PRIOR-REVIEW-${fenceHex}>>>`));
    assert.ok(prompt.includes(`Prior verdict: approved`));
    assert.ok(prompt.includes(`Prior head commit you reviewed: ${prior.head_sha}`));
    assert.ok(prompt.includes("earlier prose"));
  });

  it("renders a placeholder when prior prose is null", () => {
    const prior: PriorReviewContext = {
      head_sha: "c".repeat(40),
      verdict: "changes_requested",
      prose: null,
    };
    const prompt = buildUserPrompt({ ...baseParams, priorReview: prior }, fenceHex);
    assert.ok(prompt.includes("(no prose recorded for this prior verdict)"));
  });

  it("carries the DATA-not-instructions disclaimer on the PRIOR-REVIEW block", () => {
    // The prior-review block re-injects LLM-authored prose. Without the
    // same fenced-data framing the diff block uses, a prior round's prose
    // could become a prompt-injection relay channel — the model would see
    // its "own" prior words rather than untrusted data. Pin the disclaimer.
    const prior: PriorReviewContext = {
      head_sha: "c".repeat(40),
      verdict: "approved",
      prose: "earlier prose",
    };
    const prompt = buildUserPrompt({ ...baseParams, priorReview: prior }, fenceHex);
    assert.match(prompt, /stored historical output/);
    assert.match(prompt, /prompt-injection relay/);
  });
});

describe("augmentSystemPrompt with priorReview", () => {
  const fenceHex = "deadbeef".repeat(4);

  it("omits the ratchet block when priorReview is absent", () => {
    const out = augmentSystemPrompt("base prompt", fenceHex);
    assert.ok(!out.includes("Ratchet rule"));
    assert.ok(out.startsWith("base prompt"));
  });

  it("emits the approved-ratchet language for a prior approval", () => {
    const prior: PriorReviewContext = {
      head_sha: "c".repeat(40),
      verdict: "approved",
      prose: null,
    };
    const out = augmentSystemPrompt("base prompt", fenceHex, prior);
    assert.ok(out.includes("Ratchet rule"));
    assert.ok(out.includes("previously APPROVED this branch"));
    assert.ok(out.includes(prior.head_sha));
  });

  it("emits the changes-requested ratchet language for a prior non-approval", () => {
    const prior: PriorReviewContext = {
      head_sha: "c".repeat(40),
      verdict: "changes_requested",
      prose: null,
    };
    const out = augmentSystemPrompt("base prompt", fenceHex, prior);
    assert.ok(out.includes("Ratchet rule"));
    assert.ok(out.includes("previously requested changes / denied this branch"));
    assert.ok(!out.includes("previously APPROVED this branch"));
  });
});
