/**
 * AGT-881 / issue #65 — cross-branch review contamination.
 *
 * The setup that broke: N branches off one base, each reviewed from its own
 * `git worktree` of a single clone. Worktrees share the git *common* dir, so
 * they share one `.git/stamp/state.db`. Delta-narrowing resolved "my prior
 * review" as "the newest review row against this base_sha" — which, in a
 * parallel wave, is routinely a *sibling* branch's row. The narrowed diff
 * `git diff <sibling head>..<my head>` renders the sibling's additions as my
 * deletions, so reviewers blocked on an apparent mass reversion of files the
 * branch had never touched. Four of nine branches in one bloom-cms wave came
 * back falsely `changes_requested`.
 *
 * These tests build that exact topology (real repo, real worktrees, one
 * shared DB) and pin all four acceptance criteria:
 *   AC1 — prior-review resolution is keyed on branch/ancestry, so a sibling
 *         head is never a narrowing predecessor.
 *   AC2 — a narrowed diff naming paths outside `base..head` is discarded in
 *         favour of a full review.
 *   AC3 — a cached verdict is never served to a (branch, head) it wasn't
 *         minted against.
 *   AC4 — this file: two branches off one base, reviewed from worktrees
 *         sharing a git dir, each scoped to its own diff.
 *
 * Everything runs at the library seam (`resolveReviewScope` and friends) —
 * the same code path `commands/review.ts` uses — so no LLM is involved.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import {
  findCachedVerdict,
  openDb,
  priorReviewCandidates,
  recordReview,
} from "../src/lib/db.ts";
import { changedPaths, deltaDiff, resolveDiff } from "../src/lib/git.ts";
import { stampStateDbPath } from "../src/lib/paths.ts";
import {
  narrowingContamination,
  patchPaths,
  resolveReviewBranch,
  resolveReviewScope,
  selectPriorReview,
} from "../src/lib/reviewScope.ts";
import type { ReviewProvenance } from "../src/lib/provenance.ts";

const REVIEWER = "security";
const DIFF_HASH = "d".repeat(64);
const PROMPT_HASH = "p".repeat(64);
// AGT-1137: provenance is a cache-key conjunct too. These tests are about the
// branch/head conjuncts, so they hold one backend constant throughout — the
// row is recorded with it and every lookup asks for it.
const PROVENANCE: ReviewProvenance = {
  backend_kind: "anthropic",
  backend_model: "claude-sonnet-4-6",
  backend_endpoint: null,
};

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: "pipe" });
}

function commitFile(repo: string, name: string, body: string, msg: string): string {
  writeFileSync(join(repo, name), body);
  git(["add", name], repo);
  git(["commit", "-q", "-m", msg], repo);
  return git(["rev-parse", "HEAD"], repo).trim();
}

describe("cross-branch review scoping (AGT-881 / issue #65)", () => {
  let tmp: string;
  /** Primary checkout, on `main`. Owns the real `.git` dir. */
  let repo: string;
  /** Worktree on `branchA`. */
  let wtA: string;
  /** Worktree on `branchB`. */
  let wtB: string;
  let baseSha: string;
  let headA: string;
  let headB: string;

  beforeEach(() => {
    tmp = realpathSync(mkdtempSync(join(tmpdir(), "stamp-xbranch-")));
    repo = join(tmp, "repo");
    mkdirSync(repo);
    git(["init", "-q", "-b", "main", repo], tmp);
    git(["config", "user.email", "t@example.com"], repo);
    git(["config", "user.name", "Test"], repo);
    baseSha = commitFile(repo, "shared.txt", "base\n", "base");

    // Two worktrees of ONE clone, branched off the same base — the wave.
    wtA = join(tmp, "wtA");
    wtB = join(tmp, "wtB");
    git(["worktree", "add", "-q", wtA, "-b", "branchA", "main"], repo);
    git(["worktree", "add", "-q", wtB, "-b", "branchB", "main"], repo);
    headA = commitFile(wtA, "a.txt", "branch A work\n", "A: add a.txt");
    headB = commitFile(wtB, "b.txt", "branch B work\n", "B: add b.txt");
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("precondition: both worktrees resolve to the same state.db", () => {
    // If this ever stops being true the bug class disappears — and so does
    // the shared verdict history that makes the ratchet work at all. Pin it
    // so a future change to `stampStateDbPath` has to confront both.
    assert.equal(stampStateDbPath(wtA), stampStateDbPath(wtB));
    assert.equal(stampStateDbPath(wtA), stampStateDbPath(repo));
  });

  it("resolves the branch identity of each worktree from `main..HEAD`", () => {
    assert.equal(resolveReviewBranch("main..HEAD", wtA), "branchA");
    assert.equal(resolveReviewBranch("main..HEAD", wtB), "branchB");
    // An explicit branch on the head side wins over the checkout, so
    // `stamp review --diff main..branchB` run from wtA is still branchB.
    assert.equal(resolveReviewBranch("main..branchB", wtA), "branchB");
  });

  it("AC1+AC4: branch B's review does not narrow against branch A's head", () => {
    const dbPath = stampStateDbPath(repo);
    const db = openDb(dbPath);
    try {
      // Round 1: branch A is reviewed first and records its verdict.
      const rA = resolveDiff("main..HEAD", wtA);
      assert.equal(rA.base_sha, baseSha);
      assert.equal(rA.head_sha, headA);
      const branchA = resolveReviewBranch("main..HEAD", wtA);
      const scopeA = resolveReviewScope({
        reviewers: [REVIEWER],
        candidatesByReviewer: new Map([
          [REVIEWER, priorReviewCandidates(db, REVIEWER, rA.base_sha, rA.head_sha)],
        ]),
        baseSha: rA.base_sha,
        headSha: rA.head_sha,
        branch: branchA,
        repoRoot: wtA,
        deltaEnabled: true,
      });
      assert.equal(scopeA.priorByReviewer.size, 0, "first review has no prior");
      assert.equal(scopeA.deltaDiffs.size, 0);
      recordReview(db, {
        reviewer: REVIEWER,
        base_sha: rA.base_sha,
        head_sha: rA.head_sha,
        verdict: "approved",
        issues: "branch A looks fine",
        diff_hash: DIFF_HASH,
        prompt_hash: PROMPT_HASH,
        branch: branchA,
      });

      // Round 2 (the repro): branch B is reviewed minutes later, same base.
      const rB = resolveDiff("main..HEAD", wtB);
      assert.equal(rB.base_sha, baseSha, "both branches share one base");
      const candidates = priorReviewCandidates(
        db,
        REVIEWER,
        rB.base_sha,
        rB.head_sha,
      );
      assert.equal(
        candidates.length,
        1,
        "branch A's row IS visible to branch B — one shared DB, same base",
      );
      assert.equal(candidates[0]!.head_sha, headA);

      const scopeB = resolveReviewScope({
        reviewers: [REVIEWER],
        candidatesByReviewer: new Map([[REVIEWER, candidates]]),
        baseSha: rB.base_sha,
        headSha: rB.head_sha,
        branch: resolveReviewBranch("main..HEAD", wtB),
        repoRoot: wtB,
        deltaEnabled: true,
      });
      assert.equal(
        scopeB.priorByReviewer.size,
        0,
        "a sibling branch's row is not branch B's prior review",
      );
      assert.equal(
        scopeB.deltaDiffs.size,
        0,
        "and therefore nothing is narrowed — branch B sees its full diff",
      );

      // The scoped diff is branch B's own work and nothing else.
      const seen = patchPaths(rB.diff);
      assert.deepEqual([...seen!].sort(), ["b.txt"]);
      assert.ok(
        !rB.diff.includes("a.txt"),
        "branch A's file must not appear in branch B's review at all",
      );
    } finally {
      db.close();
    }
  });

  it("AC1: the pre-fix narrowing really was contaminated (bug documentation)", () => {
    // What the old code computed for branch B: prior head = branch A's head.
    const contaminated = deltaDiff(headA, headB, wtB);
    const paths = patchPaths(contaminated);
    assert.ok(paths, "the narrowed patch parses");
    assert.ok(
      paths.has("a.txt"),
      "the sibling's file leaks into the narrowed diff…",
    );
    assert.match(
      contaminated,
      /deleted file mode|--- a\/a\.txt/,
      "…and it appears as branch B DELETING it — the false 'reversion'",
    );
  });

  it("AC2: a narrowed diff naming paths outside base..head is rejected", () => {
    const full = changedPaths(baseSha, headB, wtB);
    assert.deepEqual([...full].sort(), ["b.txt"]);

    const contaminated = deltaDiff(headA, headB, wtB);
    assert.deepEqual(
      narrowingContamination(contaminated, full),
      ["a.txt"],
      "the guard names exactly the out-of-range path",
    );

    // A legitimate narrowing (a second commit on branch B) passes cleanly.
    const headB2 = commitFile(wtB, "b2.txt", "more B\n", "B: add b2.txt");
    const clean = deltaDiff(headB, headB2, wtB);
    assert.deepEqual(
      narrowingContamination(clean, changedPaths(baseSha, headB2, wtB)),
      [],
    );
  });

  it("AC2: a non-ASCII filename does not look like contamination", () => {
    // git C-quotes `café.ts` in the patch header as two octal BYTE escapes.
    // Decode them as code points and the parsed path is mojibake that can
    // never match `changedPaths` — every narrowing in a repo with non-ASCII
    // filenames would fall back to a full review. Fail-safe, but wrong.
    const headB2 = commitFile(wtB, "café.ts", "accented\n", "B: add café.ts");
    const narrowed = deltaDiff(headB, headB2, wtB);
    assert.deepEqual([...patchPaths(narrowed)!], ["café.ts"]);
    assert.deepEqual(
      narrowingContamination(narrowed, changedPaths(baseSha, headB2, wtB)),
      [],
    );
  });

  it("AC2: resolveReviewScope falls back to the full diff on a contaminated narrowing", () => {
    // Force the bad state the guard exists for: hand it a prior row that IS
    // an ancestor-shaped predecessor by construction but whose delta escapes
    // base..head. A revert-to-base does exactly that without any DB lying:
    // branch B adds b.txt, then reverts it, so `prior..head` names b.txt
    // while `base..head` is empty of it.
    const dbPath = stampStateDbPath(repo);
    const db = openDb(dbPath);
    try {
      const branchB = resolveReviewBranch("main..HEAD", wtB);
      recordReview(db, {
        reviewer: REVIEWER,
        base_sha: baseSha,
        head_sha: headB,
        verdict: "changes_requested",
        issues: "drop b.txt",
        branch: branchB,
      });
      git(["rm", "-q", "b.txt"], wtB);
      git(["commit", "-q", "-m", "B: revert b.txt"], wtB);
      const headB2 = git(["rev-parse", "HEAD"], wtB).trim();

      const scope = resolveReviewScope({
        reviewers: [REVIEWER],
        candidatesByReviewer: new Map([
          [REVIEWER, priorReviewCandidates(db, REVIEWER, baseSha, headB2)],
        ]),
        baseSha,
        headSha: headB2,
        branch: branchB,
        repoRoot: wtB,
        deltaEnabled: true,
      });
      assert.equal(
        scope.priorByReviewer.size,
        1,
        "the prior review is still surfaced as prompt context",
      );
      assert.equal(
        scope.deltaDiffs.size,
        0,
        "but the diff is NOT narrowed — b.txt is outside base..head",
      );
      assert.equal(scope.warnings.length, 1);
      assert.match(scope.warnings[0]!, /outside/);
      assert.match(scope.warnings[0]!, /b\.txt/);
    } finally {
      db.close();
    }
  });

  it("AC3: a verdict minted on branch A is never served to branch B", () => {
    const dbPath = stampStateDbPath(repo);
    const db = openDb(dbPath);
    try {
      const treeSha = git(["rev-parse", `${headA}^{tree}`], wtA).trim();
      recordReview(db, {
        reviewer: REVIEWER,
        base_sha: baseSha,
        head_sha: headA,
        verdict: "approved",
        diff_hash: DIFF_HASH,
        prompt_hash: PROMPT_HASH,
        tree_sha: treeSha,
        branch: "branchA",
        provenance: PROVENANCE,
      });

      // Same (reviewer, diff, prompt, tree) — i.e. every pre-#65 key part
      // matches — but a different branch and head. Must miss on both counts.
      assert.equal(
        findCachedVerdict(
          db, REVIEWER, DIFF_HASH, PROMPT_HASH, treeSha, headA, "branchB",
          PROVENANCE,
        ),
        null,
        "branch B must not receive branch A's verdict",
      );
      assert.equal(
        findCachedVerdict(
          db, REVIEWER, DIFF_HASH, PROMPT_HASH, treeSha, headB, "branchA",
          PROVENANCE,
        ),
        null,
        "and a different head on the same branch must not either",
      );
      assert.equal(
        findCachedVerdict(
          db, REVIEWER, DIFF_HASH, PROMPT_HASH, treeSha, headA, null,
          PROVENANCE,
        ),
        null,
        "an unidentifiable (detached-HEAD) review must not claim it either",
      );
      // The exact (branch, head) it was minted against still replays — the
      // anti-treadmill property this cache exists for.
      assert.equal(
        findCachedVerdict(
          db, REVIEWER, DIFF_HASH, PROMPT_HASH, treeSha, headA, "branchA",
          PROVENANCE,
        )?.verdict,
        "approved",
      );
    } finally {
      db.close();
    }
  });

  it("keeps the ratchet: branch A's own earlier review survives a sibling's newer row", () => {
    const dbPath = stampStateDbPath(repo);
    const db = openDb(dbPath);
    try {
      // Branch A round 1, then branch B reviews (newer row), then branch A
      // commits again. Pre-fix, the single-row lookup returned B's row and
      // branch A silently lost its ratchet on top of being contaminated.
      recordReview(db, {
        reviewer: REVIEWER,
        base_sha: baseSha,
        head_sha: headA,
        verdict: "changes_requested",
        issues: "A round 1",
        branch: "branchA",
      });
      recordReview(db, {
        reviewer: REVIEWER,
        base_sha: baseSha,
        head_sha: headB,
        verdict: "approved",
        issues: "B round 1",
        branch: "branchB",
      });
      const headA2 = commitFile(wtA, "a2.txt", "A round 2\n", "A: add a2.txt");

      const candidates = priorReviewCandidates(db, REVIEWER, baseSha, headA2);
      assert.equal(candidates[0]!.head_sha, headB, "B's row is the newest…");
      const selected = selectPriorReview({
        candidates,
        headSha: headA2,
        branch: "branchA",
        repoRoot: wtA,
      });
      assert.equal(selected?.row.head_sha, headA, "…but A's own row is chosen");
      assert.equal(selected?.relation, "ancestor");

      const scope = resolveReviewScope({
        reviewers: [REVIEWER],
        candidatesByReviewer: new Map([[REVIEWER, candidates]]),
        baseSha,
        headSha: headA2,
        branch: "branchA",
        repoRoot: wtA,
        deltaEnabled: true,
      });
      const narrowed = scope.deltaDiffs.get(REVIEWER);
      assert.ok(narrowed, "a legitimate same-branch narrowing still happens");
      assert.deepEqual([...patchPaths(narrowed)!].sort(), ["a2.txt"]);
    } finally {
      db.close();
    }
  });

  it("accepts a same-branch amend, rejects an identically-shaped sibling", () => {
    // Both cases are "prior head and current head share a parent". Only the
    // branch name distinguishes them, which is precisely why the row carries
    // one. (Git refuses to check the same branch out in two worktrees, so a
    // branch match plus a shared parent really is one line of work.)
    const dbPath = stampStateDbPath(repo);
    const db = openDb(dbPath);
    try {
      recordReview(db, {
        reviewer: REVIEWER,
        base_sha: baseSha,
        head_sha: headB,
        verdict: "changes_requested",
        issues: "B round 1",
        branch: "branchB",
      });
      writeFileSync(join(wtB, "b.txt"), "branch B work, revised\n");
      git(["commit", "-q", "-a", "--amend", "--no-edit"], wtB);
      const headB2 = git(["rev-parse", "HEAD"], wtB).trim();

      const candidates = priorReviewCandidates(db, REVIEWER, baseSha, headB2);
      assert.equal(
        selectPriorReview({
          candidates,
          headSha: headB2,
          branch: "branchB",
          repoRoot: wtB,
        })?.relation,
        "same-branch-amend",
      );
      // Sibling branch A, one commit off the same base, is the same shape.
      assert.equal(
        selectPriorReview({
          candidates,
          headSha: headA,
          branch: "branchA",
          repoRoot: wtA,
        }),
        null,
        "a sibling with a shared parent must NOT be treated as an amend",
      );
      // A row that predates the branch column (NULL) can't claim the amend
      // path either — it can only ever match by ancestry.
      db.exec("UPDATE reviews SET branch = NULL");
      assert.equal(
        selectPriorReview({
          candidates: priorReviewCandidates(db, REVIEWER, baseSha, headB2),
          headSha: headB2,
          branch: "branchB",
          repoRoot: wtB,
        }),
        null,
        "legacy NULL-branch rows are not amend predecessors",
      );
    } finally {
      db.close();
    }
  });

  it("STAMP_NO_DELTA_REVIEW-style deltaEnabled=false keeps the prior but drops narrowing", () => {
    const dbPath = stampStateDbPath(repo);
    const db = openDb(dbPath);
    try {
      recordReview(db, {
        reviewer: REVIEWER,
        base_sha: baseSha,
        head_sha: headA,
        verdict: "changes_requested",
        issues: "A round 1",
        branch: "branchA",
      });
      const headA2 = commitFile(wtA, "a2.txt", "A round 2\n", "A: add a2.txt");
      const scope = resolveReviewScope({
        reviewers: [REVIEWER],
        candidatesByReviewer: new Map([
          [REVIEWER, priorReviewCandidates(db, REVIEWER, baseSha, headA2)],
        ]),
        baseSha,
        headSha: headA2,
        branch: "branchA",
        repoRoot: wtA,
        deltaEnabled: false,
      });
      assert.equal(scope.priorByReviewer.size, 1);
      assert.equal(scope.deltaDiffs.size, 0);
      assert.deepEqual(scope.warnings, []);
    } finally {
      db.close();
    }
  });
});

describe("patchPaths (narrowing-guard parser)", () => {
  it("reads both sides of a rename", () => {
    const patch = [
      "diff --git a/old/name.ts b/new/name.ts",
      "similarity index 100%",
      "rename from old/name.ts",
      "rename to new/name.ts",
    ].join("\n");
    assert.deepEqual(
      [...patchPaths(patch)!].sort(),
      ["new/name.ts", "old/name.ts"],
    );
  });

  it("handles paths with spaces", () => {
    const patch = "diff --git a/dir/my file.ts b/dir/my file.ts\n";
    assert.deepEqual([...patchPaths(patch)!], ["dir/my file.ts"]);
  });

  it("handles git's C-quoted paths (octal escapes are BYTES, not code points)", () => {
    const patch = 'diff --git "a/dir/caf\\303\\251.ts" "b/dir/caf\\303\\251.ts"\n';
    assert.deepEqual([...patchPaths(patch)!], ["dir/caf\u00e9.ts"]);
  });

  it("unescapes a quoted path containing a literal quote", () => {
    const patch = 'diff --git "a/we\\"ird.ts" "b/we\\"ird.ts"\n';
    assert.deepEqual([...patchPaths(patch)!], ['we"ird.ts']);
  });

  it("returns null (→ full review) on an unparseable header", () => {
    assert.equal(patchPaths("diff --git nonsense\n"), null);
    assert.equal(
      narrowingContamination("diff --git nonsense\n", new Set(["x"])),
      null,
    );
  });

  it("returns an empty set for an empty patch", () => {
    assert.deepEqual([...patchPaths("")!], []);
  });
});
