/**
 * AGT-2245: the stamp-mirror-only Ruleset must protect every branch the
 * mirror pushes (`.stamp/mirror.yml` `github.branches`), not only the
 * default branch. Covers the include-list derivation, the coverage check
 * that flags an existing Ruleset left behind by a widened mirror.yml, the
 * mirror.yml reader that feeds both, and that the shipped manual-path
 * template stays in lockstep with what the CLI generates.
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import {
  buildRulesetPayload,
  mirrorBranchRulesetPattern,
  rulesetRefIncludes,
  uncoveredMirrorBranches,
} from "../src/lib/ghRuleset.ts";
import { matchesAnyPattern } from "../src/lib/refPatterns.ts";
import { computeMirrorProvisionProblems } from "../src/lib/provisionVerify.ts";
import { readMirrorYmlBranches } from "../src/lib/mirrorYml.ts";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("rulesetRefIncludes", () => {
  it("defaults to the default branch only", () => {
    assert.deepEqual(rulesetRefIncludes([]), ["~DEFAULT_BRANCH"]);
  });

  it("adds every mirrored branch, translating stamp `*` to GitHub `**`", () => {
    assert.deepEqual(rulesetRefIncludes(["main", "release/*"]), [
      "~DEFAULT_BRANCH",
      "refs/heads/main",
      "refs/heads/release/**",
    ]);
  });

  it("dedupes and keeps order", () => {
    assert.deepEqual(rulesetRefIncludes(["release/*", "main", "release/*", "release/**"]), [
      "~DEFAULT_BRANCH",
      "refs/heads/release/**",
      "refs/heads/main",
    ]);
  });

  it("keeps `?` and literals verbatim", () => {
    assert.equal(mirrorBranchRulesetPattern("team-?"), "refs/heads/team-?");
    assert.equal(mirrorBranchRulesetPattern("v1.0"), "refs/heads/v1.0");
    assert.equal(mirrorBranchRulesetPattern("*"), "refs/heads/**");
  });

  it("the GitHub pattern is at least as broad as stamp's glob (nested release branch)", () => {
    // stamp's `*` crosses `/`, so `release/*` mirrors release/2026/q4. The
    // generated include must cover it — the coverage check uses GitHub
    // semantics, so a self-generated Ruleset must report nothing uncovered
    // for any branch the hook would mirror.
    assert.equal(matchesAnyPattern("release/2026/q4", ["release/*"]), true);
    const include = rulesetRefIncludes(["release/*"]);
    assert.deepEqual(
      uncoveredMirrorBranches(["release/2026/q4"], { include, exclude: [] }, "main"),
      [],
    );
  });

  it("buildRulesetPayload threads the mirror branches into conditions", () => {
    const payload = buildRulesetPayload({ type: "DeployKey", id: 7 }, ["main", "release/*"]) as {
      conditions: { ref_name: { include: string[]; exclude: string[] } };
    };
    assert.deepEqual(payload.conditions.ref_name.include, [
      "~DEFAULT_BRANCH",
      "refs/heads/main",
      "refs/heads/release/**",
    ]);
    assert.deepEqual(payload.conditions.ref_name.exclude, []);
  });
});

describe("uncoveredMirrorBranches", () => {
  const legacy = { include: ["~DEFAULT_BRANCH"], exclude: [] };

  it("flags release/* on a legacy default-branch-only Ruleset (the oaudit finding)", () => {
    assert.deepEqual(uncoveredMirrorBranches(["main", "release/*"], legacy, "main"), [
      "release/*",
    ]);
  });

  it("treats the default branch as covered by ~DEFAULT_BRANCH", () => {
    assert.deepEqual(uncoveredMirrorBranches(["main"], legacy, "main"), []);
  });

  it("is conservative when the default branch is unknown", () => {
    assert.deepEqual(uncoveredMirrorBranches(["main"], legacy, null), ["main"]);
  });

  it("accepts a Ruleset stamp generated", () => {
    const include = rulesetRefIncludes(["main", "release/*", "hotfix-?"]);
    assert.deepEqual(
      uncoveredMirrorBranches(["main", "release/*", "hotfix-?"], { include, exclude: [] }, "trunk"),
      [],
    );
  });

  it("does not accept GitHub `release/*` for stamp `release/*` (misses nested branches)", () => {
    assert.deepEqual(
      uncoveredMirrorBranches(["release/*"], { include: ["refs/heads/release/*"], exclude: [] }, "main"),
      ["release/*"],
    );
  });

  it("~ALL and refs/heads/** cover everything", () => {
    for (const inc of ["~ALL", "refs/heads/**"]) {
      assert.deepEqual(
        uncoveredMirrorBranches(["main", "release/*"], { include: [inc], exclude: [] }, "main"),
        [],
      );
    }
  });

  it("matches literal branches against include patterns", () => {
    assert.deepEqual(
      uncoveredMirrorBranches(
        ["release/1.x", "develop"],
        { include: ["refs/heads/release/*"], exclude: [] },
        "main",
      ),
      ["develop"],
    );
  });

  it("an exclude match uncovers a literal branch", () => {
    assert.deepEqual(
      uncoveredMirrorBranches(
        ["release/1.x"],
        { include: ["~ALL"], exclude: ["refs/heads/release/1.x"] },
        "main",
      ),
      ["release/1.x"],
    );
  });
});

describe("computeMirrorProvisionProblems — branch coverage", () => {
  const MIRROR = { owner: "o", repo: "r" };
  it("fails verification when mirrored branches are uncovered", () => {
    const problems = computeMirrorProvisionProblems(
      { ownerType: "User", deployKeyId: null, rulesetId: 3, uncoveredBranches: ["release/*"] },
      MIRROR,
      "/tmp/clone",
    );
    assert.equal(problems.length, 1);
    assert.match(problems[0]!, /does not cover mirrored branch\(es\) "release\/\*"/);
  });

  it("fails closed when the Ruleset's conditions couldn't be read", () => {
    const problems = computeMirrorProvisionProblems(
      { ownerType: "User", deployKeyId: null, rulesetId: 3, uncoveredBranches: null },
      MIRROR,
      "/tmp/clone",
    );
    assert.equal(problems.length, 1);
    assert.match(problems[0]!, /couldn't read the `stamp-mirror-only` Ruleset's target branches/);
  });

  it("passes when all are covered", () => {
    assert.deepEqual(
      computeMirrorProvisionProblems(
        { ownerType: "User", deployKeyId: null, rulesetId: 3, uncoveredBranches: [] },
        MIRROR,
        "/tmp/clone",
      ),
      [],
    );
  });
});

describe("readMirrorYmlBranches", () => {
  function withRepo(yml: string | null, fn: (root: string) => void): void {
    const root = mkdtempSync(join(tmpdir(), "stamp-mirror-branches-"));
    try {
      if (yml !== null) {
        mkdirSync(join(root, ".stamp"));
        writeFileSync(join(root, ".stamp", "mirror.yml"), yml);
      }
      fn(root);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }

  it("reads github.branches", () => {
    withRepo(`github:\n  repo: o/r\n  branches:\n    - main\n    - "release/*"\n`, (root) => {
      assert.deepEqual(readMirrorYmlBranches(root), ["main", "release/*"]);
    });
  });

  it("returns [] when absent or malformed", () => {
    withRepo(null, (root) => assert.deepEqual(readMirrorYmlBranches(root), []));
    withRepo(`github:\n  repo: o/r\n  branches: main\n`, (root) =>
      assert.deepEqual(readMirrorYmlBranches(root), []),
    );
    withRepo(`: : not yaml [`, (root) => assert.deepEqual(readMirrorYmlBranches(root), []));
  });
});

describe("docs/github-ruleset-template.json", () => {
  const template = JSON.parse(
    readFileSync(join(REPO_ROOT, "docs", "github-ruleset-template.json"), "utf8"),
  ) as Record<string, unknown>;

  it("matches the CLI payload for the documented mirror.yml example (main + release/*)", () => {
    // The template is the manual-path twin of buildRulesetPayload. Keep
    // everything but the placeholder bypass actor identical, and keep its
    // branch targets equal to what `stamp provision` generates for the
    // quickstart's mirror.yml example — minus the literal `main`, which
    // ~DEFAULT_BRANCH already covers on a default-named repo.
    const generated = buildRulesetPayload({ type: "DeployKey", id: 0 }, ["release/*"]) as Record<
      string,
      unknown
    >;
    assert.deepEqual(template, generated);
  });

  it("covers release/* — not only the default branch", () => {
    const include = (template["conditions"] as { ref_name: { include: string[] } }).ref_name
      .include;
    assert.deepEqual(
      uncoveredMirrorBranches(["main", "release/*"], { include, exclude: [] }, "main"),
      [],
    );
  });
});
