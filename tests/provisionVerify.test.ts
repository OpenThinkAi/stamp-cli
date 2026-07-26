/**
 * Tests for the post-provision mirror verification policy (issue #64):
 * given a fresh read of GitHub's state, which situations block the
 * `✓ provisioned` summary. The gh round-trips live in provision.ts; this
 * covers the pure decision half.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { computeMirrorProvisionProblems } from "../src/lib/provisionVerify.ts";

const MIRROR = { owner: "MicroMediaSites", repo: "site-template" };
const CLONE = "/Users/op/Development/site-template";

describe("computeMirrorProvisionProblems", () => {
  it("passes an org repo with both deploy key and ruleset", () => {
    const problems = computeMirrorProvisionProblems(
      { ownerType: "Organization", deployKeyId: 158348533, rulesetId: 42 },
      MIRROR,
      CLONE,
    );
    assert.deepEqual(problems, []);
  });

  it("flags an org repo with no deploy key, naming the repair", () => {
    const problems = computeMirrorProvisionProblems(
      { ownerType: "Organization", deployKeyId: null, rulesetId: 42 },
      MIRROR,
      CLONE,
    );
    assert.equal(problems.length, 1);
    // The exact half-provisioned failure from issue #64: the problem text
    // must name the symptom AND the unobvious repair command.
    assert.match(problems[0]!, /Permission denied \(publickey\)/);
    assert.match(problems[0]!, /stamp provision --migrate-bypass/);
    assert.match(problems[0]!, new RegExp(`cd ${CLONE}`));
  });

  it("flags a missing ruleset independently of the key", () => {
    const problems = computeMirrorProvisionProblems(
      { ownerType: "Organization", deployKeyId: 158348533, rulesetId: null },
      MIRROR,
      CLONE,
    );
    assert.equal(problems.length, 1);
    assert.match(problems[0]!, /stamp-mirror-only/);
  });

  it("stacks both problems when key and ruleset are both absent", () => {
    const problems = computeMirrorProvisionProblems(
      { ownerType: "Organization", deployKeyId: null, rulesetId: null },
      MIRROR,
      CLONE,
    );
    assert.equal(problems.length, 2);
  });

  it("does not require a deploy key on a personal repo", () => {
    // Personal repos bypass the ruleset via a User actor; no deploy key
    // is registered by design, so its absence is not a defect.
    const problems = computeMirrorProvisionProblems(
      { ownerType: "User", deployKeyId: null, rulesetId: 42 },
      MIRROR,
      CLONE,
    );
    assert.deepEqual(problems, []);
  });

  it("reports a single readability problem when the owner lookup failed", () => {
    // gh couldn't even read the repo — the key/ruleset probes will have
    // failed for the same reason, so exactly one problem, not three
    // copies of the same auth failure.
    const problems = computeMirrorProvisionProblems(
      { ownerType: null, deployKeyId: null, rulesetId: null },
      MIRROR,
      CLONE,
    );
    assert.equal(problems.length, 1);
    assert.match(problems[0]!, /gh auth status/);
  });
});
