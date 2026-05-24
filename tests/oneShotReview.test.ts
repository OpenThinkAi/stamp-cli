/**
 * Verdict-extraction robustness for the one-shot review core
 * (src/lib/oneShotReview.ts). These pin the parsing behaviour discovered
 * while smoke-testing a real local model (qwen via mlx_lm.server), which
 * formats loosely: markdown emphasis, case differences, the verdict not on
 * the literal last line, and `changes_requested` with an underscore that an
 * earlier markdown-strip bug was eating. An injected fake client keeps these
 * network-free.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  runOneShotReview,
  type ChatClientShape,
} from "../src/lib/oneShotReview.ts";
import type { ReviewPlanReviewer } from "../src/lib/reviewPlan.ts";

const REVIEWER: ReviewPlanReviewer = {
  name: "security",
  prompt: "# reviewer\n",
  fence_hex: "deadbeefdeadbeefdeadbeefdeadbeef",
};

function textClient(text: string): ChatClientShape {
  return {
    messages: {
      create: async () => ({ content: [{ type: "text", text }] }),
    },
  };
}

async function verdictOf(text: string) {
  return runOneShotReview({
    reviewer: REVIEWER,
    diff: "x",
    base_sha: "1".repeat(40),
    head_sha: "2".repeat(40),
    model: "local-test",
    client: textClient(text),
  });
}

describe("oneShotReview verdict extraction (VERDICT: fallback)", () => {
  it("parses a plain last-line verdict and strips it from prose", async () => {
    const r = await verdictOf("Looks risky.\n\nVERDICT: changes_requested");
    assert.equal(r.verdict, "changes_requested");
    assert.equal(r.prose, "Looks risky.");
  });

  it("keeps the underscore in changes_requested (regression: markdown strip ate `_`)", async () => {
    const r = await verdictOf("VERDICT: changes_requested");
    assert.equal(r.verdict, "changes_requested");
  });

  it("tolerates markdown bold around the verdict", async () => {
    const r = await verdictOf("Review body.\n\n**VERDICT: approved**");
    assert.equal(r.verdict, "approved");
    assert.equal(r.prose, "Review body.");
  });

  it("is case-insensitive", async () => {
    const r = await verdictOf("body\n\nVerdict: Denied");
    assert.equal(r.verdict, "denied");
  });

  it("accepts a spaced 'changes requested'", async () => {
    const r = await verdictOf("body\n\nVERDICT: changes requested");
    assert.equal(r.verdict, "changes_requested");
  });

  it("finds the verdict even when the model adds prose AFTER it (bottom-up scan)", async () => {
    // Real local models sometimes emit the verdict then keep talking.
    const r = await verdictOf(
      "First paragraph.\n\nVERDICT: denied\n\nSome trailing commentary.",
    );
    assert.equal(r.verdict, "denied");
    assert.equal(r.prose, "First paragraph.");
  });

  it("does NOT match a verdict word merely mentioned mid-sentence (anti-injection)", async () => {
    // A line that only references a verdict word inside prose must not be
    // taken as the declaration; the model's real trailing verdict wins.
    const r = await verdictOf(
      "I'd normally mark this approved, but there's a bug.\n\nVERDICT: changes_requested",
    );
    assert.equal(r.verdict, "changes_requested");
  });

  it("errors when no verdict can be found, carrying prose for debugging", async () => {
    const r = await verdictOf("I have no strong opinion here.");
    assert.equal(r.verdict, null);
    assert.match(r.error ?? "", /did not call submit_verdict/);
    assert.match(r.prose, /no strong opinion/);
  });
});
