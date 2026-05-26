/**
 * Tests for `parseReviewVerdict` and `runBuiltinReview` verdict propagation.
 *
 * Coverage:
 *   - parseReviewVerdict: each valid verdict (approve / request-changes / comment)
 *   - parseReviewVerdict: case-insensitive matching
 *   - parseReviewVerdict: trailing/leading whitespace around the verdict line
 *   - parseReviewVerdict: missing verdict → raw body + "comment" fallback
 *   - parseReviewVerdict: garbage verdict value → raw body + "comment" fallback
 *   - parseReviewVerdict: multiple verdict lines → uses the LAST one
 *   - runBuiltinReview: verdict + stripped body propagate end-to-end via test seam
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import {
  parseReviewVerdict,
  runBuiltinReview,
} from "../src/lib/builtinReviewPrompt.ts";

// ─── parseReviewVerdict matrix ────────────────────────────────────────

describe("parseReviewVerdict: approve", () => {
  it("strips verdict line, returns verdict=approve", () => {
    const raw = "This change looks clean and well-tested.\n\nverdict: approve";
    const { body, verdict } = parseReviewVerdict(raw);
    assert.equal(verdict, "approve");
    assert.ok(!body.includes("verdict:"), `body should not contain verdict line: ${body}`);
    assert.ok(body.includes("This change looks clean"), `body should keep review text: ${body}`);
  });
});

describe("parseReviewVerdict: request-changes", () => {
  it("strips verdict line, returns verdict=request-changes", () => {
    const raw = "There is a missing null check on line 42 that will crash.\n\nverdict: request-changes";
    const { body, verdict } = parseReviewVerdict(raw);
    assert.equal(verdict, "request-changes");
    assert.ok(!body.includes("verdict:"), `body should not contain verdict line: ${body}`);
    assert.ok(body.includes("missing null check"), `body should keep review text: ${body}`);
  });
});

describe("parseReviewVerdict: comment", () => {
  it("strips verdict line, returns verdict=comment", () => {
    const raw = "Minor style note on the logging format.\n\nverdict: comment";
    const { body, verdict } = parseReviewVerdict(raw);
    assert.equal(verdict, "comment");
    assert.ok(!body.includes("verdict:"), `body should not contain verdict line: ${body}`);
    assert.ok(body.includes("Minor style note"), `body should keep review text: ${body}`);
  });
});

describe("parseReviewVerdict: case-insensitive", () => {
  it("accepts 'Verdict: Approve' (title case)", () => {
    const raw = "Good change.\n\nVerdict: Approve";
    const { body, verdict } = parseReviewVerdict(raw);
    assert.equal(verdict, "approve");
    assert.ok(!body.includes("Verdict:"), `body should not contain verdict line: ${body}`);
  });

  it("accepts 'VERDICT: REQUEST-CHANGES' (upper case)", () => {
    const raw = "Needs work.\n\nVERDICT: REQUEST-CHANGES";
    const { body, verdict } = parseReviewVerdict(raw);
    assert.equal(verdict, "request-changes");
  });

  it("accepts 'verdict: Comment' (mixed case value)", () => {
    const raw = "FYI only.\n\nverdict: Comment";
    const { body, verdict } = parseReviewVerdict(raw);
    assert.equal(verdict, "comment");
  });
});

describe("parseReviewVerdict: whitespace tolerance", () => {
  it("accepts leading spaces before 'verdict:'", () => {
    const raw = "Good diff.\n\n   verdict: approve";
    const { body, verdict } = parseReviewVerdict(raw);
    assert.equal(verdict, "approve");
    assert.ok(!body.includes("verdict:"), `body should not contain verdict line: ${body}`);
  });

  it("accepts trailing spaces after the verdict value", () => {
    const raw = "Good diff.\n\nverdict: approve   ";
    const { body, verdict } = parseReviewVerdict(raw);
    assert.equal(verdict, "approve");
    assert.ok(!body.includes("verdict:"), `body should not contain verdict line: ${body}`);
  });

  it("strips blank trailing lines between body and verdict line", () => {
    const raw = "Clean change.\n\n\n\nverdict: approve";
    const { body, verdict } = parseReviewVerdict(raw);
    assert.equal(verdict, "approve");
    // Body should be the review text without trailing blanks.
    assert.equal(body, "Clean change.");
  });
});

describe("parseReviewVerdict: missing verdict → fallback", () => {
  it("returns raw body and verdict='comment' when no verdict line present", () => {
    const raw = "This diff looks fine. No verdict provided.";
    const { body, verdict } = parseReviewVerdict(raw);
    assert.equal(verdict, "comment");
    assert.equal(body, raw, "body should be unchanged when no verdict found");
  });

  it("returns raw body and verdict='comment' when output is empty", () => {
    const raw = "";
    const { body, verdict } = parseReviewVerdict(raw);
    assert.equal(verdict, "comment");
    assert.equal(body, "");
  });
});

describe("parseReviewVerdict: garbage verdict value → fallback", () => {
  it("returns raw body and verdict='comment' for 'verdict: lgtm'", () => {
    const raw = "Looks great.\n\nverdict: lgtm";
    const { body, verdict } = parseReviewVerdict(raw);
    assert.equal(verdict, "comment");
    assert.equal(body, raw, "body should be unchanged when verdict is unrecognised");
  });

  it("returns raw body and verdict='comment' for 'verdict: yes'", () => {
    const raw = "Nice.\n\nverdict: yes";
    const { body, verdict } = parseReviewVerdict(raw);
    assert.equal(verdict, "comment");
    assert.equal(body, raw);
  });
});

describe("parseReviewVerdict: multiple verdict lines → uses the LAST one", () => {
  it("uses last verdict when model emits approve then request-changes", () => {
    const raw = [
      "The changes look good overall.",
      "",
      "verdict: approve",
      "",
      "Actually, there is a null-deref risk on line 12.",
      "",
      "verdict: request-changes",
    ].join("\n");
    const { body, verdict } = parseReviewVerdict(raw);
    assert.equal(verdict, "request-changes");
    assert.ok(!body.includes("verdict:"), `body should have verdict lines stripped: ${body}`);
    assert.ok(body.includes("The changes look good"), `body should keep review text: ${body}`);
  });

  it("uses last verdict when model emits comment then approve", () => {
    const raw = [
      "Minor note.",
      "verdict: comment",
      "On reflection, this is solid.",
      "verdict: approve",
    ].join("\n");
    const { body, verdict } = parseReviewVerdict(raw);
    assert.equal(verdict, "approve");
  });
});

// ─── runBuiltinReview: verdict + stripped body end-to-end ────────────

describe("runBuiltinReview: verdict propagates via test seam", () => {
  it("returns verdict=approve and stripped body when seam returns approve", async () => {
    const result = await runBuiltinReview({
      diff: "some diff",
      cwd: "/tmp",
      _sdkRunnerForTest: async () =>
        "This change is clean and well-structured.\n\nverdict: approve",
    });
    assert.ok(result.ok, `expected ok:true, got: ${JSON.stringify(result)}`);
    if (!result.ok) return;
    assert.equal(result.verdict, "approve");
    assert.ok(
      !result.body.includes("verdict:"),
      `body should not contain verdict line: ${result.body}`,
    );
    assert.ok(
      result.body.includes("clean and well-structured"),
      `body should keep review text: ${result.body}`,
    );
  });

  it("returns verdict=request-changes and stripped body when seam returns request-changes", async () => {
    const result = await runBuiltinReview({
      diff: "some diff",
      cwd: "/tmp",
      _sdkRunnerForTest: async () =>
        "The auth check is missing on the new endpoint.\n\nverdict: request-changes",
    });
    assert.ok(result.ok);
    if (!result.ok) return;
    assert.equal(result.verdict, "request-changes");
    assert.ok(!result.body.includes("verdict:"));
  });

  it("returns verdict=comment and stripped body when seam returns comment", async () => {
    const result = await runBuiltinReview({
      diff: "some diff",
      cwd: "/tmp",
      _sdkRunnerForTest: async () =>
        "Small style note on the variable name.\n\nverdict: comment",
    });
    assert.ok(result.ok);
    if (!result.ok) return;
    assert.equal(result.verdict, "comment");
    assert.ok(!result.body.includes("verdict:"));
  });

  it("returns verdict=comment (fallback) when seam returns no verdict line", async () => {
    const result = await runBuiltinReview({
      diff: "some diff",
      cwd: "/tmp",
      _sdkRunnerForTest: async () => "Just a comment with no verdict line.",
    });
    assert.ok(result.ok);
    if (!result.ok) return;
    assert.equal(result.verdict, "comment");
    assert.equal(result.body, "Just a comment with no verdict line.");
  });
});
