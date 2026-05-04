/**
 * Unit tests for src/lib/retro.ts — the producer-side wire format and the
 * canonical orchestrator-side parser for AGT-052 retro candidates.
 *
 * Pin the round-trip and the edge cases here so the formatter and parser
 * cannot drift independently. Live-LLM integration coverage (AC #5) lives in
 * tests/integration/reviewer-retro.test.ts.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  formatRetroBlock,
  parseRetroBlocks,
  RETRO_MAX_CANDIDATES,
  STAMP_RETRO_VERSION,
  type RetroCandidate,
} from "../src/lib/retro.ts";

describe("formatRetroBlock", () => {
  it("emits the documented marker shape with a JSON body", () => {
    const out = formatRetroBlock("security", [
      { kind: "convention", observation: "x" },
    ]);
    assert.match(out, /^<<<STAMP-RETRO v=1 reviewer="security">>>\n/);
    assert.match(out, /\n<<<END-STAMP-RETRO>>>$/);
    const body = out
      .split("\n")
      .slice(1, -1)
      .join("\n");
    const parsed = JSON.parse(body) as {
      candidates: RetroCandidate[];
    };
    assert.deepEqual(parsed, {
      candidates: [{ kind: "convention", observation: "x" }],
    });
  });

  it("emits an empty-candidates block (distinguishes 'ran, nothing' from 'no retro support')", () => {
    const out = formatRetroBlock("standards", []);
    assert.match(out, /<<<STAMP-RETRO v=1 reviewer="standards">>>/);
    assert.match(out, /<<<END-STAMP-RETRO>>>/);
    const body = out.split("\n").slice(1, -1).join("\n");
    assert.deepEqual(JSON.parse(body), { candidates: [] });
  });

  it("rejects reviewer names outside [A-Za-z0-9_-]+", () => {
    assert.throws(
      () => formatRetroBlock("evil reviewer", []),
      /not in \[A-Za-z0-9_-\]\+/,
    );
    assert.throws(() => formatRetroBlock("", []), /not in \[A-Za-z0-9_-\]\+/);
    assert.throws(
      () => formatRetroBlock('a"b', []),
      /not in \[A-Za-z0-9_-\]\+/,
    );
  });
});

describe("parseRetroBlocks", () => {
  it("round-trips a single block", () => {
    const candidates: RetroCandidate[] = [
      { kind: "convention", observation: "always source from base_sha tree" },
      {
        kind: "invariant",
        observation: "VERDICT line must be the LAST non-empty line",
        evidence: "src/lib/reviewer.ts:34",
      },
    ];
    const stdout = formatRetroBlock("security", candidates);
    const parsed = parseRetroBlocks(stdout);
    assert.equal(parsed.length, 1);
    assert.equal(parsed[0]!.reviewer, "security");
    assert.deepEqual(parsed[0]!.candidates, candidates);
  });

  it("returns an empty array when no retro fences are present", () => {
    const stdout = "reviewer: security\n────────\nverdict: approved\n";
    assert.deepEqual(parseRetroBlocks(stdout), []);
  });

  it("recovers an empty-candidates block as a present-but-empty signal", () => {
    const stdout = formatRetroBlock("product", []);
    const parsed = parseRetroBlocks(stdout);
    assert.equal(parsed.length, 1);
    assert.equal(parsed[0]!.reviewer, "product");
    assert.deepEqual(parsed[0]!.candidates, []);
  });

  it("extracts multiple per-reviewer blocks from one stdout in document order", () => {
    const stdout = [
      "lots of preamble",
      formatRetroBlock("security", [
        { kind: "gotcha", observation: "first" },
      ]),
      "verdict bar text",
      formatRetroBlock("standards", []),
      "more text",
      formatRetroBlock("product", [
        { kind: "prior_decision", observation: "third" },
      ]),
    ].join("\n");
    const parsed = parseRetroBlocks(stdout);
    assert.equal(parsed.length, 3);
    assert.deepEqual(
      parsed.map((p) => p.reviewer),
      ["security", "standards", "product"],
    );
    assert.equal(parsed[0]!.candidates[0]!.observation, "first");
    assert.equal(parsed[1]!.candidates.length, 0);
    assert.equal(parsed[2]!.candidates[0]!.observation, "third");
  });

  it("preserves observations containing JSON-significant characters", () => {
    const candidate: RetroCandidate = {
      kind: "gotcha",
      observation:
        'commit msg may contain quotes ("..."), backslashes (\\), and braces ({})',
      evidence: "src/lib/git.ts:12",
    };
    const stdout = formatRetroBlock("standards", [candidate]);
    const parsed = parseRetroBlocks(stdout);
    assert.deepEqual(parsed[0]!.candidates[0], candidate);
  });

  it("preserves observations containing newlines", () => {
    const candidate: RetroCandidate = {
      kind: "convention",
      observation:
        "Two-line note:\nline 2 is the consequence and reads as one observation",
    };
    const stdout = formatRetroBlock("security", [candidate]);
    const parsed = parseRetroBlocks(stdout);
    assert.deepEqual(parsed[0]!.candidates[0], candidate);
  });

  it("skips blocks whose body is not JSON (does not throw)", () => {
    const stdout = [
      `<<<STAMP-RETRO v=${STAMP_RETRO_VERSION} reviewer="security">>>`,
      "this is not json at all",
      "<<<END-STAMP-RETRO>>>",
      formatRetroBlock("standards", [{ kind: "convention", observation: "ok" }]),
    ].join("\n");
    const parsed = parseRetroBlocks(stdout);
    assert.equal(parsed.length, 1);
    assert.equal(parsed[0]!.reviewer, "standards");
  });

  it("skips blocks whose body fails schema validation (unknown kind, missing observation, etc.)", () => {
    const stdout = [
      `<<<STAMP-RETRO v=${STAMP_RETRO_VERSION} reviewer="security">>>`,
      JSON.stringify({ candidates: [{ kind: "process_complaint", observation: "x" }] }),
      "<<<END-STAMP-RETRO>>>",
      `<<<STAMP-RETRO v=${STAMP_RETRO_VERSION} reviewer="standards">>>`,
      JSON.stringify({ candidates: [{ kind: "convention" }] }),
      "<<<END-STAMP-RETRO>>>",
      formatRetroBlock("product", []),
    ].join("\n");
    const parsed = parseRetroBlocks(stdout);
    assert.equal(parsed.length, 1);
    assert.equal(parsed[0]!.reviewer, "product");
  });

  it("forward-compat: silently skips blocks with unknown version", () => {
    const stdout = [
      `<<<STAMP-RETRO v=999 reviewer="security">>>`,
      JSON.stringify({ anything: "from a future version" }),
      "<<<END-STAMP-RETRO>>>",
      formatRetroBlock("standards", [{ kind: "convention", observation: "ok" }]),
    ].join("\n");
    const parsed = parseRetroBlocks(stdout);
    assert.equal(parsed.length, 1);
    assert.equal(parsed[0]!.reviewer, "standards");
  });
});

describe("retro caps and exports", () => {
  it("RETRO_MAX_CANDIDATES is the documented 5", () => {
    // The cap is a wire-format-adjacent contract: the reviewer prompt and
    // the system-prompt appendix both reference "0 to 5". If this changes,
    // those copy points need to change in lockstep.
    assert.equal(RETRO_MAX_CANDIDATES, 5);
  });

  it("STAMP_RETRO_VERSION is 1", () => {
    // Bumping this is a coordinated migration with downstream parsers.
    // Bump intentionally and update the orchestrator at the same time.
    assert.equal(STAMP_RETRO_VERSION, 1);
  });
});
