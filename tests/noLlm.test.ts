/**
 * Tests for STAMP_NO_LLM=1 — operator-declared mode that refuses to
 * invoke the Claude Agent SDK for any reviewer call. Closes the memo's
 * "diffs ship verbatim to Anthropic" categorical objection: with this
 * env var on, stamp's signing + verification primitives keep working
 * but no review will start.
 *
 * Same env-equality strictness as STAMP_REQUIRE_HUMAN_MERGE and
 * STAMP_HASH_MCP_NAMES — only the literal string "1" enables the
 * refusal; "true", "yes", and "" all remain enabled-LLM mode.
 */

import { strict as assert } from "node:assert";
import { afterEach, beforeEach, describe, it } from "node:test";

import { invokeReviewer } from "../src/lib/reviewer.ts";
import type { StampConfig } from "../src/lib/config.ts";

// Minimal config the function will accept. The test never actually
// reaches the SDK call site because STAMP_NO_LLM=1 throws first.
const cfg: StampConfig = {
  branches: { main: { required: ["security"] } },
  reviewers: { security: { prompt: ".stamp/reviewers/security.md" } },
};

const baseArgs = {
  reviewer: "security",
  config: cfg,
  repoRoot: "/tmp/whatever",
  diff: "diff --git a/x b/x\nindex 0..0 100644\n",
  base_sha: "0".repeat(40),
  head_sha: "f".repeat(40),
  systemPrompt: "you are a reviewer",
};

describe("STAMP_NO_LLM=1 short-circuit", () => {
  let saved: string | undefined;

  beforeEach(() => {
    saved = process.env.STAMP_NO_LLM;
  });

  afterEach(() => {
    if (saved === undefined) delete process.env.STAMP_NO_LLM;
    else process.env.STAMP_NO_LLM = saved;
  });

  it("throws synchronously before touching the SDK when STAMP_NO_LLM=1", async () => {
    process.env.STAMP_NO_LLM = "1";
    await assert.rejects(
      () => invokeReviewer(baseArgs),
      /STAMP_NO_LLM=1 is set/,
    );
  });

  it("error message names the disabled surfaces and the unset path", async () => {
    process.env.STAMP_NO_LLM = "1";
    let err: Error | null = null;
    try {
      await invokeReviewer(baseArgs);
    } catch (e) {
      err = e as Error;
    }
    assert.ok(err);
    // Names the affected stamp surfaces…
    assert.match(err!.message, /review/);
    // …and the still-working primitives so an operator deciding whether
    // to opt in knows what they keep.
    assert.match(err!.message, /verify|merge|keys/);
    // …and how to disable.
    assert.match(err!.message, /Unset STAMP_NO_LLM/);
  });

  it("does NOT short-circuit on STAMP_NO_LLM='0'", async () => {
    // The strict-equality pattern: only the literal "1" enables the
    // refusal. Anything else (including the legacy-shaped "0" that
    // STAMP_HASH_MCP_NAMES uses for opt-out) is normal-LLM mode.
    process.env.STAMP_NO_LLM = "0";
    // We won't reach the SDK in this test (no real auth, no real repo),
    // but the throw we DO hit must NOT be the STAMP_NO_LLM throw.
    await assert.rejects(
      () => invokeReviewer(baseArgs),
      (err: Error) => !err.message.includes("STAMP_NO_LLM=1 is set"),
    );
  });

  it("does NOT short-circuit on STAMP_NO_LLM='true' / '' / unset", async () => {
    for (const v of ["true", "", "yes", "on"]) {
      process.env.STAMP_NO_LLM = v;
      await assert.rejects(
        () => invokeReviewer(baseArgs),
        (err: Error) =>
          !err.message.includes("STAMP_NO_LLM=1 is set"),
        `STAMP_NO_LLM=${JSON.stringify(v)} must NOT trigger the short-circuit`,
      );
    }
    delete process.env.STAMP_NO_LLM;
    await assert.rejects(
      () => invokeReviewer(baseArgs),
      (err: Error) => !err.message.includes("STAMP_NO_LLM=1 is set"),
      "unset STAMP_NO_LLM must NOT trigger the short-circuit",
    );
  });
});
