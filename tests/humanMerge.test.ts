/**
 * Tests for the audit-H1 operator-confirmation gate.
 *
 * The hard cases:
 *   - no-TTY + no opt-out  → throws (the central behaviour change of C1)
 *   - --yes flag           → bypass
 *   - env var set to "0"   → bypass
 *   - branch config flag   → bypass
 *   - any-other env value  → no bypass (defends against
 *                            STAMP_REQUIRE_HUMAN_MERGE="" silently disabling)
 *
 * The interactive prompt path is exercised manually; piping a 'y' line on
 * stdin requires a process spawn rather than an in-process call, which is
 * heavier than this unit test wants.
 */

import { strict as assert } from "node:assert";
import { afterEach, beforeEach, describe, it } from "node:test";

import type { BranchRule } from "../src/lib/config.ts";
import { requireHumanMerge } from "../src/lib/humanMerge.ts";

const baseRule: BranchRule = { required: ["security", "standards", "product"] };

const baseArgs = {
  target: "main",
  source: "feature",
  base_sha: "0".repeat(40),
  head_sha: "f".repeat(40),
  branchRule: baseRule,
  yes: false,
};

describe("requireHumanMerge — opt-outs", () => {
  let savedEnv: string | undefined;
  let savedStdinIsTTY: unknown;
  let savedStdoutIsTTY: unknown;

  beforeEach(() => {
    savedEnv = process.env.STAMP_REQUIRE_HUMAN_MERGE;
    delete process.env.STAMP_REQUIRE_HUMAN_MERGE;
    // Force "no TTY" so the absence of an opt-out throws rather than
    // blocking on a real prompt. Tests assert opt-outs by *not* throwing.
    savedStdinIsTTY = (process.stdin as { isTTY?: boolean }).isTTY;
    savedStdoutIsTTY = (process.stdout as { isTTY?: boolean }).isTTY;
    (process.stdin as { isTTY?: boolean }).isTTY = false;
    (process.stdout as { isTTY?: boolean }).isTTY = false;
  });

  afterEach(() => {
    if (savedEnv === undefined) delete process.env.STAMP_REQUIRE_HUMAN_MERGE;
    else process.env.STAMP_REQUIRE_HUMAN_MERGE = savedEnv;
    (process.stdin as { isTTY?: boolean }).isTTY = savedStdinIsTTY as boolean;
    (process.stdout as { isTTY?: boolean }).isTTY = savedStdoutIsTTY as boolean;
  });

  it("throws when no TTY and no opt-out is set", () => {
    assert.throws(
      () => requireHumanMerge(baseArgs),
      /no TTY/,
    );
  });

  it("throws message uses the 'confirmation required:' discriminator (agent regex contract)", () => {
    let thrown: Error | null = null;
    try {
      requireHumanMerge(baseArgs);
    } catch (e) {
      thrown = e as Error;
    }
    assert.ok(thrown);
    assert.match(thrown!.message, /^confirmation required:/);
  });

  it("throws message names all three opt-out paths so the operator can pick one", () => {
    let thrown: Error | null = null;
    try {
      requireHumanMerge(baseArgs);
    } catch (e) {
      thrown = e as Error;
    }
    assert.ok(thrown);
    assert.match(thrown!.message, /--yes/);
    assert.match(thrown!.message, /STAMP_REQUIRE_HUMAN_MERGE=0/);
    assert.match(thrown!.message, /require_human_merge: false/);
  });

  it("returns silently when --yes is passed", () => {
    requireHumanMerge({ ...baseArgs, yes: true });
  });

  it("returns silently when STAMP_REQUIRE_HUMAN_MERGE=0", () => {
    process.env.STAMP_REQUIRE_HUMAN_MERGE = "0";
    requireHumanMerge(baseArgs);
  });

  it("returns silently when branch config opts out", () => {
    requireHumanMerge({
      ...baseArgs,
      branchRule: { ...baseRule, require_human_merge: false },
    });
  });

  it("does NOT bypass on STAMP_REQUIRE_HUMAN_MERGE=1 (defaults are already on; only =0 means bypass)", () => {
    process.env.STAMP_REQUIRE_HUMAN_MERGE = "1";
    assert.throws(() => requireHumanMerge(baseArgs), /no TTY/);
  });

  it("does NOT bypass on STAMP_REQUIRE_HUMAN_MERGE='' (empty != 0)", () => {
    process.env.STAMP_REQUIRE_HUMAN_MERGE = "";
    assert.throws(() => requireHumanMerge(baseArgs), /no TTY/);
  });

  it("does NOT bypass when require_human_merge is true (the default)", () => {
    assert.throws(
      () =>
        requireHumanMerge({
          ...baseArgs,
          branchRule: { ...baseRule, require_human_merge: true },
        }),
      /no TTY/,
    );
  });

  it("config-level opt-out wins even when --yes is also set (idempotent allow)", () => {
    requireHumanMerge({
      ...baseArgs,
      yes: true,
      branchRule: { ...baseRule, require_human_merge: false },
    });
  });
});
