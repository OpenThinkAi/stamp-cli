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
 * AC#2 (AGT-414): diffStat is printed above the confirmation prompt when
 * present. Exercised via the _readLine test seam.
 *
 * AC#3 (AGT-414): require_human_merge: "strict" requires operator to type
 * `merge <source> -> <target>`. Exercised via the _readLine test seam.
 */

import { strict as assert } from "node:assert";
import { afterEach, beforeEach, describe, it } from "node:test";

import type { BranchRule } from "../src/lib/config.ts";
import { parseConfigFromYaml } from "../src/lib/config.ts";
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

// ──────────────────────────────────────────────────────────────────────────────
// AC#2 (AGT-414): diffStat is printed above the prompt when present.
// ──────────────────────────────────────────────────────────────────────────────

describe("requireHumanMerge — diffStat display (AC#2)", () => {
  let savedStdinIsTTY: unknown;
  let savedStdoutIsTTY: unknown;
  const writtenLines: string[] = [];
  let origWrite: typeof process.stdout.write;

  beforeEach(() => {
    savedStdinIsTTY = (process.stdin as { isTTY?: boolean }).isTTY;
    savedStdoutIsTTY = (process.stdout as { isTTY?: boolean }).isTTY;
    (process.stdin as { isTTY?: boolean }).isTTY = true;
    (process.stdout as { isTTY?: boolean }).isTTY = true;
    writtenLines.length = 0;
    // Intercept stdout.write so we can inspect what the function prints.
    origWrite = process.stdout.write.bind(process.stdout);
    (process.stdout as { write: unknown }).write = (chunk: unknown) => {
      writtenLines.push(String(chunk));
      return true;
    };
  });

  afterEach(() => {
    (process.stdin as { isTTY?: boolean }).isTTY = savedStdinIsTTY as boolean;
    (process.stdout as { isTTY?: boolean }).isTTY = savedStdoutIsTTY as boolean;
    (process.stdout as { write: unknown }).write = origWrite;
  });

  it("prints diffStat above the prompt when provided", () => {
    const stat = " src/foo.ts | 10 +++++-----\n 1 file changed, 5 insertions(+), 5 deletions(-)";
    // _readLine returns "y" to confirm so the function returns cleanly.
    requireHumanMerge({
      ...baseArgs,
      diffStat: stat,
      _readLine: () => "y",
    });
    const allOutput = writtenLines.join("");
    assert.ok(
      allOutput.includes("src/foo.ts"),
      "diffStat content must appear in stdout output",
    );
    assert.ok(
      allOutput.includes("5 insertions"),
      "diffStat churn counts must appear in stdout output",
    );
  });

  it("does not print anything for diffStat when absent", () => {
    requireHumanMerge({
      ...baseArgs,
      _readLine: () => "y",
    });
    const allOutput = writtenLines.join("");
    // Only the prompt itself should appear (no stat block).
    assert.ok(
      !allOutput.includes("file changed"),
      "No diffStat in output when not provided",
    );
  });

  it("does not print diffStat when it is whitespace-only", () => {
    requireHumanMerge({
      ...baseArgs,
      diffStat: "   \n  ",
      _readLine: () => "y",
    });
    const allOutput = writtenLines.join("");
    assert.ok(
      !allOutput.includes("file changed"),
      "Blank diffStat must not produce output",
    );
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// AC#3 (AGT-414): require_human_merge: "strict" typed-phrase prompt.
// ──────────────────────────────────────────────────────────────────────────────

describe("requireHumanMerge — strict phrase (AC#3)", () => {
  let savedStdinIsTTY: unknown;
  let savedStdoutIsTTY: unknown;
  let savedWrite: typeof process.stdout.write;

  beforeEach(() => {
    savedStdinIsTTY = (process.stdin as { isTTY?: boolean }).isTTY;
    savedStdoutIsTTY = (process.stdout as { isTTY?: boolean }).isTTY;
    savedWrite = process.stdout.write.bind(process.stdout);
    (process.stdin as { isTTY?: boolean }).isTTY = true;
    (process.stdout as { isTTY?: boolean }).isTTY = true;
    // Silence stdout for these tests — we only care about throws/returns.
    (process.stdout as { write: unknown }).write = () => true;
  });

  afterEach(() => {
    (process.stdin as { isTTY?: boolean }).isTTY = savedStdinIsTTY as boolean;
    (process.stdout as { isTTY?: boolean }).isTTY = savedStdoutIsTTY as boolean;
    (process.stdout as { write: unknown }).write = savedWrite;
  });

  const strictRule: BranchRule = {
    required: ["security", "standards", "product"],
    require_human_merge: "strict",
  };

  it("returns when operator types the exact phrase 'merge <source> -> <target>'", () => {
    requireHumanMerge({
      ...baseArgs,
      branchRule: strictRule,
      _readLine: () => "merge feature -> main",
    });
    // No throw = success
  });

  it("throws when operator types a wrong phrase", () => {
    assert.throws(
      () =>
        requireHumanMerge({
          ...baseArgs,
          branchRule: strictRule,
          _readLine: () => "y",
        }),
      /strict confirmation required/,
    );
  });

  it("throws when operator types an empty phrase", () => {
    assert.throws(
      () =>
        requireHumanMerge({
          ...baseArgs,
          branchRule: strictRule,
          _readLine: () => "",
        }),
      /<empty>/,
    );
  });

  it("throws when operator types the phrase with wrong source", () => {
    assert.throws(
      () =>
        requireHumanMerge({
          ...baseArgs,
          branchRule: strictRule,
          _readLine: () => "merge wrong-branch -> main",
        }),
      /strict confirmation required/,
    );
  });

  it("three opt-outs still work when require_human_merge is 'strict'", () => {
    // --yes bypasses even in strict mode (opt-outs precede the prompt).
    requireHumanMerge({
      ...baseArgs,
      branchRule: strictRule,
      yes: true,
    });
    // STAMP_REQUIRE_HUMAN_MERGE=0 bypasses.
    const saved = process.env.STAMP_REQUIRE_HUMAN_MERGE;
    try {
      process.env.STAMP_REQUIRE_HUMAN_MERGE = "0";
      requireHumanMerge({ ...baseArgs, branchRule: strictRule });
    } finally {
      if (saved === undefined) delete process.env.STAMP_REQUIRE_HUMAN_MERGE;
      else process.env.STAMP_REQUIRE_HUMAN_MERGE = saved;
    }
  });

  it("require_human_merge === 'strict' does NOT coerce into the === false bypass (no-coerce invariant)", () => {
    // 'strict' is truthy but must NOT satisfy the `=== false` opt-out check.
    // With TTY forced to false, we should get the no-TTY error rather than
    // silently returning (which would mean strict coerced into the false path).
    const savedStdin = (process.stdin as { isTTY?: boolean }).isTTY;
    const savedStdout = (process.stdout as { isTTY?: boolean }).isTTY;
    (process.stdin as { isTTY?: boolean }).isTTY = false;
    (process.stdout as { isTTY?: boolean }).isTTY = false;
    try {
      assert.throws(
        () => requireHumanMerge({ ...baseArgs, branchRule: strictRule }),
        /confirmation required/,
        "'strict' must NOT be treated as === false (must not silently bypass the gate)",
      );
    } finally {
      (process.stdin as { isTTY?: boolean }).isTTY = savedStdin;
      (process.stdout as { isTTY?: boolean }).isTTY = savedStdout;
    }
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// AC#3 (AGT-414): config parser round-trip for require_human_merge: "strict"
// ──────────────────────────────────────────────────────────────────────────────

describe("parseConfigFromYaml — require_human_merge: strict (AC#3)", () => {
  const cfg = (rhm: string) => `
branches:
  main:
    required: [security]
    require_human_merge: ${rhm}
reviewers:
  security:
    prompt: .stamp/reviewers/security.md
`;

  it("parses require_human_merge: true", () => {
    const c = parseConfigFromYaml(cfg("true"));
    assert.strictEqual(c.branches.main?.require_human_merge, true);
  });

  it("parses require_human_merge: false", () => {
    const c = parseConfigFromYaml(cfg("false"));
    assert.strictEqual(c.branches.main?.require_human_merge, false);
  });

  it('parses require_human_merge: "strict"', () => {
    const c = parseConfigFromYaml(cfg('"strict"'));
    assert.strictEqual(c.branches.main?.require_human_merge, "strict");
  });

  it("rejects other string values", () => {
    assert.throws(
      () => parseConfigFromYaml(cfg('"yes"')),
      /require_human_merge must be a boolean or "strict"/,
    );
    assert.throws(
      () => parseConfigFromYaml(cfg('"always"')),
      /require_human_merge must be a boolean or "strict"/,
    );
  });

  it("rejects numeric values", () => {
    assert.throws(
      () => parseConfigFromYaml(cfg("1")),
      /require_human_merge must be a boolean or "strict"/,
    );
  });
});
