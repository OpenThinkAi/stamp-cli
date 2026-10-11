/**
 * Unit tests for the AI-attribution commit-message policy (AGT-1724 /
 * GH#81) — the shared pattern module used by both `stamp merge` and the
 * server pre-receive hook.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  ATTRIBUTION_ENV_VAR,
  DEFAULT_ATTRIBUTION_PATTERNS,
  envEnablesAttributionPolicy,
  findAttributionMatches,
  formatViolations,
  parseAttributionConfig,
  parseCommitMessageLog,
  resolveAttributionPolicy,
  scanCommitMessages,
} from "../src/lib/attributionPolicy.ts";

const DEFAULTS = [...DEFAULT_ATTRIBUTION_PATTERNS];

function ids(message: string, patterns = DEFAULTS): string[] {
  return findAttributionMatches(message, patterns).map((m) => m.patternId);
}

describe("default attribution patterns", () => {
  it("catches a Claude-Session trailer", () => {
    assert.deepEqual(
      ids("fix: thing\n\nbody\n\nClaude-Session: https://example.invalid/x\n"),
      ["claude-session-trailer"],
    );
  });

  it("matches case-insensitively", () => {
    assert.deepEqual(ids("x\n\nclaude-session: abc"), ["claude-session-trailer"]);
    assert.deepEqual(
      ids("x\n\nco-authored-by: claude <noreply@anthropic.com>"),
      ["co-authored-by-claude"],
    );
  });

  it("catches Co-Authored-By Claude and Co-Authored-By anthropic", () => {
    assert.deepEqual(
      ids("x\n\nCo-Authored-By: Claude Opus <noreply@example.invalid>"),
      ["co-authored-by-claude"],
    );
    assert.deepEqual(
      ids("x\n\nCo-Authored-By: Bot <bot@anthropic.com>"),
      ["co-authored-by-claude"],
    );
  });

  it("catches the Generated with Claude Code footer, with or without link brackets", () => {
    assert.deepEqual(
      ids("x\n\n🤖 Generated with [Claude Code](https://example.invalid)"),
      ["generated-with-claude-code"],
    );
    assert.deepEqual(ids("x\n\nGenerated with Claude Code"), [
      "generated-with-claude-code",
    ]);
  });

  it("catches a claude.ai/code/session_ URL anywhere in a line", () => {
    assert.deepEqual(
      ids("x\n\nsee https://claude.ai/code/session_01ABC for context"),
      ["claude-ai-session-url"],
    );
  });

  it("reports every matching line (trailer + URL on the same line hit both)", () => {
    const m = ids(
      "x\n\nClaude-Session: https://claude.ai/code/session_01ABC",
    );
    assert.deepEqual(m.sort(), ["claude-ai-session-url", "claude-session-trailer"]);
  });
});

describe("no false positives", () => {
  const clean = [
    "Fix the Claude reviewer prompt for the security persona",
    "Bump @anthropic-ai/sdk to 0.40",
    "docs: explain how stamp talks to Claude Code",
    "Co-Authored-By: Jane Doe <jane@example.invalid>",
    "Mention Claude-Session trailers in the README", // not at line start
    "see https://claude.ai/docs for the API",
    "Generated with a script",
  ];
  for (const msg of clean) {
    it(`does not flag: ${JSON.stringify(msg)}`, () => {
      assert.deepEqual(ids(`subject\n\n${msg}\n`), []);
    });
  }

  it("is message-only: a diff mentioning attribution is irrelevant because only messages are scanned", () => {
    // The scanner's input is commit messages; this asserts a clean message
    // stays clean even though the change it describes adds these strings.
    const msg = "Add AI-attribution policy patterns (AGT-1724, #81)\n\nAdds the Claude-Session and Co-Authored-By checks.";
    assert.deepEqual(ids(msg), []);
  });
});

describe("env toggle", () => {
  it("is off by default", () => {
    assert.equal(envEnablesAttributionPolicy({}), false);
    assert.equal(resolveAttributionPolicy({}, {}).enabled, false);
  });

  it("is on for 1 / true / yes / on", () => {
    for (const v of ["1", "true", "TRUE", "yes", "on", " 1 "]) {
      assert.equal(
        envEnablesAttributionPolicy({ [ATTRIBUTION_ENV_VAR]: v }),
        true,
        v,
      );
    }
  });

  it("stays off for 0 / false / empty / junk", () => {
    for (const v of ["0", "false", "", "maybe"]) {
      assert.equal(
        envEnablesAttributionPolicy({ [ATTRIBUTION_ENV_VAR]: v }),
        false,
        v,
      );
    }
  });
});

describe("per-repo config override", () => {
  const ON = { [ATTRIBUTION_ENV_VAR]: "1" };

  it("absent block → defaults, env decides", () => {
    const parsed = parseAttributionConfig({ branches: {} });
    assert.deepEqual(parsed, { config: {}, errors: [] });
    const p = resolveAttributionPolicy(parsed.config, ON);
    assert.equal(p.enabled, true);
    assert.equal(p.patterns.length, DEFAULTS.length);
  });

  it("enabled: false disables even when the env var is on", () => {
    const parsed = parseAttributionConfig({
      commit_policy: { forbid_ai_attribution: { enabled: false } },
    });
    assert.equal(resolveAttributionPolicy(parsed.config, ON).enabled, false);
  });

  it("enabled: true enables even when the env var is off", () => {
    const parsed = parseAttributionConfig({
      commit_policy: { forbid_ai_attribution: { enabled: true } },
    });
    assert.equal(resolveAttributionPolicy(parsed.config, {}).enabled, true);
  });

  it("boolean shorthand works", () => {
    const parsed = parseAttributionConfig({
      commit_policy: { forbid_ai_attribution: true },
    });
    assert.deepEqual(parsed, { config: { enabled: true }, errors: [] });
  });

  it("extra_patterns extend the defaults", () => {
    const parsed = parseAttributionConfig({
      commit_policy: {
        forbid_ai_attribution: { extra_patterns: ["^Assisted-By:"] },
      },
    });
    assert.deepEqual(parsed.errors, []);
    const p = resolveAttributionPolicy(parsed.config, ON);
    assert.equal(p.patterns.length, DEFAULTS.length + 1);
    assert.deepEqual(ids("x\n\nassisted-by: some agent", p.patterns), [
      "extra_patterns[0]",
    ]);
    // Defaults still apply.
    assert.deepEqual(ids("x\n\nClaude-Session: y", p.patterns), [
      "claude-session-trailer",
    ]);
  });

  it("disable_patterns drops named defaults", () => {
    const parsed = parseAttributionConfig({
      commit_policy: {
        forbid_ai_attribution: { disable_patterns: ["claude-ai-session-url"] },
      },
    });
    assert.deepEqual(parsed.errors, []);
    const p = resolveAttributionPolicy(parsed.config, ON);
    assert.deepEqual(
      ids("x\n\nsee https://claude.ai/code/session_01ABC", p.patterns),
      [],
    );
    assert.deepEqual(ids("x\n\nClaude-Session: y", p.patterns), [
      "claude-session-trailer",
    ]);
  });

  it("reports invalid config without throwing, keeping what parsed", () => {
    const parsed = parseAttributionConfig({
      commit_policy: {
        forbid_ai_attribution: {
          enabled: "yes",
          extra_patterns: ["(unclosed", "^Ok:"],
          disable_patterns: ["no-such-pattern"],
        },
      },
    });
    assert.equal(parsed.errors.length, 3);
    assert.match(parsed.errors.join("\n"), /enabled must be a boolean/);
    assert.match(parsed.errors.join("\n"), /extra_patterns\[0\] is not a valid regex/);
    assert.match(parsed.errors.join("\n"), /unknown pattern id "no-such-pattern"/);
    assert.deepEqual(parsed.config.extra_patterns, ["^Ok:"]);
    assert.equal(parsed.config.enabled, undefined);
  });

  it("rejects a non-mapping commit_policy", () => {
    assert.match(
      parseAttributionConfig({ commit_policy: "on" }).errors[0] ?? "",
      /commit_policy must be a mapping/,
    );
  });
});

describe("commit log parsing + scanning", () => {
  const A = "a".repeat(40);
  const B = "b".repeat(40);

  it("parses git log -z --format=%H%n%B output", () => {
    const raw =
      `${A}\nfirst subject\n\nbody line\n\0` +
      `${B}\nsecond subject\n\nClaude-Session: x\n\0`;
    const commits = parseCommitMessageLog(raw);
    assert.equal(commits.length, 2);
    assert.equal(commits[0]!.sha, A);
    assert.match(commits[0]!.message, /^first subject/);
    assert.equal(commits[1]!.sha, B);
  });

  it("returns empty for empty output", () => {
    assert.deepEqual(parseCommitMessageLog(""), []);
  });

  it("scan names offending SHAs and lines", () => {
    const commits = parseCommitMessageLog(
      `${A}\nclean\n\0${B}\nattributed\n\nClaude-Session: x\n\0`,
    );
    const v = scanCommitMessages(commits, DEFAULTS);
    assert.equal(v.length, 1);
    assert.equal(v[0]!.sha, B);
    assert.equal(v[0]!.subject, "attributed");
    const report = formatViolations(v);
    assert.match(report, new RegExp(`^${B.slice(0, 12)} attributed`));
    assert.match(report, /\[claude-session-trailer\] Claude-Session: x/);
  });
});
