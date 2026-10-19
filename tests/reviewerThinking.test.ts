/**
 * Unit tests for src/lib/reviewerThinking.ts: the per-model thinking-off
 * mapping, the opt-in precedence (env > per-user config > off), and the two
 * transports (direct Messages API param, Agent SDK options + env).
 *
 * The mapping table mirrors what the live API accepted on 2026-10-19. A
 * change here should come with a fresh live check, not just a test edit.
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import {
  CLAUDE_CODE_EXTRA_BODY_ENV,
  REVIEWER_THINKING_ENV,
  agentSdkThinkingOptions,
  anthropicThinkingParam,
  reviewerThinkingEnabled,
  thinkingOffParamFor,
} from "../src/lib/reviewerThinking.ts";
import {
  DEFAULT_REVIEWER_MODELS,
  parseUserConfig,
  stringifyUserConfig,
  writeUserConfig,
} from "../src/lib/userConfig.ts";
import {
  HEADLESS_DEFAULT_MODEL,
  runHeadlessReview,
  type AnthropicClientShape,
} from "../src/lib/headlessReviewer.ts";

let savedThinking: string | undefined;
let savedHome: string | undefined;
let tmpHome: string;

beforeEach(() => {
  savedThinking = process.env[REVIEWER_THINKING_ENV];
  delete process.env[REVIEWER_THINKING_ENV];
  savedHome = process.env.HOME;
  tmpHome = mkdtempSync(join(tmpdir(), "stamp-thinking-"));
  process.env.HOME = tmpHome;
});

afterEach(() => {
  if (savedThinking === undefined) delete process.env[REVIEWER_THINKING_ENV];
  else process.env[REVIEWER_THINKING_ENV] = savedThinking;
  if (savedHome === undefined) delete process.env.HOME;
  else process.env.HOME = savedHome;
  rmSync(tmpHome, { recursive: true, force: true });
});

describe("thinkingOffParamFor: per-model mapping", () => {
  it("sends between_tools for claude-sonnet-5-5 (it rejects disabled)", () => {
    assert.deepEqual(thinkingOffParamFor("claude-sonnet-5-5"), {
      type: "between_tools",
    });
    assert.deepEqual(thinkingOffParamFor("claude-sonnet-5-5-20261001"), {
      type: "between_tools",
    });
  });

  it("sends nothing for adaptive-only models", () => {
    assert.equal(thinkingOffParamFor("claude-opus-5-5"), null);
    assert.equal(thinkingOffParamFor("claude-fable-5"), null);
    assert.equal(thinkingOffParamFor("claude-fable-5-5"), null);
  });

  it("sends disabled for models that accept it", () => {
    for (const id of [
      "claude-sonnet-4-6",
      "claude-sonnet-4-5",
      "claude-opus-4-7",
      "claude-haiku-4-5",
      "claude-haiku-4-5-20251001",
      "claude-sonnet-5",
      "claude-opus-5",
      "claude-opus-5-20261001",
      "claude-haiku-5-5",
      "claude-3-5-sonnet-20241022",
    ]) {
      assert.deepEqual(thinkingOffParamFor(id), { type: "disabled" }, id);
    }
  });

  it("sends nothing for unknown, future, or non-Claude ids", () => {
    for (const id of [
      "claude-opus-5-6",
      "claude-sonnet-6",
      "gpt-5",
      "qwen3-coder-30b",
      "",
    ]) {
      assert.equal(thinkingOffParamFor(id), null, id);
    }
    assert.equal(thinkingOffParamFor(null), null);
    assert.equal(thinkingOffParamFor(undefined), null);
  });

  it("sees through provider prefixes and bracketed suffixes", () => {
    assert.deepEqual(thinkingOffParamFor("anthropic/claude-sonnet-5-5"), {
      type: "between_tools",
    });
    assert.deepEqual(thinkingOffParamFor("us.anthropic.claude-sonnet-4-6"), {
      type: "disabled",
    });
    assert.deepEqual(thinkingOffParamFor("claude-sonnet-5-5[1m]"), {
      type: "between_tools",
    });
  });
});

describe("default model", () => {
  it("ships claude-sonnet-5-5 everywhere, which maps to between_tools", () => {
    for (const model of Object.values(DEFAULT_REVIEWER_MODELS)) {
      assert.equal(model, "claude-sonnet-5-5");
    }
    assert.equal(HEADLESS_DEFAULT_MODEL, "claude-sonnet-5-5");
    assert.deepEqual(anthropicThinkingParam(HEADLESS_DEFAULT_MODEL, false), {
      type: "between_tools",
    });
  });
});

describe("reviewerThinkingEnabled: precedence", () => {
  it("is off by default", () => {
    assert.equal(reviewerThinkingEnabled("security", null), false);
    assert.equal(reviewerThinkingEnabled(undefined), false);
  });

  it("honours reviewer_thinking in the per-user config", () => {
    const cfg = parseUserConfig(
      "reviewers:\n  security: claude-sonnet-5-5\nreviewer_thinking:\n  security: true\n",
    );
    assert.equal(reviewerThinkingEnabled("security", cfg), true);
    assert.equal(reviewerThinkingEnabled("standards", cfg), false);
  });

  it("reads ~/.stamp/config.yml when no config is passed", () => {
    writeUserConfig({ reviewers: {}, reviewer_thinking: { product: true } });
    assert.equal(reviewerThinkingEnabled("product"), true);
    assert.equal(reviewerThinkingEnabled("security"), false);
  });

  it("lets STAMP_REVIEWER_THINKING override the config both ways", () => {
    const cfg = parseUserConfig("reviewer_thinking:\n  security: true\n");
    process.env[REVIEWER_THINKING_ENV] = "1";
    assert.equal(reviewerThinkingEnabled("standards", cfg), true);
    assert.equal(reviewerThinkingEnabled(undefined), true);
    process.env[REVIEWER_THINKING_ENV] = "0";
    assert.equal(reviewerThinkingEnabled("security", cfg), false);
    process.env[REVIEWER_THINKING_ENV] = "garbage";
    assert.equal(reviewerThinkingEnabled("security", cfg), true);
  });
});

describe("reviewer_thinking config parsing", () => {
  it("round-trips through stringify", () => {
    const cfg = parseUserConfig(
      "reviewers:\n  security: claude-sonnet-5-5\nreviewer_thinking:\n  security: true\n  product: false\n",
    );
    assert.deepEqual(cfg.reviewer_thinking, { security: true, product: false });
    assert.deepEqual(parseUserConfig(stringifyUserConfig(cfg)), cfg);
  });

  it("rejects non-boolean values and bad reviewer names", () => {
    assert.throws(
      () => parseUserConfig('reviewer_thinking:\n  security: "false"\n'),
      /reviewer_thinking\.security must be a boolean/,
    );
    assert.throws(
      () => parseUserConfig("reviewer_thinking:\n  -bad: true\n"),
      /reviewer name '-bad' under 'reviewer_thinking' is invalid/,
    );
    assert.throws(
      () => parseUserConfig("reviewer_thinking: [security]\n"),
      /'reviewer_thinking' must be a mapping/,
    );
  });
});

describe("anthropicThinkingParam", () => {
  it("omits the field when thinking is enabled", () => {
    assert.equal(anthropicThinkingParam("claude-sonnet-5-5", true), undefined);
  });
  it("omits the field for adaptive-only models", () => {
    assert.equal(anthropicThinkingParam("claude-opus-5-5", false), undefined);
  });
});

describe("agentSdkThinkingOptions", () => {
  const baseEnv = { PATH: "/usr/bin", HOME: "/home/x" };

  it("passes thinking:disabled plus CLAUDE_CODE_EXTRA_BODY with the real value", () => {
    const opts = agentSdkThinkingOptions("claude-sonnet-5-5", false, baseEnv);
    assert.deepEqual(opts.thinking, { type: "disabled" });
    assert.equal(opts.env?.PATH, "/usr/bin", "env must carry the inherited vars");
    assert.deepEqual(JSON.parse(opts.env![CLAUDE_CODE_EXTRA_BODY_ENV]!), {
      thinking: { type: "between_tools" },
    });
  });

  it("uses disabled in the extra body for models that accept it", () => {
    const opts = agentSdkThinkingOptions("claude-haiku-5-5", false, baseEnv);
    assert.deepEqual(JSON.parse(opts.env![CLAUDE_CODE_EXTRA_BODY_ENV]!), {
      thinking: { type: "disabled" },
    });
  });

  it("returns nothing for thinking-on, adaptive-only, and unpinned models", () => {
    assert.deepEqual(agentSdkThinkingOptions("claude-sonnet-5-5", true, baseEnv), {});
    assert.deepEqual(agentSdkThinkingOptions("claude-opus-5-5", false, baseEnv), {});
    assert.deepEqual(agentSdkThinkingOptions(null, false, baseEnv), {});
  });

  it("merges into an operator's own CLAUDE_CODE_EXTRA_BODY", () => {
    const opts = agentSdkThinkingOptions("claude-sonnet-5-5", false, {
      ...baseEnv,
      [CLAUDE_CODE_EXTRA_BODY_ENV]: '{"metadata":{"user_id":"u"}}',
    });
    assert.deepEqual(JSON.parse(opts.env![CLAUDE_CODE_EXTRA_BODY_ENV]!), {
      metadata: { user_id: "u" },
      thinking: { type: "between_tools" },
    });
  });

  it("leaves an operator's own thinking key, or an unparseable value, alone", () => {
    assert.deepEqual(
      agentSdkThinkingOptions("claude-sonnet-5-5", false, {
        ...baseEnv,
        [CLAUDE_CODE_EXTRA_BODY_ENV]: '{"thinking":{"type":"adaptive"}}',
      }),
      {},
    );
    assert.deepEqual(
      agentSdkThinkingOptions("claude-sonnet-5-5", false, {
        ...baseEnv,
        [CLAUDE_CODE_EXTRA_BODY_ENV]: "not json",
      }),
      {},
    );
  });
});

describe("headless path sends the thinking field", () => {
  function capturingClient(sent: unknown[]): AnthropicClientShape {
    return {
      messages: {
        create: async (params) => {
          sent.push(params);
          return {
            content: [
              {
                type: "tool_use",
                name: "submit_verdict",
                input: { verdict: "approved", prose: "ok" },
              },
            ],
          } as unknown as Awaited<ReturnType<AnthropicClientShape["messages"]["create"]>>;
        },
      },
    };
  }

  const base = {
    reviewer: { name: "security", prompt: "# r\n", fence_hex: "ab".repeat(16) },
    diff: "diff --git a/x b/x\n+y\n",
    base_sha: "1".repeat(40),
    head_sha: "2".repeat(40),
  };

  it("sends between_tools for claude-sonnet-5-5 by default", async () => {
    const sent: Array<Record<string, unknown>> = [];
    await runHeadlessReview({ ...base, model: "claude-sonnet-5-5", client: capturingClient(sent) });
    assert.deepEqual(sent[0]!.thinking, { type: "between_tools" });
  });

  it("omits thinking when the reviewer opted in", async () => {
    const sent: Array<Record<string, unknown>> = [];
    await runHeadlessReview({
      ...base,
      model: "claude-sonnet-5-5",
      client: capturingClient(sent),
      thinkingEnabled: true,
    });
    assert.equal("thinking" in sent[0]!, false);
  });

  it("omits thinking for an adaptive-only model", async () => {
    const sent: Array<Record<string, unknown>> = [];
    await runHeadlessReview({ ...base, model: "claude-opus-5-5", client: capturingClient(sent) });
    assert.equal("thinking" in sent[0]!, false);
  });
});
