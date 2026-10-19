/**
 * Extended-thinking policy for Anthropic reviewer calls: OFF by default.
 *
 * Why: Claude 5-generation models run ADAPTIVE thinking whenever the request
 * omits `thinking`. On a review that makes the call slow and can spend the
 * whole output budget before the verdict arrives. A reviewer reads a diff
 * and returns a verdict; it does not need a reasoning pass before it
 * answers. So every Anthropic reviewer call sends that model's thinking-off
 * value, unless the operator opts back in.
 *
 * "Off" is spelled differently per model. Verified against the live API on
 * 2026-10-19:
 *
 *   claude-sonnet-5-5           `{type:"between_tools"}`. `disabled` is a 400
 *                               ("send between_tools instead"). The model does
 *                               not think before it answers; it may think
 *                               only between tool calls.
 *   claude-opus-5-5, claude-fable-*
 *                               adaptive only: both `disabled` and
 *                               `between_tools` are a 400, so nothing is sent
 *                               and the model keeps its default.
 *   claude-sonnet-5, claude-opus-5, claude-haiku-5-5, every claude-*-4-*
 *   and claude-3* model         `{type:"disabled"}`.
 *   anything else               nothing sent. An unknown id keeps the SDK
 *                               default rather than risk a 400 that would
 *                               fail every review.
 *
 * Two transports, two knobs:
 *
 *   - Headless and server-side reviews call the Messages API directly
 *     (`@anthropic-ai/sdk`), so they send `thinking` in the request body
 *     (`anthropicThinkingParam`).
 *   - Trusted-mode reviews go through the Claude Agent SDK, which spawns the
 *     Claude Code CLI. Its `thinking` option only knows
 *     adaptive/enabled/disabled, and the CLI (2.1.296) DROPS `disabled` for
 *     5.5-generation models instead of forwarding it. The request goes out
 *     with no `thinking` field, which on those models means adaptive.
 *     `--thinking` rejects `between_tools`, and `maxThinkingTokens: 0`,
 *     `alwaysThinkingEnabled: false` and `effort` do not turn it off either.
 *     The one knob that reaches the wire is the CLI's `CLAUDE_CODE_EXTRA_BODY`
 *     env var, which merges a JSON object into each request body. So the
 *     Agent SDK path sets that (`agentSdkThinkingOptions`) and also passes
 *     `thinking: {type:"disabled"}`, which stops the CLI adding its
 *     `clear_thinking` context-management edit. The API rejects that edit
 *     unless thinking is on.
 *
 * Opt back in with `STAMP_REVIEWER_THINKING=1` (every reviewer, this run), or
 * per reviewer with `reviewer_thinking: { <name>: true }` in
 * `~/.stamp/config.yml`. `STAMP_REVIEWER_THINKING=0` forces thinking off even
 * where the per-user config turned it on. Thinking on means "send nothing":
 * the model's own default applies, as it did before 3.6.0.
 */

import { loadUserConfig, type UserConfig } from "./userConfig.js";

/** The `thinking` value that turns thinking off for a given model. */
export type ThinkingOffParam = { type: "disabled" } | { type: "between_tools" };

/** Strip a provider/proxy prefix (`anthropic/`, `us.anthropic.`) and any
 *  bracketed suffix (`[1m]`) so the family checks below see the bare id. */
function bareModelId(model: string): string {
  let id = model.trim().toLowerCase();
  const slash = id.lastIndexOf("/");
  if (slash >= 0) id = id.slice(slash + 1);
  const claude = id.indexOf("claude-");
  if (claude > 0) id = id.slice(claude);
  const bracket = id.indexOf("[");
  if (bracket >= 0) id = id.slice(0, bracket);
  return id;
}

/**
 * The thinking-off value for `model`, or null when nothing should be sent
 * (adaptive-only models, unknown ids, or no model at all). See the module
 * comment for the table and how it was verified.
 */
export function thinkingOffParamFor(
  model: string | null | undefined,
): ThinkingOffParam | null {
  if (!model) return null;
  const id = bareModelId(model);
  if (!id.startsWith("claude-")) return null;

  // Adaptive-only: reject both disabled and between_tools.
  if (id.startsWith("claude-fable-")) return null;
  if (/^claude-opus-5-5(?:$|-)/.test(id)) return null;

  // Rejects disabled; between_tools is its thinking-off mode.
  if (/^claude-sonnet-5-5(?:$|-)/.test(id)) return { type: "between_tools" };

  // Accept disabled.
  if (/^claude-haiku-5-5(?:$|-)/.test(id)) return { type: "disabled" };
  // claude-sonnet-5 / claude-opus-5, bare or dated (claude-opus-5-20261001),
  // but not a later point release such as claude-opus-5-6.
  if (/^claude-(?:sonnet|opus)-5(?:$|-\d{8}$)/.test(id)) {
    return { type: "disabled" };
  }
  if (/^claude-(?:sonnet|opus|haiku)-4(?:$|-)/.test(id)) {
    return { type: "disabled" };
  }
  if (/^claude-3/.test(id)) return { type: "disabled" };

  return null;
}

/** Env var that restores the model's default thinking for every reviewer. */
export const REVIEWER_THINKING_ENV = "STAMP_REVIEWER_THINKING";

function parseThinkingEnv(raw: string | undefined): boolean | undefined {
  const v = raw?.trim().toLowerCase();
  if (!v) return undefined;
  if (["1", "true", "on", "yes"].includes(v)) return true;
  if (["0", "false", "off", "no"].includes(v)) return false;
  return undefined;
}

/**
 * Whether `reviewer` runs with the model's default thinking (true) or with
 * thinking off (false, the default). Precedence: `STAMP_REVIEWER_THINKING`
 * env > `reviewer_thinking.<name>` in `~/.stamp/config.yml` > off.
 *
 * `cfg` is injectable for tests and for callers that already loaded the
 * config. When omitted the file is read, and a load error counts as "no
 * config", the same hot-path posture as `resolveReviewerBackend`.
 */
export function reviewerThinkingEnabled(
  reviewer: string | undefined,
  cfg?: UserConfig | null,
): boolean {
  const env = parseThinkingEnv(process.env[REVIEWER_THINKING_ENV]);
  if (env !== undefined) return env;
  if (reviewer === undefined) return false;
  let config = cfg;
  if (config === undefined) {
    try {
      config = loadUserConfig();
    } catch {
      config = null;
    }
  }
  return config?.reviewer_thinking?.[reviewer] ?? false;
}

/**
 * The `thinking` field for a direct Messages API call, or undefined to omit
 * it (thinking on, or a model that takes no thinking-off value).
 */
export function anthropicThinkingParam(
  model: string | null | undefined,
  thinkingEnabled: boolean,
): ThinkingOffParam | undefined {
  if (thinkingEnabled) return undefined;
  return thinkingOffParamFor(model) ?? undefined;
}

/** The CLI env var that merges a JSON object into each API request body. */
export const CLAUDE_CODE_EXTRA_BODY_ENV = "CLAUDE_CODE_EXTRA_BODY";

/**
 * Extra `query()` options that turn thinking off on the Agent SDK path:
 * `thinking: {type:"disabled"}` plus a child-process `env` whose
 * `CLAUDE_CODE_EXTRA_BODY` carries the model's real thinking-off value (see
 * the module comment for why both are needed). Returns `{}` when there is
 * nothing to send.
 *
 * `baseEnv` is the environment the child would otherwise inherit. The SDK's
 * `env` option REPLACES `process.env` rather than merging with it, so it is
 * spread in full. An operator's own `CLAUDE_CODE_EXTRA_BODY` is kept: stamp
 * adds `thinking` only when that object has none, and leaves the variable
 * alone (and sends nothing) if it is not a JSON object.
 */
export function agentSdkThinkingOptions(
  model: string | null | undefined,
  thinkingEnabled: boolean,
  baseEnv: NodeJS.ProcessEnv = process.env,
): {
  thinking?: { type: "disabled" };
  env?: Record<string, string | undefined>;
} {
  const off = anthropicThinkingParam(model, thinkingEnabled);
  if (off === undefined) return {};

  const existingRaw = baseEnv[CLAUDE_CODE_EXTRA_BODY_ENV];
  let extra: Record<string, unknown> = {};
  if (existingRaw !== undefined && existingRaw.trim() !== "") {
    let parsed: unknown;
    try {
      parsed = JSON.parse(existingRaw);
    } catch {
      return {};
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {};
    }
    extra = parsed as Record<string, unknown>;
    if (Object.prototype.hasOwnProperty.call(extra, "thinking")) return {};
  }

  return {
    thinking: { type: "disabled" },
    env: {
      ...baseEnv,
      [CLAUDE_CODE_EXTRA_BODY_ENV]: JSON.stringify({ ...extra, thinking: off }),
    },
  };
}
