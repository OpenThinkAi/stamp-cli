/**
 * Built-in default review prompt for `stamp pr listen` (AGT-429).
 *
 * Provides a single hard-coded system prompt and a thin `runBuiltinReview`
 * wrapper around the Claude Agent SDK's `query()`. This is intentionally
 * NOT the heavy `invokeReviewer` path in reviewer.ts — no MCP tools, no
 * verdict tooling, no prompt-injection fences, no per-reviewer config.
 * The wire-frame uses a minimal direct SDK call per the approved plan.
 *
 * Named prompt: `"builtin-default"` (logged to stderr by prListen.ts).
 *
 * Injection seam: `_sdkRunnerForTest` replaces the real SDK call in tests.
 */

import { query } from "@anthropic-ai/claude-agent-sdk";

export const BUILTIN_DEFAULT_PROMPT =
  "You are a code reviewer. Summarize the key changes in the diff below and rate the overall quality. " +
  "Be concise: 2–4 sentences max. Focus on correctness, clarity, and any obvious risks. " +
  "Do not request changes or approvals — this is a peer summary only.";

export const BUILTIN_PROMPT_NAME = "builtin-default";

export interface RunBuiltinReviewInput {
  /** The PR diff text to review (user message). */
  diff: string;
  /** Working directory for the SDK call. */
  cwd: string;
  /** Optional model override (passed through to query options). */
  model?: string;
  /**
   * Test-only injection seam: replace the real SDK `query()` call.
   * The function receives the diff as the prompt and returns the review body
   * as a string (or throws on failure).
   */
  _sdkRunnerForTest?: (diff: string) => Promise<string>;
}

export interface RunBuiltinReviewResult {
  ok: true;
  body: string;
}

export interface RunBuiltinReviewFailure {
  ok: false;
  message: string;
}

export type RunBuiltinReviewOutcome = RunBuiltinReviewResult | RunBuiltinReviewFailure;

/**
 * Run a single hard-coded peer-review query against the diff using the
 * Claude Agent SDK. Returns `{ ok: true, body }` on success.
 *
 * Honors `STAMP_NO_LLM=1` by refusing before the SDK call, consistent
 * with `invokeReviewer` in reviewer.ts.
 */
export async function runBuiltinReview(
  input: RunBuiltinReviewInput,
): Promise<RunBuiltinReviewOutcome> {
  if (process.env["STAMP_NO_LLM"] === "1") {
    return {
      ok: false,
      message:
        "STAMP_NO_LLM=1 is set; refusing to invoke the Claude Agent SDK " +
        "for the builtin-default peer review.",
    };
  }

  // Test injection: bypass real SDK.
  if (input._sdkRunnerForTest) {
    try {
      const body = await input._sdkRunnerForTest(input.diff);
      return { ok: true, body };
    } catch (err) {
      return {
        ok: false,
        message: `builtin-default review failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  // Production: call the real SDK.
  try {
    const q = query({
      prompt: input.diff,
      options: {
        cwd: input.cwd,
        systemPrompt: BUILTIN_DEFAULT_PROMPT,
        maxTurns: 1,
        persistSession: false,
        ...(input.model ? { model: input.model } : {}),
      },
    });

    let finalText: string | null = null;
    for await (const msg of q) {
      if (msg.type === "result" && msg.subtype === "success") {
        finalText = msg.result;
        break;
      }
      if (msg.type === "result") {
        return {
          ok: false,
          message: `builtin-default review SDK returned non-success result: ${msg.subtype}`,
        };
      }
    }

    if (finalText === null) {
      return {
        ok: false,
        message: "builtin-default review SDK returned no result message",
      };
    }

    return { ok: true, body: finalText };
  } catch (err) {
    return {
      ok: false,
      message: `builtin-default review failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}
