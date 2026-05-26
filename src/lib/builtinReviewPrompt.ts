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
  "You are a peer code reviewer. Briefly summarise the diff (2-6 sentences) focused on correctness, clarity, and obvious risks. Be substantive but concise.\n\n" +
  "At the end of your response, on its own final line, output exactly one of:\n\n" +
  "  verdict: approve\n" +
  "  verdict: request-changes\n" +
  "  verdict: comment\n\n" +
  "Choose `approve` for clean, low-risk changes you would sign off on.\n" +
  "Choose `request-changes` only when there is a clear issue the author\n" +
  "should address before merge — name it in the body.\n" +
  "Choose `comment` for informational reviews, when the diff is small or\n" +
  "ambiguous, or when you're unsure. `comment` is the safe default.\n\n" +
  "Do not write anything after the verdict line.";

export const BUILTIN_PROMPT_NAME = "builtin-default";

export interface RunBuiltinReviewInput {
  /** The PR diff text to review (user message). */
  diff: string;
  /** Working directory for the SDK call. */
  cwd: string;
  /** Optional model override (passed through to query options). */
  model?: string;
  /**
   * Override the system prompt used for the review SDK call.
   * When supplied, `promptName` should also be provided for log lines.
   * Defaults to `BUILTIN_DEFAULT_PROMPT` (AC #4).
   */
  systemPrompt?: string;
  /**
   * Display name for this prompt, used in stderr log lines.
   * Defaults to `BUILTIN_PROMPT_NAME` (`"builtin-default"`).
   */
  promptName?: string;
  /**
   * Test-only injection seam: replace the real SDK `query()` call.
   * The function receives the diff as the prompt and returns the review body
   * as a string (or throws on failure).
   */
  _sdkRunnerForTest?: (diff: string) => Promise<string>;
}

export type ReviewVerdict = "approve" | "request-changes" | "comment";

export interface RunBuiltinReviewResult {
  ok: true;
  body: string;          // body WITH the verdict line stripped
  verdict: ReviewVerdict;
  /** Cost of the review SDK call in USD, from `total_cost_usd` on the result message. 0 when using a test seam or when the field is absent. */
  costUsd: number;
}

export interface RunBuiltinReviewFailure {
  ok: false;
  message: string;
}

export type RunBuiltinReviewOutcome = RunBuiltinReviewResult | RunBuiltinReviewFailure;

/**
 * Parse the raw SDK output for a verdict line and strip it from the body.
 *
 * Scans for the LAST line matching `^\s*verdict\s*:\s*(approve|request-changes|comment)\s*$`
 * (case-insensitive). If found, strips that line and any blank trailing lines
 * before it from the body and returns the parsed verdict. If not found (or
 * the value is not a recognised verdict), returns the raw text as body and
 * `verdict: "comment"` (the safe fallback).
 */
export function parseReviewVerdict(raw: string): { body: string; verdict: ReviewVerdict } {
  const lines = raw.split("\n");
  const verdictRegex = /^\s*verdict\s*:\s*(approve|request-changes|comment)\s*$/i;
  const validVerdicts = new Set(["approve", "request-changes", "comment"]);

  // Find the LAST matching verdict line (used to determine the verdict value).
  let lastVerdictIdx = -1;
  let parsedVerdict: ReviewVerdict = "comment";
  for (let i = lines.length - 1; i >= 0; i--) {
    const m = verdictRegex.exec(lines[i]!);
    if (m) {
      const v = m[1]!.toLowerCase();
      if (validVerdicts.has(v)) {
        lastVerdictIdx = i;
        parsedVerdict = v as ReviewVerdict;
        break;
      }
    }
  }

  if (lastVerdictIdx === -1) {
    // No valid verdict line found — return raw body, safe fallback.
    return { body: raw, verdict: "comment" };
  }

  // Strip the last verdict line and any blank trailing lines before it, then
  // remove any remaining verdict lines in the body (defensive against the
  // model repeating a verdict in the middle of its output).
  let endIdx = lastVerdictIdx - 1;
  while (endIdx >= 0 && lines[endIdx]!.trim() === "") {
    endIdx--;
  }

  const bodyLines = lines
    .slice(0, endIdx + 1)
    .filter((line) => !verdictRegex.test(line));

  // Trim any trailing blank lines introduced by filtering.
  let trimEnd = bodyLines.length - 1;
  while (trimEnd >= 0 && bodyLines[trimEnd]!.trim() === "") {
    trimEnd--;
  }

  const body = bodyLines.slice(0, trimEnd + 1).join("\n");
  return { body, verdict: parsedVerdict };
}

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
      const raw = await input._sdkRunnerForTest(input.diff);
      const { body, verdict } = parseReviewVerdict(raw);
      return { ok: true, body, verdict, costUsd: 0 };
    } catch (err) {
      return {
        ok: false,
        message: `builtin-default review failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  // Production: call the real SDK.
  const resolvedSystemPrompt = input.systemPrompt ?? BUILTIN_DEFAULT_PROMPT;
  try {
    const q = query({
      prompt: input.diff,
      options: {
        cwd: input.cwd,
        systemPrompt: resolvedSystemPrompt,
        maxTurns: 1,
        persistSession: false,
        ...(input.model ? { model: input.model } : {}),
      },
    });

    let finalText: string | null = null;
    let costUsd = 0;
    for await (const msg of q) {
      if (msg.type === "result" && msg.subtype === "success") {
        finalText = msg.result;
        // Capture total_cost_usd from the SDK result message (AGT-432 AC #2).
        const msgAny = msg as Record<string, unknown>;
        if (typeof msgAny["total_cost_usd"] === "number") {
          costUsd = msgAny["total_cost_usd"] as number;
        }
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

    const { body: parsedBody, verdict } = parseReviewVerdict(finalText);
    return { ok: true, body: parsedBody, verdict, costUsd };
  } catch (err) {
    return {
      ok: false,
      message: `builtin-default review failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}
