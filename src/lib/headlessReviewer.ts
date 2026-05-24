/**
 * Headless local-only fallback (AGT-341). Sibling to `stamp review --plan`
 * for contexts where there is no parent Claude Code session to dispatch
 * subagents — cron jobs, git hooks, CI steps, ad-hoc scripts. The
 * trade-off: instead of running through a parent's interactive Claude Code
 * session (unmetered by the June 15 split), the operator pays the per-token
 * Anthropic API bill via their own `ANTHROPIC_API_KEY`. Documented in
 * docs/local-only-mode.md.
 *
 * **This is the no-trust, no-attestation path.** Identical trust posture to
 * `--plan` mode: the bytes that come back are iteration feedback only;
 * nothing is signed, nothing is cached in state.db, and `stamp merge` is
 * NOT unlocked. See HEADLESS_NO_TRUST_BANNER.
 *
 * This module is now a thin Anthropic-specific wrapper around the
 * backend-agnostic core in `oneShotReview.ts`: it constructs an Anthropic
 * client from `ANTHROPIC_API_KEY` and delegates the prompt-build /
 * verdict-extract / single-call loop to `runOneShotReview`. The trusted
 * local-model backend (LM Studio etc.) injects a different client into the
 * same core; the only difference is that the trusted caller persists the
 * verdict and this one does not.
 *
 * Auto-detect of "is there a parent agent?" was deliberately SKIPPED — the
 * SDK exposes no reliable signal and `isTTY === false` false-positives in
 * CI. Headless stays an explicit flag.
 */

import Anthropic from "@anthropic-ai/sdk";

import type { ReviewPlanReviewer } from "./reviewPlan.js";
import {
  runOneShotReview,
  type ChatClientShape,
  type OneShotReviewResult,
} from "./oneShotReview.js";

// Re-export the shared surface under the historical headless names so
// existing importers (commands/review.ts, src/server/reviewPipeline.ts,
// and the test suite) keep resolving these from here.
export { SUBMIT_VERDICT_TOOL } from "./oneShotReview.js";
export type AnthropicClientShape = ChatClientShape;
export type HeadlessReviewerResult = OneShotReviewResult;

/**
 * Default model id for headless reviewers when no per-reviewer pin exists
 * in `~/.stamp/config.yml`. Matches the per-reviewer Sonnet defaults
 * shipped for trusted mode (see src/lib/userConfig.ts) so an operator with
 * a pin gets a consistent model across modes, and an operator with no pin
 * gets the same Sonnet model both ways.
 *
 * Bump in lockstep with `DEFAULT_REVIEWER_MODELS` in userConfig.ts if/when
 * the project moves off Sonnet 4.6.
 */
export const HEADLESS_DEFAULT_MODEL = "claude-sonnet-4-6";

/**
 * No-trust banner for headless mode. Wording diverges from
 * PLAN_NO_TRUST_BANNER by one sentence (the API-key metering caveat) so
 * operators piping `stamp review --headless` into a script see the billing
 * implication on stderr without needing to read the docs.
 *
 * Keep in lockstep with PLAN_NO_TRUST_BANNER's `note: ` lowercase prefix +
 * plain-sentence shape (no terminal newline; the caller writes it).
 */
export const HEADLESS_NO_TRUST_BANNER =
  "note: this produces iteration feedback only. No attestation will be created. " +
  "Headless mode uses your ANTHROPIC_API_KEY (API-billed, separate from " +
  "Claude Code subscription). " +
  "To produce a verifiable verdict, configure a `review_server` in `.stamp/config.yml`.";

/**
 * Thrown by `runHeadlessReview` when ANTHROPIC_API_KEY is not set. Caught
 * by commands/review.ts and re-thrown as a UsageError (exit code 2) so an
 * agent loop can distinguish missing-key from a real runtime failure
 * without parsing stderr.
 *
 * Carries the canonical docs pointer in its message — operators see the
 * remediation path inline rather than having to grep for it.
 */
export class MissingApiKeyError extends Error {
  constructor() {
    super(
      "ANTHROPIC_API_KEY is not set. Headless mode (`stamp review --headless`) " +
        "calls the Anthropic API directly and requires the key to be exported " +
        "in the environment. " +
        "If you have a parent Claude Code session, use `stamp review --plan` " +
        "instead (it dispatches reviewers through the parent agent and does " +
        "not need an API key). " +
        "See docs/local-only-mode.md for setup details.",
    );
    this.name = "MissingApiKeyError";
  }
}

export interface RunHeadlessReviewOptions {
  /** The plan entry built by buildReviewPlan() — name, prompt, fence_hex. */
  reviewer: ReviewPlanReviewer;
  /** Resolved diff bytes (the full base..head diff). */
  diff: string;
  /** Base sha for prompt context. */
  base_sha: string;
  /** Head sha for prompt context. */
  head_sha: string;
  /** Resolved model id (caller threads in resolveReviewerModel result or
   *  HEADLESS_DEFAULT_MODEL). */
  model: string;
  /** Inject a custom client for testing. Production callers leave unset; we
   *  construct an Anthropic client from ANTHROPIC_API_KEY (env). */
  client?: ChatClientShape;
}

/**
 * Run one reviewer against a diff via a single Anthropic Messages call.
 * Returns a `HeadlessReviewerResult` (never throws for runtime failures):
 * API failures, parse failures, and missing-tool failures all fold into
 * `result.error` with `verdict: null`.
 *
 * **Exception:** MissingApiKeyError IS thrown (as a rejection) when no API
 * key is configured AND no client was injected. The command layer catches
 * it BEFORE the fan-out so the operator sees one clear "set
 * ANTHROPIC_API_KEY" message instead of N copies. Tests inject a `client`
 * to bypass the env check.
 */
export async function runHeadlessReview(
  opts: RunHeadlessReviewOptions,
): Promise<HeadlessReviewerResult> {
  const client = opts.client ?? buildClientFromEnv();
  return runOneShotReview({
    reviewer: opts.reviewer,
    diff: opts.diff,
    base_sha: opts.base_sha,
    head_sha: opts.head_sha,
    model: opts.model,
    client,
  });
}

/**
 * Construct the production Anthropic client from `ANTHROPIC_API_KEY`.
 * Throws `MissingApiKeyError` if the env var is unset — caught by the
 * command layer and re-thrown as a UsageError so the CLI exits 2 with the
 * docs pointer.
 */
function buildClientFromEnv(): ChatClientShape {
  const apiKey = process.env["ANTHROPIC_API_KEY"];
  if (!apiKey) throw new MissingApiKeyError();
  return new Anthropic({ apiKey }) as unknown as ChatClientShape;
}
