import type { DataFlowConfig } from "./config.js";

/**
 * AGT-415 — per-invocation data-flow disclosure for `stamp review`.
 *
 * Four behaviours, all hanging off the same theme (the diff leaves the
 * host on every review):
 *
 *   1. A terse per-invocation stderr MARKER, fired on every review in both
 *      the direct-to-Anthropic and `review_server` transports — distinct
 *      from the once-per-repo notice in `llmNotice.ts`, which only fires
 *      the first time per repo.
 *   2. An ECHO of the operator-authored `data_flow.disclosure` block, when
 *      one is committed.
 *   3. A confirmation GATE: when `data_flow.require_confirmation: true` is
 *      committed but `confirmed: true` is not, review refuses to run.
 *   4. A loud WARNING when `STAMP_ANTHROPIC_NO_RETAIN=1` is set, because
 *      this SDK version exposes no honoured request-level zero-retention
 *      knob (Anthropic ZDR is an account-level contract). Better to say so
 *      than to imply a guarantee that isn't there.
 *
 * The marker and echo share the `STAMP_SUPPRESS_LLM_NOTICE=1` suppress
 * switch with the once-per-repo notice: an operator who opted out once
 * stays opted out. The gate and the no-retain warning are NOT suppressible
 * — a refusal isn't a notice, and silently muting a security-posture
 * warning is exactly the over-promise this ticket exists to avoid.
 */

const SUPPRESS_ENV = "STAMP_SUPPRESS_LLM_NOTICE";

function noticesSuppressed(): boolean {
  return process.env[SUPPRESS_ENV] === "1";
}

/**
 * AC #1 — the per-invocation marker line. Mode-neutral wording ("off-host")
 * so it reads accurately whether the diff goes directly to Anthropic or
 * through a `review_server` that calls Anthropic on the client's behalf.
 */
export function formatDiffSentMarker(reviewerCount: number): string {
  const plural = reviewerCount === 1 ? "reviewer" : "reviewers";
  return (
    `note: diff sent off-host for review (${reviewerCount} ${plural}). ` +
    `Set ${SUPPRESS_ENV}=1 to silence.`
  );
}

/** Write the per-invocation marker to stderr unless notices are suppressed. */
export function printDiffSentMarker(reviewerCount: number): void {
  if (noticesSuppressed()) return;
  process.stderr.write(`${formatDiffSentMarker(reviewerCount)}\n`);
}

/**
 * AC #2 — render the operator-authored disclosure block, or null when
 * there's nothing to echo. Pure so it's trivially testable; the printer
 * below handles the suppress switch + stderr write.
 */
export function formatDataFlowDisclosure(
  dataFlow: DataFlowConfig | undefined,
): string | null {
  const text = dataFlow?.disclosure?.trim();
  if (!text) return null;
  return `data-flow disclosure (from .stamp/config.yml):\n${text}`;
}

/** Echo the committed disclosure block to stderr unless notices are suppressed. */
export function printDataFlowDisclosure(
  dataFlow: DataFlowConfig | undefined,
): void {
  if (noticesSuppressed()) return;
  const block = formatDataFlowDisclosure(dataFlow);
  if (block) process.stderr.write(`${block}\n`);
}

/**
 * AC #3 — opt-in confirmation gate. Refuses (throws) only when the
 * operator has armed the gate with `require_confirmation: true` AND has
 * not committed `confirmed: true`. A disclosure-only block (or no block at
 * all) never blocks.
 *
 * Reads from a `DataFlowConfig` already sourced from the merge-base tree
 * by the caller — see `runReview`, which parses config from `base_sha`.
 */
export function assertDataFlowConfirmed(
  dataFlow: DataFlowConfig | undefined,
): void {
  if (!dataFlow?.require_confirmation) return;
  if (dataFlow.confirmed === true) return;
  throw new Error(
    `data_flow.require_confirmation is set in .stamp/config.yml, but ` +
      `data_flow.confirmed is not true — refusing to run \`stamp review\` ` +
      `because this repo requires an explicit, committed acknowledgement ` +
      `that the diff is sent off-host to a sub-processor (Anthropic) for ` +
      `review. To proceed, an operator must commit \`data_flow.confirmed: ` +
      `true\` to .stamp/config.yml (the acknowledgement itself goes through ` +
      `stamp review, leaving an audit record). To stop sending diffs ` +
      `off-host entirely, set STAMP_NO_LLM=1.`,
  );
}

const NO_RETAIN_ENV = "STAMP_ANTHROPIC_NO_RETAIN";

/**
 * AC #4 — `STAMP_ANTHROPIC_NO_RETAIN=1` warning string, or null when the
 * flag isn't set. The flag is a documented NO-OP: the installed Claude
 * Agent SDK exposes no honoured request-level zero-retention control, and
 * Anthropic Zero Data Retention is an account-level contract, not a
 * per-request flag/header/env var. We warn rather than silently no-op so
 * an operator never believes retention is disabled when it isn't.
 */
export function formatNoRetainWarning(): string | null {
  if (process.env[NO_RETAIN_ENV] !== "1") return null;
  return (
    `warning: ${NO_RETAIN_ENV}=1 is set, but it is a NO-OP in this build. ` +
    `The Claude Agent SDK exposes no honoured request-level zero-retention ` +
    `control, and Anthropic Zero Data Retention (ZDR) is an account-level ` +
    `contract — it cannot be toggled per request via an env var or header. ` +
    `Diffs are still sent off-host with whatever retention posture your ` +
    `Anthropic account has. To actually bound exposure: arrange a ZDR ` +
    `contract with Anthropic, or set STAMP_NO_LLM=1 to stop sending diffs ` +
    `off-host. See README "Data flow / privacy".`
  );
}

/**
 * Print the no-retain warning when the flag is set. Deliberately NOT gated
 * by STAMP_SUPPRESS_LLM_NOTICE: the operator set a flag that implies a
 * privacy guarantee, and they need to know it isn't honoured.
 */
export function printNoRetainWarning(): void {
  const warning = formatNoRetainWarning();
  if (warning) process.stderr.write(`${warning}\n`);
}
