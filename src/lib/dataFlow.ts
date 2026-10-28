import type { DataFlowConfig } from "./config.js";
import { isLoopbackEndpoint } from "./providerCredentials.js";

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
  // Lead with the `note:` prefix like every other stderr advisory in
  // stamp-cli (marker, warnings, errors) so an agent scanning stderr by
  // prefix can classify the line. AGT-415 product review.
  return `note: data-flow disclosure (from .stamp/config.yml):\n${text}`;
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

// ─── AGT-2248: peer listener (`stamp pr listen`) data-flow gate ─────────

/** The Anthropic API origin the Agent SDK calls when nothing overrides it. */
const DEFAULT_ANTHROPIC_ENDPOINT = "https://api.anthropic.com";

/**
 * Where the listener's Agent SDK calls (Haiku triage + Sonnet review) will
 * actually go. `host` is the `URL.host` the call hits, compared against the
 * target repo's `data_flow.peer_review_endpoints`; null means the endpoint
 * cannot be pinned to a host (Bedrock / Vertex / Foundry routing, or an
 * unparseable base URL), which the gate treats as "off-host, never
 * consented".
 */
export interface PeerLlmEndpoint {
  /** Human-readable endpoint for log lines (a URL, or the routing mode). */
  label: string;
  host: string | null;
  offHost: boolean;
}

const CLOUD_ROUTING_ENVS = [
  "CLAUDE_CODE_USE_BEDROCK",
  "CLAUDE_CODE_USE_VERTEX",
  "CLAUDE_CODE_USE_FOUNDRY",
] as const;

function envFlagOn(v: string | undefined): boolean {
  if (v === undefined) return false;
  const t = v.trim().toLowerCase();
  return t !== "" && t !== "0" && t !== "false";
}

/**
 * Resolve the listener's LLM endpoint from the env its SDK sessions inherit
 * (`reviewerChildEnv()` spreads `process.env`, and both sessions run with
 * `settingSources: []`, so no settings file can redirect them). Like
 * `stamp review` since AGT-1138, the gate asks the ENDPOINT, not the
 * backend kind: an `ANTHROPIC_BASE_URL` on loopback keeps content on this
 * host; anything else leaves it.
 */
export function resolvePeerLlmEndpoint(
  env: NodeJS.ProcessEnv = process.env,
): PeerLlmEndpoint {
  for (const name of CLOUD_ROUTING_ENVS) {
    if (envFlagOn(env[name])) {
      return { label: `${name}=1 cloud routing`, host: null, offHost: true };
    }
  }
  const base = env["ANTHROPIC_BASE_URL"]?.trim() || DEFAULT_ANTHROPIC_ENDPOINT;
  let host: string | null;
  try {
    host = new URL(base).host.toLowerCase() || null;
  } catch {
    host = null;
  }
  return { label: base, host, offHost: !isLoopbackEndpoint(base) };
}

/**
 * Decide whether the listener may send a peer PR's content (title + paths
 * to triage, the full diff to review) to `endpoint`, given the target
 * repo's `data_flow` block. The listener calls it for the block at the
 * event's `base_sha` and again for the block at the protected tip; both
 * must pass.
 *
 * Fail-closed, because the listener is unattended and cannot prompt:
 *   - loopback endpoint → allowed; nothing leaves this host (same carve-out
 *     `stamp review` makes for an all-local run).
 *   - `require_confirmation: true` without `confirmed: true` → refused,
 *     exactly as `assertDataFlowConfirmed` refuses `stamp review`.
 *   - endpoint host not listed in `peer_review_endpoints` (including the
 *     list being absent) → refused. The committed list is the repo's
 *     recorded consent for that specific endpoint.
 */
export function checkPeerDataFlow(
  dataFlow: DataFlowConfig | undefined,
  endpoint: PeerLlmEndpoint,
): { ok: true } | { ok: false; reason: string } {
  if (!endpoint.offHost) return { ok: true };
  try {
    assertDataFlowConfirmed(dataFlow);
  } catch {
    return {
      ok: false,
      reason:
        `the repo's data_flow.require_confirmation is set but data_flow.confirmed is not true; ` +
        `peer content is not sent off-host until an operator commits the confirmation`,
    };
  }
  if (endpoint.host === null) {
    return {
      ok: false,
      reason:
        `this listener's LLM endpoint (${endpoint.label}) cannot be pinned to a host, so no ` +
        `data_flow.peer_review_endpoints entry can consent to it; point ANTHROPIC_BASE_URL at ` +
        `a listed endpoint or a model on this host`,
    };
  }
  const allowed = dataFlow?.peer_review_endpoints ?? [];
  if (!allowed.includes(endpoint.host)) {
    return {
      ok: false,
      reason:
        `the repo has not consented to peer LLM review at ${endpoint.host}: add ` +
        `"${endpoint.host}" to data_flow.peer_review_endpoints in .stamp/config.yml ` +
        `(lands through stamp review) to allow it`,
    };
  }
  return { ok: true };
}

/**
 * Per-event marker for the listener — the peer twin of
 * `formatDiffSentMarker`. Names what leaves (title, paths, diff), where it
 * goes, and that it is someone else's PR.
 */
export function formatPeerEgressMarker(
  prLabel: string,
  repo: string,
  endpoint: PeerLlmEndpoint,
): string {
  if (!endpoint.offHost) {
    return `note: ${repo} ${prLabel}: peer review uses a model on this host (${endpoint.label}); content stays on this host.`;
  }
  return (
    `note: ${repo} ${prLabel}: title, changed paths and diff sent off-host to ` +
    `${endpoint.host} for peer review (allowed by data_flow.peer_review_endpoints). ` +
    `Set ${SUPPRESS_ENV}=1 to silence.`
  );
}

/** Write the peer marker to stderr unless notices are suppressed. */
export function printPeerEgressMarker(
  prLabel: string,
  repo: string,
  endpoint: PeerLlmEndpoint,
): void {
  if (noticesSuppressed()) return;
  process.stderr.write(`${formatPeerEgressMarker(prLabel, repo, endpoint)}\n`);
}
