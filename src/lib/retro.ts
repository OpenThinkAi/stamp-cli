import { z } from "zod";

/**
 * Retro candidates are codebase observations a reviewer chose to leave behind
 * for the next agent — conventions worth respecting, invariants that aren't
 * obvious from the code, prior decisions worth not relitigating, gotchas the
 * next reader would otherwise rediscover the hard way. Producer-side surface
 * for the agentic-iterative-learning loop (AGT-052). Routing/dedupe lives
 * downstream in the orchestrator, not here.
 *
 * Scope is deliberately narrow: codebase observations only. NOT process
 * retrospection ("the review took too long"), NOT bug reports about the diff
 * itself (those go in the verdict prose), NOT tool-friction observations
 * (those route through a separate channel).
 */
export const RETRO_KIND_VALUES = [
  "convention",
  "invariant",
  "prior_decision",
  "gotcha",
] as const;
export type RetroKind = (typeof RETRO_KIND_VALUES)[number];

export const retroCandidateSchema = z.object({
  kind: z.enum(RETRO_KIND_VALUES),
  observation: z.string().min(1),
  /** Optional citation — typically a `file:line` or short quote. */
  evidence: z.string().optional(),
});

export type RetroCandidate = z.infer<typeof retroCandidateSchema>;

/**
 * Per-reviewer cap on candidates. A misbehaving reviewer (loop bug,
 * prompt-injection success) that calls submit_retro repeatedly has its
 * excess calls silently dropped, keeping stdout bounded. Matches the
 * `submit_verdict` last-call-wins precedent: keep the first N, drop
 * the rest, don't fail the review.
 */
export const RETRO_MAX_CANDIDATES = 5;

/**
 * Wire-format version. Bumping this is a coordinated migration with every
 * downstream parser (oteam role-pipeline et al.) — don't churn lightly.
 */
export const STAMP_RETRO_VERSION = 1;

/**
 * Fence shape: `<<<STAMP-RETRO v=1 reviewer="<name>">>>` … `<<<END-STAMP-RETRO>>>`.
 * Static (not per-call random) so orchestrators can grep deterministically
 * across runs. Reviewer names are constrained by config to `[A-Za-z0-9_-]+`,
 * which keeps the attribute form unambiguous without quoting subtleties.
 */
const REVIEWER_NAME_REGEX = /^[A-Za-z0-9_-]+$/;
const BLOCK_REGEX =
  /<<<STAMP-RETRO v=(\d+) reviewer="([A-Za-z0-9_-]+)">>>\n([\s\S]*?)\n<<<END-STAMP-RETRO>>>/g;

/**
 * Build the stdout retro block for one reviewer. Always emitted by
 * `printReview` — even when `candidates` is empty — so an orchestrator can
 * distinguish "reviewer ran with retros enabled and chose to emit nothing"
 * from "older stamp-cli version that has no retro support at all."
 */
export function formatRetroBlock(
  reviewer: string,
  candidates: RetroCandidate[],
): string {
  if (!REVIEWER_NAME_REGEX.test(reviewer)) {
    throw new Error(
      `reviewer name "${reviewer}" is not in [A-Za-z0-9_-]+; cannot be embedded in a retro fence header`,
    );
  }
  const open = `<<<STAMP-RETRO v=${STAMP_RETRO_VERSION} reviewer="${reviewer}">>>`;
  const close = `<<<END-STAMP-RETRO>>>`;
  // Escape `<` in the JSON body so that an observation discussing the retro
  // markers themselves can't appear to close the fence early. The parser
  // round-trips the body through JSON.parse, which decodes < back to
  // `<`, so this is invisible to consumers. Without this, a reviewer writing
  // about *this very feature* — a near-certain occurrence in PRs that touch
  // it — would silently drop their block: the body regex stops at the first
  // literal `\n<<<END-STAMP-RETRO>>>` it sees.
  const body = JSON.stringify({ candidates }).replace(/</g, "\\u003c");
  return `${open}\n${body}\n${close}`;
}

export interface ParsedRetroBlock {
  reviewer: string;
  candidates: RetroCandidate[];
}

/**
 * Canonical orchestrator-side parser. Scans `stdout` for every well-formed
 * `STAMP-RETRO` fence and returns the parsed contents in document order.
 * Exported so downstream consumers (oteam role-pipeline, e2e tests) use the
 * same parser the formatter is paired with — no hand-rolled regex drift.
 *
 * Forward-compat: blocks with an unknown `v=` are silently skipped so that a
 * future stamp-cli emitting `v=2` content doesn't crash an orchestrator
 * pinned to today's parser. The orchestrator simply sees no retros from
 * those reviewers and continues.
 *
 * Robustness: blocks whose body fails JSON parse or schema validation are
 * dropped (not thrown). A retro channel that hard-fails the orchestrator on
 * one malformed block would defeat its own purpose — the rest of the run's
 * outputs (verdicts, prose, other reviewers' retros) must still flow.
 */
export function parseRetroBlocks(stdout: string): ParsedRetroBlock[] {
  const out: ParsedRetroBlock[] = [];
  const bodySchema = z.object({ candidates: z.array(retroCandidateSchema) });
  for (const m of stdout.matchAll(BLOCK_REGEX)) {
    const version = Number(m[1]);
    if (version !== STAMP_RETRO_VERSION) continue;
    const reviewer = m[2]!;
    const body = m[3]!;
    let parsed: unknown;
    try {
      parsed = JSON.parse(body);
    } catch {
      continue;
    }
    const result = bodySchema.safeParse(parsed);
    if (!result.success) continue;
    out.push({ reviewer, candidates: result.data.candidates });
  }
  return out;
}
