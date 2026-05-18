/**
 * Local-only review plan emission (design.md "Local-only mode (Option E)").
 *
 * Stamp's role in local-only mode ends here: it emits a structured plan
 * describing the diff to review and the reviewers (with their full prompt
 * text + per-reviewer fence hex) so a parent agent — currently a Claude
 * Code session with an Agent tool — can dispatch N parallel subagents that
 * review independently. There is no `stamp record-feedback` round-trip; the
 * parent already has each subagent's response and doesn't need stamp to
 * format or persist it.
 *
 * The plan carries NO trust property: no verdict is signed, no attestation
 * is produced, and a banner (emitted to stderr by the command layer) tells
 * the parent agent so. Local-only mode is an iteration aid only; the
 * verifiable-verdict path requires a `review_server` (M2, server-attested
 * reviews — see AGT-327).
 *
 * Schema-stability contract: AGT-340 ships a Claude Code skill that
 * consumes this output, so the JSON shape here is a published contract.
 * Field renames, removals, or type changes break that skill. Adding
 * optional fields is fine; treat the existing fields as load-bearing.
 */

import { randomBytes } from "node:crypto";

import { parseConfigFromYaml, type StampConfig } from "./config.js";
import { resolveDiff, showAtRef, type ResolvedDiff } from "./git.js";
import { stampConfigFile } from "./paths.js";

/**
 * One entry per reviewer in the plan. The parent agent uses this to
 * dispatch a subagent: it builds a prompt around `prompt` (the full
 * reviewer-prompt bytes, sourced from the merge-base tree) and embeds the
 * diff inside per-reviewer `fence_hex` markers so an attacker who controls
 * diff content cannot trivially close the fence and emit out-of-band
 * instructions. Mirrors the trusted-mode reviewer.ts pattern.
 */
export interface ReviewPlanReviewer {
  /** Reviewer key as it appears in `.stamp/config.yml` (e.g. "security"). */
  name: string;
  /**
   * Full text of the reviewer prompt file (e.g. `.stamp/reviewers/security.md`),
   * read from the merge-base tree at `base_sha`. NOT a hash — the parent
   * agent dispatches subagents with this exact prompt body as system text.
   */
  prompt: string;
  /**
   * Per-reviewer random hex used as the diff-fence boundary marker. The
   * parent should embed the diff between `<<<DIFF-{fence_hex}>>>` and
   * `<<<END-DIFF-{fence_hex}>>>` (matching the trusted-mode convention so
   * the same prompt-injection mitigations transfer). Each reviewer gets a
   * fresh hex so subagent prompts cannot collide.
   */
  fence_hex: string;
}

/**
 * Top-level plan emitted on stdout by `stamp review --plan`. Stable JSON
 * shape — AGT-340 (Claude Code skill) parses this directly.
 *
 * `schema_version` is a forward-compat hook for the skill: it should refuse
 * to consume a major version it doesn't recognize. Adding fields keeps the
 * version stable; renaming or removing fields bumps it.
 */
export interface ReviewPlan {
  /** Plan-shape version. Bumped on breaking changes only. */
  schema_version: 1;
  /** Original revspec the operator passed (e.g. "main..HEAD"). */
  revspec: string;
  /** Merge-base commit SHA of the diff. */
  base_sha: string;
  /** Head commit SHA being reviewed. */
  head_sha: string;
  /** Unified diff text covering base..head. */
  diff: string;
  /** Reviewers (and their prompt bodies + fences) the parent should dispatch. */
  reviewers: ReviewPlanReviewer[];
}

/**
 * Banner the command layer writes to stderr when emitting a plan. Lives
 * here (not in the command) so the wording stays under the lib's
 * versioning — if the contract changes, the test that pins this string
 * forces a deliberate update. Wording aligned with design.md "Local-only
 * mode (Option E)".
 */
export const PLAN_NO_TRUST_BANNER =
  "This produces iteration feedback only. No attestation will be created. " +
  "To produce a verifiable verdict, configure a `review_server` in `.stamp/config.yml`.";

export interface BuildReviewPlanOptions {
  /** Git revspec to review, e.g. "main..HEAD". */
  diff: string;
  /** If set, restrict the plan to a single reviewer by name (matches `stamp review --only`). */
  only?: string;
  /** Repo root (absolute path); the command layer resolves this from cwd. */
  repoRoot: string;
}

/**
 * Build a `ReviewPlan` from a repo + diff revspec. Mirrors the security
 * properties of `runReview`:
 *
 *   - `.stamp/config.yml` AND each reviewer prompt are sourced from the
 *     merge-base tree, NOT the working tree. Reading from the working tree
 *     would let a feature branch ship a modified reviewer prompt and have
 *     that prompt review its own introduction.
 *   - The reviewer set is the one configured at `base_sha`. If the branch
 *     ADDS a new reviewer, the new reviewer cannot review its own
 *     introduction — deliberate boundary, same as trusted mode.
 *
 * Does NOT call the LLM, does NOT touch the verdict cache, does NOT write
 * to state.db. Pure plan emission.
 */
export function buildReviewPlan(opts: BuildReviewPlanOptions): ReviewPlan {
  const configPath = stampConfigFile(opts.repoRoot);
  // The command layer already throws a friendly "run `stamp init`" error
  // when the config file is missing, so this function assumes the caller
  // has verified existence. We re-read via `git show` against base_sha
  // anyway, so a missing working-tree config is not the failure mode we
  // catch here.
  void configPath;

  const resolved: ResolvedDiff = resolveDiff(opts.diff, opts.repoRoot);

  let baseConfigYaml: string;
  try {
    baseConfigYaml = showAtRef(resolved.base_sha, ".stamp/config.yml", opts.repoRoot);
  } catch (err) {
    throw new Error(
      `failed to read .stamp/config.yml at base ${resolved.base_sha.slice(0, 8)}: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  const config: StampConfig = parseConfigFromYaml(baseConfigYaml);

  const reviewerNames = chooseReviewers(config, opts.only);
  if (reviewerNames.length === 0) {
    throw new Error(
      `no reviewers to plan at base ${resolved.base_sha.slice(0, 8)} (config there has ${Object.keys(config.reviewers).length} configured). ` +
        `If this branch ADDS a new reviewer, the new reviewer cannot review its own introduction — ` +
        `that's a deliberate security boundary. Land the reviewer in a separate PR first, then it can ` +
        `review subsequent diffs.`,
    );
  }

  const reviewers: ReviewPlanReviewer[] = [];
  for (const name of reviewerNames) {
    const def = config.reviewers[name]!;
    let prompt: string;
    try {
      prompt = showAtRef(resolved.base_sha, def.prompt, opts.repoRoot);
    } catch (err) {
      throw new Error(
        `failed to read prompt for reviewer "${name}" from base ${resolved.base_sha.slice(0, 8)}: ` +
          `${err instanceof Error ? err.message : String(err)}. ` +
          `(The reviewer is configured at the base but its prompt file is missing there.)`,
      );
    }
    reviewers.push({
      name,
      prompt,
      // Per-reviewer 16-byte hex — same length / generation as the
      // trusted-mode reviewer.ts so the parent agent's fence handling
      // transfers without re-tuning. Independent per reviewer so two
      // subagent prompts can't collide on the same boundary marker.
      fence_hex: randomBytes(16).toString("hex"),
    });
  }

  return {
    schema_version: 1,
    revspec: opts.diff,
    base_sha: resolved.base_sha,
    head_sha: resolved.head_sha,
    diff: resolved.diff,
    reviewers,
  };
}

function chooseReviewers(config: StampConfig, only?: string): string[] {
  if (only) {
    if (!(only in config.reviewers)) {
      throw new Error(
        `reviewer "${only}" is not configured. Available: ${
          Object.keys(config.reviewers).join(", ") || "(none)"
        }`,
      );
    }
    return [only];
  }
  return Object.keys(config.reviewers);
}
