/**
 * Persona/config consistency lint (issue #53, AGT-878).
 *
 * A reviewer configured with `enforce_reads_on_dotstamp: true` whose persona
 * prompt tells it to IGNORE `.stamp/` is a structurally contradictory
 * configuration: the persona steers the model away from ever Reading those
 * files, while the harness voids any approval whose tool trace lacks a Read
 * of every modified `.stamp/*` path. Observed on fx-tracker 2026-07-04; it
 * cost two wasted review rounds before anyone noticed.
 *
 * The runtime already papers over the worst of it — `buildDotstampReadDirective`
 * (src/lib/reviewer.ts, issue #52) injects an up-front Read directive that
 * explicitly supersedes persona scope exclusions, so a compliant reviewer can
 * pass on the first round. This lint closes the loop at *config* level: the
 * contradiction is still a latent authoring bug worth telling the operator
 * about, because a persona and its enforcement flag disagreeing about scope
 * is a smell regardless of whether the harness can rescue it.
 *
 * SCOPE: this is a static text heuristic over the persona prompt. It reports;
 * it never changes what the reviewer is allowed to do. The runtime
 * enforcement (`findMissingDotstampReads`) is untouched by anything here —
 * a clean lint does not buy a reviewer any slack, and a dirty lint does not
 * take any away.
 */

/** A single suspected `.stamp/`-exclusion in a persona prompt. */
export interface DotstampExclusionHit {
  /** 1-indexed line number within the prompt. */
  line: number;
  /** The offending line, trimmed and length-capped for terminal display. */
  text: string;
  /** The exclusion wording that matched, for the operator-facing report. */
  cue: string;
}

/** Cap on how much of an offending line we echo back. Persona prompts can
 *  contain very long lines; an unbounded echo wrecks the report layout. */
const MAX_ECHO = 140;

/** Only lines that actually name `.stamp` are candidates. */
const DOTSTAMP_MENTION = /\.stamp\b/i;

/**
 * Wordings that indicate "this is not yours to review". Deliberately narrow:
 * a false positive here fails an operator's `stamp reviewers verify` (exit
 * LOCK_DRIFT_EXIT), so the bar is "would a reader agree this line excludes
 * `.stamp/` from review", not "does this line mention scope at all".
 *
 * Each is matched only on lines that also mention `.stamp`.
 */
const EXCLUSION_CUES: readonly RegExp[] = [
  /\b(?:ignore|ignoring|skip|skipping|exclude|excluding|excluded|disregard|omit|omitting)\b/gi,
  /\bout[ -]of[ -]scope\b/gi,
  /\bnot (?:in scope|in your scope|your (?:concern|problem|scope|responsibility)|yours)\b/gi,
  /\bseparate concern\b/gi,
  /\b(?:don'?t|do not|never) (?:review|read|inspect|examine|look at|worry about|bother with)\b/gi,
  /\bno need to (?:review|read|inspect|examine|look at)\b/gi,
  /\bnot (?:reviewed|covered|considered|checked)\b/gi,
];

/**
 * Negation guard. "Do NOT ignore `.stamp/` changes" contains the cue
 * "ignore" but says the opposite; flagging it would be actively misleading.
 * We look at the text immediately preceding a cue match (same line) for a
 * negator within a word or two.
 *
 * Cues that carry their own negation ("do not review", "not in scope") are
 * unaffected: this inspects what comes BEFORE the match, and those cues
 * start at the negator.
 */
const PRECEDING_NEGATOR = /(?:\bnot|\bnever|n'?t|\bavoid|\bdon'?t)\s+(?:\w+\s+)?$/i;

/**
 * Scan a persona prompt for wording that excludes `.stamp/` from review.
 *
 * Pure and side-effect free — the caller decides what a hit means. Returns
 * every distinct offending line (at most one hit per line, first cue wins),
 * in document order.
 */
export function findDotstampExclusions(prompt: string): DotstampExclusionHit[] {
  const hits: DotstampExclusionHit[] = [];
  const lines = prompt.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    if (!DOTSTAMP_MENTION.test(line)) continue;

    const cue = firstUnnegatedCue(line);
    if (cue === null) continue;

    const trimmed = line.trim();
    hits.push({
      line: i + 1,
      text:
        trimmed.length > MAX_ECHO ? `${trimmed.slice(0, MAX_ECHO - 1)}…` : trimmed,
      cue,
    });
  }

  return hits;
}

/**
 * First exclusion cue on `line` that isn't preceded by a negator, or null.
 * Cue regexes are module-level and `g`-flagged, so `lastIndex` is reset
 * before each use — a stale `lastIndex` would silently skip matches on the
 * next line scanned.
 */
function firstUnnegatedCue(line: string): string | null {
  let best: { index: number; cue: string } | null = null;

  for (const re of EXCLUSION_CUES) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(line)) !== null) {
      // Zero-length matches would spin forever; none of the cues can produce
      // one, but the guard is cheap next to an infinite loop.
      if (m[0].length === 0) {
        re.lastIndex++;
        continue;
      }
      if (PRECEDING_NEGATOR.test(line.slice(0, m.index))) continue;
      if (best === null || m.index < best.index) {
        best = { index: m.index, cue: m[0] };
      }
      break;
    }
  }

  return best === null ? null : best.cue;
}

/**
 * Operator-facing report for one reviewer's hits. Mirrors the shape of
 * `formatDriftReport` — `error:` header line, indented detail, `fix:`
 * footer — so the two failure modes of `stamp reviewers verify` read the
 * same way.
 */
export function formatDotstampExclusionReport(
  reviewerName: string,
  promptPath: string,
  hits: readonly DotstampExclusionHit[],
): string {
  const lines: string[] = [
    `error: reviewer '${reviewerName}' has enforce_reads_on_dotstamp: true but its persona excludes .stamp/ from review`,
  ];
  for (const hit of hits) {
    lines.push(`  ${promptPath}:${hit.line}: ${hit.text}`);
    lines.push(`    matched exclusion wording: "${hit.cue}"`);
  }
  lines.push(
    `  why: enforce_reads_on_dotstamp voids any approval whose tool trace lacks a Read of every`,
  );
  lines.push(
    `       modified .stamp/* path. A persona that puts .stamp/ out of scope steers the reviewer`,
  );
  lines.push(
    `       away from those Reads, so .stamp-touching diffs burn review rounds.`,
  );
  lines.push(
    `  fix: bring the two into agreement — either drop the .stamp/ exclusion from the persona, or`,
  );
  lines.push(
    `       set reviewers.${reviewerName}.enforce_reads_on_dotstamp: false in .stamp/config.yml.`,
  );
  lines.push(
    `       Escape hatch for a false positive: 'stamp reviewers verify --no-persona-lint'.`,
  );
  return lines.join("\n");
}
