/**
 * Review scoping: deciding *which* prior review a `stamp review` run is
 * allowed to treat as its own predecessor, and therefore what diff the
 * reviewer is shown.
 *
 * Why this is a module and not three lines in `commands/review.ts`
 * ---------------------------------------------------------------
 * `state.db` lives under the git *common* dir (`stampStateDbPath`), so every
 * worktree of one clone writes review rows into ONE database. That is
 * deliberate — verdicts are a property of the repo, not of a checkout — but
 * it means "the most recent review against base_sha X" is a question whose
 * answer routinely belongs to a *different branch*.
 *
 * Issue #65 / AGT-881 is what that costs when the answer is used to narrow a
 * diff. In a 9-branch parallel wave (bloom-cms, 2026-07-27) four branches got
 * false `changes_requested` verdicts: delta-narrowing computed
 * `git diff <sibling's reviewed head>..<my head>`, which renders the
 * sibling's additions as *my* deletions. Reviewers then correctly blocked on
 * an apparent mass reversion of files the branch had never touched — one
 * cited a file that did not exist at either end of its own range.
 *
 * Three layers here, each independently sufficient to prevent that:
 *   1. `selectPriorReview` — a candidate is only "my prior review" if it is
 *      an ancestor of my head, or if it is on my branch and shares my
 *      parent (the amend/squash case). Sibling heads satisfy neither.
 *   2. `narrowingContamination` — even given a bad predecessor, a narrowed
 *      diff that names files outside `base..head` is rejected outright.
 *   3. `resolveReviewBranch` — supplies the branch identity that layer 1 and
 *      the verdict cache key (`findCachedVerdict`) both need.
 *
 * Everything here fails *closed*: any git error, any unparseable patch, any
 * ambiguity resolves to "no prior review / no narrowing", i.e. a full review.
 * A full review is always correct and merely more expensive; a wrongly
 * narrowed one produces confidently wrong verdicts.
 */

import type { PriorReviewRow } from "./db.js";
import {
  changedPaths,
  currentBranch,
  deltaDiff,
  isAncestor,
  parentSha,
  runGit,
} from "./git.js";

/**
 * The branch identity a review run is scoped to, or null when there isn't
 * one (detached HEAD, or a revspec head that names a raw SHA / remote ref).
 *
 * Resolution order:
 *   1. the head side of the `<base>..<head>` revspec, when it names a local
 *      branch — `stamp review --diff main..feature-x` is scoped to
 *      `feature-x` no matter which worktree it was typed in;
 *   2. otherwise the branch checked out in `cwd` — this is the `main..HEAD`
 *      case, which is what the parallel-wave build loops actually run.
 *
 * Null is a legitimate answer, not an error. It is also the *strict* answer:
 * a null branch can never match a named branch in the cache key, and can
 * never satisfy the same-branch amend rule, so an un-branch-identifiable
 * review simply gets less reuse.
 */
export function resolveReviewBranch(
  revspec: string,
  cwd: string,
): string | null {
  const parts = revspec.split("..");
  const headRef = parts.length === 2 ? parts[1] : undefined;
  if (headRef && headRef !== "HEAD") {
    try {
      const full = runGit(
        ["rev-parse", "--symbolic-full-name", headRef],
        cwd,
      ).trim();
      if (full.startsWith("refs/heads/")) {
        return full.slice("refs/heads/".length);
      }
    } catch {
      // Not a ref (raw SHA, `HEAD~2`, …) — fall through to the checkout.
    }
  }
  try {
    const branch = currentBranch(cwd);
    if (branch && branch !== "HEAD") return branch;
  } catch {
    // No HEAD / not a repo: the caller's own git calls will report it.
  }
  return null;
}

/** Why a candidate row was accepted as this run's prior review. */
export type PriorReviewRelation = "ancestor" | "same-branch-amend";

export interface SelectedPriorReview {
  row: PriorReviewRow;
  relation: PriorReviewRelation;
}

/**
 * Pick the newest candidate row that is provably a predecessor of
 * `headSha` on *this* branch, or null when none is.
 *
 * `candidates` comes from `priorReviewCandidates` — same reviewer, same
 * base_sha, current head excluded, newest first. Same-base is necessary but
 * nowhere near sufficient: N sibling branches off one base all share it.
 *
 * Accepted, in order of preference per candidate:
 *
 *  - **ancestor** — `candidate.head_sha` is an ancestor of `headSha`. This is
 *    proof by history: everything the prior review saw is contained in the
 *    current head, so `prior..head` is a strict subset of this branch's own
 *    work. Branch-name-independent by design (a rename, or a review run from
 *    a differently-named worktree, must not throw away the ratchet).
 *
 *  - **same-branch-amend** — same branch name, and both heads share a parent.
 *    This is `git commit --amend` / squash iteration on a single-commit
 *    branch, which the ancestor test rejects and which is the dominant agent
 *    workflow. It REQUIRES a non-null branch match on both sides: two sibling
 *    branches off one base, each one commit deep, are otherwise
 *    indistinguishable from an amend by ancestry alone — exactly the #65
 *    contamination. Git refuses to check out one branch in two worktrees, so
 *    a branch-name match plus a shared parent really is the same line of work.
 *
 * Anything else — a sibling's head, a NULL-branch legacy row that isn't an
 * ancestor, a row whose commits git can't resolve — is skipped, and the walk
 * continues to older candidates. That continuation matters on its own: before
 * this, a single sibling row at the head of the list masked the branch's own
 * genuine prior review, silently costing the ratchet.
 */
export function selectPriorReview(input: {
  candidates: PriorReviewRow[];
  headSha: string;
  branch: string | null;
  repoRoot: string;
}): SelectedPriorReview | null {
  const { candidates, headSha, branch, repoRoot } = input;
  for (const row of candidates) {
    let relation: PriorReviewRelation | null = null;
    try {
      if (isAncestor(row.head_sha, headSha, repoRoot)) {
        relation = "ancestor";
      } else if (branch !== null && row.branch !== null && row.branch === branch) {
        const priorParent = parentSha(row.head_sha, repoRoot);
        const currentParent = parentSha(headSha, repoRoot);
        if (
          priorParent !== null &&
          currentParent !== null &&
          priorParent === currentParent
        ) {
          relation = "same-branch-amend";
        }
      }
    } catch {
      // Fail closed on any git error: a transient glitch must never inject
      // another branch's verdict or narrow away this branch's diff.
      relation = null;
    }
    if (relation) return { row, relation };
  }
  return null;
}

/**
 * File paths named by a unified diff's `diff --git a/<x> b/<y>` headers.
 *
 * Returns `null` when any header can't be parsed unambiguously. Callers must
 * treat null as "contaminated / unknown" and fall back to a full review — the
 * point of reading the patch text (rather than asking git for the file list
 * again) is that the patch text is what the reviewer actually sees, so it is
 * the only thing worth checking.
 *
 * `deltaDiff` pins `--src-prefix=a/ --dst-prefix=b/`, so the `a/`+`b/` shape
 * is guaranteed for stamp-produced narrowings regardless of the user's diff
 * config.
 */
export function patchPaths(patch: string): Set<string> | null {
  const paths = new Set<string>();
  for (const line of patch.split("\n")) {
    if (!line.startsWith("diff --git ")) continue;
    const parsed = parseDiffGitHeader(line.slice("diff --git ".length));
    if (!parsed) return null;
    paths.add(parsed[0]);
    paths.add(parsed[1]);
  }
  return paths;
}

/** Parse the `a/<x> b/<y>` tail of a `diff --git` line into [x, y]. */
function parseDiffGitHeader(rest: string): [string, string] | null {
  if (rest.startsWith('"')) {
    const first = readCQuoted(rest, 0);
    if (!first || rest[first.end] !== " ") return null;
    const secondStart = first.end + 1;
    const second =
      rest[secondStart] === '"'
        ? readCQuoted(rest, secondStart)
        : { value: rest.slice(secondStart), end: rest.length };
    if (!second || second.end !== rest.length) return null;
    return stripPrefixes(first.value, second.value);
  }
  // Unquoted. Paths may contain spaces, so every space is a candidate split;
  // a header is only usable if exactly one split yields `a/… b/…`, or if the
  // splits agree on a single same-path (non-rename) reading.
  const splits: Array<[string, string]> = [];
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] !== " ") continue;
    const left = rest.slice(0, i);
    const right = rest.slice(i + 1);
    if (left.startsWith("a/") && right.startsWith("b/")) {
      splits.push([left.slice(2), right.slice(2)]);
    }
  }
  if (splits.length === 1) return splits[0]!;
  const identical = splits.filter(([l, r]) => l === r);
  if (identical.length === 1) return identical[0]!;
  return null;
}

function stripPrefixes(a: string, b: string): [string, string] | null {
  if (!a.startsWith("a/") || !b.startsWith("b/")) return null;
  return [a.slice(2), b.slice(2)];
}

/**
 * Read one git C-style quoted string starting at `start`; `end` is the index
 * just past the closing quote.
 *
 * Decoding runs at the BYTE level and UTF-8-decodes once at the end. Git's
 * octal escapes are bytes, not code points: `café.ts` is quoted as
 * `"caf\303\251.ts"`, two escapes for one character. Assembling those with
 * `String.fromCharCode` would yield the Latin-1 mojibake `cafÃ©.ts`, which
 * would never compare equal to the real path from `changedPaths` — so every
 * narrowing touching a non-ASCII path would look contaminated and silently
 * fall back to a full review.
 */
function readCQuoted(
  s: string,
  start: number,
): { value: string; end: number } | null {
  if (s[start] !== '"') return null;
  const bytes: number[] = [];
  let i = start + 1;
  while (i < s.length) {
    const ch = s[i]!;
    if (ch === '"') {
      return { value: Buffer.from(bytes).toString("utf8"), end: i + 1 };
    }
    if (ch !== "\\") {
      // Unescaped runs are plain ASCII in git's quoted output, but encode
      // rather than assume so a stray literal multi-byte char round-trips.
      bytes.push(...Buffer.from(ch, "utf8"));
      i++;
      continue;
    }
    const esc = s[i + 1];
    if (esc === undefined) return null;
    if (esc >= "0" && esc <= "7") {
      const oct = s.slice(i + 1, i + 4);
      if (!/^[0-7]{3}$/.test(oct)) return null;
      bytes.push(parseInt(oct, 8));
      i += 4;
      continue;
    }
    const simple: Record<string, number> = {
      n: 0x0a,
      t: 0x09,
      r: 0x0d,
      f: 0x0c,
      b: 0x08,
      v: 0x0b,
      a: 0x07,
      '"': 0x22,
      "\\": 0x5c,
    };
    const mapped = simple[esc];
    if (mapped === undefined) return null;
    bytes.push(mapped);
    i += 2;
  }
  return null;
}

/**
 * Paths a narrowed diff names that are NOT part of `base..head`, or `null`
 * when the patch can't be parsed (also a rejection — see `patchPaths`).
 *
 * An empty array means the narrowing is clean. Anything else means the
 * reviewer would be shown changes that are not this branch's, and the caller
 * must fall back to the full diff.
 *
 * Note that a legitimate narrowing CAN trip this: if a prior round added file
 * F and the current head reverts F to its base content, `prior..head` names F
 * while `base..head` does not. Falling back to a full review there is the
 * right call anyway — a revert-to-base is precisely the change a delta-scoped
 * reviewer is least equipped to judge.
 *
 * `fullPaths` is a `--no-renames` set (see `changedPaths`), so a rename
 * detected inside the narrowed patch matches on both its old and new name.
 */
export function narrowingContamination(
  narrowedPatch: string,
  fullPaths: Set<string>,
): string[] | null {
  const narrowedPaths = patchPaths(narrowedPatch);
  if (narrowedPaths === null) return null;
  const extra = [...narrowedPaths].filter((p) => !fullPaths.has(p));
  extra.sort();
  return extra;
}

export interface ReviewScopeInput {
  /** Reviewers being run this round, in any order. */
  reviewers: string[];
  /** Candidate prior rows per reviewer (newest first), from
   *  `priorReviewCandidates`. Reviewers served from the verdict cache should
   *  be omitted — they never reach the LLM. */
  candidatesByReviewer: Map<string, PriorReviewRow[]>;
  baseSha: string;
  headSha: string;
  branch: string | null;
  repoRoot: string;
  /** False when `STAMP_NO_DELTA_REVIEW=1`: prior verdicts still surface as
   *  prompt context, but no diff is narrowed. */
  deltaEnabled: boolean;
}

export interface ReviewScopeResult {
  /** Prior review accepted for each reviewer (prompt ratchet context). */
  priorByReviewer: Map<string, SelectedPriorReview>;
  /** Narrowed diff text per reviewer. A reviewer with a prior review but no
   *  entry here is shown the full diff. */
  deltaDiffs: Map<string, string>;
  /** Operator-facing warning lines (no trailing newline). */
  warnings: string[];
}

/**
 * Resolve, for each reviewer, which prior review applies and whether its diff
 * can be narrowed — the whole of #65's fix in one call so `commands/review.ts`
 * and the regression tests exercise the same code path.
 */
export function resolveReviewScope(input: ReviewScopeInput): ReviewScopeResult {
  const priorByReviewer = new Map<string, SelectedPriorReview>();
  const deltaDiffs = new Map<string, string>();
  const warnings: string[] = [];

  for (const name of input.reviewers) {
    const candidates = input.candidatesByReviewer.get(name) ?? [];
    if (candidates.length === 0) continue;
    const selected = selectPriorReview({
      candidates,
      headSha: input.headSha,
      branch: input.branch,
      repoRoot: input.repoRoot,
    });
    if (selected) priorByReviewer.set(name, selected);
  }

  if (!input.deltaEnabled || priorByReviewer.size === 0) {
    return { priorByReviewer, deltaDiffs, warnings };
  }

  // The reference set for the guard. If git can't enumerate the branch's own
  // files there is nothing to check narrowings against, so no narrowing is
  // allowed at all.
  let fullPaths: Set<string>;
  try {
    fullPaths = changedPaths(input.baseSha, input.headSha, input.repoRoot);
  } catch (err) {
    warnings.push(
      `warning: could not enumerate changed paths for ` +
        `${input.baseSha.slice(0, 8)}..${input.headSha.slice(0, 8)} — ` +
        `reviewing the full diff (${errText(err)})`,
    );
    return { priorByReviewer, deltaDiffs, warnings };
  }

  for (const [name, selected] of priorByReviewer) {
    let narrowed: string;
    try {
      narrowed = deltaDiff(selected.row.head_sha, input.headSha, input.repoRoot);
    } catch (err) {
      // Surface it: a silent fallback would let the agent believe narrowing
      // held when it didn't, which is the confusion this feature exists to
      // prevent.
      warnings.push(
        `warning: delta computation failed for reviewer '${name}' — ` +
          `falling back to full diff with prompt-only ratchet (${errText(err)})`,
      );
      continue;
    }
    const extra = narrowingContamination(narrowed, fullPaths);
    if (extra === null) {
      warnings.push(
        `warning: could not parse the narrowed diff for reviewer '${name}' — ` +
          `falling back to the full diff (delta scoping is only safe when its ` +
          `file list can be verified)`,
      );
      continue;
    }
    if (extra.length > 0) {
      const shown = extra.slice(0, 5).join(", ");
      const more = extra.length > 5 ? ` (+${extra.length - 5} more)` : "";
      warnings.push(
        `warning: narrowed diff for reviewer '${name}' names ${extra.length} ` +
          `path${extra.length === 1 ? "" : "s"} outside ` +
          `${input.baseSha.slice(0, 8)}..${input.headSha.slice(0, 8)}: ${shown}${more} — ` +
          `falling back to the full diff. The prior review recorded at ` +
          `${selected.row.head_sha.slice(0, 8)} does not describe this branch's ` +
          `history (see issue #65).`,
      );
      continue;
    }
    deltaDiffs.set(name, narrowed);
  }

  return { priorByReviewer, deltaDiffs, warnings };
}

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
