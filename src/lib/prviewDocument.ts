/**
 * Emit a stamp review as a prview `prview-review/1` document (AGT-1426).
 *
 * `stamp review --prview <file>` runs the normal review, then folds each
 * reviewer's prose into findings prview can render next to the diff. The
 * gate, the verdict cache, and the attestation format are untouched: this
 * module only reads what the review already produced.
 *
 * Everything here is pure (no git, no fs) except `resolvePrviewTarget`,
 * which is a thin wrapper over `git remote`. The document is anchored on
 * `target.head`; hunk ids are `path@oldStart:newStart` taken from the
 * headers of `git diff -M <base> <head>` (default 3 lines of context),
 * which is the diff prview itself computes.
 *
 * The schema requires `line` to be an integer, so a finding that is not
 * line-anchored is placed on its hunk's first new-side line (0 for a file
 * with no hunks); prview treats a line outside the hunk the same way.
 */

import { basename } from "node:path";
import { runGit } from "./git.js";
import { parseOrgRepoFromUrl } from "./remote.js";

export const PRVIEW_SCHEMA = "prview-review/1";

export interface PrviewHunk {
  path: string;
  oldStart: number;
  newStart: number;
  newLen: number;
}

export interface PrviewDiffIndex {
  /** Hunks per new path, in diff order. */
  hunks: Map<string, PrviewHunk[]>;
  /** Paths in the diff with no hunks (pure rename, binary, mode change). */
  fileOnly: string[];
  /** Every path in the diff, in diff order. */
  files: string[];
}

export interface PrviewFinding {
  id: string;
  source: string;
  hunk: string;
  side: "new" | "old";
  line: number;
  severity: "blocking" | "warn" | "nit";
  kind: string;
  claim: string;
  evidence?: string;
}

export interface PrviewTarget {
  repo?: string;
  base: string;
  head: string;
  platform?: string;
  title?: string;
  label?: string;
}

export interface PrviewDocument {
  schema: typeof PRVIEW_SCHEMA;
  target: PrviewTarget;
  findings: PrviewFinding[];
  on_submit: { run: string[] };
}

export interface PrviewReviewerInput {
  reviewer: string;
  verdict: string;
  prose: string;
}

export const PRVIEW_ON_SUBMIT: { run: string[] } = {
  run: ["stamp", "attest", "--from", "{file}"],
};

// ---------------------------------------------------------------------------
// Diff -> hunk index

const HUNK_HEADER = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,(\d+))? @@/;

function unquote(p: string): string {
  const t = p.replace(/\t.*$/, "");
  return t.startsWith('"') && t.endsWith('"') ? t.slice(1, -1) : t;
}

/** Parse `git diff -M` output into per-file hunks. Never throws. */
export function indexDiff(diff: string): PrviewDiffIndex {
  const hunks = new Map<string, PrviewHunk[]>();
  const files: string[] = [];
  let current: string | null = null;
  let oldPath: string | null = null;

  const startFile = (p: string) => {
    current = p;
    if (!files.includes(p)) files.push(p);
  };

  for (const line of diff.split("\n")) {
    if (line.startsWith("diff --git ")) {
      // Provisional path from the header (`a/x b/y`, take the b side); the
      // `---`/`+++`/`rename to` lines below refine it for odd names.
      const m = line.match(/ b\/(.+)$/);
      oldPath = null;
      current = null;
      if (m) startFile(unquote(m[1]!));
      continue;
    }
    if (current === null) continue;
    if (line.startsWith("rename to ")) {
      const p = unquote(line.slice("rename to ".length));
      files.splice(files.lastIndexOf(current), 1);
      startFile(p);
    } else if (line.startsWith("--- ")) {
      oldPath = line.slice(4) === "/dev/null" ? null : unquote(line.slice(4)).replace(/^a\//, "");
    } else if (line.startsWith("+++ ")) {
      const target = line.slice(4);
      if (target === "/dev/null") {
        // Deleted file: the only path it has is the old one.
        if (oldPath !== null && oldPath !== current) {
          files.splice(files.lastIndexOf(current), 1);
          startFile(oldPath);
        }
      } else {
        const p = unquote(target).replace(/^b\//, "");
        if (p !== current) {
          files.splice(files.lastIndexOf(current), 1);
          startFile(p);
        }
      }
    } else {
      const h = line.match(HUNK_HEADER);
      if (h) {
        const list = hunks.get(current) ?? [];
        list.push({
          path: current,
          oldStart: Number(h[1]),
          newStart: Number(h[2]),
          newLen: h[3] === undefined ? 1 : Number(h[3]),
        });
        hunks.set(current, list);
      }
    }
  }
  const fileOnly = files.filter((f) => !hunks.has(f));
  return { hunks, fileOnly, files };
}

export function hunkId(h: PrviewHunk): string {
  return `${h.path}@${h.oldStart}:${h.newStart}`;
}

/** Anchor a (path, optional new-side line) on the diff. Null if the path is not in it. */
export function anchorFor(
  index: PrviewDiffIndex,
  path: string,
  line: number | null,
): { hunk: string; line: number } | null {
  const list = index.hunks.get(path);
  if (!list || list.length === 0) {
    return index.fileOnly.includes(path) ? { hunk: `${path}@file`, line: 0 } : null;
  }
  if (line !== null) {
    const inside = list.find((h) => line >= h.newStart && line < h.newStart + Math.max(h.newLen, 1));
    if (inside) return { hunk: hunkId(inside), line };
    // Not shown by any hunk: nearest hunk, placed at its first line.
    const dist = (h: PrviewHunk) => Math.abs(line - h.newStart);
    const nearest = list.reduce((a, b) => (dist(b) < dist(a) ? b : a));
    return { hunk: hunkId(nearest), line: nearest.newStart };
  }
  const first = list[0]!;
  return { hunk: hunkId(first), line: first.newStart };
}

// ---------------------------------------------------------------------------
// Prose -> findings

interface Block {
  text: string;
  heading: string;
}

const LIST_ITEM = /^\s*(?:[-*+]|\d+[.)])\s+/;
const HEADING = /^\s*(?:#{1,6}\s+|\*\*[^*]+\*\*:?\s*$|[A-Za-z][A-Za-z /-]{0,40}:\s*$)/;

/** Split prose into candidate finding blocks: list items and paragraphs. */
export function splitBlocks(prose: string): Block[] {
  const blocks: Block[] = [];
  let heading = "";
  let buf: string[] = [];
  const flush = () => {
    const text = buf.join("\n").trim();
    if (text) blocks.push({ text, heading });
    buf = [];
  };
  for (const line of prose.split("\n")) {
    if (/^\s*$/.test(line) || /^\s*[-─=]{3,}\s*$/.test(line)) {
      flush();
    } else if (HEADING.test(line) && !LIST_ITEM.test(line)) {
      flush();
      heading = line;
    } else if (LIST_ITEM.test(line)) {
      flush();
      buf.push(line);
    } else {
      buf.push(line);
    }
  }
  flush();
  return blocks;
}

const NEGATED_BLOCKING = /\b(?:no|none|zero|without|not)\b[^.\n]{0,24}\bblock(?:ing|er|ers)\b/i;
const NIT_WORDS = /\b(?:nit|nits|nitpick|minor|optional|non-blocking|cosmetic|suggestion)\b/i;
const BLOCKING_WORDS = /\b(?:blocking|blocker|blockers|must[- ]fix|critical)\b/i;

function severityFrom(text: string): "blocking" | "warn" | "nit" | null {
  if (NIT_WORDS.test(text)) return "nit";
  if (BLOCKING_WORDS.test(text) && !NEGATED_BLOCKING.test(text)) return "blocking";
  return null;
}

const KIND_KEYWORDS: Array<[string, RegExp]> = [
  ["security", /\b(?:inject\w*|auth\w*|secret|token|xss|csrf|sanitiz\w*|vulnerab\w*|traversal|credential\w*|exploit\w*)\b/i],
  ["test", /\b(?:tests?|coverage|assert\w*)\b/i],
  ["perf", /\b(?:perf\w*|slow|latency|quadratic|memory leak)\b/i],
  ["bug", /\b(?:bug|crash\w*|throws?|null|undefined|off-by-one|race|regress\w*|incorrect|wrong|broken)\b/i],
  ["design", /\b(?:naming|flag|convention\w*|refactor\w*|duplicat\w*|structure|api|surface)\b/i],
];

function kindFor(reviewer: string, text: string): string {
  if (reviewer === "security") return "security";
  // File names are noise for keyword matching (`auth.ts` is not an auth finding).
  const words = text.replace(/\S+\.[A-Za-z]{1,5}\b\S*/g, " ");
  for (const [kind, re] of KIND_KEYWORDS) if (re.test(words)) return kind;
  if (reviewer === "standards" || reviewer === "product") return "design";
  return "review";
}

function truncate(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max - 1).trimEnd() + "…";
}

function stripMarkup(s: string): string {
  return s
    .replace(/^\s*```\w*\s*$/gm, "")
    .replace(LIST_ITEM, "")
    .replace(/[*`]+|(?<!\w)_+|_+(?!\w)/g, "")
    .replace(/^\s*\[(?:blocking|warn|warning|nit|minor)\]\s*:?/i, "")
    .replace(/\s+/g, " ")
    .trim();
}

/** Split cleaned text into a one-sentence claim (<=300) and the rest as evidence (<=500). */
function claimAndEvidence(clean: string): { claim: string; evidence?: string } {
  const m = clean.match(/^(.+?[.!?])(?:\s+|$)/);
  let claim = m ? m[1]! : clean;
  if (claim.length > 300) claim = clean;
  const rest = clean.slice(claim.length).trim();
  const out: { claim: string; evidence?: string } = { claim: truncate(claim, 300) };
  const evidence = claim.length > 300 ? clean.slice(299).trim() : rest;
  if (evidence) out.evidence = truncate(evidence, 500);
  return out;
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Build a matcher for file references (`path`, `path:42`, `path:42-50`,
 * `path#L42`, `path line 42`, `path (line 42)`) against exactly the files in
 * the diff, so prose that merely mentions some other path never anchors.
 * A bare basename matches when it is unique among the diff's files.
 */
function buildRefMatcher(files: string[]): (text: string) => Array<{ path: string; line: number | null }> {
  const keys = new Map<string, string>();
  const baseCount = new Map<string, number>();
  for (const f of files) baseCount.set(basename(f), (baseCount.get(basename(f)) ?? 0) + 1);
  for (const f of files) {
    keys.set(f, f);
    if (baseCount.get(basename(f)) === 1 && !keys.has(basename(f))) keys.set(basename(f), f);
  }
  if (keys.size === 0) return () => [];
  const alt = [...keys.keys()].sort((a, b) => b.length - a.length).map(escapeRe).join("|");
  const re = new RegExp(
    `(?<![\\w./-])(${alt})(?![\\w/-])(?:(?::|#L?|,?\\s+lines?\\s+|\\s+L|\\s*\\(\\s*lines?\\s+)(\\d+)(?:\\s*[-–]\\s*L?\\d+)?)?`,
    "g",
  );
  return (text) => {
    const out: Array<{ path: string; line: number | null }> = [];
    for (const m of text.matchAll(re)) {
      out.push({ path: keys.get(m[1]!)!, line: m[2] === undefined ? null : Number(m[2]) });
    }
    return out;
  };
}

/** Pure: one reviewer's prose -> findings anchored on `index`. */
export function parseReviewerFindings(
  input: PrviewReviewerInput,
  index: PrviewDiffIndex,
): Omit<PrviewFinding, "id">[] {
  const source = truncate(`stamp:${input.reviewer}`, 40);
  const blocksOut: Omit<PrviewFinding, "id">[] = [];
  // Paragraphs after an anchored finding that name no file (the explanation
  // under a "**Critical** — `file:3`" header line) belong to that finding.
  const trailing = new Map<Omit<PrviewFinding, "id">, string[]>();
  let last: Omit<PrviewFinding, "id"> | null = null;
  const match = buildRefMatcher(index.files);
  const failing = input.verdict !== "approved";

  for (const block of splitBlocks(input.prose)) {
    if (/^\s*verdict\s*:/i.test(block.text)) continue;
    const refs = match(block.text);
    // Anchor on the first reference the diff can actually place.
    let anchor: { hunk: string; line: number } | null = null;
    for (const r of refs) {
      anchor = anchorFor(index, r.path, r.line);
      if (anchor) break;
    }
    if (!anchor) {
      if (last && refs.length === 0 && !LIST_ITEM.test(block.text)) {
        const extra = stripMarkup(block.text);
        if (extra) trailing.set(last, [...(trailing.get(last) ?? []), extra]);
      }
      continue;
    }
    const clean = stripMarkup(block.text);
    if (!clean) continue;
    const { claim, evidence } = claimAndEvidence(clean);
    last = {
      source,
      hunk: anchor.hunk,
      side: "new",
      line: anchor.line,
      severity: severityFrom(block.text) ?? severityFrom(block.heading) ?? "warn",
      kind: truncate(kindFor(input.reviewer, block.text), 30),
      claim,
      ...(evidence ? { evidence } : {}),
    };
    blocksOut.push(last);
  }
  if (blocksOut.length > 0) {
    return blocksOut.map((f) => {
      const extra = trailing.get(f);
      if (!extra) return f;
      return { ...f, evidence: truncate([f.evidence, ...extra].filter(Boolean).join(" "), 500) };
    });
  }

  // Nothing line-anchored: one summary finding on the change's first hunk,
  // so the reviewer's verdict and reasoning still show up in prview.
  const first = index.files[0];
  const anchor = first ? anchorFor(index, first, null) : null;
  const summarySource = input.prose
    .split("\n")
    .filter((l) => l.trim() && !/^\s*verdict\s*:/i.test(l) && !/^\s*[-─=]{3,}\s*$/.test(l))
    .join("\n");
  const clean = stripMarkup(summarySource);
  if (!anchor || !clean) return [];
  const { claim, evidence } = claimAndEvidence(clean);
  return [
    {
      source,
      hunk: anchor.hunk,
      side: "new",
      line: anchor.line,
      severity: failing ? "blocking" : "nit",
      kind: "summary",
      claim,
      ...(evidence ? { evidence } : {}),
    },
  ];
}

// ---------------------------------------------------------------------------
// Target + document

export interface RemoteEntry {
  name: string;
  url: string;
}

function hostOf(url: string): string | null {
  const scp = url.match(/^[A-Za-z0-9._-]+@([^:]+):/);
  if (scp) return scp[1]!.toLowerCase();
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

const PLATFORM_BY_HOST: Record<string, string> = {
  "github.com": "github",
  "gitlab.com": "gitlab",
  "bitbucket.org": "bitbucket",
};

/**
 * Pick repo + platform from the remotes. Prefers a `github` remote (stamp
 * repos usually keep the forge as a mirror next to a stamp-server `origin`),
 * then `origin`, then the rest. Falls back to the local directory name.
 */
export function pickRemoteTarget(
  remotes: RemoteEntry[],
  fallbackName: string,
): { repo: string; platform?: string } {
  const rank = (r: RemoteEntry) => (r.name === "github" ? 0 : r.name === "origin" ? 1 : 2);
  const ordered = [...remotes].sort((a, b) => rank(a) - rank(b));
  for (const r of ordered) {
    const parsed = parseOrgRepoFromUrl(r.url);
    if (!parsed) continue;
    const platform = PLATFORM_BY_HOST[hostOf(r.url) ?? ""];
    return { repo: `${parsed.org}/${parsed.repo}`, ...(platform ? { platform } : {}) };
  }
  return { repo: fallbackName };
}

export function resolvePrviewTarget(input: {
  repoRoot: string;
  revspec: string;
  baseSha: string;
  headSha: string;
}): PrviewTarget {
  const remotes: RemoteEntry[] = [];
  try {
    for (const name of runGit(["remote"], input.repoRoot).split("\n").map((s) => s.trim()).filter(Boolean)) {
      try {
        remotes.push({ name, url: runGit(["remote", "get-url", name], input.repoRoot).trim() });
      } catch {
        /* unreadable remote: skip */
      }
    }
  } catch {
    /* no remotes */
  }
  const { repo, platform } = pickRemoteTarget(remotes, basename(input.repoRoot));
  let title: string | undefined;
  try {
    title = runGit(["log", "-1", "--format=%s", input.headSha], input.repoRoot).trim() || undefined;
  } catch {
    /* no subject */
  }
  return {
    repo,
    base: input.baseSha,
    head: input.headSha,
    ...(platform ? { platform } : {}),
    ...(title ? { title } : {}),
    label: input.revspec,
  };
}

/** `git diff -M <base> <head>`: the exact diff prview anchors hunks on. */
export function prviewDiff(baseSha: string, headSha: string, repoRoot: string): string {
  return runGit(["diff", "-M", baseSha, headSha], repoRoot);
}

export function buildPrviewDocument(input: {
  target: PrviewTarget;
  diff: string;
  reviewers: PrviewReviewerInput[];
}): PrviewDocument {
  const index = indexDiff(input.diff);
  const findings: PrviewFinding[] = [];
  for (const r of input.reviewers) {
    for (const f of parseReviewerFindings(r, index)) {
      findings.push({ id: String(findings.length + 1), ...f });
    }
  }
  return {
    schema: PRVIEW_SCHEMA,
    target: input.target,
    findings,
    on_submit: { run: [...PRVIEW_ON_SUBMIT.run] },
  };
}
