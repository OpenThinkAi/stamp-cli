/**
 * `stamp peer drafts list|show|delete` — draft management commands (AGT-432 AC #8–10).
 *
 * Operates over `~/.stamp/drafts/` — draft files written by the listener when
 * `post_mode: "draft"` is set in the triage decision. Each draft is a Markdown
 * file named `<patch-id>.md` with YAML frontmatter.
 *
 * Subcommands:
 *   list   — list all drafts in reverse-chronological order (exit 0/1/2/3)
 *   show   — render a draft to stdout by patch-id or unambiguous prefix (exit 0/1/2/3)
 *   delete — delete a named draft; --all --yes for bulk delete (exit 0/1/2/3)
 *
 * Exit codes:
 *   0   — success
 *   1   — draft(s) not found / directory missing or empty
 *   2   — arg-parse error (Commander only)
 *   3   — I/O error
 */

import { readdirSync, readFileSync, statSync, unlinkSync } from "node:fs";
import { join, basename } from "node:path";
import { draftsDir } from "../lib/paths.js";

// ─── Types ────────────────────────────────────────────────────────────

export interface DraftsMeta {
  /** Patch-id (stem of the filename, without .md). */
  patchId: string;
  /** Full path to the draft file. */
  filePath: string;
  /** mtime of the file. */
  mtime: Date;
  /** PR title extracted from YAML frontmatter, or "—" if absent. */
  prTitle: string;
}

// ─── Helpers ─────────────────────────────────────────────────────────

/** Format a Date as a human-readable age string relative to now. */
function formatAge(mtime: Date): string {
  const diffMs = Date.now() - mtime.getTime();
  const diffSecs = Math.floor(diffMs / 1000);
  if (diffSecs < 60) return `${diffSecs}s ago`;
  const diffMins = Math.floor(diffSecs / 60);
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${Math.floor(diffHours / 24)}d ago`;
}

/** Extract the `pr_url` from YAML frontmatter (crude but sufficient for our format). */
function extractFrontmatterTitle(content: string): string {
  // Frontmatter format: `pr_url: <url>` — we use the url as title fallback.
  const prUrlMatch = content.match(/^pr_url:\s*(.+)$/m);
  if (prUrlMatch && prUrlMatch[1]) {
    // Extract the last path segment (PR number) as a short title.
    const url = prUrlMatch[1].trim();
    const m = url.match(/\/pull\/(\d+)$/);
    if (m) return `PR #${m[1]}`;
    return url;
  }
  return "—";
}

/**
 * List all `.md` files in the drafts dir, sorted by mtime descending.
 * Returns null if the directory doesn't exist or is empty.
 */
function listDraftFiles(dir: string): DraftsMeta[] | null {
  let entries: string[];
  try {
    entries = readdirSync(dir).filter((e) => e.endsWith(".md"));
  } catch (err) {
    const isNotFound =
      err instanceof Error && "code" in err && (err as NodeJS.ErrnoException).code === "ENOENT";
    if (isNotFound) return null;
    throw err;
  }

  if (entries.length === 0) return null;

  const metas: DraftsMeta[] = [];
  for (const entry of entries) {
    const filePath = join(dir, entry);
    try {
      const st = statSync(filePath);
      const patchId = basename(entry, ".md");
      let prTitle = "—";
      try {
        const content = readFileSync(filePath, "utf8");
        prTitle = extractFrontmatterTitle(content);
      } catch {
        // If we can't read for title, just leave it as "—".
      }
      metas.push({ patchId, filePath, mtime: st.mtime, prTitle });
    } catch {
      // Skip files we can't stat.
    }
  }

  // Sort by mtime descending (most recent first).
  metas.sort((a, b) => b.mtime.getTime() - a.mtime.getTime());
  return metas.length > 0 ? metas : null;
}

/**
 * Resolve a patch-id or unambiguous prefix to a `DraftsMeta`.
 * Returns `{ found: meta }` on unique match.
 * Returns `{ ambiguous: matches }` on multiple matches.
 * Returns `{ notFound: true }` when no match.
 */
function resolvePatchId(
  dir: string,
  prefix: string,
): { found: DraftsMeta } | { ambiguous: DraftsMeta[] } | { notFound: true } {
  const metas = listDraftFiles(dir);
  if (!metas) return { notFound: true };

  // Exact match first.
  const exact = metas.filter((m) => m.patchId === prefix);
  if (exact.length === 1) return { found: exact[0]! };
  if (exact.length > 1) return { ambiguous: exact };

  // Prefix match.
  const prefixMatches = metas.filter((m) => m.patchId.startsWith(prefix));
  if (prefixMatches.length === 1) return { found: prefixMatches[0]! };
  if (prefixMatches.length > 1) return { ambiguous: prefixMatches };

  return { notFound: true };
}

// ─── Input types ─────────────────────────────────────────────────────

export interface DraftsListOptions {
  /** Test-only: override draftsDir. */
  _dirForTest?: string;
  /** Test-only: override process.exit. */
  _exitForTest?: (code: number) => never;
  /** Test-only: capture stdout writes. */
  _stdoutWriteForTest?: (line: string) => void;
  /** Test-only: capture stderr writes. */
  _stderrWriteForTest?: (line: string) => void;
}

export interface DraftsShowOptions {
  patchId: string;
  /** Test-only: override draftsDir. */
  _dirForTest?: string;
  /** Test-only: override process.exit. */
  _exitForTest?: (code: number) => never;
  /** Test-only: capture stdout writes. */
  _stdoutWriteForTest?: (line: string) => void;
  /** Test-only: capture stderr writes. */
  _stderrWriteForTest?: (line: string) => void;
}

export interface DraftsDeleteOptions {
  patchId?: string;
  /** Delete all drafts (requires --yes). */
  all?: boolean;
  /** Required with --all to prevent accidental bulk deletion. */
  yes?: boolean;
  /** Test-only: override draftsDir. */
  _dirForTest?: string;
  /** Test-only: override process.exit. */
  _exitForTest?: (code: number) => never;
  /** Test-only: capture stdout writes. */
  _stdoutWriteForTest?: (line: string) => void;
  /** Test-only: capture stderr writes. */
  _stderrWriteForTest?: (line: string) => void;
}

// ─── list ─────────────────────────────────────────────────────────────

export function runDraftsList(opts: DraftsListOptions): void {
  const exitFn = opts._exitForTest ?? ((code: number) => process.exit(code) as never);
  const stdoutWrite = opts._stdoutWriteForTest ?? ((s: string) => { process.stdout.write(s); });
  const stderrWrite = opts._stderrWriteForTest ?? ((s: string) => { process.stderr.write(s); });
  const dir = opts._dirForTest ?? draftsDir();

  let metas: DraftsMeta[] | null;
  try {
    metas = listDraftFiles(dir);
  } catch (err) {
    stderrWrite(`error: failed to list drafts: ${err instanceof Error ? err.message : String(err)}\n`);
    exitFn(3);
    return;
  }

  if (!metas) {
    stderrWrite(`error: no drafts found\n`);
    exitFn(1);
    return;
  }

  for (const meta of metas) {
    const age = formatAge(meta.mtime);
    stdoutWrite(`${meta.patchId}  ${age}  ${meta.prTitle}\n`);
  }
  exitFn(0);
}

// ─── show ─────────────────────────────────────────────────────────────

export function runDraftsShow(opts: DraftsShowOptions): void {
  const exitFn = opts._exitForTest ?? ((code: number) => process.exit(code) as never);
  const stdoutWrite = opts._stdoutWriteForTest ?? ((s: string) => { process.stdout.write(s); });
  const stderrWrite = opts._stderrWriteForTest ?? ((s: string) => { process.stderr.write(s); });
  const dir = opts._dirForTest ?? draftsDir();

  let resolved: ReturnType<typeof resolvePatchId>;
  try {
    resolved = resolvePatchId(dir, opts.patchId);
  } catch (err) {
    stderrWrite(`error: failed to access drafts: ${err instanceof Error ? err.message : String(err)}\n`);
    exitFn(3);
    return;
  }

  if ("notFound" in resolved) {
    stderrWrite(`error: draft not found: ${opts.patchId} — run 'stamp peer drafts list' to see available drafts\n`);
    exitFn(1);
    return;
  }
  if ("ambiguous" in resolved) {
    stderrWrite(`error: ambiguous patch-id prefix "${opts.patchId}" — matches:\n`);
    for (const m of resolved.ambiguous) {
      stderrWrite(`  ${m.patchId}\n`);
    }
    exitFn(1);
    return;
  }

  const { found } = resolved;
  let content: string;
  try {
    content = readFileSync(found.filePath, "utf8");
  } catch (err) {
    stderrWrite(
      `error: failed to read draft ${found.patchId}: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    exitFn(3);
    return;
  }

  stdoutWrite(content);
  exitFn(0);
}

// ─── delete ──────────────────────────────────────────────────────────

export function runDraftsDelete(opts: DraftsDeleteOptions): void {
  const exitFn = opts._exitForTest ?? ((code: number) => process.exit(code) as never);
  const stdoutWrite = opts._stdoutWriteForTest ?? ((s: string) => { process.stdout.write(s); });
  const stderrWrite = opts._stderrWriteForTest ?? ((s: string) => { process.stderr.write(s); });
  const dir = opts._dirForTest ?? draftsDir();

  if (opts.all) {
    // --all mode.
    let metas: DraftsMeta[] | null;
    try {
      metas = listDraftFiles(dir);
    } catch (err) {
      stderrWrite(`error: failed to list drafts: ${err instanceof Error ? err.message : String(err)}\n`);
      exitFn(3);
      return;
    }

    if (!metas) {
      stderrWrite(`error: no drafts found\n`);
      exitFn(1);
      return;
    }

    if (!opts.yes) {
      // Dry-run: list what would be deleted, exit 1 with re-run prompt.
      stderrWrite(`would delete ${metas.length} draft(s):\n`);
      for (const m of metas) {
        stderrWrite(`  ${m.patchId}\n`);
      }
      stderrWrite(`note: re-run with --all --yes to confirm\n`);
      exitFn(1);
      return;
    }

    // Confirmed bulk delete.
    let ioError = false;
    for (const meta of metas) {
      try {
        unlinkSync(meta.filePath);
        stdoutWrite(`deleted ${meta.patchId}\n`);
      } catch (err) {
        stderrWrite(
          `error: failed to delete ${meta.patchId}: ${err instanceof Error ? err.message : String(err)}\n`,
        );
        ioError = true;
      }
    }
    exitFn(ioError ? 3 : 0);
    return;
  }

  // Single-item delete.
  if (!opts.patchId) {
    stderrWrite(`error: patch-id required (or use --all --yes to delete all)\n`);
    exitFn(2);
    return;
  }

  let resolved: ReturnType<typeof resolvePatchId>;
  try {
    resolved = resolvePatchId(dir, opts.patchId);
  } catch (err) {
    stderrWrite(`error: failed to access drafts: ${err instanceof Error ? err.message : String(err)}\n`);
    exitFn(3);
    return;
  }

  if ("notFound" in resolved) {
    stderrWrite(`error: draft not found: ${opts.patchId} — run 'stamp peer drafts list' to see available drafts\n`);
    exitFn(1);
    return;
  }
  if ("ambiguous" in resolved) {
    stderrWrite(`error: ambiguous patch-id prefix "${opts.patchId}" — matches:\n`);
    for (const m of resolved.ambiguous) {
      stderrWrite(`  ${m.patchId}\n`);
    }
    exitFn(1);
    return;
  }

  const { found } = resolved;
  try {
    unlinkSync(found.filePath);
  } catch (err) {
    stderrWrite(
      `error: failed to delete draft ${found.patchId}: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    exitFn(3);
    return;
  }

  stdoutWrite(`deleted ${found.patchId}\n`);
  exitFn(0);
}
