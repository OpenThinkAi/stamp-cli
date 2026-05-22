/**
 * Pure helpers for `stamp init --migrate-to-server-attested` (AGT-342).
 *
 * The migration command does four mechanical things to a 1.x repo:
 *
 *   1. Scaffold `.stamp/trusted-keys/manifest.yml` from the `.pub` files
 *      already in `.stamp/trusted-keys/`. Every entry defaults to
 *      `capabilities: [operator]`; the caller's interactive prompt
 *      promotes selected names to `[admin, operator]` before serialization.
 *   2. Comment out `mcp_servers:` and `tools:` blocks in
 *      `.stamp/config.yml` (Phase 1 reviewers are diff-only — see
 *      docs/migration-1.x-to-2.x.md, "What about my mcp_servers / tools
 *      config"). The blocks are commented out, not deleted, so operators
 *      can review post-migration. We operate on raw text rather than
 *      round-tripping through the YAML parser so the operator's existing
 *      comments and formatting survive.
 *   3. Append a default `path_rules:` block gating `.stamp/**` with
 *      `require_capability: admin`, `minimum_signatures: 2`,
 *      `bypass_review_cycle: true`.
 *   4. Idempotent: re-running on a manifest that already has capabilities
 *      skips the manifest write; re-running on a config that already has
 *      `path_rules:` skips the append (with a warning if the existing
 *      `.stamp/**` rule differs from the default).
 *
 * Helpers in this module are pure: they take strings + structured input
 * and return strings + descriptors. The IO + interactive flow lives in
 * `src/commands/migrateServerAttested.ts` so we can test the
 * transformations directly.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

import { fingerprintFromPem } from "./keys.js";
import { stampTrustedKeysDir } from "./paths.js";

/**
 * One detected pubkey under `.stamp/trusted-keys/`. The `name` is the
 * filename minus `.pub`, sanitized to fit the manifest's `NAME_PATTERN`
 * (`[A-Za-z0-9_.-]+`); the `fingerprint` is the canonical `sha256:<hex>`
 * computed by `fingerprintFromPem`.
 */
export interface DetectedKey {
  /** Operator-chosen manifest name. Defaults to the filename stem. */
  name: string;
  /** Source filename (no path). Surfaced in the prompt so operators can
   *  identify which physical file each entry maps to. */
  filename: string;
  /** sha256:<64-hex>; same shape as `fingerprintFromPem`. */
  fingerprint: string;
}

/**
 * Scan `.stamp/trusted-keys/` for `*.pub` files and return one
 * `DetectedKey` per file. Order is stable (lexicographic by filename) so
 * the interactive prompt + manifest serializer are deterministic across
 * runs. Throws if the directory doesn't exist OR contains no `.pub`
 * files — the migration command has nothing to do without input keys.
 *
 * Unparseable PEMs are skipped with a comment via `onSkip` so the
 * caller can surface them; we deliberately do NOT throw on a single
 * malformed file because a partial migration is more useful than a
 * complete refusal.
 */
export function detectExistingKeys(
  repoRoot: string,
  onSkip?: (filename: string, reason: string) => void,
): DetectedKey[] {
  const dir = stampTrustedKeysDir(repoRoot);
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    throw new Error(
      `no existing keys to migrate — \`.stamp/trusted-keys/\` does not exist. ` +
        `Run \`stamp init\` first for a fresh 2.x setup.`,
    );
  }

  const out: DetectedKey[] = [];
  for (const filename of entries.sort()) {
    if (!filename.endsWith(".pub")) continue;
    const full = join(dir, filename);
    try {
      const st = statSync(full);
      if (!st.isFile()) continue;
    } catch {
      continue;
    }
    let pem: string;
    try {
      pem = readFileSync(full, "utf8");
    } catch (err) {
      onSkip?.(filename, err instanceof Error ? err.message : String(err));
      continue;
    }
    let fingerprint: string;
    try {
      fingerprint = fingerprintFromPem(pem);
    } catch (err) {
      onSkip?.(
        filename,
        `malformed PEM (${err instanceof Error ? err.message : String(err)})`,
      );
      continue;
    }
    out.push({
      name: nameFromFilename(filename),
      filename,
      fingerprint,
    });
  }

  if (out.length === 0) {
    throw new Error(
      `no existing keys to migrate — \`.stamp/trusted-keys/\` contains no readable \`*.pub\` files. ` +
        `Run \`stamp init\` first for a fresh 2.x setup.`,
    );
  }

  return out;
}

/**
 * Derive a manifest entry name from a pubkey filename. Strips `.pub`,
 * substitutes any character outside `[A-Za-z0-9_.-]` with `_` so the
 * derived name matches `trustedKeysManifest.ts`'s NAME_PATTERN. Empty
 * results (a filename of just punctuation) fall back to `"key"`.
 *
 * Examples:
 *   "alice.pub"                          -> "alice"
 *   "sha256_abc123.pub"                  -> "sha256_abc123"
 *   "ed25519@host.example.com.pub"       -> "ed25519_host.example.com"
 *
 * Two files that collapse to the same name (rare but possible) get
 * de-duplicated by the caller via `disambiguateNames` so the manifest
 * never holds duplicate keys.
 */
export function nameFromFilename(filename: string): string {
  const stem = filename.endsWith(".pub")
    ? filename.slice(0, -".pub".length)
    : filename;
  const sanitized = stem.replace(/[^A-Za-z0-9_.-]/g, "_");
  return sanitized.length > 0 ? sanitized : "key";
}

/**
 * Apply `_2`, `_3`, ... suffixes to repeated names so the resulting
 * list is unique while preserving order. The manifest schema requires
 * unique names within `keys:` and we want a deterministic disambiguation
 * rather than the YAML library silently dropping later duplicates.
 */
export function disambiguateNames(keys: DetectedKey[]): DetectedKey[] {
  const seen = new Map<string, number>();
  return keys.map((k) => {
    const count = seen.get(k.name) ?? 0;
    seen.set(k.name, count + 1);
    if (count === 0) return k;
    return { ...k, name: `${k.name}_${count + 1}` };
  });
}

/** A `[server]+role_source:server` entry to emit into the manifest alongside
 *  the operator's detected keys. Used by the WS2 one-PR Shape 4 setup so the
 *  scaffold leaves the manifest ready to attest. */
export interface ServerManifestEntry {
  /** Operator-chosen short name. Defaults to `review-server-prod` in the
   *  calling flow but pluggable so multi-server fleets can rename. */
  name: string;
  /** `sha256:<hex>` — same shape `fingerprintFromPem` produces. */
  fingerprint: string;
}

/**
 * Serialize a manifest from a set of detected keys and an
 * admin-promotion selection. Output matches the schema documented in
 * `trustedKeysManifest.ts`: a top-level `keys:` map, each entry with a
 * `fingerprint` line and a `capabilities` flow-style array.
 *
 * We emit YAML by hand rather than round-tripping through `yaml`'s
 * stringifier because:
 *   - The shape is small and fixed; the hand-rolled form is easier to
 *     diff-review than the library's output.
 *   - We want flow-style capability arrays (`[operator]`) to match the
 *     migration-guide example and the worked-example test in
 *     `trustedKeysManifest.test.ts`.
 *
 * Entries are sorted alphabetically by name so re-running the command
 * with the same input produces byte-identical output. `serverEntries`
 * (optional) are merged into the same sort and emitted with
 * `capabilities: [server]` + `role_source: server` per the Shape 4
 * activation whitelist (`validateShape4ActivationDiff`).
 */
export function serializeManifest(
  keys: DetectedKey[],
  adminFingerprints: ReadonlySet<string>,
  serverEntries: ReadonlyArray<ServerManifestEntry> = [],
): string {
  type Row =
    | { kind: "operator"; name: string; fingerprint: string; admin: boolean }
    | { kind: "server"; name: string; fingerprint: string };
  const rows: Row[] = [
    ...keys.map((k): Row => ({
      kind: "operator",
      name: k.name,
      fingerprint: k.fingerprint,
      admin: adminFingerprints.has(k.fingerprint),
    })),
    ...serverEntries.map((s): Row => ({
      kind: "server",
      name: s.name,
      fingerprint: s.fingerprint,
    })),
  ];
  rows.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const lines: string[] = [
    "# Trusted-keys manifest for server-attested reviews (stamp 2.x).",
    "# Generated by `stamp init --migrate-to-server-attested`. Edit by hand to",
    "# adjust capabilities; changes go through the .stamp/** path_rules gate",
    "# (admin-signed, bypasses the reviewer cycle).",
    "keys:",
  ];
  for (const r of rows) {
    lines.push(`  ${r.name}:`);
    lines.push(`    fingerprint: ${r.fingerprint}`);
    if (r.kind === "server") {
      lines.push(`    capabilities: [server]`);
      lines.push(`    role_source: server`);
    } else {
      lines.push(
        `    capabilities: ${r.admin ? "[admin, operator]" : "[operator]"}`,
      );
    }
  }
  // Terminate with a single trailing newline so the file is POSIX-clean.
  return lines.join("\n") + "\n";
}

/**
 * Result of a config-rewrite pass. The `warnings` array carries
 * operator-facing messages the caller surfaces on stderr; `changed`
 * tells the caller whether the on-disk file would change (used to
 * suppress the "wrote config.yml" line when there's nothing to write).
 */
export interface ConfigRewriteResult {
  /** Updated raw text. Same as input when `changed: false`. */
  text: string;
  /** True iff `text` differs from the input. */
  changed: boolean;
  /** Names of top-level blocks that were commented out
   *  (`mcp_servers`, `tools`, or both). Each appears at most once. */
  commentedBlocks: string[];
  /** True iff a `path_rules:` block was appended. False when one was
   *  already present (no append) or when nothing else changed. */
  pathRulesAppended: boolean;
  /** Warnings to surface to the operator (e.g. existing path_rules
   *  with a different `.stamp/**` rule). */
  warnings: string[];
  /** Name of the branch whose rule received `review_server:` (one-PR
   *  Shape 4 path). Empty when the caller didn't request the addition
   *  or when no edit was needed (already present). */
  reviewServerBranchAdded: string | null;
  /** Names of reviewer entries whose block was rewritten from
   *  prompt-paths form to `{}` form (Shape 4 cleanup). */
  reviewersRewrittenTo: string[];
}

/** Options for `rewriteConfigForMigration` to support the one-PR Shape 4
 *  flow. Defaults preserve the original (Phase-1-only) behavior so
 *  pre-existing callers/tests keep working. */
export interface RewriteOptions {
  /** When set, the rewriter ADDS `review_server: <url>` to the named
   *  branch's rule (idempotent — skipped if the branch already has one,
   *  warning if the existing value differs). When null/undefined, the
   *  rewriter doesn't touch any branch rule. */
  reviewServer?: { branch: string; url: string } | null;
  /** When true, the rewriter strips per-reviewer body fields (prompt,
   *  tools, mcp_servers) so each reviewer entry becomes `{}` form (Shape
   *  4 server-bundled prompt mode). Leaves the SET of reviewer names
   *  intact — that's the Shape-4-cleanup contract the bootstrap whitelist
   *  recognizes. Defaults to false. */
  rewriteReviewersToEmpty?: boolean;
  /** Override the `minimum_signatures` in the appended path_rules block.
   *  Defaults to 2 (the safe-default for multi-admin repos). */
  minimumSignatures?: number;
}

/**
 * Rewrite `.stamp/config.yml` text for the migration:
 *
 *   - Comment out any top-level `mcp_servers:` or `tools:` block
 *     (line-by-line `# ` prefix). Indented occurrences nested inside
 *     a reviewer's definition also get commented; we walk the
 *     indentation, not just top-level keys, because both forms appear
 *     in real configs.
 *   - Append a default `path_rules:` block gating `.stamp/**` if no
 *     `path_rules:` key already exists. If the operator has a
 *     `path_rules:` with a DIFFERENT `.stamp/**` rule, emit a warning
 *     and leave the existing block alone (idempotent + non-destructive).
 *
 * The function is intentionally line-oriented and never invokes a YAML
 * parser: round-tripping through `parse`/`stringify` would lose
 * operator comments, blank lines, and quoting style. The trade-off is
 * that we tolerate only standard YAML indentation (spaces, not tabs);
 * the migration guide already requires that.
 */
export function rewriteConfigForMigration(
  input: string,
  opts: RewriteOptions = {},
): ConfigRewriteResult {
  const warnings: string[] = [];
  const minimumSignatures = opts.minimumSignatures ?? 2;
  const pathRulesBlock = renderPathRulesBlock(minimumSignatures);
  let reviewServerBranchAdded: string | null = null;
  let reviewersRewrittenTo: string[] = [];

  // Comment-out pass: when we're going to rewrite reviewers to {} form,
  // commenting is redundant (the entry body gets replaced wholesale). Skip
  // it to avoid leaving stray "# tools:" comments inside an otherwise-{}
  // reviewer entry — and to avoid the whitelist seeing the base's `tools`
  // sub-key surviving as parsed nothing while text still carries it.
  let textLines: string[];
  let commentedBlocks: string[] = [];
  if (opts.rewriteReviewersToEmpty) {
    textLines = input.split("\n");
  } else {
    const commented = commentOutBlocks(input, ["mcp_servers", "tools"]);
    textLines = commented.lines;
    commentedBlocks = commented.blocks;
  }
  let text = textLines.join("\n");

  if (opts.rewriteReviewersToEmpty) {
    const rewriteRes = rewriteReviewersToEmptyForm(text);
    text = rewriteRes.text;
    reviewersRewrittenTo = rewriteRes.rewritten;
  }

  if (opts.reviewServer) {
    const rsRes = addReviewServerToBranch(
      text,
      opts.reviewServer.branch,
      opts.reviewServer.url,
    );
    text = rsRes.text;
    if (rsRes.added) reviewServerBranchAdded = opts.reviewServer.branch;
    for (const w of rsRes.warnings) warnings.push(w);
  }

  let pathRulesAppended = false;
  const existingPathRules = findTopLevelPathRulesBlock(text);
  if (!existingPathRules) {
    // Ensure the appended block is separated from the previous content
    // by exactly one blank line. Trim trailing whitespace, then add the
    // separator and the block.
    const trimmed = text.replace(/\s*$/, "");
    text =
      trimmed +
      (trimmed.length > 0 ? "\n\n" : "") +
      pathRulesBlock +
      "\n";
    pathRulesAppended = true;
  } else if (!pathRulesMatchesRequested(text, minimumSignatures)) {
    warnings.push(
      `\`path_rules:\` already present in .stamp/config.yml with a different ` +
        `\`.stamp/**\` rule. Leaving the existing block in place — review ` +
        `manually against the recommended default:\n` +
        indentBlock(pathRulesBlock, "  "),
    );
  }

  const changed = text !== input;
  return {
    text,
    changed,
    commentedBlocks,
    pathRulesAppended,
    warnings,
    reviewServerBranchAdded,
    reviewersRewrittenTo,
  };
}

/** Two-admin default `path_rules:` block. Alias for
 *  `renderPathRulesBlock(2)`; kept named for tests that match the
 *  multi-admin default exactly. Single-admin repos render with
 *  `renderPathRulesBlock(1)`. */
export const DEFAULT_PATH_RULES_BLOCK = renderPathRulesBlock(2);

/** Build the `path_rules:` block with the given `minimum_signatures`.
 *  Pulled into a helper so the one-PR migration can smart-default to 1
 *  when only one admin was promoted (a 2-signature gate on a 1-admin
 *  repo would deadlock every subsequent .stamp/** change). */
export function renderPathRulesBlock(minimumSignatures: number): string {
  return [
    "# path_rules gates trust-anchor edits behind admin capabilities.",
    "# See docs/migration-1.x-to-2.x.md and DESIGN.md for the threat model.",
    "path_rules:",
    '  ".stamp/**":',
    "    require_capability: admin",
    `    minimum_signatures: ${minimumSignatures}`,
    "    bypass_review_cycle: true",
  ].join("\n");
}

/**
 * Walk `lines` from `startIdx` and return a `{start,end}` range
 * spanning a YAML block whose first line is the key declaration at
 * `startIdx`. The block ends at the first subsequent line that is
 * non-empty, non-comment, and indented at-or-less than the key
 * declaration's own indent. Trailing blank lines inside the block are
 * NOT included in the range (they belong to the next block visually).
 *
 * Used by `commentOutBlocks` to bound a single map entry's lines so
 * the `# ` prefix lands consistently.
 */
function blockRange(
  lines: string[],
  startIdx: number,
): { start: number; end: number } {
  const keyLine = lines[startIdx]!;
  const keyIndent = leadingSpaces(keyLine);
  let end = startIdx + 1;
  while (end < lines.length) {
    const line = lines[end]!;
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#")) {
      end++;
      continue;
    }
    if (leadingSpaces(line) <= keyIndent) break;
    end++;
  }
  // Walk back past trailing blanks so a separator line between
  // `mcp_servers:` and the next reviewer key doesn't get a `# ` prefix.
  while (end > startIdx + 1 && lines[end - 1]!.trim() === "") end--;
  return { start: startIdx, end };
}

function leadingSpaces(line: string): number {
  let i = 0;
  while (i < line.length && line[i] === " ") i++;
  return i;
}

interface CommentResult {
  lines: string[];
  blocks: string[];
}

/**
 * Scan `text` for any YAML key in `keyNames` at any indentation level
 * and comment out the matching key declaration plus its block body.
 * Returns the rewritten lines (split form so the caller can re-join
 * with control over the trailing newline) plus the deduplicated list
 * of key names that were actually commented.
 *
 * Already-commented blocks are skipped: a line that starts with `#`
 * before the key is treated as a no-op so re-running the migration
 * doesn't double-comment (`## tools:`).
 */
function commentOutBlocks(text: string, keyNames: string[]): CommentResult {
  const lines = text.split("\n");
  const blocks = new Set<string>();
  // Build a regex that matches "<indent><key>:" anywhere in the file,
  // including nested under reviewer entries. Using a per-key check
  // keeps the matching tight and avoids accidentally commenting an
  // unrelated key whose name happens to start with one of these.
  const keyPattern = new RegExp(
    `^(\\s*)(${keyNames.map(escapeRegex).join("|")}):\\s*(#.*)?$`,
  );

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    // Skip lines that have already been commented out — we don't want
    // to re-prefix on idempotent re-runs.
    if (/^\s*#/.test(line)) continue;
    const m = line.match(keyPattern);
    if (!m) continue;

    const matchedKey = m[2]!;
    const range = blockRange(lines, i);
    for (let j = range.start; j < range.end; j++) {
      lines[j] = commentLine(lines[j]!);
    }
    blocks.add(matchedKey);
    i = range.end - 1; // resume scanning past the just-commented block
  }
  return { lines, blocks: [...blocks] };
}

/**
 * Prefix a single line with `# ` while preserving its existing
 * indentation. Blank lines get `#` alone (no trailing space) so
 * diff-readers don't see invisible whitespace.
 */
function commentLine(line: string): string {
  if (line.trim() === "") return "#";
  const indent = leadingSpaces(line);
  return line.slice(0, indent) + "# " + line.slice(indent);
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

interface PathRulesProbe {
  /** True iff the existing block contains a `.stamp/**` entry whose
   *  body matches the default rule (require_capability: admin,
   *  minimum_signatures: 2, bypass_review_cycle: true). Used to
   *  decide whether to warn. */
  matchesDefault: boolean;
}

/**
 * Return a probe of any existing top-level `path_rules:` block in
 * `text`, or `null` when no such block exists. Top-level means an
 * unindented key line. We don't try to merge entries — the caller
 * either appends fresh or warns; that keeps the rewrite predictable.
 */
function findTopLevelPathRulesBlock(text: string): PathRulesProbe | null {
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (/^\s*#/.test(line)) continue;
    if (/^path_rules\s*:\s*(#.*)?$/.test(line)) {
      return { matchesDefault: pathRulesMatchesDefault(lines, i) };
    }
  }
  return null;
}

/**
 * Best-effort check whether an existing `path_rules:` block's
 * `.stamp/**` entry matches the default we'd otherwise install. Used
 * to suppress the warning when the operator already has the
 * recommended rule — re-running the migration on an already-migrated
 * repo should be silent on path_rules. Imprecise on purpose: we look
 * for the three field assignments anywhere in the block, allowing
 * different orderings + extra surrounding lines.
 */
function pathRulesMatchesDefault(
  lines: string[],
  pathRulesIdx: number,
  expectedMinSigs: number = 2,
): boolean {
  const range = blockRange(lines, pathRulesIdx);
  let sawStampGlob = false;
  let sawAdmin = false;
  let sawMinSigs = false;
  let sawBypass = false;
  const minSigsRe = new RegExp(`^minimum_signatures\\s*:\\s*${expectedMinSigs}\\b`);
  for (let i = range.start; i < range.end; i++) {
    const line = lines[i]!.trim();
    if (/^"?\.stamp\/\*\*"?\s*:/.test(line)) sawStampGlob = true;
    if (/^require_capability\s*:\s*admin\b/.test(line)) sawAdmin = true;
    if (minSigsRe.test(line)) sawMinSigs = true;
    if (/^bypass_review_cycle\s*:\s*true\b/.test(line)) sawBypass = true;
  }
  return sawStampGlob && sawAdmin && sawMinSigs && sawBypass;
}

/** Probe whether the existing `path_rules:` block matches the rule we
 *  would install given `minimumSignatures`. Used to suppress the
 *  warning on an idempotent re-run. */
function pathRulesMatchesRequested(
  text: string,
  minimumSignatures: number,
): boolean {
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (/^\s*#/.test(line)) continue;
    if (/^path_rules\s*:\s*(#.*)?$/.test(line)) {
      return pathRulesMatchesDefault(lines, i, minimumSignatures);
    }
  }
  return false;
}

function indentBlock(block: string, indent: string): string {
  return block
    .split("\n")
    .map((l) => (l.length > 0 ? indent + l : l))
    .join("\n");
}

/**
 * Rewrite every reviewer entry under a top-level `reviewers:` block to
 * empty-object form (`<name>: {}`). Preserves entry names and the
 * surrounding file shape; replaces only the lines that constitute each
 * reviewer's body. Idempotent: a second pass on the rewritten text is
 * a no-op (entries already in `{}` form are detected and skipped).
 *
 * The Shape 4 bootstrap whitelist (`validateShape4ActivationDiff`)
 * recognizes this exact pattern: a reviewer's HEAD shape must equal its
 * BASE shape OR be `{}`. We emit `{}` form so a Shape 4 activation diff
 * is whitelist-clean.
 *
 * Line-oriented (no YAML parse round-trip) for the same reason as the
 * comment-out logic: round-tripping would lose comments + formatting.
 */
function rewriteReviewersToEmptyForm(text: string): {
  text: string;
  rewritten: string[];
} {
  const lines = text.split("\n");
  let i = 0;
  // Find a top-level `reviewers:` block. Same constraint as
  // findTopLevelPathRulesBlock — unindented key line, not commented.
  let reviewersIdx = -1;
  for (i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (/^\s*#/.test(line)) continue;
    if (/^reviewers\s*:\s*(#.*)?$/.test(line)) {
      reviewersIdx = i;
      break;
    }
  }
  if (reviewersIdx < 0) return { text, rewritten: [] };

  const blockEnd = blockRange(lines, reviewersIdx).end;
  // Sweep through the reviewers block. Each non-comment, non-blank line
  // at indent > 0 (2 by stamp convention but we accept any positive
  // indent) is either a reviewer name declaration (key:) or a body line
  // belonging to the most recent name. We replace each name+body with
  // `  <name>: {}`.
  const out: string[] = [];
  // Preserve everything up to and including the `reviewers:` line.
  for (let j = 0; j <= reviewersIdx; j++) out.push(lines[j]!);

  const rewritten: string[] = [];
  i = reviewersIdx + 1;
  // The reviewer block's own indent baseline = the indent of the first
  // child line. Sweep finds the first non-comment, non-blank child.
  let nameIndent = -1;
  let scan = i;
  while (scan < blockEnd) {
    const l = lines[scan]!;
    const t = l.trim();
    if (t !== "" && !t.startsWith("#")) {
      nameIndent = leadingSpaces(l);
      break;
    }
    scan++;
  }
  if (nameIndent < 0) {
    // Empty reviewers block — nothing to do.
    for (let j = reviewersIdx + 1; j < lines.length; j++) out.push(lines[j]!);
    return { text: out.join("\n"), rewritten: [] };
  }

  while (i < blockEnd) {
    const line = lines[i]!;
    const t = line.trim();
    if (t === "" || t.startsWith("#")) {
      // Preserve blank lines and comments unchanged.
      out.push(line);
      i++;
      continue;
    }
    const indent = leadingSpaces(line);
    if (indent !== nameIndent) {
      // Not a name line at the expected indent — preserve as-is. This
      // covers edge cases like a comment-prefixed body line we don't
      // want to clobber.
      out.push(line);
      i++;
      continue;
    }
    // Parse the name. Accept `name:`, `name: {}`, `name: # comment`.
    const m = line.match(/^(\s*)([A-Za-z0-9._-]+)\s*:\s*(\{\s*\})?\s*(#.*)?$/);
    if (!m) {
      // Couldn't parse — preserve the original line and advance one
      // line (don't pretend to rewrite something we don't understand).
      out.push(line);
      i++;
      continue;
    }
    const namePrefix = m[1]!;
    const name = m[2]!;
    const alreadyEmpty = m[3] !== undefined;
    if (alreadyEmpty) {
      // Idempotent: leave the line alone, skip over any body lines (a
      // well-formed `name: {}` shouldn't have a body, but tolerate one).
      out.push(line);
      i++;
      while (i < blockEnd) {
        const next = lines[i]!;
        const nt = next.trim();
        if (nt === "") {
          out.push(next);
          i++;
          continue;
        }
        if (leadingSpaces(next) > nameIndent) {
          out.push(next);
          i++;
          continue;
        }
        break;
      }
      continue;
    }
    // Rewrite to empty form. Drop the entry's body lines (all lines
    // indented deeper than nameIndent, up to the next name or block
    // end). Preserve interleaved blank lines as standalone empties
    // outside the entry — they typically separate reviewers visually.
    out.push(`${namePrefix}${name}: {}`);
    rewritten.push(name);
    i++;
    while (i < blockEnd) {
      const next = lines[i]!;
      const nt = next.trim();
      if (nt === "") {
        // Blank line — keep as a separator, end the body sweep.
        out.push(next);
        i++;
        break;
      }
      if (leadingSpaces(next) > nameIndent) {
        // Body line — drop it.
        i++;
        continue;
      }
      // Next entry / sibling — stop sweeping.
      break;
    }
  }

  // Append everything after the reviewers block.
  for (let j = blockEnd; j < lines.length; j++) out.push(lines[j]!);
  return { text: out.join("\n"), rewritten };
}

/**
 * Add `review_server: <url>` to the named branch's rule in a YAML
 * `.stamp/config.yml` blob. Line-oriented to preserve operator
 * comments/formatting. Idempotent: if the branch already carries a
 * `review_server:`, leave the file alone (and warn if the existing
 * value differs from `url`). If the branch isn't found, warn — the
 * caller decided which branch; we don't invent one here.
 */
function addReviewServerToBranch(
  text: string,
  branch: string,
  url: string,
): { text: string; added: boolean; warnings: string[] } {
  const warnings: string[] = [];
  const lines = text.split("\n");

  // Find the top-level `branches:` block.
  let branchesIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (/^\s*#/.test(line)) continue;
    if (/^branches\s*:\s*(#.*)?$/.test(line)) {
      branchesIdx = i;
      break;
    }
  }
  if (branchesIdx < 0) {
    warnings.push(
      `\`branches:\` block not found in .stamp/config.yml — cannot add review_server. Add a branches section first.`,
    );
    return { text, added: false, warnings };
  }

  const branchesEnd = blockRange(lines, branchesIdx).end;
  // Find the branch entry at one level of indent under `branches:`.
  let branchIdx = -1;
  // Determine the indent baseline for branch entries: first non-blank
  // non-comment child line.
  let entryIndent = -1;
  for (let i = branchesIdx + 1; i < branchesEnd; i++) {
    const l = lines[i]!;
    const t = l.trim();
    if (t === "" || t.startsWith("#")) continue;
    entryIndent = leadingSpaces(l);
    break;
  }
  if (entryIndent < 0) {
    warnings.push(
      `\`branches:\` block is empty — cannot add review_server. Add a branch rule first.`,
    );
    return { text, added: false, warnings };
  }
  const branchRe = new RegExp(`^\\s{${entryIndent}}${escapeRegex(branch)}\\s*:\\s*(#.*)?$`);
  for (let i = branchesIdx + 1; i < branchesEnd; i++) {
    const l = lines[i]!;
    if (/^\s*#/.test(l)) continue;
    if (branchRe.test(l)) {
      branchIdx = i;
      break;
    }
  }
  if (branchIdx < 0) {
    warnings.push(
      `branch "${branch}" not found under \`branches:\` in .stamp/config.yml — cannot add review_server.`,
    );
    return { text, added: false, warnings };
  }

  const branchEnd = blockRange(lines, branchIdx).end;
  const bodyIndent = entryIndent + 2;
  // Look for an existing review_server line in the branch body.
  for (let i = branchIdx + 1; i < branchEnd; i++) {
    const l = lines[i]!;
    if (/^\s*#/.test(l)) continue;
    const m = l.match(/^(\s*)review_server\s*:\s*(.*?)\s*(#.*)?$/);
    if (m && leadingSpaces(l) === bodyIndent) {
      const existing = (m[2] ?? "").replace(/^"|"$/g, "").replace(/^'|'$/g, "");
      if (existing === url) {
        return { text, added: false, warnings };
      }
      warnings.push(
        `branch "${branch}" already has review_server: ${existing} in .stamp/config.yml — leaving in place (requested: ${url}). Edit by hand if you want to change it.`,
      );
      return { text, added: false, warnings };
    }
  }

  // Insert `<indent>review_server: <url>` immediately after the branch
  // key line so the new field appears at the top of the branch body
  // (consistent with how stamp init lays out other branch fields).
  const insertion = `${" ".repeat(bodyIndent)}review_server: ${url}`;
  const newLines = [
    ...lines.slice(0, branchIdx + 1),
    insertion,
    ...lines.slice(branchIdx + 1),
  ];
  return { text: newLines.join("\n"), added: true, warnings };
}
