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
import { stampTrustedKeysDir, stampConfigFile } from "./paths.js";

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
 * with the same input produces byte-identical output.
 */
export function serializeManifest(
  keys: DetectedKey[],
  adminFingerprints: ReadonlySet<string>,
): string {
  const sorted = [...keys].sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
  );
  const lines: string[] = [
    "# Trusted-keys manifest for server-attested reviews (stamp 2.x).",
    "# Generated by `stamp init --migrate-to-server-attested`. Edit by hand to",
    "# adjust capabilities; changes go through the .stamp/** path_rules gate",
    "# (admin-signed, bypasses the reviewer cycle).",
    "keys:",
  ];
  for (const k of sorted) {
    const caps = adminFingerprints.has(k.fingerprint)
      ? "[admin, operator]"
      : "[operator]";
    lines.push(`  ${k.name}:`);
    lines.push(`    fingerprint: ${k.fingerprint}`);
    lines.push(`    capabilities: ${caps}`);
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
export function rewriteConfigForMigration(input: string): ConfigRewriteResult {
  const commented: { lines: string[]; blocks: string[] } = commentOutBlocks(
    input,
    ["mcp_servers", "tools"],
  );

  let text = commented.lines.join("\n");
  // Preserve the input's trailing-newline behavior. `split("\n")` on a
  // string that ends with "\n" produces a trailing "" entry, which the
  // join recreates; on a string without one, no extra newline appears.
  // No further work needed.

  const warnings: string[] = [];
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
      DEFAULT_PATH_RULES_BLOCK +
      "\n";
    pathRulesAppended = true;
  } else if (!existingPathRules.matchesDefault) {
    warnings.push(
      `\`path_rules:\` already present in .stamp/config.yml with a different ` +
        `\`.stamp/**\` rule. Leaving the existing block in place — review ` +
        `manually against the recommended default:\n` +
        indentBlock(DEFAULT_PATH_RULES_BLOCK, "  "),
    );
  }

  const changed = text !== input;
  return {
    text,
    changed,
    commentedBlocks: commented.blocks,
    pathRulesAppended,
    warnings,
  };
}

/** Default `path_rules:` block appended when none exists. Pinned here
 *  rather than constructed dynamically so the migration test can match
 *  it exactly. */
export const DEFAULT_PATH_RULES_BLOCK = [
  "# path_rules gates trust-anchor edits behind admin capabilities.",
  "# See docs/migration-1.x-to-2.x.md and DESIGN.md for the threat model.",
  "path_rules:",
  '  ".stamp/**":',
  "    require_capability: admin",
  "    minimum_signatures: 2",
  "    bypass_review_cycle: true",
].join("\n");

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
): boolean {
  const range = blockRange(lines, pathRulesIdx);
  let sawStampGlob = false;
  let sawAdmin = false;
  let sawMinSigs = false;
  let sawBypass = false;
  for (let i = range.start; i < range.end; i++) {
    const line = lines[i]!.trim();
    if (/^"?\.stamp\/\*\*"?\s*:/.test(line)) sawStampGlob = true;
    if (/^require_capability\s*:\s*admin\b/.test(line)) sawAdmin = true;
    if (/^minimum_signatures\s*:\s*2\b/.test(line)) sawMinSigs = true;
    if (/^bypass_review_cycle\s*:\s*true\b/.test(line)) sawBypass = true;
  }
  return sawStampGlob && sawAdmin && sawMinSigs && sawBypass;
}

function indentBlock(block: string, indent: string): string {
  return block
    .split("\n")
    .map((l) => (l.length > 0 ? indent + l : l))
    .join("\n");
}

/**
 * Path to a repo's `.stamp/config.yml`. Re-exported here so command
 * code can import a single migration-facing module instead of pulling
 * `paths.js` directly.
 */
export function configPath(repoRoot: string): string {
  return stampConfigFile(repoRoot);
}
