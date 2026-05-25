/**
 * Client-side peer-repos configuration for the `stamp pr listen` operator
 * verification path (AGT-454).
 *
 * Resolves `<org>/<repo>` → local absolute path via `~/.stamp/peer-repos.yml`.
 * The listener verifies that a PR author is an operator in the manifest at
 * `base_sha` of its own local clone — no server repo access required.
 *
 * File format (`~/.stamp/peer-repos.yml`):
 *
 *   "anglepoint-inc/hivedb": /Users/alice/code/hivedb
 *   "openthink-ai/stamp-cli": /Users/alice/code/stamp-cli
 *
 * Unmapped repos → `null` (caller must skip with a loud log line, fail-closed).
 * Missing file → empty map (same semantics as no entries).
 *
 * YAML is deliberately minimal: only top-level string→string mappings are
 * supported. Any mapping value that is not a non-empty string, or any
 * relative path, is silently skipped (logs a note on stderr).
 */

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";

/** Default location for the peer-repos map. */
export function peerReposConfigPath(): string {
  return join(homedir(), ".stamp", "peer-repos.yml");
}

/**
 * Load and parse `~/.stamp/peer-repos.yml`. Returns a `Map<string, string>`
 * keyed by `<org>/<repo>` (lowercased), valued by absolute local clone path.
 *
 * Never throws: missing file → empty map; parse errors → partial map (bad
 * entries skipped with a stderr note).
 */
export function loadPeerReposConfig(): Map<string, string> {
  const configPath = peerReposConfigPath();
  const map = new Map<string, string>();

  if (!existsSync(configPath)) return map;

  let raw: string;
  try {
    raw = readFileSync(configPath, "utf8");
  } catch (err) {
    process.stderr.write(
      `note: peer-repos.yml unreadable at ${configPath}: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    return map;
  }

  // Minimal YAML parser: handle only top-level key: value lines.
  // We intentionally avoid pulling in a full YAML library (no new deps).
  // Supported forms:
  //   "org/repo": /abs/path
  //   'org/repo': /abs/path
  //   org/repo: /abs/path
  for (const rawLine of raw.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    // Match: optional-quote KEY optional-quote : VALUE
    const match = line.match(/^["']?([^"':]+)["']?\s*:\s*(.+)$/);
    if (!match) {
      // Silently skip non-matching lines (YAML comments, blank lines, etc.)
      continue;
    }

    const repoKey = match[1]!.trim().toLowerCase();
    const pathVal = match[2]!.trim().replace(/^["']|["']$/g, ""); // strip optional outer quotes

    if (!repoKey.includes("/")) {
      process.stderr.write(`note: peer-repos.yml: skipping entry without slash in key: "${repoKey}"\n`);
      continue;
    }

    if (!isAbsolute(pathVal)) {
      process.stderr.write(
        `note: peer-repos.yml: skipping relative path for "${repoKey}" (must be absolute): "${pathVal}"\n`,
      );
      continue;
    }

    map.set(repoKey, pathVal);
  }

  return map;
}

/**
 * Resolve `<org>/<repo>` → local clone path from the peer-repos map.
 * Returns `null` when the repo is unmapped.
 *
 * `peerReposMap` is passed in so callers can load it once and reuse across events.
 */
export function resolveLocalRepoPath(
  repo: string,
  peerReposMap: Map<string, string>,
): string | null {
  return peerReposMap.get(repo.toLowerCase()) ?? null;
}
