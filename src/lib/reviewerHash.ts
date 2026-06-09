import { createHash } from "node:crypto";
import { parse as parseYaml } from "yaml";
import { parseToolsLoose, type McpServerDef, type ToolSpec } from "./config.js";

/**
 * Minimal reviewer-section extractor used by verify paths. Mirrors the
 * loadConfig shape but tolerates missing branches and other structural
 * issues — we only need {prompt, tools, mcp_servers} per reviewer for
 * hash recomputation, so broken-elsewhere configs shouldn't block the
 * check.
 */
export interface ReviewerDefForHashing {
  prompt: string;
  tools?: ToolSpec[];
  mcp_servers?: Record<string, unknown>;
  /** AGT-472: surfaced for the v3 verify path so the loose parser sees the
   *  same `bash` opt-in `loadConfig` does. Omit-on-unset so callers can
   *  pass the unmodified field through to `hashTools` and existing configs
   *  hash byte-identically. */
  bash?: boolean;
}

export function readReviewersFromYaml(
  yamlText: string,
): Record<string, ReviewerDefForHashing> {
  const parsed = parseYaml(yamlText) as Record<string, unknown> | null;
  const rawReviewers = (parsed?.reviewers ?? {}) as Record<string, unknown>;
  const out: Record<string, ReviewerDefForHashing> = {};
  for (const [name, def] of Object.entries(rawReviewers)) {
    if (!def || typeof def !== "object") continue;
    const d = def as Record<string, unknown>;
    if (typeof d.prompt !== "string") continue;
    out[name] = {
      prompt: d.prompt,
      ...(Array.isArray(d.tools) ? { tools: parseToolsLoose(d.tools) } : {}),
      ...(d.mcp_servers && typeof d.mcp_servers === "object"
        ? { mcp_servers: d.mcp_servers as Record<string, unknown> }
        : {}),
      ...(typeof d.bash === "boolean" ? { bash: d.bash } : {}),
    };
  }
  return out;
}

/**
 * Hashes for per-reviewer attestation fields (plan Step 2).
 *
 * These let a verifier recompute hashes from the committed .stamp/ tree at
 * the merge commit and compare against what the attestation payload claims.
 * Mismatch → someone signed an attestation that doesn't reflect the actual
 * committed config.
 *
 * Hashing is deliberate about canonical form so equivalent YAML produces the
 * same hash:
 *   - tools: order-independent (treated as a set; sorted alphabetically)
 *   - mcp_servers: object keys sorted at every level; arrays preserve order
 *     (CLI arg order is semantically meaningful); env values hashed verbatim
 *     (an env reference string like "$LINEAR_API_KEY" hashes differently
 *     from "$EVIL_TOKEN", which is what we want — the unresolved config as
 *     committed to the repo is what the hash represents)
 *
 * Empty/absent tools or mcp_servers produce a stable "no-op" hash (sha256 of
 * "[]" or "{}" respectively) rather than a special null marker, so the
 * verifier doesn't need to handle absence as a distinct case.
 */

function sha256Hex(input: string | Buffer): string {
  const h = createHash("sha256");
  h.update(input);
  return h.digest("hex");
}

/**
 * Hash the raw bytes of a reviewer prompt file. Callers must source the
 * bytes from the committed git tree (`git show <sha>:<path>`), not the
 * working directory — Windows + core.autocrlf and .gitattributes eol
 * filters can make working-tree bytes diverge from committed bytes, and
 * verifiers always hash the committed form.
 *
 * Takes `Buffer` (not `string | Buffer`) so the input type is unambiguous
 * at call sites. String callers should convert with Buffer.from(s, "utf8")
 * at the point they read the bytes — UTF-8 is the documented assumption
 * for reviewer prompts.
 */
export function hashPromptBytes(bytes: Buffer): string {
  return sha256Hex(bytes);
}

/**
 * Sentinel injected into the canonicalized tools list when a reviewer has
 * `bash: true` set in `.stamp/config.yml` (AGT-472). Double-underscore
 * prefix guarantees it cannot collide with a real SDK tool name (real
 * names are either CamelCase like `Bash`/`Read` or `mcp__<server>__<tool>`,
 * both shapes distinct from `__bash`). Pure-ASCII so JSON serialization
 * is deterministic across encodings.
 *
 * Exported for the unit-test surface — production callers should not
 * reference it directly; they call `hashTools(def.tools, def.bash)`.
 */
export const BASH_OPT_IN_SENTINEL = "__bash";

/**
 * Canonicalize a tools list into a deterministic JSON form for hashing.
 *
 * Backward compat (the strict invariant this function preserves):
 *
 *   1. Pre-A.2 configs were `string[]`; A.2+ are
 *      `(string | { name, allowed_hosts? })[]`. The canonical form
 *      preserves the original shape per-entry — a string entry hashes as
 *      a JSON string, an object entry hashes as a canonicalized JSON
 *      object — so existing v3 attestations whose hashes were computed
 *      against pure-string tools continue to verify identically.
 *
 *   2. AGT-472: the `bash` opt-in is folded into this same hash by
 *      injecting a `BASH_OPT_IN_SENTINEL` string entry into the
 *      canonicalized list when `bash === true`. When `bash` is absent or
 *      false, NOTHING is injected — so every reviewer that existed
 *      before AGT-472 hashes byte-identically (omit-on-unset). Flipping
 *      `bash: false → true` is the only edit that changes `tools_sha256`,
 *      which is exactly the visibility property we want: a feature
 *      branch cannot silently widen its own reviewer's shell capability
 *      because the attestation chain visibly differs.
 *
 * Entries are sorted by their JSON string representation for determinism;
 * this keeps tool ORDER from affecting the hash (a reviewer with tools
 * `["Read", "Grep"]` and one with `["Grep", "Read"]` hash equally).
 */
export function hashTools(
  tools: ToolSpec[] | string[] | undefined,
  bash?: boolean,
): string {
  const normalized: unknown[] = (tools ?? []).map((t) =>
    typeof t === "string" ? t : (canonicalize(t) as unknown),
  );
  // Inject ONLY on bash === true. `false` and `undefined` both produce
  // the pre-AGT-472 hash (byte-identical) so existing attestations remain
  // valid without re-signing.
  if (bash === true) {
    normalized.push(BASH_OPT_IN_SENTINEL);
  }
  const sorted = [...normalized].sort((a, b) => {
    const aKey = typeof a === "string" ? a : JSON.stringify(a);
    const bKey = typeof b === "string" ? b : JSON.stringify(b);
    return aKey < bKey ? -1 : aKey > bKey ? 1 : 0;
  });
  return sha256Hex(JSON.stringify(sorted));
}

// Accepts the strict McpServerDef shape (from loadConfig) or an unstructured
// object (from the hook's minimal YAML parse). canonicalize walks structurally,
// so both paths produce the same hash for equivalent data.
export function hashMcpServers(
  servers: Record<string, McpServerDef> | Record<string, unknown> | undefined,
): string {
  const canonical = canonicalize(servers ?? {});
  return sha256Hex(JSON.stringify(canonical));
}

// Recursively sort object keys to produce a canonical JSON form. Arrays
// preserve order — in MCP configs, CLI arg order is semantically meaningful
// (e.g. `--debug` in a different position may or may not matter, and we
// don't want to silently equate reorderings).
export function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = canonicalize((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}
