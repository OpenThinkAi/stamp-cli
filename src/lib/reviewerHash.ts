import { createHash } from "node:crypto";
import type { McpServerDef } from "./config.js";

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

export function hashPromptBytes(bytes: string | Buffer): string {
  return sha256Hex(bytes);
}

export function hashTools(tools: string[] | undefined): string {
  const sorted = [...(tools ?? [])].sort();
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
function canonicalize(value: unknown): unknown {
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
