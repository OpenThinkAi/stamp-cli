import { createHash } from "node:crypto";
import { canonicalize } from "./reviewerHash.js";

/**
 * Per-review tool-invocation trace (plan Step 4).
 *
 * Each entry captures one tool call the reviewer's Claude agent made during
 * `stamp review`. Tool name is recorded verbatim (e.g. "Read", "Grep", or
 * `mcp__<server>__<tool>` for MCP calls); input is represented by the
 * sha256 of its canonical JSON so the trace doesn't leak potentially
 * sensitive argument content (file contents fetched back, LLM-derived
 * prompts, etc.) into the signed attestation.
 *
 * Threat model note: this trace is NOT cryptographic evidence that the
 * tools actually ran with those inputs. The operator runs the SDK locally
 * and can forge any trace they like. The value is audit: a downstream
 * verifier with knowledge of the prompt's expected behavior can check
 * "for a diff mentioning LIN-123, I expect a call to mcp__linear__get_issue
 * with input hashing to <X>" — catches lazy tampering, not determined
 * forgery. See docs/plans/verified-reviewer-configs.md Step 4.
 */
export interface ToolCall {
  /** Tool identifier as the SDK reports it — built-in name ("Read"), or
   *  "mcp__<server>__<tool>" for MCP-hosted tools. */
  tool: string;
  /** sha256 of canonical-JSON-stringified input. */
  input_sha256: string;
}

export function hashToolInput(input: unknown): string {
  const canonical = canonicalize(input ?? null);
  return createHash("sha256").update(JSON.stringify(canonical)).digest("hex");
}

/** Serialize a tool-call list to a JSON string for storage (DB column) or
 *  transport (attestation payload). Null/empty → null, so unused reviewers
 *  don't carry a [] in the DB. */
export function serializeToolCalls(calls: ToolCall[] | null | undefined): string | null {
  if (!calls || calls.length === 0) return null;
  return JSON.stringify(calls);
}

export function parseToolCalls(raw: string | null | undefined): ToolCall[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    const out: ToolCall[] = [];
    for (const entry of parsed) {
      if (!entry || typeof entry !== "object") continue;
      const e = entry as Record<string, unknown>;
      if (typeof e.tool === "string" && typeof e.input_sha256 === "string") {
        out.push({ tool: e.tool, input_sha256: e.input_sha256 });
      }
    }
    return out;
  } catch {
    return [];
  }
}

/**
 * Rewrite an MCP tool name (`mcp__<server>__<tool>`) to its hashed form
 * (`mcp__sha256:<hex8>__sha256:<hex8>`). Built-in SDK names — anything not
 * starting with `mcp__` — are returned unchanged.
 *
 * The 8-hex-char (32-bit) prefix is intentional: a single review touches a
 * handful of MCP names so collisions are negligible, and the `sha256:`
 * literal anchors the format for a future verifier that wants to widen.
 */
export function redactMcpToolName(tool: string): string {
  if (!tool.startsWith("mcp__")) return tool;
  const rest = tool.slice("mcp__".length);
  const sep = rest.indexOf("__");
  if (sep < 0) return tool;
  const server = rest.slice(0, sep);
  const name = rest.slice(sep + 2);
  if (!server || !name) return tool;
  const h = (s: string) =>
    createHash("sha256").update(s, "utf8").digest("hex").slice(0, 8);
  return `mcp__sha256:${h(server)}__sha256:${h(name)}`;
}

/**
 * Optionally redact MCP tool names in a tool-call list before they're
 * embedded in the signed attestation. Off by default (verbatim names);
 * `STAMP_HASH_MCP_NAMES=1` opts the operator into hashing so the public
 * mirror doesn't disclose the existence of internal MCP servers.
 *
 * Applied at attestation-build time only: in-memory SDK traces and the
 * local `reviews.tool_calls` DB column stay verbatim so operators retain
 * full local visibility into what their reviewers did.
 */
export function redactToolCallsForAttestation(calls: ToolCall[]): ToolCall[] {
  if (process.env.STAMP_HASH_MCP_NAMES !== "1") return calls;
  return calls.map((c) => ({ ...c, tool: redactMcpToolName(c.tool) }));
}
