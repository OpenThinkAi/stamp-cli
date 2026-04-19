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
