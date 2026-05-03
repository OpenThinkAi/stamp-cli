/**
 * Tests for AGT-045 — privacy: hash MCP server/tool names in mirrored
 * attestation.
 *
 * The threat: a reviewer that talks to internal MCP servers (e.g.
 * `mcp__acme-billing__lookup_invoice`) leaks the existence of that internal
 * service into the public mirror via the `Stamp-Payload` trailer's
 * `tool_calls[].tool` field. The opt-in `STAMP_HASH_MCP_NAMES=1` env var
 * rewrites those names at attestation-build time.
 *
 * AC #6 cases pinned here:
 *   - env-set + mcp__server__tool → mcp__sha256:<hex8>__sha256:<hex8>
 *   - env-set + built-in (no mcp__ prefix) → passthrough
 *   - env-unset → behavior identical to today (full passthrough)
 */

import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { afterEach, describe, it } from "node:test";

import {
  redactMcpToolName,
  redactToolCallsForAttestation,
  type ToolCall,
} from "../src/lib/toolCalls.js";

const h8 = (s: string) =>
  createHash("sha256").update(s, "utf8").digest("hex").slice(0, 8);

describe("redactMcpToolName", () => {
  it("hashes both server and tool segments deterministically", () => {
    const out = redactMcpToolName("mcp__acme-billing__lookup_invoice");
    assert.equal(
      out,
      `mcp__sha256:${h8("acme-billing")}__sha256:${h8("lookup_invoice")}`,
    );
  });

  it("passes built-in SDK tool names through unchanged", () => {
    assert.equal(redactMcpToolName("Read"), "Read");
    assert.equal(redactMcpToolName("Grep"), "Grep");
    assert.equal(redactMcpToolName("Bash"), "Bash");
  });

  it("returns the input unchanged for malformed mcp__ names", () => {
    // Missing the second `__` separator → can't split into server/tool.
    assert.equal(redactMcpToolName("mcp__no-separator"), "mcp__no-separator");
    // Empty server segment.
    assert.equal(redactMcpToolName("mcp____tool"), "mcp____tool");
  });
});

describe("redactToolCallsForAttestation", () => {
  afterEach(() => {
    delete process.env.STAMP_HASH_MCP_NAMES;
  });

  it("with STAMP_HASH_MCP_NAMES=1, hashes mcp__ entries and leaves built-ins alone", () => {
    process.env.STAMP_HASH_MCP_NAMES = "1";
    const input: ToolCall[] = [
      { tool: "Read", input_sha256: "a".repeat(64) },
      { tool: "mcp__acme-billing__lookup_invoice", input_sha256: "b".repeat(64) },
      { tool: "Grep", input_sha256: "c".repeat(64) },
    ];
    const out = redactToolCallsForAttestation(input);
    assert.equal(out[0]!.tool, "Read");
    assert.equal(
      out[1]!.tool,
      `mcp__sha256:${h8("acme-billing")}__sha256:${h8("lookup_invoice")}`,
    );
    assert.equal(out[2]!.tool, "Grep");
    // input_sha256 is preserved on every entry.
    assert.equal(out[0]!.input_sha256, "a".repeat(64));
    assert.equal(out[1]!.input_sha256, "b".repeat(64));
    assert.equal(out[2]!.input_sha256, "c".repeat(64));
  });

  it("with STAMP_HASH_MCP_NAMES unset, returns the calls untouched", () => {
    delete process.env.STAMP_HASH_MCP_NAMES;
    const input: ToolCall[] = [
      { tool: "mcp__internal-hr__get_employee", input_sha256: "d".repeat(64) },
      { tool: "Read", input_sha256: "e".repeat(64) },
    ];
    const out = redactToolCallsForAttestation(input);
    assert.equal(out[0]!.tool, "mcp__internal-hr__get_employee");
    assert.equal(out[1]!.tool, "Read");
  });

  it("only treats the literal string '1' as opt-in (not 'true', not '0')", () => {
    process.env.STAMP_HASH_MCP_NAMES = "true";
    const input: ToolCall[] = [
      { tool: "mcp__acme__x", input_sha256: "f".repeat(64) },
    ];
    assert.equal(
      redactToolCallsForAttestation(input)[0]!.tool,
      "mcp__acme__x",
      "STAMP_HASH_MCP_NAMES=true should NOT trigger redaction (strict =='1')",
    );
  });
});
