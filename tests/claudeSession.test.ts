/**
 * Unit tests for `src/lib/claudeSession.ts`.
 *
 * Tests the `detectClaudeSession` function across a matrix of env presences:
 *   - both CLAUDECODE and CLAUDE_CODE_SESSION_ID present → ok: true
 *   - only CLAUDECODE set, SESSION_ID absent → ok: false
 *   - only SESSION_ID set, CLAUDECODE absent/wrong → ok: false
 *   - neither set → ok: false
 *   - malformed SESSION_ID (too short, wrong chars) → ok: false
 *   - various valid hex/UUID shapes → ok: true
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { detectClaudeSession } from "../src/lib/claudeSession.ts";

// ─── Both vars present and valid → ok: true ──────────────────────────

describe("detectClaudeSession: both vars present → ok: true", () => {
  it("returns ok:true with a UUID-shaped session id", () => {
    const env = {
      CLAUDECODE: "1",
      CLAUDE_CODE_SESSION_ID: "550e8400-e29b-41d4-a716-446655440000",
    };
    const result = detectClaudeSession(env);
    assert.equal(result.ok, true, `expected ok:true, got: ${JSON.stringify(result)}`);
    if (result.ok) {
      assert.equal(result.session.sessionId, "550e8400-e29b-41d4-a716-446655440000");
    }
  });

  it("returns ok:true with a plain hex session id (no dashes)", () => {
    const env = {
      CLAUDECODE: "1",
      CLAUDE_CODE_SESSION_ID: "abcdef1234567890",
    };
    const result = detectClaudeSession(env);
    assert.equal(result.ok, true, `expected ok:true, got: ${JSON.stringify(result)}`);
    if (result.ok) {
      assert.equal(result.session.sessionId, "abcdef1234567890");
    }
  });

  it("returns ok:true with uppercase hex session id", () => {
    const env = {
      CLAUDECODE: "1",
      CLAUDE_CODE_SESSION_ID: "ABCDEF1234567890",
    };
    const result = detectClaudeSession(env);
    assert.equal(result.ok, true, `expected ok:true, got: ${JSON.stringify(result)}`);
  });

  it("returns ok:true with a mixed-case hex session id (8 chars minimum)", () => {
    const env = {
      CLAUDECODE: "1",
      CLAUDE_CODE_SESSION_ID: "aB3dEf12",
    };
    const result = detectClaudeSession(env);
    assert.equal(result.ok, true, `expected ok:true for 8-char hex, got: ${JSON.stringify(result)}`);
  });
});

// ─── CLAUDECODE missing or wrong → ok: false ────────────────────────

describe("detectClaudeSession: CLAUDECODE missing or wrong → ok: false", () => {
  it("returns ok:false when CLAUDECODE is absent", () => {
    const env = {
      CLAUDE_CODE_SESSION_ID: "550e8400-e29b-41d4-a716-446655440000",
    };
    const result = detectClaudeSession(env);
    assert.equal(result.ok, false, `expected ok:false, got: ${JSON.stringify(result)}`);
  });

  it("returns ok:false when CLAUDECODE is '0'", () => {
    const env = {
      CLAUDECODE: "0",
      CLAUDE_CODE_SESSION_ID: "550e8400-e29b-41d4-a716-446655440000",
    };
    const result = detectClaudeSession(env);
    assert.equal(result.ok, false, `expected ok:false, got: ${JSON.stringify(result)}`);
  });

  it("returns ok:false when CLAUDECODE is 'true' (not '1')", () => {
    const env = {
      CLAUDECODE: "true",
      CLAUDE_CODE_SESSION_ID: "550e8400-e29b-41d4-a716-446655440000",
    };
    const result = detectClaudeSession(env);
    assert.equal(result.ok, false, `expected ok:false, got: ${JSON.stringify(result)}`);
  });

  it("returns ok:false when neither var is set", () => {
    const env = {};
    const result = detectClaudeSession(env);
    assert.equal(result.ok, false, `expected ok:false, got: ${JSON.stringify(result)}`);
  });
});

// ─── SESSION_ID missing or malformed → ok: false ────────────────────

describe("detectClaudeSession: SESSION_ID absent or malformed → ok: false", () => {
  it("returns ok:false when CLAUDE_CODE_SESSION_ID is absent", () => {
    const env = {
      CLAUDECODE: "1",
    };
    const result = detectClaudeSession(env);
    assert.equal(result.ok, false, `expected ok:false, got: ${JSON.stringify(result)}`);
  });

  it("returns ok:false when SESSION_ID is empty string", () => {
    const env = {
      CLAUDECODE: "1",
      CLAUDE_CODE_SESSION_ID: "",
    };
    const result = detectClaudeSession(env);
    assert.equal(result.ok, false, `expected ok:false for empty session id, got: ${JSON.stringify(result)}`);
  });

  it("returns ok:false when SESSION_ID is too short (< 8 chars)", () => {
    const env = {
      CLAUDECODE: "1",
      CLAUDE_CODE_SESSION_ID: "abc1234", // 7 chars
    };
    const result = detectClaudeSession(env);
    assert.equal(result.ok, false, `expected ok:false for 7-char id, got: ${JSON.stringify(result)}`);
  });

  it("returns ok:false when SESSION_ID contains non-hex chars (path separator)", () => {
    const env = {
      CLAUDECODE: "1",
      CLAUDE_CODE_SESSION_ID: "abc/def12345678",
    };
    const result = detectClaudeSession(env);
    assert.equal(result.ok, false, `expected ok:false for path-containing id, got: ${JSON.stringify(result)}`);
  });

  it("returns ok:false when SESSION_ID contains spaces", () => {
    const env = {
      CLAUDECODE: "1",
      CLAUDE_CODE_SESSION_ID: "abc def 12345678",
    };
    const result = detectClaudeSession(env);
    assert.equal(result.ok, false, `expected ok:false for space-containing id, got: ${JSON.stringify(result)}`);
  });

  it("returns ok:false when SESSION_ID contains non-hex letters (e.g. 'g')", () => {
    const env = {
      CLAUDECODE: "1",
      CLAUDE_CODE_SESSION_ID: "abcdefg1234567890",
    };
    const result = detectClaudeSession(env);
    assert.equal(result.ok, false, `expected ok:false for non-hex 'g', got: ${JSON.stringify(result)}`);
  });
});

// ─── Default env (uses process.env) ────────────────────────────────

describe("detectClaudeSession: default env arg", () => {
  it("uses process.env by default (smoke test — just verify it doesn't throw)", () => {
    // We can't assert the result (varies by environment), just that it returns a discriminated union.
    const result = detectClaudeSession();
    assert.ok(
      typeof result.ok === "boolean",
      `expected result.ok to be a boolean, got: ${typeof result.ok}`,
    );
  });
});
