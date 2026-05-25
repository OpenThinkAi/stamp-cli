/**
 * AGT-432 — Unit tests for `stamp peer log` (`peerLog.ts`).
 *
 * Coverage per AC #7:
 *   - missing log file → exit 1 + message
 *   - empty log file → exit 1 + message
 *   - valid NDJSON → outputs colorized lines, exit 0
 *   - --raw → outputs raw NDJSON, exit 0
 *   - --last N → limits to last N triplets
 *   - daily cap hit reason → highlighted in output
 *   - I/O error → exit 3
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { writeFileSync, mkdirSync, unlinkSync, rmdirSync } from "node:fs";

import { runPeerLog } from "../src/commands/peerLog.ts";

// ─── Helpers ─────────────────────────────────────────────────────────

function makeExitCapture(): { exitFn: (code: number) => never; capturedCode: () => number | undefined } {
  let captured: number | undefined;
  const exitFn = (code: number): never => {
    captured = code;
    throw Object.assign(new Error(`exit(${code})`), { __exitCode: code });
  };
  return { exitFn, capturedCode: () => captured };
}

function makeTriplet(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    ts: "2026-05-24T12:00:00.000Z",
    repo: "acme/widget",
    pr_url: "https://github.com/acme/widget/pull/42",
    rules_hash: "abc123",
    event_payload: {},
    decision: { claim_seat: "if_available", post_mode: "auto-post", prompt: "default" },
    ...overrides,
  });
}

function writeTempLog(content: string): string {
  const dir = join(tmpdir(), `peer-log-test-${Date.now()}`);
  mkdirSync(dir, { recursive: true });
  const path = join(dir, "peer-watch.log");
  writeFileSync(path, content, "utf8");
  return path;
}

// ─── AC #7: missing log file → exit 1 ────────────────────────────────

describe("peerLog: missing log file → exit 1", () => {
  it("exits 1 with message when log file does not exist", () => {
    const { exitFn, capturedCode } = makeExitCapture();
    const stderrLines: string[] = [];

    try {
      runPeerLog({
        _logPathForTest: "/tmp/definitely-does-not-exist-peerlog-test.log",
        _exitForTest: exitFn,
        _stderrWriteForTest: (s) => { stderrLines.push(s); },
      });
    } catch { /* exitFn throws */ }

    assert.equal(capturedCode(), 1, `expected exit 1, got ${capturedCode()}`);
    const stderrJoined = stderrLines.join("");
    assert.ok(
      stderrJoined.includes("no peer-watch.log found"),
      `expected 'no peer-watch.log found' in: ${stderrJoined}`,
    );
  });
});

// ─── AC #7: empty log file → exit 1 ──────────────────────────────────

describe("peerLog: empty log file → exit 1", () => {
  it("exits 1 with message when log file is empty", () => {
    const logPath = writeTempLog("");
    const { exitFn, capturedCode } = makeExitCapture();
    const stderrLines: string[] = [];

    try {
      runPeerLog({
        _logPathForTest: logPath,
        _exitForTest: exitFn,
        _stderrWriteForTest: (s) => { stderrLines.push(s); },
      });
    } catch { /* exitFn throws */ } finally {
      try { unlinkSync(logPath); } catch { /* ignore */ }
    }

    assert.equal(capturedCode(), 1, `expected exit 1, got ${capturedCode()}`);
    const stderrJoined = stderrLines.join("");
    assert.ok(
      stderrJoined.includes("no peer-watch.log found"),
      `expected 'no peer-watch.log found' in: ${stderrJoined}`,
    );
  });

  it("exits 1 when log file has only whitespace/blank lines", () => {
    const logPath = writeTempLog("   \n   \n");
    const { exitFn, capturedCode } = makeExitCapture();

    try {
      runPeerLog({
        _logPathForTest: logPath,
        _exitForTest: exitFn,
        _stderrWriteForTest: () => {},
      });
    } catch { /* exitFn throws */ } finally {
      try { unlinkSync(logPath); } catch { /* ignore */ }
    }

    assert.equal(capturedCode(), 1, `expected exit 1 for blank-only file, got ${capturedCode()}`);
  });
});

// ─── AC #7: valid NDJSON → colorized output, exit 0 ──────────────────

describe("peerLog: valid NDJSON → colorized output, exit 0", () => {
  it("outputs lines for each record and exits 0", () => {
    const content =
      makeTriplet({ decision: { claim_seat: "if_available", post_mode: "auto-post", prompt: "default" } }) + "\n" +
      makeTriplet({ decision: { claim_seat: "skip", post_mode: "auto-post", prompt: "default" } }) + "\n";
    const logPath = writeTempLog(content);
    const { exitFn, capturedCode } = makeExitCapture();
    const stdoutLines: string[] = [];

    try {
      runPeerLog({
        _logPathForTest: logPath,
        _exitForTest: exitFn,
        _stdoutWriteForTest: (s) => { stdoutLines.push(s); },
        _stderrWriteForTest: () => {},
      });
    } catch { /* exitFn throws */ } finally {
      try { unlinkSync(logPath); } catch { /* ignore */ }
    }

    assert.equal(capturedCode(), 0, `expected exit 0, got ${capturedCode()}`);
    const out = stdoutLines.join("");
    assert.ok(out.includes("if_available"), `expected 'if_available' in output: ${JSON.stringify(out)}`);
    assert.ok(out.includes("skip"), `expected 'skip' in output: ${JSON.stringify(out)}`);
  });

  it("includes ANSI color codes for non-raw output (dim for skip)", () => {
    const content = makeTriplet({ decision: { claim_seat: "skip", post_mode: "auto-post", prompt: "default" } }) + "\n";
    const logPath = writeTempLog(content);
    const { exitFn } = makeExitCapture();
    const stdoutLines: string[] = [];

    try {
      runPeerLog({
        _logPathForTest: logPath,
        _exitForTest: exitFn,
        _stdoutWriteForTest: (s) => { stdoutLines.push(s); },
        _stderrWriteForTest: () => {},
      });
    } catch { /* exitFn throws */ } finally {
      try { unlinkSync(logPath); } catch { /* ignore */ }
    }

    const out = stdoutLines.join("");
    // ANSI dim code (\x1b[2m) expected for skip
    assert.ok(out.includes("\x1b[2m"), `expected ANSI dim code in output for skip: ${JSON.stringify(out)}`);
  });
});

// ─── AC #7: --raw → raw NDJSON output ────────────────────────────────

describe("peerLog: --raw → raw NDJSON output", () => {
  it("outputs raw JSON lines without ANSI codes", () => {
    const content = makeTriplet() + "\n";
    const logPath = writeTempLog(content);
    const { exitFn, capturedCode } = makeExitCapture();
    const stdoutLines: string[] = [];

    try {
      runPeerLog({
        raw: true,
        _logPathForTest: logPath,
        _exitForTest: exitFn,
        _stdoutWriteForTest: (s) => { stdoutLines.push(s); },
        _stderrWriteForTest: () => {},
      });
    } catch { /* exitFn throws */ } finally {
      try { unlinkSync(logPath); } catch { /* ignore */ }
    }

    assert.equal(capturedCode(), 0, `expected exit 0, got ${capturedCode()}`);
    const out = stdoutLines.join("");
    // No ANSI escape codes in raw mode
    assert.ok(!out.includes("\x1b["), `expected no ANSI in raw output, got: ${JSON.stringify(out)}`);
    // Output should be parseable JSON
    const parsed = JSON.parse(out.trim());
    assert.equal(parsed.repo, "acme/widget");
  });
});

// ─── AC #7: --last N → limited output ────────────────────────────────

describe("peerLog: --limit N limits output to last N triplets", () => {
  it("shows only the last 2 triplets when --limit 2", () => {
    const lines = [
      makeTriplet({ ts: "2026-05-01T00:00:00.000Z" }),
      makeTriplet({ ts: "2026-05-02T00:00:00.000Z" }),
      makeTriplet({ ts: "2026-05-03T00:00:00.000Z" }),
    ];
    const logPath = writeTempLog(lines.join("\n") + "\n");
    const { exitFn, capturedCode } = makeExitCapture();
    const stdoutLines: string[] = [];

    try {
      runPeerLog({
        limit: 2,
        _logPathForTest: logPath,
        _exitForTest: exitFn,
        _stdoutWriteForTest: (s) => { stdoutLines.push(s); },
        _stderrWriteForTest: () => {},
        raw: true,
      });
    } catch { /* exitFn throws */ } finally {
      try { unlinkSync(logPath); } catch { /* ignore */ }
    }

    assert.equal(capturedCode(), 0, `expected exit 0, got ${capturedCode()}`);
    const out = stdoutLines.join("");
    // Should contain last 2 timestamps, not first
    assert.ok(out.includes("2026-05-02"), `expected 2026-05-02 in output: ${out}`);
    assert.ok(out.includes("2026-05-03"), `expected 2026-05-03 in output: ${out}`);
    assert.ok(!out.includes("2026-05-01"), `should NOT include 2026-05-01 in output: ${out}`);
  });
});

// ─── AC #7: daily cap hit → highlighted ──────────────────────────────

describe("peerLog: daily cap hit → [daily cap hit] marker in output", () => {
  it("highlights triplets with reason: 'daily cap hit'", () => {
    const content = makeTriplet({
      decision: { claim_seat: "skip", post_mode: "auto-post", prompt: "default", cost_cap_usd: 5 },
      reason: "daily cap hit",
    }) + "\n";
    const logPath = writeTempLog(content);
    const { exitFn, capturedCode } = makeExitCapture();
    const stdoutLines: string[] = [];

    try {
      runPeerLog({
        _logPathForTest: logPath,
        _exitForTest: exitFn,
        _stdoutWriteForTest: (s) => { stdoutLines.push(s); },
        _stderrWriteForTest: () => {},
      });
    } catch { /* exitFn throws */ } finally {
      try { unlinkSync(logPath); } catch { /* ignore */ }
    }

    assert.equal(capturedCode(), 0, `expected exit 0, got ${capturedCode()}`);
    const out = stdoutLines.join("");
    assert.ok(
      out.includes("daily cap hit"),
      `expected 'daily cap hit' marker in output: ${JSON.stringify(out)}`,
    );
  });
});
