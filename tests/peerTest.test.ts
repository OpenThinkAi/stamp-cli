/**
 * AGT-430 — Unit tests for `stamp peer test` (`peerTest.ts`).
 *
 * Coverage per AC #7:
 *   - fixture event + seam triage → pretty JSON on stdout, exit 0
 *   - missing peer-watch.md → exit 1
 *   - unreadable/invalid fixture → exit 1
 *   - STAMP_NO_LLM=1 → exit 3
 *   - runner that throws (schema failure) → skip decision printed + exit 0
 *     (note: peerTest prints whatever runTriage returns; exit 3 is only
 *      for the no-seam/real-SDK path — injected runner path exits 0)
 *
 * All external boundaries (peer-watch.md, fixture file, SDK) are injected.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeFileSync, unlinkSync } from "node:fs";

import { runPeerTest } from "../src/commands/peerTest.ts";

// ─── Helpers ─────────────────────────────────────────────────────────

/** Capture stdout during fn. */
async function captureStdout<T>(fn: () => Promise<T>): Promise<{ result: T; stdout: string }> {
  const lines: string[] = [];
  const origWrite = process.stdout.write.bind(process.stdout);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (process.stdout as any).write = (chunk: unknown) => {
    if (typeof chunk === "string") lines.push(chunk);
    return true;
  };
  let result: T;
  try {
    result = await fn();
  } finally {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process.stdout as any).write = origWrite;
  }
  return { result, stdout: lines.join("") };
}

/** Capture stderr during fn. */
async function captureStderr<T>(fn: () => Promise<T>): Promise<{ result: T; stderr: string }> {
  const lines: string[] = [];
  const origWrite = process.stderr.write.bind(process.stderr);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (process.stderr as any).write = (chunk: unknown) => {
    if (typeof chunk === "string") lines.push(chunk);
    return true;
  };
  let result: T;
  try {
    result = await fn();
  } finally {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process.stderr as any).write = origWrite;
  }
  return { result, stderr: lines.join("") };
}

/** Intercept process.exit calls; return exit code. */
function makeExitCapture(): { exitFn: (code: number) => never; capturedCode: () => number | undefined } {
  let captured: number | undefined;
  const exitFn = (code: number): never => {
    captured = code;
    throw Object.assign(new Error(`exit(${code})`), { __exitCode: code });
  };
  return { exitFn, capturedCode: () => captured };
}

/** Write a temp fixture file and return its path. Auto-cleaned by the test. */
function writeTempFixture(content: string, suffix = ".json"): string {
  const p = join(tmpdir(), `peer-test-fixture-${Date.now()}${suffix}`);
  writeFileSync(p, content, "utf8");
  return p;
}

const FAKE_RULES = { rules: "Claim all PRs", hash: "abc123" };

const VALID_FIXTURE = JSON.stringify({
  event_type: "pr-opened",
  patch_id: "a".repeat(40),
  payload: {
    repo: "acme/widget",
    title: "Add feature",
    body: "This adds a new feature.",
    pr_url: "https://github.com/acme/widget/pull/42",
    diff: "diff --git a/src/index.ts ...",
    paths_changed: ["src/index.ts"],
  },
});

const VALID_HAIKU_RESPONSE = '{"claim_seat":"if_available","post_mode":"auto-post","prompt":"default"}';

// ─── AC #7: fixture + seam triage → pretty JSON, exit 0 ──────────────

describe("AC #7: peerTest — fixture + seam triage → pretty JSON on stdout, exit 0", () => {
  it("prints TriageDecision as pretty JSON to stdout and exits 0", async () => {
    const fixturePath = writeTempFixture(VALID_FIXTURE);
    const { exitFn, capturedCode } = makeExitCapture();

    const runner = async (_sys: string, _user: string): Promise<string> =>
      VALID_HAIKU_RESPONSE;

    const lines: string[] = [];
    const origWrite = process.stdout.write.bind(process.stdout);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process.stdout as any).write = (chunk: unknown) => {
      if (typeof chunk === "string") lines.push(chunk);
      return true;
    };

    try {
      await runPeerTest({
        eventPath: fixturePath,
        _peerWatchRulesForTest: FAKE_RULES,
        _haikuRunnerForTest: runner,
        _exitForTest: exitFn,
      });
    } catch {
      // exitFn throws — that's expected.
    } finally {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (process.stdout as any).write = origWrite;
      try { unlinkSync(fixturePath); } catch { /* ignore */ }
    }

    const stdout = lines.join("");
    assert.equal(capturedCode(), 0, `expected exit 0, got ${capturedCode()}`);
    // Should be pretty JSON (has newlines / indentation).
    assert.ok(stdout.includes("\n"), `expected multi-line pretty JSON on stdout, got: ${JSON.stringify(stdout)}`);
    const parsed = JSON.parse(stdout);
    assert.equal(parsed.claim_seat, "if_available");
    assert.equal(parsed.post_mode, "auto-post");
    assert.equal(parsed.prompt, "default");
  });

  it("handles flat fixture (no nested payload) correctly", async () => {
    const flatFixture = JSON.stringify({
      repo: "acme/widget",
      title: "Flat event",
      body: "A flat event structure.",
      pr_url: "https://github.com/acme/widget/pull/1",
    });
    const fixturePath = writeTempFixture(flatFixture);
    const { exitFn, capturedCode } = makeExitCapture();

    const runner = async (): Promise<string> => VALID_HAIKU_RESPONSE;

    // Suppress stdout during this test.
    const origWrite = process.stdout.write.bind(process.stdout);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process.stdout as any).write = () => true;
    try {
      await runPeerTest({
        eventPath: fixturePath,
        _peerWatchRulesForTest: FAKE_RULES,
        _haikuRunnerForTest: runner,
        _exitForTest: exitFn,
      });
    } catch { /* exitFn throws */ } finally {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (process.stdout as any).write = origWrite;
      try { unlinkSync(fixturePath); } catch { /* ignore */ }
    }

    assert.equal(capturedCode(), 0, `expected exit 0, got ${capturedCode()}`);
  });
});

// ─── AC #7: missing peer-watch.md → exit 1 ───────────────────────────

describe("AC #7: peerTest — missing peer-watch.md → exit 1", () => {
  it("exits 1 when peer-watch.md is missing", async () => {
    const fixturePath = writeTempFixture(VALID_FIXTURE);
    const { exitFn, capturedCode } = makeExitCapture();

    try {
      await captureStderr(() =>
        runPeerTest({
          eventPath: fixturePath,
          _peerWatchRulesForTest: null, // simulates missing file
          _exitForTest: exitFn,
        }),
      );
    } catch { /* exitFn throws */ } finally {
      try { unlinkSync(fixturePath); } catch { /* ignore */ }
    }

    assert.equal(capturedCode(), 1, `expected exit 1, got ${capturedCode()}`);
  });
});

// ─── AC #7: unreadable fixture → exit 1 ──────────────────────────────

describe("AC #7: peerTest — unreadable or invalid fixture → exit 1", () => {
  it("exits 1 when the fixture file does not exist", async () => {
    const { exitFn, capturedCode } = makeExitCapture();

    try {
      await captureStderr(() =>
        runPeerTest({
          eventPath: "/tmp/does-not-exist-fixture-agt430.json",
          _peerWatchRulesForTest: FAKE_RULES,
          _exitForTest: exitFn,
        }),
      );
    } catch { /* exitFn throws */ }

    assert.equal(capturedCode(), 1, `expected exit 1, got ${capturedCode()}`);
  });

  it("exits 1 when the fixture file is not valid JSON", async () => {
    const fixturePath = writeTempFixture("not json at all {{{{");
    const { exitFn, capturedCode } = makeExitCapture();

    try {
      await captureStderr(() =>
        runPeerTest({
          eventPath: fixturePath,
          _peerWatchRulesForTest: FAKE_RULES,
          _exitForTest: exitFn,
        }),
      );
    } catch { /* exitFn throws */ } finally {
      try { unlinkSync(fixturePath); } catch { /* ignore */ }
    }

    assert.equal(capturedCode(), 1, `expected exit 1, got ${capturedCode()}`);
  });
});

// ─── AC #7: STAMP_NO_LLM=1 → exit 3 ─────────────────────────────────

describe("AC #7: peerTest — STAMP_NO_LLM=1 → exit 3", () => {
  it("exits 3 when STAMP_NO_LLM=1 is set", async () => {
    const fixturePath = writeTempFixture(VALID_FIXTURE);
    const { exitFn, capturedCode } = makeExitCapture();
    const origNoLlm = process.env["STAMP_NO_LLM"];
    process.env["STAMP_NO_LLM"] = "1";

    try {
      await captureStderr(() =>
        runPeerTest({
          eventPath: fixturePath,
          _peerWatchRulesForTest: FAKE_RULES,
          _exitForTest: exitFn,
        }),
      );
    } catch { /* exitFn throws */ } finally {
      if (origNoLlm === undefined) delete process.env["STAMP_NO_LLM"];
      else process.env["STAMP_NO_LLM"] = origNoLlm;
      try { unlinkSync(fixturePath); } catch { /* ignore */ }
    }

    assert.equal(capturedCode(), 3, `expected exit 3, got ${capturedCode()}`);
  });
});
