/**
 * Unit tests for `peer-watch.log` size-based rotation (OpenThinkAi/stamp-cli#47).
 *
 * `appendTriplet` must keep the operator log bounded: once it reaches the
 * configured cap, rotate `peer-watch.log` → `.1` → `.2` → `.3` (dropping the
 * oldest) before the next append, so a stuck/hot listener loop can't exhaust
 * disk. Rotation is best-effort and must never throw.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  existsSync,
  statSync,
  readFileSync,
  writeFileSync,
} from "node:fs";

import { appendTriplet, type AppendTripletInput } from "../src/lib/peerWatchLog.ts";

// ─── Helpers ─────────────────────────────────────────────────────────

function makeTmpDir(): string {
  return mkdtempSync(join(tmpdir(), "peer-watch-rotate-"));
}

function baseRecord(logPath: string, overrides: Partial<AppendTripletInput> = {}): AppendTripletInput {
  return {
    ts: "2026-06-06T00:00:00.000Z",
    repo: "acme/widget",
    pr_url: "https://github.com/acme/widget/pull/42",
    rules_hash: "abc123",
    event_payload: {},
    decision: { claim_seat: "if_available", post_mode: "auto-post", prompt: "default" },
    _logPathForTest: logPath,
    ...overrides,
  };
}

// ─── No rotation under the cap ───────────────────────────────────────

describe("appendTriplet: appends without rotating when under the cap", () => {
  it("keeps a single log file and no archives", () => {
    const dir = makeTmpDir();
    const logPath = join(dir, "peer-watch.log");
    try {
      appendTriplet(baseRecord(logPath, { _maxBytesForTest: 1024 * 1024 }));
      appendTriplet(baseRecord(logPath, { _maxBytesForTest: 1024 * 1024 }));

      assert.ok(existsSync(logPath), "live log should exist");
      assert.ok(!existsSync(`${logPath}.1`), "no archive expected under cap");
      const lines = readFileSync(logPath, "utf8").trim().split("\n");
      assert.equal(lines.length, 2, "both records should be in the live log");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ─── Rotation at the cap ─────────────────────────────────────────────

describe("appendTriplet: rotates when the log reaches the cap", () => {
  it("moves the live log to .1 and starts a fresh log", () => {
    const dir = makeTmpDir();
    const logPath = join(dir, "peer-watch.log");
    try {
      // Pre-seed the live log so it's already at/over a tiny cap.
      writeFileSync(logPath, "x".repeat(200), "utf8");

      // Next append should rotate first, then write a single fresh record.
      appendTriplet(baseRecord(logPath, { _maxBytesForTest: 100 }));

      assert.ok(existsSync(`${logPath}.1`), "archive .1 should exist after rotation");
      assert.equal(statSync(`${logPath}.1`).size, 200, ".1 should hold the pre-rotation bytes");

      const liveLines = readFileSync(logPath, "utf8").trim().split("\n");
      assert.equal(liveLines.length, 1, "live log should hold only the new record");
      assert.equal(JSON.parse(liveLines[0]).repo, "acme/widget");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("keeps at most KEEP archives, dropping the oldest", () => {
    const dir = makeTmpDir();
    const logPath = join(dir, "peer-watch.log");
    try {
      // Force a rotation on every append by using a 1-byte cap. Tag each
      // record so we can trace which generation landed where.
      for (let i = 1; i <= 5; i++) {
        appendTriplet(baseRecord(logPath, { _maxBytesForTest: 1, rules_hash: `gen-${i}` }));
      }

      // After 5 forced rotations we keep .1/.2/.3 plus the live log; .4 must not exist.
      assert.ok(existsSync(logPath), "live log present");
      assert.ok(existsSync(`${logPath}.1`), ".1 present");
      assert.ok(existsSync(`${logPath}.2`), ".2 present");
      assert.ok(existsSync(`${logPath}.3`), ".3 present");
      assert.ok(!existsSync(`${logPath}.4`), ".4 must be dropped (KEEP=3)");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ─── Crash-safety ────────────────────────────────────────────────────

describe("appendTriplet: rotation never throws", () => {
  it("does not throw when the parent dir is created on demand", () => {
    const dir = makeTmpDir();
    const logPath = join(dir, "nested", "deep", "peer-watch.log");
    try {
      assert.doesNotThrow(() => {
        appendTriplet(baseRecord(logPath, { _maxBytesForTest: 100 }));
      });
      assert.ok(existsSync(logPath), "log written under freshly created dirs");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
