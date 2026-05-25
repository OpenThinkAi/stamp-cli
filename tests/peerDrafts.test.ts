/**
 * AGT-432 — Unit tests for `stamp peer drafts list|show|delete` (`peerDrafts.ts`).
 *
 * Coverage per AC #8–10:
 *   list:
 *     - missing/empty dir → exit 1
 *     - populated dir → exit 0, reverse-chron order, correct format
 *   show:
 *     - not found → exit 1 with message
 *     - found by exact id → exit 0, content on stdout
 *     - found by unambiguous prefix → exit 0
 *     - ambiguous prefix → exit 1 with list of matches
 *   delete:
 *     - not found → exit 1
 *     - found → exit 0, file deleted
 *     - --all without --yes → exit 1, lists files, no deletion
 *     - --all --yes → exit 0, all deleted
 *     - ambiguous prefix → exit 1
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { mkdirSync, writeFileSync, existsSync, unlinkSync, rmdirSync } from "node:fs";

import { runDraftsList, runDraftsShow, runDraftsDelete } from "../src/commands/peerDrafts.ts";

// ─── Helpers ─────────────────────────────────────────────────────────

function makeExitCapture(): { exitFn: (code: number) => never; capturedCode: () => number | undefined } {
  let captured: number | undefined;
  const exitFn = (code: number): never => {
    captured = code;
    throw Object.assign(new Error(`exit(${code})`), { __exitCode: code });
  };
  return { exitFn, capturedCode: () => captured };
}

function makeDraftsDir(): string {
  const dir = join(tmpdir(), `peer-drafts-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function writeDraft(dir: string, patchId: string, prUrl = "https://github.com/acme/widget/pull/42"): string {
  const path = join(dir, `${patchId}.md`);
  const content = `---\npatch_id: ${patchId}\npr_url: ${prUrl}\nts: 2026-05-24T12:00:00.000Z\n---\n\n# Review body\n\nThis is the review content.`;
  writeFileSync(path, content, "utf8");
  return path;
}

function cleanup(dir: string): void {
  try {
    const files = require("fs").readdirSync(dir);
    for (const f of files) {
      try { unlinkSync(join(dir, f)); } catch { /* ignore */ }
    }
    try { rmdirSync(dir); } catch { /* ignore */ }
  } catch { /* ignore */ }
}

// ─── list: missing dir → exit 1 ──────────────────────────────────────

describe("peerDrafts list: missing dir → exit 1", () => {
  it("exits 1 with 'no drafts found' when dir does not exist", () => {
    const { exitFn, capturedCode } = makeExitCapture();
    const stderrLines: string[] = [];

    try {
      runDraftsList({
        _dirForTest: "/tmp/definitely-not-a-real-drafts-dir-agt432",
        _exitForTest: exitFn,
        _stderrWriteForTest: (s) => { stderrLines.push(s); },
      });
    } catch { /* exitFn throws */ }

    assert.equal(capturedCode(), 1, `expected exit 1, got ${capturedCode()}`);
    assert.ok(
      stderrLines.join("").includes("no drafts found"),
      `expected 'no drafts found', got: ${stderrLines.join("")}`,
    );
  });

  it("exits 1 with 'no drafts found' when dir is empty", () => {
    const dir = makeDraftsDir();
    const { exitFn, capturedCode } = makeExitCapture();
    const stderrLines: string[] = [];

    try {
      runDraftsList({
        _dirForTest: dir,
        _exitForTest: exitFn,
        _stderrWriteForTest: (s) => { stderrLines.push(s); },
      });
    } catch { /* exitFn throws */ } finally {
      cleanup(dir);
    }

    assert.equal(capturedCode(), 1, `expected exit 1, got ${capturedCode()}`);
  });
});

// ─── list: populated dir → exit 0 ────────────────────────────────────

describe("peerDrafts list: populated dir → exit 0, correct format", () => {
  it("lists drafts with patchId, age, and PR title", () => {
    const dir = makeDraftsDir();
    const patchId = "a".repeat(40);
    writeDraft(dir, patchId);

    const { exitFn, capturedCode } = makeExitCapture();
    const stdoutLines: string[] = [];

    try {
      runDraftsList({
        _dirForTest: dir,
        _exitForTest: exitFn,
        _stdoutWriteForTest: (s) => { stdoutLines.push(s); },
        _stderrWriteForTest: () => {},
      });
    } catch { /* exitFn throws */ } finally {
      cleanup(dir);
    }

    assert.equal(capturedCode(), 0, `expected exit 0, got ${capturedCode()}`);
    const out = stdoutLines.join("");
    assert.ok(out.includes(patchId), `expected patchId in output: ${out}`);
    // PR title extracted from pr_url → "PR #42"
    assert.ok(out.includes("PR #42"), `expected 'PR #42' in output: ${out}`);
  });

  it("lists multiple drafts in output", () => {
    const dir = makeDraftsDir();
    const id1 = "1".repeat(40);
    const id2 = "2".repeat(40);
    writeDraft(dir, id1, "https://github.com/acme/widget/pull/1");
    writeDraft(dir, id2, "https://github.com/acme/widget/pull/2");

    const { exitFn, capturedCode } = makeExitCapture();
    const stdoutLines: string[] = [];

    try {
      runDraftsList({
        _dirForTest: dir,
        _exitForTest: exitFn,
        _stdoutWriteForTest: (s) => { stdoutLines.push(s); },
        _stderrWriteForTest: () => {},
      });
    } catch { /* exitFn throws */ } finally {
      cleanup(dir);
    }

    assert.equal(capturedCode(), 0, `expected exit 0, got ${capturedCode()}`);
    const out = stdoutLines.join("");
    assert.ok(out.includes(id1), `expected id1 in output: ${out}`);
    assert.ok(out.includes(id2), `expected id2 in output: ${out}`);
  });
});

// ─── show: not found → exit 1 ────────────────────────────────────────

describe("peerDrafts show: not found → exit 1", () => {
  it("exits 1 with 'draft not found' when patch-id does not exist", () => {
    const dir = makeDraftsDir();
    const { exitFn, capturedCode } = makeExitCapture();
    const stderrLines: string[] = [];

    try {
      runDraftsShow({
        patchId: "nonexistent",
        _dirForTest: dir,
        _exitForTest: exitFn,
        _stderrWriteForTest: (s) => { stderrLines.push(s); },
      });
    } catch { /* exitFn throws */ } finally {
      cleanup(dir);
    }

    assert.equal(capturedCode(), 1, `expected exit 1, got ${capturedCode()}`);
    assert.ok(
      stderrLines.join("").includes("draft not found"),
      `expected 'draft not found', got: ${stderrLines.join("")}`,
    );
  });
});

// ─── show: exact match → exit 0, content on stdout ───────────────────

describe("peerDrafts show: exact match → exit 0", () => {
  it("shows draft content to stdout", () => {
    const dir = makeDraftsDir();
    const patchId = "b".repeat(40);
    writeDraft(dir, patchId);

    const { exitFn, capturedCode } = makeExitCapture();
    const stdoutLines: string[] = [];

    try {
      runDraftsShow({
        patchId,
        _dirForTest: dir,
        _exitForTest: exitFn,
        _stdoutWriteForTest: (s) => { stdoutLines.push(s); },
        _stderrWriteForTest: () => {},
      });
    } catch { /* exitFn throws */ } finally {
      cleanup(dir);
    }

    assert.equal(capturedCode(), 0, `expected exit 0, got ${capturedCode()}`);
    const out = stdoutLines.join("");
    assert.ok(out.includes("Review body"), `expected review body content in stdout: ${out}`);
    assert.ok(out.includes(patchId), `expected patch_id in stdout: ${out}`);
  });
});

// ─── show: unambiguous prefix → exit 0 ───────────────────────────────

describe("peerDrafts show: unambiguous prefix → exit 0", () => {
  it("resolves draft by prefix", () => {
    const dir = makeDraftsDir();
    const patchId = "deadbeef" + "0".repeat(32);
    writeDraft(dir, patchId);

    const { exitFn, capturedCode } = makeExitCapture();
    const stdoutLines: string[] = [];

    try {
      runDraftsShow({
        patchId: "deadbeef",   // prefix
        _dirForTest: dir,
        _exitForTest: exitFn,
        _stdoutWriteForTest: (s) => { stdoutLines.push(s); },
        _stderrWriteForTest: () => {},
      });
    } catch { /* exitFn throws */ } finally {
      cleanup(dir);
    }

    assert.equal(capturedCode(), 0, `expected exit 0 for unambiguous prefix, got ${capturedCode()}`);
    const out = stdoutLines.join("");
    assert.ok(out.length > 0, "expected non-empty output");
  });
});

// ─── show: ambiguous prefix → exit 1 ────────────────────────────────

describe("peerDrafts show: ambiguous prefix → exit 1", () => {
  it("exits 1 and lists matches on ambiguous prefix", () => {
    const dir = makeDraftsDir();
    const id1 = "abcdef1234" + "0".repeat(30);
    const id2 = "abcdef5678" + "0".repeat(30);
    writeDraft(dir, id1);
    writeDraft(dir, id2);

    const { exitFn, capturedCode } = makeExitCapture();
    const stderrLines: string[] = [];

    try {
      runDraftsShow({
        patchId: "abcdef",   // ambiguous — matches both
        _dirForTest: dir,
        _exitForTest: exitFn,
        _stdoutWriteForTest: () => {},
        _stderrWriteForTest: (s) => { stderrLines.push(s); },
      });
    } catch { /* exitFn throws */ } finally {
      cleanup(dir);
    }

    assert.equal(capturedCode(), 1, `expected exit 1 for ambiguous prefix, got ${capturedCode()}`);
    const err = stderrLines.join("");
    assert.ok(
      err.includes("ambiguous"),
      `expected 'ambiguous' in stderr: ${err}`,
    );
    assert.ok(err.includes(id1), `expected id1 in ambiguity list: ${err}`);
    assert.ok(err.includes(id2), `expected id2 in ambiguity list: ${err}`);
  });
});

// ─── delete: not found → exit 1 ──────────────────────────────────────

describe("peerDrafts delete: not found → exit 1", () => {
  it("exits 1 when patch-id does not exist", () => {
    const dir = makeDraftsDir();
    const { exitFn, capturedCode } = makeExitCapture();
    const stderrLines: string[] = [];

    try {
      runDraftsDelete({
        patchId: "nonexistent",
        _dirForTest: dir,
        _exitForTest: exitFn,
        _stderrWriteForTest: (s) => { stderrLines.push(s); },
      });
    } catch { /* exitFn throws */ } finally {
      cleanup(dir);
    }

    assert.equal(capturedCode(), 1, `expected exit 1, got ${capturedCode()}`);
    assert.ok(
      stderrLines.join("").includes("draft not found"),
      `expected 'draft not found', got: ${stderrLines.join("")}`,
    );
  });
});

// ─── delete: found → exit 0, file deleted ────────────────────────────

describe("peerDrafts delete: found → exit 0, file deleted", () => {
  it("deletes the draft and exits 0", () => {
    const dir = makeDraftsDir();
    const patchId = "c".repeat(40);
    const filePath = writeDraft(dir, patchId);

    const { exitFn, capturedCode } = makeExitCapture();
    const stdoutLines: string[] = [];

    try {
      runDraftsDelete({
        patchId,
        _dirForTest: dir,
        _exitForTest: exitFn,
        _stdoutWriteForTest: (s) => { stdoutLines.push(s); },
        _stderrWriteForTest: () => {},
      });
    } catch { /* exitFn throws */ } finally {
      cleanup(dir);
    }

    assert.equal(capturedCode(), 0, `expected exit 0, got ${capturedCode()}`);
    assert.ok(!existsSync(filePath), "draft file should have been deleted");
    assert.ok(stdoutLines.join("").includes(patchId), `expected patchId in stdout: ${stdoutLines.join("")}`);
  });
});

// ─── delete: --all without --yes → exit 1, no deletion ───────────────

describe("peerDrafts delete --all without --yes → exit 1, no deletion", () => {
  it("exits 1 and lists files that would be deleted, does NOT delete them", () => {
    const dir = makeDraftsDir();
    const patchId = "d".repeat(40);
    const filePath = writeDraft(dir, patchId);

    const { exitFn, capturedCode } = makeExitCapture();
    const stderrLines: string[] = [];

    try {
      runDraftsDelete({
        all: true,
        // yes: false (omitted)
        _dirForTest: dir,
        _exitForTest: exitFn,
        _stderrWriteForTest: (s) => { stderrLines.push(s); },
      });
    } catch { /* exitFn throws */ } finally {
      cleanup(dir);
    }

    assert.equal(capturedCode(), 1, `expected exit 1, got ${capturedCode()}`);
    assert.ok(existsSync(filePath), "draft file should NOT have been deleted without --yes");
    const err = stderrLines.join("");
    assert.ok(
      err.includes("--yes") || err.includes("re-run"),
      `expected --yes prompt in stderr: ${err}`,
    );
  });
});

// ─── delete: --all --yes → exit 0, all deleted ───────────────────────

describe("peerDrafts delete --all --yes → exit 0, all deleted", () => {
  it("deletes all drafts and exits 0", () => {
    const dir = makeDraftsDir();
    const id1 = "e".repeat(40);
    const id2 = "f".repeat(40);
    const path1 = writeDraft(dir, id1);
    const path2 = writeDraft(dir, id2);

    const { exitFn, capturedCode } = makeExitCapture();
    const stdoutLines: string[] = [];

    try {
      runDraftsDelete({
        all: true,
        yes: true,
        _dirForTest: dir,
        _exitForTest: exitFn,
        _stdoutWriteForTest: (s) => { stdoutLines.push(s); },
        _stderrWriteForTest: () => {},
      });
    } catch { /* exitFn throws */ } finally {
      cleanup(dir);
    }

    assert.equal(capturedCode(), 0, `expected exit 0, got ${capturedCode()}`);
    assert.ok(!existsSync(path1), "draft 1 should be deleted");
    assert.ok(!existsSync(path2), "draft 2 should be deleted");
  });

  it("exits 1 when dir is empty (nothing to delete)", () => {
    const dir = makeDraftsDir();
    const { exitFn, capturedCode } = makeExitCapture();

    try {
      runDraftsDelete({
        all: true,
        yes: true,
        _dirForTest: dir,
        _exitForTest: exitFn,
        _stderrWriteForTest: () => {},
      });
    } catch { /* exitFn throws */ } finally {
      cleanup(dir);
    }

    assert.equal(capturedCode(), 1, `expected exit 1 for empty dir, got ${capturedCode()}`);
  });
});
