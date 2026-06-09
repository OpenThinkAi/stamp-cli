/**
 * Unit tests for the per-repo merge lock (AGT-474).
 *
 * Covers:
 *  - basic acquire/release round-trip writes + removes the lockfile
 *  - second acquire against a live lock throws "another stamp merge is in progress"
 *  - stale lock (dead PID) is reaped and acquire succeeds
 *  - stale lock (age past staleSec) is reaped
 *  - cross-host lock is treated as stale (host mismatch)
 *  - release is idempotent (double-release is a no-op, not a throw)
 *
 * The lock module's only external surface is the gitCommonDir() path
 * helper; we scaffold a real `.git` dir in a temp tree so `gitCommonDir`
 * resolves correctly without needing a full `git init`.
 */

import { strict as assert } from "node:assert";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { acquireMergeLock, mergeLockPath } from "../src/lib/mergeLock.ts";

/**
 * Build a minimal "repo root" with a `.git` directory present so
 * `gitCommonDir(repoRoot)` returns `<repoRoot>/.git` (the directory case).
 * No git ref machinery is needed — the lock only uses gitCommonDir for
 * path resolution.
 */
function setupRepo(): { repo: string; cleanup: () => void } {
  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-merge-lock-"));
  mkdirSync(path.join(root, ".git"), { recursive: true });
  return {
    repo: root,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

describe("mergeLock (AGT-474)", () => {
  it("acquire then release writes the lockfile and removes it on release", () => {
    const h = setupRepo();
    try {
      const lockPath = mergeLockPath(h.repo);
      assert.equal(
        existsSync(lockPath),
        false,
        "lockfile should not exist before acquire",
      );
      const lock = acquireMergeLock(h.repo);
      try {
        assert.equal(
          existsSync(lockPath),
          true,
          "lockfile should exist after acquire",
        );
        const rec = JSON.parse(readFileSync(lockPath, "utf8"));
        assert.equal(rec.pid, process.pid);
        assert.equal(typeof rec.host, "string");
        assert.ok(rec.host.length > 0);
        assert.equal(typeof rec.startedAt, "number");
      } finally {
        lock.release();
      }
      assert.equal(
        existsSync(lockPath),
        false,
        "lockfile should be removed after release",
      );
    } finally {
      h.cleanup();
    }
  });

  it("second acquire against a live lock throws 'another stamp merge is in progress'", () => {
    const h = setupRepo();
    try {
      const lock = acquireMergeLock(h.repo);
      try {
        assert.throws(
          () => acquireMergeLock(h.repo),
          (err: unknown) => {
            const msg = err instanceof Error ? err.message : String(err);
            assert.match(msg, /another stamp merge is in progress/i);
            return true;
          },
        );
      } finally {
        lock.release();
      }
    } finally {
      h.cleanup();
    }
  });

  it("stale lock (dead PID, same host) is reaped on next acquire", () => {
    const h = setupRepo();
    try {
      const lockPath = mergeLockPath(h.repo);
      mkdirSync(path.dirname(lockPath), { recursive: true });
      // Pick a pid that should not exist on the host. 999999 is well beyond
      // typical pid_max on darwin/linux defaults; if it happens to exist
      // the test will false-fail, which is acceptable — re-run.
      writeFileSync(
        lockPath,
        JSON.stringify({
          pid: 999999,
          host: os.hostname(),
          startedAt: Date.now(),
          cmd: "stale stamp merge (synthetic)",
        }),
      );

      const lock = acquireMergeLock(h.repo);
      try {
        const rec = JSON.parse(readFileSync(lockPath, "utf8"));
        assert.equal(
          rec.pid,
          process.pid,
          "stale lock should have been replaced with this process's record",
        );
      } finally {
        lock.release();
      }
    } finally {
      h.cleanup();
    }
  });

  it("stale lock (age past staleSec) is reaped even if PID is somehow alive", () => {
    const h = setupRepo();
    try {
      const lockPath = mergeLockPath(h.repo);
      mkdirSync(path.dirname(lockPath), { recursive: true });
      // Write a lock claiming to be held by THIS process (so the pid is
      // definitely alive), but with a startedAt timestamp far in the past.
      // The age check should declare it stale before the PID check matters.
      writeFileSync(
        lockPath,
        JSON.stringify({
          pid: process.pid,
          host: os.hostname(),
          startedAt: Date.now() - 24 * 60 * 60 * 1000, // 24h ago
          cmd: "ancient",
        }),
      );

      // Set a tight stale window so the age check fires.
      const lock = acquireMergeLock(h.repo, { staleSec: 5 });
      try {
        const rec = JSON.parse(readFileSync(lockPath, "utf8"));
        assert.equal(rec.cmd, "stamp merge");
      } finally {
        lock.release();
      }
    } finally {
      h.cleanup();
    }
  });

  it("cross-host lock is treated as stale (no cross-host coordination per AC#5)", () => {
    const h = setupRepo();
    try {
      const lockPath = mergeLockPath(h.repo);
      mkdirSync(path.dirname(lockPath), { recursive: true });
      writeFileSync(
        lockPath,
        JSON.stringify({
          pid: process.pid,
          host: "definitely-not-this-host.invalid",
          startedAt: Date.now(),
          cmd: "stamp merge",
        }),
      );

      const lock = acquireMergeLock(h.repo);
      try {
        const rec = JSON.parse(readFileSync(lockPath, "utf8"));
        assert.equal(rec.host, os.hostname());
      } finally {
        lock.release();
      }
    } finally {
      h.cleanup();
    }
  });

  it("release is idempotent — double-release does not throw", () => {
    const h = setupRepo();
    try {
      const lock = acquireMergeLock(h.repo);
      lock.release();
      // Second release must be a no-op, not a throw.
      lock.release();
    } finally {
      h.cleanup();
    }
  });

  it("malformed lockfile is treated as stale", () => {
    const h = setupRepo();
    try {
      const lockPath = mergeLockPath(h.repo);
      mkdirSync(path.dirname(lockPath), { recursive: true });
      writeFileSync(lockPath, "this is not json");
      const lock = acquireMergeLock(h.repo);
      try {
        const rec = JSON.parse(readFileSync(lockPath, "utf8"));
        assert.equal(rec.pid, process.pid);
      } finally {
        lock.release();
      }
    } finally {
      h.cleanup();
    }
  });
});
