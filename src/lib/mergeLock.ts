/**
 * Exclusive file lock for `stamp merge` to prevent concurrent invocations
 * in the same checkout from racing on the post-merge `git commit --amend`
 * window (AGT-474, GH#31).
 *
 * The race: agent A's `git merge --no-ff` moves HEAD to A's merge commit;
 * required_checks run for ~2-3 min; agent B's `git merge --no-ff` advances
 * HEAD to B's merge during that window; A's checks complete and A's
 * `git commit --amend` rewrites B's merge with A's trailers — producing a
 * commit whose `Stamp-Payload.head_sha` doesn't match its actual second
 * parent. Server pre-receive correctly rejects, but the bad commit blocks
 * all subsequent pushes until manually unwound.
 *
 * This lock makes the same-checkout case safe by serializing `stamp merge`
 * runs against the SAME git common dir (so worktrees of one clone share
 * one lock; distinct clones — which can't race the same ref anyway — don't
 * coordinate). Per ticket AC#5 the lock is intentionally local-checkout-
 * scoped: no cross-host coordination.
 *
 * Stale-lock handling: the lockfile carries `{pid, host, startedAt, cmd}`.
 * An EEXIST on acquire triggers a stale check, evaluated in this order:
 *   - file is older than `STAMP_MERGE_LOCK_STALE_SEC` (default 600s) → stale
 *     (NOTE: this fires regardless of PID liveness — a healthy-but-slow
 *     merge that exceeds the window will have its lock stolen by a
 *     concurrent invocation. Default 10 min is generous for any sane
 *     merge; raise via env if your `required_checks` are slower),
 *   - if `host` differs from this host → stale (host-A's lock is opaque to
 *     us; we treat it as abandoned rather than wait indefinitely),
 *   - if `pid` is not alive on this host → stale.
 * A stale lock is unlinked and acquire retried, up to MAX_RETRIES times.
 *
 * Not used: external libs (`proper-lockfile`, `lockfile`). Self-contained
 * O_EXCL + PID file keeps the runtime dep tree tight — this is ~80 LOC.
 */

import {
  closeSync,
  mkdirSync,
  openSync,
  readFileSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { hostname } from "node:os";
import { dirname, join } from "node:path";

import { gitCommonDir } from "./paths.js";

const DEFAULT_STALE_SEC = 600;
const MAX_RETRIES = 3;

export interface MergeLockOptions {
  /** Override the stale-lock age threshold (test seam). */
  staleSec?: number;
  /** Tag in the lock file's `cmd` field (test/diagnostic). */
  cmdTag?: string;
}

export interface MergeLock {
  /** Absolute path to the lock file. */
  readonly path: string;
  /**
   * Release the lock. Safe to call multiple times; subsequent releases are
   * no-ops. Idempotent so callers can wire it into both a `finally` block
   * and a signal handler without double-unlink errors.
   */
  release: () => void;
}

interface LockRecord {
  pid: number;
  host: string;
  startedAt: number;
  cmd: string;
}

export function mergeLockPath(repoRoot: string): string {
  return join(gitCommonDir(repoRoot), "stamp", "merge.lock");
}

/**
 * Acquire the per-repo exclusive merge lock. Throws an Error with a
 * user-facing message starting with "another stamp merge is in progress"
 * if a live, current lock is held by another invocation.
 */
export function acquireMergeLock(
  repoRoot: string,
  opts: MergeLockOptions = {},
): MergeLock {
  const lockPath = mergeLockPath(repoRoot);
  const staleSec =
    opts.staleSec ??
    Number(process.env["STAMP_MERGE_LOCK_STALE_SEC"] ?? DEFAULT_STALE_SEC);
  const record: LockRecord = {
    pid: process.pid,
    host: hostname(),
    startedAt: Date.now(),
    cmd: opts.cmdTag ?? "stamp merge",
  };

  mkdirSync(dirname(lockPath), { recursive: true });

  let lastErr: Error | undefined;
  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    try {
      // O_CREAT | O_EXCL — atomically creates or fails with EEXIST.
      const fd = openSync(lockPath, "wx");
      try {
        writeFileSync(fd, JSON.stringify(record));
      } finally {
        closeSync(fd);
      }
      return makeLock(lockPath);
    } catch (err) {
      const e = err as NodeJS.ErrnoException;
      if (e.code !== "EEXIST") {
        // Disk error, permission, etc. — propagate as-is; no stale logic
        // can fix it. Wrap with context so the operator knows where to look.
        throw new Error(
          `failed to acquire stamp merge lock at ${lockPath}: ${e.message}`,
        );
      }

      // EEXIST — investigate.
      const stale = isStale(lockPath, staleSec);
      if (!stale.stale) {
        throw new Error(
          `another stamp merge is in progress (pid ${stale.holder.pid} on ${stale.holder.host}, started ${describeAge(stale.holder.startedAt)}). ` +
            `Lockfile: ${lockPath}. ` +
            `If you're certain the prior process is dead, delete the lockfile and retry.`,
        );
      }

      // Stale — best-effort unlink and retry. A second process unlinking the
      // same stale lock at the same instant is fine: ENOENT means someone
      // else already cleared it, so we proceed to the next attempt and
      // re-race on openSync('wx').
      try {
        unlinkSync(lockPath);
      } catch (unlinkErr) {
        const ue = unlinkErr as NodeJS.ErrnoException;
        if (ue.code !== "ENOENT") {
          lastErr = new Error(
            `stale stamp merge lock at ${lockPath} could not be removed: ${ue.message}. Remove it manually and retry.`,
          );
          break;
        }
      }
      // loop and retry openSync
    }
  }

  throw (
    lastErr ??
    new Error(
      `failed to acquire stamp merge lock at ${lockPath} after ${MAX_RETRIES} attempts (lock contention). ` +
        `Try again, or delete the lockfile manually if no \`stamp merge\` is running.`,
    )
  );
}

function makeLock(lockPath: string): MergeLock {
  let released = false;
  return {
    path: lockPath,
    release: () => {
      if (released) return;
      released = true;
      try {
        unlinkSync(lockPath);
      } catch (err) {
        const e = err as NodeJS.ErrnoException;
        // ENOENT means the lock was already gone — fine, idempotent.
        // Any other error: surface as a warning on stderr but do NOT throw
        // (we're typically called from a `finally`; throwing would mask
        // the original error).
        if (e.code !== "ENOENT") {
          console.error(
            `warning: failed to release stamp merge lock at ${lockPath}: ${e.message}`,
          );
        }
      }
    },
  };
}

interface StaleResult {
  stale: boolean;
  holder: LockRecord;
}

function isStale(lockPath: string, staleSec: number): StaleResult {
  // Default-stale fallback: if we can't read or parse the lock, treat it
  // as stale rather than jamming the operator behind an opaque file.
  // The acquire loop will unlink and retry; if the file is actually
  // legitimate the next attempt will just race against the live holder
  // who will then re-create it (in which case we throw the proper "in
  // progress" diagnostic — no false success).
  let raw: string;
  try {
    raw = readFileSync(lockPath, "utf8");
  } catch {
    return {
      stale: true,
      holder: defaultHolder(),
    };
  }

  let rec: LockRecord;
  try {
    const parsed = JSON.parse(raw) as Partial<LockRecord>;
    if (
      typeof parsed.pid !== "number" ||
      typeof parsed.host !== "string" ||
      typeof parsed.startedAt !== "number"
    ) {
      return { stale: true, holder: defaultHolder() };
    }
    rec = {
      pid: parsed.pid,
      host: parsed.host,
      startedAt: parsed.startedAt,
      cmd: parsed.cmd ?? "stamp merge",
    };
  } catch {
    return { stale: true, holder: defaultHolder() };
  }

  // Age-based staleness — covers SIGKILL, OOM, hung-but-not-blocking cases
  // where the holder's mtime hasn't advanced past the staleSec window.
  // Use mtime via stat as a secondary clock so a forward-clock-skewed
  // startedAt doesn't accidentally extend the lifetime indefinitely; take
  // the older of the two timestamps as "when this lock effectively began."
  let mtimeMs = rec.startedAt;
  try {
    const st = statSync(lockPath);
    mtimeMs = st.mtimeMs;
  } catch {
    // ignore — fall back to the embedded startedAt
  }
  const effectiveStart = Math.min(rec.startedAt, mtimeMs);
  const ageSec = (Date.now() - effectiveStart) / 1000;
  if (ageSec > staleSec) {
    return { stale: true, holder: rec };
  }

  // Host-scoped PID check. A lock owned by a different host is opaque to
  // us (we can't `kill -0` someone else's pid), so treat as stale per
  // AC#5 — local-checkout-scoped only, no cross-host coordination.
  if (rec.host !== hostname()) {
    return { stale: true, holder: rec };
  }

  // PID liveness: `kill -0` succeeds for live targets, throws ESRCH for
  // dead ones, EPERM if the pid is alive but owned by another user (rare
  // but treat as live — defensive).
  try {
    process.kill(rec.pid, 0);
    return { stale: false, holder: rec };
  } catch (err) {
    const e = err as NodeJS.ErrnoException;
    if (e.code === "EPERM") return { stale: false, holder: rec };
    // ESRCH or any other → dead.
    return { stale: true, holder: rec };
  }
}

function defaultHolder(): LockRecord {
  return {
    pid: -1,
    host: "unknown",
    startedAt: 0,
    cmd: "unknown",
  };
}

function describeAge(startedAt: number): string {
  if (!startedAt) return "at unknown time";
  const sec = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m${sec % 60}s ago`;
  const hr = Math.floor(min / 60);
  return `${hr}h${min % 60}m ago`;
}
