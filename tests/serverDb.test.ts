/**
 * Membership sqlite unit tests. Covers:
 *   - schema init via openServerDb (idempotent CREATE TABLE IF NOT EXISTS)
 *   - INSERT / SELECT round-trip on the users table
 *   - upsertUserByFingerprint idempotency (the env-sync path runs every boot)
 *   - findUserBySshFingerprint — the load-bearing read path for the
 *     AuthorizedKeysCommand resolver
 *   - CHECK-constraint rejection on bad role / source values
 *   - suggestUniqueShortName collision-avoidance numbering
 *   - read-only open mode: read-side works, writes throw
 *   - parent-dir mode is wide enough that sqlite can create its
 *     `-journal` sidecar (regression: 0o750 silently demoted writes
 *     to "attempt to write a readonly database")
 *
 * Cross-user filesystem perms (root:git ownership) are NOT exercised
 * here — they require running as root with the `git` group available,
 * which the test harness isn't. Those are validated end-to-end by the
 * Docker image tests instead.
 */

import { strict as assert } from "node:assert";
import { chmodSync, mkdtempSync, rmSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, before, after } from "node:test";

import {
  appendEvent,
  checkAndConsumeToken,
  claimSeatTx,
  countByRole,
  findCachedServerVerdict,
  findPatch,
  findUserBySshFingerprint,
  findUserByShortName,
  insertPatch,
  insertUser,
  listUsers,
  openServerDb,
  recordServerVerdict,
  releaseSeat,
  resolveReviewRateCap,
  suggestUniqueShortName,
  touchHeartbeat,
  upsertUserByFingerprint,
} from "../src/lib/serverDb.ts";

function tmpDbPath(): { path: string; cleanup: () => void } {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-serverdb-"));
  return {
    path: path.join(dir, "users.db"),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

const fixturePk = (n: number) => ({
  short_name: `user-${n}`,
  ssh_pubkey: `ssh-ed25519 AAAAfake${n} user-${n}@example`,
  ssh_fp: `SHA256:fake-fingerprint-${n}`,
  role: "admin" as const,
  source: "env" as const,
});

describe("openServerDb", () => {
  it("creates schema on first open and is idempotent across reopens", () => {
    const t = tmpDbPath();
    try {
      const db1 = openServerDb({ path: t.path, skipChmod: true });
      insertUser(db1, fixturePk(1));
      db1.close();

      // Second open should see the row and not throw on re-running CREATE
      // TABLE IF NOT EXISTS.
      const db2 = openServerDb({ path: t.path, skipChmod: true });
      const rows = listUsers(db2);
      assert.equal(rows.length, 1);
      assert.equal(rows[0]?.short_name, "user-1");
      db2.close();
    } finally {
      t.cleanup();
    }
  });

  it("opens read-only and refuses writes", () => {
    const t = tmpDbPath();
    try {
      // Initialize the DB first (schema requires a writable open).
      const writer = openServerDb({ path: t.path, skipChmod: true });
      insertUser(writer, fixturePk(1));
      writer.close();

      const reader = openServerDb({ path: t.path, readOnly: true });
      // Reads work.
      const user = findUserBySshFingerprint(reader, fixturePk(1).ssh_fp);
      assert.equal(user?.short_name, "user-1");
      // Writes throw.
      assert.throws(() => insertUser(reader, fixturePk(2)));
      reader.close();
    } finally {
      t.cleanup();
    }
  });

  it("sets parent dir to 0o1770 — sticky+0o770 (0o750 silently demotes writes)", () => {
    // Pinned regression: phase 1 set the dir to 0o750. The git user
    // (HTTP server, mint-invite, users-cli) couldn't create sqlite's
    // -journal sidecar in that dir, so every UPDATE threw "attempt to
    // write a readonly database". Found end-to-end by `stamp users
    // promote` blowing up the first time it was tried in production.
    //
    // 0o1770 = sticky bit + rwxrwx---. The 0o770 portion gives the
    // git-group process file-create access (sqlite -journal); the
    // sticky bit protects future root-owned files in this dir from
    // being touched by group-writable processes. Mask 0o7777 to
    // preserve sticky in the assertion — masking only 0o777 would
    // silently allow a regression that drops the sticky bit.
    const t = tmpDbPath();
    try {
      openServerDb({ path: t.path }).close();
      const dirMode = statSync(path.dirname(t.path)).mode & 0o7777;
      assert.equal(
        dirMode,
        0o1770,
        `parent dir should be 0o1770 (sticky + 0o770) to allow sqlite -journal creation while protecting root-owned files, got 0o${dirMode.toString(8)}`,
      );
    } finally {
      t.cleanup();
    }
  });

  it("can write through a connection when the dir is 0o770 (positive control)", () => {
    // Counterpart to the regression test above: prove that the dir
    // mode openServerDb chose actually sustains a write transaction.
    // If sqlite ever changed its journal-creation contract (e.g. went
    // to WAL by default and demanded different perms), this would be
    // the canary.
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path });
      try {
        // Force a write that requires journal creation.
        insertUser(db, fixturePk(1));
        db.prepare("UPDATE users SET role = 'member' WHERE short_name = ?").run(
          "user-1",
        );
      } finally {
        db.close();
      }
    } finally {
      t.cleanup();
    }
  });

  it("a 0o500 parent dir reproduces the original 'readonly' failure mode", () => {
    // Direct reproduction of the production bug, in-process: when the
    // parent dir doesn't allow the test user to create new files,
    // sqlite refuses writes on subsequent connections. Pins the
    // failure mode so a future regression in openServerDb that
    // accidentally narrows the dir mode produces a recognizable
    // exception, not a silent demotion.
    const t = tmpDbPath();
    try {
      // Create + populate the DB while the dir is still writable.
      const db1 = openServerDb({ path: t.path });
      insertUser(db1, fixturePk(1));
      db1.close();

      // Lock down the dir so the test process can no longer create
      // files in it (mimics the git user against a 0o750 root:git dir).
      chmodSync(path.dirname(t.path), 0o500);

      try {
        const db2 = openServerDb({ path: t.path, skipChmod: true });
        try {
          assert.throws(
            () =>
              db2
                .prepare("UPDATE users SET role = 'member' WHERE short_name = ?")
                .run("user-1"),
            /readonly/,
          );
        } finally {
          db2.close();
        }
      } finally {
        // Restore so cleanup can rm.
        chmodSync(path.dirname(t.path), 0o700);
      }
    } finally {
      t.cleanup();
    }
  });
});

describe("insertUser / findUserBySshFingerprint", () => {
  it("round-trips an inserted row by ssh_fp", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      const id = insertUser(db, fixturePk(1));
      assert.ok(id > 0);

      const found = findUserBySshFingerprint(db, fixturePk(1).ssh_fp);
      assert.ok(found);
      assert.equal(found.id, id);
      assert.equal(found.short_name, "user-1");
      assert.equal(found.role, "admin");
      assert.equal(found.source, "env");
      assert.equal(found.stamp_pubkey, null);
      assert.equal(found.last_seen_at, null);
      assert.ok(typeof found.created_at === "number");
      db.close();
    } finally {
      t.cleanup();
    }
  });

  it("returns null for an unknown fingerprint", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      const found = findUserBySshFingerprint(db, "SHA256:does-not-exist");
      assert.equal(found, null);
      db.close();
    } finally {
      t.cleanup();
    }
  });

  it("rejects a duplicate short_name with a UNIQUE constraint error", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      insertUser(db, fixturePk(1));
      // Same short_name, different fingerprint → still rejected by the
      // UNIQUE(short_name) constraint.
      assert.throws(() =>
        insertUser(db, { ...fixturePk(2), short_name: "user-1" }),
      );
      db.close();
    } finally {
      t.cleanup();
    }
  });

  it("rejects a duplicate ssh_fp with a UNIQUE constraint error", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      insertUser(db, fixturePk(1));
      assert.throws(() =>
        insertUser(db, { ...fixturePk(2), ssh_fp: fixturePk(1).ssh_fp }),
      );
      db.close();
    } finally {
      t.cleanup();
    }
  });

  it("CHECK constraint rejects an invalid role", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      assert.throws(() =>
        // @ts-expect-error — testing runtime CHECK by passing a bad role
        insertUser(db, { ...fixturePk(1), role: "superuser" }),
      );
      db.close();
    } finally {
      t.cleanup();
    }
  });

  it("CHECK constraint rejects an invalid source", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      assert.throws(() =>
        // @ts-expect-error — testing runtime CHECK by passing a bad source
        insertUser(db, { ...fixturePk(1), source: "ldap" }),
      );
      db.close();
    } finally {
      t.cleanup();
    }
  });
});

describe("upsertUserByFingerprint", () => {
  it("inserts on first call, no-ops on second call with the same fp", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      const r1 = upsertUserByFingerprint(db, fixturePk(1));
      assert.equal(r1.created, true);

      const r2 = upsertUserByFingerprint(db, fixturePk(1));
      assert.equal(r2.created, false);
      assert.equal(r2.id, r1.id);

      // Only one row total.
      assert.equal(listUsers(db).length, 1);
      db.close();
    } finally {
      t.cleanup();
    }
  });

  it("does NOT mutate role on existing rows (admin demotion sticks across boots)", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      // First insert: admin (as if env-imported on boot 1).
      upsertUserByFingerprint(db, fixturePk(1));
      // Simulate operator demoting this user to member via phase 3 CLI.
      db.prepare("UPDATE users SET role = 'member' WHERE ssh_fp = ?").run(
        fixturePk(1).ssh_fp,
      );
      // Now boot 2: env-sync runs again with the same key still in env var.
      upsertUserByFingerprint(db, fixturePk(1));

      const after = findUserBySshFingerprint(db, fixturePk(1).ssh_fp);
      assert.equal(
        after?.role,
        "member",
        "env re-sync silently re-promoted a member back to admin — auth regression",
      );
      db.close();
    } finally {
      t.cleanup();
    }
  });
});

describe("listUsers / countByRole", () => {
  it("listUsers returns rows in insertion (id) order", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      insertUser(db, { ...fixturePk(1), role: "owner" });
      insertUser(db, { ...fixturePk(2), role: "admin" });
      insertUser(db, { ...fixturePk(3), role: "member" });

      const rows = listUsers(db);
      assert.deepEqual(
        rows.map((r) => r.short_name),
        ["user-1", "user-2", "user-3"],
      );
      db.close();
    } finally {
      t.cleanup();
    }
  });

  it("countByRole groups correctly", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      insertUser(db, { ...fixturePk(1), role: "owner" });
      insertUser(db, { ...fixturePk(2), role: "admin" });
      insertUser(db, { ...fixturePk(3), role: "admin" });
      insertUser(db, { ...fixturePk(4), role: "member" });

      assert.equal(countByRole(db, "owner"), 1);
      assert.equal(countByRole(db, "admin"), 2);
      assert.equal(countByRole(db, "member"), 1);
      db.close();
    } finally {
      t.cleanup();
    }
  });
});

describe("suggestUniqueShortName", () => {
  it("returns the desired name when free", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      assert.equal(suggestUniqueShortName(db, "alice"), "alice");
      db.close();
    } finally {
      t.cleanup();
    }
  });

  it("appends -2 / -3 / ... on collision", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      insertUser(db, { ...fixturePk(1), short_name: "alice" });
      assert.equal(suggestUniqueShortName(db, "alice"), "alice-2");

      insertUser(db, { ...fixturePk(2), short_name: "alice-2" });
      assert.equal(suggestUniqueShortName(db, "alice"), "alice-3");
      db.close();
    } finally {
      t.cleanup();
    }
  });
});

describe("findUserByShortName", () => {
  it("returns the row for a known short_name", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      insertUser(db, { ...fixturePk(1), short_name: "alice" });
      const found = findUserByShortName(db, "alice");
      assert.equal(found?.short_name, "alice");
      db.close();
    } finally {
      t.cleanup();
    }
  });

  it("returns null for an unknown short_name", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      assert.equal(findUserByShortName(db, "bob"), null);
      db.close();
    } finally {
      t.cleanup();
    }
  });
});

describe("checkAndConsumeToken — token-bucket rate limit (AGT-420)", () => {
  const T = 1_700_000_000_000; // fixed ms clock for determinism

  it("allows up to `cap` calls, then rejects, with a fixed clock", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      const cap = 3;
      for (let i = 0; i < cap; i++) {
        assert.equal(
          checkAndConsumeToken(db, 1, "review", cap, T),
          true,
          `call ${i + 1} should be allowed`,
        );
      }
      assert.equal(
        checkAndConsumeToken(db, 1, "review", cap, T),
        false,
        "the (cap+1)th call should be rejected",
      );
      db.close();
    } finally {
      t.cleanup();
    }
  });

  it("refills over elapsed time (lazy refill)", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      const cap = 3; // rate = 3/hour → one token per 1200s
      for (let i = 0; i < cap; i++) checkAndConsumeToken(db, 1, "review", cap, T);
      assert.equal(checkAndConsumeToken(db, 1, "review", cap, T), false);
      // advance 1200s → exactly one token refilled
      assert.equal(
        checkAndConsumeToken(db, 1, "review", cap, T + 1200_000),
        true,
        "one token should refill after 1200s at 3/hour",
      );
      assert.equal(
        checkAndConsumeToken(db, 1, "review", cap, T + 1200_000),
        false,
        "the refilled token is already spent",
      );
      db.close();
    } finally {
      t.cleanup();
    }
  });

  it("isolates buckets per subject and per action", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      assert.equal(checkAndConsumeToken(db, 1, "review", 1, T), true);
      assert.equal(checkAndConsumeToken(db, 1, "review", 1, T), false); // subject 1 review exhausted
      assert.equal(checkAndConsumeToken(db, 2, "review", 1, T), true); // different subject — fresh
      assert.equal(checkAndConsumeToken(db, 1, "mint_invite", 1, T), true); // same subject, different action — fresh
      db.close();
    } finally {
      t.cleanup();
    }
  });
});

describe("server verdict cache (AGT-420)", () => {
  it("returns null on a miss, the stored verdict on a hit, and upserts", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      assert.equal(findCachedServerVerdict(db, "security", "d1", "p1"), null);

      recordServerVerdict(db, "security", "d1", "p1", "approved", "looks good");
      assert.deepEqual(findCachedServerVerdict(db, "security", "d1", "p1"), {
        verdict: "approved",
        prose: "looks good",
      });

      // upsert: same triple, new verdict wins
      recordServerVerdict(db, "security", "d1", "p1", "changes_requested", "nit");
      assert.deepEqual(findCachedServerVerdict(db, "security", "d1", "p1"), {
        verdict: "changes_requested",
        prose: "nit",
      });
      db.close();
    } finally {
      t.cleanup();
    }
  });

  it("keys on the full (reviewer, diff_sha256, prompt_sha256) triple", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      recordServerVerdict(db, "security", "d1", "p1", "approved", "ok");
      // any single key component differing → miss
      assert.equal(findCachedServerVerdict(db, "standards", "d1", "p1"), null);
      assert.equal(findCachedServerVerdict(db, "security", "d2", "p1"), null);
      assert.equal(findCachedServerVerdict(db, "security", "d1", "p2"), null);
      db.close();
    } finally {
      t.cleanup();
    }
  });
});

describe("resolveReviewRateCap (AGT-420)", () => {
  const saved = process.env.MAX_REVIEWS_PER_HOUR;
  after(() => {
    if (saved === undefined) delete process.env.MAX_REVIEWS_PER_HOUR;
    else process.env.MAX_REVIEWS_PER_HOUR = saved;
  });

  it("defaults to 30 for member, 5x for admin/owner", () => {
    delete process.env.MAX_REVIEWS_PER_HOUR;
    assert.equal(resolveReviewRateCap("member"), 30);
    assert.equal(resolveReviewRateCap("admin"), 150);
    assert.equal(resolveReviewRateCap("owner"), 150);
  });

  it("honors MAX_REVIEWS_PER_HOUR and falls back to default on a bad value", () => {
    process.env.MAX_REVIEWS_PER_HOUR = "10";
    assert.equal(resolveReviewRateCap("member"), 10);
    process.env.MAX_REVIEWS_PER_HOUR = "not-a-number";
    assert.equal(resolveReviewRateCap("member"), 30);
  });
});

// ─── AGT-427: peer-review schema + helpers ──────────────────────────

describe("peer_review schema (AGT-427)", () => {
  it("schema creates peer_review_patches and peer_review_events tables idempotently (AC 1)", () => {
    const t = tmpDbPath();
    try {
      // First open: creates schema.
      const db1 = openServerDb({ path: t.path, skipChmod: true });
      // Verify tables exist via PRAGMA.
      const tables1 = db1
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .all() as { name: string }[];
      const tableNames1 = tables1.map((r) => r.name);
      assert.ok(tableNames1.includes("peer_review_patches"), "peer_review_patches table must exist after first open");
      assert.ok(tableNames1.includes("peer_review_events"), "peer_review_events table must exist after first open");

      // Check columns via PRAGMA table_info.
      const patchCols = db1
        .prepare("PRAGMA table_info(peer_review_patches)")
        .all() as { name: string }[];
      const patchColNames = patchCols.map((c) => c.name);
      for (const col of [
        "patch_id", "requested_by_fp", "base_sha", "head_sha", "repo",
        "broadcast_at", "seat_1_holder", "seat_2_holder",
        "seat_1_claimed_at", "seat_2_claimed_at",
      ]) {
        assert.ok(patchColNames.includes(col), `peer_review_patches must have column ${col}`);
      }

      const eventCols = db1
        .prepare("PRAGMA table_info(peer_review_events)")
        .all() as { name: string }[];
      const eventColNames = eventCols.map((c) => c.name);
      for (const col of ["id", "patch_id", "event_type", "actor_fp", "occurred_at", "payload"]) {
        assert.ok(eventColNames.includes(col), `peer_review_events must have column ${col}`);
      }

      db1.close();

      // Second open: schema is idempotent — no error, tables still present.
      const db2 = openServerDb({ path: t.path, skipChmod: true });
      const tables2 = db2
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .all() as { name: string }[];
      const tableNames2 = tables2.map((r) => r.name);
      assert.ok(tableNames2.includes("peer_review_patches"), "peer_review_patches must survive second open");
      assert.ok(tableNames2.includes("peer_review_events"), "peer_review_events must survive second open");
      // No extra tables should have appeared.
      assert.deepStrictEqual(
        tableNames1.sort(),
        tableNames2.sort(),
        "table set must be identical after two schema runs",
      );
      db2.close();
    } finally {
      t.cleanup();
    }
  });
});

describe("insertPatch / findPatch / appendEvent (AGT-427)", () => {
  it("round-trips a patch row", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      insertPatch(db, {
        patch_id: "patch-001",
        requested_by_fp: "SHA256:author",
        base_sha: "a".repeat(40),
        head_sha: "b".repeat(40),
        repo: "acme/widget",
      });
      const row = findPatch(db, "patch-001");
      assert.ok(row, "patch row must be found after insert");
      assert.equal(row.patch_id, "patch-001");
      assert.equal(row.requested_by_fp, "SHA256:author");
      assert.equal(row.repo, "acme/widget");
      assert.equal(row.seat_1_holder, null);
      assert.equal(row.seat_2_holder, null);
      db.close();
    } finally {
      t.cleanup();
    }
  });

  it("appendEvent inserts a row retrievable via select", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      insertPatch(db, {
        patch_id: "p-evt",
        requested_by_fp: "SHA256:a",
        base_sha: "a".repeat(40),
        head_sha: "b".repeat(40),
        repo: "acme/foo",
      });
      appendEvent(db, "p-evt", "pr-opened", "SHA256:a", { note: "test" });
      const events = db
        .prepare("SELECT event_type, actor_fp, payload FROM peer_review_events WHERE patch_id = 'p-evt'")
        .all() as { event_type: string; actor_fp: string; payload: string }[];
      assert.equal(events.length, 1);
      assert.equal(events[0]?.event_type, "pr-opened");
      assert.equal(events[0]?.actor_fp, "SHA256:a");
      const parsed = JSON.parse(events[0]?.payload ?? "{}") as { note: string };
      assert.equal(parsed.note, "test");
      db.close();
    } finally {
      t.cleanup();
    }
  });

  it("findPatch returns null for unknown patch_id", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      assert.equal(findPatch(db, "does-not-exist"), null);
      db.close();
    } finally {
      t.cleanup();
    }
  });
});

describe("claimSeatTx (AGT-427)", () => {
  it("first claimant gets seat 1, second gets seat 2", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      insertPatch(db, {
        patch_id: "p-claim",
        requested_by_fp: "SHA256:author",
        base_sha: "a".repeat(40),
        head_sha: "b".repeat(40),
        repo: "acme/foo",
      });
      const r1 = claimSeatTx(db, "p-claim", "SHA256:reviewer-1");
      assert.deepStrictEqual(r1, { ok: true, seat: 1 });

      const r2 = claimSeatTx(db, "p-claim", "SHA256:reviewer-2");
      assert.deepStrictEqual(r2, { ok: true, seat: 2 });

      const row = findPatch(db, "p-claim");
      assert.equal(row?.seat_1_holder, "SHA256:reviewer-1");
      assert.equal(row?.seat_2_holder, "SHA256:reviewer-2");
      db.close();
    } finally {
      t.cleanup();
    }
  });

  it("rejects when both seats are taken (seats_full)", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      insertPatch(db, {
        patch_id: "p-full",
        requested_by_fp: "SHA256:author",
        base_sha: "a".repeat(40),
        head_sha: "b".repeat(40),
        repo: "acme/foo",
      });
      claimSeatTx(db, "p-full", "SHA256:r1");
      claimSeatTx(db, "p-full", "SHA256:r2");
      const r3 = claimSeatTx(db, "p-full", "SHA256:r3");
      assert.deepStrictEqual(r3, { ok: false, error: "seats_full" });
      db.close();
    } finally {
      t.cleanup();
    }
  });

  it("rejects the original author (author_cannot_claim_own_pr)", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      insertPatch(db, {
        patch_id: "p-author",
        requested_by_fp: "SHA256:author",
        base_sha: "a".repeat(40),
        head_sha: "b".repeat(40),
        repo: "acme/foo",
      });
      const r = claimSeatTx(db, "p-author", "SHA256:author");
      assert.deepStrictEqual(r, { ok: false, error: "author_cannot_claim_own_pr" });
      db.close();
    } finally {
      t.cleanup();
    }
  });

  it("rejects a reviewer who already holds the other seat (already_holds_other_seat)", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      insertPatch(db, {
        patch_id: "p-self",
        requested_by_fp: "SHA256:author",
        base_sha: "a".repeat(40),
        head_sha: "b".repeat(40),
        repo: "acme/foo",
      });
      claimSeatTx(db, "p-self", "SHA256:reviewer");
      const r2 = claimSeatTx(db, "p-self", "SHA256:reviewer");
      assert.deepStrictEqual(r2, { ok: false, error: "already_holds_other_seat" });
      db.close();
    } finally {
      t.cleanup();
    }
  });

  it("returns patch_not_found for unknown patch", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      const r = claimSeatTx(db, "no-such-patch", "SHA256:reviewer");
      assert.deepStrictEqual(r, { ok: false, error: "patch_not_found" });
      db.close();
    } finally {
      t.cleanup();
    }
  });
});

describe("releaseSeat (AGT-427)", () => {
  it("clears a held seat and returns true", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      insertPatch(db, {
        patch_id: "p-rel",
        requested_by_fp: "SHA256:author",
        base_sha: "a".repeat(40),
        head_sha: "b".repeat(40),
        repo: "acme/foo",
      });
      claimSeatTx(db, "p-rel", "SHA256:r1");
      const released = releaseSeat(db, "p-rel", "SHA256:r1");
      assert.equal(released, true);
      const row = findPatch(db, "p-rel");
      assert.equal(row?.seat_1_holder, null);
      db.close();
    } finally {
      t.cleanup();
    }
  });

  it("returns false when the claimant holds no seat", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      insertPatch(db, {
        patch_id: "p-rel2",
        requested_by_fp: "SHA256:author",
        base_sha: "a".repeat(40),
        head_sha: "b".repeat(40),
        repo: "acme/foo",
      });
      const released = releaseSeat(db, "p-rel2", "SHA256:nobody");
      assert.equal(released, false);
      db.close();
    } finally {
      t.cleanup();
    }
  });
});

describe("touchHeartbeat (AGT-427)", () => {
  it("refreshes the timestamp and returns the seat number", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      insertPatch(db, {
        patch_id: "p-hb",
        requested_by_fp: "SHA256:author",
        base_sha: "a".repeat(40),
        head_sha: "b".repeat(40),
        repo: "acme/foo",
      });
      claimSeatTx(db, "p-hb", "SHA256:r1");
      const before = findPatch(db, "p-hb")?.seat_1_claimed_at;
      const seat = touchHeartbeat(db, "p-hb", "SHA256:r1", Date.now() + 5000);
      assert.equal(seat, 1);
      const after = findPatch(db, "p-hb")?.seat_1_claimed_at;
      assert.ok(
        after !== null && after !== undefined && (before === null || before === undefined || after >= before),
        "seat_1_claimed_at should be refreshed",
      );
      db.close();
    } finally {
      t.cleanup();
    }
  });

  it("returns null when the claimant holds no seat (404 case)", () => {
    const t = tmpDbPath();
    try {
      const db = openServerDb({ path: t.path, skipChmod: true });
      insertPatch(db, {
        patch_id: "p-hb2",
        requested_by_fp: "SHA256:author",
        base_sha: "a".repeat(40),
        head_sha: "b".repeat(40),
        repo: "acme/foo",
      });
      const seat = touchHeartbeat(db, "p-hb2", "SHA256:nobody");
      assert.equal(seat, null);
      db.close();
    } finally {
      t.cleanup();
    }
  });
});
