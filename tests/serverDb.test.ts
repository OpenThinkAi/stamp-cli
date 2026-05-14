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
 *
 * Filesystem perms (root:git 0640 / parent 0750) are NOT exercised here —
 * they require running as root with the `git` group available, which the
 * test harness isn't. Those are validated end-to-end by the Docker image
 * tests instead.
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, before, after } from "node:test";

import {
  countByRole,
  findUserBySshFingerprint,
  findUserByShortName,
  insertUser,
  listUsers,
  openServerDb,
  suggestUniqueShortName,
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
