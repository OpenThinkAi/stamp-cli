/**
 * End-to-end test for the boot-time AUTHORIZED_KEYS → sqlite bootstrap.
 *
 * The seeder runs as root from entrypoint.sh on every container boot. Since
 * AGT-2260 it imports AUTHORIZED_KEYS only into an EMPTY users table with no
 * bootstrap marker, and records the marker so it never imports again — a
 * user removed with `stamp users remove` must not come back on reboot.
 * Properties exercised below:
 *
 *   - First boot: each valid line lands as role=admin source=env; the
 *     bootstrap marker is recorded
 *   - Re-running with the same env var is a no-op
 *   - A demoted user is not re-promoted; a removed user is not resurrected,
 *     even when every row is removed
 *   - Keys added to AUTHORIZED_KEYS after bootstrap are NOT imported, and
 *     are reported by fingerprint
 *   - Upgrade of a pre-AGT-2260 server (populated table, no marker): no
 *     import, marker recorded, existing rows untouched
 *   - Malformed lines are logged but do not abort the seed
 *   - Empty / unset AUTHORIZED_KEYS exits cleanly and records no marker
 *   - short_name collisions on same-comment keys get distinct names
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import {
  ENV_SEED_MARKER,
  getServerMeta,
  insertUser,
  listUsers,
  openServerDb,
} from "../src/lib/serverDb.ts";
import { parseSshPubkey } from "../src/lib/sshKeys.ts";

const SEEDER_TS = path.resolve(
  import.meta.dirname,
  "..",
  "src",
  "server",
  "seed-users.ts",
);

// Two real ed25519 keys generated specifically as fixtures (different
// comments so derived short_names don't collide unless we want them to).
const KEY_A =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO0fHPCBttt9fiLYtDixe2+eGATWUa+BiRi7V5B7Bc7b alice@laptop";
const KEY_B =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0fH9hWlMnH5o3iZqIDe9DTKQUyfPnEHpJfntZjEbka bob@laptop";

function runSeeder(
  dbPath: string,
  authorizedKeys: string,
): { stdout: string; stderr: string; status: number | null } {
  const result = spawnSync(
    process.execPath,
    ["--import", "tsx", SEEDER_TS],
    {
      env: {
        ...process.env,
        STAMP_SERVER_DB_PATH: dbPath,
        AUTHORIZED_KEYS: authorizedKeys,
      },
      encoding: "utf8",
    },
  );
  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    status: result.status,
  };
}

function tmpDb(): { dbPath: string; cleanup: () => void } {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-seed-"));
  return {
    dbPath: path.join(dir, "users.db"),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

describe("stamp-seed-users", () => {
  it("imports two distinct keys as role=admin source=env", () => {
    const t = tmpDb();
    try {
      const blob = [KEY_A, KEY_B].join("\n");
      const r = runSeeder(t.dbPath, blob);
      assert.equal(r.status, 0, `non-zero exit; stderr=${r.stderr}`);

      const db = openServerDb({ path: t.dbPath, readOnly: true });
      const users = listUsers(db);
      db.close();

      assert.equal(users.length, 2);
      for (const u of users) {
        assert.equal(u.role, "admin");
        assert.equal(u.source, "env");
        assert.equal(u.stamp_pubkey, null);
      }
      // AGT-422: short_names are content-addressed (PII-free), NOT derived
      // from the key comment, and the stored pubkey has the comment stripped.
      const names = users.map((u) => u.short_name).sort();
      assert.equal(names.length, 2);
      for (const n of names) assert.match(n, /^user-[0-9a-f]{8}$/);
      assert.notEqual(names[0], names[1]); // distinct
      for (const u of users) {
        assert.doesNotMatch(u.ssh_pubkey, /laptop/); // comment (alice@laptop / bob@laptop) stripped
        assert.match(u.ssh_pubkey, /^ssh-ed25519 [A-Za-z0-9+/=]+$/); // bare <algo> <base64>
      }
    } finally {
      t.cleanup();
    }
  });

  it("is idempotent — re-running with the same env var no-ops", () => {
    const t = tmpDb();
    try {
      const blob = [KEY_A, KEY_B].join("\n");
      runSeeder(t.dbPath, blob);
      runSeeder(t.dbPath, blob);
      runSeeder(t.dbPath, blob);

      const db = openServerDb({ path: t.dbPath, readOnly: true });
      const users = listUsers(db);
      db.close();
      assert.equal(users.length, 2);
    } finally {
      t.cleanup();
    }
  });

  it("does not re-promote a manually-demoted user on subsequent boots", () => {
    const t = tmpDb();
    try {
      runSeeder(t.dbPath, KEY_A);

      // Simulate a phase-3 operator action: demote alice to member. The
      // short_name is now content-addressed, so demote the (single) row
      // rather than hardcoding a name.
      const writer = openServerDb({ path: t.dbPath, skipChmod: true });
      writer.prepare("UPDATE users SET role = 'member'").run();
      writer.close();

      // Boot 2: env var unchanged. Re-running the seeder must not
      // silently restore admin.
      runSeeder(t.dbPath, KEY_A);

      const db = openServerDb({ path: t.dbPath, readOnly: true });
      const users = listUsers(db);
      db.close();
      assert.equal(users.length, 1);
      assert.equal(
        users[0]?.role,
        "member",
        "env re-sync re-promoted a demoted user — auth regression",
      );
    } finally {
      t.cleanup();
    }
  });

  it("skips comments and blanks, logs parse errors, continues past malformed lines", () => {
    const t = tmpDb();
    try {
      const blob = [
        "# this is a comment",
        "",
        KEY_A,
        "ssh-dss AAAAfake unsupported-algo",
        "garbage no-base64",
        KEY_B,
      ].join("\n");
      const r = runSeeder(t.dbPath, blob);
      assert.equal(r.status, 0);
      // Errors reported to stderr; both bad lines mentioned.
      assert.match(r.stderr, /ignoring malformed AUTHORIZED_KEYS line/);

      const db = openServerDb({ path: t.dbPath, readOnly: true });
      const users = listUsers(db);
      db.close();
      assert.equal(users.length, 2);
    } finally {
      t.cleanup();
    }
  });

  it("exits cleanly with no rows when AUTHORIZED_KEYS is empty", () => {
    const t = tmpDb();
    try {
      const r = runSeeder(t.dbPath, "");
      assert.equal(r.status, 0);
      // Note: the DB file may not even exist because openServerDb is never
      // reached when AUTHORIZED_KEYS is empty. That's the correct behavior
      // — no spurious empty DB on a fresh server before any keys are added.
    } finally {
      t.cleanup();
    }
  });

  it("gives same-comment keys DISTINCT content-addressed names (AGT-422)", () => {
    const t = tmpDb();
    try {
      // Two DIFFERENT keys with the SAME comment. Pre-AGT-422 the
      // comment-derived slug collided (→ -2 suffix); now the short_name is
      // content-addressed from the keyblob, so identical comments are
      // irrelevant and the two keys get distinct, PII-free names.
      const a = KEY_A.replace("alice@laptop", "shared@host");
      const b = KEY_B.replace("bob@laptop", "shared@host");
      const r = runSeeder(t.dbPath, [a, b].join("\n"));
      assert.equal(r.status, 0, `stderr=${r.stderr}`);

      const db = openServerDb({ path: t.dbPath, readOnly: true });
      const users = listUsers(db);
      db.close();
      assert.equal(users.length, 2);
      const names = users.map((u) => u.short_name).sort();
      for (const n of names) assert.match(n, /^user-[0-9a-f]{8}$/);
      assert.notEqual(names[0], names[1]);
      // and no PII from the shared comment leaked into either name
      for (const n of names) assert.doesNotMatch(n, /shared|host/);
    } finally {
      t.cleanup();
    }
  });

  it("records the bootstrap marker on first boot", () => {
    const t = tmpDb();
    try {
      runSeeder(t.dbPath, KEY_A);
      const db = openServerDb({ path: t.dbPath, readOnly: true });
      const marker = getServerMeta(db, ENV_SEED_MARKER);
      db.close();
      assert.match(marker ?? "", /seeded 1 key/);
    } finally {
      t.cleanup();
    }
  });

  it("does not resurrect a removed user on reboot (AGT-2260)", () => {
    const t = tmpDb();
    try {
      runSeeder(t.dbPath, [KEY_A, KEY_B].join("\n"));
      const fpB = parseSshPubkey(KEY_B).fingerprint;
      const writer = openServerDb({ path: t.dbPath, skipChmod: true });
      writer.prepare("DELETE FROM users WHERE ssh_fp = ?").run(fpB);
      writer.close();

      // Reboot with AUTHORIZED_KEYS unchanged: bob must stay removed.
      const r = runSeeder(t.dbPath, [KEY_A, KEY_B].join("\n"));
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /already bootstrapped/);
      assert.ok(r.stderr.includes(fpB), `removed key not reported: ${r.stderr}`);

      const db = openServerDb({ path: t.dbPath, readOnly: true });
      const fps = listUsers(db).map((u) => u.ssh_fp);
      db.close();
      assert.deepEqual(fps, [parseSshPubkey(KEY_A).fingerprint]);
    } finally {
      t.cleanup();
    }
  });

  it("does not re-seed when every user was removed", () => {
    const t = tmpDb();
    try {
      runSeeder(t.dbPath, KEY_A);
      const writer = openServerDb({ path: t.dbPath, skipChmod: true });
      writer.prepare("DELETE FROM users").run();
      writer.close();
      runSeeder(t.dbPath, KEY_A);
      const db = openServerDb({ path: t.dbPath, readOnly: true });
      assert.equal(listUsers(db).length, 0);
      db.close();
    } finally {
      t.cleanup();
    }
  });

  it("does not import keys added to AUTHORIZED_KEYS after bootstrap", () => {
    const t = tmpDb();
    try {
      runSeeder(t.dbPath, KEY_A);
      const r = runSeeder(t.dbPath, [KEY_A, KEY_B].join("\n"));
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stderr, /1 AUTHORIZED_KEYS key\(s\) are not members and were NOT added/);
      const db = openServerDb({ path: t.dbPath, readOnly: true });
      assert.equal(listUsers(db).length, 1);
      db.close();
    } finally {
      t.cleanup();
    }
  });

  it("warns when an env-seeded member's key was removed from AUTHORIZED_KEYS (AGT-2270)", () => {
    const t = tmpDb();
    try {
      runSeeder(t.dbPath, [KEY_A, KEY_B].join("\n"));
      const r = runSeeder(t.dbPath, KEY_A);
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stderr, /1 member\(s\) seeded from AUTHORIZED_KEYS are no longer listed there but still have access/);
      assert.match(r.stderr, /stamp users remove/);
      const quiet = runSeeder(t.dbPath, [KEY_A, KEY_B].join("\n"));
      assert.doesNotMatch(quiet.stderr, /no longer listed/);
    } finally {
      t.cleanup();
    }
  });

  it("upgrade: a populated table without a marker is marked, not re-imported", () => {
    const t = tmpDb();
    try {
      // A pre-AGT-2260 server: alice is a member (seeded on an earlier boot
      // and later demoted); bob was removed before the upgrade but is still
      // listed in AUTHORIZED_KEYS.
      const a = parseSshPubkey(KEY_A);
      const writer = openServerDb({ path: t.dbPath, skipChmod: true });
      insertUser(writer, {
        short_name: "alice",
        ssh_pubkey: KEY_A,
        ssh_fp: a.fingerprint,
        role: "member",
        source: "env",
      });
      writer.close();

      const r = runSeeder(t.dbPath, [KEY_A, KEY_B].join("\n"));
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /already has 1 member\(s\); recorded bootstrap as done/);

      const db = openServerDb({ path: t.dbPath, readOnly: true });
      const users = listUsers(db);
      const marker = getServerMeta(db, ENV_SEED_MARKER);
      db.close();
      assert.equal(users.length, 1);
      assert.equal(users[0]?.short_name, "alice");
      assert.equal(users[0]?.role, "member");
      assert.match(marker ?? "", /existing-users/);
    } finally {
      t.cleanup();
    }
  });

  it("records no marker when nothing was imported into an empty table", () => {
    const t = tmpDb();
    try {
      runSeeder(t.dbPath, "garbage no-base64");
      // A later boot with a valid key can still bootstrap the empty server.
      runSeeder(t.dbPath, KEY_A);
      const db = openServerDb({ path: t.dbPath, readOnly: true });
      assert.equal(listUsers(db).length, 1);
      db.close();
    } finally {
      t.cleanup();
    }
  });
});
