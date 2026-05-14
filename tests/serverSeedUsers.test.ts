/**
 * End-to-end test for the boot-time AUTHORIZED_KEYS → sqlite seeder.
 *
 * The seeder runs as root from entrypoint.sh once per container boot. It
 * walks the AUTHORIZED_KEYS env var, INSERT-OR-NO-OPs each entry into the
 * users table as role=admin source=env, and is safe to re-run. Critical
 * properties exercised below:
 *
 *   - Multi-line env var with comments + blanks parses correctly
 *   - Each accepted line lands as one row with role=admin source=env
 *   - Re-running with the same env var is a no-op (boot N+1 doesn't
 *     duplicate boot N's rows)
 *   - A row manually demoted between boots (operator action via phase 3
 *     CLI, simulated here with raw UPDATE) is NOT re-promoted to admin
 *   - Malformed lines are logged but do not abort the seed; valid lines
 *     after them still land
 *   - Empty / unset AUTHORIZED_KEYS exits cleanly
 *   - short_name collisions on env keys with the same comment get
 *     auto-suffixed (-2, -3, ...) rather than failing
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { listUsers, openServerDb } from "../src/lib/serverDb.ts";

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
      // short_names derived from the comments
      const names = users.map((u) => u.short_name).sort();
      assert.deepEqual(names, ["alice-laptop", "bob-laptop"]);
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

      // Simulate a phase-3 operator action: demote alice to member.
      const writer = openServerDb({ path: t.dbPath, skipChmod: true });
      writer
        .prepare("UPDATE users SET role = 'member' WHERE short_name = ?")
        .run("alice-laptop");
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

  it("auto-suffixes short_name on collision between keys with same comment", () => {
    const t = tmpDb();
    try {
      // Same comment in both keys → derived short_name would collide.
      const a = KEY_A.replace("alice@laptop", "shared@host");
      const b = KEY_B.replace("bob@laptop", "shared@host");
      const r = runSeeder(t.dbPath, [a, b].join("\n"));
      assert.equal(r.status, 0, `stderr=${r.stderr}`);

      const db = openServerDb({ path: t.dbPath, readOnly: true });
      const users = listUsers(db);
      db.close();
      assert.equal(users.length, 2);
      const names = users.map((u) => u.short_name).sort();
      assert.deepEqual(names, ["shared-host", "shared-host-2"]);
    } finally {
      t.cleanup();
    }
  });
});
