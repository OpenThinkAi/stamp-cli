/**
 * AGT-2260 — `stamp-break-glass`, the root-only recovery CLI.
 *
 * users.db is the only source of SSH access, so this is how an operator
 * who lost every admin key gets back in (root shell in the container).
 * Exercises the lib entry with an injected uid: non-root is refused; add
 * inserts new keys and re-roles existing ones; list prints the table.
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { runBreakGlass } from "../src/lib/breakGlass.ts";
import { insertUser, listUsers, openServerDb } from "../src/lib/serverDb.ts";
import { parseSshPubkey } from "../src/lib/sshKeys.ts";

const KEY_A =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO0fHPCBttt9fiLYtDixe2+eGATWUa+BiRi7V5B7Bc7b alice@laptop";
const KEY_B =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0fH9hWlMnH5o3iZqIDe9DTKQUyfPnEHpJfntZjEbka bob@laptop";

function setup() {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-break-glass-"));
  const dbPath = path.join(dir, "users.db");
  return { dir, dbPath, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function run(dbPath: string, argv: string[], opts: { uid?: number; stdin?: string } = {}) {
  let out = "";
  let err = "";
  const code = runBreakGlass(argv, {
    uid: opts.uid ?? 0,
    dbPath,
    skipChmod: true,
    readStdin: () => opts.stdin ?? "",
    out: (s) => (out += s),
    err: (s) => (err += s),
  });
  return { code, out, err };
}

function users(dbPath: string) {
  const db = openServerDb({ path: dbPath, readOnly: true });
  try {
    return listUsers(db);
  } finally {
    db.close();
  }
}

describe("stamp-break-glass", () => {
  it("refuses any uid but 0 and writes nothing", () => {
    const t = setup();
    try {
      const r = run(t.dbPath, ["add", "-"], { uid: 1000, stdin: KEY_A });
      assert.equal(r.code, 1);
      assert.match(r.err, /must run as root/);
      assert.equal(run(t.dbPath, ["list"], { uid: 1000 }).code, 1);
    } finally {
      t.cleanup();
    }
  });

  it("adds keys from stdin as admin into an empty DB", () => {
    const t = setup();
    try {
      const r = run(t.dbPath, ["add", "-"], { stdin: `${KEY_A}\n# note\n${KEY_B}\n` });
      assert.equal(r.code, 0, r.err);
      const u = users(t.dbPath);
      assert.equal(u.length, 2);
      for (const row of u) {
        assert.equal(row.role, "admin");
        assert.equal(row.source, "manual");
        assert.match(row.short_name, /^user-[0-9a-f]{8}$/);
      }
    } finally {
      t.cleanup();
    }
  });

  it("reads a key file and promotes an existing row to owner", () => {
    const t = setup();
    try {
      const a = parseSshPubkey(KEY_A);
      const db = openServerDb({ path: t.dbPath, skipChmod: true });
      insertUser(db, { short_name: "alice", ssh_pubkey: KEY_A, ssh_fp: a.fingerprint, role: "member", source: "invite" });
      db.close();
      const f = path.join(t.dir, "alice.pub");
      writeFileSync(f, KEY_A + "\n");
      const r = run(t.dbPath, ["add", "--role", "owner", f]);
      assert.equal(r.code, 0, r.err);
      assert.match(r.out, /set-role alice .* member -> owner/);
      const u = users(t.dbPath);
      assert.equal(u.length, 1);
      assert.equal(u[0]?.role, "owner");
      assert.equal(u[0]?.source, "invite");
    } finally {
      t.cleanup();
    }
  });

  it("rejects bad usage, bad roles and input with no valid key", () => {
    const t = setup();
    try {
      assert.equal(run(t.dbPath, []).code, 2);
      assert.equal(run(t.dbPath, ["remove", "x"]).code, 2);
      assert.equal(run(t.dbPath, ["add", "--role", "member", "-"], { stdin: KEY_A }).code, 2);
      assert.equal(run(t.dbPath, ["add", "-"], { stdin: "garbage" }).code, 2);
      assert.equal(run(t.dbPath, ["add", "-", "extra"], { stdin: KEY_A }).code, 2);
    } finally {
      t.cleanup();
    }
  });

  it("lists the users table", () => {
    const t = setup();
    try {
      run(t.dbPath, ["add", "-"], { stdin: KEY_A });
      const r = run(t.dbPath, ["list"]);
      assert.equal(r.code, 0);
      assert.match(r.out, new RegExp(`\\tadmin\\tmanual\\t${parseSshPubkey(KEY_A).fingerprint.replace(/[+/]/g, "\\$&")}\\t`));
    } finally {
      t.cleanup();
    }
  });
});
