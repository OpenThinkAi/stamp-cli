/**
 * End-to-end test for the AuthorizedKeysCommand resolver.
 *
 * sshd invokes the bundled script as:
 *   /usr/local/sbin/stamp-authorized-keys <username> <fingerprint>
 *
 * with the offered SSH key's fingerprint in OpenSSH `%f` format. Tests
 * here spawn the unbundled TS via tsx (same execution surface as `npm
 * run dev`), pointing STAMP_SERVER_DB_PATH at a tmpfs DB so the script
 * hits a known set of fixtures. Verifies the four states the resolver
 * must handle correctly:
 *
 *   - Known fingerprint  → stdout = ssh_pubkey line, exit 0
 *   - Unknown fingerprint → empty stdout, exit 0 (sshd falls through to
 *                           AuthorizedKeysFile)
 *   - Wrong username     → empty stdout, exit 0 (only `git` is valid)
 *   - Malformed fp       → empty stdout, exit 0 (fail open)
 *
 * Exit 0 in every case is intentional: ANY nonzero exit would make sshd
 * abort the auth attempt outright, locking the operator out if the DB is
 * briefly unavailable during a redeploy. The resolver always degrades to
 * "no match, try the next method."
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { insertUser, openServerDb } from "../src/lib/serverDb.ts";

const RESOLVER_TS = path.resolve(
  import.meta.dirname,
  "..",
  "src",
  "server",
  "authorized-keys.ts",
);

const KEY_LINE =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO0fHPCBttt9fiLYtDixe2+eGATWUa+BiRi7V5B7Bc7b tester@example";
const KEY_FINGERPRINT = "SHA256:ULy/G0aXU8CnDHhJe9uePIDwgzzNp16KH4b5LxLR/+k";

function setupDb(): { dbPath: string; cleanup: () => void } {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-authkeys-"));
  const dbPath = path.join(dir, "users.db");
  const db = openServerDb({ path: dbPath, skipChmod: true });
  try {
    insertUser(db, {
      short_name: "tester",
      ssh_pubkey: KEY_LINE,
      ssh_fp: KEY_FINGERPRINT,
      role: "admin",
      source: "env",
    });
  } finally {
    db.close();
  }
  return { dbPath, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function runResolver(
  dbPath: string,
  username: string,
  fingerprint: string,
): { stdout: string; stderr: string; status: number | null } {
  const result = spawnSync(
    process.execPath,
    ["--import", "tsx", RESOLVER_TS, username, fingerprint],
    {
      env: {
        ...process.env,
        STAMP_SERVER_DB_PATH: dbPath,
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

describe("stamp-authorized-keys resolver", () => {
  it("prints the matching ssh_pubkey line on a known fingerprint", () => {
    const t = setupDb();
    try {
      const r = runResolver(t.dbPath, "git", KEY_FINGERPRINT);
      assert.equal(r.status, 0, `non-zero exit; stderr=${r.stderr}`);
      assert.equal(r.stdout.trim(), KEY_LINE);
    } finally {
      t.cleanup();
    }
  });

  it("emits empty stdout (and exits 0) on an unknown fingerprint", () => {
    const t = setupDb();
    try {
      const r = runResolver(t.dbPath, "git", "SHA256:does-not-exist");
      assert.equal(r.status, 0);
      assert.equal(r.stdout, "");
    } finally {
      t.cleanup();
    }
  });

  it("emits empty stdout when the username isn't `git`", () => {
    const t = setupDb();
    try {
      // Right fingerprint, wrong user. sshd should never invoke us with
      // a non-`git` user (only git is exposed as an SSH target), but
      // defense-in-depth: if it ever does, no key data leaks.
      const r = runResolver(t.dbPath, "root", KEY_FINGERPRINT);
      assert.equal(r.status, 0);
      assert.equal(r.stdout, "");
    } finally {
      t.cleanup();
    }
  });

  it("emits empty stdout for a malformed fingerprint", () => {
    const t = setupDb();
    try {
      const r = runResolver(t.dbPath, "git", "MD5:legacy-format");
      assert.equal(r.status, 0);
      assert.equal(r.stdout, "");
    } finally {
      t.cleanup();
    }
  });

  it("exits 0 with empty stdout when the DB file is missing (fail-open)", () => {
    // No setupDb — STAMP_SERVER_DB_PATH points at a path that doesn't exist.
    const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-authkeys-missing-"));
    const dbPath = path.join(dir, "does-not-exist.db");
    try {
      const r = runResolver(dbPath, "git", KEY_FINGERPRINT);
      assert.equal(
        r.status,
        0,
        `resolver should fail open on missing DB; got status=${r.status} stderr=${r.stderr}`,
      );
      assert.equal(r.stdout, "");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
