/**
 * AGT-423 — authorization + end-to-end behavior of the `purge-trash` SSH
 * verb. The verb is an IRREVERSIBLE mass-delete, so (per the AGT-423
 * security review) it gates on role ≥ admin. These tests spawn the
 * unbundled TS via tsx with a faked SSH_USER_AUTH + a temp membership DB +
 * a temp trash dir, the same shape as serverMintInvite.test.ts.
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { insertUser, openServerDb } from "../src/lib/serverDb.ts";

const PURGE_TRASH_TS = path.resolve(
  import.meta.dirname,
  "..",
  "src",
  "server",
  "purge-trash.ts",
);

const ADMIN_SSH_LINE =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO0fHPCBttt9fiLYtDixe2+eGATWUa+BiRi7V5B7Bc7b admin@host";
const ADMIN_SSH_FP = "SHA256:ULy/G0aXU8CnDHhJe9uePIDwgzzNp16KH4b5LxLR/+k";
const MEMBER_SSH_LINE =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0fH9hWlMnH5o3iZqIDe9DTKQUyfPnEHpJfntZjEbka member@host";
const MEMBER_SSH_FP = "SHA256:JjZxN+NVk11skR8NQvPgkbYR8jF4UT4Zy/xtptZF52w";

interface Harness {
  dir: string;
  dbPath: string;
  authPath: string;
  trashDir: string;
  cleanup: () => void;
}

function setup(
  caller: { line: string; fp: string; role: "owner" | "admin" | "member" } | null,
): Harness {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-purge-"));
  const dbPath = path.join(dir, "users.db");
  const authPath = path.join(dir, "ssh_user_auth");
  const trashDir = path.join(dir, ".trash");
  mkdirSync(trashDir);

  if (caller) {
    const db = openServerDb({ path: dbPath, skipChmod: true });
    try {
      insertUser(db, {
        short_name: "caller",
        ssh_pubkey: caller.line,
        ssh_fp: caller.fp,
        role: caller.role,
        source: "env",
      });
    } finally {
      db.close();
    }
    writeFileSync(authPath, `publickey ${caller.line}\n`, { mode: 0o600 });
  }

  return {
    dir,
    dbPath,
    authPath,
    trashDir,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function runPurge(
  h: Harness,
  args: string[],
  opts: { withAuth?: boolean } = {},
): { stdout: string; stderr: string; status: number | null } {
  const env: Record<string, string | undefined> = {
    ...process.env,
    STAMP_SERVER_DB_PATH: h.dbPath,
    STAMP_TRASH_DIR: h.trashDir,
  };
  if (opts.withAuth !== false) env["SSH_USER_AUTH"] = h.authPath;
  else env["SSH_USER_AUTH"] = undefined;
  const r = spawnSync(process.execPath, ["--import", "tsx", PURGE_TRASH_TS, ...args], {
    env: env as NodeJS.ProcessEnv,
    encoding: "utf8",
  });
  return { stdout: r.stdout ?? "", stderr: r.stderr ?? "", status: r.status };
}

describe("purge-trash — authorization (AGT-423)", () => {
  it("refuses a member caller with exit 3 (irreversible → owner/admin only)", () => {
    const h = setup({ line: MEMBER_SSH_LINE, fp: MEMBER_SSH_FP, role: "member" });
    try {
      // Even with an old entry present, the role gate fires first.
      mkdirSync(path.join(h.trashDir, "20200101T000000Z-old.git"));
      const r = runPurge(h, ["--older-than", "30d"]);
      assert.equal(r.status, 3, `stderr=${r.stderr}`);
      assert.match(r.stderr, /not permitted to purge trash/);
      // Nothing was deleted — the denial happened before any fs work.
      assert.equal(existsSync(path.join(h.trashDir, "20200101T000000Z-old.git")), true);
    } finally {
      h.cleanup();
    }
  });

  it("refuses when SSH_USER_AUTH is unset (exit 1)", () => {
    const h = setup({ line: ADMIN_SSH_LINE, fp: ADMIN_SSH_FP, role: "admin" });
    try {
      const r = runPurge(h, ["--older-than", "30d"], { withAuth: false });
      assert.equal(r.status, 1, `stderr=${r.stderr}`);
      assert.match(r.stderr, /authenticated identity/);
    } finally {
      h.cleanup();
    }
  });

  it("an admin caller purges old trash (exit 0) and keeps recent", () => {
    const h = setup({ line: ADMIN_SSH_LINE, fp: ADMIN_SSH_FP, role: "admin" });
    try {
      mkdirSync(path.join(h.trashDir, "20200101T000000Z-old.git"));
      mkdirSync(path.join(h.trashDir, "20991231T235959Z-future.git")); // far future → kept
      const r = runPurge(h, ["--older-than", "30d"]);
      assert.equal(r.status, 0, `stderr=${r.stderr}`);
      assert.match(r.stderr, /purged 1 trashed repo/);
      assert.equal(existsSync(path.join(h.trashDir, "20200101T000000Z-old.git")), false);
      assert.equal(existsSync(path.join(h.trashDir, "20991231T235959Z-future.git")), true);
    } finally {
      h.cleanup();
    }
  });

  it("rejects a malformed --older-than (exit 2) before auth/fs", () => {
    const h = setup({ line: ADMIN_SSH_LINE, fp: ADMIN_SSH_FP, role: "admin" });
    try {
      const r = runPurge(h, ["--older-than", "soon"]);
      assert.equal(r.status, 2, `stderr=${r.stderr}`);
      assert.match(r.stderr, /must be '<N>d'/);
    } finally {
      h.cleanup();
    }
  });
});
