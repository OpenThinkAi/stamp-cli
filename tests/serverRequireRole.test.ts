/**
 * AGT-2259 — role gate for the repo-management SSH verbs.
 *
 * Every SSH user runs the git-shell-commands verbs as the one Unix user
 * `git`, so before this fix any enrolled key (role=member included) could
 * create, delete, `--purge` or restore any repo on the server. Two layers
 * are covered here:
 *
 *   1. `stamp-require-role` (src/server/require-role.ts), spawned via tsx
 *      with a faked SSH_USER_AUTH + temp users.db — same harness shape as
 *      serverPurgeTrash.test.ts.
 *   2. The shell verbs themselves (server/{new,delete,restore}-stamp-repo),
 *      run against a temp git root with the gate path pointed at a stub.
 *      The scripts hardcode /usr/local/sbin/stamp-require-role and /srv/git
 *      (no env seam a remote caller could steer), so the test rewrites those
 *      literals in a temp copy. This proves each verb calls the gate and
 *      exits with its code BEFORE touching a live or trashed repo.
 *
 * The end-to-end over-real-SSH check (member refused, admin admitted) lives
 * in scripts/docker-boot-smoke.sh.
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { insertUser, openServerDb, type Role } from "../src/lib/serverDb.ts";

const ROOT = path.resolve(import.meta.dirname, "..");
const REQUIRE_ROLE_TS = path.join(ROOT, "src", "server", "require-role.ts");
const GATE_PATH = "/usr/local/sbin/stamp-require-role";

const ADMIN_SSH_LINE =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO0fHPCBttt9fiLYtDixe2+eGATWUa+BiRi7V5B7Bc7b admin@host";
const ADMIN_SSH_FP = "SHA256:ULy/G0aXU8CnDHhJe9uePIDwgzzNp16KH4b5LxLR/+k";
const MEMBER_SSH_LINE =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0fH9hWlMnH5o3iZqIDe9DTKQUyfPnEHpJfntZjEbka member@host";
const MEMBER_SSH_FP = "SHA256:JjZxN+NVk11skR8NQvPgkbYR8jF4UT4Zy/xtptZF52w";

// ---------------------------------------------------------------------------
// 1. stamp-require-role
// ---------------------------------------------------------------------------

function runGate(
  caller: { line: string; fp: string; role: Role } | null,
  args: string[],
  opts: { enrolled?: boolean } = {},
): { status: number | null; stderr: string } {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-require-role-"));
  try {
    const dbPath = path.join(dir, "users.db");
    const authPath = path.join(dir, "ssh_user_auth");
    const db = openServerDb({ path: dbPath, skipChmod: true });
    try {
      if (caller && opts.enrolled !== false) {
        insertUser(db, {
          short_name: "caller",
          ssh_pubkey: caller.line,
          ssh_fp: caller.fp,
          role: caller.role,
          source: "env",
        });
      }
    } finally {
      db.close();
    }
    const env: Record<string, string | undefined> = {
      ...process.env,
      STAMP_SERVER_DB_PATH: dbPath,
      SSH_USER_AUTH: undefined,
    };
    if (caller) {
      writeFileSync(authPath, `publickey ${caller.line}\n`, { mode: 0o600 });
      env["SSH_USER_AUTH"] = authPath;
    }
    const r = spawnSync(process.execPath, ["--import", "tsx", REQUIRE_ROLE_TS, ...args], {
      env: env as NodeJS.ProcessEnv,
      encoding: "utf8",
    });
    return { status: r.status, stderr: r.stderr ?? "" };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const member = { line: MEMBER_SSH_LINE, fp: MEMBER_SSH_FP, role: "member" as Role };
const admin = { line: ADMIN_SSH_LINE, fp: ADMIN_SSH_FP, role: "admin" as Role };
const owner = { line: ADMIN_SSH_LINE, fp: ADMIN_SSH_FP, role: "owner" as Role };

describe("stamp-require-role (AGT-2259)", () => {
  it("refuses a member with exit 3 and names the action", () => {
    const r = runGate(member, ["admin", "delete repos"]);
    assert.equal(r.status, 3, r.stderr);
    assert.match(r.stderr, /role member is not permitted to delete repos; need owner or admin/);
  });

  it("admits an admin and an owner at min=admin", () => {
    assert.equal(runGate(admin, ["admin", "delete repos"]).status, 0);
    assert.equal(runGate(owner, ["admin", "delete repos"]).status, 0);
  });

  it("min=owner refuses an admin (exit 3) and admits an owner", () => {
    const r = runGate(admin, ["owner", "do owner things"]);
    assert.equal(r.status, 3, r.stderr);
    assert.match(r.stderr, /need owner\./);
    assert.equal(runGate(owner, ["owner", "do owner things"]).status, 0);
  });

  it("refuses with exit 1 when SSH_USER_AUTH is unset", () => {
    const r = runGate(null, ["admin", "delete repos"]);
    assert.equal(r.status, 1, r.stderr);
    assert.match(r.stderr, /authenticated identity/);
  });

  it("refuses with exit 1 when the caller's key isn't enrolled", () => {
    const r = runGate(admin, ["admin", "delete repos"], { enrolled: false });
    assert.equal(r.status, 1, r.stderr);
    assert.match(r.stderr, /not in the membership DB/);
  });

  it("rejects bad usage with exit 2 (never a silent pass)", () => {
    assert.equal(runGate(admin, []).status, 2);
    assert.equal(runGate(admin, ["member", "x"]).status, 2);
    assert.equal(runGate(admin, ["admin"]).status, 2);
    assert.equal(runGate(admin, ["admin", "x", "extra"]).status, 2);
  });
});

// ---------------------------------------------------------------------------
// 2. The shell verbs call the gate before touching /srv/git
// ---------------------------------------------------------------------------

interface ShellHarness {
  gitRoot: string;
  trashDir: string;
  gateLog: string;
  run: (verb: string, args: string[], gateRc: number) => { status: number | null; stderr: string };
  cleanup: () => void;
}

function shellHarness(): ShellHarness {
  const dir = realpathSync(mkdtempSync(path.join(os.tmpdir(), "stamp-verb-gate-")));
  const gitRoot = path.join(dir, "git");
  const trashDir = path.join(gitRoot, ".trash");
  const etcStamp = path.join(dir, "etc-stamp");
  const gateLog = path.join(dir, "gate.log");
  const stub = path.join(dir, "stub-require-role");
  mkdirSync(trashDir, { recursive: true });
  mkdirSync(etcStamp);
  writeFileSync(
    stub,
    `#!/bin/sh\nprintf '%s\\n' "$*" >> "${gateLog}"\nexit "$STUB_GATE_RC"\n`,
  );
  chmodSync(stub, 0o755);

  const run = (verb: string, args: string[], gateRc: number) => {
    const src = readFileSync(path.join(ROOT, "server", verb), "utf8");
    assert.ok(src.includes(GATE_PATH), `${verb} must call ${GATE_PATH}`);
    const rewritten = src
      .split(GATE_PATH)
      .join(stub)
      .split("/srv/git")
      .join(gitRoot)
      .split("/etc/stamp")
      .join(etcStamp);
    const script = path.join(dir, verb);
    writeFileSync(script, rewritten);
    const r = spawnSync("sh", [script, ...args], {
      encoding: "utf8",
      env: { ...process.env, STUB_GATE_RC: String(gateRc) },
    });
    return { status: r.status, stderr: r.stderr ?? "" };
  };

  return {
    gitRoot,
    trashDir,
    gateLog,
    run,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

const TRASHED = "20200101T000000Z-victim.git";

function seedVictim(h: ShellHarness): void {
  mkdirSync(path.join(h.gitRoot, "victim.git"));
  mkdirSync(path.join(h.trashDir, TRASHED));
}

describe("repo verbs are role-gated (AGT-2259)", () => {
  it("delete-stamp-repo: denial (exit 3) leaves the live repo", () => {
    const h = shellHarness();
    try {
      seedVictim(h);
      const r = h.run("delete-stamp-repo", ["victim"], 3);
      assert.equal(r.status, 3, r.stderr);
      assert.ok(existsSync(path.join(h.gitRoot, "victim.git")));
      assert.match(readFileSync(h.gateLog, "utf8"), /^admin delete repo 'victim'$/m);
    } finally {
      h.cleanup();
    }
  });

  it("delete-stamp-repo --purge: denial leaves the live repo AND its trash copy", () => {
    const h = shellHarness();
    try {
      seedVictim(h);
      const r = h.run("delete-stamp-repo", ["victim", "--purge"], 3);
      assert.equal(r.status, 3, r.stderr);
      assert.ok(existsSync(path.join(h.gitRoot, "victim.git")));
      assert.ok(existsSync(path.join(h.trashDir, TRASHED)));
      assert.match(readFileSync(h.gateLog, "utf8"), /^admin purge repo 'victim' \(irreversible\)$/m);
    } finally {
      h.cleanup();
    }
  });

  it("delete-stamp-repo: an identity failure (exit 1) also stops before any fs work", () => {
    const h = shellHarness();
    try {
      seedVictim(h);
      const r = h.run("delete-stamp-repo", ["victim", "--purge"], 1);
      assert.equal(r.status, 1, r.stderr);
      assert.ok(existsSync(path.join(h.gitRoot, "victim.git")));
      assert.ok(existsSync(path.join(h.trashDir, TRASHED)));
    } finally {
      h.cleanup();
    }
  });

  it("delete-stamp-repo: admitted caller soft-deletes, then purges", () => {
    const h = shellHarness();
    try {
      seedVictim(h);
      let r = h.run("delete-stamp-repo", ["victim"], 0);
      assert.equal(r.status, 0, r.stderr);
      assert.ok(!existsSync(path.join(h.gitRoot, "victim.git")));
      assert.equal(readdirSync(h.trashDir).filter((e) => e.endsWith("-victim.git")).length, 2);
      r = h.run("delete-stamp-repo", ["victim", "--purge"], 0);
      assert.equal(r.status, 0, r.stderr);
      assert.deepEqual(readdirSync(h.trashDir), []);
    } finally {
      h.cleanup();
    }
  });

  it("restore-stamp-repo: denial leaves the trash entry and creates nothing", () => {
    const h = shellHarness();
    try {
      mkdirSync(path.join(h.trashDir, TRASHED));
      const r = h.run("restore-stamp-repo", ["victim", "--as", "hijack"], 3);
      assert.equal(r.status, 3, r.stderr);
      assert.ok(existsSync(path.join(h.trashDir, TRASHED)));
      assert.ok(!existsSync(path.join(h.gitRoot, "hijack.git")));
      assert.match(readFileSync(h.gateLog, "utf8"), /^admin restore repo 'victim'$/m);
    } finally {
      h.cleanup();
    }
  });

  it("restore-stamp-repo: admitted caller restores", () => {
    const h = shellHarness();
    try {
      mkdirSync(path.join(h.trashDir, TRASHED));
      const r = h.run("restore-stamp-repo", ["victim"], 0);
      assert.equal(r.status, 0, r.stderr);
      assert.ok(existsSync(path.join(h.gitRoot, "victim.git")));
    } finally {
      h.cleanup();
    }
  });

  it("new-stamp-repo: denial exits 3 before creating anything", () => {
    const h = shellHarness();
    try {
      const r = h.run("new-stamp-repo", ["fresh"], 3);
      assert.equal(r.status, 3, r.stderr);
      assert.ok(!existsSync(path.join(h.gitRoot, "fresh.git")));
      assert.match(readFileSync(h.gateLog, "utf8"), /^admin create repo 'fresh'$/m);
    } finally {
      h.cleanup();
    }
  });

  it("new-stamp-repo: admitted caller proceeds past the gate", () => {
    const h = shellHarness();
    try {
      // No operator.pub in the temp /etc/stamp, so the script stops at its
      // next check — proving the gate let it through.
      const r = h.run("new-stamp-repo", ["fresh"], 0);
      assert.equal(r.status, 1, r.stderr);
      assert.match(r.stderr, /operator public key not found/);
    } finally {
      h.cleanup();
    }
  });

  it("the image installs the gate as a helper, not a git-shell verb", () => {
    const dockerfile = readFileSync(path.join(ROOT, "server", "Dockerfile"), "utf8");
    assert.match(dockerfile, /require-role\.cjs \/usr\/local\/sbin\/stamp-require-role/);
    assert.doesNotMatch(dockerfile, /git-shell-commands\/stamp-require-role/);
  });
});
