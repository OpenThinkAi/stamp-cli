/**
 * AGT-2252: per-user repo grants that bind the caller-chosen
 * `--org`/`--repo` on `stamp-review` to the caller's authorization.
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import {
  addRepoGrant,
  isCallerAuthorizedForOrg,
  listRepoGrants,
  parseRepoSpec,
  resolveRepoAccess,
} from "../src/lib/repoAccess.ts";
import { findUserByShortName, insertUser, openServerDb, type Role } from "../src/lib/serverDb.ts";
import { listRepoGrantsForCaller, removeUser, setRepoGrant } from "../src/lib/userOps.ts";

function withDb(fn: (db: ReturnType<typeof openServerDb>) => void): void {
  const dir = mkdtempSync(path.join(os.tmpdir(), "repo-access-"));
  const db = openServerDb({ path: path.join(dir, "users.db"), skipChmod: true });
  try {
    fn(db);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

let seq = 0;
function addUser(db: ReturnType<typeof openServerDb>, name: string, role: Role) {
  seq++;
  insertUser(db, {
    short_name: name,
    ssh_pubkey: `ssh-ed25519 AAAA${seq} ${name}`,
    ssh_fp: `SHA256:fixture-${name}-${seq}`,
    role,
    source: "manual",
  });
  return findUserByShortName(db, name)!;
}

describe("parseRepoSpec", () => {
  it("accepts org/repo and org/*, lowercasing", () => {
    assert.deepEqual(parseRepoSpec("Acme/Widget.co"), { org: "acme", repo: "widget.co" });
    assert.deepEqual(parseRepoSpec("acme/*"), { org: "acme", repo: "*" });
  });
  it("rejects malformed specs", () => {
    for (const bad of ["acme", "acme/", "/repo", "a/b/c", "*/repo", "acme/../x", "-x/y", "acme/re po"]) {
      assert.equal(parseRepoSpec(bad), null, bad);
    }
  });
});

describe("resolveRepoAccess", () => {
  it("owners and admins are operators", () => {
    withDb((db) => {
      assert.equal(resolveRepoAccess(db, addUser(db, "o", "owner"), "x", "y"), "operator");
      assert.equal(resolveRepoAccess(db, addUser(db, "a", "admin"), "x", "y"), "operator");
    });
  });

  it("member: unscoped with no grants, granted on match, denied otherwise", () => {
    withDb((db) => {
      const m = addUser(db, "m", "member");
      assert.equal(resolveRepoAccess(db, m, "Sandbox", "Play"), "unscoped");
      addRepoGrant(db, m.id, "Acme", "Prod", null);
      assert.equal(resolveRepoAccess(db, m, "acme", "prod"), "granted");
      assert.equal(resolveRepoAccess(db, m, "ACME", "PROD"), "granted");
      assert.equal(resolveRepoAccess(db, m, "Sandbox", "Play"), "denied");
      assert.equal(resolveRepoAccess(db, m, "acme", "other"), "denied");
      addRepoGrant(db, m.id, "acme", "*", null);
      assert.equal(resolveRepoAccess(db, m, "acme", "other"), "granted");
    });
  });

  it("isCallerAuthorizedForOrg reflects grants (reusable for SSE binding)", () => {
    withDb((db) => {
      const m = addUser(db, "m", "member");
      assert.equal(isCallerAuthorizedForOrg(db, m, "acme"), false);
      addRepoGrant(db, m.id, "acme", "prod", null);
      assert.equal(isCallerAuthorizedForOrg(db, m, "ACME"), true);
      assert.equal(isCallerAuthorizedForOrg(db, m, "sandbox"), false);
      assert.equal(isCallerAuthorizedForOrg(db, addUser(db, "a", "admin"), "anything"), true);
    });
  });
});

describe("setRepoGrant / listRepoGrantsForCaller", () => {
  it("only owners/admins may grant; only members can be granted; revoke removes", () => {
    withDb((db) => {
      const owner = addUser(db, "owner1", "owner");
      const admin = addUser(db, "admin1", "admin");
      const m = addUser(db, "mem1", "member");
      const m2 = addUser(db, "mem2", "member");

      assert.deepEqual(setRepoGrant(db, m2, "mem1", "acme/prod", "grant"), {
        ok: false,
        reason: "caller_lacks_authority",
      });
      assert.deepEqual(setRepoGrant(db, owner, "admin1", "acme/prod", "grant"), {
        ok: false,
        reason: "target_not_member",
      });
      assert.deepEqual(setRepoGrant(db, admin, "mem1", "nope", "grant"), {
        ok: false,
        reason: "invalid_repo_spec",
      });
      assert.deepEqual(setRepoGrant(db, admin, "ghost", "acme/prod", "grant"), {
        ok: false,
        reason: "target_not_found",
      });

      const g = setRepoGrant(db, admin, "mem1", "Acme/Prod", "grant");
      assert.deepEqual(g, { ok: true, org: "acme", repo: "prod", changed: true });
      assert.deepEqual(setRepoGrant(db, admin, "mem1", "acme/prod", "grant"), {
        ok: true,
        org: "acme",
        repo: "prod",
        changed: false,
      });
      assert.equal(listRepoGrants(db, m.id).length, 1);

      // Members may list their own grants only.
      const own = listRepoGrantsForCaller(db, m, "mem1");
      assert.ok(own.ok && own.grants.length === 1);
      assert.deepEqual(listRepoGrantsForCaller(db, m2, "mem1"), {
        ok: false,
        reason: "caller_lacks_authority",
      });

      assert.deepEqual(setRepoGrant(db, owner, "mem1", "acme/prod", "revoke"), {
        ok: true,
        org: "acme",
        repo: "prod",
        changed: true,
      });
      assert.equal(listRepoGrants(db, m.id).length, 0);
    });
  });

  it("removing a user cascades their grants", () => {
    withDb((db) => {
      const owner = addUser(db, "owner1", "owner");
      const m = addUser(db, "mem1", "member");
      addRepoGrant(db, m.id, "acme", "prod", owner.id);
      const r = removeUser(db, owner, "mem1");
      assert.ok(r.ok);
      const n = db.prepare("SELECT COUNT(*) AS n FROM user_repo_grants").get() as { n: number };
      assert.equal(n.n, 0);
    });
  });
});
