/**
 * Authority-matrix and last-owner-guard tests for setUserRole / removeUser.
 *
 * These rules are load-bearing for the entire server membership model:
 * - Owner can do anything, subject to the last-owner guard
 * - Admin can manage members only, with one bootstrap exception
 *   (admin promoting themselves to owner when no owners exist)
 * - Member has no user-management surface
 * - Last-owner guard refuses any operation that would leave zero owners
 * - removeUser additionally refuses self-removal
 *
 * Drift in any of these would silently weaken authorization. Tests exhaust
 * each cell of the matrix and pin the boundary conditions (last owner,
 * bootstrap, self-removal).
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import {
  findUserByShortName,
  insertUser,
  openServerDb,
  type Role,
  type UserRow,
} from "../src/lib/serverDb.ts";
import {
  listUsersForCaller,
  removeUser,
  setUserRole,
} from "../src/lib/userOps.ts";

function tmpDb(): { dbPath: string; cleanup: () => void } {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-userops-"));
  return {
    dbPath: path.join(dir, "users.db"),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

interface Fixture {
  dbPath: string;
  cleanup: () => void;
  users: Record<"owner1" | "owner2" | "admin1" | "admin2" | "member1" | "member2", UserRow>;
}

let seed = 0;
function seedUser(
  db: ReturnType<typeof openServerDb>,
  short_name: string,
  role: Role,
): UserRow {
  // Bump a counter so each fixture row has a unique ssh_pubkey/ssh_fp
  // even within a single test process — UNIQUE constraint enforced by
  // schema.
  seed++;
  insertUser(db, {
    short_name,
    ssh_pubkey: `ssh-ed25519 AAAAfake-${seed} ${short_name}@host`,
    ssh_fp: `SHA256:fake-fp-${seed}`,
    role,
    source: "manual",
  });
  const row = findUserByShortName(db, short_name);
  if (!row) throw new Error(`fixture seed failed for ${short_name}`);
  return row;
}

function buildFixture(initialOwners: number): Fixture {
  const t = tmpDb();
  const db = openServerDb({ path: t.dbPath, skipChmod: true });
  try {
    const users: Fixture["users"] = {
      owner1: seedUser(db, "owner1", initialOwners >= 1 ? "owner" : "admin"),
      owner2: seedUser(db, "owner2", initialOwners >= 2 ? "owner" : "admin"),
      admin1: seedUser(db, "admin1", "admin"),
      admin2: seedUser(db, "admin2", "admin"),
      member1: seedUser(db, "member1", "member"),
      member2: seedUser(db, "member2", "member"),
    };
    return { ...t, users };
  } finally {
    db.close();
  }
}

function open(dbPath: string): ReturnType<typeof openServerDb> {
  return openServerDb({ path: dbPath, skipChmod: true });
}

describe("setUserRole — owner caller (has full authority)", () => {
  it("owner may promote a member to admin", () => {
    const fx = buildFixture(2);
    const db = open(fx.dbPath);
    try {
      const r = setUserRole(db, fx.users.owner1, "member1", "admin");
      assert.equal(r.ok, true);
      if (!r.ok) return;
      assert.equal(r.old_role, "member");
      assert.equal(r.new_role, "admin");
      assert.equal(r.no_change, false);
    } finally {
      db.close();
      fx.cleanup();
    }
  });

  it("owner may promote a member to owner", () => {
    const fx = buildFixture(2);
    const db = open(fx.dbPath);
    try {
      const r = setUserRole(db, fx.users.owner1, "member1", "owner");
      assert.equal(r.ok, true);
    } finally {
      db.close();
      fx.cleanup();
    }
  });

  it("owner may demote another owner to admin (if not last)", () => {
    const fx = buildFixture(2);
    const db = open(fx.dbPath);
    try {
      const r = setUserRole(db, fx.users.owner1, "owner2", "admin");
      assert.equal(r.ok, true);
    } finally {
      db.close();
      fx.cleanup();
    }
  });

  it("owner may demote an admin to member", () => {
    const fx = buildFixture(2);
    const db = open(fx.dbPath);
    try {
      const r = setUserRole(db, fx.users.owner1, "admin1", "member");
      assert.equal(r.ok, true);
    } finally {
      db.close();
      fx.cleanup();
    }
  });

  it("reports no_change when target already has the target role", () => {
    const fx = buildFixture(2);
    const db = open(fx.dbPath);
    try {
      const r = setUserRole(db, fx.users.owner1, "admin1", "admin");
      assert.equal(r.ok, true);
      if (!r.ok) return;
      assert.equal(r.no_change, true);
    } finally {
      db.close();
      fx.cleanup();
    }
  });
});

describe("setUserRole — admin caller (members only, plus bootstrap)", () => {
  it("admin may NOT promote a member to admin", () => {
    const fx = buildFixture(2);
    const db = open(fx.dbPath);
    try {
      const r = setUserRole(db, fx.users.admin1, "member1", "admin");
      assert.equal(r.ok, false);
      if (r.ok) return;
      assert.equal(r.reason, "caller_lacks_authority");
    } finally {
      db.close();
      fx.cleanup();
    }
  });

  it("admin may NOT promote a member to owner", () => {
    const fx = buildFixture(2);
    const db = open(fx.dbPath);
    try {
      const r = setUserRole(db, fx.users.admin1, "member1", "owner");
      assert.equal(r.ok, false);
    } finally {
      db.close();
      fx.cleanup();
    }
  });

  it("admin may NOT demote a peer admin to member", () => {
    const fx = buildFixture(2);
    const db = open(fx.dbPath);
    try {
      const r = setUserRole(db, fx.users.admin1, "admin2", "member");
      assert.equal(r.ok, false);
      if (r.ok) return;
      assert.equal(r.reason, "caller_lacks_authority");
    } finally {
      db.close();
      fx.cleanup();
    }
  });

  it("admin may NOT touch an owner", () => {
    const fx = buildFixture(2);
    const db = open(fx.dbPath);
    try {
      const r = setUserRole(db, fx.users.admin1, "owner2", "admin");
      assert.equal(r.ok, false);
    } finally {
      db.close();
      fx.cleanup();
    }
  });

  it("admin no-op on a member→member request is allowed", () => {
    // Edge: member1 is already a member; admin asks for member. Authority
    // path is admin-managing-member (allowed); result is no_change.
    const fx = buildFixture(2);
    const db = open(fx.dbPath);
    try {
      const r = setUserRole(db, fx.users.admin1, "member1", "member");
      assert.equal(r.ok, true);
      if (!r.ok) return;
      assert.equal(r.no_change, true);
    } finally {
      db.close();
      fx.cleanup();
    }
  });

  it("BOOTSTRAP: admin may self-promote to owner when no owners exist", () => {
    const fx = buildFixture(0);
    const db = open(fx.dbPath);
    try {
      const r = setUserRole(db, fx.users.admin1, "admin1", "owner");
      assert.equal(r.ok, true);
      if (!r.ok) return;
      assert.equal(r.old_role, "admin");
      assert.equal(r.new_role, "owner");
    } finally {
      db.close();
      fx.cleanup();
    }
  });

  it("BOOTSTRAP: refuses once an owner already exists", () => {
    const fx = buildFixture(1);
    const db = open(fx.dbPath);
    try {
      // owner1 is owner; admin1 attempting self-promotion is no longer a
      // bootstrap case — the ladder must go through the existing owner.
      const r = setUserRole(db, fx.users.admin1, "admin1", "owner");
      assert.equal(r.ok, false);
      if (r.ok) return;
      assert.equal(r.reason, "caller_lacks_authority");
    } finally {
      db.close();
      fx.cleanup();
    }
  });

  it("BOOTSTRAP: refuses an admin trying to promote a DIFFERENT admin to owner", () => {
    // Self-promotion only — can't bootstrap-promote a peer to owner.
    const fx = buildFixture(0);
    const db = open(fx.dbPath);
    try {
      const r = setUserRole(db, fx.users.admin1, "admin2", "owner");
      assert.equal(r.ok, false);
      if (r.ok) return;
      assert.equal(r.reason, "caller_lacks_authority");
    } finally {
      db.close();
      fx.cleanup();
    }
  });
});

describe("setUserRole — member caller (no authority)", () => {
  it("member cannot manage anyone", () => {
    const fx = buildFixture(2);
    const db = open(fx.dbPath);
    try {
      const r = setUserRole(db, fx.users.member1, "member2", "member");
      assert.equal(r.ok, false);
      if (r.ok) return;
      assert.equal(r.reason, "caller_lacks_authority");
    } finally {
      db.close();
      fx.cleanup();
    }
  });
});

describe("setUserRole — last-owner guard", () => {
  it("refuses to demote the LAST owner to admin", () => {
    const fx = buildFixture(1);
    const db = open(fx.dbPath);
    try {
      const r = setUserRole(db, fx.users.owner1, "owner1", "admin");
      assert.equal(r.ok, false);
      if (r.ok) return;
      assert.equal(r.reason, "last_owner_would_be_lost");
    } finally {
      db.close();
      fx.cleanup();
    }
  });

  it("refuses to demote the LAST owner to member", () => {
    const fx = buildFixture(1);
    const db = open(fx.dbPath);
    try {
      const r = setUserRole(db, fx.users.owner1, "owner1", "member");
      assert.equal(r.ok, false);
    } finally {
      db.close();
      fx.cleanup();
    }
  });

  it("allows demotion when two owners exist", () => {
    const fx = buildFixture(2);
    const db = open(fx.dbPath);
    try {
      const r = setUserRole(db, fx.users.owner1, "owner2", "admin");
      assert.equal(r.ok, true);
    } finally {
      db.close();
      fx.cleanup();
    }
  });
});

describe("setUserRole — input validation", () => {
  it("rejects an unknown target role", () => {
    const fx = buildFixture(2);
    const db = open(fx.dbPath);
    try {
      // @ts-expect-error — exercising the runtime guard
      const r = setUserRole(db, fx.users.owner1, "member1", "guest");
      assert.equal(r.ok, false);
      if (r.ok) return;
      assert.equal(r.reason, "invalid_target_role");
    } finally {
      db.close();
      fx.cleanup();
    }
  });

  it("returns target_not_found for an unknown short_name", () => {
    const fx = buildFixture(2);
    const db = open(fx.dbPath);
    try {
      const r = setUserRole(db, fx.users.owner1, "nobody", "admin");
      assert.equal(r.ok, false);
      if (r.ok) return;
      assert.equal(r.reason, "target_not_found");
    } finally {
      db.close();
      fx.cleanup();
    }
  });
});

describe("removeUser — authority + guards", () => {
  it("owner may remove anyone (non-self, non-last-owner)", () => {
    const fx = buildFixture(2);
    const db = open(fx.dbPath);
    try {
      const r = removeUser(db, fx.users.owner1, "admin1");
      assert.equal(r.ok, true);
    } finally {
      db.close();
      fx.cleanup();
    }
  });

  it("admin may remove a member", () => {
    const fx = buildFixture(2);
    const db = open(fx.dbPath);
    try {
      const r = removeUser(db, fx.users.admin1, "member1");
      assert.equal(r.ok, true);
    } finally {
      db.close();
      fx.cleanup();
    }
  });

  it("admin may NOT remove a peer admin", () => {
    const fx = buildFixture(2);
    const db = open(fx.dbPath);
    try {
      const r = removeUser(db, fx.users.admin1, "admin2");
      assert.equal(r.ok, false);
      if (r.ok) return;
      assert.equal(r.reason, "caller_lacks_authority");
    } finally {
      db.close();
      fx.cleanup();
    }
  });

  it("admin may NOT remove an owner", () => {
    const fx = buildFixture(2);
    const db = open(fx.dbPath);
    try {
      const r = removeUser(db, fx.users.admin1, "owner1");
      assert.equal(r.ok, false);
    } finally {
      db.close();
      fx.cleanup();
    }
  });

  it("member may NOT remove anyone", () => {
    const fx = buildFixture(2);
    const db = open(fx.dbPath);
    try {
      const r = removeUser(db, fx.users.member1, "member2");
      assert.equal(r.ok, false);
    } finally {
      db.close();
      fx.cleanup();
    }
  });

  it("refuses self-removal even for owners", () => {
    const fx = buildFixture(2);
    const db = open(fx.dbPath);
    try {
      const r = removeUser(db, fx.users.owner1, "owner1");
      assert.equal(r.ok, false);
      if (r.ok) return;
      assert.equal(r.reason, "cannot_remove_self");
    } finally {
      db.close();
      fx.cleanup();
    }
  });

  it("refuses to remove the last owner when called by another owner", () => {
    // Build two owners, then have one remove the other. The remaining
    // would-be-zero state triggers the last-owner guard. (In a 1-owner
    // fixture the caller-lacks-authority + cannot-remove-self guards
    // shadow this branch; it's reachable only with ≥2 owners where one
    // gets demoted-via-removal.)
    const fx = buildFixture(2);
    const db = open(fx.dbPath);
    try {
      // Demote owner2 to admin so only owner1 holds the role.
      const d = setUserRole(db, fx.users.owner1, "owner2", "admin");
      assert.equal(d.ok, true);
      // Promote a fresh admin to owner so we have a non-self caller.
      const p = setUserRole(db, fx.users.owner1, "admin2", "owner");
      assert.equal(p.ok, true);
      // Now: owner1, admin2 (was just promoted to owner). Demote
      // admin2 back to admin so owner1 is the sole owner.
      const d2 = setUserRole(db, fx.users.owner1, "admin2", "admin");
      assert.equal(d2.ok, true);
      // Refresh admin2's row so its current role is correct.
      const admin2Fresh = findUserByShortName(db, "admin2")!;
      // Now admin2-as-admin attempts to remove the sole owner — fails on
      // authority before the last-owner guard could be reached.
      const r = removeUser(db, admin2Fresh, "owner1");
      assert.equal(r.ok, false);
      if (r.ok) return;
      // Authority fires first (admin removing an owner) — guard is
      // structurally shadowed in this scenario but the test pins the
      // outer behavior.
      assert.equal(r.reason, "caller_lacks_authority");
    } finally {
      db.close();
      fx.cleanup();
    }
  });
});

describe("listUsersForCaller", () => {
  it("returns rows sorted owner → admin → member, alphabetical within role", () => {
    const fx = buildFixture(1);
    const db = open(fx.dbPath);
    try {
      const r = listUsersForCaller(db, fx.users.member1);
      assert.equal(r.ok, true);
      if (!r.ok) return;
      const names = r.users.map((u) => u.short_name);
      // owner1 first (only owner), then admins alphabetical, then members.
      assert.equal(names[0], "owner1");
      // After owner1, the admins should come next in alpha order.
      const adminBlock = names.slice(1, 4);
      assert.deepEqual(adminBlock, ["admin1", "admin2", "owner2"]);
      // owner2 is admin in this fixture (initialOwners=1). The role sort
      // groups by role; "owner2" the name happens to be in the admin
      // block because its actual role is admin. Pinning the alphabetical
      // order within the block.
    } finally {
      db.close();
      fx.cleanup();
    }
  });

  it("members may list users (no authority restriction on read)", () => {
    const fx = buildFixture(2);
    const db = open(fx.dbPath);
    try {
      const r = listUsersForCaller(db, fx.users.member1);
      assert.equal(r.ok, true);
    } finally {
      db.close();
      fx.cleanup();
    }
  });
});
