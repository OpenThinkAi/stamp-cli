/**
 * End-to-end tests for the SSH-invoked stamp-users dispatcher.
 *
 * Spawns the unbundled TS via tsx with a faked SSH_USER_AUTH file (same
 * harness shape as the mint-invite e2e tests) so identity binding is
 * exercised against the real readAuthenticatedPubkey path rather than
 * stubbed at the wrapper level.
 *
 * Exit-code contract (0..6) is consumed by src/commands/users.ts for
 * specific operator prose — tests assert specific codes so a divergence
 * silently routing errors to the wrong CLI prose is caught.
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import {
  findUserByShortName,
  insertUser,
  openServerDb,
  type Role,
} from "../src/lib/serverDb.ts";

const USERS_CLI_TS = path.resolve(
  import.meta.dirname,
  "..",
  "src",
  "server",
  "users-cli.ts",
);

// Two real ed25519 fixtures — pinned fingerprints cross-checked against
// ssh-keygen -lf in other tests.
const CALLER_SSH_LINE =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO0fHPCBttt9fiLYtDixe2+eGATWUa+BiRi7V5B7Bc7b caller@host";
const CALLER_SSH_FP = "SHA256:ULy/G0aXU8CnDHhJe9uePIDwgzzNp16KH4b5LxLR/+k";

const OTHER_SSH_LINE =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0fH9hWlMnH5o3iZqIDe9DTKQUyfPnEHpJfntZjEbka other@host";
const OTHER_SSH_FP = "SHA256:JjZxN+NVk11skR8NQvPgkbYR8jF4UT4Zy/xtptZF52w";

const EXIT = {
  OK: 0,
  CONFIG: 1,
  USAGE: 2,
  AUTHORITY: 3,
  NOT_FOUND: 4,
  LAST_OWNER: 5,
  CANNOT_REMOVE_SELF: 6,
} as const;

interface Harness {
  dbPath: string;
  authPath: string;
  cleanup: () => void;
}

function setup(callerRole: Role | "none"): Harness {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-users-cli-"));
  const dbPath = path.join(dir, "users.db");
  const authPath = path.join(dir, "ssh_user_auth");

  if (callerRole !== "none") {
    const db = openServerDb({ path: dbPath, skipChmod: true });
    try {
      insertUser(db, {
        short_name: "caller",
        ssh_pubkey: CALLER_SSH_LINE,
        ssh_fp: CALLER_SSH_FP,
        role: callerRole,
        source: "env",
      });
      // Seed a couple of other users to exercise the matrix.
      insertUser(db, {
        short_name: "other",
        ssh_pubkey: OTHER_SSH_LINE,
        ssh_fp: OTHER_SSH_FP,
        role: "member",
        source: "env",
      });
    } finally {
      db.close();
    }
  }

  writeFileSync(authPath, `publickey ${CALLER_SSH_LINE}\n`, { mode: 0o600 });

  return {
    dbPath,
    authPath,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function run(
  h: Harness,
  args: string[],
): { stdout: string; stderr: string; status: number | null } {
  const result = spawnSync(
    process.execPath,
    ["--import", "tsx", USERS_CLI_TS, ...args],
    {
      env: {
        ...process.env,
        STAMP_SERVER_DB_PATH: h.dbPath,
        SSH_USER_AUTH: h.authPath,
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

describe("stamp-users — list", () => {
  it("returns JSON with one entry per user (any role may call)", () => {
    const h = setup("member");
    try {
      const r = run(h, ["list"]);
      assert.equal(r.status, EXIT.OK, `stderr=${r.stderr}`);
      const payload = JSON.parse(r.stdout) as { users: unknown[] };
      assert.equal(payload.users.length, 2);
    } finally {
      h.cleanup();
    }
  });

  it("orders rows owner → admin → member", () => {
    const h = setup("admin");
    try {
      // Add an owner and another admin so the sort has something to do.
      const db = openServerDb({ path: h.dbPath, skipChmod: true });
      try {
        insertUser(db, {
          short_name: "the-owner",
          ssh_pubkey: "ssh-ed25519 AAAAown owner@host",
          ssh_fp: "SHA256:owner-fp",
          role: "owner",
          source: "manual",
        });
      } finally {
        db.close();
      }
      const r = run(h, ["list"]);
      assert.equal(r.status, EXIT.OK);
      const payload = JSON.parse(r.stdout) as {
        users: Array<{ short_name: string; role: Role }>;
      };
      // First entry must be the owner.
      assert.equal(payload.users[0]?.role, "owner");
      assert.equal(payload.users[0]?.short_name, "the-owner");
    } finally {
      h.cleanup();
    }
  });
});

describe("stamp-users — promote/demote", () => {
  it("owner can promote a member to admin", () => {
    const h = setup("owner");
    try {
      const r = run(h, ["promote", "other", "--to", "admin"]);
      assert.equal(r.status, EXIT.OK, `stderr=${r.stderr}`);
      assert.match(r.stderr, /member → admin/);

      const db = openServerDb({ path: h.dbPath, readOnly: true });
      try {
        const row = findUserByShortName(db, "other");
        assert.equal(row?.role, "admin");
      } finally {
        db.close();
      }
    } finally {
      h.cleanup();
    }
  });

  it("admin cannot promote a member to admin (returns AUTHORITY)", () => {
    const h = setup("admin");
    try {
      const r = run(h, ["promote", "other", "--to", "admin"]);
      assert.equal(r.status, EXIT.AUTHORITY);
      assert.match(r.stderr, /caller_lacks_authority/);
    } finally {
      h.cleanup();
    }
  });

  it("bootstrap: admin self-promotes to owner when none exist", () => {
    const h = setup("admin");
    try {
      const r = run(h, ["promote", "caller", "--to", "owner"]);
      assert.equal(r.status, EXIT.OK, `stderr=${r.stderr}`);
      assert.match(r.stderr, /admin → owner/);
    } finally {
      h.cleanup();
    }
  });

  it("owner demoting themselves when they're the last owner trips LAST_OWNER", () => {
    const h = setup("owner");
    try {
      const r = run(h, ["demote", "caller", "--to", "admin"]);
      assert.equal(r.status, EXIT.LAST_OWNER);
      assert.match(r.stderr, /last_owner_would_be_lost/);
    } finally {
      h.cleanup();
    }
  });

  it("returns NOT_FOUND for an unknown short_name", () => {
    const h = setup("owner");
    try {
      const r = run(h, ["promote", "nobody", "--to", "admin"]);
      assert.equal(r.status, EXIT.NOT_FOUND);
    } finally {
      h.cleanup();
    }
  });

  it("USAGE: rejects missing --to", () => {
    const h = setup("owner");
    try {
      const r = run(h, ["promote", "other"]);
      assert.equal(r.status, EXIT.USAGE);
    } finally {
      h.cleanup();
    }
  });

  it("USAGE: rejects promote --to member (only admin/owner valid for promote)", () => {
    const h = setup("owner");
    try {
      const r = run(h, ["promote", "other", "--to", "member"]);
      assert.equal(r.status, EXIT.USAGE);
    } finally {
      h.cleanup();
    }
  });

  it("USAGE: rejects demote --to owner (only admin/member valid for demote)", () => {
    const h = setup("owner");
    try {
      const r = run(h, ["demote", "other", "--to", "owner"]);
      assert.equal(r.status, EXIT.USAGE);
    } finally {
      h.cleanup();
    }
  });
});

describe("stamp-users — remove", () => {
  it("admin can remove a member", () => {
    const h = setup("admin");
    try {
      const r = run(h, ["remove", "other"]);
      assert.equal(r.status, EXIT.OK, `stderr=${r.stderr}`);
      const db = openServerDb({ path: h.dbPath, readOnly: true });
      try {
        assert.equal(findUserByShortName(db, "other"), null);
      } finally {
        db.close();
      }
    } finally {
      h.cleanup();
    }
  });

  it("returns CANNOT_REMOVE_SELF when the caller targets themselves", () => {
    const h = setup("owner");
    try {
      const r = run(h, ["remove", "caller"]);
      assert.equal(r.status, EXIT.CANNOT_REMOVE_SELF);
      assert.match(r.stderr, /cannot_remove_self/);
    } finally {
      h.cleanup();
    }
  });
});

describe("stamp-users — identity binding", () => {
  it("CONFIG: refuses when caller is not in the DB", () => {
    const h = setup("none");
    try {
      const r = run(h, ["list"]);
      assert.equal(r.status, EXIT.CONFIG);
      assert.match(r.stderr, /not in the membership DB/);
    } finally {
      h.cleanup();
    }
  });

  it("CONFIG: refuses when SSH_USER_AUTH is unset", () => {
    const h = setup("owner");
    try {
      const r = spawnSync(
        process.execPath,
        ["--import", "tsx", USERS_CLI_TS, "list"],
        {
          env: {
            ...process.env,
            STAMP_SERVER_DB_PATH: h.dbPath,
            SSH_USER_AUTH: undefined,
          } as NodeJS.ProcessEnv,
          encoding: "utf8",
        },
      );
      assert.equal(r.status, EXIT.CONFIG);
      assert.match(r.stderr ?? "", /authenticated identity/);
    } finally {
      h.cleanup();
    }
  });
});

describe("stamp-users — unknown subcommand", () => {
  it("returns USAGE for an unknown subcommand", () => {
    const h = setup("owner");
    try {
      const r = run(h, ["banhammer", "other"]);
      assert.equal(r.status, EXIT.USAGE);
      assert.match(r.stderr, /unknown subcommand/);
    } finally {
      h.cleanup();
    }
  });

  it("returns USAGE for no subcommand at all", () => {
    const h = setup("owner");
    try {
      const r = run(h, []);
      assert.equal(r.status, EXIT.USAGE);
    } finally {
      h.cleanup();
    }
  });
});
