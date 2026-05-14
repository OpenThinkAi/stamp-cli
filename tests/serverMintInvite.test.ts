/**
 * End-to-end tests for the SSH-invoked mint-invite wrapper.
 *
 * The wrapper is `stamp-mint-invite <short_name> [--role admin|member]`,
 * invoked via git-shell against the server. Its identity binding goes
 * through SSH_USER_AUTH (an sshd-written file when ExposeAuthInfo yes is
 * set); we fake that file from the test side so the bundled script can
 * be exercised without an actual ssh connection.
 *
 * Spawns the unbundled TS via tsx so the test runs on the same code
 * the bundled .cjs ships in production — without needing a `npm run
 * build` step in the test loop.
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { findInvite } from "../src/lib/invites.ts";
import {
  insertUser,
  listUsers,
  openServerDb,
} from "../src/lib/serverDb.ts";

const MINT_INVITE_TS = path.resolve(
  import.meta.dirname,
  "..",
  "src",
  "server",
  "mint-invite.ts",
);

// Re-uses tests/sshKeys.test.ts fixture so the fingerprint is known.
const ADMIN_SSH_LINE =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO0fHPCBttt9fiLYtDixe2+eGATWUa+BiRi7V5B7Bc7b admin@host";
const ADMIN_SSH_FP = "SHA256:ULy/G0aXU8CnDHhJe9uePIDwgzzNp16KH4b5LxLR/+k";

const MEMBER_SSH_LINE =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0fH9hWlMnH5o3iZqIDe9DTKQUyfPnEHpJfntZjEbka member@host";
const MEMBER_SSH_FP = "SHA256:JjZxN+NVk11skR8NQvPgkbYR8jF4UT4Zy/xtptZF52w";

interface Harness {
  dbPath: string;
  authPath: string;
  cleanup: () => void;
}

function setup(callerRole: "owner" | "admin" | "member" | "none"): Harness {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-mint-"));
  const dbPath = path.join(dir, "users.db");
  const authPath = path.join(dir, "ssh_user_auth");

  if (callerRole !== "none") {
    const db = openServerDb({ path: dbPath, skipChmod: true });
    try {
      insertUser(db, {
        short_name: "caller",
        ssh_pubkey: ADMIN_SSH_LINE,
        ssh_fp: ADMIN_SSH_FP,
        role: callerRole,
        source: "env",
      });
    } finally {
      db.close();
    }
  }

  // sshd writes one line per successful auth method; we only need the
  // publickey one here. Format: "publickey <algo> <base64> <comment>".
  writeFileSync(authPath, `publickey ${ADMIN_SSH_LINE}\n`, { mode: 0o600 });

  return {
    dbPath,
    authPath,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function runMintInvite(
  harness: Harness,
  args: string[],
  envOverrides: Record<string, string> = {},
): { stdout: string; stderr: string; status: number | null } {
  const result = spawnSync(
    process.execPath,
    ["--import", "tsx", MINT_INVITE_TS, ...args],
    {
      env: {
        ...process.env,
        STAMP_SERVER_DB_PATH: harness.dbPath,
        SSH_USER_AUTH: harness.authPath,
        STAMP_PUBLIC_URL: "https://stamp.example.com",
        ...envOverrides,
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

describe("stamp-mint-invite — success path", () => {
  it("an admin caller mints a member invite and prints the share URL", () => {
    const h = setup("admin");
    try {
      const r = runMintInvite(h, ["bob", "--role", "member"]);
      assert.equal(r.status, 0, `stderr=${r.stderr}`);
      // stdout = single line, the share URL
      const url = r.stdout.trim();
      assert.match(url, /^stamp\+invite:\/\/stamp\.example\.com\/[A-Za-z0-9_-]{43}$/);
      // stderr carries the human-readable diagnostic
      assert.match(r.stderr, /minted invite for short_name=bob role=member/);
      // DB-side: an invite row exists for the printed token, expiry in the future.
      const token = url.split("/").pop()!;
      const db = openServerDb({ path: h.dbPath, readOnly: true });
      try {
        const row = findInvite(db, token);
        assert.ok(row);
        assert.equal(row.role, "member");
        assert.equal(row.consumed_at, null);
        assert.ok(row.expires_at > Math.floor(Date.now() / 1000));
      } finally {
        db.close();
      }
    } finally {
      h.cleanup();
    }
  });

  it("an owner caller can mint an admin invite", () => {
    const h = setup("owner");
    try {
      const r = runMintInvite(h, ["nancy", "--role", "admin"]);
      assert.equal(r.status, 0, `stderr=${r.stderr}`);
      assert.match(r.stderr, /role=admin/);
    } finally {
      h.cleanup();
    }
  });

  it("flips ?insecure=1 onto the URL when STAMP_PUBLIC_URL is http", () => {
    const h = setup("admin");
    try {
      const r = runMintInvite(h, ["dev-user"], {
        STAMP_PUBLIC_URL: "http://localhost:8080",
      });
      assert.equal(r.status, 0, `stderr=${r.stderr}`);
      const url = r.stdout.trim();
      assert.match(url, /^stamp\+invite:\/\/localhost:8080\/[A-Za-z0-9_-]{43}\?insecure=1$/);
    } finally {
      h.cleanup();
    }
  });
});

describe("stamp-mint-invite — authorization", () => {
  it("refuses when caller has role=member", () => {
    const h = setup("member");
    try {
      const r = runMintInvite(h, ["bob"]);
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /not permitted to mint invites/);
    } finally {
      h.cleanup();
    }
  });

  it("refuses admin minting --role admin (only owners may invite admins)", () => {
    // Strict authority matrix: admins can invite members only; inviting
    // admins is the same authority class as promoting members to admin,
    // which is owner-only. Was permissive in the original phase-2 cut
    // and tightened here.
    const h = setup("admin");
    try {
      const r = runMintInvite(h, ["nancy", "--role", "admin"]);
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /admins may only mint --role member/);
    } finally {
      h.cleanup();
    }
  });

  it("refuses when caller's SSH key isn't in the DB at all", () => {
    const h = setup("none");
    try {
      const r = runMintInvite(h, ["bob"]);
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /not in the membership DB/);
    } finally {
      h.cleanup();
    }
  });

  it("refuses when SSH_USER_AUTH is unset (no ExposeAuthInfo)", () => {
    const h = setup("admin");
    try {
      const r = spawnSync(
        process.execPath,
        ["--import", "tsx", MINT_INVITE_TS, "bob"],
        {
          env: {
            ...process.env,
            STAMP_SERVER_DB_PATH: h.dbPath,
            STAMP_PUBLIC_URL: "https://stamp.example.com",
            // Deliberately omit SSH_USER_AUTH
            SSH_USER_AUTH: undefined,
          } as NodeJS.ProcessEnv,
          encoding: "utf8",
        },
      );
      assert.notEqual(r.status, 0);
      assert.match(r.stderr ?? "", /authenticated identity/);
    } finally {
      h.cleanup();
    }
  });
});

describe("stamp-mint-invite — input validation", () => {
  it("rejects an invalid short_name shape", () => {
    const h = setup("admin");
    try {
      const r = runMintInvite(h, ["has spaces!"]);
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /invalid shape/);
    } finally {
      h.cleanup();
    }
  });

  it("rejects --role values other than admin/member", () => {
    const h = setup("admin");
    try {
      const r = runMintInvite(h, ["bob", "--role", "owner"]);
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /admin' or 'member/);
    } finally {
      h.cleanup();
    }
  });

  it("rejects a short_name that's already taken in the users table", () => {
    const h = setup("admin");
    try {
      // Pre-seed a user with the name we're about to invite — collision.
      const db = openServerDb({ path: h.dbPath, skipChmod: true });
      try {
        insertUser(db, {
          short_name: "bob",
          ssh_pubkey: MEMBER_SSH_LINE,
          ssh_fp: MEMBER_SSH_FP,
          role: "member",
          source: "manual",
        });
      } finally {
        db.close();
      }

      const r = runMintInvite(h, ["bob"]);
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /already in use/);
    } finally {
      h.cleanup();
    }
  });

  it("refuses to mint when STAMP_PUBLIC_URL is unset", () => {
    const h = setup("admin");
    try {
      const r = spawnSync(
        process.execPath,
        ["--import", "tsx", MINT_INVITE_TS, "bob"],
        {
          env: {
            ...process.env,
            STAMP_SERVER_DB_PATH: h.dbPath,
            SSH_USER_AUTH: h.authPath,
            // STAMP_PUBLIC_URL deliberately undefined
            STAMP_PUBLIC_URL: undefined,
          } as NodeJS.ProcessEnv,
          encoding: "utf8",
        },
      );
      assert.notEqual(r.status, 0);
      assert.match(r.stderr ?? "", /STAMP_PUBLIC_URL is not set/);

      // Sanity-check: no invite row was created in the DB.
      const db = openServerDb({ path: h.dbPath, readOnly: true });
      try {
        const users = listUsers(db);
        assert.equal(users.length, 1); // just the caller
      } finally {
        db.close();
      }
    } finally {
      h.cleanup();
    }
  });
});
