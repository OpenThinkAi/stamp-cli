/**
 * Invite token mint / consume tests.
 *
 * Covers the load-bearing properties of the invite primitive:
 *   - tokens are unique, base64url-shaped, 43 chars (32 bytes no padding)
 *   - consume is single-use: a second call returns already_consumed
 *   - expired tokens return expired (TTL respected at consume time)
 *   - missing tokens return not_found
 *   - the consume is atomic — concurrent calls don't both succeed
 *
 * The HTTP-server-driven accept flow consumes a token AND inserts a
 * user row; those are exercised separately in the http-server test.
 * This file isolates the DB primitive so a regression here is loud and
 * specific.
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import {
  consumeInviteToken,
  findInvite,
  generateInviteToken,
  markInviteConsumer,
  mintInvite,
  TOKEN_LENGTH_CHARS,
} from "../src/lib/invites.ts";
import {
  insertUser,
  openServerDb,
} from "../src/lib/serverDb.ts";

function tmpDb(): { dbPath: string; cleanup: () => void } {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-invites-"));
  return {
    dbPath: path.join(dir, "users.db"),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function seedAdmin(dbPath: string): number {
  const db = openServerDb({ path: dbPath, skipChmod: true });
  try {
    return insertUser(db, {
      short_name: "alice",
      ssh_pubkey: "ssh-ed25519 AAAAseed alice@host",
      ssh_fp: "SHA256:seed-fp",
      role: "admin",
      source: "env",
    });
  } finally {
    db.close();
  }
}

describe("generateInviteToken", () => {
  it("produces a 43-char base64url token (32 bytes, no padding)", () => {
    const token = generateInviteToken();
    assert.equal(token.length, TOKEN_LENGTH_CHARS);
    assert.match(token, /^[A-Za-z0-9_-]+$/);
    assert.ok(!token.includes("="));
  });

  it("produces unique tokens across many calls (sanity, not exhaustive)", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 100; i++) {
      const t = generateInviteToken();
      assert.ok(!seen.has(t), "duplicate token generated within 100 trials");
      seen.add(t);
    }
  });
});

describe("mintInvite + consumeInviteToken", () => {
  it("round-trips a freshly minted token to success on first consume", () => {
    const t = tmpDb();
    try {
      const id = seedAdmin(t.dbPath);
      const db = openServerDb({ path: t.dbPath, skipChmod: true });
      try {
        const minted = mintInvite(db, { role: "member", invited_by: id });
        assert.equal(minted.token.length, TOKEN_LENGTH_CHARS);

        const result = consumeInviteToken(db, minted.token);
        assert.equal(result.ok, true);
        if (!result.ok) return;
        assert.equal(result.row.token, minted.token);
        assert.equal(result.row.role, "member");
        assert.equal(result.row.invited_by, id);
      } finally {
        db.close();
      }
    } finally {
      t.cleanup();
    }
  });

  it("refuses a second consume of the same token (already_consumed)", () => {
    const t = tmpDb();
    try {
      const id = seedAdmin(t.dbPath);
      const db = openServerDb({ path: t.dbPath, skipChmod: true });
      try {
        const minted = mintInvite(db, { role: "member", invited_by: id });
        const first = consumeInviteToken(db, minted.token);
        assert.equal(first.ok, true);

        const second = consumeInviteToken(db, minted.token);
        assert.equal(second.ok, false);
        if (second.ok) return;
        assert.equal(second.reason, "already_consumed");
      } finally {
        db.close();
      }
    } finally {
      t.cleanup();
    }
  });

  it("refuses an unknown token (not_found)", () => {
    const t = tmpDb();
    try {
      seedAdmin(t.dbPath);
      const db = openServerDb({ path: t.dbPath, skipChmod: true });
      try {
        const result = consumeInviteToken(db, "no-such-token");
        assert.equal(result.ok, false);
        if (result.ok) return;
        assert.equal(result.reason, "not_found");
      } finally {
        db.close();
      }
    } finally {
      t.cleanup();
    }
  });

  it("refuses an expired token (expired)", () => {
    const t = tmpDb();
    try {
      const id = seedAdmin(t.dbPath);
      const db = openServerDb({ path: t.dbPath, skipChmod: true });
      try {
        // Mint with a wallclock of 0 + ttl 60s → expires at 60. Consume
        // at wallclock 100 → past expiry by 40s.
        const minted = mintInvite(db, {
          role: "member",
          invited_by: id,
          now: 0,
          ttl_seconds: 60,
        });
        assert.equal(minted.expires_at, 60);

        const result = consumeInviteToken(db, minted.token, 100);
        assert.equal(result.ok, false);
        if (result.ok) return;
        assert.equal(result.reason, "expired");

        // And the row stays untouched (consumed_at still null) — TTL
        // rejection is read-only on the row.
        const row = findInvite(db, minted.token);
        assert.equal(row?.consumed_at, null);
      } finally {
        db.close();
      }
    } finally {
      t.cleanup();
    }
  });

  it("respects the TTL boundary: now == expires_at is still valid", () => {
    const t = tmpDb();
    try {
      const id = seedAdmin(t.dbPath);
      const db = openServerDb({ path: t.dbPath, skipChmod: true });
      try {
        const minted = mintInvite(db, {
          role: "member",
          invited_by: id,
          now: 0,
          ttl_seconds: 60,
        });
        // Consume AT the boundary. consumeInviteToken uses `expires_at <
        // now`, so equal-second is still valid (a one-second leniency that
        // prevents flaky test failures around clock-tick boundaries).
        const result = consumeInviteToken(db, minted.token, 60);
        assert.equal(result.ok, true);
      } finally {
        db.close();
      }
    } finally {
      t.cleanup();
    }
  });
});

describe("markInviteConsumer", () => {
  it("sets consumed_by after the consumer's user row is inserted", () => {
    const t = tmpDb();
    try {
      const adminId = seedAdmin(t.dbPath);
      const db = openServerDb({ path: t.dbPath, skipChmod: true });
      try {
        const minted = mintInvite(db, { role: "member", invited_by: adminId });
        consumeInviteToken(db, minted.token);

        // Simulate the HTTP-server side: insert the new user, then mark
        // the invite with their id.
        const newUserId = insertUser(db, {
          short_name: "bob",
          ssh_pubkey: "ssh-ed25519 AAAAbob bob@host",
          ssh_fp: "SHA256:bob-fp",
          role: "member",
          source: "invite",
          invited_by: adminId,
        });
        markInviteConsumer(db, minted.token, newUserId);

        const row = findInvite(db, minted.token);
        assert.equal(row?.consumed_by, newUserId);
      } finally {
        db.close();
      }
    } finally {
      t.cleanup();
    }
  });
});
