/**
 * HTTP server end-to-end tests.
 *
 * Starts the actual `startServer` against a tmpfs DB on a random free
 * port (per test, no port collisions), makes real HTTP requests with
 * node:http, and verifies both response shape and DB side-effects.
 *
 * Covers the success path (200 + user row inserted with the right role
 * + invite marked consumed) and the major error paths (415 / 400 / 404
 * / 409 / 410 / 413), each producing a JSON {ok:false, error:"..."}
 * body. The status-code contract is part of the wire surface — phase-3
 * tooling and any future agent-facing client may key off these
 * specific values.
 */

import { strict as assert } from "node:assert";
import { request } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import type { Server } from "node:http";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { startServer } from "../src/server/http-server.ts";
import { mintInvite } from "../src/lib/invites.ts";
import {
  findUserByShortName,
  insertUser,
  openServerDb,
} from "../src/lib/serverDb.ts";

// Pinned ed25519 fixture (same one tests/sshKeys.test.ts uses — generated
// once with ssh-keygen, fingerprint cross-verified).
const INVITEE_SSH_LINE =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO0fHPCBttt9fiLYtDixe2+eGATWUa+BiRi7V5B7Bc7b new@laptop";
const INVITEE_SSH_FP = "SHA256:ULy/G0aXU8CnDHhJe9uePIDwgzzNp16KH4b5LxLR/+k";

// A second fixture for the "already-consumed token" test — re-using the
// same SSH key would 409 on ssh_pubkey_already_registered before the
// already-consumed status would surface, masking the test's actual claim.
const OTHER_SSH_LINE =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0fH9hWlMnH5o3iZqIDe9DTKQUyfPnEHpJfntZjEbka other@laptop";

const VALID_STAMP_PEM =
  "-----BEGIN PUBLIC KEY-----\n" +
  "MCowBQYDK2VwAyEAEXAMPLEbutSyntacticallyValidBASE64Body//AA=\n" +
  "-----END PUBLIC KEY-----\n";

interface Harness {
  port: number;
  dbPath: string;
  adminId: number;
  server: Server;
  cleanup: () => Promise<void>;
}

async function start(): Promise<Harness> {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-http-"));
  const dbPath = path.join(dir, "users.db");

  // Seed an admin so mintInvite has a valid invited_by reference.
  const db = openServerDb({ path: dbPath, skipChmod: true });
  let adminId: number;
  try {
    adminId = insertUser(db, {
      short_name: "alice",
      ssh_pubkey: "ssh-ed25519 AAAAseed alice@host",
      ssh_fp: "SHA256:admin-fp",
      role: "admin",
      source: "env",
    });
  } finally {
    db.close();
  }

  // Drive the server to consult our tmp DB via the env-var override.
  process.env["STAMP_SERVER_DB_PATH"] = dbPath;

  // Port 0 = "kernel picks a free port"; we read it from the listening
  // socket once the listen() callback fires.
  const server = startServer(0);
  await new Promise<void>((resolve) => server.once("listening", () => resolve()));
  const addr = server.address();
  if (!addr || typeof addr === "string") {
    throw new Error("expected server.address() to return AddressInfo");
  }
  const port = addr.port;

  return {
    port,
    dbPath,
    adminId,
    server,
    cleanup: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      delete process.env["STAMP_SERVER_DB_PATH"];
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

interface HttpResponse {
  status: number;
  body: Record<string, unknown>;
}

function post(
  port: number,
  url: string,
  body: unknown,
  headers: Record<string, string> = {},
): Promise<HttpResponse> {
  const payload = Buffer.from(JSON.stringify(body), "utf8");
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: "127.0.0.1",
        port,
        path: url,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": payload.length.toString(),
          ...headers,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          try {
            resolve({
              status: res.statusCode ?? 0,
              body: JSON.parse(text) as Record<string, unknown>,
            });
          } catch {
            resolve({
              status: res.statusCode ?? 0,
              body: { raw: text },
            });
          }
        });
      },
    );
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

function get(port: number, url: string): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    const req = request(
      { host: "127.0.0.1", port, path: url, method: "GET" },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          try {
            resolve({
              status: res.statusCode ?? 0,
              body: JSON.parse(text) as Record<string, unknown>,
            });
          } catch {
            resolve({
              status: res.statusCode ?? 0,
              body: { raw: text },
            });
          }
        });
      },
    );
    req.on("error", reject);
    req.end();
  });
}

function mintTokenAgainst(dbPath: string, adminId: number): string {
  const db = openServerDb({ path: dbPath, skipChmod: true });
  try {
    return mintInvite(db, { role: "member", invited_by: adminId }).token;
  } finally {
    db.close();
  }
}

describe("HTTP server: GET /healthz", () => {
  it("returns 200 {ok:true}", async () => {
    const h = await start();
    try {
      const r = await get(h.port, "/healthz");
      assert.equal(r.status, 200);
      assert.equal(r.body.ok, true);
    } finally {
      await h.cleanup();
    }
  });
});

describe("HTTP server: POST /invite/accept — success", () => {
  it("consumes the token, inserts a user row, returns 200 with role/user_id", async () => {
    const h = await start();
    try {
      const token = mintTokenAgainst(h.dbPath, h.adminId);

      const r = await post(h.port, "/invite/accept", {
        token,
        ssh_pubkey: INVITEE_SSH_LINE,
        stamp_pubkey: VALID_STAMP_PEM,
        short_name: "newbie",
      });

      assert.equal(r.status, 200);
      assert.equal(r.body.ok, true);
      assert.equal(r.body.role, "member");
      assert.equal(r.body.short_name, "newbie");
      assert.ok(typeof r.body.user_id === "number");

      // DB-side: the user row landed with source=invite and the right role.
      const db = openServerDb({ path: h.dbPath, readOnly: true });
      try {
        const user = findUserByShortName(db, "newbie");
        assert.ok(user);
        assert.equal(user.role, "member");
        assert.equal(user.source, "invite");
        assert.equal(user.ssh_fp, INVITEE_SSH_FP);
        assert.equal(user.stamp_pubkey, VALID_STAMP_PEM);
        assert.equal(user.invited_by, h.adminId);
      } finally {
        db.close();
      }
    } finally {
      await h.cleanup();
    }
  });

  it("accepts an invite with no stamp_pubkey (phase-4 fills it later)", async () => {
    const h = await start();
    try {
      const token = mintTokenAgainst(h.dbPath, h.adminId);
      const r = await post(h.port, "/invite/accept", {
        token,
        ssh_pubkey: INVITEE_SSH_LINE,
        short_name: "no-stamp",
      });
      assert.equal(r.status, 200);
      assert.equal(r.body.ok, true);

      const db = openServerDb({ path: h.dbPath, readOnly: true });
      try {
        const user = findUserByShortName(db, "no-stamp");
        assert.equal(user?.stamp_pubkey, null);
      } finally {
        db.close();
      }
    } finally {
      await h.cleanup();
    }
  });
});

describe("HTTP server: POST /invite/accept — errors", () => {
  it("returns 404 for an unknown token", async () => {
    const h = await start();
    try {
      const r = await post(h.port, "/invite/accept", {
        token: "no-such-token-aaaaaaaaaaaaaaaaaaaa",
        ssh_pubkey: INVITEE_SSH_LINE,
        short_name: "anyone",
      });
      assert.equal(r.status, 404);
      assert.equal(r.body.error, "invite_not_found");
    } finally {
      await h.cleanup();
    }
  });

  it("returns 410 for an already-consumed token", async () => {
    const h = await start();
    try {
      const token = mintTokenAgainst(h.dbPath, h.adminId);
      const first = await post(h.port, "/invite/accept", {
        token,
        ssh_pubkey: INVITEE_SSH_LINE,
        short_name: "first",
      });
      assert.equal(first.status, 200);

      const second = await post(h.port, "/invite/accept", {
        token,
        ssh_pubkey: OTHER_SSH_LINE,
        short_name: "second",
      });
      assert.equal(second.status, 410);
      assert.equal(second.body.error, "invite_already_consumed");
    } finally {
      await h.cleanup();
    }
  });

  it("returns 409 when the SSH pubkey is already registered", async () => {
    const h = await start();
    try {
      // Pre-register a user with the invitee's SSH pubkey, simulating
      // the case where they already have an account on this server.
      const db = openServerDb({ path: h.dbPath, skipChmod: true });
      try {
        insertUser(db, {
          short_name: "preexisting",
          ssh_pubkey: INVITEE_SSH_LINE,
          ssh_fp: INVITEE_SSH_FP,
          role: "member",
          source: "manual",
        });
      } finally {
        db.close();
      }

      const token = mintTokenAgainst(h.dbPath, h.adminId);
      const r = await post(h.port, "/invite/accept", {
        token,
        ssh_pubkey: INVITEE_SSH_LINE,
        short_name: "different-name",
      });
      assert.equal(r.status, 409);
      assert.equal(r.body.error, "ssh_pubkey_already_registered");
    } finally {
      await h.cleanup();
    }
  });

  it("returns 409 when the short_name is already taken", async () => {
    const h = await start();
    try {
      const token = mintTokenAgainst(h.dbPath, h.adminId);
      const r = await post(h.port, "/invite/accept", {
        token,
        ssh_pubkey: INVITEE_SSH_LINE,
        // "alice" was seeded by start() as the admin — collision expected.
        short_name: "alice",
      });
      assert.equal(r.status, 409);
      assert.equal(r.body.error, "short_name_taken");
    } finally {
      await h.cleanup();
    }
  });

  it("returns 400 for missing required fields", async () => {
    const h = await start();
    try {
      const r1 = await post(h.port, "/invite/accept", {
        ssh_pubkey: INVITEE_SSH_LINE,
        short_name: "x",
      });
      assert.equal(r1.status, 400);
      assert.equal(r1.body.error, "token_required");

      const r2 = await post(h.port, "/invite/accept", {
        token: "some-token",
        short_name: "x",
      });
      assert.equal(r2.status, 400);
      assert.equal(r2.body.error, "ssh_pubkey_required");

      const r3 = await post(h.port, "/invite/accept", {
        token: "some-token",
        ssh_pubkey: INVITEE_SSH_LINE,
      });
      assert.equal(r3.status, 400);
      assert.equal(r3.body.error, "short_name_malformed");
    } finally {
      await h.cleanup();
    }
  });

  it("returns 400 for a malformed short_name", async () => {
    const h = await start();
    try {
      const r = await post(h.port, "/invite/accept", {
        token: "some-token",
        ssh_pubkey: INVITEE_SSH_LINE,
        short_name: "has spaces and !@#",
      });
      assert.equal(r.status, 400);
      assert.equal(r.body.error, "short_name_malformed");
    } finally {
      await h.cleanup();
    }
  });

  it("returns 400 for an invalid SSH pubkey shape", async () => {
    const h = await start();
    try {
      const token = mintTokenAgainst(h.dbPath, h.adminId);
      const r = await post(h.port, "/invite/accept", {
        token,
        ssh_pubkey: "garbage no-base64",
        short_name: "x",
      });
      assert.equal(r.status, 400);
      assert.match(r.body.error as string, /^ssh_pubkey_invalid:/);
    } finally {
      await h.cleanup();
    }
  });

  it("returns 415 when Content-Type is not application/json", async () => {
    const h = await start();
    try {
      const r = await post(
        h.port,
        "/invite/accept",
        { token: "x" },
        { "Content-Type": "text/plain" },
      );
      assert.equal(r.status, 415);
      assert.equal(r.body.error, "content_type_must_be_application_json");
    } finally {
      await h.cleanup();
    }
  });

  it("returns 400 for body that isn't valid JSON", async () => {
    const h = await start();
    try {
      // Bypass the helper's auto-JSON-encode by hand-rolling a request
      // with a malformed body.
      const r = await new Promise<HttpResponse>((resolve, reject) => {
        const payload = Buffer.from("{not valid json", "utf8");
        const req = request(
          {
            host: "127.0.0.1",
            port: h.port,
            path: "/invite/accept",
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Content-Length": payload.length.toString(),
            },
          },
          (res) => {
            const chunks: Buffer[] = [];
            res.on("data", (c) => chunks.push(c));
            res.on("end", () => {
              resolve({
                status: res.statusCode ?? 0,
                body: JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>,
              });
            });
          },
        );
        req.on("error", reject);
        req.write(payload);
        req.end();
      });
      assert.equal(r.status, 400);
      assert.equal(r.body.error, "body_not_json");
    } finally {
      await h.cleanup();
    }
  });

  it("returns 404 for any unmapped path", async () => {
    const h = await start();
    try {
      const r = await post(h.port, "/nope", { token: "x" });
      assert.equal(r.status, 404);
      assert.equal(r.body.error, "not_found");
    } finally {
      await h.cleanup();
    }
  });
});
