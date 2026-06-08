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
import { createHash, createPublicKey, generateKeyPairSync } from "node:crypto";
import { request } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import type { Server } from "node:http";
import os from "node:os";
import path from "node:path";
import { describe, it, before, after } from "node:test";

import { startServer } from "../src/server/http-server.ts";
import { mintInvite } from "../src/lib/invites.ts";
import {
  findUserByShortName,
  insertPatch,
  insertUser,
  openServerDb,
} from "../src/lib/serverDb.ts";
import { signBytes } from "../src/lib/signing.ts";
import { canonicalSerializePeerPayload } from "../src/lib/attestationV4.ts";

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

  it("returns 413 when the body exceeds the 16 KiB cap", async () => {
    const h = await start();
    try {
      // Build a body big enough to trip the cap. JSON-shaped on purpose so
      // a mis-routed code path (e.g. accepting the body and then 400-ing
      // on JSON parse) would not coincidentally match the 413 contract.
      const padding = "a".repeat(20_000);
      const r = await post(h.port, "/invite/accept", {
        token: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
        ssh_pubkey: INVITEE_SSH_LINE,
        short_name: "padded",
        padding,
      });
      assert.equal(r.status, 413);
      assert.equal(r.body.error, "body_too_large");
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

// ─── POST /peer/* endpoint tests (AGT-453) ───────────────────────────────
//
// Tests the five new HTTP seat-protocol endpoints:
//   POST /peer/claim-seat
//   POST /peer/heartbeat
//   POST /peer/release-seat
//   POST /peer/re-review-request
//   POST /peer/register-extra
//
// Also includes the regression test for ssh-fp ≠ stamp-fp identity:
// migrating to HTTP makes identity uniformly stamp-fp; an enrolled user
// whose ssh_fp and stamp_fp differ should succeed on HTTP heartbeat.

// ─── Shared test key helpers ──────────────────────────────────────────

interface TestKeypair {
  privateKeyPem: string;
  publicKeyPem: string;
  fingerprint: string; // sha256:<hex> SPKI fingerprint
}

function genTestKeypair(): TestKeypair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }) as string;
  const spkiDer = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" }) as Buffer;
  const fingerprint = "sha256:" + createHash("sha256").update(spkiDer).digest("hex");
  return { privateKeyPem, publicKeyPem, fingerprint };
}

/**
 * Build the x-stamp-* auth headers for a POST /peer/<verb> request.
 * Mirrors the server's `postCanonicalBytes` + `authenticatePostRequest`.
 */
function buildPeerPostHeaders(
  kp: TestKeypair,
  verb: string,
  bodyJson: string,
): Record<string, string> {
  const timestamp = new Date().toISOString();
  const bodyHex = createHash("sha256").update(Buffer.from(bodyJson, "utf8")).digest("hex");
  const canonical = Buffer.from(`peer-${verb}\n${timestamp}\n${bodyHex}`, "utf8");
  const signature = signBytes(kp.privateKeyPem, canonical);
  return {
    "x-stamp-pubkey": Buffer.from(kp.publicKeyPem, "utf8").toString("base64"),
    "x-stamp-timestamp": timestamp,
    "x-stamp-signature": signature,
  };
}

// ─── Peer harness: startServer with STAMP_PEER_REVIEWS_ENABLED ───────

interface PeerHarness {
  port: number;
  dbPath: string;
  server: ReturnType<typeof startServer>;
  cleanup: () => Promise<void>;
}

async function startPeer(): Promise<PeerHarness> {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-peer-http-"));
  const dbPath = path.join(dir, "users.db");

  // Seed an admin user so we can insert patches etc.
  const db = openServerDb({ path: dbPath, skipChmod: true });
  try {
    insertUser(db, {
      short_name: "admin",
      ssh_pubkey: "ssh-ed25519 AAAAseed admin@host",
      ssh_fp: "SHA256:admin-fp",
      role: "admin",
      source: "env",
    });
  } finally {
    db.close();
  }

  process.env["STAMP_SERVER_DB_PATH"] = dbPath;
  process.env["STAMP_PEER_REVIEWS_ENABLED"] = "1";
  const server = startServer(0);
  await new Promise<void>((resolve) => server.once("listening", () => resolve()));
  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("bad address");
  const port = (addr as { port: number }).port;

  return {
    port,
    dbPath,
    server,
    cleanup: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      delete process.env["STAMP_SERVER_DB_PATH"];
      delete process.env["STAMP_PEER_REVIEWS_ENABLED"];
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** Insert an enrolled user (with stamp_pubkey) and a test patch row. */
function seedPeerUser(
  dbPath: string,
  kp: TestKeypair,
  shortName: string,
): number {
  const db = openServerDb({ path: dbPath, skipChmod: true });
  try {
    return insertUser(db, {
      short_name: shortName,
      ssh_pubkey: `ssh-ed25519 AAAASeed${shortName} ${shortName}@host`,
      ssh_fp: `SHA256:ssh-fp-${shortName}`,
      role: "member",
      source: "invite",
      stamp_pubkey: kp.publicKeyPem,
    });
  } finally {
    db.close();
  }
}

function seedPatch(
  dbPath: string,
  patchId: string,
  requestedByFp: string,
): void {
  const db = openServerDb({ path: dbPath, skipChmod: true });
  try {
    insertPatch(db, {
      patch_id: patchId,
      requested_by_fp: requestedByFp,
      base_sha: "0".repeat(40),
      head_sha: "1".repeat(40),
      repo: "acme/widget",
      pr_url: "https://github.com/acme/widget/pull/1",
    });
  } finally {
    db.close();
  }
}

// ─── POST /peer/claim-seat ────────────────────────────────────────────

describe("POST /peer/claim-seat: auth + success path (AGT-453)", () => {
  it("returns 401 with missing auth headers", async () => {
    const h = await startPeer();
    try {
      const r = await post(h.port, "/peer/claim-seat", {});
      assert.equal(r.status, 401);
    } finally {
      await h.cleanup();
    }
  });

  it("returns 404 when STAMP_PEER_REVIEWS_ENABLED is absent", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-peer-dark-"));
    const dbPath = path.join(dir, "users.db");
    process.env["STAMP_SERVER_DB_PATH"] = dbPath;
    delete process.env["STAMP_PEER_REVIEWS_ENABLED"];
    const db = openServerDb({ path: dbPath, skipChmod: true });
    db.close();
    const server = startServer(0);
    await new Promise<void>((resolve) => server.once("listening", () => resolve()));
    const addr = server.address() as { port: number };
    try {
      const r = await post(addr.port, "/peer/claim-seat", {});
      assert.equal(r.status, 404);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      delete process.env["STAMP_SERVER_DB_PATH"];
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("returns 200 on claim-seat success", async () => {
    const h = await startPeer();
    const authorKp = genTestKeypair();
    const reviewerKp = genTestKeypair();
    const patchId = "a".repeat(40);

    seedPeerUser(h.dbPath, authorKp, "author1");
    seedPeerUser(h.dbPath, reviewerKp, "reviewer1");
    seedPatch(h.dbPath, patchId, authorKp.fingerprint);

    try {
      const bodyPayload = {
        patch_id: patchId,
        claimant_fp: reviewerKp.fingerprint,
        base_sha: "0".repeat(40),
        repo: "acme/widget",
        pubkey: reviewerKp.publicKeyPem,
      };
      const bodyJson = JSON.stringify({
        ...bodyPayload,
        signature: signBytes(reviewerKp.privateKeyPem, canonicalSerializePeerPayload(bodyPayload)),
      });
      const headers = buildPeerPostHeaders(reviewerKp, "claim-seat", bodyJson);
      const r = await post(h.port, "/peer/claim-seat", JSON.parse(bodyJson), headers);
      assert.equal(r.status, 200, `expected 200, got ${r.status}: ${JSON.stringify(r.body)}`);
      assert.equal(r.body.ok, true);
      assert.ok(typeof r.body.seat === "number", "response should include seat number");
    } finally {
      await h.cleanup();
    }
  });

  it("returns 409 seats_full when both seats are taken", async () => {
    const h = await startPeer();
    const authorKp = genTestKeypair();
    const r1Kp = genTestKeypair();
    const r2Kp = genTestKeypair();
    const r3Kp = genTestKeypair();
    const patchId = "b".repeat(40);

    seedPeerUser(h.dbPath, authorKp, "author2");
    seedPeerUser(h.dbPath, r1Kp, "reviewer2a");
    seedPeerUser(h.dbPath, r2Kp, "reviewer2b");
    seedPeerUser(h.dbPath, r3Kp, "reviewer2c");
    seedPatch(h.dbPath, patchId, authorKp.fingerprint);

    // Claim both seats.
    const claimFor = async (kp: TestKeypair) => {
      const bodyPayload = { patch_id: patchId, claimant_fp: kp.fingerprint, base_sha: "0".repeat(40), repo: "acme/widget", pubkey: kp.publicKeyPem };
      const bodyJson = JSON.stringify({ ...bodyPayload, signature: signBytes(kp.privateKeyPem, canonicalSerializePeerPayload(bodyPayload)) });
      return post(h.port, "/peer/claim-seat", JSON.parse(bodyJson), buildPeerPostHeaders(kp, "claim-seat", bodyJson));
    };

    try {
      const r1 = await claimFor(r1Kp);
      assert.equal(r1.status, 200, "first claim should succeed");
      const r2 = await claimFor(r2Kp);
      assert.equal(r2.status, 200, "second claim should succeed");
      const r3 = await claimFor(r3Kp);
      assert.equal(r3.status, 409, "third claim should be rejected (seats_full)");
      assert.equal(r3.body.error, "seats_full");
    } finally {
      await h.cleanup();
    }
  });
});

// ─── POST /peer/heartbeat ─────────────────────────────────────────────

describe("POST /peer/heartbeat: success + 404 no-seat (AGT-453)", () => {
  it("returns 200 when seat holder sends heartbeat", async () => {
    const h = await startPeer();
    const authorKp = genTestKeypair();
    const reviewerKp = genTestKeypair();
    const patchId = "c".repeat(40);

    seedPeerUser(h.dbPath, authorKp, "author3");
    seedPeerUser(h.dbPath, reviewerKp, "reviewer3");
    seedPatch(h.dbPath, patchId, authorKp.fingerprint);

    // First claim a seat.
    const claimBody = { patch_id: patchId, claimant_fp: reviewerKp.fingerprint, base_sha: "0".repeat(40), repo: "acme/widget", pubkey: reviewerKp.publicKeyPem };
    const claimJson = JSON.stringify({ ...claimBody, signature: signBytes(reviewerKp.privateKeyPem, canonicalSerializePeerPayload(claimBody)) });
    const cr = await post(h.port, "/peer/claim-seat", JSON.parse(claimJson), buildPeerPostHeaders(reviewerKp, "claim-seat", claimJson));
    assert.equal(cr.status, 200, "claim should succeed first");

    try {
      // Now heartbeat.
      const hbBody = { patch_id: patchId, claimant_fp: reviewerKp.fingerprint, signature: "sig" };
      const hbJson = JSON.stringify(hbBody);
      const r = await post(h.port, "/peer/heartbeat", hbBody, buildPeerPostHeaders(reviewerKp, "heartbeat", hbJson));
      assert.equal(r.status, 200, `expected 200 on heartbeat, got ${r.status}: ${JSON.stringify(r.body)}`);
      assert.equal(r.body.ok, true);
    } finally {
      await h.cleanup();
    }
  });

  it("returns 404 when no seat held", async () => {
    const h = await startPeer();
    const reviewerKp = genTestKeypair();

    seedPeerUser(h.dbPath, reviewerKp, "reviewer4");

    try {
      const hbBody = { patch_id: "d".repeat(40), claimant_fp: reviewerKp.fingerprint, signature: "sig" };
      const hbJson = JSON.stringify(hbBody);
      const r = await post(h.port, "/peer/heartbeat", hbBody, buildPeerPostHeaders(reviewerKp, "heartbeat", hbJson));
      assert.equal(r.status, 404, `expected 404 when no seat held, got ${r.status}`);
    } finally {
      await h.cleanup();
    }
  });
});

// ─── POST /peer/release-seat ──────────────────────────────────────────

describe("POST /peer/release-seat: success path (AGT-453)", () => {
  it("returns 200 and released:true after releasing a held seat", async () => {
    const h = await startPeer();
    const authorKp = genTestKeypair();
    const reviewerKp = genTestKeypair();
    const patchId = "e".repeat(40);

    seedPeerUser(h.dbPath, authorKp, "author5");
    seedPeerUser(h.dbPath, reviewerKp, "reviewer5");
    seedPatch(h.dbPath, patchId, authorKp.fingerprint);

    // Claim.
    const claimBody = { patch_id: patchId, claimant_fp: reviewerKp.fingerprint, base_sha: "0".repeat(40), repo: "acme/widget", pubkey: reviewerKp.publicKeyPem };
    const claimJson = JSON.stringify({ ...claimBody, signature: signBytes(reviewerKp.privateKeyPem, canonicalSerializePeerPayload(claimBody)) });
    await post(h.port, "/peer/claim-seat", JSON.parse(claimJson), buildPeerPostHeaders(reviewerKp, "claim-seat", claimJson));

    try {
      const relBody = { patch_id: patchId, claimant_fp: reviewerKp.fingerprint, signature: "sig" };
      const relJson = JSON.stringify(relBody);
      const r = await post(h.port, "/peer/release-seat", relBody, buildPeerPostHeaders(reviewerKp, "release-seat", relJson));
      assert.equal(r.status, 200, `expected 200 on release, got ${r.status}`);
      assert.equal(r.body.released, true);
    } finally {
      await h.cleanup();
    }
  });
});

// ─── POST /peer/register-extra ────────────────────────────────────────

describe("POST /peer/register-extra: extras path (AGT-453)", () => {
  it("returns 200 on valid register-extra", async () => {
    const h = await startPeer();
    const authorKp = genTestKeypair();
    const reviewerKp = genTestKeypair();
    const patchId = "f".repeat(40);

    seedPeerUser(h.dbPath, authorKp, "author6");
    seedPeerUser(h.dbPath, reviewerKp, "reviewer6");
    seedPatch(h.dbPath, patchId, authorKp.fingerprint);

    try {
      const bodyPayload = { patch_id: patchId, claimant_fp: reviewerKp.fingerprint, base_sha: "0".repeat(40), repo: "acme/widget", pubkey: reviewerKp.publicKeyPem };
      const bodyJson = JSON.stringify({ ...bodyPayload, signature: signBytes(reviewerKp.privateKeyPem, canonicalSerializePeerPayload(bodyPayload)) });
      const r = await post(h.port, "/peer/register-extra", JSON.parse(bodyJson), buildPeerPostHeaders(reviewerKp, "register-extra", bodyJson));
      assert.equal(r.status, 200, `expected 200, got ${r.status}: ${JSON.stringify(r.body)}`);
      assert.equal(r.body.ok, true);
    } finally {
      await h.cleanup();
    }
  });

  it("returns 409 when reviewer is the PR author", async () => {
    const h = await startPeer();
    const authorKp = genTestKeypair();
    const patchId = "g".repeat(40);

    seedPeerUser(h.dbPath, authorKp, "author7");
    seedPatch(h.dbPath, patchId, authorKp.fingerprint);

    try {
      // Author tries to register-extra for their own PR.
      const bodyPayload = { patch_id: patchId, claimant_fp: authorKp.fingerprint, base_sha: "0".repeat(40), repo: "acme/widget", pubkey: authorKp.publicKeyPem };
      const bodyJson = JSON.stringify({ ...bodyPayload, signature: signBytes(authorKp.privateKeyPem, canonicalSerializePeerPayload(bodyPayload)) });
      const r = await post(h.port, "/peer/register-extra", JSON.parse(bodyJson), buildPeerPostHeaders(authorKp, "register-extra", bodyJson));
      assert.equal(r.status, 409, `expected 409 for author self-register, got ${r.status}`);
    } finally {
      await h.cleanup();
    }
  });
});

// ─── Regression: ssh-fp ≠ stamp-fp identity case (AGT-453) ──────────
//
// Prior SSH verbs bound identity to ssh-fp (caller.fingerprint from
// SSH_USER_AUTH). For users where ssh-fp ≠ stamp-fp, heartbeat/release-seat
// would silently fail or bind to the wrong seat. HTTP endpoints bind to
// stamp-fp uniformly — this test verifies the correct identity is used.

describe("AGT-453 regression: ssh-fp ≠ stamp-fp identity — HTTP heartbeat uses stamp-fp", () => {
  it("succeeds when stamp-fp matches claimant_fp even when ssh_fp differs", async () => {
    const h = await startPeer();
    // User has a DIFFERENT ssh_fp from their stamp-fp (diverged-key scenario).
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }) as string;
    const spkiDer = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" }) as Buffer;
    const stampFp = "sha256:" + createHash("sha256").update(spkiDer).digest("hex");
    // ssh_fp intentionally different.
    const differentSshFp = "SHA256:totally-different-ssh-key-fingerprint";

    const db = openServerDb({ path: h.dbPath, skipChmod: true });
    try {
      insertUser(db, {
        short_name: "diverged-user",
        ssh_pubkey: "ssh-ed25519 AAAADifferent diverged@host",
        ssh_fp: differentSshFp,
        role: "member",
        source: "invite",
        stamp_pubkey: publicKeyPem,
      });
    } finally {
      db.close();
    }

    const authorKp = genTestKeypair();
    seedPeerUser(h.dbPath, authorKp, "author8");
    const patchId = "h".repeat(40);
    seedPatch(h.dbPath, patchId, authorKp.fingerprint);

    const kp: TestKeypair = { privateKeyPem, publicKeyPem, fingerprint: stampFp };

    // Claim a seat using stamp-fp.
    const claimBody = { patch_id: patchId, claimant_fp: stampFp, base_sha: "0".repeat(40), repo: "acme/widget", pubkey: publicKeyPem };
    const claimJson = JSON.stringify({ ...claimBody, signature: signBytes(privateKeyPem, canonicalSerializePeerPayload(claimBody)) });
    const cr = await post(h.port, "/peer/claim-seat", JSON.parse(claimJson), buildPeerPostHeaders(kp, "claim-seat", claimJson));
    assert.equal(cr.status, 200, `claim with stamp-fp should succeed even when ssh-fp differs: ${JSON.stringify(cr.body)}`);

    try {
      // Heartbeat using stamp-fp — should succeed.
      const hbBody = { patch_id: patchId, claimant_fp: stampFp, signature: "sig" };
      const hbJson = JSON.stringify(hbBody);
      const r = await post(h.port, "/peer/heartbeat", hbBody, buildPeerPostHeaders(kp, "heartbeat", hbJson));
      assert.equal(r.status, 200, `heartbeat with stamp-fp (ssh-fp ≠ stamp-fp) should succeed: ${JSON.stringify(r.body)}`);
      assert.equal(r.body.ok, true, "heartbeat response should be ok:true");
    } finally {
      await h.cleanup();
    }
  });
});
