/**
 * AGT-454 — SSE peer-review event transport tests (replaces wsTransport.test.ts).
 *
 * Coverage:
 *   - GET /peer/events with an enrolled key + valid sig + fresh ts → 200
 *     text/event-stream, and a pushed event is received as a data: frame.
 *   - bad signature → 401.
 *   - unenrolled key → 401.
 *   - stale timestamp → 401.
 *   - feature flag off → endpoint inert (404).
 *
 * Uses an in-memory (tmpdir) users DB fixture via STAMP_SERVER_DB_PATH and a
 * real loopback HTTP server (startServer) so the auth + streaming path is
 * exercised end to end.
 */

import { strict as assert } from "node:assert";
import { describe, it, beforeEach, afterEach } from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { request as httpRequest } from "node:http";
import os from "node:os";
import path from "node:path";

import { signBytes } from "../src/lib/signing.ts";
import { fingerprintFromPem } from "../src/lib/keys.ts";
import { insertUser, openServerDb } from "../src/lib/serverDb.ts";
import {
  startServer,
  pushEventToSseClient,
  __clearSseConnectionsForTests,
  __getSseConnectionsForTests,
} from "../src/server/http-server.ts";
import { fanoutEvent, clearListenerRegistry } from "../src/server/peerReviews.ts";
import type { PeerReviewEvent } from "../src/lib/peerReviewEvent.ts";

// ─── Fixtures ─────────────────────────────────────────────────────────

function genStampKeypair(): { publicKeyPem: string; privateKeyPem: string; fingerprint: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }) as string;
  return { privateKeyPem, publicKeyPem, fingerprint: fingerprintFromPem(publicKeyPem) };
}

// A throwaway SSH pubkey line (we only exercise stamp_pubkey lookup here, but
// the users schema requires non-null ssh_pubkey/ssh_fp).
const SSH_LINE = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest sse-user";

interface Ctx {
  dir: string;
  dbPath: string;
  cleanup: () => void;
}

function setupDb(stampPubkeyPem: string | null): Ctx {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-sse-tests-"));
  const dbPath = path.join(dir, "users.db");
  const db = openServerDb({ path: dbPath, skipChmod: true });
  try {
    insertUser(db, {
      short_name: "sse-user",
      ssh_pubkey: SSH_LINE,
      ssh_fp: "SHA256:" + "x".repeat(43),
      stamp_pubkey: stampPubkeyPem,
      role: "member",
      source: "env",
    });
  } finally {
    db.close();
  }
  return { dir, dbPath, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

async function withServer(
  fn: (port: number) => Promise<void>,
): Promise<void> {
  const server = startServer(0);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const addr = server.address() as { port: number };
  try {
    await fn(addr.port);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

/** Build the three auth headers for a given keypair + timestamp. */
function authHeaders(
  kp: { publicKeyPem: string; privateKeyPem: string },
  timestamp: string,
  opts: { badSig?: boolean } = {},
): Record<string, string> {
  const canonical = Buffer.from(`peer-events\n${timestamp}`, "utf8");
  let signature = signBytes(kp.privateKeyPem, canonical);
  if (opts.badSig) {
    // Sign a different message → signature won't verify against the canonical.
    signature = signBytes(kp.privateKeyPem, Buffer.from("wrong-message", "utf8"));
  }
  return {
    Accept: "text/event-stream",
    "x-stamp-pubkey": Buffer.from(kp.publicKeyPem, "utf8").toString("base64"),
    "x-stamp-timestamp": timestamp,
    "x-stamp-signature": signature,
  };
}

/**
 * Open a GET /peer/events request. Resolves once the response headers arrive,
 * returning the status code, headers, and a handle to read streamed data and
 * abort the request.
 */
function openEvents(
  port: number,
  headers: Record<string, string>,
): Promise<{
  status: number;
  contentType: string;
  nextData: () => Promise<string>;
  abort: () => void;
}> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, path: "/peer/events?org=acme", method: "GET", headers },
      (res) => {
        res.setEncoding("utf8");
        let buffer = "";
        let dataResolve: ((s: string) => void) | null = null;
        res.on("data", (chunk: string) => {
          buffer += chunk;
          // Surface only `data:` frames to nextData() callers; ignore comments.
          let idx: number;
          while ((idx = buffer.indexOf("\n\n")) >= 0) {
            const frame = buffer.slice(0, idx);
            buffer = buffer.slice(idx + 2);
            const dataLine = frame
              .split("\n")
              .find((l) => l.startsWith("data:"));
            if (dataLine && dataResolve) {
              const r = dataResolve;
              dataResolve = null;
              r(dataLine.slice("data:".length).replace(/^ /, ""));
            }
          }
        });
        resolve({
          status: res.statusCode ?? 0,
          contentType: String(res.headers["content-type"] ?? ""),
          nextData: () =>
            new Promise<string>((r) => {
              dataResolve = r;
            }),
          abort: () => req.destroy(),
        });
      },
    );
    req.on("error", (err) => {
      // A 401 path ends the response cleanly; only reject on connect errors
      // before the response callback fires.
      reject(err);
    });
    req.end();
  });
}

/** Read a non-200 JSON response body for the error-path assertions. */
function getStatus(
  port: number,
  headers: Record<string, string>,
): Promise<{ status: number }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, path: "/peer/events?org=acme", method: "GET", headers },
      (res) => {
        res.resume();
        resolve({ status: res.statusCode ?? 0 });
      },
    );
    req.on("error", reject);
    req.end();
  });
}

// ─── Cleanup ──────────────────────────────────────────────────────────

beforeEach(() => {
  clearListenerRegistry();
  __clearSseConnectionsForTests();
});
afterEach(() => {
  delete process.env["STAMP_PEER_REVIEWS_ENABLED"];
  delete process.env["STAMP_SERVER_DB_PATH"];
  clearListenerRegistry();
  __clearSseConnectionsForTests();
});

// ─── Happy path ───────────────────────────────────────────────────────

describe("GET /peer/events — enrolled key + valid sig + fresh ts", () => {
  it("returns 200 text/event-stream and receives a pushed event", async () => {
    const kp = genStampKeypair();
    const ctx = setupDb(kp.publicKeyPem);
    process.env["STAMP_SERVER_DB_PATH"] = ctx.dbPath;
    process.env["STAMP_PEER_REVIEWS_ENABLED"] = "1";
    try {
      await withServer(async (port) => {
        const conn = await openEvents(port, authHeaders(kp, new Date().toISOString()));
        assert.equal(conn.status, 200, "should return 200");
        assert.ok(
          conn.contentType.includes("text/event-stream"),
          `content-type should be event-stream, got ${conn.contentType}`,
        );

        // Give the server a tick to register the stream, then fan out an event
        // for the subscribed org. fanoutEvent → registered onEvent → data frame.
        await new Promise((r) => setTimeout(r, 50));
        assert.ok(
          __getSseConnectionsForTests().includes(kp.fingerprint),
          "the stream should be registered under the caller's fingerprint",
        );

        const event: PeerReviewEvent = {
          event_type: "pr-opened",
          patch_id: "a".repeat(40),
          actor_fp: "sha256:author",
          payload: { repo: "acme/widget", pr_url: "https://github.com/acme/widget/pull/9" },
        };
        const dataP = conn.nextData();
        const notified = fanoutEvent("acme", event);
        assert.equal(notified, 1, "fanout should reach the SSE listener");

        const raw = await dataP;
        const parsed = JSON.parse(raw) as PeerReviewEvent;
        assert.equal(parsed.patch_id, "a".repeat(40));
        assert.equal(parsed.event_type, "pr-opened");

        conn.abort();
      });
    } finally {
      ctx.cleanup();
    }
  });

  it("pushEventToSseClient delivers directly to the registered fingerprint", async () => {
    const kp = genStampKeypair();
    const ctx = setupDb(kp.publicKeyPem);
    process.env["STAMP_SERVER_DB_PATH"] = ctx.dbPath;
    process.env["STAMP_PEER_REVIEWS_ENABLED"] = "1";
    try {
      await withServer(async (port) => {
        const conn = await openEvents(port, authHeaders(kp, new Date().toISOString()));
        assert.equal(conn.status, 200);
        await new Promise((r) => setTimeout(r, 50));

        const dataP = conn.nextData();
        const ok = pushEventToSseClient(kp.fingerprint, {
          event_type: "re-review-requested",
          patch_id: "b".repeat(40),
          actor_fp: "sha256:author",
          payload: {},
        });
        assert.equal(ok, true, "pushEventToSseClient should find the stream");
        const parsed = JSON.parse(await dataP) as PeerReviewEvent;
        assert.equal(parsed.patch_id, "b".repeat(40));
        conn.abort();
      });
    } finally {
      ctx.cleanup();
    }
  });
});

// ─── Auth failure paths ───────────────────────────────────────────────

describe("GET /peer/events — auth failures → 401", () => {
  it("rejects a bad signature with 401", async () => {
    const kp = genStampKeypair();
    const ctx = setupDb(kp.publicKeyPem);
    process.env["STAMP_SERVER_DB_PATH"] = ctx.dbPath;
    process.env["STAMP_PEER_REVIEWS_ENABLED"] = "1";
    try {
      await withServer(async (port) => {
        const { status } = await getStatus(
          port,
          authHeaders(kp, new Date().toISOString(), { badSig: true }),
        );
        assert.equal(status, 401, "bad signature should be 401");
      });
    } finally {
      ctx.cleanup();
    }
  });

  it("rejects an unenrolled key with 401 (valid sig, but not in users)", async () => {
    const enrolled = genStampKeypair();
    const stranger = genStampKeypair();
    const ctx = setupDb(enrolled.publicKeyPem); // only `enrolled` is in the DB
    process.env["STAMP_SERVER_DB_PATH"] = ctx.dbPath;
    process.env["STAMP_PEER_REVIEWS_ENABLED"] = "1";
    try {
      await withServer(async (port) => {
        const { status } = await getStatus(port, authHeaders(stranger, new Date().toISOString()));
        assert.equal(status, 401, "unenrolled key should be 401");
      });
    } finally {
      ctx.cleanup();
    }
  });

  it("rejects a stale timestamp with 401", async () => {
    const kp = genStampKeypair();
    const ctx = setupDb(kp.publicKeyPem);
    process.env["STAMP_SERVER_DB_PATH"] = ctx.dbPath;
    process.env["STAMP_PEER_REVIEWS_ENABLED"] = "1";
    try {
      await withServer(async (port) => {
        const staleTs = new Date(Date.now() - 10 * 60 * 1000).toISOString(); // 10 min ago
        const { status } = await getStatus(port, authHeaders(kp, staleTs));
        assert.equal(status, 401, "stale timestamp should be 401");
      });
    } finally {
      ctx.cleanup();
    }
  });

  it("rejects a request with missing auth headers with 401", async () => {
    const kp = genStampKeypair();
    const ctx = setupDb(kp.publicKeyPem);
    process.env["STAMP_SERVER_DB_PATH"] = ctx.dbPath;
    process.env["STAMP_PEER_REVIEWS_ENABLED"] = "1";
    try {
      await withServer(async (port) => {
        const { status } = await getStatus(port, { Accept: "text/event-stream" });
        assert.equal(status, 401, "missing headers should be 401");
      });
    } finally {
      ctx.cleanup();
    }
  });
});

// ─── Feature flag off → endpoint inert ────────────────────────────────

describe("GET /peer/events — feature flag off → inert (404)", () => {
  it("returns 404 when STAMP_PEER_REVIEWS_ENABLED is unset", async () => {
    const kp = genStampKeypair();
    const ctx = setupDb(kp.publicKeyPem);
    process.env["STAMP_SERVER_DB_PATH"] = ctx.dbPath;
    delete process.env["STAMP_PEER_REVIEWS_ENABLED"];
    try {
      await withServer(async (port) => {
        const { status } = await getStatus(port, authHeaders(kp, new Date().toISOString()));
        assert.equal(status, 404, "endpoint should be inert (404) when feature is dark");
      });
    } finally {
      ctx.cleanup();
    }
  });
});
