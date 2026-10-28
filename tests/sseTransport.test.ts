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
import { insertUser, openServerDb, type Role } from "../src/lib/serverDb.ts";
import { addRepoGrant } from "../src/lib/repoAccess.ts";
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

/**
 * Seed one user. Defaults to a member granted `acme/*` — the subscription
 * the happy-path tests open (AGT-2256 binds `?org=` to repo grants).
 */
function setupDb(
  stampPubkeyPem: string | null,
  opts: { role?: Role; grants?: Array<[string, string]> } = {},
): Ctx {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-sse-tests-"));
  const dbPath = path.join(dir, "users.db");
  const db = openServerDb({ path: dbPath, skipChmod: true });
  try {
    const id = insertUser(db, {
      short_name: "sse-user",
      ssh_pubkey: SSH_LINE,
      ssh_fp: "SHA256:" + "x".repeat(43),
      stamp_pubkey: stampPubkeyPem,
      role: opts.role ?? "member",
      source: "env",
    });
    for (const [org, repo] of opts.grants ?? [["acme", "*"]]) {
      addRepoGrant(db, id, org, repo, null);
    }
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
  reqPath = "/peer/events?org=acme",
): Promise<{
  status: number;
  contentType: string;
  nextData: () => Promise<string>;
  comments: () => string[];
  abort: () => void;
}> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, path: reqPath, method: "GET", headers },
      (res) => {
        res.setEncoding("utf8");
        let buffer = "";
        const comments: string[] = [];
        let dataResolve: ((s: string) => void) | null = null;
        res.on("data", (chunk: string) => {
          buffer += chunk;
          // Surface only `data:` frames to nextData() callers; ignore comments.
          let idx: number;
          while ((idx = buffer.indexOf("\n\n")) >= 0) {
            const frame = buffer.slice(0, idx);
            buffer = buffer.slice(idx + 2);
            if (frame.startsWith(":")) comments.push(frame);
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
          comments: () => comments,
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
  reqPath = "/peer/events?org=acme",
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, path: reqPath, method: "GET", headers },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (c: string) => { body += c; });
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
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

// ─── AGT-2256: subscription bound to the caller's repo grants ─────────

/** Resolve with the next data frame, or null if none arrives within `ms`. */
function nextDataOrNull(
  conn: { nextData: () => Promise<string> },
  ms = 150,
): Promise<string | null> {
  return Promise.race([
    conn.nextData(),
    new Promise<null>((r) => setTimeout(() => r(null), ms)),
  ]);
}

function prOpened(repo: string): PeerReviewEvent {
  return {
    event_type: "pr-opened",
    patch_id: "c".repeat(40),
    actor_fp: "sha256:author",
    payload: {
      repo,
      title: "Rotate the prod signing key",
      body: "secret rollout plan",
      paths_changed: ["infra/keys.tf"],
      pr_url: `https://github.com/${repo}/pull/1`,
    },
  };
}

describe("GET /peer/events — org subscription bound to repo grants (AGT-2256)", () => {
  it("refuses (403) an unscoped member (no grants) — fail closed", async () => {
    const kp = genStampKeypair();
    const ctx = setupDb(kp.publicKeyPem, { grants: [] });
    process.env["STAMP_SERVER_DB_PATH"] = ctx.dbPath;
    process.env["STAMP_PEER_REVIEWS_ENABLED"] = "1";
    try {
      await withServer(async (port) => {
        const r = await getStatus(port, authHeaders(kp, new Date().toISOString()));
        assert.equal(r.status, 403);
        assert.match(r.body, /stamp users grant sse-user --repo <org>\/\*/);
        assert.equal(__getSseConnectionsForTests().length, 0);
      });
    } finally {
      ctx.cleanup();
    }
  });

  it("refuses (403) a member naming only another team's org", async () => {
    const kp = genStampKeypair();
    const ctx = setupDb(kp.publicKeyPem, { grants: [["acme", "*"]] });
    process.env["STAMP_SERVER_DB_PATH"] = ctx.dbPath;
    process.env["STAMP_PEER_REVIEWS_ENABLED"] = "1";
    try {
      await withServer(async (port) => {
        const r = await getStatus(port, authHeaders(kp, new Date().toISOString()), "/peer/events?org=other-org");
        assert.equal(r.status, 403);
      });
    } finally {
      ctx.cleanup();
    }
  });

  it("drops unauthorized orgs from a mixed list and never delivers their events", async () => {
    const kp = genStampKeypair();
    const ctx = setupDb(kp.publicKeyPem, { grants: [["acme", "*"]] });
    process.env["STAMP_SERVER_DB_PATH"] = ctx.dbPath;
    process.env["STAMP_PEER_REVIEWS_ENABLED"] = "1";
    try {
      await withServer(async (port) => {
        const conn = await openEvents(
          port,
          authHeaders(kp, new Date().toISOString()),
          "/peer/events?org=acme&org=Other-Org",
        );
        assert.equal(conn.status, 200);
        await new Promise((r) => setTimeout(r, 50));
        assert.ok(
          conn.comments().some((c) => c.includes("not authorized for orgs other-org")),
          `expected a denied-orgs comment, got ${JSON.stringify(conn.comments())}`,
        );
        assert.equal(fanoutEvent("other-org", prOpened("other-org/secret")), 0);
        assert.equal(await nextDataOrNull(conn), null);
        conn.abort();
      });
    } finally {
      ctx.cleanup();
    }
  });

  it("a repo-scoped grant does not leak sibling repos in the same org", async () => {
    const kp = genStampKeypair();
    const ctx = setupDb(kp.publicKeyPem, { grants: [["acme", "widget"]] });
    process.env["STAMP_SERVER_DB_PATH"] = ctx.dbPath;
    process.env["STAMP_PEER_REVIEWS_ENABLED"] = "1";
    try {
      await withServer(async (port) => {
        const conn = await openEvents(port, authHeaders(kp, new Date().toISOString()));
        assert.equal(conn.status, 200);
        await new Promise((r) => setTimeout(r, 50));
        fanoutEvent("acme", prOpened("acme/gadget"));
        assert.equal(await nextDataOrNull(conn), null, "acme/gadget must not be delivered");
        const p = conn.nextData();
        fanoutEvent("acme", prOpened("acme/widget"));
        const parsed = JSON.parse(await p) as PeerReviewEvent;
        assert.equal((parsed.payload as { repo: string }).repo, "acme/widget");
        conn.abort();
      });
    } finally {
      ctx.cleanup();
    }
  });

  it("owners/admins need no grants and may subscribe to any org", async () => {
    const kp = genStampKeypair();
    const ctx = setupDb(kp.publicKeyPem, { role: "admin", grants: [] });
    process.env["STAMP_SERVER_DB_PATH"] = ctx.dbPath;
    process.env["STAMP_PEER_REVIEWS_ENABLED"] = "1";
    try {
      await withServer(async (port) => {
        const conn = await openEvents(
          port,
          authHeaders(kp, new Date().toISOString()),
          "/peer/events?org=anything",
        );
        assert.equal(conn.status, 200);
        await new Promise((r) => setTimeout(r, 50));
        const p = conn.nextData();
        fanoutEvent("anything", prOpened("anything/repo"));
        assert.ok(await p);
        conn.abort();
      });
    } finally {
      ctx.cleanup();
    }
  });

  it("strips the PR body from fanned-out payloads (title + paths kept)", async () => {
    const kp = genStampKeypair();
    const ctx = setupDb(kp.publicKeyPem);
    process.env["STAMP_SERVER_DB_PATH"] = ctx.dbPath;
    process.env["STAMP_PEER_REVIEWS_ENABLED"] = "1";
    try {
      await withServer(async (port) => {
        const conn = await openEvents(port, authHeaders(kp, new Date().toISOString()));
        await new Promise((r) => setTimeout(r, 50));
        const p = conn.nextData();
        fanoutEvent("acme", prOpened("acme/widget"));
        const payload = (JSON.parse(await p) as PeerReviewEvent).payload as Record<string, unknown>;
        assert.equal("body" in payload, false);
        assert.equal(payload["title"], "Rotate the prod signing key");
        assert.deepEqual(payload["paths_changed"], ["infra/keys.tf"]);
        conn.abort();
      });
    } finally {
      ctx.cleanup();
    }
  });
});
