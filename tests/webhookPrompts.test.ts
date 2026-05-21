/**
 * AGT-374 — tests for the `POST /webhook/prompts` route.
 *
 * Coverage matrix per the ticket's AC bullet 6:
 *
 *   a. valid-signature 202 — HMAC-SHA256 of body matches header → 202 +
 *      stub refresh-fn invoked once.
 *   b. invalid-signature 401 — bad header / wrong secret / bad algorithm
 *      prefix / mangled hex → 401 + stub NOT invoked + supplied signature
 *      never appears in any log line.
 *   c. missing-secret 503 — STAMP_PROMPTS_WEBHOOK_SECRET unset → 503 with
 *      explicit error code + stub NOT invoked.
 *   d. burst-of-5-in-1s — five valid deliveries fired back-to-back collapse
 *      to one refresh kickoff (route-level throttle).
 *
 * Setup mirrors `serverHttp.test.ts`: tmpfs DB so the listener boots cleanly,
 * port 0 so the kernel picks a free socket, fresh harness per `describe`.
 * The refresh function is swapped out via `__setRefreshFnForTests` so we
 * never touch a real git fixture from this file — that surface is already
 * covered by `promptsCache.test.ts`.
 */

import { strict as assert } from "node:assert";
import { createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { request, type Server } from "node:http";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import {
  __resetWebhookStateForTests,
  __setRefreshFnForTests,
  startServer,
} from "../src/server/http-server.ts";
import type {
  CloneOrFetchOpts,
  RefreshResult,
} from "../src/server/prompts-cache.ts";

// ─── harness ─────────────────────────────────────────────────────────

interface Harness {
  port: number;
  server: Server;
  // Counter bumped on each refresh-fn invocation. Tests assert on this.
  refreshCount: { value: number };
  // Optional gate: when set, the stub resolves only after `gate.resolve()`
  // is called. Used by the burst test to keep the refresh "in flight"
  // while subsequent deliveries arrive.
  gate: { resolve: (() => void) | null };
  // Captured opts from the most recent refresh call — lets tests assert
  // the env-var-derived options were threaded through correctly.
  lastOpts: { value: CloneOrFetchOpts | null };
  // Captured stdout/stderr lines so we can grep for things that MUST NOT
  // appear in logs (e.g. the rejected signature value).
  logLines: string[];
  // Restore the original write streams + env vars on cleanup.
  cleanup: () => Promise<void>;
}

async function start(): Promise<Harness> {
  // We don't need a real users DB for webhook tests, but startServer
  // doesn't open one at boot anyway (only on invite-accept request). Still,
  // set the override so any incidental open() doesn't write into the
  // dev's shared DB location.
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-webhook-"));
  process.env["STAMP_SERVER_DB_PATH"] = path.join(dir, "users.db");

  const refreshCount = { value: 0 };
  const gate: { resolve: (() => void) | null } = { resolve: null };
  const lastOpts: { value: CloneOrFetchOpts | null } = { value: null };

  __setRefreshFnForTests(async (opts: CloneOrFetchOpts) => {
    refreshCount.value += 1;
    lastOpts.value = opts;
    if (gate.resolve) {
      await new Promise<void>((resolve) => {
        gate.resolve = resolve;
      });
    }
    const result: RefreshResult = {
      commitSha: "0".repeat(40),
      refreshedAt: new Date().toISOString(),
    };
    return result;
  });
  __resetWebhookStateForTests();

  // Capture log lines. The handler writes via process.stdout/stderr.write;
  // we shim those to mirror to an array while still letting test output
  // surface normally. Tests assert that no log line contains the bad
  // signature value.
  const logLines: string[] = [];
  const origStdoutWrite = process.stdout.write.bind(process.stdout);
  const origStderrWrite = process.stderr.write.bind(process.stderr);
  process.stdout.write = ((chunk: string | Uint8Array, ...rest: unknown[]) => {
    const s = typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
    logLines.push(s);
    return (origStdoutWrite as (c: unknown, ...r: unknown[]) => boolean)(chunk, ...rest);
  }) as typeof process.stdout.write;
  process.stderr.write = ((chunk: string | Uint8Array, ...rest: unknown[]) => {
    const s = typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
    logLines.push(s);
    return (origStderrWrite as (c: unknown, ...r: unknown[]) => boolean)(chunk, ...rest);
  }) as typeof process.stderr.write;

  const server = startServer(0);
  await new Promise<void>((resolve) => server.once("listening", () => resolve()));
  const addr = server.address();
  if (!addr || typeof addr === "string") {
    throw new Error("expected server.address() to return AddressInfo");
  }
  const port = addr.port;

  return {
    port,
    server,
    refreshCount,
    gate,
    lastOpts,
    logLines,
    cleanup: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      process.stdout.write = origStdoutWrite;
      process.stderr.write = origStderrWrite;
      __setRefreshFnForTests(null);
      __resetWebhookStateForTests();
      delete process.env["STAMP_SERVER_DB_PATH"];
      delete process.env["STAMP_PROMPTS_WEBHOOK_SECRET"];
      delete process.env["STAMP_PROMPTS_REPO_URL"];
      delete process.env["STAMP_PROMPTS_REPO_REF"];
      delete process.env["STAMP_PROMPTS_CACHE_ROOT"];
      delete process.env["STAMP_PROMPTS_DEPLOY_KEY_PATH"];
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

interface PostResult {
  status: number;
  body: Record<string, unknown>;
}

function postRaw(
  port: number,
  url: string,
  bodyBytes: Buffer,
  headers: Record<string, string>,
): Promise<PostResult> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: "127.0.0.1",
        port,
        path: url,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": bodyBytes.length.toString(),
          ...headers,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let body: Record<string, unknown>;
          try {
            body = JSON.parse(text) as Record<string, unknown>;
          } catch {
            body = { raw: text };
          }
          resolve({ status: res.statusCode ?? 0, body });
        });
      },
    );
    req.on("error", reject);
    req.write(bodyBytes);
    req.end();
  });
}

function signBody(secret: string, body: Buffer): string {
  return "sha256=" + createHmac("sha256", secret).update(body).digest("hex");
}

/**
 * Drain one tick of the event loop so the handler's `setImmediate(...)`
 * callback (which schedules the refresh) actually runs before the test
 * assertion. The handler responds BEFORE scheduling, so post() returning
 * doesn't guarantee `refreshCount` has been bumped yet.
 */
async function flush(times = 2): Promise<void> {
  for (let i = 0; i < times; i++) {
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
}

// ─── tests ───────────────────────────────────────────────────────────

describe("POST /webhook/prompts — valid signature", () => {
  it("returns 202 and schedules a refresh when the HMAC matches", async () => {
    const h = await start();
    try {
      process.env["STAMP_PROMPTS_WEBHOOK_SECRET"] = "shh-correct-horse";
      process.env["STAMP_PROMPTS_REPO_URL"] =
        "https://github.com/example/prompts.git";
      process.env["STAMP_PROMPTS_REPO_REF"] = "main";
      process.env["STAMP_PROMPTS_CACHE_ROOT"] = "/tmp/test-cache";

      const body = Buffer.from(JSON.stringify({ ref: "refs/heads/main" }), "utf8");
      const sig = signBody("shh-correct-horse", body);

      const r = await postRaw(h.port, "/webhook/prompts", body, {
        "X-Hub-Signature-256": sig,
        "X-GitHub-Delivery": "test-delivery-001",
        "X-GitHub-Event": "push",
      });
      assert.equal(r.status, 202);
      assert.equal(r.body.ok, true);

      await flush();
      assert.equal(h.refreshCount.value, 1, "refresh should fire exactly once");
      assert.ok(h.lastOpts.value, "refresh fn should have received opts");
      assert.equal(h.lastOpts.value?.url, "https://github.com/example/prompts.git");
      assert.equal(h.lastOpts.value?.ref, "main");
      assert.equal(h.lastOpts.value?.cacheRoot, "/tmp/test-cache");
    } finally {
      await h.cleanup();
    }
  });
});

describe("POST /webhook/prompts — invalid signature", () => {
  it("returns 401 when X-Hub-Signature-256 doesn't match the body", async () => {
    const h = await start();
    try {
      process.env["STAMP_PROMPTS_WEBHOOK_SECRET"] = "the-real-secret";
      process.env["STAMP_PROMPTS_REPO_URL"] =
        "https://github.com/example/prompts.git";

      const body = Buffer.from(JSON.stringify({ ref: "refs/heads/main" }), "utf8");
      // Signed with the wrong secret on purpose.
      const badSig = signBody("attacker-guessed-secret", body);

      const r = await postRaw(h.port, "/webhook/prompts", body, {
        "X-Hub-Signature-256": badSig,
        "X-GitHub-Delivery": "test-delivery-bad",
      });
      assert.equal(r.status, 401);
      assert.equal(r.body.error, "invalid_signature");

      await flush();
      assert.equal(h.refreshCount.value, 0, "refresh must NOT fire on bad sig");

      // AC bullet 3: the bad signature itself is never echoed to logs.
      const joined = h.logLines.join("");
      assert.ok(
        !joined.includes(badSig),
        "rejected signature value must not appear in any log line",
      );
      // The bad-hex digest (everything after sha256=) also must not appear.
      assert.ok(
        !joined.includes(badSig.slice("sha256=".length)),
        "rejected digest hex must not appear in any log line",
      );
      // But the delivery ID and "invalid signature" tag should be logged.
      assert.ok(
        joined.includes("test-delivery-bad"),
        "delivery ID should be logged on rejection",
      );
      assert.ok(
        joined.includes("invalid signature"),
        "rejection reason should be logged",
      );
    } finally {
      await h.cleanup();
    }
  });

  it("returns 401 when the signature header is missing entirely", async () => {
    const h = await start();
    try {
      process.env["STAMP_PROMPTS_WEBHOOK_SECRET"] = "the-real-secret";
      process.env["STAMP_PROMPTS_REPO_URL"] =
        "https://github.com/example/prompts.git";

      const body = Buffer.from(JSON.stringify({}), "utf8");
      const r = await postRaw(h.port, "/webhook/prompts", body, {
        "X-GitHub-Delivery": "test-delivery-nosig",
      });
      assert.equal(r.status, 401);
      assert.equal(r.body.error, "invalid_signature");
      await flush();
      assert.equal(h.refreshCount.value, 0);
    } finally {
      await h.cleanup();
    }
  });

  it("returns 401 when the signature has the wrong algorithm prefix", async () => {
    const h = await start();
    try {
      process.env["STAMP_PROMPTS_WEBHOOK_SECRET"] = "the-real-secret";
      process.env["STAMP_PROMPTS_REPO_URL"] =
        "https://github.com/example/prompts.git";

      const body = Buffer.from(JSON.stringify({}), "utf8");
      // sha1 is the legacy github header — we accept ONLY sha256.
      const sha1ish = "sha1=" + createHmac("sha1", "the-real-secret").update(body).digest("hex");
      const r = await postRaw(h.port, "/webhook/prompts", body, {
        "X-Hub-Signature-256": sha1ish,
        "X-GitHub-Delivery": "test-delivery-sha1",
      });
      assert.equal(r.status, 401);
      await flush();
      assert.equal(h.refreshCount.value, 0);
    } finally {
      await h.cleanup();
    }
  });

  it("returns 401 when the signature hex is mangled (odd length / non-hex)", async () => {
    const h = await start();
    try {
      process.env["STAMP_PROMPTS_WEBHOOK_SECRET"] = "the-real-secret";
      process.env["STAMP_PROMPTS_REPO_URL"] =
        "https://github.com/example/prompts.git";

      const body = Buffer.from(JSON.stringify({}), "utf8");
      const r = await postRaw(h.port, "/webhook/prompts", body, {
        // 63 chars + a 'z' — odd length AND non-hex character to make
        // sure neither Buffer.from('hex') silent-truncate nor a length
        // mismatch crash us.
        "X-Hub-Signature-256": "sha256=" + "a".repeat(63) + "z",
        "X-GitHub-Delivery": "test-delivery-mangled",
      });
      assert.equal(r.status, 401);
      await flush();
      assert.equal(h.refreshCount.value, 0);
    } finally {
      await h.cleanup();
    }
  });
});

describe("POST /webhook/prompts — missing secret", () => {
  it("returns 503 when STAMP_PROMPTS_WEBHOOK_SECRET is unset", async () => {
    const h = await start();
    try {
      // Explicitly DO NOT set the secret. Even a valid-looking signature
      // can't authenticate against a server that hasn't been configured.
      delete process.env["STAMP_PROMPTS_WEBHOOK_SECRET"];
      process.env["STAMP_PROMPTS_REPO_URL"] =
        "https://github.com/example/prompts.git";

      const body = Buffer.from(JSON.stringify({ ref: "refs/heads/main" }), "utf8");
      const r = await postRaw(h.port, "/webhook/prompts", body, {
        "X-Hub-Signature-256": "sha256=" + "a".repeat(64),
        "X-GitHub-Delivery": "test-delivery-noscrt",
      });
      assert.equal(r.status, 503);
      assert.equal(r.body.error, "webhook_secret_unconfigured");
      assert.ok(
        typeof r.body.detail === "string" && r.body.detail.includes("STAMP_PROMPTS_WEBHOOK_SECRET"),
        "503 response should name the env var the operator must set",
      );

      await flush();
      assert.equal(h.refreshCount.value, 0, "refresh must NOT fire");
    } finally {
      await h.cleanup();
    }
  });
});

describe("POST /webhook/prompts — coalescing", () => {
  it("collapses a burst of 5 valid deliveries within 1s to exactly 1 refresh", async () => {
    const h = await start();
    try {
      process.env["STAMP_PROMPTS_WEBHOOK_SECRET"] = "burst-secret";
      process.env["STAMP_PROMPTS_REPO_URL"] =
        "https://github.com/example/prompts.git";

      // Gate the first refresh so it stays "in flight" while the rest of
      // the burst arrives. Without this gate, the first refresh would
      // settle before delivery #2 arrives and the second-pass throttle
      // path ("previous in window, none in flight, no-op") wouldn't be
      // exercised — the test would still pass on count==1, but the
      // trailing-edge re-fire behaviour would be untested.
      h.gate.resolve = () => {}; // placeholder; the stub overwrites this with the real resolver

      const body = Buffer.from(JSON.stringify({ ref: "refs/heads/main" }), "utf8");
      const sig = signBody("burst-secret", body);

      // Fire 5 requests in parallel. Each must return 202 (the throttle is
      // ON the refresh, not on the response).
      const responses = await Promise.all(
        Array.from({ length: 5 }, (_, i) =>
          postRaw(h.port, "/webhook/prompts", body, {
            "X-Hub-Signature-256": sig,
            "X-GitHub-Delivery": `burst-${i}`,
            "X-GitHub-Event": "push",
          }),
        ),
      );
      for (const r of responses) {
        assert.equal(r.status, 202, "every delivery in the burst should return 202");
      }

      // Wait for all 5 setImmediate-scheduled refresh calls to run their
      // synchronous coalescing-check code.
      await flush(5);

      // Only the FIRST delivery should have entered the refresh function.
      // The other 4 collapse: one is the trailing-edge mark, the rest are
      // no-op'd inside the throttle window.
      assert.equal(
        h.refreshCount.value,
        1,
        "5 deliveries in <5s must collapse to 1 refresh kickoff",
      );

      // Release the gate so the first refresh settles, then the trailing
      // re-fire kicks off (because pendingTrailingRefresh got set during
      // the burst).
      if (h.gate.resolve) h.gate.resolve();
      await flush(5);

      // After the gate releases, the trailing re-fire bumps the count to
      // 2. We're not asserting on the exact count beyond "the burst
      // collapsed" — counting the trailing-edge re-fire is more an
      // observation of the implementation choice than an AC. But we DO
      // assert it stayed below the upper bound (5) — i.e. coalescing
      // genuinely fired.
      assert.ok(
        h.refreshCount.value < 5,
        `coalescing should keep refresh count well below 5 (got ${h.refreshCount.value})`,
      );
    } finally {
      await h.cleanup();
    }
  });
});

describe("POST /webhook/prompts — misc", () => {
  it("returns 413 when the body exceeds the 64 KiB cap", async () => {
    const h = await start();
    try {
      process.env["STAMP_PROMPTS_WEBHOOK_SECRET"] = "any-secret";
      process.env["STAMP_PROMPTS_REPO_URL"] =
        "https://github.com/example/prompts.git";

      // 80 KiB body — guaranteed to bust the 64 KiB cap before any HMAC
      // calculation. Note: this is sent BEFORE the HMAC is computed, so
      // an attacker can't exhaust memory by sending huge oversized bodies.
      const body = Buffer.alloc(80 * 1024, "a");
      const sig = signBody("any-secret", body);
      const r = await postRaw(h.port, "/webhook/prompts", body, {
        "X-Hub-Signature-256": sig,
        "X-GitHub-Delivery": "test-delivery-toobig",
      });
      assert.equal(r.status, 413);
      assert.equal(r.body.error, "body_too_large");

      await flush();
      assert.equal(h.refreshCount.value, 0);
    } finally {
      await h.cleanup();
    }
  });

  it("returns 503 when the secret is set but STAMP_PROMPTS_REPO_URL is unset", async () => {
    const h = await start();
    try {
      process.env["STAMP_PROMPTS_WEBHOOK_SECRET"] = "set";
      delete process.env["STAMP_PROMPTS_REPO_URL"];

      const body = Buffer.from(JSON.stringify({}), "utf8");
      const sig = signBody("set", body);
      const r = await postRaw(h.port, "/webhook/prompts", body, {
        "X-Hub-Signature-256": sig,
        "X-GitHub-Delivery": "test-delivery-nourl",
      });
      // HMAC validates (we have a secret), but we can't actually fetch
      // without a URL. 503 with a different error code tells the
      // operator what to fix.
      assert.equal(r.status, 503);
      assert.equal(r.body.error, "prompts_repo_url_unconfigured");

      await flush();
      assert.equal(h.refreshCount.value, 0);
    } finally {
      await h.cleanup();
    }
  });
});
