/**
 * AGT-2264 — the HTTP listener no longer runs the prompts refresh itself.
 *
 * In the container the listener runs as the unprivileged stamp-http user,
 * which can't read the prompts deploy key or write the git-owned cache. With
 * STAMP_PROMPTS_REFRESH_TRIGGER set, a validly-signed webhook only replaces a
 * trigger file; the git-user stamp-workers process watches that file and runs
 * the same coalesced refresh. These tests cover both halves plus the
 * `gitWorkers: false` listener mode.
 */

import { strict as assert } from "node:assert";
import { createHmac } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { request, type Server } from "node:http";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import {
  __getPollStateForTests,
  __isTrashSweepArmedForTests,
  __resetPollStateForTests,
  __resetTrashSweepStateForTests,
  __resetWebhookStateForTests,
  __setRefreshFnForTests,
  readPromptsRefreshTrigger,
  startPromptsRefreshTriggerWatcher,
  startServer,
  stopPromptsRefreshTriggerWatcher,
  writePromptsRefreshTrigger,
} from "../src/server/http-server.ts";
import type { CloneOrFetchOpts } from "../src/server/prompts-cache.ts";

const SECRET = "trigger-test-secret";
const ENV_KEYS = [
  "STAMP_SERVER_DB_PATH",
  "STAMP_PROMPTS_WEBHOOK_SECRET",
  "STAMP_PROMPTS_REFRESH_TRIGGER",
  "STAMP_PROMPTS_REPO_URL",
  "STAMP_PROMPTS_CACHE_ROOT",
  "STAMP_PROMPTS_POLL_INTERVAL_SEC",
  "STAMP_TRASH_SWEEP_INTERVAL_SEC",
];

let dir: string;
let savedEnv: Record<string, string | undefined>;
let refreshCalls: Array<{ opts: CloneOrFetchOpts }>;

beforeEach(() => {
  dir = mkdtempSync(path.join(os.tmpdir(), "stamp-trigger-"));
  savedEnv = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  for (const k of ENV_KEYS) delete process.env[k];
  process.env["STAMP_SERVER_DB_PATH"] = path.join(dir, "users.db");
  refreshCalls = [];
  __setRefreshFnForTests(async (opts) => {
    refreshCalls.push({ opts });
    return { commitSha: "0".repeat(40), refreshedAt: new Date().toISOString() };
  });
  __resetWebhookStateForTests();
});

afterEach(() => {
  stopPromptsRefreshTriggerWatcher();
  __setRefreshFnForTests(null);
  __resetWebhookStateForTests();
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
  rmSync(dir, { recursive: true, force: true });
});

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.once("listening", () => resolve()));
  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("no address");
  return addr.port;
}

function post(port: number, body: Buffer, headers: Record<string, string>): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: "127.0.0.1",
        port,
        path: "/webhook/prompts",
        method: "POST",
        headers: { "Content-Length": String(body.length), ...headers },
      },
      (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode ?? 0));
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

function sign(body: Buffer): string {
  return "sha256=" + createHmac("sha256", SECRET).update(body).digest("hex");
}

async function waitFor(pred: () => boolean, ms = 3000): Promise<void> {
  const until = Date.now() + ms;
  while (!pred()) {
    if (Date.now() > until) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 20));
  }
}

describe("listener side: webhook writes the trigger (AGT-2264)", () => {
  it("valid signature → 202 + trigger holds the delivery id; no in-process refresh, URL not needed", async () => {
    const trigger = path.join(dir, "prompts-refresh");
    process.env["STAMP_PROMPTS_WEBHOOK_SECRET"] = SECRET;
    process.env["STAMP_PROMPTS_REFRESH_TRIGGER"] = trigger;
    const server = startServer(0, { gitWorkers: false });
    try {
      const port = await listen(server);
      const body = Buffer.from('{"ref":"refs/heads/main"}');
      const status = await post(port, body, {
        "X-Hub-Signature-256": sign(body),
        "X-GitHub-Delivery": "abc-123",
      });
      assert.equal(status, 202);
      assert.equal(readFileSync(trigger, "utf8"), "abc-123\n");
      await new Promise((r) => setTimeout(r, 50));
      assert.equal(refreshCalls.length, 0, "listener must not refresh in-process");
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });

  it("invalid signature → 401 and no trigger", async () => {
    const trigger = path.join(dir, "prompts-refresh");
    process.env["STAMP_PROMPTS_WEBHOOK_SECRET"] = SECRET;
    process.env["STAMP_PROMPTS_REFRESH_TRIGGER"] = trigger;
    const server = startServer(0, { gitWorkers: false });
    try {
      const port = await listen(server);
      const status = await post(port, Buffer.from("{}"), {
        "X-Hub-Signature-256": "sha256=" + "0".repeat(64),
      });
      assert.equal(status, 401);
      assert.equal(existsSync(trigger), false);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });

  it("an unwritable trigger location → 500 refresh_trigger_failed", async () => {
    process.env["STAMP_PROMPTS_WEBHOOK_SECRET"] = SECRET;
    process.env["STAMP_PROMPTS_REFRESH_TRIGGER"] = path.join(dir, "missing-dir", "prompts-refresh");
    const server = startServer(0, { gitWorkers: false });
    try {
      const port = await listen(server);
      const body = Buffer.from("{}");
      const status = await post(port, body, { "X-Hub-Signature-256": sign(body) });
      assert.equal(status, 500);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });

  it("default startServer still arms both (positive control)", async () => {
    __resetPollStateForTests();
    __resetTrashSweepStateForTests();
    process.env["STAMP_PROMPTS_REPO_URL"] = "https://example.invalid/prompts.git";
    process.env["STAMP_PROMPTS_POLL_INTERVAL_SEC"] = "3600";
    process.env["STAMP_TRASH_SWEEP_INTERVAL_SEC"] = "3600";
    const server = startServer(0);
    try {
      await listen(server);
      assert.equal(__getPollStateForTests().armed, true);
      assert.equal(__isTrashSweepArmedForTests(), true);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
      __resetPollStateForTests();
      __resetTrashSweepStateForTests();
    }
  });

  it("gitWorkers:false arms neither the prompts poll nor the trash sweep", async () => {
    __resetPollStateForTests();
    __resetTrashSweepStateForTests();
    process.env["STAMP_PROMPTS_REPO_URL"] = "https://example.invalid/prompts.git";
    process.env["STAMP_PROMPTS_POLL_INTERVAL_SEC"] = "3600";
    process.env["STAMP_TRASH_SWEEP_INTERVAL_SEC"] = "3600";
    const server = startServer(0, { gitWorkers: false });
    try {
      await listen(server);
      assert.equal(__getPollStateForTests().armed, false);
      assert.equal(__isTrashSweepArmedForTests(), false);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
      __resetPollStateForTests();
      __resetTrashSweepStateForTests();
    }
  });
});

describe("worker side: trigger watcher runs the coalesced refresh (AGT-2264)", () => {
  it("a replaced trigger fires one refresh with the configured opts", async () => {
    const trigger = path.join(dir, "prompts-refresh");
    process.env["STAMP_PROMPTS_REFRESH_TRIGGER"] = trigger;
    process.env["STAMP_PROMPTS_REPO_URL"] = "https://example.invalid/prompts.git";
    process.env["STAMP_PROMPTS_CACHE_ROOT"] = path.join(dir, "cache");
    startPromptsRefreshTriggerWatcher(20);
    // Let the watcher take its baseline stat (file absent).
    await new Promise((r) => setTimeout(r, 60));
    writePromptsRefreshTrigger(trigger, "delivery-1");
    await waitFor(() => refreshCalls.length === 1);
    assert.equal(refreshCalls[0]!.opts.url, "https://example.invalid/prompts.git");
    assert.equal(refreshCalls[0]!.opts.cacheRoot, path.join(dir, "cache"));
    // No STAMP_PROMPTS_DEPLOY_KEY_PATH and no key at the default location →
    // no key (a keyless https/file:// repo must not be handed a missing key,
    // which the cache module rejects).
    assert.equal(refreshCalls[0]!.opts.deployKeyPath, undefined);
  });

  it("is a no-op without STAMP_PROMPTS_REPO_URL", async () => {
    const trigger = path.join(dir, "prompts-refresh");
    process.env["STAMP_PROMPTS_REFRESH_TRIGGER"] = trigger;
    startPromptsRefreshTriggerWatcher(20);
    await new Promise((r) => setTimeout(r, 60));
    writePromptsRefreshTrigger(trigger, "delivery-1");
    await new Promise((r) => setTimeout(r, 150));
    assert.equal(refreshCalls.length, 0);
  });
});

describe("readPromptsRefreshTrigger treats the file as untrusted (AGT-2264)", () => {
  it("returns the id for a well-formed trigger", () => {
    const p = path.join(dir, "t");
    writePromptsRefreshTrigger(p, "abc-123");
    assert.equal(readPromptsRefreshTrigger(p), "abc-123");
  });

  it("returns 'invalid' (not the content) for a malformed one", () => {
    const p = path.join(dir, "t");
    writeFileSync(p, "line1\nINJECTED log line\n");
    assert.equal(readPromptsRefreshTrigger(p), "invalid");
  });

  it("refuses to follow a symlink", () => {
    const target = path.join(dir, "secret");
    writeFileSync(target, "abc-123\n");
    const p = path.join(dir, "t");
    symlinkSync(target, p);
    assert.equal(readPromptsRefreshTrigger(p), null);
  });

  it("returns 'missing' when the file is gone", () => {
    assert.equal(readPromptsRefreshTrigger(path.join(dir, "nope")), "missing");
  });
});
