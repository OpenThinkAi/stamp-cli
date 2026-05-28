/**
 * `stamp pr listen --org <org>...` — foreground peer-review listener (AGT-429/AGT-430).
 *
 * Connects to the stamp-server's SSE event stream (`GET /peer/events`) with
 * sign-with-key auth (AGT-454) and enters an event loop that:
 *
 *   1. Waits for the next `pr-opened` event parsed from the SSE stream.
 *   2. Skips events where `requested_by_fp` matches the operator's own
 *      fingerprint (author-exclusion).
 *   3. Runs the Haiku triage call against `~/.stamp/peer-watch.md` (AGT-430)
 *      using event metadata (title + paths_changed) only. If `peer-watch.md`
 *      is missing, falls back to a default claim decision. If triage returns
 *      `claim_seat: "skip"`, skips the event.
 *   4. Resolves the named prompt from `~/.stamp/personal/peers/<name>.md`.
 *      Missing prompt → logs `✗` and skips (AC #3).
 *   5. Logs the triage triplet to `~/.stamp/peer-watch.log` (AC #6).
 *   6. Claims a reviewer seat via `claim-seat` (seatClient.ts).
 *   7. Fetches the real unified diff via `gh pr diff <pr_url>` (the per-repo
 *      GitHub authorization boundary). Failure → releases the seat and skips.
 *   8. Starts a 60-second heartbeat interval while the review runs.
 *   9. Runs the peer review via `runBuiltinReview` over the fetched diff using
 *      the resolved named prompt as the system prompt (AC #4).
 *  10. Posts the result via `gh pr review <pr_url> <flag> -b "<body>"` where
 *      `<flag>` is `--approve`, `--request-changes`, or `--comment` depending
 *      on the verdict returned by the model.
 *  11. Releases the seat on `gh` failure; loops back to step 1.
 *  12. On SIGINT: emits "note: shutting down", releases any held seat, exits 0.
 *
 * Transport: SSE is the sole listen transport. It requires `http_url` in
 * ~/.stamp/server.yml (the HTTP origin of the stamp-server). The WS transport
 * and the SSH-verb long-poll fallback were retired (AGT-454).
 *
 * Exit codes:
 *   0   — clean shutdown (SIGINT / ctrl-C)
 *   1   — auth failure (keypair missing, SSE connect failed)
 *   2   — arg-parse error (no --org provided; enforced by Commander)
 */

import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { loadUserKeypair, type Keypair } from "../lib/keys.js";
import { signBytes } from "../lib/signing.js";
import { canonicalSerializePeerPayload } from "../lib/attestationV4.js";
import { loadServerConfig } from "../lib/serverConfig.js";
import type { ServerConfig } from "../lib/serverConfig.js";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import type { IncomingMessage } from "node:http";
import type { Readable } from "node:stream";
import type { PeerReviewEvent } from "../lib/peerReviewEvent.js";
import {
  callClaimSeat,
  callHeartbeat,
  callReleaseSeat,
  type SshSpawnFn,
} from "../lib/seatClient.js";
import {
  runBuiltinReview,
  BUILTIN_DEFAULT_PROMPT,
  BUILTIN_PROMPT_NAME,
  type RunBuiltinReviewInput,
} from "../lib/builtinReviewPrompt.js";
import {
  runTriage,
  loadPeerWatchRules,
  FALLBACK_DECISION,
  type TriageDecision,
  type TriageInput,
} from "../lib/peerTriage.js";
import {
  resolveNamedPrompt,
  type ResolveNamedPromptInput,
} from "../lib/namedPrompt.js";
import { appendTriplet, type TripletRecord } from "../lib/peerWatchLog.js";
import { firePeerNotification } from "../lib/peerNotify.js";
import { draftsDir } from "../lib/paths.js";
import { loadPeerReposConfig, resolveLocalRepoPath } from "../lib/peerReposConfig.js";
import { verifyOperatorAtBaseLocal } from "../lib/peerOperatorVerify.js";
import { detectClaudeSession } from "../lib/claudeSession.js";

// ─── Options ──────────────────────────────────────────────────────────

export interface PrListenOptions {
  orgs: string[];
  /** `--server <host:port>` override. */
  server?: string;
  /**
   * Pass `--headless` to opt into daemon-mode operation without a hosting
   * Claude Code session. Loud warnings are printed on every startup; then
   * the listener proceeds unchanged. Without `--headless` (the default),
   * `stamp pr listen` requires an active Claude Code session (detected via
   * `CLAUDECODE=1` + `CLAUDE_CODE_SESSION_ID`) and exits 2 if one is absent.
   */
  headless?: boolean;
  /**
   * Test-only: inject a fake `process.env`-like object for `detectClaudeSession`.
   * When set, the session detection uses this env instead of `process.env`.
   */
  _envForTest?: NodeJS.ProcessEnv;
  /** Test-only: inject a fake SSH spawn function to avoid real network calls. */
  _sshSpawnForTest?: SshSpawnFn;
  /** Test-only: inject a fake `gh pr review` spawn result. */
  _ghReviewForTest?: (prUrl: string, body: string, verdictFlag: string) => { status: number; stderr: string };
  /** Test-only: inject a fake `gh pr diff` spawn result. */
  _ghDiffForTest?: (prUrl: string) => { status: number; stdout: string; stderr: string };
  /** Test-only: inject a fake SDK runner for the Sonnet review call. */
  _sdkRunnerForTest?: (diff: string) => Promise<string>;
  /** Test-only: inject a fake Haiku runner for the triage call. */
  _haikuRunnerForTest?: (system: string, user: string) => Promise<string>;
  /** Test-only: inject a keypair directly to skip reading from disk.
   *  Pass `null` to simulate the "no keypair" error path. */
  _keypairForTest?: Keypair | null;
  /** Test-only: replace `setInterval` to control heartbeat. */
  _setIntervalForTest?: (fn: () => void, ms: number) => ReturnType<typeof setInterval>;
  /** Test-only: override cwd passed to the builtin review. */
  _cwdForTest?: string;
  /**
   * Test-only: pre-queued events to process deterministically. When set, the
   * listener loop drains this array (one event per iteration) instead of
   * connecting to / blocking on the SSE stream. After the queue is
   * drained, the loop exits normally (exit 0). This lets tests drive the full
   * loop in-process with no timers or background goroutines.
   */
  _eventQueueForTest?: PeerReviewEvent[];
  /** Test-only: inject a fake peer-watch.md read result. `null` → file missing. */
  _peerWatchRulesForTest?: { rules: string; hash: string } | null;
  /** Test-only: inject a fake named-prompt resolver. */
  _resolveNamedPromptForTest?: (input: ResolveNamedPromptInput) => ReturnType<typeof resolveNamedPrompt>;
  /** Test-only: inject a fake triplet-append function.
   *  Called with the full triplet record instead of writing to disk. */
  _appendTripletForTest?: (record: TripletRecord) => void;
  /**
   * Test-only: override `new Date()` so day-rollover logic is deterministic.
   * Returns a Date used for local-TZ day-key computation.
   */
  _nowForTest?: () => Date;
  /**
   * Test-only: replace `firePeerNotification` so tests can assert notifications
   * without spawning osascript.
   */
  _notifyForTest?: (title: string, body: string) => void;
  /**
   * Test-only: replace the draft file write so tests can assert draft content
   * without touching the real filesystem.
   * Receives (filePath, content) — the full draft markdown string.
   */
  _writeDraftForTest?: (filePath: string, content: string) => void;
  /**
   * Test-only: pre-seed the daily spend accumulator to a specific value.
   * Allows tests to simulate cost-cap triggering without a real SDK call
   * (which would otherwise return costUsd: 0 via the test seam).
   */
  _initialDailySpendForTest?: number;
  /**
   * Test-only: override the client-side operator verification step (AGT-454).
   * When provided, `verifyOperatorAtBaseLocal` is NOT called. The function
   * receives (localRepoPath, baseSha, fingerprint) and returns the same shape
   * as `verifyOperatorAtBaseLocal`. Use `() => ({ ok: true })` to bypass the
   * gate for tests that pre-date AGT-454 and don't need operator verification.
   */
  _operatorVerifyForTest?: (
    localRepoPath: string,
    baseSha: string,
    fingerprint: string,
  ) => { ok: true } | { ok: false; reason: string };
  /**
   * Test-only: override the peer-repos map loaded from `~/.stamp/peer-repos.yml`
   * (AGT-454). When provided, `loadPeerReposConfig()` is NOT called. Pass a
   * `Map<string, string>` of `{ "org/repo" => "/absolute/path" }` to control
   * which repos are considered mapped. Pass an empty Map to simulate an
   * empty/missing config file.
   */
  _peerReposMapForTest?: Map<string, string>;
  /**
   * Test-only: inject a readable stream of raw `text/event-stream` bytes in
   * place of a real HTTPS GET to `/peer/events`. When set, the SSE connect
   * step is skipped and this stream is parsed directly. Used to drive the SSE
   * parser deterministically without a server.
   */
  _sseStreamForTest?: Readable;
  /**
   * Test-only: replace `sleep` (used by the reconnect backoff loop) so tests
   * can capture requested delay values without actually waiting. The injected
   * function receives the delay in milliseconds; it should return a resolved
   * Promise immediately (or after any synthetic wait the test requires).
   */
  _sleepForTest?: (ms: number) => Promise<void>;
  /**
   * Test-only: replace the entire `connectSseTransport` call so tests can
   * control connection success/failure, stream lifecycle, and reconnect
   * behaviour without a real server. The factory is called once per
   * connection attempt (including reconnects). Signature matches
   * `connectSseTransport`'s return type.
   */
  _connectSseForTest?: (
    attempt: number,
  ) => Promise<
    | { ok: true; nextEvent: () => Promise<PeerReviewEvent | null>; close: () => void }
    | { ok: false; reason: string }
  >;
  /**
   * Test-only: cap the number of reconnect attempts before the reconnect loop
   * gives up and returns null (which causes the outer event loop to call
   * process.exit(0)). Without this, the reconnect loop in SSE mode only
   * terminates when `shuttingDown` is set (SIGINT). Use this seam in tests
   * that exercise the reconnect loop but don't want to fire real SIGINT.
   */
  _maxReconnectAttemptsForTest?: number;
}

// ─── Helpers ──────────────────────────────────────────────────────────

/**
 * Canonical payload signing: `sortKeysDeep` (excluding the `signature` field)
 * then `JSON.stringify` then Ed25519 sign. This is the single canonicalizer
 * pinned across all peer-review signing/verifying call sites (AGT-434, AC 4).
 *
 * The function accepts any object as the payload body; callers must ensure
 * the object does NOT include a `signature` field (omit it before signing).
 */
function canonicalSign(keypair: Keypair, payloadBody: object): string {
  return signBytes(keypair.privateKeyPem, canonicalSerializePeerPayload(payloadBody));
}

/**
 * Build the SSE `/peer/events` URL from a `ServerConfig` + org list.
 *
 * Returns `{ ok: true, url }` when `httpUrl` is set (strips a trailing `/`
 * from the origin before appending `/peer/events?org=...`).
 * Returns `{ ok: false, reason }` with an actionable error message when
 * `httpUrl` is absent — the SSH host:port cannot be used for the HTTP stream.
 *
 * Exported for unit testing.
 */
export function buildPeerEventsUrl(
  serverCfg: ServerConfig,
  orgs: string[],
): { ok: true; url: string } | { ok: false; reason: string } {
  if (!serverCfg.httpUrl) {
    return {
      ok: false,
      reason:
        "SSE transport requires 'http_url' in ~/.stamp/server.yml " +
        "(e.g. http_url: https://stamp-cli-production.up.railway.app). " +
        "The SSH host:port cannot be used for the HTTP event stream — " +
        "the HTTP server lives at a different URL.",
    };
  }
  const base = `${serverCfg.httpUrl.replace(/\/$/, "")}/peer/events`;
  const query = orgs.map((o) => `org=${encodeURIComponent(o)}`).join("&");
  return { ok: true, url: query ? `${base}?${query}` : base };
}

/**
 * Parse a `text/event-stream` body into PeerReviewEvent objects.
 *
 * SSE framing: events are separated by a blank line; `data:` lines within a
 * frame are concatenated; comment lines (`:`-prefixed, e.g. heartbeats) are
 * ignored. Each completed frame's accumulated `data` payload is JSON-parsed
 * into a PeerReviewEvent and pushed via `onEvent`. Malformed frames are
 * dropped (logged to stderr) rather than aborting the stream.
 *
 * Exported for unit testing with an injected stream.
 */
export function parseSseStream(
  stream: Readable,
  onEvent: (event: PeerReviewEvent) => void,
): void {
  let buffer = "";
  let dataLines: string[] = [];

  const flushFrame = (): void => {
    if (dataLines.length === 0) return;
    const raw = dataLines.join("\n");
    dataLines = [];
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      process.stderr.write(`note: dropping malformed SSE frame\n`);
      return;
    }
    const event: PeerReviewEvent = {
      event_type: typeof parsed["event_type"] === "string" ? parsed["event_type"] : "unknown",
      patch_id: typeof parsed["patch_id"] === "string" ? parsed["patch_id"] : "",
      actor_fp: typeof parsed["actor_fp"] === "string" ? parsed["actor_fp"] : "",
      payload:
        typeof parsed["payload"] === "object" && parsed["payload"] !== null
          ? (parsed["payload"] as object)
          : {},
    };
    onEvent(event);
  };

  stream.setEncoding("utf8");
  stream.on("data", (chunk: string) => {
    buffer += chunk;
    let nlIdx: number;
    while ((nlIdx = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, nlIdx).replace(/\r$/, "");
      buffer = buffer.slice(nlIdx + 1);
      if (line === "") {
        // Blank line → end of one event frame.
        flushFrame();
        continue;
      }
      if (line.startsWith(":")) {
        // Comment / heartbeat — ignore.
        continue;
      }
      if (line.startsWith("data:")) {
        // Per the SSE spec, a single leading space after the colon is stripped.
        dataLines.push(line.slice(5).replace(/^ /, ""));
      }
      // Other field lines (event:, id:, retry:) are ignored — the server only
      // emits data: frames.
    }
  });
}

/**
 * Connect to the stamp-server's SSE `/peer/events` endpoint with sign-with-key
 * auth headers, and return an async event source (`nextEvent`) that yields the
 * pushed PeerReviewEvent objects.
 *
 * Auth (AGT-454): the client signs a canonical string `peer-events\n<iso8601>`
 * with its Ed25519 operator key and sends:
 *   x-stamp-pubkey     SPKI PEM (base64-encoded)
 *   x-stamp-timestamp  ISO-8601 timestamp
 *   x-stamp-signature  base64 Ed25519 signature
 * The server verifies the signature, checks the timestamp window, and confirms
 * the key is an enrolled user. A non-200 response → `{ ok: false, reason }`.
 *
 * Reconnection is the caller's job; this connects once. When the underlying
 * stream ends, `nextEvent()` resolves to `null` (end-of-stream).
 */
async function connectSseTransport(
  keypair: Keypair,
  orgs: string[],
  serverCfg: ServerConfig,
  streamOverride?: Readable,
): Promise<
  | { ok: true; nextEvent: () => Promise<PeerReviewEvent | null>; close: () => void }
  | { ok: false; reason: string }
> {
  // Per-event delivery plumbing shared by both the live and injected paths.
  const queue: PeerReviewEvent[] = [];
  let pendingResolve: ((event: PeerReviewEvent | null) => void) | null = null;
  let ended = false;

  const deliver = (event: PeerReviewEvent): void => {
    if (pendingResolve) {
      const r = pendingResolve;
      pendingResolve = null;
      r(event);
    } else {
      queue.push(event);
    }
  };
  const signalEnd = (): void => {
    ended = true;
    if (pendingResolve) {
      const r = pendingResolve;
      pendingResolve = null;
      r(null);
    }
  };
  const nextEvent = (): Promise<PeerReviewEvent | null> =>
    new Promise<PeerReviewEvent | null>((resolve) => {
      if (queue.length > 0) {
        resolve(queue.shift()!);
        return;
      }
      if (ended) {
        resolve(null);
        return;
      }
      pendingResolve = resolve;
    });

  // ─── Test seam: parse an injected stream directly ──────────────────
  if (streamOverride) {
    parseSseStream(streamOverride, deliver);
    streamOverride.on("end", signalEnd);
    streamOverride.on("close", signalEnd);
    streamOverride.on("error", signalEnd);
    return { ok: true, nextEvent, close: () => streamOverride.destroy() };
  }

  // ─── Live connection ───────────────────────────────────────────────
  const urlResult = buildPeerEventsUrl(serverCfg, orgs);
  if (!urlResult.ok) return { ok: false, reason: urlResult.reason };

  const timestamp = new Date().toISOString();
  const signature = signBytes(
    keypair.privateKeyPem,
    Buffer.from(`peer-events\n${timestamp}`, "utf8"),
  );
  const headers: Record<string, string> = {
    Accept: "text/event-stream",
    "x-stamp-pubkey": Buffer.from(keypair.publicKeyPem, "utf8").toString("base64"),
    "x-stamp-timestamp": timestamp,
    "x-stamp-signature": signature,
  };

  const parsed = new URL(urlResult.url);
  const requestFn = parsed.protocol === "https:" ? httpsRequest : httpRequest;

  return new Promise((resolve) => {
    const req = requestFn(
      parsed,
      { method: "GET", headers },
      (res: IncomingMessage) => {
        if (res.statusCode !== 200) {
          let body = "";
          res.setEncoding("utf8");
          res.on("data", (c: string) => { body += c; });
          res.on("end", () => {
            resolve({
              ok: false,
              reason: `server responded ${res.statusCode}${body ? `: ${body.trim()}` : ""}`,
            });
          });
          return;
        }
        parseSseStream(res, deliver);
        res.on("end", signalEnd);
        res.on("close", signalEnd);
        res.on("error", signalEnd);
        resolve({ ok: true, nextEvent, close: () => req.destroy() });
      },
    );
    // SSE streams are long-lived; the default HTTPS agent idle timeout tears
    // down quiet sockets (seen as CLIENT socket onTimeout in NODE_DEBUG=https).
    // Override the per-socket idle timeout and enable TCP keepalive so the
    // connection survives quiet windows between events.
    req.on("socket", (socket) => {
      socket.setKeepAlive(true, 30_000);
      socket.setTimeout(0);
    });
    // Defensive: if a timeout fires (e.g. from a future caller override),
    // destroy the request so the reconnect loop can restart the connection.
    req.on("timeout", () => {
      req.destroy(new Error("SSE socket idle timeout"));
    });
    req.on("error", (err: Error) => {
      if (!ended) resolve({ ok: false, reason: `SSE connection error: ${err.message}` });
    });
    req.end();
  });
}

/** Sleep for `ms` milliseconds (used by the SSE reconnect backoff loop). */
function sleep(ms: number): Promise<void> {
  return new Promise<void>((resolve) => setTimeout(resolve, ms));
}

/**
 * Return a YYYY-MM-DD string in local time, used to detect day rollovers for
 * the in-memory daily spend accumulator.
 */
function localDayKey(d: Date): string {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

/**
 * Resolve the ServerConfig from options or the user config file.
 * Returns a discriminated result so the caller can emit distinct error messages
 * for "invalid --server format" vs "no server configured at all".
 */
function resolveServerConfig(
  server?: string,
): { cfg: ServerConfig } | { cfg: null; reason: "invalid_format" | "not_configured" } {
  if (server) {
    const m = server.trim().match(/^([^:]+):(\d+)$/);
    if (!m) return { cfg: null, reason: "invalid_format" };
    const port = Number(m[2]);
    if (!Number.isInteger(port) || port < 1 || port > 65535)
      return { cfg: null, reason: "invalid_format" };
    return {
      cfg: { host: m[1]!, port, user: "git", repoRootPrefix: "/srv/git" },
    };
  }
  const loaded = loadServerConfig();
  if (!loaded) return { cfg: null, reason: "not_configured" };
  return { cfg: loaded };
}

// ─── Event loop ───────────────────────────────────────────────────────

/**
 * Core event loop. Exposed for testing (tests call this directly with
 * injected seams; Commander calls it via `runPrListen`).
 */
export async function runPrListen(opts: PrListenOptions): Promise<void> {
  const { orgs } = opts;

  // ─── Session-hosted guard ─────────────────────────────────────────
  // Default mode: stamp pr listen requires a hosting Claude Code session.
  // Without one the listener becomes a daemon by behavior (no presence,
  // no observability, holds keys without active consent) — explicitly
  // out of scope for this feature. --headless opts into daemon-mode with
  // loud, non-suppressible warnings.
  if (opts.headless) {
    process.stderr.write(
      `warning: --headless: listener will run without a hosting Claude session.\n` +
        `  - no presence: events will be triaged and posted to GitHub on your behalf\n` +
        `    with no interactive operator. close this terminal and you have a daemon.\n` +
        `  - quota: Claude Code subscription / ANTHROPIC_API_KEY usage is silent.\n` +
        `    set cost_cap_usd in peer-watch.md or you can blow through limits.\n` +
        `  - identity: every review posts under your gh identity. you are the\n` +
        `    operator of record for whatever this thing approves or comments.\n` +
        `  - shutdown: exits on ctrl-C only. no automatic session-end teardown.\n` +
        `  this mode is explicitly opt-in; the supported default is session-hosted.\n`,
    );
    // Proceed with the rest of the listener startup.
  } else {
    const envToProbe = opts._envForTest ?? process.env;
    const sessionResult = detectClaudeSession(envToProbe);
    if (!sessionResult.ok) {
      process.stderr.write(
        `error: stamp pr listen requires an active Claude Code session as its host.\n` +
          `  open Claude Code and run this command from within the session (so it can\n` +
          `  spawn the listener as a managed background process). without a hosting\n` +
          `  session there is no presence: the listener becomes a de-facto daemon,\n` +
          `  which is explicitly out of scope for this feature.\n` +
          `\n` +
          `  to run anyway, pass --headless. read the warnings carefully — running\n` +
          `  unattended changes the trust model (silent quota burn, no observability,\n` +
          `  no ctrl-C-driven exit when you walk away).\n`,
      );
      process.exit(2);
    }
    // Bound to a Claude session — log the binding line.
    const sessionPrefix = sessionResult.session.sessionId.slice(0, 8);
    process.stderr.write(`note: bound to Claude session ${sessionPrefix}\n`);
  }

  // ─── Auth preflight ───────────────────────────────────────────────
  // Prefer the injected seam; only fall through to loadUserKeypair when the
  // key is genuinely absent from options (undefined, not null — null is the
  // "no key" test path that forces the error path).
  const keypair: Keypair | null =
    opts._keypairForTest !== undefined ? (opts._keypairForTest as Keypair | null) : loadUserKeypair();
  if (!keypair) {
    process.stderr.write(
      `error: no stamp signing key found at ~/.stamp/keys/ed25519. ` +
        `Run 'stamp keys generate' to create one.\n`,
    );
    process.exit(1);
  }

  const serverResult = resolveServerConfig(opts.server);
  if (!serverResult.cfg) {
    if (serverResult.reason === "invalid_format") {
      process.stderr.write(
        `error: invalid --server format ${JSON.stringify(opts.server)} — expected host:port ` +
          `(e.g. stamp.example.com:2222)\n`,
      );
    } else {
      process.stderr.write(
        `error: no stamp-server configured. Run 'stamp server config <host:port>' or pass --server.\n`,
      );
    }
    process.exit(1);
  }
  const serverCfg: ServerConfig = serverResult.cfg;

  // ─── Transport: SSE (sole listen transport, AGT-454) ─────────────
  // Connect to the stamp-server's `GET /peer/events` SSE stream. The
  // signed-key auth (x-stamp-pubkey/timestamp/signature) is built inside
  // connectSseTransport. In tests, an in-memory stream is injected via
  // _sseStreamForTest; in queue-mode tests the connect step is skipped
  // entirely (the loop drains _eventQueueForTest).
  const useQueueMode = Array.isArray(opts._eventQueueForTest);

  // sseCleanup: called on shutdown to close the SSE stream gracefully.
  let sseCleanup: (() => void) | null = null;
  // sseNextEvent: the per-event resolver fed by the SSE parser.
  let sseNextEvent: (() => Promise<PeerReviewEvent | null>) | null = null;
  // Whether the outer reconnect loop should keep running.
  let shuttingDown = false;

  // Reconnect backoff constants for the SSE loop.
  const BACKOFF_BASE_MS = 1_000;
  const BACKOFF_CAP_MS = 60_000;

  // sleepFn: injectable for tests so they don't actually wait.
  const sleepFn = opts._sleepForTest ?? sleep;

  if (!useQueueMode) {
    // ── Initial connection with reconnect-on-end loop ────────────────
    // The first connection attempt happens here before the event loop starts.
    // If it fails, we exit(1) (same as before). Subsequent disconnections
    // (stream ended, socket teardown, etc.) trigger the reconnect loop below
    // once we're inside the event loop.
    let connectAttempt = 0;
    const connectFn = opts._connectSseForTest
      ? (attempt: number) => opts._connectSseForTest!(attempt)
      : (_attempt: number) =>
          connectSseTransport(keypair, orgs, serverCfg, opts._sseStreamForTest);

    // First attempt — exit 1 on failure (keeps existing startup-failure UX).
    const firstResult = await connectFn(connectAttempt);
    if (!firstResult.ok) {
      process.stderr.write(
        `error: SSE connect failed — ${firstResult.reason}\n`,
      );
      process.exit(1);
    }
    // innerNextEvent tracks the *current stream's* nextEvent function and is
    // updated on each successful reconnect. It is intentionally separate from
    // sseNextEvent (which is overwritten below with the reconnecting wrapper).
    let innerNextEvent: () => Promise<PeerReviewEvent | null> = firstResult.nextEvent;
    sseCleanup = firstResult.close;
    process.stderr.write(`⟳ subscribed (SSE); listening for PR events\n`);

    // ── Reconnect-on-end inner loop ─────────────────────────────────
    // Wraps innerNextEvent so that when the stream ends (null returned), the
    // listener reconnects with exponential backoff rather than exiting.
    // This is the fix for the silent-deaf bug: the SSE stream can end at any
    // time (socket teardown, server hangup, network hiccup) and the listener
    // must re-establish the connection transparently.
    //
    // Key: this function closes over `innerNextEvent` (a `let` variable) rather
    // than over `sseNextEvent` (which is replaced with this very function below).
    // Updating `innerNextEvent` on reconnect avoids the self-calling recursion
    // that would result from closing over `sseNextEvent`.
    // totalReconnects tracks reconnect cycles (stream-end → reconnect) across
    // the lifetime of this listener. Declared outside the closure so it
    // accumulates correctly across multiple outer-loop calls to nextEvent().
    // Used only for the _maxReconnectAttemptsForTest cap seam.
    let totalReconnects = 0;

    const reconnectingNextEvent = async (): Promise<PeerReviewEvent | null> => {
      for (;;) {
        if (shuttingDown) return null;
        const event = await innerNextEvent();
        if (event !== null) {
          // Normal event — return it to the event loop.
          return event;
        }
        // Stream ended. If we're shutting down, propagate the null.
        if (shuttingDown) return null;

        // Test seam: stop reconnecting after a configured number of cycles.
        totalReconnects += 1;
        if (
          opts._maxReconnectAttemptsForTest !== undefined &&
          totalReconnects > opts._maxReconnectAttemptsForTest
        ) {
          return null;
        }

        process.stderr.write(`note: SSE stream ended; reconnecting…\n`);

        // Reconnect with exponential backoff. connectAttempt counts how many
        // times we have attempted a reconnect since the last clean connection.
        let succeeded = false;
        while (!shuttingDown) {
          const delay = Math.min(BACKOFF_CAP_MS, BACKOFF_BASE_MS * 2 ** connectAttempt);
          await sleepFn(delay);
          if (shuttingDown) return null;

          const retryResult = await connectFn(connectAttempt);
          connectAttempt += 1;

          if (retryResult.ok) {
            sseCleanup = retryResult.close;
            innerNextEvent = retryResult.nextEvent;
            const totalRetries = connectAttempt;
            const retryMsg =
              totalRetries === 1
                ? `⟳ resubscribed (SSE)\n`
                : `⟳ resubscribed (SSE) after ${totalRetries} retries\n`;
            process.stderr.write(retryMsg);
            connectAttempt = 0;
            succeeded = true;
            break;
          }
          // Still failing — log the reason and the next delay.
          const nextDelay = Math.min(BACKOFF_CAP_MS, BACKOFF_BASE_MS * 2 ** connectAttempt);
          process.stderr.write(
            `note: SSE connect failed (${retryResult.reason}); retrying in ${Math.round(nextDelay / 1000)}s (attempt ${connectAttempt + 1})\n`,
          );
        }
        if (!succeeded) return null;
        // Loop back to try reading from the fresh stream.
      }
    };

    // sseNextEvent now points to the reconnecting wrapper; the outer event
    // loop will call it for every event. innerNextEvent (updated on reconnect)
    // is what actually reads from the current live stream.
    sseNextEvent = reconnectingNextEvent;
  }

  // ─── Daily spend accumulator (AGT-432 AC #2) ──────────────────────
  // In-memory accumulator scoped to this listener process lifetime.
  // Resets at local-TZ midnight. Not persisted across restarts.
  const nowFn = opts._nowForTest ?? (() => new Date());
  let dailySpend = opts._initialDailySpendForTest ?? 0;
  let spendDayKey = localDayKey(nowFn());

  /** Advance the daily spend counter, resetting at local midnight. */
  function addDailySpend(amount: number): void {
    const today = localDayKey(nowFn());
    if (today !== spendDayKey) {
      // Day rolled over — reset accumulator.
      dailySpend = 0;
      spendDayKey = today;
    }
    dailySpend += amount;
  }

  // ─── SIGINT handler ──────────────────────────────────────────────
  let currentSeatPatchId: string | null = null;
  let currentHeartbeatHandle: ReturnType<typeof setInterval> | null = null;

  function clearHeartbeat(): void {
    if (currentHeartbeatHandle !== null) {
      clearInterval(currentHeartbeatHandle);
      currentHeartbeatHandle = null;
    }
  }

  async function shutdown(): Promise<void> {
    process.stderr.write(`note: shutting down\n`);
    shuttingDown = true;
    clearHeartbeat();
    // Close the SSE stream (no-op in queue-mode tests).
    if (sseCleanup) sseCleanup();

    if (currentSeatPatchId !== null) {
      await callReleaseSeat({
        patch_id: currentSeatPatchId,
        claimant_fp: keypair!.fingerprint,
        signature: canonicalSign(keypair!, {
          patch_id: currentSeatPatchId,
          claimant_fp: keypair!.fingerprint,
        }),
        serverConfig: serverCfg!,
        _sshSpawnForTest: opts._sshSpawnForTest,
      });
    }
    process.exit(0);
  }

  process.on("SIGINT", () => {
    void shutdown();
  });

  // ─── Event loop ───────────────────────────────────────────────────
  //
  // Two event sources in priority order:
  //   1. _eventQueueForTest (test seam): drains a pre-queued array.
  //   2. sseNextEvent (SSE transport): awaits the next pushed frame.
  //
  // When `_eventQueueForTest` is provided (test seam), drain that array
  // deterministically instead of blocking on the SSE stream. This avoids
  // timer/goroutine races in `node --test` environments.

  async function nextEvent(): Promise<PeerReviewEvent | null> {
    if (useQueueMode) {
      // Drain the pre-queued array; return null to signal "done".
      const q = opts._eventQueueForTest!;
      if (q.length === 0) return null;
      return q.shift()!;
    }
    if (sseNextEvent) {
      return sseNextEvent();
    }
    return null;
  }

  // AGT-454: load peer-repos map once before the loop (fail-closed per-event).
  // Prefer the injected test seam over the real config file.
  const peerReposMap =
    opts._peerReposMapForTest !== undefined
      ? opts._peerReposMapForTest
      : loadPeerReposConfig();

  for (;;) {
    const event = await nextEvent();
    // null means the queue is drained (queue-mode test) or the SSE stream
    // ended — exit the loop cleanly.
    if (event === null) {
      clearHeartbeat();
      if (sseCleanup) sseCleanup();
      process.exit(0);
    }

    // AGT-431 AC #11: handle re-review-requested identically to pr-opened
    // (re-run triage → claim → review → post against the new patch_id).
    // The only visible difference is the kind: "re-review" triplet log tag (AC #12).
    // This branch is intentionally thin and localized — AGT-432 adds
    // cost-cap enforcement to the same loop without needing to touch this code.

    // Extract PR metadata from the event payload.
    const payload = event.payload as Record<string, unknown>;
    const prNumber =
      typeof payload["pr_number"] === "number"
        ? payload["pr_number"]
        : typeof payload["patch_id"] === "string"
          ? `(patch ${payload["patch_id"].slice(0, 8)})`
          : "?";
    const patchId =
      typeof payload["patch_id"] === "string"
        ? payload["patch_id"]
        : event.patch_id;
    const baseSha =
      typeof payload["base_sha"] === "string"
        ? payload["base_sha"]
        : "0".repeat(40);
    const repo =
      typeof payload["repo"] === "string"
        ? payload["repo"]
        : "unknown/unknown";
    const prUrlRaw =
      typeof payload["pr_url"] === "string"
        ? payload["pr_url"]
        : "";
    // Security: validate pr_url before passing to `gh` as an argv element.
    // A flag-shaped pr_url (e.g. `-H` or `--hostname=evil`) would be
    // interpreted as a CLI option by gh rather than a positional argument,
    // since `--` is absent. The regex also catches the empty/absent fallback.
    const PR_URL_REGEX =
      /^https:\/\/(?:[a-zA-Z0-9.-]+)\/[^/]+\/[^/]+\/pull\/\d+$/;
    if (!PR_URL_REGEX.test(prUrlRaw)) {
      process.stderr.write(
        `note: skipping event for PR #${prNumber} — pr_url ${JSON.stringify(prUrlRaw)} ` +
          `does not match expected https://<host>/<owner>/<repo>/pull/<n> shape\n`,
      );
      continue;
    }
    const prUrl = prUrlRaw;
    // AGT-454: the notification payload is metadata-only — the real unified
    // diff is fetched via `gh pr diff` AFTER a successful seat claim (the
    // per-repo GitHub authorization boundary). No diff/body fallback here.
    const requestedByFp =
      typeof payload["requested_by_fp"] === "string"
        ? payload["requested_by_fp"]
        : event.actor_fp;

    process.stderr.write(`⟳ triaging event for PR #${prNumber}\n`);

    // ─── Author-exclusion ────────────────────────────────────────
    if (requestedByFp === keypair.fingerprint) {
      process.stderr.write(
        `note: skipping event for PR #${prNumber} — author matches own fingerprint\n`,
      );
      continue;
    }

    // ─── AGT-454: Client-side operator verification ──────────────
    // Verify the PR author (requested_by_fp) is an operator in the manifest
    // at base_sha of this listener's own local clone. Fail-closed: skip if
    // the repo is unmapped in peer-repos.yml or if the sha is not present.
    if (event.event_type === "pr-opened") {
      const localRepoPath = resolveLocalRepoPath(repo, peerReposMap);
      if (localRepoPath === null) {
        process.stderr.write(
          `note: skipping event for PR #${prNumber} — repo "${repo}" is not mapped in ` +
            `~/.stamp/peer-repos.yml; add it to enable operator verification for this repo\n`,
        );
        continue;
      }
      const verifyFn = opts._operatorVerifyForTest ?? verifyOperatorAtBaseLocal;
      const opResult = verifyFn(localRepoPath, baseSha, requestedByFp);
      if (!opResult.ok) {
        process.stderr.write(
          `note: skipping event for PR #${prNumber} — operator verification failed: ${opResult.reason}\n`,
        );
        continue;
      }
    }

    // ─── AGT-430: Haiku triage call ──────────────────────────────
    // Load operator rules from ~/.stamp/peer-watch.md.
    // If missing, fall back to the default decision (AC #8).
    const prTitle =
      typeof payload["title"] === "string" ? payload["title"] : "";
    // Triage runs on metadata only (title + paths_changed). The payload no
    // longer carries a diff/body, so prBody is intentionally empty here.
    const prBody = "";
    const prPaths: string[] =
      Array.isArray(payload["paths_changed"])
        ? (payload["paths_changed"] as unknown[]).filter((p): p is string => typeof p === "string")
        : [];

    let rulesResult: { rules: string; hash: string } | null;
    if (opts._peerWatchRulesForTest !== undefined) {
      rulesResult = opts._peerWatchRulesForTest;
    } else {
      rulesResult = loadPeerWatchRules();
    }

    let triageDecision: TriageDecision;
    let rulesHash: string;
    let triageCostUsd = 0;

    if (rulesResult === null) {
      // AC #8: peer-watch.md missing → log ⟳ notice + use fallback decision.
      process.stderr.write(
        `⟳ no ~/.stamp/peer-watch.md found; using default claim policy (if_available)\n`,
      );
      triageDecision = { ...FALLBACK_DECISION };
      rulesHash = "";
    } else {
      rulesHash = rulesResult.hash;
      const triageInput: TriageInput = {
        rules: rulesResult.rules,
        event: {
          repo,
          title: prTitle,
          body: prBody,
          paths: prPaths,
        },
        cwd: opts._cwdForTest ?? process.cwd(),
        _haikuRunnerForTest: opts._haikuRunnerForTest,
      };
      const triageResult = await runTriage(triageInput);
      triageDecision = triageResult.decision;
      triageCostUsd = triageResult.costUsd;
    }

    // ─── AGT-432 AC #2/#3: Cost-cap enforcement ───────────────────
    // At the single triage-finalize point, after triage resolves (covering
    // BOTH pr-opened and re-review-requested events), add the triage cost and
    // check whether the daily cap has been reached. This intentionally runs
    // before the triplet log so the logged decision reflects the downgrade.
    addDailySpend(triageCostUsd);

    let wasCapDowngraded = false;
    if (
      typeof triageDecision.cost_cap_usd === "number" &&
      triageDecision.cost_cap_usd > 0 &&
      dailySpend >= triageDecision.cost_cap_usd &&
      (triageDecision.claim_seat === "if_available" || triageDecision.claim_seat === "always")
    ) {
      // Downgrade to skip: daily cap hit.
      const capUsd = triageDecision.cost_cap_usd;
      triageDecision = { ...triageDecision, claim_seat: "skip" };
      wasCapDowngraded = true;
      const notifyTitle = "stamp peer";
      const notifyBody = `Daily review cap ($${capUsd.toFixed(2)}) reached — skipping PR #${prNumber}`;
      // Fire desktop notification (fire-and-forget, must never crash/stall).
      firePeerNotification({
        title: notifyTitle,
        body: notifyBody,
        _notifyForTest: opts._notifyForTest,
      });
    }

    // ─── Log triplet (AC #6 / AGT-431 AC #12 / AGT-432 AC #4) ──
    // Append regardless of whether we skip or claim.
    // For re-review-requested events, tag with kind: "re-review" (AC #12).
    // For cap-triggered skips, include reason: "daily cap hit" (AGT-432 AC #4).
    {
      const tripletRecord: TripletRecord = {
        ts: nowFn().toISOString(),
        repo,
        pr_url: prUrl,
        rules_hash: rulesHash,
        event_payload: payload as Record<string, unknown>,
        decision: triageDecision,
        ...(event.event_type === "re-review-requested" ? { kind: "re-review" } : {}),
        ...(wasCapDowngraded ? { reason: "daily cap hit" } : {}),
      };
      if (opts._appendTripletForTest) {
        opts._appendTripletForTest(tripletRecord);
      } else {
        appendTriplet(tripletRecord);
      }
    }

    // ─── Triage decision: skip? ──────────────────────────────────
    if (triageDecision.claim_seat === "skip") {
      process.stderr.write(
        `note: triage decision is skip for PR #${prNumber}; not claiming seat\n`,
      );
      continue;
    }

    // ─── Resolve named prompt (AC #3) ────────────────────────────
    let systemPrompt: string;
    let promptName: string;
    const promptNameRaw = triageDecision.prompt;

    if (promptNameRaw === "default") {
      // Use built-in default prompt.
      systemPrompt = BUILTIN_DEFAULT_PROMPT;
      promptName = BUILTIN_PROMPT_NAME;
    } else {
      const resolveInput: ResolveNamedPromptInput = { name: promptNameRaw };
      const resolveFn = opts._resolveNamedPromptForTest ?? resolveNamedPrompt;
      const resolved = resolveFn(resolveInput);

      if (!resolved.ok) {
        const reason = resolved.reason;
        process.stderr.write(
          `✗ named prompt "${promptNameRaw}" not found or invalid (${reason}) for PR #${prNumber}; skipping\n`,
        );
        continue;
      }
      systemPrompt = resolved.body;
      promptName = promptNameRaw;
    }

    // ─── Claim seat ──────────────────────────────────────────────
    // AGT-454: include pubkey in the payload so server can verify without repo access.
    const claimResult = await callClaimSeat({
      patch_id: patchId,
      claimant_fp: keypair.fingerprint,
      base_sha: baseSha,
      repo,
      pubkey: keypair.publicKeyPem,
      signature: canonicalSign(keypair, {
        patch_id: patchId,
        claimant_fp: keypair.fingerprint,
        base_sha: baseSha,
        repo,
        pubkey: keypair.publicKeyPem,
      }),
      serverConfig: serverCfg,
      _sshSpawnForTest: opts._sshSpawnForTest,
    });

    if (!claimResult.ok) {
      if (claimResult.reason === "claim_rejected") {
        const { claimRejectionReason } = claimResult;
        if (claimRejectionReason === "seats_full") {
          process.stderr.write(
            `note: seats full for PR #${prNumber}; skipping\n`,
          );
        } else if (claimRejectionReason === "author_cannot_claim_own_pr") {
          process.stderr.write(
            `note: cannot claim own PR #${prNumber} (author_cannot_claim_own_pr); skipping\n`,
          );
        } else if (claimRejectionReason === "already_holds_other_seat") {
          process.stderr.write(
            `note: already holding another seat (already_holds_other_seat); skipping PR #${prNumber}\n`,
          );
        } else {
          process.stderr.write(
            `note: claim rejected for PR #${prNumber}: ${claimResult.message}; skipping\n`,
          );
        }
        continue;
      }
      // claim_failed or peer_reviews_not_configured — log and continue.
      process.stderr.write(
        `note: claim-seat failed for PR #${prNumber}: ${claimResult.message}; skipping\n`,
      );
      continue;
    }

    const seatNumber = claimResult.seat;
    currentSeatPatchId = patchId;
    process.stderr.write(`⟳ claimed seat ${seatNumber}; running review\n`);

    // ─── AGT-454: fetch the real diff via gh (per-repo auth boundary) ──
    // The notification payload is metadata-only; the unified diff is fetched
    // from GitHub here, AFTER claiming the seat. GitHub gates this — a listener
    // that lacks repo access cannot fetch the diff and releases the seat.
    let diff: string;
    {
      let ghDiffStatus: number;
      let ghDiffStdout = "";
      let ghDiffStderr = "";
      if (opts._ghDiffForTest) {
        const r = opts._ghDiffForTest(prUrl);
        ghDiffStatus = r.status;
        ghDiffStdout = r.stdout;
        ghDiffStderr = r.stderr;
      } else {
        const r = spawnSync("gh", ["pr", "diff", prUrl], {
          stdio: ["ignore", "pipe", "pipe"],
          encoding: "utf8",
          maxBuffer: 32 * 1024 * 1024,
        });
        ghDiffStatus = r.status ?? 1;
        ghDiffStdout = r.stdout ?? "";
        ghDiffStderr = r.stderr?.trim() ?? "";
      }

      if (ghDiffStatus !== 0 || ghDiffStdout.trim() === "") {
        const reason = ghDiffStderr || (ghDiffStdout.trim() === "" ? "empty diff" : `exit ${ghDiffStatus}`);
        process.stderr.write(
          `✗ could not fetch diff (gh): ${reason}; releasing seat\n`,
        );
        currentSeatPatchId = null;
        await callReleaseSeat({
          patch_id: patchId,
          claimant_fp: keypair.fingerprint,
          signature: canonicalSign(keypair, {
            patch_id: patchId,
            claimant_fp: keypair.fingerprint,
          }),
          serverConfig: serverCfg,
          _sshSpawnForTest: opts._sshSpawnForTest,
        });
        continue;
      }
      diff = ghDiffStdout;
    }

    // ─── AC #5: heartbeat timer ──────────────────────────────────
    const setIntervalFn = opts._setIntervalForTest ?? setInterval;
    currentHeartbeatHandle = setIntervalFn(() => {
      void callHeartbeat({
        patch_id: patchId,
        claimant_fp: keypair.fingerprint,
        signature: canonicalSign(keypair, {
          patch_id: patchId,
          claimant_fp: keypair.fingerprint,
        }),
        serverConfig: serverCfg,
        _sshSpawnForTest: opts._sshSpawnForTest,
      });
    }, 60_000);

    // ─── Run review with named prompt (AC #4) ───────────────────
    const reviewInput: RunBuiltinReviewInput = {
      diff,
      cwd: opts._cwdForTest ?? process.cwd(),
      systemPrompt,
      promptName,
      _sdkRunnerForTest: opts._sdkRunnerForTest,
    };

    let reviewBody: string;
    let reviewVerdict: "approve" | "request-changes" | "comment";
    try {
      process.stderr.write(`⟳ running review with prompt "${promptName}"\n`);
      const reviewResult = await runBuiltinReview(reviewInput);
      if (!reviewResult.ok) {
        process.stderr.write(
          `✗ review failed (prompt: ${promptName}): ${reviewResult.message}; releasing seat\n`,
        );
        // clearHeartbeat() is called in finally — no explicit call needed here.
        currentSeatPatchId = null;
        await callReleaseSeat({
          patch_id: patchId,
          claimant_fp: keypair.fingerprint,
          signature: canonicalSign(keypair, {
            patch_id: patchId,
            claimant_fp: keypair.fingerprint,
          }),
          serverConfig: serverCfg,
          _sshSpawnForTest: opts._sshSpawnForTest,
        });
        continue;
      }
      reviewBody = reviewResult.body;
      reviewVerdict = reviewResult.verdict;
      // AGT-432 AC #2: add review cost to daily spend accumulator.
      addDailySpend(reviewResult.costUsd);
    } finally {
      clearHeartbeat();
    }

    // ─── AGT-432 AC (draft saving): save draft if post_mode === "draft" ───
    if (triageDecision.post_mode === "draft") {
      // Security: validate patchId is a safe hex token before constructing
      // the file path. A crafted patchId containing `../` sequences would
      // otherwise escape the drafts directory.
      if (!/^[0-9a-f]{40}$/i.test(patchId)) {
        process.stderr.write(
          `✗ refusing to save draft for PR #${prNumber}: invalid patchId format ${JSON.stringify(patchId)}\n`,
        );
        currentSeatPatchId = null;
        await callReleaseSeat({
          patch_id: patchId,
          claimant_fp: keypair.fingerprint,
          signature: canonicalSign(keypair, {
            patch_id: patchId,
            claimant_fp: keypair.fingerprint,
          }),
          serverConfig: serverCfg,
          _sshSpawnForTest: opts._sshSpawnForTest,
        });
        continue;
      }
      const draftContent =
        `---\npatch_id: ${patchId}\npr_url: ${prUrl}\nts: ${nowFn().toISOString()}\n---\n\n${reviewBody}`;
      const draftPath = join(draftsDir(), `${patchId}.md`);
      try {
        if (opts._writeDraftForTest) {
          opts._writeDraftForTest(draftPath, draftContent);
        } else {
          mkdirSync(dirname(draftPath), { recursive: true });
          writeFileSync(draftPath, draftContent, "utf8");
        }
        process.stderr.write(`⟳ saved draft for PR #${prNumber} to ${draftPath}\n`);
      } catch (err) {
        process.stderr.write(
          `✗ draft save failed for PR #${prNumber}: ${err instanceof Error ? err.message : String(err)}\n`,
        );
      }
      currentSeatPatchId = null;
      // Release seat after draft save (no gh post).
      await callReleaseSeat({
        patch_id: patchId,
        claimant_fp: keypair.fingerprint,
        signature: canonicalSign(keypair, {
          patch_id: patchId,
          claimant_fp: keypair.fingerprint,
        }),
        serverConfig: serverCfg,
        _sshSpawnForTest: opts._sshSpawnForTest,
      });
      continue;
    }

    // ─── AGT-452: dry-run — log payload, no gh post, no draft file ───
    if (triageDecision.post_mode === "dry-run") {
      process.stderr.write(
        `⟳ dry-run for PR #${prNumber} (verdict=${reviewVerdict}); would have posted via gh, no review sent\n`,
      );
      process.stderr.write(`─── dry-run review body for PR #${prNumber} ───\n${reviewBody}\n─── end dry-run body ───\n`);
      currentSeatPatchId = null;
      await callReleaseSeat({
        patch_id: patchId,
        claimant_fp: keypair.fingerprint,
        signature: canonicalSign(keypair, {
          patch_id: patchId,
          claimant_fp: keypair.fingerprint,
        }),
        serverConfig: serverCfg,
        _sshSpawnForTest: opts._sshSpawnForTest,
      });
      continue;
    }

    // ─── AC #7: post review via gh ───────────────────────────────
    const ghVerdictFlag = ({
      "approve": "--approve",
      "request-changes": "--request-changes",
      "comment": "--comment",
    } as const)[reviewVerdict];

    let ghStatus: number;
    let ghStderr = "";

    if (opts._ghReviewForTest) {
      const fakeResult = opts._ghReviewForTest(prUrl, reviewBody, ghVerdictFlag);
      ghStatus = fakeResult.status;
      ghStderr = fakeResult.stderr;
    } else {
      const ghResult = spawnSync(
        "gh",
        ["pr", "review", prUrl, ghVerdictFlag, "-b", reviewBody],
        {
          stdio: ["ignore", "pipe", "pipe"],
          encoding: "utf8",
        },
      );
      ghStatus = ghResult.status ?? 1;
      ghStderr = ghResult.stderr?.trim() ?? "";
    }

    if (ghStatus !== 0) {
      const reason = ghStderr || `exit ${ghStatus}`;
      process.stderr.write(
        `✗ gh pr review failed (${reason}); seat released\n`,
      );
      currentSeatPatchId = null;
      await callReleaseSeat({
        patch_id: patchId,
        claimant_fp: keypair.fingerprint,
        signature: canonicalSign(keypair, {
          patch_id: patchId,
          claimant_fp: keypair.fingerprint,
        }),
        serverConfig: serverCfg,
        _sshSpawnForTest: opts._sshSpawnForTest,
      });
      continue;
    }

    // Success.
    currentSeatPatchId = null;
    process.stderr.write(`✓ posted review (verdict=${reviewVerdict}) for PR #${prNumber}\n`);
  }
}
