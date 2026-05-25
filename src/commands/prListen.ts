/**
 * `stamp pr listen --org <org>...` — foreground peer-review listener (AGT-429/AGT-430).
 *
 * Subscribes the operator's fingerprint + org list against the in-process
 * listener registry (`registerListener` in peerReviews.ts) and enters an
 * event loop that:
 *
 *   1. Waits for the next `pr-opened` event via a Promise resolved by the
 *      registered `onEvent` callback.
 *   2. Skips events where `requested_by_fp` matches the operator's own
 *      fingerprint (author-exclusion).
 *   3. Runs the Haiku triage call against `~/.stamp/peer-watch.md` (AGT-430).
 *      If `peer-watch.md` is missing, falls back to a default claim decision.
 *      If triage returns `claim_seat: "skip"`, skips the event.
 *   4. Resolves the named prompt from `~/.stamp/personal/peers/<name>.md`.
 *      Missing prompt → logs `✗` and skips (AC #3).
 *   5. Logs the triage triplet to `~/.stamp/peer-watch.log` (AC #6).
 *   6. Claims a reviewer seat via `claim-seat` (seatClient.ts).
 *   7. Starts a 60-second heartbeat interval while the review runs.
 *   8. Runs the peer review via `runBuiltinReview` using the resolved named
 *      prompt as the system prompt (AC #4).
 *   9. Posts the result via `gh pr review <pr_url> --comment -b "<body>"`.
 *  10. Releases the seat on `gh` failure; loops back to step 1.
 *  11. On SIGINT: emits "note: shutting down", releases any held seat, exits 0.
 *
 * Exit codes:
 *   0   — clean shutdown (SIGINT / ctrl-C)
 *   1   — auth failure (keypair missing, subscribe failed)
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
import { WebSocket } from "ws";
import {
  registerListener,
  unregisterListener,
} from "../server/peerReviews.js";
import type { PeerReviewEvent } from "../lib/peerReviewEvent.js";
import {
  callSubscribe,
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

// ─── Options ──────────────────────────────────────────────────────────

export interface PrListenOptions {
  orgs: string[];
  /** `--server <host:port>` override. */
  server?: string;
  /** Test-only: inject a fake SSH spawn function to avoid real network calls. */
  _sshSpawnForTest?: SshSpawnFn;
  /** Test-only: inject a fake `gh pr review` spawn result. */
  _ghReviewForTest?: (prUrl: string, body: string) => { status: number; stderr: string };
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
   * blocking on a Promise resolved by `fanoutEvent`. After the queue is
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
   * Select the WebSocket transport (AGT-434) instead of the SSH-verb long-poll
   * fallback. When true, `stamp pr listen` connects via WS to the stamp-server's
   * `/peer/listen` endpoint for event delivery instead of the SSH-verb
   * `subscribe` long-poll. The SSH-verb path is retained as a flag-selected
   * fallback through AGT-433 validation.
   */
  useWsTransport?: boolean;
  /**
   * Test-only: inject a pre-constructed WebSocket for the WS transport path.
   * When set, the WS connect step is skipped and this socket is used directly.
   */
  _wsSocketForTest?: WebSocket;
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
 * Build the WebSocket URL for the `/peer/listen` endpoint from a `ServerConfig`.
 *
 * Returns `{ ok: true, url }` when `wsUrl` is set (strips a trailing `/` from
 * the origin before appending `/peer/listen`).
 * Returns `{ ok: false, reason }` with an actionable error message when
 * `wsUrl` is absent — the SSH host:port cannot be used for WS connections.
 *
 * Exported for unit testing.
 */
export function buildWsPeerListenUrl(
  serverCfg: ServerConfig,
): { ok: true; url: string } | { ok: false; reason: string } {
  if (!serverCfg.wsUrl) {
    return {
      ok: false,
      reason:
        "WS transport requires 'ws_url' in ~/.stamp/server.yml " +
        "(e.g. ws_url: wss://stamp-cli-production.up.railway.app). " +
        "The SSH host:port cannot be used for WebSocket connections — " +
        "the HTTP server lives at a different URL.",
    };
  }
  return {
    ok: true,
    url: `${serverCfg.wsUrl.replace(/\/$/, "")}/peer/listen`,
  };
}

/**
 * Connect to the stamp-server's WS `/peer/listen` endpoint, complete the
 * signed-challenge handshake, and return a Promise that resolves to a
 * readable event source: an async generator that yields `PeerReviewEvent`
 * objects as the server pushes them.
 *
 * Handshake:
 *   1. Server sends `{type:"challenge",nonce}`.
 *   2. Client signs the nonce with Ed25519 and responds with
 *      `{type:"auth", fingerprint, nonce, signature, orgs}`.
 *   3. Server responds `{type:"authenticated",fingerprint}` on success, or
 *      closes with a 44xx code on failure.
 *
 * Returns `{ ok: false, reason }` when auth fails; `{ ok: true, ws, eventGen }`
 * when connected.
 */
async function connectWsTransport(
  keypair: Keypair,
  orgs: string[],
  serverCfg: ServerConfig,
  wsSocketOverride?: WebSocket,
): Promise<
  | { ok: true; ws: WebSocket; nextEvent: () => Promise<PeerReviewEvent | null> }
  | { ok: false; reason: string }
> {
  // In-test: use the injected WS socket (skip URL resolution entirely.
  // For real connections, resolve the URL via buildWsPeerListenUrl; it fails
  // fast with an actionable error when wsUrl is missing (the SSH host:port
  // cannot be used for WS — it speaks sshd, not HTTP).
  let ws: WebSocket;
  if (wsSocketOverride) {
    ws = wsSocketOverride;
  } else {
    const urlResult = buildWsPeerListenUrl(serverCfg);
    if (!urlResult.ok) {
      return { ok: false, reason: urlResult.reason };
    }
    ws = new WebSocket(urlResult.url);
  }

  return new Promise((resolve) => {
    let authenticated = false;
    let pendingResolve: ((event: PeerReviewEvent | null) => void) | null = null;

    ws.on("error", (err) => {
      if (!authenticated) {
        resolve({ ok: false, reason: `WS connection error: ${err.message}` });
      }
    });

    ws.on("close", (code, reason) => {
      if (!authenticated) {
        resolve({ ok: false, reason: `WS closed before auth: code=${code} ${reason.toString("utf8")}` });
        return;
      }
      // Signal end-of-stream to any pending nextEvent() caller.
      if (pendingResolve) {
        const r = pendingResolve;
        pendingResolve = null;
        r(null);
      }
    });

    ws.on("message", (data: Buffer | string) => {
      const raw = typeof data === "string" ? data : data.toString("utf8");
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(raw) as Record<string, unknown>;
      } catch {
        return;
      }

      if (!authenticated) {
        // Phase 1: handle challenge → send auth.
        if (msg["type"] === "challenge") {
          const nonce = typeof msg["nonce"] === "string" ? msg["nonce"] : null;
          if (!nonce) {
            resolve({ ok: false, reason: "WS challenge missing nonce" });
            ws.close();
            return;
          }
          // Sign the nonce bytes directly (not the JSON) to bind our identity.
          const sig = signBytes(keypair.privateKeyPem, Buffer.from(nonce, "utf8"));
          ws.send(JSON.stringify({
            type: "auth",
            fingerprint: keypair.fingerprint,
            nonce,
            signature: sig,
            orgs,
          }));
          return;
        }
        if (msg["type"] === "authenticated") {
          authenticated = true;
          resolve({
            ok: true,
            ws,
            nextEvent: () =>
              new Promise<PeerReviewEvent | null>((r) => {
                pendingResolve = r;
              }),
          });
          return;
        }
        // Any other message before auth is a protocol error.
        resolve({ ok: false, reason: `unexpected WS message before auth: ${JSON.stringify(msg["type"])}` });
        ws.close();
        return;
      }

      // Phase 2: authenticated — deliver event messages.
      if (msg["type"] === "event" && pendingResolve) {
        const event: PeerReviewEvent = {
          event_type: typeof msg["event_type"] === "string" ? msg["event_type"] : "unknown",
          patch_id: typeof msg["patch_id"] === "string" ? msg["patch_id"] : "",
          actor_fp: typeof msg["actor_fp"] === "string" ? msg["actor_fp"] : "",
          payload: typeof msg["payload"] === "object" && msg["payload"] !== null
            ? msg["payload"] as object
            : {},
        };
        const r = pendingResolve;
        pendingResolve = null;
        r(event);
      }
    });
  });
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

  // ─── Transport selection: WS vs SSH long-poll ────────────────────
  // useWsTransport=true (--ws flag) → connect via WebSocket (AGT-434).
  // useWsTransport=false (default) → SSH-verb long-poll fallback.

  // wsCleanup: called on shutdown to close the WS socket gracefully.
  let wsCleanup: (() => void) | null = null;
  // wsNextEvent: when using WS transport, this is the per-event resolver.
  let wsNextEvent: (() => Promise<PeerReviewEvent | null>) | null = null;

  if (opts.useWsTransport) {
    // ─── WS transport ─────────────────────────────────────────────
    const wsResult = await connectWsTransport(
      keypair,
      orgs,
      serverCfg,
      opts._wsSocketForTest,
    );
    if (!wsResult.ok) {
      process.stderr.write(
        `error: WS connect failed — ${wsResult.reason}\n`,
      );
      process.exit(1);
    }
    wsNextEvent = wsResult.nextEvent;
    wsCleanup = () => wsResult.ws.close();
    process.stderr.write(`⟳ subscribed (WS); listening for PR events\n`);
  } else {
    // ─── SSH long-poll (fallback) ──────────────────────────────────
    // The subscription call goes to the server's `subscribe` verb. For the
    // in-process spike (AGT-429) this registers in the module-scoped registry
    // AND goes over SSH so the server knows the fingerprint. In tests, the
    // SSH call is injected.
    const subscribeResult = await callSubscribe({
      orgs,
      fingerprint: keypair.fingerprint,
      signature: canonicalSign(keypair, {
        fingerprint: keypair.fingerprint,
        orgs,
      }),
      serverConfig: serverCfg,
      _sshSpawnForTest: opts._sshSpawnForTest,
    });

    if (!subscribeResult.ok && subscribeResult.reason !== "peer_reviews_not_configured") {
      process.stderr.write(
        `error: subscribe failed — ${subscribeResult.message}\n`,
      );
      process.exit(1);
    }

    if (!subscribeResult.ok && subscribeResult.reason === "peer_reviews_not_configured") {
      process.stderr.write(
        `note: stamp-server has peer reviews disabled; operating in local-only mode\n`,
      );
    }

    process.stderr.write(`⟳ subscribed; listening for PR events\n`);

    // wsNextEvent stays null — the loop uses the in-process fan-out path.
    // wsCleanup stays null — unregisterListener handles teardown.
    // Note: the in-process listener is registered below (after sshPendingResolve
    // is in scope) so the onEvent callback can resolve the per-event Promise.
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
    clearHeartbeat();
    // Clean up based on which transport is active.
    if (opts.useWsTransport) {
      if (wsCleanup) wsCleanup();
    } else {
      unregisterListener(keypair!.fingerprint);
    }

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
  // Three event sources in priority order:
  //   1. _eventQueueForTest (test seam): drains a pre-queued array.
  //   2. wsNextEvent (WS transport): awaits the next pushed frame.
  //   3. In-process in-process fanout (SSH long-poll fallback): awaits the
  //      next `registerListener` callback.
  //
  // When `_eventQueueForTest` is provided (test seam), drain that array
  // deterministically instead of blocking on the in-process fanout Promise.
  // This avoids timer/goroutine races in `node --test` environments.
  const useQueueMode = Array.isArray(opts._eventQueueForTest);

  // In-process event wait for the SSH-path fallback.
  let sshPendingResolve: ((event: PeerReviewEvent) => void) | null = null;
  function waitForNextSshEvent(): Promise<PeerReviewEvent> {
    return new Promise<PeerReviewEvent>((resolve) => {
      sshPendingResolve = resolve;
    });
  }
  // Wire the SSH-path listener's onEvent to the promise resolver.
  // Only relevant when SSH transport is active (not WS, not queue-mode test).
  if (!opts.useWsTransport && !useQueueMode) {
    registerListener(keypair.fingerprint, {
      orgs,
      onEvent: (event: PeerReviewEvent) => {
        if (sshPendingResolve) {
          const r = sshPendingResolve;
          sshPendingResolve = null;
          r(event);
        }
      },
    });
  }

  async function nextEvent(): Promise<PeerReviewEvent | null> {
    if (useQueueMode) {
      // Drain the pre-queued array; return null to signal "done".
      const q = opts._eventQueueForTest!;
      if (q.length === 0) return null;
      return q.shift()!;
    }
    if (opts.useWsTransport && wsNextEvent) {
      return wsNextEvent();
    }
    return waitForNextSshEvent();
  }

  // AGT-454: load peer-repos map once before the loop (fail-closed per-event).
  // Prefer the injected test seam over the real config file.
  const peerReposMap =
    opts._peerReposMapForTest !== undefined
      ? opts._peerReposMapForTest
      : loadPeerReposConfig();

  for (;;) {
    const event = await nextEvent();
    // In queue mode, null means the queue is empty — exit the loop cleanly.
    if (event === null) {
      clearHeartbeat();
      unregisterListener(keypair.fingerprint);
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
    const diff =
      typeof payload["diff"] === "string"
        ? payload["diff"]
        : typeof payload["body"] === "string"
          ? payload["body"]
          : `PR diff for patch_id=${patchId}`;
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
    const prBody =
      typeof payload["body"] === "string"
        ? payload["body"]
        : typeof payload["diff"] === "string"
          ? payload["diff"]
          : "";
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

    // ─── AC #7: post review via gh ───────────────────────────────
    let ghStatus: number;
    let ghStderr = "";

    if (opts._ghReviewForTest) {
      const fakeResult = opts._ghReviewForTest(prUrl, reviewBody);
      ghStatus = fakeResult.status;
      ghStderr = fakeResult.stderr;
    } else {
      const ghResult = spawnSync(
        "gh",
        ["pr", "review", prUrl, "--comment", "-b", reviewBody],
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
    process.stderr.write(`✓ posted review for PR #${prNumber}\n`);
  }
}
