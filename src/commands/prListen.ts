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
import { dirname } from "node:path";
import { loadUserKeypair, type Keypair } from "../lib/keys.js";
import { signBytes } from "../lib/signing.js";
import { loadServerConfig } from "../lib/serverConfig.js";
import type { ServerConfig } from "../lib/serverConfig.js";
import {
  registerListener,
  unregisterListener,
  type PeerReviewEvent,
} from "../server/peerReviews.js";
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
}

// ─── Helpers ──────────────────────────────────────────────────────────

/** Build a minimal base64-encoded stub signature for the wire-frame.
 *  The server relies on SSH identity binding, not payload-signature
 *  verification, for this ticket's scope. */
function stubSignature(keypair: Keypair, ...parts: string[]): string {
  const data = Buffer.from(parts.join("|"), "utf8");
  return signBytes(keypair.privateKeyPem, data);
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

  // ─── Subscribe: register in-process listener ──────────────────────
  // The subscription call goes to the server's `subscribe` verb. For the
  // in-process spike (AGT-429) this registers in the module-scoped registry
  // AND goes over SSH so the server knows the fingerprint. In tests, the
  // SSH call is injected.
  const subscribeResult = await callSubscribe({
    orgs,
    fingerprint: keypair.fingerprint,
    signature: stubSignature(keypair, keypair.fingerprint, ...orgs),
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

  // Register the local in-process listener. This is the seam that lets
  // tests drive the loop via `fanoutEvent`.
  let pendingResolve: ((event: PeerReviewEvent) => void) | null = null;

  function waitForNextEvent(): Promise<PeerReviewEvent> {
    return new Promise<PeerReviewEvent>((resolve) => {
      pendingResolve = resolve;
    });
  }

  registerListener(keypair.fingerprint, {
    orgs,
    onEvent: (event: PeerReviewEvent) => {
      if (pendingResolve) {
        const r = pendingResolve;
        pendingResolve = null;
        r(event);
      }
    },
  });

  process.stderr.write(`⟳ subscribed; listening for PR events\n`);

  // ─── Daily spend accumulator (AGT-432 AC #2) ──────────────────────
  // In-memory accumulator scoped to this listener process lifetime.
  // Resets at local-TZ midnight. Not persisted across restarts.
  const nowFn = opts._nowForTest ?? (() => new Date());
  let dailySpend = 0;
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
    unregisterListener(keypair!.fingerprint);

    if (currentSeatPatchId !== null) {
      await callReleaseSeat({
        patch_id: currentSeatPatchId,
        claimant_fp: keypair!.fingerprint,
        signature: stubSignature(keypair!, currentSeatPatchId, keypair!.fingerprint),
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
  // When `_eventQueueForTest` is provided (test seam), drain that array
  // deterministically instead of blocking on the in-process fanout Promise.
  // This avoids timer/goroutine races in `node --test` environments.
  const useQueueMode = Array.isArray(opts._eventQueueForTest);

  async function nextEvent(): Promise<PeerReviewEvent | null> {
    if (useQueueMode) {
      // Drain the pre-queued array; return null to signal "done".
      const q = opts._eventQueueForTest!;
      if (q.length === 0) return null;
      return q.shift()!;
    }
    return waitForNextEvent();
  }

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

    if (
      typeof triageDecision.cost_cap_usd === "number" &&
      triageDecision.cost_cap_usd > 0 &&
      dailySpend >= triageDecision.cost_cap_usd &&
      (triageDecision.claim_seat === "if_available" || triageDecision.claim_seat === "always")
    ) {
      // Downgrade to skip: daily cap hit.
      triageDecision = { ...triageDecision, claim_seat: "skip" };
      const capUsd = triageDecision.cost_cap_usd;
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
      const isCapSkip =
        triageDecision.claim_seat === "skip" &&
        typeof triageDecision.cost_cap_usd === "number" &&
        triageDecision.cost_cap_usd > 0 &&
        dailySpend >= triageDecision.cost_cap_usd;

      const tripletRecord: TripletRecord = {
        ts: nowFn().toISOString(),
        repo,
        pr_url: prUrl,
        rules_hash: rulesHash,
        event_payload: payload as Record<string, unknown>,
        decision: triageDecision,
        ...(event.event_type === "re-review-requested" ? { kind: "re-review" } : {}),
        ...(isCapSkip ? { reason: "daily cap hit" } : {}),
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
    const claimResult = await callClaimSeat({
      patch_id: patchId,
      claimant_fp: keypair.fingerprint,
      base_sha: baseSha,
      repo,
      signature: stubSignature(keypair, patchId, keypair.fingerprint, baseSha, repo),
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
        signature: stubSignature(keypair, patchId, keypair.fingerprint),
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
          signature: stubSignature(keypair, patchId, keypair.fingerprint),
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
      const draftContent =
        `---\npatch_id: ${patchId}\npr_url: ${prUrl}\nts: ${nowFn().toISOString()}\n---\n\n${reviewBody}`;
      const draftPath = `${draftsDir()}/${patchId}.md`;
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
        signature: stubSignature(keypair, patchId, keypair.fingerprint),
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
        signature: stubSignature(keypair, patchId, keypair.fingerprint),
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
