/**
 * AGT-451 — Integration tests for the `claim_seat: always` extras-post path
 * in `prListen.ts`.
 *
 * Uses the existing in-listener test seams (`_haikuRunnerForTest`,
 * `_sshSpawnForTest`, `_ghReviewForTest`, `_appendTripletForTest`,
 * `_writeDraftForTest`, `_ghDiffForTest`) to drive the full loop
 * in-process without network I/O.
 *
 * Coverage:
 *   AC #1 — `always` + seats_full → register-extra called, review runs, gh post fires.
 *   AC #2 — `always` + primary seat available → primary seat claimed, no register-extra.
 *   AC #4 — The extras log line "⟳ no primary seat available; posting as extra" is emitted.
 *   AC #6 — Cost-cap still wins over `always`; no register-extra call when cap is hit.
 *   AC #7 — `--dry-run` + `always` + seats_full → extras path, gh post skipped.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import {
  generateKeyPairSync,
  createHash,
  createPublicKey,
} from "node:crypto";
import { runPrListen, type PrListenOptions } from "../src/commands/prListen.ts";
import type { PeerReviewEvent } from "../src/lib/peerReviewEvent.ts";
import type { TripletRecord } from "../src/lib/peerWatchLog.ts";
import type { HttpFetchFn, SshSpawnFn } from "../src/lib/seatClient.ts";
import type { Keypair } from "../src/lib/keys.ts";
import { clearListenerRegistry } from "../src/server/peerReviews.ts";

// ─── Key generation helpers ──────────────────────────────────────────

function genSimKeypair(): Keypair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }) as string;
  const spkiDer = createPublicKey(publicKeyPem).export({
    type: "spki",
    format: "der",
  }) as Buffer;
  const fingerprint = "sha256:" + createHash("sha256").update(spkiDer).digest("hex");
  return { privateKeyPem, publicKeyPem, fingerprint };
}

// ─── Shared fixtures ─────────────────────────────────────────────────

const authorKp = genSimKeypair();
const reviewerKp = genSimKeypair();
const PATCH_ID = "a".repeat(40);
const PR_URL = "https://github.com/acme/widget/pull/42";
const REPO = "acme/widget";

function makePrOpenedEvent(): PeerReviewEvent {
  return {
    event_type: "pr-opened",
    patch_id: PATCH_ID,
    actor_fp: authorKp.fingerprint,
    payload: {
      patch_id: PATCH_ID,
      base_sha: "0".repeat(40),
      head_sha: "1".repeat(40),
      repo: REPO,
      pr_url: PR_URL,
      requested_by_fp: authorKp.fingerprint,
      title: "Add feature",
      body: "PR body",
      paths_changed: ["src/foo.ts"],
    },
  };
}

/** Suppress stderr and process.exit during a prListen run; return captured stderr. */
async function runAndCapture(opts: PrListenOptions): Promise<{ stderr: string; exitCode: number }> {
  const lines: string[] = [];
  const origWrite = process.stderr.write.bind(process.stderr);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (process.stderr as any).write = (chunk: unknown) => {
    if (typeof chunk === "string") lines.push(chunk);
    return true;
  };

  const origExit = process.exit.bind(process);
  let exitCode = 0;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (process as any).exit = (code?: number | string) => {
    exitCode = typeof code === "number" ? code : 0;
    throw new Error(`process.exit(${code})`);
  };

  try {
    await runPrListen(opts);
  } catch (err) {
    if (!(err instanceof Error) || !err.message.startsWith("process.exit")) {
      throw err;
    }
  } finally {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process.stderr as any).write = origWrite;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process as any).exit = origExit;
    clearListenerRegistry();
  }

  return { stderr: lines.join(""), exitCode };
}

// ─── Shared seam builders (AGT-453: HTTP fetch seam) ─────────────────

// Keep SshSpawnFn import in scope for type compat — it's re-exported as a
// back-compat alias from seatClient.ts (actual spawn logic is gone).
type _SshCompat = SshSpawnFn; void (undefined as unknown as _SshCompat);

/** HTTP fetch seam where claim-seat returns seats_full (409 conflict). */
function makeHttpFetchSeatsFull(): { fetch: HttpFetchFn; claimCalls: string[]; registerExtraCalls: string[] } {
  const claimCalls: string[] = [];
  const registerExtraCalls: string[] = [];

  const fetch: HttpFetchFn = async (url, _headers, _body) => {
    if (url.endsWith("/peer/claim-seat")) {
      claimCalls.push(url);
      return { status: 409, body: JSON.stringify({ ok: false, error: "seats_full" }) };
    }
    if (url.endsWith("/peer/register-extra")) {
      registerExtraCalls.push(url);
      return { status: 200, body: JSON.stringify({ ok: true, patch_id: PATCH_ID }) };
    }
    if (url.endsWith("/peer/release-seat")) {
      return { status: 200, body: JSON.stringify({ ok: true, released: true, patch_id: PATCH_ID }) };
    }
    return { status: 200, body: JSON.stringify({ ok: true }) };
  };

  return { fetch, claimCalls, registerExtraCalls };
}

/** HTTP fetch seam where claim-seat succeeds with seat 1. */
function makeHttpFetchSeatAvailable(): { fetch: HttpFetchFn; claimCalls: string[]; registerExtraCalls: string[] } {
  const claimCalls: string[] = [];
  const registerExtraCalls: string[] = [];

  const fetch: HttpFetchFn = async (url, _headers, _body) => {
    if (url.endsWith("/peer/claim-seat")) {
      claimCalls.push(url);
      return { status: 200, body: JSON.stringify({ ok: true, seat: 1, patch_id: PATCH_ID }) };
    }
    if (url.endsWith("/peer/register-extra")) {
      registerExtraCalls.push(url);
      return { status: 200, body: JSON.stringify({ ok: true, patch_id: PATCH_ID }) };
    }
    if (url.endsWith("/peer/release-seat")) {
      return { status: 200, body: JSON.stringify({ ok: true, released: true, patch_id: PATCH_ID }) };
    }
    return { status: 200, body: JSON.stringify({ ok: true }) };
  };

  return { fetch, claimCalls, registerExtraCalls };
}

/** @deprecated kept for backward compat with helpers that use this name. */
function makeSshSpawnSeatsFull() { return makeHttpFetchSeatsFull(); }
function makeSshSpawnSeatAvailable() { return makeHttpFetchSeatAvailable(); }

// ─── AC #1 + AC #4: always + seats_full → extras path, gh post fires ───

describe("AGT-451 AC #1/#4: claim_seat: always + seats_full → register-extra, review, gh post", () => {
  it("calls register-extra, emits the extras log line, posts the review", async () => {
    const { fetch, claimCalls, registerExtraCalls } = makeSshSpawnSeatsFull();
    const ghReviewCalls: Array<{ prUrl: string; body: string; verdictFlag: string }> = [];

    const opts: PrListenOptions = {
      orgs: ["acme"],
      server: "127.0.0.1:2222",
      _keypairForTest: reviewerKp,
      _eventQueueForTest: [makePrOpenedEvent()],
      _fetchForTest: fetch,
      _haikuRunnerForTest: async () =>
        JSON.stringify({
          claim_seat: "always",
          post_mode: "auto-post",
          prompt: "default",
          cost_cap_usd: 100,
        }),
      _peerWatchRulesForTest: { rules: "always review", hash: "h1" },
      _ghDiffForTest: () => ({ status: 0, stdout: "diff --git a/src/foo.ts\n+new line", stderr: "" }),
      _ghReviewForTest: (prUrl, body, verdictFlag) => {
        ghReviewCalls.push({ prUrl, body, verdictFlag });
        return { status: 0, stderr: "" };
      },
      _appendTripletForTest: () => { /* no-op */ },
      _resolveNamedPromptForTest: () => ({ ok: true, body: "default prompt" }),
      _sdkRunnerForTest: async (_diff) =>
        JSON.stringify({ verdict: "comment", body: "LGTM from extra" }),
      _peerReposMapForTest: new Map([[REPO, "/tmp/fake-repo"]]),
      _operatorVerifyForTest: () => ({ ok: true as const }),
    };

    const { stderr } = await runAndCapture(opts);

    // AC #1: register-extra was called (not skipped at seats_full).
    assert.equal(claimCalls.length, 1, "should have attempted claim-seat once");
    assert.equal(
      registerExtraCalls.length,
      1,
      `should have called register-extra once; got: ${registerExtraCalls.length}`,
    );

    // AC #4: extras log line emitted.
    assert.ok(
      stderr.includes("⟳ no primary seat available; posting as extra"),
      `expected extras log line; stderr:\n${stderr}`,
    );

    // gh review was posted.
    assert.equal(ghReviewCalls.length, 1, "should have posted review via gh");
    assert.equal(ghReviewCalls[0]!.prUrl, PR_URL);
  });
});

// ─── AC #2: always + seat available → primary seat, no register-extra ───

describe("AGT-451 AC #2: claim_seat: always + seat available → primary seat, no register-extra", () => {
  it("takes the primary seat path; does NOT call register-extra", async () => {
    const { fetch, claimCalls, registerExtraCalls } = makeSshSpawnSeatAvailable();
    const ghReviewCalls: string[] = [];

    const opts: PrListenOptions = {
      orgs: ["acme"],
      server: "127.0.0.1:2222",
      _keypairForTest: reviewerKp,
      _eventQueueForTest: [makePrOpenedEvent()],
      _fetchForTest: fetch,
      _haikuRunnerForTest: async () =>
        JSON.stringify({
          claim_seat: "always",
          post_mode: "auto-post",
          prompt: "default",
          cost_cap_usd: 100,
        }),
      _peerWatchRulesForTest: { rules: "always review", hash: "h2" },
      _ghDiffForTest: () => ({ status: 0, stdout: "diff --git a/src/foo.ts\n+new line", stderr: "" }),
      _ghReviewForTest: (prUrl, _body, _flag) => {
        ghReviewCalls.push(prUrl);
        return { status: 0, stderr: "" };
      },
      _appendTripletForTest: () => { /* no-op */ },
      _resolveNamedPromptForTest: () => ({ ok: true, body: "default prompt" }),
      _sdkRunnerForTest: async (_diff) =>
        JSON.stringify({ verdict: "comment", body: "LGTM" }),
      _peerReposMapForTest: new Map([[REPO, "/tmp/fake-repo"]]),
      _operatorVerifyForTest: () => ({ ok: true as const }),
      _setIntervalForTest: (_fn, _ms) => 0 as unknown as ReturnType<typeof setInterval>,
    };

    const { stderr } = await runAndCapture(opts);

    // Claim-seat succeeded → primary seat path.
    assert.equal(claimCalls.length, 1, "should have attempted claim-seat once");
    assert.equal(
      registerExtraCalls.length,
      0,
      `should NOT have called register-extra; got: ${registerExtraCalls.length}`,
    );

    // The "claimed seat N" log line should appear (not the extras line).
    assert.ok(
      stderr.includes("⟳ claimed seat 1; running review"),
      `expected primary seat log; stderr:\n${stderr}`,
    );
    assert.ok(
      !stderr.includes("posting as extra"),
      `extras log line should NOT appear; stderr:\n${stderr}`,
    );

    // gh review was still posted.
    assert.equal(ghReviewCalls.length, 1, "should have posted review via gh");
  });
});

// ─── AC #6: cost-cap wins over always; no register-extra when cap hit ───

describe("AGT-451 AC #6: cost-cap hit → skip (no register-extra)", () => {
  it("skips without calling register-extra when daily cap is pre-seeded at threshold", async () => {
    const { fetch, claimCalls, registerExtraCalls } = makeSshSpawnSeatsFull();
    const triplets: TripletRecord[] = [];

    const opts: PrListenOptions = {
      orgs: ["acme"],
      server: "127.0.0.1:2222",
      _keypairForTest: reviewerKp,
      _eventQueueForTest: [makePrOpenedEvent()],
      _fetchForTest: fetch,
      _haikuRunnerForTest: async () =>
        JSON.stringify({
          claim_seat: "always",
          post_mode: "auto-post",
          prompt: "default",
          cost_cap_usd: 0.01,
        }),
      _peerWatchRulesForTest: { rules: "always review", hash: "h3" },
      // Pre-seed daily spend at the cap — the event should be downgraded to skip.
      _initialDailySpendForTest: 0.01,
      _appendTripletForTest: (record) => triplets.push(record),
      _resolveNamedPromptForTest: () => ({ ok: true, body: "default prompt" }),
      _sdkRunnerForTest: async (_diff) =>
        JSON.stringify({ verdict: "comment", body: "LGTM" }),
      _peerReposMapForTest: new Map([[REPO, "/tmp/fake-repo"]]),
      _operatorVerifyForTest: () => ({ ok: true as const }),
    };

    await runAndCapture(opts);

    // Cap should have been hit → skip, no claim, no register-extra.
    assert.equal(claimCalls.length, 0, "claim-seat should NOT be called when cap is hit");
    assert.equal(
      registerExtraCalls.length,
      0,
      "register-extra should NOT be called when cap is hit",
    );

    // Triplet should show daily cap hit.
    assert.equal(triplets.length, 1, "should have logged one triplet");
    assert.equal(triplets[0]!.reason, "daily cap hit", "triplet reason should be 'daily cap hit'");
  });
});

// ─── AC #7: dry-run + always + seats_full → extras path, no gh post ─────

describe("AGT-451 AC #7: dry-run + always + seats_full → extras path, gh post skipped", () => {
  it("registers as extra, runs review, logs dry-run body, does NOT call gh pr review", async () => {
    const { fetch, registerExtraCalls } = makeSshSpawnSeatsFull();
    const ghReviewCalls: string[] = [];

    const opts: PrListenOptions = {
      orgs: ["acme"],
      server: "127.0.0.1:2222",
      _keypairForTest: reviewerKp,
      _eventQueueForTest: [makePrOpenedEvent()],
      _fetchForTest: fetch,
      _haikuRunnerForTest: async () =>
        JSON.stringify({
          claim_seat: "always",
          post_mode: "dry-run",
          prompt: "default",
          cost_cap_usd: 100,
        }),
      _peerWatchRulesForTest: { rules: "always review", hash: "h4" },
      _ghDiffForTest: () => ({ status: 0, stdout: "diff --git a/src/foo.ts\n+new line", stderr: "" }),
      _ghReviewForTest: (prUrl, _body, _flag) => {
        ghReviewCalls.push(prUrl);
        return { status: 0, stderr: "" };
      },
      _appendTripletForTest: () => { /* no-op */ },
      _resolveNamedPromptForTest: () => ({ ok: true, body: "default prompt" }),
      _sdkRunnerForTest: async (_diff) =>
        JSON.stringify({ verdict: "comment", body: "LGTM from extra dry run" }),
      _peerReposMapForTest: new Map([[REPO, "/tmp/fake-repo"]]),
      _operatorVerifyForTest: () => ({ ok: true as const }),
    };

    const { stderr } = await runAndCapture(opts);

    // register-extra was called (not skipped at seats_full).
    assert.equal(
      registerExtraCalls.length,
      1,
      `should have called register-extra once; got: ${registerExtraCalls.length}`,
    );

    // Dry-run log line should appear.
    assert.ok(
      stderr.includes("dry-run"),
      `expected dry-run log line; stderr:\n${stderr}`,
    );

    // gh pr review should NOT have been called.
    assert.equal(
      ghReviewCalls.length,
      0,
      `gh pr review should NOT be called in dry-run mode; got: ${ghReviewCalls.length}`,
    );
  });
});
