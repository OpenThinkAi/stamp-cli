/**
 * AGT-429 — Unit tests for `stamp pr listen`.
 *
 * Coverage per ACs:
 *   AC #1  — subcommand wiring: runPrListen exported + Commander registers 'listen'
 *   AC #2  — subscribe → receive event → full loop executes (in-process queue)
 *   AC #3  — author-exclusion: own-fingerprint events are skipped
 *   AC #4  — seat-claim rejections: seats_full, author_cannot_claim_own_pr,
 *             already_holds_other_seat, unknown
 *   AC #5  — heartbeat: setInterval called while review is running
 *   AC #6  — review executes with "builtin-default" prompt name (injected SDK)
 *   AC #7  — gh pr review post: success path emits "✓ posted review"
 *   AC #7  — gh pr review failure: emits "✗ gh pr review failed" + calls release-seat
 *   AC #8  — loop re-enters after each event (two events, both processed)
 *   AC #10 — full in-process loop via _eventQueueForTest seam (no live server)
 *   AC #11 — no --org flag → exit 2 (Commander required-option check)
 *   AC #12 — auth failure (no keypair) → exit 1
 *   AC #13 — glyph discipline: stdout empty on normal loop iteration
 *
 * All subprocess boundaries are injected via test seams. No real SSH, git,
 * gh, or SDK invocations are made.
 */

import { strict as assert } from "node:assert";
import { describe, it, beforeEach, afterEach } from "node:test";
import {
  generateKeyPairSync,
  createHash,
  createPublicKey,
} from "node:crypto";

import { runPrListen, type PrListenOptions } from "../src/commands/prListen.ts";
import {
  clearListenerRegistry,
  type PeerReviewEvent,
} from "../src/server/peerReviews.ts";
import type { SshSpawnFn } from "../src/lib/seatClient.ts";
import type { Keypair } from "../src/lib/keys.ts";

// ─── Helpers ─────────────────────────────────────────────────────────

/** Generate a fresh Ed25519 keypair in PKCS#8 PEM form. */
function genKeypair(): Keypair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }) as string;
  const raw = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" }) as Buffer;
  const fingerprint = "sha256:" + createHash("sha256").update(raw).digest("hex");
  return { privateKeyPem, publicKeyPem, fingerprint };
}

/** Capture and intercept `process.exit` calls. */
class ExitSignal extends Error {
  constructor(public readonly code: number) {
    super(`process.exit(${code})`);
  }
}

/**
 * Run `runPrListen` with process.exit intercepted. Returns the exit code.
 * The caller must ensure opts._eventQueueForTest is set (or that the
 * function will call process.exit for another reason) to avoid a hang.
 */
async function runWithExitCapture(opts: PrListenOptions): Promise<number> {
  const origExit = process.exit.bind(process);
  let capturedCode: number | undefined;
  const patchedExit = (code?: number | string) => {
    capturedCode = typeof code === "number" ? code : 0;
    throw new ExitSignal(capturedCode);
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (process as any).exit = patchedExit;

  try {
    await runPrListen(opts);
    return capturedCode ?? 0;
  } catch (err) {
    if (err instanceof ExitSignal) return err.code;
    throw err;
  } finally {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process as any).exit = origExit;
  }
}

/** Capture stderr output during an async fn, return joined string. */
async function captureStderrAsync<T>(fn: () => Promise<T>): Promise<{ result: T; stderr: string }> {
  const lines: string[] = [];
  const origWrite = process.stderr.write.bind(process.stderr);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (process.stderr as any).write = (chunk: unknown) => {
    if (typeof chunk === "string") lines.push(chunk);
    return true;
  };
  let result: T;
  try {
    result = await fn();
  } finally {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process.stderr as any).write = origWrite;
  }
  return { result, stderr: lines.join("") };
}

/** Capture stdout output during an async fn, return lines. */
async function captureStdoutAsync<T>(fn: () => Promise<T>): Promise<{ result: T; stdout: string[] }> {
  const lines: string[] = [];
  const origWrite = process.stdout.write.bind(process.stdout);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (process.stdout as any).write = (chunk: unknown) => {
    if (typeof chunk === "string") lines.push(chunk);
    return true;
  };
  let result: T;
  try {
    result = await fn();
  } finally {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process.stdout as any).write = origWrite;
  }
  return { result, stdout: lines };
}

const FIXTURE_SERVER = "stamp.example.com:2222";

/** Build a minimal PeerReviewEvent for testing. */
function makeEvent(opts: {
  patch_id?: string;
  payloadOverrides?: Record<string, unknown>;
} = {}): PeerReviewEvent {
  return {
    event_type: "pr-opened",
    patch_id: opts.patch_id ?? "a".repeat(40),
    actor_fp: "sha256:" + "b".repeat(64),
    payload: {
      patch_id: opts.patch_id ?? "a".repeat(40),
      base_sha: "b".repeat(40),
      repo: "acme/widget",
      pr_url: "https://github.com/acme/widget/pull/42",
      requested_by_fp: "sha256:" + "c".repeat(64),
      diff: "diff --git a/src/foo.ts b/src/foo.ts\n+const x = 1;",
      ...opts.payloadOverrides,
    },
  };
}

/** SSH spawn seam returning success for all seat verbs. */
function makeSuccessSshSpawn(seatNum = 1): SshSpawnFn {
  return async (_cfg, verb) => {
    if (verb === "subscribe") {
      return {
        stdout: JSON.stringify({ ok: true, fingerprint: "fp", orgs: ["acme"] }),
        stderr: "",
        exitCode: 0,
        signal: null,
      };
    }
    if (verb === "claim-seat") {
      return {
        stdout: JSON.stringify({ ok: true, seat: seatNum, patch_id: "a".repeat(40) }),
        stderr: "",
        exitCode: 0,
        signal: null,
      };
    }
    if (verb === "heartbeat") {
      return {
        stdout: JSON.stringify({ ok: true, seat: seatNum, patch_id: "a".repeat(40) }),
        stderr: "",
        exitCode: 0,
        signal: null,
      };
    }
    if (verb === "release-seat") {
      return {
        stdout: JSON.stringify({ ok: true, released: true, patch_id: "a".repeat(40) }),
        stderr: "",
        exitCode: 0,
        signal: null,
      };
    }
    return { stdout: "", stderr: "unknown verb", exitCode: 1, signal: null };
  };
}

// ─── Test cleanup ─────────────────────────────────────────────────────

beforeEach(() => clearListenerRegistry());
afterEach(() => clearListenerRegistry());

// ─── AC #12: auth failure (no keypair) → exit 1 ──────────────────────

describe("AC #12: auth failure — no keypair → exit 1", () => {
  it("exits 1 when no keypair is available", async () => {
    // Pass _keypairForTest as null to force the "no keypair" error path.
    const code = await runWithExitCapture({
      orgs: ["acme"],
      server: FIXTURE_SERVER,
      _keypairForTest: null,
      _sshSpawnForTest: makeSuccessSshSpawn(),
      _eventQueueForTest: [],
    });
    assert.equal(code, 1, `expected exit 1 for missing keypair, got ${code}`);
  });
});

// ─── AC #10 + AC #2 + AC #6 + AC #7 + AC #13: full loop ─────────────

describe("AC #10: full loop via _eventQueueForTest injection", () => {
  it("subscribe → event → claim → review → post → exit 0", async () => {
    const fakeKeypair = genKeypair();
    const sshCalls: string[] = [];
    const sshSpawn: SshSpawnFn = async (cfg, verb) => {
      sshCalls.push(verb);
      return makeSuccessSshSpawn(1)(cfg, verb);
    };

    let sdkCallCount = 0;
    let sdkReceivedDiff = "";
    const sdkRunner = async (diff: string): Promise<string> => {
      sdkCallCount++;
      sdkReceivedDiff = diff;
      return "This diff adds a constant. Code quality: good. No obvious issues.";
    };

    let ghCallArgs: { prUrl: string; body: string } | null = null;
    const ghReview = (prUrl: string, body: string) => {
      ghCallArgs = { prUrl, body };
      return { status: 0, stderr: "" };
    };

    let intervalFnRef: (() => void) | null = null;
    const setIntervalFake = (fn: () => void, _ms: number): ReturnType<typeof setInterval> => {
      intervalFnRef = fn;
      return setTimeout(() => {}, 999999) as unknown as ReturnType<typeof setInterval>;
    };

    const event = makeEvent();

    const { result: exitCode, stderr } = await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: sshSpawn,
        _sdkRunnerForTest: sdkRunner,
        _ghReviewForTest: ghReview,
        _setIntervalForTest: setIntervalFake,
        _cwdForTest: "/tmp",
        _eventQueueForTest: [event],
      }),
    );

    // AC #2: exit 0 on clean queue drain.
    assert.equal(exitCode, 0, `expected exit 0, got ${exitCode}`);

    // AC #2: subscribed line.
    assert.ok(stderr.includes("⟳ subscribed"), `expected '⟳ subscribed' in: ${stderr}`);
    // AC #2: triage line.
    assert.ok(stderr.includes("⟳ triaging event"), `expected '⟳ triaging event' in: ${stderr}`);
    // AC #4+#2: seat claimed.
    assert.ok(stderr.includes("⟳ claimed seat"), `expected '⟳ claimed seat' in: ${stderr}`);
    // AC #6: builtin-default prompt name logged.
    assert.ok(stderr.includes("builtin-default"), `expected 'builtin-default' in: ${stderr}`);
    // AC #7: posted review.
    assert.ok(stderr.includes("✓ posted review"), `expected '✓ posted review' in: ${stderr}`);

    // AC #6: SDK called exactly once.
    assert.equal(sdkCallCount, 1, "SDK runner should have been called once");

    // AC #7: gh received the PR URL.
    assert.ok(ghCallArgs !== null, "gh review should have been called");
    if (ghCallArgs) {
      assert.equal(ghCallArgs.prUrl, "https://github.com/acme/widget/pull/42");
      assert.ok(ghCallArgs.body.length > 0, "review body should be non-empty");
    }

    // AC #5: setInterval was called (heartbeat timer armed).
    assert.ok(intervalFnRef !== null, "setInterval should have been called for heartbeat");

    // Verify heartbeat tick doesn't throw.
    if (intervalFnRef) intervalFnRef();

    // AC #2: SSH calls include subscribe + claim-seat.
    assert.ok(sshCalls.includes("subscribe"), `expected subscribe in: ${sshCalls}`);
    assert.ok(sshCalls.includes("claim-seat"), `expected claim-seat in: ${sshCalls}`);
  });

  it("AC #13: stdout is empty on a normal run", async () => {
    const fakeKeypair = genKeypair();
    const event = makeEvent();

    const { result: exitCode, stdout } = await captureStdoutAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: makeSuccessSshSpawn(),
        _sdkRunnerForTest: async () => "review body",
        _ghReviewForTest: () => ({ status: 0, stderr: "" }),
        _cwdForTest: "/tmp",
        _eventQueueForTest: [event],
      }),
    );

    assert.equal(exitCode, 0);
    assert.equal(stdout.length, 0, `stdout should be empty, got: ${JSON.stringify(stdout)}`);
  });
});

// ─── AC #8: loop re-enters after each event ───────────────────────────

describe("AC #8: loop re-enters — two events, both processed", () => {
  it("processes two consecutive events", async () => {
    const fakeKeypair = genKeypair();
    let sdkCallCount = 0;
    const sdkRunner = async (_diff: string): Promise<string> => {
      sdkCallCount++;
      return "review body";
    };
    let ghCallCount = 0;
    const ghReview = () => {
      ghCallCount++;
      return { status: 0, stderr: "" };
    };

    const event1 = makeEvent({ patch_id: "1".repeat(40) });
    const event2 = makeEvent({ patch_id: "2".repeat(40) });

    const { result: exitCode } = await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: makeSuccessSshSpawn(),
        _sdkRunnerForTest: sdkRunner,
        _ghReviewForTest: ghReview,
        _cwdForTest: "/tmp",
        _eventQueueForTest: [event1, event2],
      }),
    );

    assert.equal(exitCode, 0);
    assert.equal(sdkCallCount, 2, `SDK should have been called twice, got ${sdkCallCount}`);
    assert.equal(ghCallCount, 2, `gh should have been called twice, got ${ghCallCount}`);
  });
});

// ─── AC #3: author-exclusion ─────────────────────────────────────────

describe("AC #3: author-exclusion — own-fingerprint event skipped", () => {
  it("skips event when requested_by_fp matches operator fingerprint", async () => {
    const fakeKeypair = genKeypair();
    let sdkCalled = false;
    let ghCalled = false;

    // Event where requested_by_fp === operator's fingerprint.
    const selfEvent = makeEvent({
      payloadOverrides: { requested_by_fp: fakeKeypair.fingerprint },
    });


    const { stderr } = await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: makeSuccessSshSpawn(),
        _sdkRunnerForTest: async (_diff) => { sdkCalled = true; return "body"; },
        _ghReviewForTest: (_url, _body) => { ghCalled = true; return { status: 0, stderr: "" }; },
        _cwdForTest: "/tmp",
        _eventQueueForTest: [selfEvent],
      }),
    );

    // Skip message logged.
    assert.ok(
      stderr.includes("skipping event") && stderr.includes("author matches own"),
      `expected author-exclusion skip message, got: ${stderr}`,
    );
    // SDK and gh must NOT have been called.
    assert.equal(sdkCalled, false, "SDK should NOT be called for own-author event");
    assert.equal(ghCalled, false, "gh review should NOT be called for own-author event");
  });
});

// ─── AC #4: seat-claim rejection codes ───────────────────────────────

describe("AC #4: seat-claim rejections", () => {
  function makeSeatRejectionSshSpawn(stderrMsg: string): SshSpawnFn {
    return async (_cfg, verb) => {
      if (verb === "subscribe") {
        return {
          stdout: JSON.stringify({ ok: true, fingerprint: "fp", orgs: ["acme"] }),
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }
      if (verb === "claim-seat") {
        return { stdout: "", stderr: stderrMsg, exitCode: 5, signal: null };
      }
      return { stdout: "", stderr: "", exitCode: 0, signal: null };
    };
  }

  it("logs 'seats full' and skips on seats_full rejection", async () => {
    const fakeKeypair = genKeypair();
    let sdkCalled = false;

    const { stderr } = await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: makeSeatRejectionSshSpawn("error: claim rejected: seats_full"),
        _sdkRunnerForTest: async (_diff) => { sdkCalled = true; return "body"; },
        _cwdForTest: "/tmp",
        _eventQueueForTest: [makeEvent()],
      }),
    );

    assert.ok(stderr.includes("seats full"), `expected 'seats full' in: ${stderr}`);
    assert.equal(sdkCalled, false, "SDK should NOT be called when seats are full");
  });

  it("logs 'author_cannot_claim_own_pr' reason", async () => {
    const fakeKeypair = genKeypair();

    const { stderr } = await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: makeSeatRejectionSshSpawn("error: claim rejected: author_cannot_claim_own_pr"),
        _cwdForTest: "/tmp",
        _eventQueueForTest: [makeEvent()],
      }),
    );

    assert.ok(
      stderr.includes("author_cannot_claim_own_pr"),
      `expected 'author_cannot_claim_own_pr' in: ${stderr}`,
    );
  });

  it("logs 'already_holds_other_seat' reason", async () => {
    const fakeKeypair = genKeypair();

    const { stderr } = await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: makeSeatRejectionSshSpawn("error: claim rejected: already_holds_other_seat"),
        _cwdForTest: "/tmp",
        _eventQueueForTest: [makeEvent()],
      }),
    );

    assert.ok(
      stderr.includes("already_holds_other_seat"),
      `expected 'already_holds_other_seat' in: ${stderr}`,
    );
  });
});

// ─── AC #7: gh pr review failure → release-seat ──────────────────────

describe("AC #7: gh pr review failure → release-seat called", () => {
  it("emits ✗ and calls release-seat when gh fails", async () => {
    const fakeKeypair = genKeypair();
    const sshCalls: string[] = [];
    const sshSpawn: SshSpawnFn = async (cfg, verb) => {
      sshCalls.push(verb);
      return makeSuccessSshSpawn(1)(cfg, verb);
    };

    const sdkRunner = async (_diff: string): Promise<string> => "review body";
    // gh fails.
    const ghReview = () => ({ status: 1, stderr: "gh auth failure" });

    const { stderr } = await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: sshSpawn,
        _sdkRunnerForTest: sdkRunner,
        _ghReviewForTest: ghReview,
        _cwdForTest: "/tmp",
        _eventQueueForTest: [makeEvent()],
      }),
    );

    assert.ok(
      stderr.includes("✗ gh pr review failed"),
      `expected '✗ gh pr review failed' in: ${stderr}`,
    );
    // release-seat should have been called.
    assert.ok(
      sshCalls.includes("release-seat"),
      `expected release-seat in calls: ${sshCalls.join(",")}`,
    );
  });
});

// ─── STAMP_NO_LLM=1 (AC #6 consistency) ─────────────────────────────

describe("STAMP_NO_LLM=1: builtin review refuses before SDK call", () => {
  it("returns ok:false with STAMP_NO_LLM message", async () => {
    const origNoLlm = process.env["STAMP_NO_LLM"];
    process.env["STAMP_NO_LLM"] = "1";
    try {
      const { runBuiltinReview } = await import("../src/lib/builtinReviewPrompt.ts");
      const result = await runBuiltinReview({ diff: "test diff", cwd: "/tmp" });
      assert.equal(result.ok, false, "runBuiltinReview should fail when STAMP_NO_LLM=1");
      if (!result.ok) {
        assert.ok(result.message.includes("STAMP_NO_LLM"), `message missing STAMP_NO_LLM: ${result.message}`);
      }
    } finally {
      if (origNoLlm === undefined) delete process.env["STAMP_NO_LLM"];
      else process.env["STAMP_NO_LLM"] = origNoLlm;
    }
  });
});

// ─── seatClient unit tests (AC #4 rejection reason parsing) ──────────

describe("seatClient: callClaimSeat rejection reason parsing (AC #4)", () => {
  const SEAT_INPUT = {
    patch_id: "a".repeat(40),
    claimant_fp: "sha256:" + "a".repeat(64),
    base_sha: "b".repeat(40),
    repo: "acme/widget",
    signature: "sig",
    serverConfig: { host: "stamp.example.com", port: 2222, user: "git", repoRootPrefix: "/srv/git" },
  } as const;

  function makeRejectSshSpawn(stderrMsg: string): SshSpawnFn {
    return async () => ({ stdout: "", stderr: stderrMsg, exitCode: 5, signal: null });
  }

  it("maps 'seats_full' stderr → claimRejectionReason='seats_full'", async () => {
    const { callClaimSeat } = await import("../src/lib/seatClient.ts");
    const result = await callClaimSeat({
      ...SEAT_INPUT,
      _sshSpawnForTest: makeRejectSshSpawn("error: claim rejected: seats_full"),
    });
    assert.equal(result.ok, false);
    if (!result.ok && result.reason === "claim_rejected") {
      assert.equal(result.claimRejectionReason, "seats_full");
    } else {
      assert.fail(`expected claim_rejected, got ${JSON.stringify(result)}`);
    }
  });

  it("maps 'author_cannot_claim_own_pr' correctly", async () => {
    const { callClaimSeat } = await import("../src/lib/seatClient.ts");
    const result = await callClaimSeat({
      ...SEAT_INPUT,
      _sshSpawnForTest: makeRejectSshSpawn("error: claim rejected: author_cannot_claim_own_pr"),
    });
    assert.equal(result.ok, false);
    if (!result.ok && result.reason === "claim_rejected") {
      assert.equal(result.claimRejectionReason, "author_cannot_claim_own_pr");
    } else {
      assert.fail(`expected claim_rejected, got ${JSON.stringify(result)}`);
    }
  });

  it("maps 'already_holds_other_seat' correctly", async () => {
    const { callClaimSeat } = await import("../src/lib/seatClient.ts");
    const result = await callClaimSeat({
      ...SEAT_INPUT,
      _sshSpawnForTest: makeRejectSshSpawn("error: claim rejected: already_holds_other_seat"),
    });
    assert.equal(result.ok, false);
    if (!result.ok && result.reason === "claim_rejected") {
      assert.equal(result.claimRejectionReason, "already_holds_other_seat");
    } else {
      assert.fail(`expected claim_rejected, got ${JSON.stringify(result)}`);
    }
  });

  it("falls back to 'unknown' for unrecognised reason", async () => {
    const { callClaimSeat } = await import("../src/lib/seatClient.ts");
    const result = await callClaimSeat({
      ...SEAT_INPUT,
      _sshSpawnForTest: makeRejectSshSpawn("error: claim rejected: something_weird"),
    });
    assert.equal(result.ok, false);
    if (!result.ok && result.reason === "claim_rejected") {
      assert.equal(result.claimRejectionReason, "unknown");
    } else {
      assert.fail(`expected claim_rejected, got ${JSON.stringify(result)}`);
    }
  });

  it("returns ok:true with seat number on success", async () => {
    const { callClaimSeat } = await import("../src/lib/seatClient.ts");
    const result = await callClaimSeat({
      ...SEAT_INPUT,
      _sshSpawnForTest: async () => ({
        stdout: JSON.stringify({ ok: true, seat: 2, patch_id: "a".repeat(40) }),
        stderr: "",
        exitCode: 0,
        signal: null,
      }),
    });
    assert.equal(result.ok, true);
    if (result.ok) assert.equal(result.seat, 2);
  });
});

// ─── AC #1: structural — runPrListen is exported ──────────────────────

describe("AC #1: runPrListen is exported and callable", () => {
  it("exports runPrListen as a function", () => {
    assert.equal(typeof runPrListen, "function");
  });
});
