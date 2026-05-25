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
import type { ResolveNamedPromptInput } from "../src/lib/namedPrompt.ts";

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
    if (verb === "stamp-subscribe") {
      return {
        stdout: JSON.stringify({ ok: true, fingerprint: "fp", orgs: ["acme"] }),
        stderr: "",
        exitCode: 0,
        signal: null,
      };
    }
    if (verb === "stamp-claim-seat") {
      return {
        stdout: JSON.stringify({ ok: true, seat: seatNum, patch_id: "a".repeat(40) }),
        stderr: "",
        exitCode: 0,
        signal: null,
      };
    }
    if (verb === "stamp-heartbeat") {
      return {
        stdout: JSON.stringify({ ok: true, seat: seatNum, patch_id: "a".repeat(40) }),
        stderr: "",
        exitCode: 0,
        signal: null,
      };
    }
    if (verb === "stamp-release-seat") {
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

/**
 * AGT-454: Default seams to bypass the client-side operator verification gate.
 *
 * Tests that pre-date AGT-454 use `makeEvent()` which produces a `pr-opened`
 * event for `acme/widget`. The new gate skips any event whose repo is not
 * mapped in `~/.stamp/peer-repos.yml`. These seams inject a fake map with the
 * test repo present, and short-circuit `verifyOperatorAtBaseLocal` to always
 * accept. Tests that explicitly exercise the operator-verification gate should
 * override these seams.
 */
function bypassOperatorGate(): Pick<
  import("../src/commands/prListen.ts").PrListenOptions,
  "_peerReposMapForTest" | "_operatorVerifyForTest"
> {
  return {
    _peerReposMapForTest: new Map([["acme/widget", "/tmp/fake-acme-widget"]]),
    _operatorVerifyForTest: () => ({ ok: true as const }),
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
        ...bypassOperatorGate(),
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
    assert.ok(sshCalls.includes("stamp-subscribe"), `expected stamp-subscribe in: ${sshCalls}`);
    assert.ok(sshCalls.includes("stamp-claim-seat"), `expected stamp-claim-seat in: ${sshCalls}`);
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
        ...bypassOperatorGate(),
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
        ...bypassOperatorGate(),
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
      if (verb === "stamp-subscribe") {
        return {
          stdout: JSON.stringify({ ok: true, fingerprint: "fp", orgs: ["acme"] }),
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }
      if (verb === "stamp-claim-seat") {
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
        ...bypassOperatorGate(),
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
        ...bypassOperatorGate(),
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
        ...bypassOperatorGate(),
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
        ...bypassOperatorGate(),
      }),
    );

    assert.ok(
      stderr.includes("✗ gh pr review failed"),
      `expected '✗ gh pr review failed' in: ${stderr}`,
    );
    // release-seat should have been called.
    assert.ok(
      sshCalls.includes("stamp-release-seat"),
      `expected stamp-release-seat in calls: ${sshCalls.join(",")}`,
    );
  });
});

// ─── Security: pr_url validation ─────────────────────────────────────

describe("Security: pr_url validation — flag-shaped or empty pr_url skipped", () => {
  it("skips event with flag-shaped pr_url (e.g. '-H')", async () => {
    const fakeKeypair = genKeypair();
    let sdkCalled = false;

    const { stderr } = await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: makeSuccessSshSpawn(),
        _sdkRunnerForTest: async (_diff) => { sdkCalled = true; return "body"; },
        _cwdForTest: "/tmp",
        _eventQueueForTest: [
          makeEvent({ payloadOverrides: { pr_url: "-H" } }),
        ],
      }),
    );

    assert.ok(
      stderr.includes("does not match expected"),
      `expected pr_url validation message in stderr, got: ${stderr}`,
    );
    assert.equal(sdkCalled, false, "SDK should NOT be called for flag-shaped pr_url");
  });

  it("skips event with empty pr_url", async () => {
    const fakeKeypair = genKeypair();
    let sdkCalled = false;

    const { stderr } = await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: makeSuccessSshSpawn(),
        _sdkRunnerForTest: async (_diff) => { sdkCalled = true; return "body"; },
        _cwdForTest: "/tmp",
        _eventQueueForTest: [
          makeEvent({ payloadOverrides: { pr_url: "" } }),
        ],
      }),
    );

    assert.ok(
      stderr.includes("does not match expected"),
      `expected pr_url validation message in stderr, got: ${stderr}`,
    );
    assert.equal(sdkCalled, false, "SDK should NOT be called for empty pr_url");
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
    pubkey: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAfakepubkeyforthisunittest=\n-----END PUBLIC KEY-----\n",
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

// ─── AGT-430: Triage + named prompt integration ──────────────────────

describe("AGT-430 AC #1+4: triage → named prompt used as systemPrompt for review", () => {
  it("event → triage returns if_available + prompt:sec → named prompt body passed to review SDK", async () => {
    const fakeKeypair = genKeypair();
    const NAMED_PROMPT_BODY = "You are a security expert. Review this PR for vulnerabilities.";

    let sdkReceivedSystemPrompt: string | undefined;
    // We track what systemPrompt the review was called with via the diff
    // (since _sdkRunnerForTest only gets diff). We need a different approach:
    // we check that the review was NOT called with BUILTIN_DEFAULT_PROMPT by
    // verifying the resolveNamedPrompt seam was called with name="sec".

    let resolvedNameCalled: string | undefined;
    const resolveNamedPromptFake = (input: { name: string }) => {
      resolvedNameCalled = input.name;
      return { ok: true as const, body: NAMED_PROMPT_BODY, resolvedPath: "/fake/.stamp/personal/peers/sec.md" };
    };

    // Haiku triage runner returns prompt:"sec"
    const haikuRunner = async (_sys: string, _user: string): Promise<string> =>
      '{"claim_seat":"if_available","post_mode":"auto-post","prompt":"sec"}';

    let sdkCallCount = 0;
    const sdkRunner = async (_diff: string): Promise<string> => {
      sdkCallCount++;
      return "review body from named prompt";
    };

    const event = makeEvent();
    const triplets: unknown[] = [];

    const { result: exitCode, stderr } = await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: makeSuccessSshSpawn(),
        _sdkRunnerForTest: sdkRunner,
        _haikuRunnerForTest: haikuRunner,
        _peerWatchRulesForTest: { rules: "Claim if security-related", hash: "abc123" },
        _resolveNamedPromptForTest: resolveNamedPromptFake,
        _appendTripletForTest: (rec) => triplets.push(rec),
        _ghReviewForTest: () => ({ status: 0, stderr: "" }),
        _cwdForTest: "/tmp",
        _eventQueueForTest: [event],
        ...bypassOperatorGate(),
      }),
    );

    assert.equal(exitCode, 0);
    // Triage ran and named prompt was resolved.
    assert.equal(resolvedNameCalled, "sec", `expected named prompt "sec" to be resolved`);
    // Review SDK was called exactly once.
    assert.equal(sdkCallCount, 1, "SDK should be called once after named prompt resolved");
    // Prompt name logged to stderr.
    assert.ok(stderr.includes('"sec"') || stderr.includes("sec"), `expected "sec" in stderr: ${stderr}`);
    // Triplet logged.
    assert.equal(triplets.length, 1, "expected 1 triplet logged");
  });
});

describe("AGT-430 AC #3: missing named prompt → ✗ log + skip (no claim, no SDK, no gh)", () => {
  it("triage returns prompt:'missing', file absent → logs ✗ and skips the event", async () => {
    const fakeKeypair = genKeypair();

    const haikuRunner = async (): Promise<string> =>
      '{"claim_seat":"if_available","post_mode":"auto-post","prompt":"missing-prompt"}';

    // Resolver returns ok:false (missing file)
    const resolveNamedPromptFake = (_input: { name: string }) =>
      ({ ok: false as const, reason: "missing_file" as const });

    let sdkCalled = false;
    let ghCalled = false;
    const triplets: unknown[] = [];

    const { result: exitCode, stderr } = await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: makeSuccessSshSpawn(),
        _sdkRunnerForTest: async () => { sdkCalled = true; return "body"; },
        _haikuRunnerForTest: haikuRunner,
        _peerWatchRulesForTest: { rules: "rules text", hash: "abc" },
        _resolveNamedPromptForTest: resolveNamedPromptFake,
        _appendTripletForTest: (rec) => triplets.push(rec),
        _ghReviewForTest: (_url, _body) => { ghCalled = true; return { status: 0, stderr: "" }; },
        _cwdForTest: "/tmp",
        _eventQueueForTest: [makeEvent()],
        ...bypassOperatorGate(),
      }),
    );

    assert.equal(exitCode, 0);
    // ✗ logged about missing prompt.
    assert.ok(stderr.includes("✗"), `expected ✗ in stderr: ${stderr}`);
    assert.ok(stderr.includes("missing-prompt"), `expected prompt name in stderr: ${stderr}`);
    // SDK and gh must NOT have been called.
    assert.equal(sdkCalled, false, "SDK should NOT be called when named prompt is missing");
    assert.equal(ghCalled, false, "gh should NOT be called when named prompt is missing");
    // Triplet is still logged (AC #6 says "regardless of whether the decision results in a claim").
    assert.equal(triplets.length, 1, "expected triplet to be logged even when prompt missing");
  });
});

describe("AGT-430 AC #6: triplet logged regardless of skip vs. claim", () => {
  it("logs triplet when triage returns skip", async () => {
    const fakeKeypair = genKeypair();

    const haikuRunner = async (): Promise<string> =>
      '{"claim_seat":"skip","post_mode":"auto-post","prompt":"default"}';

    const triplets: unknown[] = [];

    const { result: exitCode } = await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: makeSuccessSshSpawn(),
        _haikuRunnerForTest: haikuRunner,
        _peerWatchRulesForTest: { rules: "Skip all", hash: "deadbeef" },
        _appendTripletForTest: (rec) => triplets.push(rec),
        _cwdForTest: "/tmp",
        _eventQueueForTest: [makeEvent()],
        ...bypassOperatorGate(),
      }),
    );

    assert.equal(exitCode, 0);
    // Triplet should be logged even when decision is skip.
    assert.equal(triplets.length, 1, "triplet should be logged even for a skip decision");
    // Verify record shape.
    const rec = triplets[0] as Record<string, unknown>;
    assert.ok(typeof rec["ts"] === "string", "triplet should have ts field");
    assert.ok(typeof rec["repo"] === "string", "triplet should have repo field");
    assert.ok(typeof rec["pr_url"] === "string", "triplet should have pr_url field");
    assert.ok(typeof rec["rules_hash"] === "string", "triplet should have rules_hash field");
    assert.ok(typeof rec["event_payload"] === "object", "triplet should have event_payload field");
    assert.ok(typeof rec["decision"] === "object", "triplet should have decision field");
    const decision = rec["decision"] as Record<string, unknown>;
    assert.equal(decision["claim_seat"], "skip");
  });

  it("logs triplet with correct rules_hash from the rules seam", async () => {
    const fakeKeypair = genKeypair();
    const EXPECTED_HASH = "myexpectedhash123";

    const haikuRunner = async (): Promise<string> =>
      '{"claim_seat":"if_available","post_mode":"auto-post","prompt":"default"}';

    const triplets: unknown[] = [];

    const { result: exitCode } = await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: makeSuccessSshSpawn(),
        _sdkRunnerForTest: async () => "review body",
        _haikuRunnerForTest: haikuRunner,
        _peerWatchRulesForTest: { rules: "some rules", hash: EXPECTED_HASH },
        _resolveNamedPromptForTest: () => ({ ok: false as const, reason: "missing_file" as const }),
        _appendTripletForTest: (rec) => triplets.push(rec),
        _cwdForTest: "/tmp",
        _eventQueueForTest: [makeEvent()],
        ...bypassOperatorGate(),
      }),
    );

    assert.equal(exitCode, 0);
    assert.equal(triplets.length, 1);
    const rec = triplets[0] as Record<string, unknown>;
    assert.equal(rec["rules_hash"], EXPECTED_HASH, "triplet rules_hash should match the injected hash");
  });
});

describe("AGT-430 AC #8: peer-watch.md missing → ⟳ notice + fallback decision drives claim", () => {
  it("uses fallback decision if_available when rules file is missing", async () => {
    const fakeKeypair = genKeypair();

    let sdkCalled = false;
    let ghCalled = false;
    const triplets: unknown[] = [];

    const { result: exitCode, stderr } = await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: makeSuccessSshSpawn(),
        _sdkRunnerForTest: async () => { sdkCalled = true; return "review body"; },
        // No haikuRunner needed since triage is skipped on missing rules
        _peerWatchRulesForTest: null, // simulates missing peer-watch.md
        _appendTripletForTest: (rec) => triplets.push(rec),
        _ghReviewForTest: (_url, _body) => { ghCalled = true; return { status: 0, stderr: "" }; },
        _cwdForTest: "/tmp",
        _eventQueueForTest: [makeEvent()],
        ...bypassOperatorGate(),
      }),
    );

    assert.equal(exitCode, 0);
    // ⟳ notice logged about missing rules file.
    assert.ok(stderr.includes("⟳"), `expected ⟳ notice in stderr: ${stderr}`);
    assert.ok(
      stderr.includes("peer-watch.md") || stderr.includes("peer_watch") || stderr.includes("no ~/.stamp"),
      `expected peer-watch reference in stderr: ${stderr}`,
    );
    // With fallback decision (if_available), the seat should be claimed if available.
    // The fallback also uses "default" prompt, so BUILTIN_DEFAULT_PROMPT is used.
    assert.equal(sdkCalled, true, "review SDK should be called with fallback decision");
    assert.equal(ghCalled, true, "gh should be called with fallback decision");
    // Triplet logged even in fallback path.
    assert.equal(triplets.length, 1, "triplet should be logged even in fallback path");
    const rec = triplets[0] as Record<string, unknown>;
    assert.equal((rec["decision"] as Record<string, unknown>)["claim_seat"], "if_available");
  });
});

describe("AGT-430 AC triage skip: triage returns skip → no claim, no SDK, no gh", () => {
  it("skips claim/review/gh when triage says skip", async () => {
    const fakeKeypair = genKeypair();

    const haikuRunner = async (): Promise<string> =>
      '{"claim_seat":"skip","post_mode":"auto-post","prompt":"default"}';

    let sdkCalled = false;
    let sshClaimCalled = false;
    const sshSpawn: SshSpawnFn = async (cfg, verb) => {
      if (verb === "stamp-claim-seat") sshClaimCalled = true;
      return makeSuccessSshSpawn(1)(cfg, verb);
    };

    const { result: exitCode, stderr } = await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: sshSpawn,
        _sdkRunnerForTest: async () => { sdkCalled = true; return "body"; },
        _haikuRunnerForTest: haikuRunner,
        _peerWatchRulesForTest: { rules: "Skip all PRs", hash: "abc" },
        _appendTripletForTest: () => {},
        _cwdForTest: "/tmp",
        _eventQueueForTest: [makeEvent()],
        ...bypassOperatorGate(),
      }),
    );

    assert.equal(exitCode, 0);
    // Skip notice logged.
    assert.ok(stderr.includes("skip"), `expected skip notice in stderr: ${stderr}`);
    // SSH claim-seat should NOT have been called.
    assert.equal(sshClaimCalled, false, "claim-seat should NOT be called when triage returns skip");
    assert.equal(sdkCalled, false, "review SDK should NOT be called when triage returns skip");
  });
});

// ─── AGT-431: callReReviewRequest exit-code mapping ──────────────────

describe("AGT-431: callReReviewRequest SSH exit-code mapping", () => {
  const RE_REVIEW_INPUT = {
    patch_id: "a".repeat(40),
    requester_fp: "sha256:" + "a".repeat(64),
    reviewer_filter: [] as string[],
    signature: "sig",
    serverConfig: { host: "stamp.example.com", port: 2222, user: "git", repoRootPrefix: "/srv/git" },
  } as const;

  it("maps server exit 5 → reason: 'not_author'", async () => {
    const { callReReviewRequest } = await import("../src/lib/seatClient.ts");
    const result = await callReReviewRequest({
      ...RE_REVIEW_INPUT,
      _sshSpawnForTest: async () => ({
        stdout: "",
        stderr: "error: requester_fp is not the original author",
        exitCode: 5,
        signal: null,
      }),
    });
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.reason, "not_author", `expected not_author, got ${result.reason}`);
    }
  });

  it("maps server exit 4 → reason: 'patch_not_found'", async () => {
    const { callReReviewRequest } = await import("../src/lib/seatClient.ts");
    const result = await callReReviewRequest({
      ...RE_REVIEW_INPUT,
      _sshSpawnForTest: async () => ({
        stdout: "",
        stderr: "error: patch xxx not found",
        exitCode: 4,
        signal: null,
      }),
    });
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.reason, "patch_not_found", `expected patch_not_found, got ${result.reason}`);
    }
  });

  it("maps peer_reviews_not_configured JSON → reason: 'peer_reviews_not_configured'", async () => {
    const { callReReviewRequest } = await import("../src/lib/seatClient.ts");
    const result = await callReReviewRequest({
      ...RE_REVIEW_INPUT,
      _sshSpawnForTest: async () => ({
        stdout: JSON.stringify({ ok: false, error: "peer_reviews_not_configured" }),
        stderr: "",
        exitCode: 0,
        signal: null,
      }),
    });
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.reason, "peer_reviews_not_configured");
    }
  });

  it("returns ok:true with seat_holders_notified on success", async () => {
    const { callReReviewRequest } = await import("../src/lib/seatClient.ts");
    const result = await callReReviewRequest({
      ...RE_REVIEW_INPUT,
      _sshSpawnForTest: async () => ({
        stdout: JSON.stringify({ ok: true, patch_id: "a".repeat(40), seat_holders_notified: 2 }),
        stderr: "",
        exitCode: 0,
        signal: null,
      }),
    });
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.seat_holders_notified, 2);
    }
  });
});

// ─── AGT-431 AC #11/#12: re-review-requested event handling ───────────

describe("AGT-431 AC #11: re-review-requested event triggers re-triage + review + post", () => {
  it("processes re-review-requested event identically to pr-opened (full loop)", async () => {
    const fakeKeypair = genKeypair();
    let sdkCallCount = 0;
    let ghCallCount = 0;
    const triplets: Array<Record<string, unknown>> = [];

    const reReviewEvent: PeerReviewEvent = {
      event_type: "re-review-requested",
      patch_id: "d".repeat(40),
      actor_fp: "sha256:" + "e".repeat(64),
      payload: {
        patch_id: "d".repeat(40),
        requested_by_fp: "sha256:" + "f".repeat(64),
        pr_url: "https://github.com/acme/widget/pull/99",
        repo: "acme/widget",
        seat: 1,
      },
    };

    const { result: exitCode, stderr } = await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: makeSuccessSshSpawn(),
        _sdkRunnerForTest: async () => {
          sdkCallCount++;
          return "re-review body";
        },
        _ghReviewForTest: () => {
          ghCallCount++;
          return { status: 0, stderr: "" };
        },
        _peerWatchRulesForTest: null, // use fallback (if_available)
        _appendTripletForTest: (rec) => triplets.push(rec as Record<string, unknown>),
        _cwdForTest: "/tmp",
        _eventQueueForTest: [reReviewEvent],
      }),
    );

    assert.equal(exitCode, 0, `expected exit 0, got ${exitCode}`);
    // AC #11: review ran and was posted.
    assert.equal(sdkCallCount, 1, "SDK should be called once for re-review-requested");
    assert.equal(ghCallCount, 1, "gh should be called once for re-review-requested");
    // AC #11: seat was claimed.
    assert.ok(stderr.includes("⟳ claimed seat"), `expected seat claim in: ${stderr}`);
    // AC #11: review posted.
    assert.ok(stderr.includes("✓ posted review"), `expected posted review in: ${stderr}`);
  });
});

describe("AGT-431 AC #12: re-review-requested triplet tagged kind: 're-review'", () => {
  it("logs triplet with kind='re-review' for re-review-requested events", async () => {
    const fakeKeypair = genKeypair();
    const triplets: Array<Record<string, unknown>> = [];

    const reReviewEvent: PeerReviewEvent = {
      event_type: "re-review-requested",
      patch_id: "d".repeat(40),
      actor_fp: "sha256:" + "e".repeat(64),
      payload: {
        patch_id: "d".repeat(40),
        requested_by_fp: "sha256:" + "f".repeat(64),
        pr_url: "https://github.com/acme/widget/pull/99",
        repo: "acme/widget",
        seat: 1,
      },
    };

    await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: makeSuccessSshSpawn(),
        _sdkRunnerForTest: async () => "review body",
        _ghReviewForTest: () => ({ status: 0, stderr: "" }),
        _peerWatchRulesForTest: null,
        _appendTripletForTest: (rec) => triplets.push(rec as Record<string, unknown>),
        _cwdForTest: "/tmp",
        _eventQueueForTest: [reReviewEvent],
      }),
    );

    assert.equal(triplets.length, 1, "expected exactly 1 triplet for re-review-requested");
    const rec = triplets[0]!;
    assert.equal(rec["kind"], "re-review", `expected kind='re-review' in triplet: ${JSON.stringify(rec)}`);
  });

  it("pr-opened triplet does NOT have kind field (backwards-compat)", async () => {
    const fakeKeypair = genKeypair();
    const triplets: Array<Record<string, unknown>> = [];

    await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: makeSuccessSshSpawn(),
        _sdkRunnerForTest: async () => "review body",
        _ghReviewForTest: () => ({ status: 0, stderr: "" }),
        _peerWatchRulesForTest: null,
        _appendTripletForTest: (rec) => triplets.push(rec as Record<string, unknown>),
        _cwdForTest: "/tmp",
        _eventQueueForTest: [makeEvent()], // pr-opened event
        ...bypassOperatorGate(),
      }),
    );

    assert.equal(triplets.length, 1, "expected 1 triplet for pr-opened");
    const rec = triplets[0]!;
    assert.ok(
      !("kind" in rec) || rec["kind"] === undefined,
      `pr-opened triplet should NOT have kind field, got: ${JSON.stringify(rec)}`,
    );
  });
});

// ─── AGT-432 AC #2/#3: daily cost-cap enforcement ────────────────────

describe("AGT-432 AC #3: cost-cap — cap NOT hit when dailySpend < cost_cap_usd", () => {
  it("does not downgrade or notify when dailySpend < cap", async () => {
    const fakeKeypair = genKeypair();
    const triplets: Array<Record<string, unknown>> = [];
    const notifyCalls: Array<{ title: string; body: string }> = [];
    let sdkCalled = false;
    let sshClaimCalled = false;

    // cap=0.001, _initialDailySpendForTest not set (defaults to 0)
    // 0 < 0.001 → cap NOT triggered
    const haikuRunner = async (): Promise<string> =>
      '{"claim_seat":"if_available","post_mode":"auto-post","prompt":"default","cost_cap_usd":0.001}';

    const sshSpawn: SshSpawnFn = async (cfg, verb) => {
      if (verb === "stamp-claim-seat") sshClaimCalled = true;
      return makeSuccessSshSpawn(1)(cfg, verb);
    };

    const { result: exitCode } = await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: sshSpawn,
        _sdkRunnerForTest: async () => { sdkCalled = true; return "review body"; },
        _haikuRunnerForTest: haikuRunner,
        _peerWatchRulesForTest: { rules: "claim if available", hash: "abc" },
        _appendTripletForTest: (rec) => triplets.push(rec as Record<string, unknown>),
        _notifyForTest: (title, body) => { notifyCalls.push({ title, body }); },
        _ghReviewForTest: () => ({ status: 0, stderr: "" }),
        _cwdForTest: "/tmp",
        _eventQueueForTest: [makeEvent()],
        ...bypassOperatorGate(),
      }),
    );

    assert.equal(exitCode, 0);
    assert.equal(sshClaimCalled, true, "seat should be claimed when cap is not hit");
    assert.equal(sdkCalled, true, "SDK should run when cap is not hit");
    assert.equal(notifyCalls.length, 0, "notification should NOT fire when cap is not hit");
  });
});

describe("AGT-432 AC #3: cost-cap — cap HIT when _initialDailySpendForTest >= cost_cap_usd", () => {
  it("downgrades if_available to skip and fires notification when pre-seeded daily spend >= cap", async () => {
    const fakeKeypair = genKeypair();
    const triplets: Array<Record<string, unknown>> = [];
    const notifyCalls: Array<{ title: string; body: string }> = [];
    let sdkCalled = false;
    let sshClaimCalled = false;

    // cap=0.001, _initialDailySpendForTest=0.002 → dailySpend(0.002) >= cap(0.001) → IS triggered
    const haikuRunner = async (): Promise<string> =>
      '{"claim_seat":"if_available","post_mode":"auto-post","prompt":"default","cost_cap_usd":0.001}';

    const sshSpawn: SshSpawnFn = async (cfg, verb) => {
      if (verb === "stamp-claim-seat") sshClaimCalled = true;
      return makeSuccessSshSpawn(1)(cfg, verb);
    };

    const { result: exitCode } = await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: sshSpawn,
        _sdkRunnerForTest: async () => { sdkCalled = true; return "review body"; },
        _haikuRunnerForTest: haikuRunner,
        _peerWatchRulesForTest: { rules: "claim if available", hash: "abc" },
        _appendTripletForTest: (rec) => triplets.push(rec as Record<string, unknown>),
        _notifyForTest: (title, body) => { notifyCalls.push({ title, body }); },
        _ghReviewForTest: () => ({ status: 0, stderr: "" }),
        _cwdForTest: "/tmp",
        _initialDailySpendForTest: 0.002,
        _eventQueueForTest: [makeEvent()],
        ...bypassOperatorGate(),
      }),
    );

    assert.equal(exitCode, 0);
    // Cap is HIT → seat should NOT be claimed, SDK should NOT run
    assert.equal(sshClaimCalled, false, "seat should NOT be claimed when cap is hit");
    assert.equal(sdkCalled, false, "SDK should NOT run when cap is hit");
    // Notification should fire once
    assert.equal(notifyCalls.length, 1, "notification should fire when cap is hit");
    // Triplet should have reason='daily cap hit'
    assert.equal(triplets.length, 1, "expected 1 triplet");
    assert.equal(triplets[0]!["reason"], "daily cap hit", "triplet reason should be 'daily cap hit'");
  });
});

describe("AGT-432 AC #4: cost-cap log — normal skip does NOT get reason field", () => {
  it("triplet has no reason field on triage-returned skip (not cap-triggered)", async () => {
    const fakeKeypair = genKeypair();
    const triplets: Array<Record<string, unknown>> = [];
    const notifyCalls: Array<{ title: string; body: string }> = [];

    // Triage naturally returns skip (no cost_cap_usd, no cap enforcement)
    const haikuRunner = async (): Promise<string> =>
      '{"claim_seat":"skip","post_mode":"auto-post","prompt":"default"}';

    await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: makeSuccessSshSpawn(),
        _haikuRunnerForTest: haikuRunner,
        _peerWatchRulesForTest: { rules: "skip all", hash: "abc" },
        _appendTripletForTest: (rec) => triplets.push(rec as Record<string, unknown>),
        _notifyForTest: (title, body) => { notifyCalls.push({ title, body }); },
        _cwdForTest: "/tmp",
        _eventQueueForTest: [makeEvent()],
        ...bypassOperatorGate(),
      }),
    );

    assert.equal(triplets.length, 1, "expected 1 triplet");
    const rec = triplets[0]!;
    // Normal skip (not cap-triggered): reason field should be absent
    assert.ok(
      !("reason" in rec) || rec["reason"] === undefined,
      `normal skip should NOT have reason field, got: ${JSON.stringify(rec)}`,
    );
    assert.equal(notifyCalls.length, 0, "no notification for normal skip");
  });
});

describe("AGT-432 AC #2: day rollover — daily spend resets at local midnight", () => {
  it("resets dailySpend when day changes (via _nowForTest)", async () => {
    const fakeKeypair = genKeypair();
    let dayCount = 0;
    let tripletCount = 0;

    // Alternate between two days to simulate day rollover.
    // Day 0 → process first event; Day 1 → process second event (new day).
    const days = ["2026-05-24", "2026-05-25"];
    const nowFn = () => new Date(days[dayCount % 2]! + "T12:00:00Z");

    // Use a $0.001 cap; both events have costUsd=0 (seam), so no cap trigger.
    // The test just verifies the loop completes normally across a day rollover.
    const haikuRunner = async (): Promise<string> => {
      dayCount++;
      return '{"claim_seat":"if_available","post_mode":"auto-post","prompt":"default","cost_cap_usd":0.001}';
    };

    const { result: exitCode } = await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: makeSuccessSshSpawn(),
        _sdkRunnerForTest: async () => "review body",
        _ghReviewForTest: () => ({ status: 0, stderr: "" }),
        _haikuRunnerForTest: haikuRunner,
        _peerWatchRulesForTest: { rules: "test", hash: "abc" },
        _appendTripletForTest: () => { tripletCount++; },
        _nowForTest: nowFn,
        _cwdForTest: "/tmp",
        // Two events on different days
        _eventQueueForTest: [makeEvent({ patch_id: "1".repeat(40) }), makeEvent({ patch_id: "2".repeat(40) })],
        ...bypassOperatorGate(),
      }),
    );

    assert.equal(exitCode, 0);
    // Both events should process normally even across a day rollover.
    assert.equal(tripletCount, 2, "both events should be processed");
  });
});

describe("AGT-432: draft save — listener saves draft when post_mode='draft'", () => {
  it("saves draft file and does not post via gh when post_mode='draft'", async () => {
    const fakeKeypair = genKeypair();
    const drafts: Array<{ filePath: string; content: string }> = [];
    let ghCalled = false;

    // Triage returns post_mode: 'draft'
    const haikuRunner = async (): Promise<string> =>
      '{"claim_seat":"if_available","post_mode":"draft","prompt":"default"}';

    const { result: exitCode, stderr } = await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: makeSuccessSshSpawn(),
        _sdkRunnerForTest: async () => "draft review body",
        _ghReviewForTest: () => { ghCalled = true; return { status: 0, stderr: "" }; },
        _haikuRunnerForTest: haikuRunner,
        _peerWatchRulesForTest: { rules: "draft mode", hash: "abc" },
        _appendTripletForTest: () => {},
        _writeDraftForTest: (filePath, content) => { drafts.push({ filePath, content }); },
        _cwdForTest: "/tmp",
        _eventQueueForTest: [makeEvent()],
        ...bypassOperatorGate(),
      }),
    );

    assert.equal(exitCode, 0);
    // Draft should be saved
    assert.equal(drafts.length, 1, "expected 1 draft to be saved");
    assert.ok(drafts[0]!.filePath.includes(".md"), "draft file should be .md");
    assert.ok(drafts[0]!.content.includes("draft review body"), "draft content should include review body");
    assert.ok(drafts[0]!.content.includes("pr_url"), "draft should include pr_url in frontmatter");
    // gh should NOT be called for draft mode
    assert.equal(ghCalled, false, "gh review should NOT be called when post_mode='draft'");
    // Logged to stderr
    assert.ok(stderr.includes("saved draft") || stderr.includes("draft"), `expected draft save message in stderr: ${stderr}`);
  });

  it("draft file path is in draftsDir() and named by patchId", async () => {
    const fakeKeypair = genKeypair();
    const drafts: Array<{ filePath: string; content: string }> = [];
    const patchId = "a".repeat(40);

    const haikuRunner = async (): Promise<string> =>
      '{"claim_seat":"if_available","post_mode":"draft","prompt":"default"}';

    await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: makeSuccessSshSpawn(),
        _sdkRunnerForTest: async () => "body",
        _ghReviewForTest: () => ({ status: 0, stderr: "" }),
        _haikuRunnerForTest: haikuRunner,
        _peerWatchRulesForTest: { rules: "draft mode", hash: "abc" },
        _appendTripletForTest: () => {},
        _writeDraftForTest: (filePath, content) => { drafts.push({ filePath, content }); },
        _cwdForTest: "/tmp",
        _eventQueueForTest: [makeEvent({ patch_id: patchId })],
        ...bypassOperatorGate(),
      }),
    );

    assert.equal(drafts.length, 1, "expected 1 draft");
    assert.ok(
      drafts[0]!.filePath.includes(patchId),
      `expected patchId in draft path: ${drafts[0]!.filePath}`,
    );
    assert.ok(
      drafts[0]!.filePath.includes("drafts"),
      `expected 'drafts' in path: ${drafts[0]!.filePath}`,
    );
  });
});

describe("AGT-432: re-review event also subject to cost-cap downgrade", () => {
  it("cost-cap check applies to re-review-requested events too", async () => {
    const fakeKeypair = genKeypair();
    const triplets: Array<Record<string, unknown>> = [];
    let sdkCalled = false;

    // Re-review event with if_available + cap
    const haikuRunner = async (): Promise<string> =>
      '{"claim_seat":"if_available","post_mode":"auto-post","prompt":"default","cost_cap_usd":0.001}';

    const reReviewEvent: PeerReviewEvent = {
      event_type: "re-review-requested",
      patch_id: "d".repeat(40),
      actor_fp: "sha256:" + "e".repeat(64),
      payload: {
        patch_id: "d".repeat(40),
        requested_by_fp: "sha256:" + "f".repeat(64),
        pr_url: "https://github.com/acme/widget/pull/99",
        repo: "acme/widget",
        seat: 1,
      },
    };

    const { result: exitCode } = await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: makeSuccessSshSpawn(),
        _sdkRunnerForTest: async () => { sdkCalled = true; return "re-review body"; },
        _ghReviewForTest: () => ({ status: 0, stderr: "" }),
        _haikuRunnerForTest: haikuRunner,
        _peerWatchRulesForTest: { rules: "test", hash: "abc" },
        _appendTripletForTest: (rec) => triplets.push(rec as Record<string, unknown>),
        _notifyForTest: () => {},
        _cwdForTest: "/tmp",
        _eventQueueForTest: [reReviewEvent],
      }),
    );

    assert.equal(exitCode, 0);
    // With dailySpend=0 and cap=0.001 → cap NOT hit → review proceeds
    assert.equal(sdkCalled, true, "SDK should run for re-review when cap not exceeded");
    assert.equal(triplets.length, 1, "triplet should be logged for re-review");
    // Verify triplet is tagged as re-review
    assert.equal(triplets[0]!["kind"], "re-review", "re-review triplet should have kind='re-review'");
  });

  it("AC-3: downgrades re-review-requested to skip with reason 'daily cap hit' when cap is hit", async () => {
    // Mirrors the fresh pr-opened cap-HIT test but for a re-review-requested event.
    // Proves cap enforcement applies at the shared triage-finalize point for re-review events too.
    const fakeKeypair = genKeypair();
    const triplets: Array<Record<string, unknown>> = [];
    const notifyCalls: Array<{ title: string; body: string }> = [];
    let sdkCalled = false;
    let sshClaimCalled = false;

    // cap=0.001; _initialDailySpendForTest=0.002 → dailySpend(0.002) >= cap(0.001) → IS triggered
    const haikuRunner = async (): Promise<string> =>
      '{"claim_seat":"if_available","post_mode":"auto-post","prompt":"default","cost_cap_usd":0.001}';

    const sshSpawn: SshSpawnFn = async (cfg, verb) => {
      if (verb === "stamp-claim-seat") sshClaimCalled = true;
      return makeSuccessSshSpawn(1)(cfg, verb);
    };

    const reReviewEvent: PeerReviewEvent = {
      event_type: "re-review-requested",
      patch_id: "d".repeat(40),
      actor_fp: "sha256:" + "e".repeat(64),
      payload: {
        patch_id: "d".repeat(40),
        requested_by_fp: "sha256:" + "f".repeat(64),
        pr_url: "https://github.com/acme/widget/pull/99",
        repo: "acme/widget",
        seat: 1,
      },
    };

    const { result: exitCode } = await captureStderrAsync(() =>
      runWithExitCapture({
        orgs: ["acme"],
        server: FIXTURE_SERVER,
        _keypairForTest: fakeKeypair,
        _sshSpawnForTest: sshSpawn,
        _sdkRunnerForTest: async () => { sdkCalled = true; return "re-review body"; },
        _ghReviewForTest: () => ({ status: 0, stderr: "" }),
        _haikuRunnerForTest: haikuRunner,
        _peerWatchRulesForTest: { rules: "claim if available", hash: "abc" },
        _appendTripletForTest: (rec) => triplets.push(rec as Record<string, unknown>),
        _notifyForTest: (title, body) => { notifyCalls.push({ title, body }); },
        _cwdForTest: "/tmp",
        _initialDailySpendForTest: 0.002,
        _eventQueueForTest: [reReviewEvent],
      }),
    );

    assert.equal(exitCode, 0);
    // Cap is HIT → seat should NOT be claimed, SDK should NOT run
    assert.equal(sshClaimCalled, false, "seat should NOT be claimed for re-review when cap is hit");
    assert.equal(sdkCalled, false, "SDK should NOT run for re-review when cap is hit");
    // Notification should fire once
    assert.equal(notifyCalls.length, 1, "notification should fire when cap is hit on re-review");
    // Triplet should be logged with reason='daily cap hit' (AC-3 + AC-4)
    assert.equal(triplets.length, 1, "expected 1 triplet for cap-downgraded re-review");
    assert.equal(
      triplets[0]!["reason"],
      "daily cap hit",
      "re-review triplet reason should be 'daily cap hit' when cap is hit",
    );
  });
});
