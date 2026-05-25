/**
 * AGT-431 — Unit tests for `stamp pr ping`.
 *
 * Coverage per ACs:
 *   AC #14 — non-author key → exit 1
 *   AC #15 — no PR from HEAD → exit 3
 *   AC #16 — no seat-holders → exit 0 + stderr note
 *   AC #1  — happy path: success, seat_holders_notified > 0
 *   AC #3  — --reviewer filter forwarded to callReReviewRequest
 *   AC #4  — exit code contract (0/1/3)
 *
 * All subprocess and network boundaries are injected via test seams.
 */

import { strict as assert } from "node:assert";
import { describe, it, beforeEach, afterEach } from "node:test";
import {
  generateKeyPairSync,
  createHash,
  createPublicKey,
} from "node:crypto";

import { runPrPing, type PrPingOptions } from "../src/commands/prPing.ts";
import type { SshSpawnFn } from "../src/lib/seatClient.ts";
import type { Keypair } from "../src/lib/keys.ts";
import type { ServerConfig } from "../src/lib/serverConfig.ts";

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

async function runWithExitCapture(opts: PrPingOptions): Promise<number> {
  const origExit = process.exit.bind(process);
  let capturedCode: number | undefined;
  const patchedExit = (code?: number | string) => {
    capturedCode = typeof code === "number" ? code : 0;
    throw new ExitSignal(capturedCode);
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (process as any).exit = patchedExit;

  try {
    await runPrPing(opts);
    return capturedCode ?? 0;
  } catch (err) {
    if (err instanceof ExitSignal) return err.code;
    throw err;
  } finally {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process as any).exit = origExit;
  }
}

/** Capture stderr output during an async fn. */
async function captureStderrAsync<T>(
  fn: () => Promise<T>,
): Promise<{ result: T; stderr: string }> {
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

/** Capture stdout output during an async fn. */
async function captureStdoutAsync<T>(
  fn: () => Promise<T>,
): Promise<{ result: T; stdout: string }> {
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
  return { result, stdout: lines.join("") };
}

const FIXTURE_SERVER: ServerConfig = {
  host: "stamp.example.com",
  port: 2222,
  user: "git",
  repoRootPrefix: "/srv/git",
};

const PATCH_ID = "a".repeat(40);

/** SSH spawn seam that simulates a successful re-review-request. */
function makeSuccessSshSpawn(seatHoldersNotified = 2): SshSpawnFn {
  return async (_cfg, verb) => {
    if (verb === "re-review-request") {
      return {
        stdout: JSON.stringify({
          ok: true,
          patch_id: PATCH_ID,
          seat_holders_notified: seatHoldersNotified,
        }),
        stderr: "",
        exitCode: 0,
        signal: null,
      };
    }
    return { stdout: "", stderr: "unknown verb", exitCode: 1, signal: null };
  };
}

/** SSH spawn seam that simulates the non-author rejection (server exit 5). */
function makeNotAuthorSshSpawn(): SshSpawnFn {
  return async () => ({
    stdout: "",
    stderr: "error: requester_fp xxx is not the original author",
    exitCode: 5,
    signal: null,
  });
}

/** SSH spawn seam that simulates patch not found (server exit 4). */
function makePatchNotFoundSshSpawn(): SshSpawnFn {
  return async () => ({
    stdout: "",
    stderr: "error: patch xxx not found",
    exitCode: 4,
    signal: null,
  });
}

/** Patch-id resolver seam that returns null (simulates no PR from HEAD). */
function makeNoPrPatchId(): () => null {
  return () => null;
}

/** Patch-id resolver seam that returns a valid patch_id. */
function makeValidPatchId(): () => { patch_id: string; base_sha: string; head_sha: string } {
  return () => ({
    patch_id: PATCH_ID,
    base_sha: "b".repeat(40),
    head_sha: "c".repeat(40),
  });
}

// ─── AC #15: no PR from HEAD → exit 3 ────────────────────────────────

describe("AC #15: no PR detectable from HEAD → exit 3", () => {
  it("exits 3 when _patchIdForTest returns null", async () => {
    const keypair = genKeypair();
    const code = await runWithExitCapture({
      reviewer: [],
      _keypairForTest: keypair,
      _serverConfigForTest: FIXTURE_SERVER,
      _patchIdForTest: makeNoPrPatchId(),
      _sshSpawnForTest: makeSuccessSshSpawn(),
    });
    assert.equal(code, 3, `expected exit 3, got ${code}`);
  });
});

// ─── AC #14: non-author key → exit 1 ─────────────────────────────────

describe("AC #14: non-author key → exit 1", () => {
  it("exits 1 when server returns exit 5 (not_author)", async () => {
    const keypair = genKeypair();
    const { result: code, stderr } = await captureStderrAsync(() =>
      runWithExitCapture({
        reviewer: [],
        _keypairForTest: keypair,
        _serverConfigForTest: FIXTURE_SERVER,
        _patchIdForTest: makeValidPatchId(),
        _sshSpawnForTest: makeNotAuthorSshSpawn(),
      }),
    );
    assert.equal(code, 1, `expected exit 1, got ${code}`);
    assert.ok(
      stderr.includes("not the original") || stderr.includes("not_author") || stderr.includes("refused"),
      `expected auth-failure message in: ${stderr}`,
    );
  });
});

// ─── AC #16: no seat-holders → exit 0 + stderr note ─────────────────

describe("AC #16: no active seat-holders → exit 0 + stderr note", () => {
  it("exits 0 and prints stderr note when seat_holders_notified is 0", async () => {
    const keypair = genKeypair();
    const { result: code, stderr } = await captureStderrAsync(() =>
      runWithExitCapture({
        reviewer: [],
        _keypairForTest: keypair,
        _serverConfigForTest: FIXTURE_SERVER,
        _patchIdForTest: makeValidPatchId(),
        _sshSpawnForTest: makeSuccessSshSpawn(0),
      }),
    );
    assert.equal(code, 0, `expected exit 0, got ${code}`);
    assert.ok(
      stderr.includes("no active seat-holders"),
      `expected 'no active seat-holders' note in stderr: ${stderr}`,
    );
  });
});

// ─── AC #1: happy path ────────────────────────────────────────────────

describe("AC #1: happy path — sends re-review-request and exits 0", () => {
  it("exits 0 and prints success line to stdout", async () => {
    const keypair = genKeypair();
    const { result: code, stdout } = await captureStdoutAsync(() =>
      runWithExitCapture({
        reviewer: [],
        _keypairForTest: keypair,
        _serverConfigForTest: FIXTURE_SERVER,
        _patchIdForTest: makeValidPatchId(),
        _sshSpawnForTest: makeSuccessSshSpawn(2),
      }),
    );
    assert.equal(code, 0, `expected exit 0, got ${code}`);
    assert.ok(
      stdout.includes("sent re-review-requested") || stdout.includes("seat-holder"),
      `expected success stdout message in: ${stdout}`,
    );
  });

  it("calls re-review-request SSH verb with correct patch_id and reviewer_filter", async () => {
    const keypair = genKeypair();
    const capturedPayloads: string[] = [];

    const spawnFn: SshSpawnFn = async (_cfg, verb, payload) => {
      if (verb === "re-review-request") {
        capturedPayloads.push(payload);
        return {
          stdout: JSON.stringify({ ok: true, patch_id: PATCH_ID, seat_holders_notified: 1 }),
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }
      return { stdout: "", stderr: "unknown verb", exitCode: 1, signal: null };
    };

    await captureStdoutAsync(() =>
      runWithExitCapture({
        reviewer: ["alice", "bob"],
        _keypairForTest: keypair,
        _serverConfigForTest: FIXTURE_SERVER,
        _patchIdForTest: makeValidPatchId(),
        _sshSpawnForTest: spawnFn,
      }),
    );

    assert.equal(capturedPayloads.length, 1, "SSH spawn should have been called once");
    const parsed = JSON.parse(capturedPayloads[0]!) as {
      patch_id: string;
      reviewer_filter: string[];
    };
    assert.equal(parsed.patch_id, PATCH_ID);
    assert.deepStrictEqual(parsed.reviewer_filter, ["alice", "bob"]);
  });
});

// ─── AC #3: server-returns-patch-not-found → exit 3 ─────────────────

describe("AC #3 (server): server returns exit 4 (patch not found) → CLI exit 3", () => {
  it("exits 3 when server returns exit 4", async () => {
    const keypair = genKeypair();
    const code = await runWithExitCapture({
      reviewer: [],
      _keypairForTest: keypair,
      _serverConfigForTest: FIXTURE_SERVER,
      _patchIdForTest: makeValidPatchId(),
      _sshSpawnForTest: makePatchNotFoundSshSpawn(),
    });
    assert.equal(code, 3, `expected exit 3, got ${code}`);
  });
});

// ─── peer_reviews_not_configured → exit 0 ────────────────────────────

describe("peer_reviews_not_configured → exit 0 (informational)", () => {
  it("exits 0 when server has peer reviews disabled", async () => {
    const keypair = genKeypair();
    const spawnFn: SshSpawnFn = async () => ({
      stdout: JSON.stringify({ ok: false, error: "peer_reviews_not_configured" }),
      stderr: "",
      exitCode: 0,
      signal: null,
    });
    const { result: code, stderr } = await captureStderrAsync(() =>
      runWithExitCapture({
        reviewer: [],
        _keypairForTest: keypair,
        _serverConfigForTest: FIXTURE_SERVER,
        _patchIdForTest: makeValidPatchId(),
        _sshSpawnForTest: spawnFn,
      }),
    );
    assert.equal(code, 0, `expected exit 0, got ${code}`);
    assert.ok(
      stderr.includes("peer reviews disabled"),
      `expected 'peer reviews disabled' in stderr: ${stderr}`,
    );
  });
});

// ─── Auth failure: no keypair → exit 1 ───────────────────────────────

describe("missing keypair → exit 1", () => {
  it("exits 1 when no keypair is available", async () => {
    const code = await runWithExitCapture({
      reviewer: [],
      _keypairForTest: null,
      _serverConfigForTest: FIXTURE_SERVER,
      _patchIdForTest: makeValidPatchId(),
      _sshSpawnForTest: makeSuccessSshSpawn(),
    });
    assert.equal(code, 1, `expected exit 1, got ${code}`);
  });
});
