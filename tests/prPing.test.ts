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
import type { HttpFetchFn, SshSpawnFn } from "../src/lib/seatClient.ts";
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

// ─── HTTP fetch seam helpers (AGT-453: replaced SSH spawn seam) ──────────

/** HTTP fetch seam that simulates a successful re-review-request (HTTP 200). */
function makeSuccessHttpFetch(seatHoldersNotified = 2): HttpFetchFn {
  return async (url) => {
    if (url.endsWith("/peer/re-review-request")) {
      return {
        status: 200,
        body: JSON.stringify({
          ok: true,
          patch_id: PATCH_ID,
          seat_holders_notified: seatHoldersNotified,
        }),
      };
    }
    return { status: 500, body: JSON.stringify({ ok: false, error: "unknown_url" }) };
  };
}

/** HTTP fetch seam that simulates the non-author rejection (HTTP 403). */
function makeNotAuthorHttpFetch(): HttpFetchFn {
  return async () => ({
    status: 403,
    body: JSON.stringify({ ok: false, error: "not_author", reason: "requester_fp xxx is not the original author" }),
  });
}

/** HTTP fetch seam that simulates patch not found (HTTP 404). */
function makePatchNotFoundHttpFetch(): HttpFetchFn {
  return async () => ({
    status: 404,
    body: JSON.stringify({ ok: false, error: "patch_not_found" }),
  });
}

/** @deprecated SSH spawn seam — kept for type compatibility only. */
function makeSuccessSshSpawn(_seatHoldersNotified = 2): SshSpawnFn {
  return async () => ({ stdout: "", stderr: "", exitCode: 0, signal: null });
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
      _fetchForTest: makeSuccessHttpFetch(),
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
        _fetchForTest: makeNotAuthorHttpFetch(),
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
        _fetchForTest: makeSuccessHttpFetch(0),
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
        _fetchForTest: makeSuccessHttpFetch(2),
      }),
    );
    assert.equal(code, 0, `expected exit 0, got ${code}`);
    assert.ok(
      stdout.includes("sent re-review-requested") || stdout.includes("seat-holder"),
      `expected success stdout message in: ${stdout}`,
    );
  });

  it("calls POST /peer/re-review-request with correct patch_id and reviewer_filter", async () => {
    const keypair = genKeypair();
    const capturedBodies: string[] = [];

    const fetchFn: HttpFetchFn = async (url, _headers, body) => {
      if (url.endsWith("/peer/re-review-request")) {
        capturedBodies.push(body);
        return {
          status: 200,
          body: JSON.stringify({ ok: true, patch_id: PATCH_ID, seat_holders_notified: 1 }),
        };
      }
      return { status: 500, body: JSON.stringify({ ok: false, error: "unknown_url" }) };
    };

    await captureStdoutAsync(() =>
      runWithExitCapture({
        reviewer: ["alice", "bob"],
        _keypairForTest: keypair,
        _serverConfigForTest: FIXTURE_SERVER,
        _patchIdForTest: makeValidPatchId(),
        _fetchForTest: fetchFn,
      }),
    );

    assert.equal(capturedBodies.length, 1, "HTTP fetch should have been called once");
    const parsed = JSON.parse(capturedBodies[0]!) as {
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
      _fetchForTest: makePatchNotFoundHttpFetch(),
    });
    assert.equal(code, 3, `expected exit 3, got ${code}`);
  });
});

// ─── peer_reviews_not_configured → exit 0 ────────────────────────────

describe("peer_reviews_not_configured → exit 0 (informational)", () => {
  it("exits 0 when server has peer reviews disabled", async () => {
    const keypair = genKeypair();
    const fetchFn: HttpFetchFn = async () => ({
      status: 404,
      body: JSON.stringify({ ok: false, error: "not_found" }),
    });
    const { result: code, stderr } = await captureStderrAsync(() =>
      runWithExitCapture({
        reviewer: [],
        _keypairForTest: keypair,
        _serverConfigForTest: FIXTURE_SERVER,
        _patchIdForTest: makeValidPatchId(),
        _fetchForTest: fetchFn,
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
      _fetchForTest: makeSuccessHttpFetch(),
    });
    assert.equal(code, 1, `expected exit 1, got ${code}`);
  });
});
