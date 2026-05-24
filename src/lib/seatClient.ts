/**
 * Client-side SSH transport for the four peer-review seat verbs (AGT-429):
 *   subscribe / claim-seat / heartbeat / release-seat
 *
 * Mirrors `prOpenedClient.ts` exactly in structure:
 *   - subprocess `ssh -p <port> -- <user>@<host> <verb>` with JSON payload on stdin
 *   - `_sshSpawnForTest` injection seam per verb (same `SshSpawnFn` shape)
 *   - discriminated result types per verb mapping the server's exit codes
 *
 * Exit-code mapping (server-side, per AGT-427 verb comments):
 *   0  — success (or feature-not-configured)
 *   1  — server-side / unexpected error
 *   4  — validation / auth failure
 *   5  — seat claim rejected (claim-seat only)
 *
 * Signature coverage: payloads are signed per the server's auth model; the
 * server currently relies on SSH identity binding (fp === caller.fingerprint)
 * so the signature field is included for forward-compat with future verifiers
 * (AGT-434) without a protocol change. Minimal JSON-stable canonical form is
 * used (same rationale as prOpenedClient.ts).
 */

import { spawn } from "node:child_process";
import type { ServerConfig } from "./serverConfig.js";

export type { ServerConfig };

// ─── SSH spawn seam ─────────────────────────────────────────────────

export interface SshSpawnResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
}

/** Test-only injection seam. Same shape as SshSpawnFn in prOpenedClient.ts. */
export type SshSpawnFn = (
  cfg: ServerConfig,
  verb: string,
  payload: string,
) => Promise<SshSpawnResult>;

async function defaultSshSpawn(
  cfg: ServerConfig,
  verb: string,
  payload: string,
): Promise<SshSpawnResult> {
  const sshArgv = ["-p", String(cfg.port), "--", `${cfg.user}@${cfg.host}`, verb];

  return new Promise<SshSpawnResult>((resolvePromise, rejectPromise) => {
    const child = spawn("ssh", sshArgv, {
      stdio: ["pipe", "pipe", "pipe"],
    });

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => stdoutChunks.push(c));
    child.stderr.on("data", (c: Buffer) => stderrChunks.push(c));

    child.on("error", (err) => {
      rejectPromise(
        new Error(
          `failed to spawn ssh for stamp-server ${cfg.user}@${cfg.host}:${cfg.port} verb=${verb}: ${err.message}`,
        ),
      );
    });

    child.on("close", (exitCode, signal) => {
      resolvePromise({
        stdout: Buffer.concat(stdoutChunks).toString("utf8"),
        stderr: Buffer.concat(stderrChunks).toString("utf8"),
        exitCode,
        signal,
      });
    });

    child.stdin.on("error", (err) => {
      rejectPromise(
        new Error(
          `failed to write payload to ssh stdin for ${cfg.user}@${cfg.host}:${cfg.port} verb=${verb}: ${err.message}`,
        ),
      );
    });
    child.stdin.write(payload, "utf8");
    child.stdin.end();
  });
}

// ─── subscribe ────────────────────────────────────────────────────────

export interface SubscribeSuccess {
  ok: true;
  fingerprint: string;
  orgs: string[];
}

export interface SubscribeFailure {
  ok: false;
  reason: "subscribe_failed" | "peer_reviews_not_configured";
  message: string;
  serverStderr: string;
}

export type SubscribeResult = SubscribeSuccess | SubscribeFailure;

export interface SubscribeInput {
  orgs: string[];
  fingerprint: string;
  signature: string;
  serverConfig: ServerConfig;
  _sshSpawnForTest?: SshSpawnFn;
}

export async function callSubscribe(input: SubscribeInput): Promise<SubscribeResult> {
  const spawnFn = input._sshSpawnForTest ?? defaultSshSpawn;
  const payload = JSON.stringify({
    orgs: input.orgs,
    fingerprint: input.fingerprint,
    signature: input.signature,
  });

  let result: SshSpawnResult;
  try {
    result = await spawnFn(input.serverConfig, "subscribe", payload);
  } catch (err) {
    return {
      ok: false,
      reason: "subscribe_failed",
      message: `ssh spawn failed: ${err instanceof Error ? err.message : String(err)}`,
      serverStderr: "",
    };
  }

  if (result.exitCode !== 0) {
    const stderr = result.stderr.trim();
    return {
      ok: false,
      reason: "subscribe_failed",
      message:
        `stamp-server subscribe returned exit ${result.exitCode}. ` +
        (stderr ? `server stderr: ${stderr}` : ""),
      serverStderr: stderr,
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(result.stdout.trim());
  } catch {
    return {
      ok: false,
      reason: "subscribe_failed",
      message: `stamp-server returned malformed JSON: ${JSON.stringify(result.stdout.slice(0, 200))}`,
      serverStderr: result.stderr.trim(),
    };
  }

  const obj = parsed as Record<string, unknown>;

  if (obj.ok === false && obj.error === "peer_reviews_not_configured") {
    return {
      ok: false,
      reason: "peer_reviews_not_configured",
      message: "stamp-server has peer reviews disabled",
      serverStderr: result.stderr.trim(),
    };
  }

  if (obj.ok === true) {
    return {
      ok: true,
      fingerprint: typeof obj.fingerprint === "string" ? obj.fingerprint : input.fingerprint,
      orgs: Array.isArray(obj.orgs) ? (obj.orgs as string[]) : input.orgs,
    };
  }

  const errMsg = typeof obj.error === "string" ? obj.error : JSON.stringify(obj);
  return {
    ok: false,
    reason: "subscribe_failed",
    message: `stamp-server returned error: ${errMsg}`,
    serverStderr: result.stderr.trim(),
  };
}

// ─── claim-seat ───────────────────────────────────────────────────────

/** Claim-seat rejection reasons parsed from the server's exit-5 stderr. */
export type ClaimRejectionReason =
  | "seats_full"
  | "author_cannot_claim_own_pr"
  | "already_holds_other_seat"
  | "unknown";

export interface ClaimSeatSuccess {
  ok: true;
  seat: number;
  patch_id: string;
}

export interface ClaimSeatRejected {
  ok: false;
  reason: "claim_rejected";
  claimRejectionReason: ClaimRejectionReason;
  message: string;
  serverStderr: string;
}

export interface ClaimSeatFailure {
  ok: false;
  reason: "claim_failed" | "peer_reviews_not_configured";
  message: string;
  serverStderr: string;
}

export type ClaimSeatResult = ClaimSeatSuccess | ClaimSeatRejected | ClaimSeatFailure;

export interface ClaimSeatInput {
  patch_id: string;
  claimant_fp: string;
  base_sha: string;
  repo: string;
  signature: string;
  serverConfig: ServerConfig;
  _sshSpawnForTest?: SshSpawnFn;
}

/** Parse the known rejection substrings from claim-seat's exit-5 stderr. */
function parseClaimRejectionReason(stderr: string): ClaimRejectionReason {
  if (stderr.includes("seats_full")) return "seats_full";
  if (stderr.includes("author_cannot_claim_own_pr")) return "author_cannot_claim_own_pr";
  if (stderr.includes("already_holds_other_seat")) return "already_holds_other_seat";
  return "unknown";
}

export async function callClaimSeat(input: ClaimSeatInput): Promise<ClaimSeatResult> {
  const spawnFn = input._sshSpawnForTest ?? defaultSshSpawn;
  const payload = JSON.stringify({
    patch_id: input.patch_id,
    claimant_fp: input.claimant_fp,
    base_sha: input.base_sha,
    repo: input.repo,
    signature: input.signature,
  });

  let result: SshSpawnResult;
  try {
    result = await spawnFn(input.serverConfig, "claim-seat", payload);
  } catch (err) {
    return {
      ok: false,
      reason: "claim_failed",
      message: `ssh spawn failed: ${err instanceof Error ? err.message : String(err)}`,
      serverStderr: "",
    };
  }

  if (result.exitCode === 5) {
    // Seat claim rejected: parse the server's stderr prose for the specific reason.
    const stderr = result.stderr.trim();
    const claimRejectionReason = parseClaimRejectionReason(stderr);
    return {
      ok: false,
      reason: "claim_rejected",
      claimRejectionReason,
      message: `claim rejected: ${stderr}`,
      serverStderr: stderr,
    };
  }

  if (result.exitCode !== 0) {
    const stderr = result.stderr.trim();
    return {
      ok: false,
      reason: "claim_failed",
      message:
        `stamp-server claim-seat returned exit ${result.exitCode}. ` +
        (stderr ? `server stderr: ${stderr}` : ""),
      serverStderr: stderr,
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(result.stdout.trim());
  } catch {
    return {
      ok: false,
      reason: "claim_failed",
      message: `stamp-server returned malformed JSON: ${JSON.stringify(result.stdout.slice(0, 200))}`,
      serverStderr: result.stderr.trim(),
    };
  }

  const obj = parsed as Record<string, unknown>;

  if (obj.ok === false && obj.error === "peer_reviews_not_configured") {
    return {
      ok: false,
      reason: "peer_reviews_not_configured",
      message: "stamp-server has peer reviews disabled",
      serverStderr: result.stderr.trim(),
    };
  }

  if (obj.ok === true) {
    const seat = typeof obj.seat === "number" ? obj.seat : 1;
    const patch_id = typeof obj.patch_id === "string" ? obj.patch_id : input.patch_id;
    return { ok: true, seat, patch_id };
  }

  const errMsg = typeof obj.error === "string" ? obj.error : JSON.stringify(obj);
  return {
    ok: false,
    reason: "claim_failed",
    message: `stamp-server returned error: ${errMsg}`,
    serverStderr: result.stderr.trim(),
  };
}

// ─── heartbeat ────────────────────────────────────────────────────────

export interface HeartbeatSuccess {
  ok: true;
  seat: number;
  patch_id: string;
}

export interface HeartbeatFailure {
  ok: false;
  reason: "heartbeat_failed" | "peer_reviews_not_configured";
  message: string;
  serverStderr: string;
}

export type HeartbeatResult = HeartbeatSuccess | HeartbeatFailure;

export interface HeartbeatInput {
  patch_id: string;
  claimant_fp: string;
  signature: string;
  serverConfig: ServerConfig;
  _sshSpawnForTest?: SshSpawnFn;
}

export async function callHeartbeat(input: HeartbeatInput): Promise<HeartbeatResult> {
  const spawnFn = input._sshSpawnForTest ?? defaultSshSpawn;
  const payload = JSON.stringify({
    patch_id: input.patch_id,
    claimant_fp: input.claimant_fp,
    signature: input.signature,
  });

  let result: SshSpawnResult;
  try {
    result = await spawnFn(input.serverConfig, "heartbeat", payload);
  } catch (err) {
    return {
      ok: false,
      reason: "heartbeat_failed",
      message: `ssh spawn failed: ${err instanceof Error ? err.message : String(err)}`,
      serverStderr: "",
    };
  }

  if (result.exitCode !== 0) {
    const stderr = result.stderr.trim();
    return {
      ok: false,
      reason: "heartbeat_failed",
      message:
        `stamp-server heartbeat returned exit ${result.exitCode}. ` +
        (stderr ? `server stderr: ${stderr}` : ""),
      serverStderr: stderr,
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(result.stdout.trim());
  } catch {
    return {
      ok: false,
      reason: "heartbeat_failed",
      message: `stamp-server returned malformed JSON: ${JSON.stringify(result.stdout.slice(0, 200))}`,
      serverStderr: result.stderr.trim(),
    };
  }

  const obj = parsed as Record<string, unknown>;

  if (obj.ok === false && obj.error === "peer_reviews_not_configured") {
    return {
      ok: false,
      reason: "peer_reviews_not_configured",
      message: "stamp-server has peer reviews disabled",
      serverStderr: result.stderr.trim(),
    };
  }

  if (obj.ok === true) {
    const seat = typeof obj.seat === "number" ? obj.seat : 1;
    const patch_id = typeof obj.patch_id === "string" ? obj.patch_id : input.patch_id;
    return { ok: true, seat, patch_id };
  }

  const errMsg = typeof obj.error === "string" ? obj.error : JSON.stringify(obj);
  return {
    ok: false,
    reason: "heartbeat_failed",
    message: `stamp-server returned error: ${errMsg}`,
    serverStderr: result.stderr.trim(),
  };
}

// ─── release-seat ─────────────────────────────────────────────────────

export interface ReleaseSeatSuccess {
  ok: true;
  released: boolean;
  patch_id: string;
}

export interface ReleaseSeatFailure {
  ok: false;
  reason: "release_failed" | "peer_reviews_not_configured";
  message: string;
  serverStderr: string;
}

export type ReleaseSeatResult = ReleaseSeatSuccess | ReleaseSeatFailure;

export interface ReleaseSeatInput {
  patch_id: string;
  claimant_fp: string;
  signature: string;
  serverConfig: ServerConfig;
  _sshSpawnForTest?: SshSpawnFn;
}

export async function callReleaseSeat(input: ReleaseSeatInput): Promise<ReleaseSeatResult> {
  const spawnFn = input._sshSpawnForTest ?? defaultSshSpawn;
  const payload = JSON.stringify({
    patch_id: input.patch_id,
    claimant_fp: input.claimant_fp,
    signature: input.signature,
  });

  let result: SshSpawnResult;
  try {
    result = await spawnFn(input.serverConfig, "release-seat", payload);
  } catch (err) {
    return {
      ok: false,
      reason: "release_failed",
      message: `ssh spawn failed: ${err instanceof Error ? err.message : String(err)}`,
      serverStderr: "",
    };
  }

  if (result.exitCode !== 0) {
    const stderr = result.stderr.trim();
    return {
      ok: false,
      reason: "release_failed",
      message:
        `stamp-server release-seat returned exit ${result.exitCode}. ` +
        (stderr ? `server stderr: ${stderr}` : ""),
      serverStderr: stderr,
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(result.stdout.trim());
  } catch {
    return {
      ok: false,
      reason: "release_failed",
      message: `stamp-server returned malformed JSON: ${JSON.stringify(result.stdout.slice(0, 200))}`,
      serverStderr: result.stderr.trim(),
    };
  }

  const obj = parsed as Record<string, unknown>;

  if (obj.ok === false && obj.error === "peer_reviews_not_configured") {
    return {
      ok: false,
      reason: "peer_reviews_not_configured",
      message: "stamp-server has peer reviews disabled",
      serverStderr: result.stderr.trim(),
    };
  }

  if (obj.ok === true) {
    const released = obj.released === true;
    const patch_id = typeof obj.patch_id === "string" ? obj.patch_id : input.patch_id;
    return { ok: true, released, patch_id };
  }

  const errMsg = typeof obj.error === "string" ? obj.error : JSON.stringify(obj);
  return {
    ok: false,
    reason: "release_failed",
    message: `stamp-server returned error: ${errMsg}`,
    serverStderr: result.stderr.trim(),
  };
}
