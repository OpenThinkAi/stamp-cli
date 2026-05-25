/**
 * Client-side SSH transport for the `pr-opened` server verb (AGT-428).
 *
 * The wire counterpart of `src/server/pr-opened.ts` (AGT-427): the author
 * invokes `stamp pr open <branch>` which, after a successful `git push` +
 * `gh pr create`, calls `broadcastPrOpened` to deliver a signed JSON payload
 * to the stamp-server's `pr-opened` SSH verb.
 *
 *   client                                  server (AGT-427)
 *     │                                       │
 *     ├─ spawn ssh -p <port> -- user@host     │
 *     │   pr-opened                           │
 *     ├──────── JSON payload on stdin ──────→ │
 *     │                                       │  readBoundedStdin → parsePayload
 *     │                                       │  → verifyOperatorAtBase
 *     │                                       │  → insertPatch + appendEvent
 *     │                                       │  → fanoutEvent
 *     │                                       │  → JSON on stdout
 *     │ ←─── { ok: true, patch_id } ────────  │
 *     │   OR { ok: false, error: "..." }       │
 *     │                                       │
 *
 * Design knobs settled at this layer (mirrors sshReviewClient.ts conventions):
 *
 *   1. **Subprocess `ssh`, not a Node SSH library.** Same rationale as
 *      `sshReviewClient.ts` — the operator already has SSH configured.
 *
 *   2. **JSON payload via stdin.** The server's `readBoundedStdin` reads
 *      up to `MAX_PR_OPENED_BODY_BYTES` and then parses. We write the
 *      JSON once and close stdin.
 *
 *   3. **Signature coverage.** The client signs the canonical
 *      `PrOpenedPayloadBody` (all fields excluding `signature`) using
 *      `canonicalSerializePrOpened` from `attestationV4.ts`. The server
 *      currently does NOT verify this signature (it relies on SSH identity
 *      binding via `requested_by_fp === caller.fingerprint`); the signature
 *      is included per AC #7 so a future verifier (AGT-434 WS transport)
 *      can verify it without a protocol change.
 *
 *   4. **`peer_reviews_not_configured` → informational, exit 0.** When the
 *      server has `STAMP_PEER_REVIEWS_ENABLED` unset, it returns
 *      `{ ok: false, error: "peer_reviews_not_configured" }` and exits 0.
 *      The client surfaces this as an informational note to stderr — not a
 *      hard failure — per AC #8.
 *
 *   5. **`_sshSpawnForTest` injection seam.** Production callers leave this
 *      `undefined` and the real `ssh` binary runs; tests inject a fake.
 *      Same pattern as `sshReviewClient.ts`.
 */

import { spawn } from "node:child_process";
import type { ServerConfig } from "./serverConfig.js";
import { PEER_SSH_VERBS } from "./peerSshVerbs.js";

export type { ServerConfig };

// ─── SSH spawn seam ─────────────────────────────────────────────────

export interface SshSpawnResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
}

/** Test-only injection seam: replace the real ssh subprocess with a fake.
 *  Same shape as `SshSpawnFn` in `sshReviewClient.ts`. */
export type SshSpawnFn = (
  cfg: ServerConfig,
  payload: string,
) => Promise<SshSpawnResult>;

async function defaultSshSpawn(
  cfg: ServerConfig,
  payload: string,
): Promise<SshSpawnResult> {
  // ssh argv: `-p <port> -- user@host stamp-pr-opened`
  // The `--` is the canonical guard against hostile option interpolation.
  const sshArgv = ["-p", String(cfg.port), "--", `${cfg.user}@${cfg.host}`, PEER_SSH_VERBS.prOpened];

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
          `failed to spawn ssh for stamp-server ${cfg.user}@${cfg.host}:${cfg.port}: ${err.message}`,
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
      // EPIPE: server closed before reading all stdin. Reject early.
      rejectPromise(
        new Error(
          `failed to write payload to ssh stdin for ${cfg.user}@${cfg.host}:${cfg.port}: ${err.message}`,
        ),
      );
    });
    child.stdin.write(payload, "utf8");
    child.stdin.end();
  });
}

// ─── Response types ──────────────────────────────────────────────────

/** Successful broadcast: server persisted the patch and fanned out. */
export interface BroadcastSuccess {
  ok: true;
  patch_id: string;
}

/** Server returned `peer_reviews_not_configured` — not an error. */
export interface BroadcastNotConfigured {
  ok: false;
  reason: "peer_reviews_not_configured";
}

/** Broadcast failed: transport error, non-zero exit, or other server error. */
export interface BroadcastFailure {
  ok: false;
  reason: "broadcast_failed";
  /** Operator-facing description of the failure. */
  message: string;
  /** Raw server stderr (verbatim), if any. */
  serverStderr: string;
}

export type BroadcastResult =
  | BroadcastSuccess
  | BroadcastNotConfigured
  | BroadcastFailure;

// ─── Public entrypoint ───────────────────────────────────────────────

export interface BroadcastPrOpenedInput {
  /** Full JSON payload to send (already signed). */
  payloadJson: string;
  /** Resolved server config (`loadServerConfig()` result or override). */
  serverConfig: ServerConfig;
  /** Test-only injection seam. Leave `undefined` in production. */
  _sshSpawnForTest?: SshSpawnFn;
}

/**
 * Deliver the signed `pr-opened` payload to the stamp-server over SSH.
 *
 * Returns a discriminated `BroadcastResult`:
 *   - `{ ok: true, patch_id }` — success
 *   - `{ ok: false, reason: "peer_reviews_not_configured" }` — informational
 *   - `{ ok: false, reason: "broadcast_failed", message, serverStderr }` — error
 *
 * Never throws — the caller translates the result into exit-code semantics.
 */
export async function broadcastPrOpened(
  input: BroadcastPrOpenedInput,
): Promise<BroadcastResult> {
  const spawnFn = input._sshSpawnForTest ?? defaultSshSpawn;

  let result: SshSpawnResult;
  try {
    result = await spawnFn(input.serverConfig, input.payloadJson);
  } catch (err) {
    return {
      ok: false,
      reason: "broadcast_failed",
      message: `ssh spawn failed: ${err instanceof Error ? err.message : String(err)}`,
      serverStderr: "",
    };
  }

  if (result.exitCode !== 0) {
    // Map the verb's documented exit codes (AGT-427: 1=server-error,
    // 4=request-validation, 5=rate-limit) to operator-readable prose.
    // Surface the server's stderr verbatim (same pattern as sshReviewClient
    // exitCodeHint) so a rate-limit (server exit 5) is legible even though
    // the client collapses every broadcast failure to client exit 4.
    const stderr = result.stderr.trim();
    const hint = exitCodeHint(result.exitCode);
    const signalNote = result.signal ? ` (killed by signal ${result.signal})` : "";
    return {
      ok: false,
      reason: "broadcast_failed",
      message:
        `stamp-server pr-opened returned exit ${result.exitCode}${signalNote}. ` +
        `hint: ${hint}` +
        (stderr ? `\n  server stderr:\n    ${stderr.split("\n").join("\n    ")}` : ""),
      serverStderr: stderr,
    };
  }

  // Parse the server's JSON response from stdout.
  let parsed: unknown;
  try {
    parsed = JSON.parse(result.stdout.trim());
  } catch {
    return {
      ok: false,
      reason: "broadcast_failed",
      message: `stamp-server returned malformed JSON: ${JSON.stringify(result.stdout.slice(0, 200))}`,
      serverStderr: result.stderr.trim(),
    };
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return {
      ok: false,
      reason: "broadcast_failed",
      message: `stamp-server response must be a JSON object (got ${typeof parsed})`,
      serverStderr: result.stderr.trim(),
    };
  }

  const obj = parsed as Record<string, unknown>;

  // AC #8: `peer_reviews_not_configured` is an informational exit — not a failure.
  if (obj.ok === false && obj.error === "peer_reviews_not_configured") {
    return { ok: false, reason: "peer_reviews_not_configured" };
  }

  if (obj.ok === true) {
    if (typeof obj.patch_id !== "string") {
      return {
        ok: false,
        reason: "broadcast_failed",
        message: `stamp-server response ok=true but patch_id is missing or not a string`,
        serverStderr: result.stderr.trim(),
      };
    }
    return { ok: true, patch_id: obj.patch_id };
  }

  // Any other ok:false (e.g. validation error from the server).
  const errMsg = typeof obj.error === "string" ? obj.error : JSON.stringify(obj);
  return {
    ok: false,
    reason: "broadcast_failed",
    message: `stamp-server returned error: ${errMsg}`,
    serverStderr: result.stderr.trim(),
  };
}


function exitCodeHint(exitCode: number | null): string {
  switch (exitCode) {
    case 1:
      return "server-side error (check the server logs).";
    case 4:
      return "request validation failure (oversize payload, bad shape, auth failure, or excess paths).";
    case 5:
      return "rate limited — you're over the server's pr-opened cap. Back off and retry later.";
    default:
      return `unrecognized exit code ${exitCode} — surface the stderr verbatim and check the server logs.`;
  }
}
