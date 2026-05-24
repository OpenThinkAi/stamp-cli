/**
 * SSH verb: heartbeat for a held reviewer seat (AGT-427).
 *
 * Refreshes `seat_N_claimed_at` timestamp so the seat-TTL sweep (a future
 * ticket) knows the holder is still active. Returns 404 if the caller
 * holds no seat for the given patch.
 *
 * Payload fields (JSON):
 *   patch_id, claimant_fp, signature
 *
 * Exit codes:
 *   0 — success (or feature-not-configured)
 *   1 — server-side / unexpected error
 *   4 — validation / auth failure or 404 (no seat held)
 */

import {
  appendEvent,
  findUserBySshFingerprint,
  openServerDb,
  touchHeartbeat,
  touchLastSeen,
} from "../lib/serverDb.js";
import { loadServerEnvFile } from "../lib/serverEnvFile.js";
import { readAuthenticatedPubkey } from "../lib/sshUserAuth.js";

import {
  notConfiguredResponse,
  resolvePeerReviewsEnabled,
} from "./peerReviews.js";

function fail(message: string, exitCode: number): never {
  process.stderr.write(`error: ${message}\n`);
  process.exit(exitCode);
}

async function readStdin(): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk, "utf8") : (chunk as Buffer));
  }
  return Buffer.concat(chunks);
}

interface HeartbeatPayload {
  patch_id: string;
  claimant_fp: string;
  signature: string;
}

function parsePayload(raw: Buffer): HeartbeatPayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch (e) {
    fail(`heartbeat payload is not valid JSON: ${e instanceof Error ? e.message : String(e)}`, 4);
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    fail("heartbeat payload must be a JSON object", 4);
  }

  const p = parsed as Record<string, unknown>;
  for (const k of ["patch_id", "claimant_fp", "signature"]) {
    if (typeof p[k] !== "string") fail(`heartbeat payload missing or invalid field: ${k}`, 4);
  }

  return p as unknown as HeartbeatPayload;
}

async function main(): Promise<void> {
  loadServerEnvFile();

  if (!resolvePeerReviewsEnabled()) {
    process.stderr.write(
      "info: STAMP_PEER_REVIEWS_ENABLED is not set; heartbeat is a no-op\n",
    );
    process.stdout.write(notConfiguredResponse() + "\n");
    process.exit(0);
  }

  const caller = readAuthenticatedPubkey();
  if (!caller) {
    fail(
      "could not determine authenticated identity (SSH_USER_AUTH unset or " +
        "has no publickey entry). Server may be missing 'ExposeAuthInfo yes' " +
        "in sshd_config.",
      1,
    );
  }

  const db = openServerDb({ skipChmod: true });
  try {
    const callerRow = findUserBySshFingerprint(db, caller.fingerprint);
    if (!callerRow) {
      fail(`caller fingerprint ${caller.fingerprint} is not in the membership DB`, 1);
    }
    touchLastSeen(db, callerRow.id);

    const raw = await readStdin();
    const payload = parsePayload(raw);

    const now = Date.now();
    const seat = touchHeartbeat(db, payload.patch_id, payload.claimant_fp, now);

    if (seat === null) {
      fail(
        `404: ${payload.claimant_fp} holds no seat for patch ${payload.patch_id}`,
        4,
      );
    }

    appendEvent(db, payload.patch_id, "heartbeat", payload.claimant_fp, {
      seat,
    }, now);

    process.stdout.write(
      JSON.stringify({ ok: true, seat, patch_id: payload.patch_id }) + "\n",
    );
  } finally {
    db.close();
  }
}

main().catch((err: unknown) => {
  process.stderr.write(
    `error: heartbeat crashed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`,
  );
  process.exit(1);
});
