/**
 * SSH verb: release a held reviewer seat (AGT-427).
 *
 * Reachable as `git@<host> release-seat` with the JSON payload on stdin.
 *
 * Payload fields (JSON):
 *   patch_id, claimant_fp, signature
 *
 * Verifies the caller's SSH fingerprint; clears the matching seat column
 * in `peer_review_patches`; appends a `release-seat` event row.
 *
 * Exit codes:
 *   0 — success (or feature-not-configured)
 *   1 — server-side / unexpected error
 *   4 — validation / auth failure
 */

import {
  appendEvent,
  findUserBySshFingerprint,
  openServerDb,
  releaseSeat,
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

interface ReleaseSeatPayload {
  patch_id: string;
  claimant_fp: string;
  signature: string;
}

function parsePayload(raw: Buffer): ReleaseSeatPayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch (e) {
    fail(`release-seat payload is not valid JSON: ${e instanceof Error ? e.message : String(e)}`, 4);
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    fail("release-seat payload must be a JSON object", 4);
  }

  const p = parsed as Record<string, unknown>;
  for (const k of ["patch_id", "claimant_fp", "signature"]) {
    if (typeof p[k] !== "string") fail(`release-seat payload missing or invalid field: ${k}`, 4);
  }

  return p as unknown as ReleaseSeatPayload;
}

async function main(): Promise<void> {
  loadServerEnvFile();

  if (!resolvePeerReviewsEnabled()) {
    process.stderr.write(
      "note: STAMP_PEER_REVIEWS_ENABLED is not set; release-seat is a no-op\n",
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

    // Security: bind the payload fingerprint to the SSH-authenticated caller.
    if (payload.claimant_fp !== caller.fingerprint) {
      fail(
        `claimant_fp in payload (${payload.claimant_fp}) does not match ` +
          `the SSH-authenticated caller's fingerprint (${caller.fingerprint})`,
        4,
      );
    }

    const now = Date.now();
    const released = releaseSeat(db, payload.patch_id, payload.claimant_fp);

    appendEvent(db, payload.patch_id, "release-seat", payload.claimant_fp, {
      released,
    }, now);

    process.stdout.write(
      JSON.stringify({ ok: true, released, patch_id: payload.patch_id }) + "\n",
    );
  } finally {
    db.close();
  }
}

main().catch((err: unknown) => {
  process.stderr.write(
    `error: release-seat crashed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`,
  );
  process.exit(1);
});
