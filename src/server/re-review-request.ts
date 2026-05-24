/**
 * SSH verb: request a re-review of a previously broadcast PR (AGT-427).
 *
 * Only the original PR author (`requested_by_fp`) may call this verb.
 * Fans out a `re-review-requested` event to the active listeners that
 * currently hold seats for the patch. Appends an event log row.
 * Returns success even when no seat-holders are currently active.
 *
 * Payload fields (JSON):
 *   patch_id, requester_fp, signature
 *
 * Exit codes:
 *   0 — success (or feature-not-configured)
 *   1 — server-side / unexpected error
 *   4 — patch not found or payload validation failure
 *   5 — caller is not the original author (403)
 */

import {
  appendEvent,
  findPatch,
  findUserBySshFingerprint,
  openServerDb,
  touchLastSeen,
} from "../lib/serverDb.js";
import { loadServerEnvFile } from "../lib/serverEnvFile.js";
import { readAuthenticatedPubkey } from "../lib/sshUserAuth.js";

import {
  fanoutToSeatHolders,
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

interface ReReviewPayload {
  patch_id: string;
  requester_fp: string;
  signature: string;
}

function parsePayload(raw: Buffer): ReReviewPayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch (e) {
    fail(`re-review-request payload is not valid JSON: ${e instanceof Error ? e.message : String(e)}`, 4);
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    fail("re-review-request payload must be a JSON object", 4);
  }

  const p = parsed as Record<string, unknown>;
  for (const k of ["patch_id", "requester_fp", "signature"]) {
    if (typeof p[k] !== "string") fail(`re-review-request payload missing or invalid field: ${k}`, 4);
  }

  return p as unknown as ReReviewPayload;
}

async function main(): Promise<void> {
  loadServerEnvFile();

  if (!resolvePeerReviewsEnabled()) {
    process.stderr.write(
      "info: STAMP_PEER_REVIEWS_ENABLED is not set; re-review-request is a no-op\n",
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

    const patch = findPatch(db, payload.patch_id);
    if (!patch) {
      fail(`404: patch ${payload.patch_id} not found`, 4);
    }

    // Only the original author may request a re-review.
    if (payload.requester_fp !== patch.requested_by_fp) {
      fail(
        `403: requester_fp ${payload.requester_fp} is not the original author ` +
          `(requested_by_fp=${patch.requested_by_fp}) — re-review request refused`,
        5,
      );
    }

    const now = Date.now();
    const event = {
      event_type: "re-review-requested",
      patch_id: payload.patch_id,
      actor_fp: payload.requester_fp,
      payload: { patch_id: payload.patch_id, requester_fp: payload.requester_fp },
    };

    // Fan out to active seat-holders (in-process stub; see peerReviews.ts).
    const notified = fanoutToSeatHolders(
      [patch.seat_1_holder, patch.seat_2_holder],
      event,
    );

    appendEvent(
      db,
      payload.patch_id,
      "re-review-requested",
      payload.requester_fp,
      { notified_fps: notified },
      now,
    );

    process.stdout.write(
      JSON.stringify({
        ok: true,
        patch_id: payload.patch_id,
        seat_holders_notified: notified.length,
        note: notified.length === 0 ? "no active seat-holders to notify" : undefined,
      }) + "\n",
    );
  } finally {
    db.close();
  }
}

main().catch((err: unknown) => {
  process.stderr.write(
    `error: re-review-request crashed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`,
  );
  process.exit(1);
});
