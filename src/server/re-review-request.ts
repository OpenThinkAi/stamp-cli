/**
 * SSH verb: request a re-review of a previously broadcast PR (AGT-427/AGT-431).
 *
 * Only the original PR author (`requested_by_fp`) may call this verb.
 * Fans out a `re-review-requested` event to the active listeners that
 * currently hold seats for the patch. Appends an event log row.
 * Returns success even when no seat-holders are currently active.
 *
 * Payload fields (JSON):
 *   patch_id, requester_fp, reviewer_filter (optional string[]), signature
 *
 * `reviewer_filter` is a list of short_names (e.g. ["alice", "bob"]). The
 * server resolves them to fingerprints server-side via `findUserByShortName`
 * (DB already open here). An empty or absent array means "ping all
 * seat-holders". Unknown names are silently skipped (emit a stderr note).
 *
 * The `re-review-requested` event delivered to each listener contains
 * the richer AC-8 payload: patch_id, requested_by_fp, pr_url, repo, seat.
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
  findUserByShortName,
  openServerDb,
  touchLastSeen,
} from "../lib/serverDb.js";
import { loadServerEnvFile } from "../lib/serverEnvFile.js";
import { readAuthenticatedPubkey } from "../lib/sshUserAuth.js";

import { canonicalSerializePeerPayload } from "../lib/attestationV4.js";
import {
  fanoutToSeatHoldersFiltered,
  notConfiguredResponse,
  resolvePeerReviewsEnabled,
  verifyPeerPayloadSignatureFromPubkey,
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
  /** Optional list of reviewer short_names (resolved server-side to fps). */
  reviewer_filter?: string[];
  /** SPKI PEM of the stamp signing key (AGT-454). Included in canonical signed bytes. */
  pubkey: string;
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
  for (const k of ["patch_id", "requester_fp", "pubkey", "signature"]) {
    if (typeof p[k] !== "string") fail(`re-review-request payload missing or invalid field: ${k}`, 4);
  }

  // reviewer_filter is optional; validate as array-of-strings if present.
  if ("reviewer_filter" in p) {
    if (!Array.isArray(p["reviewer_filter"]) || !p["reviewer_filter"].every((x) => typeof x === "string")) {
      fail("reviewer_filter must be an array of strings when present", 4);
    }
  }

  return p as unknown as ReReviewPayload;
}

async function main(): Promise<void> {
  loadServerEnvFile();

  if (!resolvePeerReviewsEnabled()) {
    process.stderr.write(
      "note: STAMP_PEER_REVIEWS_ENABLED is not set; re-review-request is a no-op\n",
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

    // AGT-454 Auth (GitHub-blind broker, pure-crypto):
    //   1. Recompute fingerprintFromPem(payload.pubkey); reject if ≠ requester_fp.
    //   2. Verify Ed25519 sig over canonicalSerializePeerPayload(payloadWithoutSig).
    // Author-identity check (requester_fp === original requested_by_fp) remains DB-based below.
    const { signature: _sig, ...payloadWithoutSig } = payload;
    const canonicalBytes = canonicalSerializePeerPayload(payloadWithoutSig);
    const authResult = verifyPeerPayloadSignatureFromPubkey(
      payload.pubkey,
      payload.requester_fp,
      canonicalBytes,
      payload.signature,
    );
    if (!authResult.ok) {
      fail(`auth failure: ${authResult.reason}`, 4);
    }

    const patch = findPatch(db, payload.patch_id);
    if (!patch) {
      fail(`patch ${payload.patch_id} not found`, 4);
    }

    // Only the original author may request a re-review.
    if (payload.requester_fp !== patch.requested_by_fp) {
      fail(
        `requester_fp ${payload.requester_fp} is not the original author ` +
          `(requested_by_fp=${patch.requested_by_fp}) — re-review request refused`,
        5,
      );
    }

    // Resolve reviewer_filter: short_names → fingerprints (server-side, DB already open).
    // AC-3/7: the CLI forwards raw --reviewer names; we resolve them here.
    let resolvedFilter: string[] = [];
    const rawFilter = payload.reviewer_filter ?? [];
    if (rawFilter.length > 0) {
      for (const name of rawFilter) {
        const userRow = findUserByShortName(db, name);
        if (userRow) {
          resolvedFilter.push(userRow.ssh_fp);
        } else {
          process.stderr.write(`note: reviewer_filter name "${name}" not found in membership DB; skipping\n`);
        }
      }
      // Fail-safe: if a non-empty filter was requested but ALL names failed to
      // resolve, delivering to everyone would violate least-privilege — the
      // caller intended a restricted ping but got a broadcast. Treat this as
      // "notify nobody" rather than silently expanding to all seat-holders.
      if (resolvedFilter.length === 0) {
        process.stderr.write(
          `note: none of the supplied reviewer_filter names resolved to a known user; no seat-holders notified\n`,
        );
        process.stdout.write(
          JSON.stringify({
            ok: true,
            patch_id: payload.patch_id,
            seat_holders_notified: 0,
            note: "no reviewer_filter names resolved; no seat-holders notified",
          }) + "\n",
        );
        process.exit(0);
      }
    }
    // Empty resolvedFilter (rawFilter was empty) → no filter applied (all seat-holders notified).

    // Build the seat map for the two seats with per-seat metadata.
    const seatMap: Array<{ fp: string; seat: 1 | 2 }> = [];
    if (patch.seat_1_holder) seatMap.push({ fp: patch.seat_1_holder, seat: 1 });
    if (patch.seat_2_holder) seatMap.push({ fp: patch.seat_2_holder, seat: 2 });

    const now = Date.now();

    // Build the richer AC-8 event payload.
    const eventPayload = {
      patch_id: payload.patch_id,
      requested_by_fp: payload.requester_fp,
      pr_url: patch.pr_url ?? null,
      repo: patch.repo,
    };

    // Fan out to active seat-holders with optional filter.
    const notified = fanoutToSeatHoldersFiltered(
      seatMap,
      {
        event_type: "re-review-requested",
        patch_id: payload.patch_id,
        actor_fp: payload.requester_fp,
        payload: eventPayload,
      },
      resolvedFilter,
    );

    appendEvent(
      db,
      payload.patch_id,
      "re-review-requested",
      payload.requester_fp,
      { notified_fps: notified, reviewer_filter: rawFilter },
      now,
    );

    if (notified.length === 0) {
      process.stderr.write(
        `note: no active seat-holders to notify for patch ${payload.patch_id}\n`,
      );
    }

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
