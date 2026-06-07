/**
 * SSH verb: register an "extra" reviewer for a peer-review broadcast (AGT-451).
 *
 * Reachable as `git@<host> stamp-register-extra` with the JSON payload on stdin.
 *
 * This verb is invoked by a listener whose triage decision is `claim_seat: always`
 * when a primary `claim-seat` attempt returns `seats_full`. The extras path records
 * the intent on the server and lets the listener proceed to run + post its review
 * unconditionally (subject only to the daily cost cap). No numbered seat is
 * allocated — this verb only appends an `extras-register` event to the event log.
 *
 * Payload fields (JSON):
 *   patch_id, claimant_fp, base_sha, repo, pubkey, signature
 *
 * Enforcement (mirrors claim-seat / AGT-454 GitHub-blind broker):
 *   a) pubkey-recompute bind: fingerprintFromPem(pubkey) === claimant_fp
 *   b) Ed25519 sig over canonicalSerializePeerPayload(payloadWithoutSig) verified
 *      against the carried pubkey (pure-crypto, zero repo access)
 *   c) claimant fingerprint ≠ requested_by_fp (author exclusion)
 *   d) per-fingerprint rate limit via checkAndConsumeToken — own bucket key
 *      `register-extra` (separate from `claim-seat`) so extras don't starve
 *      primary claims. Override via REGISTER_EXTRA_RATE_CAP env var.
 *
 * Differences from claim-seat:
 *   - Does NOT touch seat_1_holder / seat_2_holder (no numbered seat allocation).
 *   - Does NOT check for self-collision (already_holds_other_seat is a seat-slot
 *     concern; extras are slot-less).
 *   - Appends an `extras-register` row to the event log and returns { ok: true }.
 *
 * Exit codes:
 *   0 — success (or feature-not-configured)
 *   1 — server-side / unexpected error
 *   4 — validation / auth failure
 *   5 — registration rejected (author-exclusion / rate limit exceeded)
 */

import {
  appendEvent,
  checkAndConsumeToken,
  findPatch,
  findUserBySshFingerprint,
  openServerDb,
  touchLastSeen,
} from "../lib/serverDb.js";
import { loadServerEnvFile } from "../lib/serverEnvFile.js";
import { readAuthenticatedPubkey } from "../lib/sshUserAuth.js";
import { canonicalSerializePeerPayload } from "../lib/attestationV4.js";
import {
  notConfiguredResponse,
  resolvePeerReviewLimit,
  resolvePeerReviewsEnabled,
  verifyPeerPayloadSignatureFromPubkey,
  PR_OPENED_RATE_CAP_DEFAULT,
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

interface RegisterExtraPayload {
  patch_id: string;
  claimant_fp: string;
  base_sha: string;
  repo: string;
  /** SPKI PEM of the stamp signing key (AGT-454). Included in canonical signed bytes. */
  pubkey: string;
  signature: string;
}

function parsePayload(raw: Buffer): RegisterExtraPayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch (e) {
    fail(
      `register-extra payload is not valid JSON: ${e instanceof Error ? e.message : String(e)}`,
      4,
    );
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    fail("register-extra payload must be a JSON object", 4);
  }

  const p = parsed as Record<string, unknown>;
  for (const k of ["patch_id", "claimant_fp", "base_sha", "repo", "pubkey", "signature"]) {
    if (typeof p[k] !== "string") fail(`register-extra payload missing or invalid field: ${k}`, 4);
  }

  if (!/^[0-9a-f]{40}$/.test(p["base_sha"] as string))
    fail("base_sha must be a 40-char lowercase hex SHA", 4);

  return p as unknown as RegisterExtraPayload;
}

async function main(): Promise<void> {
  loadServerEnvFile();

  if (!resolvePeerReviewsEnabled()) {
    process.stderr.write(
      "note: STAMP_PEER_REVIEWS_ENABLED is not set; register-extra is a no-op\n",
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

    // Per-fingerprint rate limit on register-extra — own bucket so it doesn't
    // starve the claim-seat bucket. Default matches claim-seat; override via
    // REGISTER_EXTRA_RATE_CAP.
    const registerExtraRateCap = resolvePeerReviewLimit(
      "REGISTER_EXTRA_RATE_CAP",
      PR_OPENED_RATE_CAP_DEFAULT,
    );
    if (!checkAndConsumeToken(db, callerRow.id, "register-extra", registerExtraRateCap)) {
      fail(
        `rate limit exceeded: ${callerRow.short_name} is over the register-extra cap (${registerExtraRateCap}/hour)`,
        5,
      );
    }

    const raw = await readStdin();
    const payload = parsePayload(raw);

    // Validate repo format to prevent path traversal / injection.
    if (!/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(payload.repo)) {
      fail(
        `repo must be <org>/<name> with alphanumeric/dash/dot/underscore only (got ${JSON.stringify(payload.repo)})`,
        4,
      );
    }

    // AGT-454 Auth (GitHub-blind broker, pure-crypto):
    //   1. Recompute fingerprintFromPem(payload.pubkey); reject if ≠ claimant_fp.
    //   2. Verify Ed25519 sig over canonicalSerializePeerPayload(payloadWithoutSig).
    const { signature: _sig, ...payloadWithoutSig } = payload;
    const canonicalBytes = canonicalSerializePeerPayload(payloadWithoutSig);
    const authResult = verifyPeerPayloadSignatureFromPubkey(
      payload.pubkey,
      payload.claimant_fp,
      canonicalBytes,
      payload.signature,
    );
    if (!authResult.ok) {
      fail(`auth failure: ${authResult.reason}`, 4);
    }

    // Author-exclusion: claimant must not be the original PR author.
    // Look up the patch to get the requested_by_fp.
    const patchRow = findPatch(db, payload.patch_id);
    if (patchRow && patchRow.requested_by_fp === payload.claimant_fp) {
      fail(
        `register-extra rejected: author_cannot_review_own_pr (${payload.claimant_fp})`,
        5,
      );
    }

    const now = Date.now();
    appendEvent(
      db,
      payload.patch_id,
      "extras-register",
      payload.claimant_fp,
      { repo: payload.repo },
      now,
    );

    process.stdout.write(
      JSON.stringify({ ok: true, patch_id: payload.patch_id }) + "\n",
    );
  } finally {
    db.close();
  }
}

main().catch((err: unknown) => {
  process.stderr.write(
    `error: register-extra crashed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`,
  );
  process.exit(1);
});
