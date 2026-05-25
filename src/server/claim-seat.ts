/**
 * SSH verb: claim a reviewer seat for a peer-review broadcast (AGT-427/AGT-454).
 *
 * Reachable as `git@<host> claim-seat` with the JSON payload on stdin.
 *
 * Payload fields (JSON):
 *   patch_id, claimant_fp, base_sha, repo, pubkey, signature
 *
 * Enforcement (AGT-454 GitHub-blind broker):
 *   a) pubkey-recompute bind: fingerprintFromPem(pubkey) === claimant_fp
 *   b) Ed25519 sig over canonicalSerializePeerPayload(payloadWithoutSig) verified
 *      against the carried pubkey (pure-crypto, zero repo access)
 *   c) claimant fingerprint ≠ requested_by_fp (author exclusion → author_cannot_claim_own_pr)
 *   d) claimant fingerprint ≠ the other seat-holder (self-collision → already_holds_other_seat)
 *   e) fewer than two seats taken → seat number returned; both taken → seats_full
 *   f) per-fingerprint rate limit via checkAndConsumeToken (seat-squat mitigation, §4a)
 *
 * Operator-ness @ base_sha is NOT checked server-side — that is the listener's
 * responsibility (client-side, against its own local clone).
 *
 * Exit codes:
 *   0 — success (or feature-not-configured)
 *   1 — server-side / unexpected error
 *   4 — validation / auth failure
 *   5 — seat claim rejected (author-exclusion / self-collision / seats-full / rate limit exceeded)
 */

import {
  appendEvent,
  checkAndConsumeToken,
  claimSeatTx,
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

interface ClaimSeatPayload {
  patch_id: string;
  claimant_fp: string;
  base_sha: string;
  repo: string;
  /** SPKI PEM of the stamp signing key (AGT-454). Included in canonical signed bytes. */
  pubkey: string;
  signature: string;
}

function parsePayload(raw: Buffer): ClaimSeatPayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch (e) {
    fail(`claim-seat payload is not valid JSON: ${e instanceof Error ? e.message : String(e)}`, 4);
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    fail("claim-seat payload must be a JSON object", 4);
  }

  const p = parsed as Record<string, unknown>;
  for (const k of ["patch_id", "claimant_fp", "base_sha", "repo", "pubkey", "signature"]) {
    if (typeof p[k] !== "string") fail(`claim-seat payload missing or invalid field: ${k}`, 4);
  }

  if (!/^[0-9a-f]{40}$/.test(p["base_sha"] as string))
    fail("base_sha must be a 40-char lowercase hex SHA", 4);

  return p as unknown as ClaimSeatPayload;
}

async function main(): Promise<void> {
  loadServerEnvFile();

  if (!resolvePeerReviewsEnabled()) {
    process.stderr.write(
      "note: STAMP_PEER_REVIEWS_ENABLED is not set; claim-seat is a no-op\n",
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

    // AGT-454 §4a: per-fingerprint rate limit on claim-seat (seat-squat mitigation).
    const claimSeatRateCap = resolvePeerReviewLimit("CLAIM_SEAT_RATE_CAP", PR_OPENED_RATE_CAP_DEFAULT);
    if (!checkAndConsumeToken(db, callerRow.id, "claim-seat", claimSeatRateCap)) {
      fail(
        `rate limit exceeded: ${callerRow.short_name} is over the claim-seat cap (${claimSeatRateCap}/hour)`,
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
    // Operator-ness is verified client-side; author-exclusion/self-collision/seat-full
    // remain fingerprint-only in claimSeatTx.
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

    const now = Date.now();
    const result = claimSeatTx(db, payload.patch_id, payload.claimant_fp, now);

    if (!result.ok) {
      fail(
        `claim rejected: ${result.error}`,
        5,
      );
    }

    appendEvent(db, payload.patch_id, "claim-seat", payload.claimant_fp, {
      seat: result.seat,
      repo: payload.repo,
    }, now);

    process.stdout.write(
      JSON.stringify({ ok: true, seat: result.seat, patch_id: payload.patch_id }) + "\n",
    );
  } finally {
    db.close();
  }
}

main().catch((err: unknown) => {
  process.stderr.write(
    `error: claim-seat crashed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`,
  );
  process.exit(1);
});
