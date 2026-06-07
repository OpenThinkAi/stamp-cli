/**
 * AGT-451 — Unit tests for the `register-extra` server logic.
 *
 * Tests the core enforcement the server-side `stamp-register-extra` verb
 * applies, driving the DB functions directly (same in-process pattern as
 * peerSim.test.ts) rather than spawning the actual binary.
 *
 * Coverage:
 *   - Happy path: `extras-register` event appended; no seat-slot mutation.
 *   - Auth failure (fp mismatch): `verifyPeerPayloadSignatureFromPubkey` rejects.
 *   - Auth failure (tampered payload): signature fails.
 *   - Author-exclusion: claimant_fp === requested_by_fp → rejected.
 *   - Rate-limit exceeded: `checkAndConsumeToken` returns false after N calls.
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import os from "node:os";
import {
  generateKeyPairSync,
  createHash,
  createPublicKey,
} from "node:crypto";
import { describe, it, before, after } from "node:test";

import {
  openServerDb,
  insertPatch,
  findPatch,
  appendEvent,
  checkAndConsumeToken,
  findPeerReviewEventsAfter,
  maxPeerReviewEventId,
} from "../src/lib/serverDb.ts";
import {
  verifyPeerPayloadSignatureFromPubkey,
  PR_OPENED_RATE_CAP_DEFAULT,
} from "../src/server/peerReviews.ts";
import { canonicalSerializePeerPayload } from "../src/lib/attestationV4.ts";
import { signBytes } from "../src/lib/signing.ts";
import type { DatabaseSync } from "node:sqlite";

// ─── Key generation helpers ──────────────────────────────────────────

interface SimKeypair {
  privateKeyPem: string;
  publicKeyPem: string;
  fp: string;
}

function genKeypair(): SimKeypair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }) as string;
  const spkiDer = createPublicKey(publicKeyPem).export({
    type: "spki",
    format: "der",
  }) as Buffer;
  const fp = "sha256:" + createHash("sha256").update(spkiDer).digest("hex");
  return { privateKeyPem, publicKeyPem, fp };
}

/**
 * Simulate the core register-extra enforcement (the part that runs in the DB
 * layer, extracted from register-extra.ts for in-process testability):
 *
 *   1. Auth: verifyPeerPayloadSignatureFromPubkey
 *   2. Author-exclusion (via findPatch)
 *   3. Rate-limit (checkAndConsumeToken)
 *   4. appendEvent("extras-register", ...)
 *
 * Returns { ok: true } on success; { ok: false, reason } on rejection.
 * exit-code mapping is the subprocess's concern; this tests the logic.
 */
function doRegisterExtra(
  db: DatabaseSync,
  claimantUserId: number,
  payload: {
    patch_id: string;
    claimant_fp: string;
    base_sha: string;
    repo: string;
    pubkey: string;
    signature: string;
  },
  rateCap: number = PR_OPENED_RATE_CAP_DEFAULT,
): { ok: true } | { ok: false; reason: string } {
  // Rate-limit check
  if (!checkAndConsumeToken(db, claimantUserId, "register-extra", rateCap)) {
    return { ok: false, reason: "rate_limit_exceeded" };
  }

  // Auth: pubkey-recompute + sig verify
  const { signature: _sig, ...payloadWithoutSig } = payload;
  const canonicalBytes = canonicalSerializePeerPayload(payloadWithoutSig);
  const authResult = verifyPeerPayloadSignatureFromPubkey(
    payload.pubkey,
    payload.claimant_fp,
    canonicalBytes,
    payload.signature,
  );
  if (!authResult.ok) {
    return { ok: false, reason: `auth_failure: ${authResult.reason}` };
  }

  // Author-exclusion
  const patchRow = findPatch(db, payload.patch_id);
  if (patchRow && patchRow.requested_by_fp === payload.claimant_fp) {
    return { ok: false, reason: "author_cannot_review_own_pr" };
  }

  // Append event (no seat-slot mutation)
  appendEvent(db, payload.patch_id, "extras-register", payload.claimant_fp, {
    repo: payload.repo,
  });

  return { ok: true };
}

// ─── Shared harness ──────────────────────────────────────────────────

interface Harness {
  tmpDir: string;
  db: DatabaseSync;
  author: SimKeypair;
  reviewer: SimKeypair;
  /** Fake user IDs used for rate-limit token buckets. */
  authorUserId: number;
  reviewerUserId: number;
  patchId: string;
  repo: string;
}

let harness: Harness;

before(() => {
  const tmpDir = mkdtempSync(join(os.tmpdir(), "stamp-server-register-extra-test-"));
  const db = openServerDb({ path: join(tmpDir, "stamp.db") });

  const author = genKeypair();
  const reviewer = genKeypair();

  // Fake user IDs — the real server resolves these from the membership DB;
  // here we use arbitrary integers (rate-limit token buckets are keyed by id).
  const authorUserId = 1;
  const reviewerUserId = 2;

  const patchId = "a".repeat(40);
  const repo = "acme/widget";

  // Insert a patch row so findPatch returns a known requested_by_fp.
  insertPatch(db, {
    patch_id: patchId,
    requested_by_fp: author.fp,
    base_sha: "b".repeat(40),
    head_sha: "c".repeat(40),
    repo,
    pr_url: "https://github.com/acme/widget/pull/1",
  });

  harness = { tmpDir, db, author, reviewer, authorUserId, reviewerUserId, patchId, repo };
});

after(() => {
  harness.db.close();
  rmSync(harness.tmpDir, { recursive: true, force: true });
});

// ─── Happy path ──────────────────────────────────────────────────────

describe("register-extra server logic: happy path", () => {
  it("appends an extras-register event to the log, returns ok: true", () => {
    const { db, reviewer, reviewerUserId, patchId, repo } = harness;

    const beforeMaxId = maxPeerReviewEventId(db);
    const payloadBody = {
      patch_id: patchId,
      claimant_fp: reviewer.fp,
      base_sha: "b".repeat(40),
      repo,
      pubkey: reviewer.publicKeyPem,
    };
    const canonicalBytes = canonicalSerializePeerPayload(payloadBody);
    const signature = signBytes(reviewer.privateKeyPem, canonicalBytes);

    const result = doRegisterExtra(db, reviewerUserId, {
      ...payloadBody,
      signature,
    });
    assert.ok(result.ok, `expected ok: true; got: ${JSON.stringify(result)}`);

    // Exactly one new event row, with event_type = "extras-register".
    const events = findPeerReviewEventsAfter(db, beforeMaxId);
    assert.equal(events.length, 1, "should append exactly one event");
    assert.equal(events[0]!.event_type, "extras-register");
    assert.equal(events[0]!.actor_fp, reviewer.fp);
  });

  it("does NOT mutate seat_1_holder or seat_2_holder on the patch row", () => {
    const { db, patchId } = harness;

    // Read patch row — seat columns should remain null.
    const patchRow = findPatch(db, patchId);
    assert.ok(patchRow !== null, "patch row should exist");
    assert.equal(patchRow!.seat_1_holder, null, "seat_1_holder should not be set");
    assert.equal(patchRow!.seat_2_holder, null, "seat_2_holder should not be set");
  });
});

// ─── Auth failure: fp mismatch ───────────────────────────────────────

describe("register-extra server logic: auth failure (fp mismatch)", () => {
  it("rejects when claimed fp does not match sha256(SPKI-DER) of pubkey", () => {
    const { db, reviewer, reviewerUserId, patchId, repo } = harness;
    const impostor = genKeypair();

    const payloadBody = {
      patch_id: patchId,
      // Claim impostor's fp but provide reviewer's pubkey → mismatch.
      claimant_fp: impostor.fp,
      base_sha: "b".repeat(40),
      repo,
      pubkey: reviewer.publicKeyPem,
    };
    const canonicalBytes = canonicalSerializePeerPayload(payloadBody);
    const signature = signBytes(reviewer.privateKeyPem, canonicalBytes);

    const result = doRegisterExtra(db, reviewerUserId, {
      ...payloadBody,
      signature,
    });
    assert.ok(!result.ok, "should reject fp mismatch");
    assert.ok(
      result.ok === false && result.reason.includes("auth_failure"),
      `expected auth_failure; got: ${JSON.stringify(result)}`,
    );
  });
});

// ─── Auth failure: tampered payload ─────────────────────────────────

describe("register-extra server logic: auth failure (tampered payload)", () => {
  it("rejects a tampered payload (signature no longer valid)", () => {
    const { db, reviewer, reviewerUserId, patchId, repo } = harness;

    const payloadBody = {
      patch_id: patchId,
      claimant_fp: reviewer.fp,
      base_sha: "b".repeat(40),
      repo,
      pubkey: reviewer.publicKeyPem,
    };
    const canonicalBytes = canonicalSerializePeerPayload(payloadBody);
    const signature = signBytes(reviewer.privateKeyPem, canonicalBytes);

    // Tamper: change the repo field after signing.
    const result = doRegisterExtra(db, reviewerUserId, {
      ...payloadBody,
      repo: "tampered/repo",
      signature,
    });
    assert.ok(!result.ok, "should reject tampered payload");
    assert.ok(
      result.ok === false && result.reason.includes("auth_failure"),
      `expected auth_failure; got: ${JSON.stringify(result)}`,
    );
  });
});

// ─── Author-exclusion ────────────────────────────────────────────────

describe("register-extra server logic: author-exclusion", () => {
  it("rejects when claimant_fp === requested_by_fp (the PR author)", () => {
    const { db, author, authorUserId, patchId, repo } = harness;

    // The patch's requested_by_fp is author.fp — they cannot register as extra.
    const payloadBody = {
      patch_id: patchId,
      claimant_fp: author.fp,
      base_sha: "b".repeat(40),
      repo,
      pubkey: author.publicKeyPem,
    };
    const canonicalBytes = canonicalSerializePeerPayload(payloadBody);
    const signature = signBytes(author.privateKeyPem, canonicalBytes);

    const result = doRegisterExtra(db, authorUserId, {
      ...payloadBody,
      signature,
    });
    assert.ok(!result.ok, "should reject author registering as extra for own PR");
    assert.ok(
      result.ok === false && result.reason === "author_cannot_review_own_pr",
      `expected author_cannot_review_own_pr; got: ${JSON.stringify(result)}`,
    );
  });
});

// ─── Rate-limit exceeded ─────────────────────────────────────────────

describe("register-extra server logic: rate-limit exceeded", () => {
  it("rejects when rate cap is exceeded (cap=1, second call rejected)", () => {
    const { db, patchId, repo } = harness;

    // Fresh keypair so we don't collide with happy-path's rate-limit state.
    const freshReviewer = genKeypair();
    const freshUserId = 99;

    const payloadBody = {
      patch_id: patchId,
      claimant_fp: freshReviewer.fp,
      base_sha: "b".repeat(40),
      repo,
      pubkey: freshReviewer.publicKeyPem,
    };
    const canonicalBytes = canonicalSerializePeerPayload(payloadBody);
    const signature = signBytes(freshReviewer.privateKeyPem, canonicalBytes);
    const payload = { ...payloadBody, signature };

    // First call should succeed (cap=1).
    const first = doRegisterExtra(db, freshUserId, payload, 1);
    assert.ok(first.ok, `first call should succeed; got: ${JSON.stringify(first)}`);

    // Second call should hit the rate limit.
    const second = doRegisterExtra(db, freshUserId, payload, 1);
    assert.ok(!second.ok, "second call should be rate-limited");
    assert.ok(
      second.ok === false && second.reason === "rate_limit_exceeded",
      `expected rate_limit_exceeded; got: ${JSON.stringify(second)}`,
    );
  });
});
