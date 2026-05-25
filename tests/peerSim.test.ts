/**
 * AGT-454 — Peer-agentic review simulation (rewritten for real topology).
 *
 * Drives the complete seat protocol and event-fanout path on one machine
 * using multiple Ed25519 keypairs against an in-process DB.
 *
 * Architecture: the loop is a hybrid transport.
 *   - Seat protocol (claim semantics) → `claimSeatTx` called directly on
 *     the in-process DB. The SSH-verb subprocess path is the production
 *     delivery mechanism, but its seat enforcement is entirely in
 *     `claimSeatTx` (see src/lib/serverDb.ts). Driving that function
 *     directly covers the AC5 assertions without the subprocess/SSH-auth
 *     complexity.
 *   - Event fanout → `fanoutToSeatHolders` / `registerListener` in-process.
 *   - Cost-cap + prListen loop → `prListen.ts` in-process via the
 *     `_eventQueueForTest` + `_sshSpawnForTest` seams.
 *
 * AGT-454 CHANGES FROM AGT-433:
 *   - DELETED: STAMP_BARE_REPOS_DIR / bareRepoPath describe block — function removed.
 *   - KEPT: AC5 claimSeatTx enforcement block.
 *   - KEPT: fanoutToSeatHolders block.
 *   - KEPT: cost-cap enforcement block.
 *   - ADDED: server-crypto describe block (accept-valid / reject-fp-mismatch /
 *            reject-tamper / reject-pubkey-swap) exercising the new
 *            `verifyPeerPayloadSignatureFromPubkey`.
 *   - ADDED: client-operator describe block using a real tmp git repo fixture
 *            with a committed manifest.yml at a real base_sha, exercising
 *            `verifyOperatorAtBaseLocal`.
 */

import { strict as assert } from "node:assert";
import { describe, it, before, after } from "node:test";
import {
  mkdtempSync,
  mkdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import os from "node:os";
import {
  generateKeyPairSync,
  createHash,
  createPublicKey,
} from "node:crypto";
import { spawnSync } from "node:child_process";

import {
  insertPatch,
  openServerDb,
  claimSeatTx,
} from "../src/lib/serverDb.ts";
import {
  fanoutToSeatHolders,
  registerListener,
  unregisterListener,
  clearListenerRegistry,
  type PeerReviewEvent,
} from "../src/server/peerReviews.ts";
import { verifyPeerPayloadSignatureFromPubkey } from "../src/server/peerReviews.ts";
import { verifyOperatorAtBaseLocal } from "../src/lib/peerOperatorVerify.ts";
import { canonicalSerializePeerPayload } from "../src/lib/attestationV4.ts";
import { signBytes } from "../src/lib/signing.ts";
import { runPrListen, type PrListenOptions } from "../src/commands/prListen.ts";
import type { TripletRecord } from "../src/lib/peerWatchLog.ts";
import type { SshSpawnFn } from "../src/lib/seatClient.ts";
import type { Keypair } from "../src/lib/keys.ts";

// ─── Key generation helpers ──────────────────────────────────────────

/**
 * Minimal keypair shape for the sim: a stamp SPKI fingerprint (`sha256:<hex>`)
 * used as the seat-holder identifier in DB rows.
 */
interface SimKeypair {
  privateKeyPem: string;
  publicKeyPem: string;
  /** sha256:<hex> SPKI fingerprint — used as the primary identifier. */
  fp: string;
  name: string;
}

function genSimKeypair(name: string): SimKeypair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }) as string;
  const spkiDer = createPublicKey(publicKeyPem).export({
    type: "spki",
    format: "der",
  }) as Buffer;
  const fp = "sha256:" + createHash("sha256").update(spkiDer).digest("hex");
  return { privateKeyPem, publicKeyPem, fp, name };
}

// ─── Shared harness ──────────────────────────────────────────────────

interface SimHarness {
  tmpDir: string;
  dbPath: string;
  repo: string;
  patchId: string;
  prUrl: string;
  author: SimKeypair;
  reviewerB: SimKeypair;
  reviewerC: SimKeypair;
  reviewerD: SimKeypair;
  cleanup: () => void;
}

let harness: SimHarness;

before(() => {
  const tmpDir = mkdtempSync(join(os.tmpdir(), "peer-sim-"));
  const dbPath = join(tmpDir, "users.db");

  const repo = "anglepoint-engineering/stamp-peer-review-validation";
  // Use a real 40-char hex string (not random) for reproducibility.
  const patchId = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
  const prUrl = "https://github.com/anglepoint-engineering/stamp-peer-review-validation/pull/7";

  const author = genSimKeypair("author");
  const reviewerB = genSimKeypair("reviewer-b");
  const reviewerC = genSimKeypair("reviewer-c");
  const reviewerD = genSimKeypair("reviewer-d");

  // Insert the patch row directly (bypasses pr-opened SSH verb and git/manifest check).
  // This is the correct approach for the sim: we're testing seat-protocol semantics,
  // not the pr-opened auth path (which has its own tests in serverPeerReviews.test.ts).
  const db = openServerDb({ path: dbPath, skipChmod: true });
  try {
    insertPatch(db, {
      patch_id: patchId,
      requested_by_fp: author.fp,
      base_sha: "0".repeat(40),
      head_sha: "0".repeat(40),
      repo,
      pr_url: prUrl,
    });
  } finally {
    db.close();
  }

  harness = {
    tmpDir,
    dbPath,
    repo,
    patchId,
    prUrl,
    author,
    reviewerB,
    reviewerC,
    reviewerD,
    cleanup: () => rmSync(tmpDir, { recursive: true, force: true }),
  };
});

after(() => {
  clearListenerRegistry();
  harness?.cleanup();
});

// ─── AC5: seat protocol via claimSeatTx ──────────────────────────────
//
// Drives `claimSeatTx` directly — the atomic seat-enforcement function
// that all SSH verbs delegate to. This covers the AC5 assertions without
// requiring real sshd or a running server process.

describe("AC5: seat protocol — claimSeatTx enforcement", () => {
  it("reviewer-b claims seat 1 → { ok: true, seat: 1 }", () => {
    const { dbPath, patchId, reviewerB } = harness;
    const db = openServerDb({ path: dbPath, skipChmod: true });
    try {
      const result = claimSeatTx(db, patchId, reviewerB.fp);
      assert.ok(result.ok, `claimSeatTx should succeed; got: ${JSON.stringify(result)}`);
      if (result.ok) {
        assert.equal(result.seat, 1, "first claim should get seat 1");
      }
    } finally {
      db.close();
    }
  });

  it("reviewer-c claims seat 2 → { ok: true, seat: 2 }", () => {
    const { dbPath, patchId, reviewerC } = harness;
    const db = openServerDb({ path: dbPath, skipChmod: true });
    try {
      const result = claimSeatTx(db, patchId, reviewerC.fp);
      assert.ok(result.ok, `claimSeatTx should succeed; got: ${JSON.stringify(result)}`);
      if (result.ok) {
        assert.equal(result.seat, 2, "second claim should get seat 2");
      }
    } finally {
      db.close();
    }
  });

  it("reviewer-b second claim → already_holds_other_seat (self-collision)", () => {
    const { dbPath, patchId, reviewerB } = harness;
    const db = openServerDb({ path: dbPath, skipChmod: true });
    try {
      const result = claimSeatTx(db, patchId, reviewerB.fp);
      assert.ok(!result.ok, "second claim by reviewer-b should fail");
      if (!result.ok) {
        assert.equal(
          result.error,
          "already_holds_other_seat",
          `expected already_holds_other_seat; got: ${result.error}`,
        );
      }
    } finally {
      db.close();
    }
  });

  it("author claim → author_cannot_claim_own_pr", () => {
    const { dbPath, patchId, author } = harness;
    const db = openServerDb({ path: dbPath, skipChmod: true });
    try {
      const result = claimSeatTx(db, patchId, author.fp);
      assert.ok(!result.ok, "author claim should fail");
      if (!result.ok) {
        assert.equal(
          result.error,
          "author_cannot_claim_own_pr",
          `expected author_cannot_claim_own_pr; got: ${result.error}`,
        );
      }
    } finally {
      db.close();
    }
  });

  it("third if_available claimant (reviewer-d) → seats_full", () => {
    const { dbPath, patchId, reviewerD } = harness;
    // B and C already hold seats (from prior tests in this suite).
    const db = openServerDb({ path: dbPath, skipChmod: true });
    try {
      const result = claimSeatTx(db, patchId, reviewerD.fp);
      assert.ok(!result.ok, "reviewer-d should fail with seats_full");
      if (!result.ok) {
        assert.equal(
          result.error,
          "seats_full",
          `expected seats_full; got: ${result.error}`,
        );
      }
    } finally {
      db.close();
    }
  });
});

// ─── AC5: re-review-requested delivered to seat-holders ──────────────

describe("AC5: re-review-requested delivered to both seat-holders via in-process fanout", () => {
  it("fanoutToSeatHolders delivers re-review-requested to reviewer-b and reviewer-c", () => {
    const { reviewerB, reviewerC, author, patchId, prUrl, repo } = harness;

    const receivedB: PeerReviewEvent[] = [];
    const receivedC: PeerReviewEvent[] = [];

    registerListener(reviewerB.fp, {
      orgs: ["anglepoint-engineering"],
      onEvent: (ev) => receivedB.push(ev),
    });
    registerListener(reviewerC.fp, {
      orgs: ["anglepoint-engineering"],
      onEvent: (ev) => receivedC.push(ev),
    });

    const event: PeerReviewEvent = {
      event_type: "re-review-requested",
      patch_id: patchId,
      actor_fp: author.fp,
      payload: {
        patch_id: patchId,
        requested_by_fp: author.fp,
        pr_url: prUrl,
        repo,
      },
    };

    const notified = fanoutToSeatHolders([reviewerB.fp, reviewerC.fp], event);

    assert.deepStrictEqual(
      notified.sort(),
      [reviewerB.fp, reviewerC.fp].sort(),
      "both seat-holders should be notified",
    );
    assert.equal(receivedB.length, 1, "reviewer-b should receive one event");
    assert.equal(receivedC.length, 1, "reviewer-c should receive one event");
    assert.equal(receivedB[0]!.event_type, "re-review-requested");
    assert.equal(receivedC[0]!.event_type, "re-review-requested");

    unregisterListener(reviewerB.fp);
    unregisterListener(reviewerC.fp);
  });
});

// ─── AC5: cost-cap enforcement via prListen seams ────────────────────

describe("AC5: cost-cap enforcement — cap-hit triplet logged + notification fired", () => {
  it("events with initial spend >= cap → triplets logged as 'daily cap hit' + notification fired", async () => {
    const { reviewerB, author, patchId, prUrl, repo } = harness;

    const triplets: TripletRecord[] = [];
    const notifications: Array<{ title: string; body: string }> = [];

    // Use the reviewer's stamp keypair as prListen's identity.
    const kp: Keypair = {
      privateKeyPem: reviewerB.privateKeyPem,
      publicKeyPem: reviewerB.publicKeyPem,
      fingerprint: reviewerB.fp,
    };

    // Fake SSH spawn — subscribe and release-seat succeed; claim should not
    // be called when the cap is pre-hit.
    let seatClaimCount = 0;
    const fakeSshSpawn: SshSpawnFn = async (_cfg, verb, _payload) => {
      if (verb === "subscribe") {
        return { stdout: JSON.stringify({ ok: true }) + "\n", stderr: "", exitCode: 0, signal: null };
      }
      if (verb === "claim-seat") {
        seatClaimCount++;
        return {
          stdout: JSON.stringify({ ok: true, seat: 1, patch_id: patchId }) + "\n",
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }
      if (verb === "release-seat") {
        return { stdout: JSON.stringify({ ok: true }) + "\n", stderr: "", exitCode: 0, signal: null };
      }
      return { stdout: "", stderr: `unknown verb: ${verb}`, exitCode: 1, signal: null };
    };

    // Two identical pr-opened events for the same patch.
    // author.fp !== reviewerB.fp → no author-exclusion.
    const event: PeerReviewEvent = {
      event_type: "pr-opened",
      patch_id: patchId,
      actor_fp: author.fp,
      payload: {
        patch_id: patchId,
        base_sha: "0".repeat(40),
        head_sha: "0".repeat(40),
        repo,
        pr_url: prUrl,
        requested_by_fp: author.fp,
        title: "Test PR",
        body: "PR body",
        paths_changed: ["src/foo.ts"],
      },
    };

    const opts: PrListenOptions = {
      orgs: ["anglepoint-engineering"],
      // Provide a server address so resolveServerConfig doesn't fail.
      server: "127.0.0.1:2222",
      _keypairForTest: kp,
      _eventQueueForTest: [{ ...event }, { ...event }],
      _sshSpawnForTest: fakeSshSpawn,
      // Haiku triage: $0.01 cap, if_available, draft mode.
      _haikuRunnerForTest: async (_system, _user) =>
        JSON.stringify({
          claim_seat: "if_available",
          post_mode: "draft",
          prompt: "default",
          cost_cap_usd: 0.01,
        }),
      _peerWatchRulesForTest: { rules: "dummy-rules", hash: "dummy-hash" },
      // Pre-seed daily spend to $0.01 (at the cap threshold).
      // Cap check is `dailySpend >= cost_cap_usd`, so both events
      // are immediately downgraded to "skip" with reason "daily cap hit".
      _initialDailySpendForTest: 0.01,
      _appendTripletForTest: (record) => triplets.push(record),
      _notifyForTest: (title, body) => notifications.push({ title, body }),
      _writeDraftForTest: (_filePath, _content) => { /* suppress disk write */ },
      _resolveNamedPromptForTest: (_input) => ({ ok: true, body: "sim prompt" }),
      _sdkRunnerForTest: async (_diff) => "sim review body",
      // AGT-454: bypass operator gate — repo is not mapped in peer-repos.yml.
      _peerReposMapForTest: new Map([[repo, "/tmp/fake-repo"]]),
      _operatorVerifyForTest: () => ({ ok: true as const }),
    };

    // Suppress stderr during the run.
    const origWrite = process.stderr.write.bind(process.stderr);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process.stderr as any).write = () => true;

    const origExit = process.exit.bind(process);
    let exitCode = 0;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process as any).exit = (code?: number | string) => {
      exitCode = typeof code === "number" ? code : 0;
      throw new Error(`process.exit(${code})`);
    };

    try {
      await runPrListen(opts);
    } catch (err) {
      if (!(err instanceof Error) || !err.message.startsWith("process.exit")) {
        throw err;
      }
    } finally {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (process.stderr as any).write = origWrite;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (process as any).exit = origExit;
      clearListenerRegistry();
    }

    // Both events should have been cap-skipped and logged.
    assert.equal(triplets.length, 2, "should have logged two triplet records");

    const capSkipped = triplets.filter((t) => t.reason === "daily cap hit");
    assert.ok(
      capSkipped.length >= 1,
      `at least one triplet should have reason "daily cap hit"; got: ${JSON.stringify(triplets.map((t) => t.reason))}`,
    );

    // Desktop notification should have fired at least once with the cap message.
    const capNotifications = notifications.filter((n) =>
      n.body.includes("Daily review cap") || n.body.includes("daily cap"),
    );
    assert.ok(
      capNotifications.length >= 1,
      `_notifyForTest should have been called with a cap-hit body; got: ${JSON.stringify(notifications)}`,
    );

    // No seat claim should have been attempted.
    assert.equal(seatClaimCount, 0, "seat claim should not be called when cap is hit");

    assert.equal(exitCode, 0, "prListen should exit 0 after queue drains");
  });
});

// ─── Server crypto: verifyPeerPayloadSignatureFromPubkey ─────────────
//
// Tests for the new pure-crypto server verification function (AGT-454).
// These replace the never-real server-bare-repo auth path.

describe("AGT-454: server crypto — verifyPeerPayloadSignatureFromPubkey", () => {
  it("accepts a correctly-signed payload with matching fp", () => {
    const kp = genSimKeypair("actor");
    const payloadBody = {
      patch_id: "a".repeat(40),
      requested_by_fp: kp.fp,
      repo: "acme/widget",
      base_sha: "b".repeat(40),
      pubkey: kp.publicKeyPem,
    };
    const canonical = canonicalSerializePeerPayload(payloadBody);
    const signature = signBytes(kp.privateKeyPem, canonical);

    const result = verifyPeerPayloadSignatureFromPubkey(kp.publicKeyPem, kp.fp, canonical, signature);
    assert.ok(result.ok, `should accept valid payload; got: ${JSON.stringify(result)}`);
  });

  it("rejects when claimed fp does not match sha256(SPKI-DER) of pubkey", () => {
    const kp = genSimKeypair("actor");
    const impostor = genSimKeypair("impostor");
    // Provide kp.publicKeyPem but claim impostor.fp — fp mismatch.
    const payloadBody = {
      patch_id: "a".repeat(40),
      requested_by_fp: impostor.fp,
      pubkey: kp.publicKeyPem,
    };
    const canonical = canonicalSerializePeerPayload(payloadBody);
    const signature = signBytes(kp.privateKeyPem, canonical);

    const result = verifyPeerPayloadSignatureFromPubkey(kp.publicKeyPem, impostor.fp, canonical, signature);
    assert.ok(!result.ok, "should reject fp mismatch");
    if (!result.ok) {
      assert.ok(result.reason.includes("fp mismatch"), `reason should mention fp mismatch; got: ${result.reason}`);
    }
  });

  it("rejects a tampered payload (signature no longer valid over modified bytes)", () => {
    const kp = genSimKeypair("actor");
    const payloadBody = {
      patch_id: "a".repeat(40),
      requested_by_fp: kp.fp,
      pubkey: kp.publicKeyPem,
    };
    const canonical = canonicalSerializePeerPayload(payloadBody);
    const signature = signBytes(kp.privateKeyPem, canonical);

    // Tamper: change the canonical bytes slightly before verifying.
    const tampered = Buffer.from(canonical);
    tampered[0] = tampered[0]! ^ 0x01;

    const result = verifyPeerPayloadSignatureFromPubkey(kp.publicKeyPem, kp.fp, tampered, signature);
    assert.ok(!result.ok, "should reject tampered payload");
    if (!result.ok) {
      assert.ok(
        result.reason.includes("signature verification failed"),
        `reason should mention sig failure; got: ${result.reason}`,
      );
    }
  });

  it("rejects a pubkey/fp swap (both pubkey and fp from a different keypair)", () => {
    // Attacker scenario: sign with actor's key but provide impostor's pubkey+fp.
    const actor = genSimKeypair("actor");
    const impostor = genSimKeypair("impostor");

    // Sign with actor's private key.
    const payloadBody = {
      patch_id: "a".repeat(40),
      requested_by_fp: actor.fp,
      pubkey: actor.publicKeyPem,
    };
    const canonical = canonicalSerializePeerPayload(payloadBody);
    const signature = signBytes(actor.privateKeyPem, canonical);

    // Try to present impostor's pubkey+fp while reusing actor's sig.
    // fp-recompute will catch this: fingerprintFromPem(impostor.publicKeyPem) ≠ actor.fp.
    const result = verifyPeerPayloadSignatureFromPubkey(
      impostor.publicKeyPem,
      actor.fp,          // claimed fp = actor's fp, but pubkey = impostor's pubkey
      canonical,
      signature,
    );
    assert.ok(!result.ok, "should reject pubkey/fp swap");
  });
});

// ─── Client operator check: verifyOperatorAtBaseLocal ────────────────
//
// Creates a real tmp git repo with a committed manifest at a known base_sha.
// Mirrors the mkdtemp+git-init+commit pattern from tests/attest.test.ts.

describe("AGT-454: client-side operator verification — verifyOperatorAtBaseLocal", () => {
  let fixtureDir: string;
  let baseSha: string;
  let operatorKp: SimKeypair;
  let outsiderKp: SimKeypair;

  before(() => {
    fixtureDir = mkdtempSync(join(os.tmpdir(), "peer-operator-verify-"));
    operatorKp = genSimKeypair("operator");
    outsiderKp = genSimKeypair("outsider");

    // Init a minimal git repo.
    const git = (args: string[]) =>
      spawnSync("git", args, { cwd: fixtureDir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

    git(["init", "-b", "main"]);
    git(["config", "user.email", "test@test.com"]);
    git(["config", "user.name", "Test"]);

    // Create a minimal manifest with operator entry for operatorKp.
    // Format matches serializeManifestYaml: keys is a map keyed by short_name.
    const manifestDir = join(fixtureDir, ".stamp", "trusted-keys");
    mkdirSync(manifestDir, { recursive: true });
    const manifestYaml = [
      "keys:",
      "  operator:",
      `    fingerprint: ${operatorKp.fp}`,
      "    capabilities: [operator]",
    ].join("\n") + "\n";
    writeFileSync(join(manifestDir, "manifest.yml"), manifestYaml, "utf8");

    // Also write a dummy pubkey file so the dir is non-empty.
    writeFileSync(join(manifestDir, "operator.pub"), operatorKp.publicKeyPem, "utf8");

    git(["add", "."]);
    git(["commit", "-m", "init manifest"]);

    const result = git(["rev-parse", "HEAD"]);
    baseSha = result.stdout.trim();
  });

  after(() => {
    rmSync(fixtureDir, { recursive: true, force: true });
  });

  it("accepts operator fingerprint present in manifest at base_sha", () => {
    const result = verifyOperatorAtBaseLocal(fixtureDir, baseSha, operatorKp.fp);
    assert.ok(result.ok, `should accept operator; got: ${JSON.stringify(result)}`);
  });

  it("rejects fingerprint not in manifest at base_sha", () => {
    const result = verifyOperatorAtBaseLocal(fixtureDir, baseSha, outsiderKp.fp);
    assert.ok(!result.ok, "should reject outsider fp");
    if (!result.ok) {
      assert.ok(
        result.reason.includes("not in manifest"),
        `reason should mention 'not in manifest'; got: ${result.reason}`,
      );
    }
  });

  it("rejects when base_sha is not present in local clone (absent sha)", () => {
    // Use an all-zeros sha that doesn't exist in the fixture repo.
    const absentSha = "0".repeat(40);
    const result = verifyOperatorAtBaseLocal(fixtureDir, absentSha, operatorKp.fp);
    assert.ok(!result.ok, "should reject unknown sha");
    if (!result.ok) {
      // No auto-fetch: the function returns base_sha_not_found immediately
      // (DoS amplification fix — any registered user can supply an arbitrary
      // base_sha, so fetching on attacker-controlled input is not safe).
      assert.ok(
        result.reason.includes("base_sha_not_found"),
        `reason should mention base_sha_not_found (no auto-fetch); got: ${result.reason}`,
      );
    }
  });
});
