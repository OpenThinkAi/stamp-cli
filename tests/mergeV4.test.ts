/**
 * End-to-end test for `stamp merge` folding server-signed approvals into
 * a v4 attestation envelope (AGT-334).
 *
 * Drives the real `runMerge` against a temp stamp-gated repo with:
 *   - `.stamp/config.yml` carrying `review_server: ssh://...` on the
 *     target branch (the v4 dispatch trigger)
 *   - a synthetic Ed25519 server keypair whose public key is committed
 *     to `.stamp/trusted-keys/` and whose fingerprint is registered in
 *     the trusted-keys manifest with `capabilities: [server]`
 *   - a pre-seeded `reviews` row carrying a server-signed `ApprovalV4`
 *     (we sign canonical bytes with the synthetic server key — same
 *     code path the real stamp-server would exercise via AGT-331)
 *   - an `ensureUserKeypair`-minted operator key (HOME redirected to
 *     tmp so we don't touch the real `~/.stamp`)
 *
 * Asserts:
 *   - happy path: trailers land on the merge commit, decode as v4
 *     payload, outer (operator) signature verifies, inner (server)
 *     signatures verify, all fields agree with the (base, head) pair
 *   - missing approval → clean error pointing at `stamp review`
 *   - stale diff_sha256 → clean error pointing at `stamp review`
 *   - stale base_sha → clean error pointing at `stamp review`
 *   - non-approved server verdict → clean error
 *   - missing reviewer in DB → clean error
 *   - unit: envelope assembly + canonical bytes + signature verify
 *     against a synthetic operator key (no merge command involved)
 *
 * The verifier here is deliberately handwritten — AGT-335 will ship the
 * real pre-receive v4 verifier and this test is intentionally kept
 * independent of it so the two can land in either order.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import {
  generateKeyPairSync,
  createHash,
  createPublicKey,
  verify as cryptoVerify,
} from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { runMerge } from "../src/commands/merge.ts";
import {
  canonicalSerializeApproval,
  canonicalSerializePayload,
  trailerValueToPayloadBytes,
  type ApprovalV4,
  type AttestationPayloadV4,
} from "../src/lib/attestationV4.ts";
import {
  openDb,
  recordReview,
  serverApprovalsFor,
  type Verdict,
} from "../src/lib/db.ts";
import { fingerprintFromPem, ensureUserKeypair } from "../src/lib/keys.ts";
import { stampStateDbPath } from "../src/lib/paths.ts";
import { signBytes, verifyBytes } from "../src/lib/signing.ts";

// ─── Harness ────────────────────────────────────────────────────────

interface ServerKey {
  privatePem: string;
  publicPem: string;
  fingerprint: string; // sha256:<hex>
}

interface Harness {
  repo: string;
  home: string;
  prevHome: string | undefined;
  serverKey: ServerKey;
  cleanup: () => void;
}

function git(repo: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd: repo,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function generateServerKey(): ServerKey {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  return {
    privatePem,
    publicPem,
    fingerprint: fingerprintFromPem(publicPem),
  };
}

const REVIEWER_PROMPT = "You are the security reviewer. Approve everything.\n";

/**
 * Set up a stamp-gated repo with v4-mode config:
 *   - branches.main.review_server = ssh://... (triggers v4 dispatch)
 *   - a security reviewer prompt at .stamp/reviewers/security.md
 *   - a server pubkey committed to .stamp/trusted-keys/ with
 *     a manifest entry binding the fingerprint to capabilities: [server]
 *   - a feature branch with one commit
 *
 * The operator's stamp key is minted on-demand by `ensureUserKeypair()`
 * via the redirected HOME — same pattern as tests/attest.test.ts.
 */
function setupHarness(): Harness {
  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-mergev4-"));
  const repo = path.join(root, "repo");
  const home = path.join(root, "home");
  mkdirSync(repo, { recursive: true });
  mkdirSync(home, { recursive: true });

  const prevHome = process.env["HOME"];
  process.env["HOME"] = home;

  const serverKey = generateServerKey();

  git(repo, ["init", "-q", "-b", "main"]);
  git(repo, ["config", "user.name", "Test"]);
  git(repo, ["config", "user.email", "test@example.invalid"]);
  git(repo, ["config", "commit.gpgsign", "false"]);

  // .stamp/config.yml with review_server set on main (triggers v4).
  mkdirSync(path.join(repo, ".stamp", "reviewers"), { recursive: true });
  mkdirSync(path.join(repo, ".stamp", "trusted-keys"), { recursive: true });
  writeFileSync(
    path.join(repo, ".stamp", "config.yml"),
    [
      "branches:",
      "  main:",
      "    required: [security]",
      "    review_server: ssh://git@stamp.test.invalid:22",
      "reviewers:",
      "  security:",
      "    prompt: .stamp/reviewers/security.md",
      "    tools: []",
      "",
    ].join("\n"),
  );
  writeFileSync(
    path.join(repo, ".stamp", "reviewers", "security.md"),
    REVIEWER_PROMPT,
  );

  // Commit the server's pubkey + manifest registering it with the
  // `server` capability. The pubkey file is named after the fingerprint
  // (mirroring the convention in `src/lib/keys.ts`).
  const pubFileName = serverKey.fingerprint.replace(":", "_") + ".pub";
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", pubFileName),
    serverKey.publicPem,
  );
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", "manifest.yml"),
    [
      "keys:",
      "  review-server-test:",
      `    fingerprint: ${serverKey.fingerprint}`,
      "    capabilities: [server]",
      "",
    ].join("\n"),
  );

  writeFileSync(path.join(repo, "README.md"), "initial\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "initial: seed .stamp/ config"]);

  // Feature branch with one commit.
  git(repo, ["checkout", "-q", "-b", "feature"]);
  writeFileSync(path.join(repo, "feature.txt"), "hello\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "add feature"]);

  // Switch back to main — `stamp merge` requires being on the target branch.
  git(repo, ["checkout", "-q", "main"]);

  return {
    repo,
    home,
    prevHome,
    serverKey,
    cleanup: () => {
      process.env["HOME"] = prevHome;
      rmSync(root, { recursive: true, force: true });
    },
  };
}

function shaOf(repo: string, ref: string): string {
  return git(repo, ["rev-parse", ref]).trim();
}

function diffBetween(repo: string, base: string, head: string): string {
  return git(repo, ["diff", `${base}...${head}`]);
}

function sha256Hex(bytes: Buffer | string): string {
  return createHash("sha256")
    .update(typeof bytes === "string" ? Buffer.from(bytes, "utf8") : bytes)
    .digest("hex");
}

/**
 * Sign an ApprovalV4 with the synthetic server key — mirrors the
 * `runReviewPipeline` signing step but standalone so the test doesn't
 * depend on importing the server pipeline.
 */
function signApproval(
  approval: ApprovalV4,
  serverKey: ServerKey,
): { approvalJson: string; signatureB64: string } {
  const canonical = canonicalSerializeApproval(approval);
  return {
    approvalJson: JSON.stringify(approval),
    signatureB64: signBytes(serverKey.privatePem, canonical),
  };
}

/**
 * Seed a server-attested review row in the local DB. Mirrors what
 * `sshReviewClient.requestServerReview` → `recordReview` would do in a
 * real run.
 */
function seedV4Review(
  repo: string,
  approval: ApprovalV4,
  signatureB64: string,
  verdict: Verdict = "approved",
): void {
  const db = openDb(stampStateDbPath(repo));
  try {
    recordReview(db, {
      reviewer: approval.reviewer,
      base_sha: approval.base_sha,
      head_sha: approval.head_sha,
      verdict,
      issues: `${approval.reviewer} ${verdict}`,
      serverAttestation: {
        approval_json: JSON.stringify(approval),
        signature_b64: signatureB64,
        server_key_id: approval.server_key_id,
      },
    });
  } finally {
    db.close();
  }
}

function runFromRepo<T>(repo: string, fn: () => T): T {
  const prev = process.cwd();
  process.chdir(repo);
  try {
    return fn();
  } finally {
    process.chdir(prev);
  }
}

/**
 * Extract `Stamp-Payload` / `Stamp-Verified` trailer values from a
 * commit message. Standalone (not importing `parseCommitAttestation`
 * from the v3 module) because the trailers carry v4 bytes.
 */
function extractTrailers(commitMsg: string): {
  payloadB64: string;
  signatureB64: string;
} {
  const payloadMatch = commitMsg.match(/^Stamp-Payload:\s*(.+)$/m);
  const sigMatch = commitMsg.match(/^Stamp-Verified:\s*(.+)$/m);
  assert.ok(payloadMatch, "Stamp-Payload trailer missing");
  assert.ok(sigMatch, "Stamp-Verified trailer missing");
  return {
    payloadB64: payloadMatch[1]!.trim(),
    signatureB64: sigMatch[1]!.trim(),
  };
}

function buildApproval(args: {
  reviewer: string;
  baseSha: string;
  headSha: string;
  diffSha256: string;
  serverFingerprint: string;
  verdict?: ApprovalV4["verdict"];
}): ApprovalV4 {
  return {
    reviewer: args.reviewer,
    verdict: args.verdict ?? "approved",
    prompt_sha256: sha256Hex(REVIEWER_PROMPT),
    diff_sha256: args.diffSha256,
    base_sha: args.baseSha,
    head_sha: args.headSha,
    // The exact manifest snapshot hash doesn't affect this test's
    // assertions (AGT-335 verifies it; merge just propagates it). Use
    // a deterministic placeholder of the right shape.
    trusted_keys_snapshot_sha256: "sha256:" + "0".repeat(64),
    issued_at: "2026-05-17T18:42:13Z",
    server_key_id: args.serverFingerprint,
  };
}

// Use the no-TTY opt-out so requireHumanMerge doesn't block tests.
process.env["STAMP_REQUIRE_HUMAN_MERGE"] = "0";

// ─── Tests ─────────────────────────────────────────────────────────

describe("runMerge v4 — happy path", () => {
  it("folds a server-signed approval into a verifying v4 envelope", () => {
    const h = setupHarness();
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "feature");
      const diff = diffBetween(h.repo, base, head);
      const diffSha256 = sha256Hex(diff);

      const approval = buildApproval({
        reviewer: "security",
        baseSha: base,
        headSha: head,
        diffSha256,
        serverFingerprint: h.serverKey.fingerprint,
      });
      const { signatureB64 } = signApproval(approval, h.serverKey);
      seedV4Review(h.repo, approval, signatureB64);

      // Run the merge.
      runFromRepo(h.repo, () =>
        runMerge({ branch: "feature", into: "main", yes: true }),
      );

      // Extract trailers from the merge commit.
      const mergeMsg = git(h.repo, ["log", "-1", "--pretty=%B"]);
      const { payloadB64, signatureB64: outerSigB64 } =
        extractTrailers(mergeMsg);

      // Decode the canonical payload bytes straight out of the
      // trailer. The two trailers carry the payload bytes (base64
      // of canonicalSerializePayload) and the operator's signature
      // separately — there's no JSON envelope wrapping them on the
      // commit-trailer wire (that's a separate codepath in
      // `parseEnvelope`, for non-trailer storage).
      const payloadBytes = trailerValueToPayloadBytes(payloadB64);
      const payload: AttestationPayloadV4 = JSON.parse(
        payloadBytes.toString("utf8"),
      );

      // Top-level invariants.
      assert.equal(payload.schema_version, 4);
      assert.equal(payload.base_sha, base);
      assert.equal(payload.head_sha, head);
      assert.equal(payload.target_branch, "main");
      assert.equal(payload.diff_sha256, diffSha256);
      assert.equal(payload.approvals.length, 1);
      assert.deepEqual(payload.trust_anchor_signatures, []);
      assert.equal(payload.checks.length, 0);

      // Operator signature verifies against the freshly-minted keypair.
      const { keypair } = ensureUserKeypair();
      assert.equal(payload.signer_key_id, keypair.fingerprint);
      const outerOk = verifyBytes(
        keypair.publicKeyPem,
        canonicalSerializePayload(payload),
        outerSigB64,
      );
      assert.ok(outerOk, "operator signature must verify");

      // Inner (server) signature verifies against the server's pubkey.
      const entry = payload.approvals[0]!;
      assert.equal(entry.approval.reviewer, "security");
      assert.equal(entry.approval.verdict, "approved");
      assert.equal(entry.approval.base_sha, base);
      assert.equal(entry.approval.head_sha, head);
      assert.equal(entry.approval.diff_sha256, diffSha256);
      assert.equal(entry.server_attestation.server_key_id, h.serverKey.fingerprint);
      // The outer wrapper's server_key_id must match the inner signed
      // payload's server_key_id (settled architectural decision #9 —
      // the inner one is the authoritative source).
      assert.equal(
        entry.server_attestation.server_key_id,
        entry.approval.server_key_id,
      );

      const innerOk = cryptoVerify(
        null,
        canonicalSerializeApproval(entry.approval),
        createPublicKey(h.serverKey.publicPem),
        Buffer.from(entry.server_attestation.signature, "base64"),
      );
      assert.ok(innerOk, "server signature must verify");
    } finally {
      h.cleanup();
    }
  });
});

describe("runMerge v4 — failure modes", () => {
  it("rolls back and errors when no server-signed row exists for a required reviewer", () => {
    const h = setupHarness();
    try {
      const beforeHead = shaOf(h.repo, "main");

      // No seedV4Review — the gate-check still needs an approved row,
      // so seed a legacy (1.x-shape) approved row to pass the gate.
      // The v4 fold step will then fail because there's no server-
      // signed row.
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "feature");
      const db = openDb(stampStateDbPath(h.repo));
      try {
        recordReview(db, {
          reviewer: "security",
          base_sha: base,
          head_sha: head,
          verdict: "approved",
          issues: "legacy",
        });
      } finally {
        db.close();
      }

      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runMerge({ branch: "feature", into: "main", yes: true }),
          ),
        /missing server signature for reviewer "security"/,
      );

      // Rollback: HEAD on main hasn't moved.
      assert.equal(shaOf(h.repo, "main"), beforeHead);
    } finally {
      h.cleanup();
    }
  });

  it("rolls back and errors when the server signature is for a stale diff_sha256", () => {
    const h = setupHarness();
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "feature");

      const beforeMain = shaOf(h.repo, "main");

      // Approval signed against a wrong diff_sha256 (random 64-hex).
      const staleDiffSha = "ab".repeat(32);
      const approval = buildApproval({
        reviewer: "security",
        baseSha: base,
        headSha: head,
        diffSha256: staleDiffSha,
        serverFingerprint: h.serverKey.fingerprint,
      });
      const { signatureB64 } = signApproval(approval, h.serverKey);
      seedV4Review(h.repo, approval, signatureB64);

      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runMerge({ branch: "feature", into: "main", yes: true }),
          ),
        /stale signature/,
      );

      assert.equal(shaOf(h.repo, "main"), beforeMain);
    } finally {
      h.cleanup();
    }
  });

  it("rolls back when the server signed an approval against a non-'approved' verdict", () => {
    const h = setupHarness();
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "feature");
      const diff = diffBetween(h.repo, base, head);
      const diffSha256 = sha256Hex(diff);

      // The gate check needs an approved row, so first seed an approved
      // row WITHOUT server attestation, then a v4 row with a non-
      // approved verdict to trigger the v4-side mismatch.
      const db = openDb(stampStateDbPath(h.repo));
      try {
        // Approved row passes gate.
        recordReview(db, {
          reviewer: "security",
          base_sha: base,
          head_sha: head,
          verdict: "approved",
          issues: "legacy approved",
        });
        // Newer server-signed changes_requested row: serverApprovalsFor
        // picks this (latest server-signed row wins).
        const approval = buildApproval({
          reviewer: "security",
          baseSha: base,
          headSha: head,
          diffSha256,
          serverFingerprint: h.serverKey.fingerprint,
          verdict: "changes_requested",
        });
        const { signatureB64 } = signApproval(approval, h.serverKey);
        recordReview(db, {
          reviewer: "security",
          base_sha: base,
          head_sha: head,
          verdict: "changes_requested",
          issues: "server requests changes",
          serverAttestation: {
            approval_json: JSON.stringify(approval),
            signature_b64: signatureB64,
            server_key_id: approval.server_key_id,
          },
        });
      } finally {
        db.close();
      }

      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runMerge({ branch: "feature", into: "main", yes: true }),
          ),
        // The gate check fires first because latestReviews picks the
        // most recent verdict, which is changes_requested. That's the
        // operator-visible failure surface for this scenario — the v4
        // helper's verdict cross-check is the belt-and-suspenders for
        // the case where a non-approved server row coexists with an
        // approved newer non-server row (we don't exercise that here
        // because the gate check covers the common case).
        /gate CLOSED|carries verdict "changes_requested"/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rolls back when the server signature is forged (does not Ed25519-verify)", () => {
    // Defense-in-depth: even though the SSH client verified the
    // signature at write time, buildV4Trailers re-verifies at merge
    // time. Plant a row whose approval body cross-checks pass but
    // whose `signature_b64` is invalid — the merge must reject it.
    const h = setupHarness();
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "feature");
      const diff = diffBetween(h.repo, base, head);
      const diffSha256 = sha256Hex(diff);

      const approval = buildApproval({
        reviewer: "security",
        baseSha: base,
        headSha: head,
        diffSha256,
        serverFingerprint: h.serverKey.fingerprint,
      });
      // Forge the signature — base64 of 64 zero bytes (Ed25519 sig
      // length) so the verify call is structurally valid but
      // semantically wrong.
      const forgedSig = Buffer.alloc(64, 0).toString("base64");
      seedV4Review(h.repo, approval, forgedSig);

      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runMerge({ branch: "feature", into: "main", yes: true }),
          ),
        /failed Ed25519 verification/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rolls back when the manifest at base_sha doesn't list the signing key", () => {
    // The SSH client only wrote the row because the manifest at the
    // time included the server's fingerprint. If the operator's
    // base_sha has since rotated keys (manifest no longer lists
    // this server), the merge must refuse — we cannot anchor trust
    // in a key the repo no longer trusts.
    const h = setupHarness();
    try {
      // Overwrite the manifest with a different (random) fingerprint.
      const otherFp = "sha256:" + "1".repeat(64);
      writeFileSync(
        path.join(h.repo, ".stamp", "trusted-keys", "manifest.yml"),
        [
          "keys:",
          "  other-server:",
          `    fingerprint: ${otherFp}`,
          "    capabilities: [server]",
          "",
        ].join("\n"),
      );
      git(h.repo, ["add", "-A"]);
      git(h.repo, ["commit", "-q", "-m", "rotate manifest"]);

      // Re-resolve base/head — the rotation changed main's tip.
      const base = shaOf(h.repo, "main");
      // Re-create the feature branch on top of the new base so the
      // merge-base picks up the rotated manifest.
      git(h.repo, ["checkout", "-q", "-b", "feature-rotated", "feature"]);
      git(h.repo, ["rebase", "-q", "main"]);
      const head = shaOf(h.repo, "feature-rotated");
      git(h.repo, ["checkout", "-q", "main"]);

      const diff = diffBetween(h.repo, base, head);
      const diffSha256 = sha256Hex(diff);

      // Sign with the harness's original server key (which is NO
      // LONGER in the manifest at base).
      const approval = buildApproval({
        reviewer: "security",
        baseSha: base,
        headSha: head,
        diffSha256,
        serverFingerprint: h.serverKey.fingerprint,
      });
      const { signatureB64 } = signApproval(approval, h.serverKey);
      seedV4Review(h.repo, approval, signatureB64);

      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runMerge({ branch: "feature-rotated", into: "main", yes: true }),
          ),
        /isn't listed in \.stamp\/trusted-keys\/manifest\.yml/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rolls back when the server signature is bound to a different base_sha", () => {
    const h = setupHarness();
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "feature");
      const diff = diffBetween(h.repo, base, head);
      const diffSha256 = sha256Hex(diff);

      // Sign against a fake base_sha — serverApprovalsFor filters on
      // the row's (base_sha, head_sha) columns, so we store the row's
      // base_sha truthfully but embed a different base_sha inside the
      // signed approval JSON. That's a writer-side bug but
      // buildV4Trailers should catch it explicitly.
      const fakeBase = "0".repeat(40);
      const approval = buildApproval({
        reviewer: "security",
        baseSha: fakeBase,
        headSha: head,
        diffSha256,
        serverFingerprint: h.serverKey.fingerprint,
      });
      const { signatureB64 } = signApproval(approval, h.serverKey);

      // Insert with the row-level base_sha matching the real merge
      // (so serverApprovalsFor finds it) but the inner approval_json
      // claims a different base_sha.
      const db = openDb(stampStateDbPath(h.repo));
      try {
        recordReview(db, {
          reviewer: "security",
          base_sha: base,
          head_sha: head,
          verdict: "approved",
          issues: "approved",
          serverAttestation: {
            approval_json: JSON.stringify(approval),
            signature_b64: signatureB64,
            server_key_id: approval.server_key_id,
          },
        });
      } finally {
        db.close();
      }

      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runMerge({ branch: "feature", into: "main", yes: true }),
          ),
        /signed against base_sha/,
      );
    } finally {
      h.cleanup();
    }
  });
});

describe("runMerge v4 — unit: envelope assembly + canonical bytes", () => {
  it("re-derived canonical bytes match the bytes the operator signature was computed over", () => {
    // Constructive unit check: build a payload by hand, canonical-
    // serialize, sign with a fresh keypair, then re-canonicalize the
    // payload (key order shuffled) and confirm the signature still
    // verifies. This pins the contract that the merge command's
    // signing-target bytes are deterministic across key-order.
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const privatePem = privateKey
      .export({ type: "pkcs8", format: "pem" })
      .toString();
    const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const operatorFp = fingerprintFromPem(publicPem);

    const approval: ApprovalV4 = {
      reviewer: "security",
      verdict: "approved",
      prompt_sha256: "a".repeat(64),
      diff_sha256: "b".repeat(64),
      base_sha: "c".repeat(40),
      head_sha: "d".repeat(40),
      trusted_keys_snapshot_sha256: "sha256:" + "e".repeat(64),
      issued_at: "2026-05-17T18:42:13Z",
      server_key_id: "sha256:" + "f".repeat(64),
    };

    const payload: AttestationPayloadV4 = {
      schema_version: 4,
      base_sha: approval.base_sha,
      head_sha: approval.head_sha,
      target_branch: "main",
      diff_sha256: approval.diff_sha256,
      approvals: [
        {
          approval,
          server_attestation: {
            server_key_id: approval.server_key_id,
            signature: "fake-server-sig==",
          },
        },
      ],
      checks: [],
      trust_anchor_signatures: [],
      signer_key_id: operatorFp,
    };

    const bytes = canonicalSerializePayload(payload);
    const sigB64 = signBytes(privatePem, bytes);

    // Shuffle keys at the top level and inside the approval — the
    // canonical serializer must sort them, producing identical bytes.
    const shuffled = JSON.parse(JSON.stringify(payload));
    // Force a different insertion order by deleting-and-re-adding.
    const reordered: AttestationPayloadV4 = {
      signer_key_id: shuffled.signer_key_id,
      trust_anchor_signatures: shuffled.trust_anchor_signatures,
      checks: shuffled.checks,
      approvals: shuffled.approvals,
      diff_sha256: shuffled.diff_sha256,
      target_branch: shuffled.target_branch,
      head_sha: shuffled.head_sha,
      base_sha: shuffled.base_sha,
      schema_version: shuffled.schema_version,
    };
    const reBytes = canonicalSerializePayload(reordered);
    assert.deepEqual(bytes, reBytes, "canonical bytes must be insertion-order-invariant");

    const ok = cryptoVerify(
      null,
      reBytes,
      createPublicKey(publicPem),
      Buffer.from(sigB64, "base64"),
    );
    assert.ok(ok, "operator signature must verify against re-canonicalized bytes");
  });
});

describe("runMerge v4 — serverApprovalsFor projection sanity", () => {
  it("returns one row per reviewer with the JSON + signature + key_id columns", () => {
    // Sanity check on the DB shape AGT-334 reads from. Documents the
    // (base_sha, head_sha, reviewer) → ApprovalEntryV4 mapping the
    // merge command relies on; if AGT-333's column layout drifts this
    // catches it before the merge integration test does.
    const h = setupHarness();
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "feature");
      const diff = diffBetween(h.repo, base, head);
      const diffSha256 = sha256Hex(diff);

      const approval = buildApproval({
        reviewer: "security",
        baseSha: base,
        headSha: head,
        diffSha256,
        serverFingerprint: h.serverKey.fingerprint,
      });
      const { signatureB64 } = signApproval(approval, h.serverKey);
      seedV4Review(h.repo, approval, signatureB64);

      const db = openDb(stampStateDbPath(h.repo));
      try {
        const rows = serverApprovalsFor(db, base, head);
        assert.equal(rows.length, 1);
        const row = rows[0]!;
        assert.equal(row.reviewer, "security");
        assert.equal(row.base_sha, base);
        assert.equal(row.head_sha, head);
        assert.equal(row.verdict, "approved");
        assert.equal(row.server_key_id, h.serverKey.fingerprint);
        assert.equal(row.signature_b64, signatureB64);
        const parsed = JSON.parse(row.approval_json) as ApprovalV4;
        assert.equal(parsed.reviewer, "security");
        assert.equal(parsed.diff_sha256, diffSha256);
      } finally {
        db.close();
      }
    } finally {
      h.cleanup();
    }
  });
});

