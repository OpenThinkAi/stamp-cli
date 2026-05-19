/**
 * AGT-355 — client-side `stamp attest` v3 envelope assembly.
 *
 * Drives `runAttest` against a temp repo whose branch rule declares a
 * `review_server` (server-attested PR mode trigger) AND whose local DB
 * carries server-signed approval rows (the artifact `requestServerReview`
 * → `recordReview(...serverAttestation)` writes at review time). Verifies
 * the resulting attestation ref carries a v3 envelope: per-approval
 * `ApprovalEntryV4` entries (with server signature), top-level
 * `diff_sha256`, operator-signed outer envelope, `schema_version: 3`.
 *
 * Scope:
 *   - happy path: v3 envelope, server's per-approval signature
 *     verifies, operator's outer signature verifies, runVerifyPr
 *     accepts the produced envelope
 *   - fallback: branch rule WITHOUT `review_server` produces v2 (legacy)
 *     envelope — defends the 1.6.0 PR-check path
 *   - failure: review_server configured but DB lacks server signature
 *     for a required reviewer → actionable error naming the server
 *     upgrade path (the 2.0.0-client vs 2.0.0-server compat case)
 *
 * Together with `tests/serverPrAttestationProduction.test.ts` (server
 * side) and `tests/v3PrAttestationServerProducedE2E.test.ts` (end-to-
 * end), this closes the AGT-355 producer surface.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  createPublicKey,
  verify as cryptoVerify,
} from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { runAttest } from "../src/commands/attest.ts";
import {
  canonicalSerializeApproval,
  type ApprovalEntryV4,
  type ApprovalV4,
} from "../src/lib/attestationV4.ts";
import { openDb, recordReview } from "../src/lib/db.ts";
import { ensureUserKeypair, fingerprintFromPem } from "../src/lib/keys.ts";
import { stampStateDbPath } from "../src/lib/paths.ts";
import {
  parseEnvelope,
  readAttestationBlobBytes,
  serializePayload,
  PR_ATTESTATION_SCHEMA_VERSION,
  LEGACY_CLIENT_PR_ATTESTATION_SCHEMA_VERSION,
} from "../src/lib/prAttestation.ts";
import { signBytes, verifyBytes } from "../src/lib/signing.ts";
import { parseManifest, snapshotSha256 } from "../src/lib/trustedKeysManifest.ts";
import { runVerifyPr } from "../src/commands/verifyPr.ts";

// Tests run `stamp attest` against a real repo + fabricated server
// signing key. Use the no-TTY opt-out so requireHumanMerge doesn't
// interfere (attest doesn't call it today; defensive in case it
// changes).
process.env["STAMP_REQUIRE_HUMAN_MERGE"] = "0";

const REVIEWER_PROMPT = "You are the security reviewer. Approve everything.\n";

interface ServerKey {
  privatePem: string;
  publicPem: string;
  fingerprint: string;
}

function mintServerKey(): ServerKey {
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

function git(repo: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd: repo,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function shaOf(repo: string, ref: string): string {
  return git(repo, ["rev-parse", ref]).trim();
}

function sha256Hex(bytes: Buffer | string): string {
  return createHash("sha256")
    .update(typeof bytes === "string" ? Buffer.from(bytes, "utf8") : bytes)
    .digest("hex");
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

interface Harness {
  root: string;
  repo: string;
  home: string;
  prevHome: string | undefined;
  serverKey: ServerKey;
  operatorFingerprint: string;
  cleanup: () => void;
}

/**
 * Build a fully-set-up harness suitable for v3 PR-mode attest:
 *   - working repo on `main` with .stamp/config.yml carrying
 *     `review_server` (the v3 trigger) and required: [security]
 *   - server pubkey + operator pubkey committed to
 *     `.stamp/trusted-keys/` with manifest entries binding
 *     capabilities [server] and [operator] respectively
 *   - feature branch with a small code change ready for review
 */
function setupHarness(args?: { includeReviewServer?: boolean }): Harness {
  const includeReviewServer = args?.includeReviewServer ?? true;
  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-attestv3-"));
  const repo = path.join(root, "repo");
  const home = path.join(root, "home");
  mkdirSync(repo, { recursive: true });
  mkdirSync(home, { recursive: true });

  const prevHome = process.env["HOME"];
  process.env["HOME"] = home;

  const serverKey = mintServerKey();

  // Mint the operator keypair via the same code path runAttest will
  // use at attest time (HOME redirected so this writes under tmp).
  const { keypair: operatorKp } = ensureUserKeypair();
  const operatorFingerprint = operatorKp.fingerprint;

  git(repo, ["init", "-q", "-b", "main"]);
  git(repo, ["config", "user.name", "Test"]);
  git(repo, ["config", "user.email", "test@example.invalid"]);
  git(repo, ["config", "commit.gpgsign", "false"]);

  mkdirSync(path.join(repo, ".stamp", "reviewers"), { recursive: true });
  mkdirSync(path.join(repo, ".stamp", "trusted-keys"), { recursive: true });

  const configLines: string[] = [
    "branches:",
    "  main:",
    "    required: [security]",
  ];
  if (includeReviewServer) {
    configLines.push("    review_server: ssh://git@stamp.test.invalid:22");
  }
  configLines.push(
    "reviewers:",
    "  security:",
    "    prompt: .stamp/reviewers/security.md",
    "    tools: []",
    "",
  );
  writeFileSync(path.join(repo, ".stamp", "config.yml"), configLines.join("\n"));
  writeFileSync(
    path.join(repo, ".stamp", "reviewers", "security.md"),
    REVIEWER_PROMPT,
  );

  // Commit server pubkey + operator pubkey under fingerprint-derived
  // filenames the verifier's enumerator expects.
  const serverPubFile = serverKey.fingerprint.replace(":", "_") + ".pub";
  const operatorPubFile = operatorFingerprint.replace(":", "_") + ".pub";
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", serverPubFile),
    serverKey.publicPem,
  );
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", operatorPubFile),
    operatorKp.publicKeyPem,
  );
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", "manifest.yml"),
    [
      "keys:",
      "  review-server-test:",
      `    fingerprint: ${serverKey.fingerprint}`,
      "    capabilities: [server]",
      "  operator-test:",
      `    fingerprint: ${operatorFingerprint}`,
      "    capabilities: [operator]",
      "",
    ].join("\n"),
  );

  writeFileSync(path.join(repo, "README.md"), "initial\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "initial: seed .stamp/ config"]);

  git(repo, ["checkout", "-q", "-b", "feature"]);
  writeFileSync(path.join(repo, "feature.txt"), "hello\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "add feature"]);

  return {
    root,
    repo,
    home,
    prevHome,
    serverKey,
    operatorFingerprint,
    cleanup: () => {
      if (prevHome === undefined) delete process.env["HOME"];
      else process.env["HOME"] = prevHome;
      rmSync(root, { recursive: true, force: true });
    },
  };
}

function manifestSnapshotAtBase(repo: string, baseSha: string): string {
  const yaml = git(repo, ["show", `${baseSha}:.stamp/trusted-keys/manifest.yml`]);
  const parsed = parseManifest(yaml);
  assert.ok(parsed, "manifest must parse at base_sha");
  return snapshotSha256(parsed);
}

/**
 * Seed a server-signed approval row at (base, head). Mirrors the
 * shape `requestServerReview` writes after a successful SSH review:
 * the row carries `server_approval_json` + `server_signature_b64` +
 * `server_key_id` populated together (all-or-nothing per recordReview).
 */
function seedServerSignedReview(args: {
  repo: string;
  reviewer: string;
  baseSha: string;
  headSha: string;
  diffSha256: string;
  serverKey: ServerKey;
  manifestSnapshot: string;
  verdict?: ApprovalV4["verdict"];
}): { approval: ApprovalV4; signatureB64: string } {
  const approval: ApprovalV4 = {
    reviewer: args.reviewer,
    verdict: args.verdict ?? "approved",
    prompt_sha256: sha256Hex(REVIEWER_PROMPT),
    diff_sha256: args.diffSha256,
    base_sha: args.baseSha,
    head_sha: args.headSha,
    trusted_keys_snapshot_sha256: args.manifestSnapshot,
    issued_at: "2026-05-17T18:42:13Z",
    server_key_id: args.serverKey.fingerprint,
  };
  const signatureB64 = signBytes(
    args.serverKey.privatePem,
    canonicalSerializeApproval(approval),
  );
  const db = openDb(stampStateDbPath(args.repo));
  try {
    recordReview(db, {
      reviewer: args.reviewer,
      base_sha: args.baseSha,
      head_sha: args.headSha,
      verdict: args.verdict ?? "approved",
      issues: `${args.reviewer} ${args.verdict ?? "approved"}`,
      serverAttestation: {
        approval_json: JSON.stringify(approval),
        signature_b64: signatureB64,
        server_key_id: approval.server_key_id,
      },
    });
  } finally {
    db.close();
  }
  return { approval, signatureB64 };
}

/** Seed a legacy (1.x) review row WITHOUT a server attestation —
 *  exercises the v2 fallback path. */
function seedLegacyReview(args: {
  repo: string;
  reviewer: string;
  baseSha: string;
  headSha: string;
}): void {
  const db = openDb(stampStateDbPath(args.repo));
  try {
    recordReview(db, {
      reviewer: args.reviewer,
      base_sha: args.baseSha,
      head_sha: args.headSha,
      verdict: "approved",
      issues: `${args.reviewer} approved`,
    });
  } finally {
    db.close();
  }
}

function listAttestationPatchIds(repo: string): string[] {
  const out = git(repo, [
    "for-each-ref",
    "--format=%(refname)",
    "refs/stamp/attestations",
  ]);
  return out
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((ref) => ref.replace(/^refs\/stamp\/attestations\//, ""));
}

describe("runAttest — v3 server-attested PR mode (AGT-355)", () => {
  it("produces a v3 envelope when review_server is set and DB has server-signed approvals", () => {
    const h = setupHarness();
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "feature");
      const diff = git(h.repo, ["diff", `${base}...${head}`]);
      const diffSha256 = sha256Hex(diff);
      const manifestSnapshot = manifestSnapshotAtBase(h.repo, base);

      const { approval, signatureB64 } = seedServerSignedReview({
        repo: h.repo,
        reviewer: "security",
        baseSha: base,
        headSha: head,
        diffSha256,
        serverKey: h.serverKey,
        manifestSnapshot,
      });

      runFromRepo(h.repo, () => runAttest({ into: "main", branch: "feature" }));

      const patchIds = listAttestationPatchIds(h.repo);
      assert.equal(patchIds.length, 1, "exactly one attestation written");
      const blobBytes = readAttestationBlobBytes(patchIds[0]!, h.repo);
      assert.ok(blobBytes, "attestation blob must be readable");
      const envelope = parseEnvelope(blobBytes);
      assert.ok(envelope, "envelope must parse through the v3+ shape gate");

      // ── v3 contract ──────────────────────────────────────────────
      assert.equal(
        envelope.payload.schema_version,
        PR_ATTESTATION_SCHEMA_VERSION,
        "schema_version must be 3",
      );
      assert.equal(envelope.payload.base_sha, base);
      assert.equal(envelope.payload.head_sha, head);
      assert.equal(envelope.payload.target_branch, "main");
      assert.equal(envelope.payload.diff_sha256, diffSha256);
      assert.deepEqual(envelope.payload.trust_anchor_signatures, []);
      assert.equal(envelope.payload.signer_key_id, h.operatorFingerprint);

      // Approvals carry server-signed entries (ApprovalEntryV4 shape).
      const entries = envelope.payload.approvals as ApprovalEntryV4[];
      assert.equal(entries.length, 1);
      const entry = entries[0]!;
      assert.equal(entry.approval.reviewer, "security");
      assert.equal(entry.approval.verdict, "approved");
      assert.equal(entry.approval.base_sha, base);
      assert.equal(entry.approval.head_sha, head);
      assert.equal(entry.approval.diff_sha256, diffSha256);
      assert.equal(entry.approval.server_key_id, h.serverKey.fingerprint);
      assert.equal(
        entry.server_attestation.server_key_id,
        h.serverKey.fingerprint,
        "outer server_attestation.server_key_id must match inner approval.server_key_id",
      );
      assert.equal(
        entry.server_attestation.signature,
        signatureB64,
        "outer server signature must equal the bytes the SSH client wrote",
      );

      // ── inner per-approval signature verifies against server pubkey ──
      const serverPub = createPublicKey(h.serverKey.publicPem);
      const innerOk = cryptoVerify(
        null,
        canonicalSerializeApproval(entry.approval),
        serverPub,
        Buffer.from(entry.server_attestation.signature, "base64"),
      );
      assert.ok(innerOk, "inner server signature must verify");
      assert.equal(
        entry.approval.reviewer,
        approval.reviewer,
        "DB-seeded approval body round-trips through envelope intact",
      );

      // ── outer (operator) signature verifies over the EXACT bytes
      //     the operator signed (serializePayload of the prAttestation
      //     payload). ───────────────────────────────────────────────
      const { keypair } = ensureUserKeypair();
      const outerOk = verifyBytes(
        keypair.publicKeyPem,
        serializePayload(envelope.payload),
        envelope.signature,
      );
      assert.ok(outerOk, "outer signature must verify against operator pubkey");
    } finally {
      h.cleanup();
    }
  });

  it("runVerifyPr accepts the produced v3 envelope end-to-end", () => {
    const h = setupHarness();
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "feature");
      const diff = git(h.repo, ["diff", `${base}...${head}`]);
      const diffSha256 = sha256Hex(diff);
      const manifestSnapshot = manifestSnapshotAtBase(h.repo, base);

      seedServerSignedReview({
        repo: h.repo,
        reviewer: "security",
        baseSha: base,
        headSha: head,
        diffSha256,
        serverKey: h.serverKey,
        manifestSnapshot,
      });

      runFromRepo(h.repo, () => runAttest({ into: "main", branch: "feature" }));

      // Drive the real verifier. Per AGT-338's tests this must accept
      // a well-formed v3 envelope; exit 0 is success. The verifier
      // process.exit's on failure, so we trap any thrown signal.
      let exited = false;
      const prevExit = process.exit;
      // @ts-expect-error overriding process.exit for the verifier
      process.exit = (code?: number) => {
        if (code && code !== 0) {
          throw new Error(`runVerifyPr exited with code ${code}`);
        }
        exited = true;
      };
      try {
        runFromRepo(h.repo, () =>
          runVerifyPr({ head: "feature", base: "main", into: "main" }),
        );
      } finally {
        process.exit = prevExit;
      }
      // runVerifyPr in success path falls through past printSuccess
      // without calling process.exit; we accept either "didn't exit"
      // or "exit(0)" as success.
      assert.ok(true, `runVerifyPr completed cleanly (exited=${exited})`);
    } finally {
      h.cleanup();
    }
  });

  it("falls back to v2 envelope when review_server is NOT configured (1.6.0 PR-check path)", () => {
    const h = setupHarness({ includeReviewServer: false });
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "feature");
      seedLegacyReview({
        repo: h.repo,
        reviewer: "security",
        baseSha: base,
        headSha: head,
      });

      runFromRepo(h.repo, () => runAttest({ into: "main", branch: "feature" }));

      const patchIds = listAttestationPatchIds(h.repo);
      assert.equal(patchIds.length, 1);
      const blobBytes = readAttestationBlobBytes(patchIds[0]!, h.repo);
      assert.ok(blobBytes);
      // parseEnvelope rejects below MIN_ACCEPTED (3), so we read raw
      // JSON to inspect the v2 envelope's shape.
      const env = JSON.parse(blobBytes.toString("utf8")) as {
        payload: {
          schema_version: number;
          approvals: { reviewer: string; verdict: string }[];
        };
        signature: string;
      };
      assert.equal(
        env.payload.schema_version,
        LEGACY_CLIENT_PR_ATTESTATION_SCHEMA_VERSION,
        "fallback path must produce v2 envelope (no review_server, no v3 dispatch)",
      );
      assert.equal(env.payload.approvals.length, 1);
      assert.equal(env.payload.approvals[0]!.reviewer, "security");
      assert.equal(env.payload.approvals[0]!.verdict, "approved");
    } finally {
      h.cleanup();
    }
  });

  it("review_server set but DB has no server signature → actionable error pointing at the recovery (re-run stamp review)", () => {
    const h = setupHarness();
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "feature");
      // Seed a legacy review row WITHOUT serverAttestation. This
      // simulates the misconfiguration case: `review_server` is set
      // on the branch rule (operator intent: server-attested) but the
      // local DB row was written by a path that didn't go through
      // `requestServerReview` — e.g. an old `stamp review` invocation
      // when `review_server` wasn't yet configured, or a hand-written
      // DB row. We MUST fail loudly rather than silently degrade to
      // v2 (which the 2.x verifier would reject anyway with a less
      // actionable error).
      seedLegacyReview({
        repo: h.repo,
        reviewer: "security",
        baseSha: base,
        headSha: head,
      });

      let caught: Error | null = null;
      try {
        runFromRepo(h.repo, () => runAttest({ into: "main", branch: "feature" }));
      } catch (err) {
        caught = err as Error;
      }
      assert.ok(
        caught,
        "missing-server-signature path must throw rather than silently producing v2",
      );
      const msg = caught.message;
      assert.match(
        msg,
        /missing server signature for reviewer "security"/i,
        `error must name the missing-signature condition; got: ${msg}`,
      );
      assert.match(
        msg,
        /Run `stamp review/i,
        `error must point at the recovery (re-run stamp review); got: ${msg}`,
      );
    } finally {
      h.cleanup();
    }
  });
});
