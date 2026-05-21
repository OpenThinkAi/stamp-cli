/**
 * WS1 — `stamp attest` PR-mode admin trust-anchor signature collection.
 *
 * Drives `runAttest` against a fixture repo whose feature branch
 * touches `.stamp/**`, with one or more admin signatures pre-seeded
 * into the trust-anchor notes-ref (the artifact `stamp admin sign
 * --pending` writes). Asserts:
 *
 *   1. The resulting v3 envelope carries the collected signatures in
 *      `trust_anchor_signatures`.
 *   2. The signatures verify end-to-end through the shared
 *      `verifyV4TrustAnchorSignatures` + `verifyV4StampPathsGuard`
 *      phases — the same code path the GH Action verifier runs.
 *   3. Non-`.stamp/**` diffs are short-circuited to `[]` (no
 *      regression for the common case).
 *   4. Missing / stale / non-admin signatures all surface actionable
 *      errors before the envelope is signed.
 *
 * Co-located with `tests/attestServerSignedFlow.test.ts` (general v3
 * PR-mode envelope assembly) and `tests/v4Roundtrip.test.ts` (verifier
 * phase-by-phase coverage). This file focuses solely on the trust-
 * anchor collection surface AGT-355 left as a TODO.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { parse as parseYaml } from "yaml";

import { runAttest } from "../src/commands/attest.ts";
import {
  canonicalSerializeApproval,
  type ApprovalEntryV4,
  type ApprovalV4,
  type AttestationPayloadV4,
  type CheckAttestationV4,
  type TrustAnchorSignatureV4,
} from "../src/lib/attestationV4.ts";
import { openDb, recordReview } from "../src/lib/db.ts";
import {
  ensureUserKeypair,
  fingerprintFromPem,
} from "../src/lib/keys.ts";
import { stampStateDbPath } from "../src/lib/paths.ts";
import {
  parseEnvelope,
  readAttestationBlobBytes,
  PR_ATTESTATION_SCHEMA_VERSION,
} from "../src/lib/prAttestation.ts";
// PR-mode admin sigs use the PR envelope's schema_version (3) — see
// trustAnchorPayload.ts's `schemaVersion` field doc for rationale.
import { signBytes } from "../src/lib/signing.ts";
import {
  emptyNote,
  noteWithAppendedSignature,
  readNote,
  writeNote,
} from "../src/lib/trustAnchorNotes.ts";
import { trustAnchorSigningBytes } from "../src/lib/trustAnchorPayload.ts";
import {
  parseManifest,
  snapshotSha256,
} from "../src/lib/trustedKeysManifest.ts";
import { buildPubkeyMap } from "../src/lib/sshReviewClient.ts";
import {
  parsePathRules,
  verifyV4StampPathsGuard,
  verifyV4TrustAnchorSignatures,
  type PathRule,
  type PhaseInputV4,
} from "../src/lib/v4Trust.ts";

// runAttest doesn't call requireHumanMerge but be defensive in case a
// future change pulls it in (matches the sibling tests' posture).
process.env["STAMP_REQUIRE_HUMAN_MERGE"] = "0";

const REVIEWER_PROMPT = "You are the security reviewer. Approve everything.\n";

interface Ed25519Key {
  privatePem: string;
  publicPem: string;
  fingerprint: string;
}

function mintEd25519Key(): Ed25519Key {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();
  const publicPem = publicKey
    .export({ type: "spki", format: "pem" })
    .toString();
  return { privatePem, publicPem, fingerprint: fingerprintFromPem(publicPem) };
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

/**
 * Harness setup: a repo with one or more admin keys + a server key
 * already in the base-sha manifest, a feature branch whose diff
 * touches `.stamp/**` (so the `.stamp/**` path-rule matches), and a
 * server-signed review row seeded for the required reviewer.
 *
 * `pathRulesYaml` is folded into `.stamp/config.yml` at base so the
 * collector finds it the same way the verifier will.
 *
 * Caveat: the operator's keypair is minted under a redirected $HOME
 * via `ensureUserKeypair`. The same fingerprint must end up listed in
 * the manifest before the initial commit, so we mint it first and
 * THEN write `.stamp/`.
 */
interface AdminHarness {
  root: string;
  repo: string;
  home: string;
  prevHome: string | undefined;
  serverKey: Ed25519Key;
  adminKeys: Ed25519Key[];
  operatorFingerprint: string;
  cleanup: () => void;
}

interface SetupArgs {
  /** Number of admin keys to commit into the manifest. Each gets a
   *  .pub file and a `capabilities: [admin]` entry. */
  adminCount: number;
  /** Override path_rules in .stamp/config.yml. Defaults to the
   *  canonical `.stamp/**` rule used by Shape 4 repos. */
  pathRules?: string;
  /** If true, the feature branch additionally edits a `.stamp/**`
   *  file so the path-rule matches. */
  touchStamp: boolean;
}

function setupHarness(args: SetupArgs): AdminHarness {
  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-ws1-prmode-"));
  const repo = path.join(root, "repo");
  const home = path.join(root, "home");
  mkdirSync(repo, { recursive: true });
  mkdirSync(home, { recursive: true });

  const prevHome = process.env["HOME"];
  process.env["HOME"] = home;

  const serverKey = mintEd25519Key();
  const adminKeys: Ed25519Key[] = [];
  for (let i = 0; i < args.adminCount; i++) adminKeys.push(mintEd25519Key());

  // Operator keypair via the same path runAttest will use. HOME is
  // already redirected so this lands under tmp.
  const { keypair: operatorKp } = ensureUserKeypair();
  const operatorFingerprint = operatorKp.fingerprint;

  git(repo, ["init", "-q", "-b", "main"]);
  git(repo, ["config", "user.name", "Test"]);
  git(repo, ["config", "user.email", "test@example.invalid"]);
  git(repo, ["config", "commit.gpgsign", "false"]);

  mkdirSync(path.join(repo, ".stamp", "reviewers"), { recursive: true });
  mkdirSync(path.join(repo, ".stamp", "trusted-keys"), { recursive: true });

  const pathRulesYaml = args.pathRules ??
    `path_rules:
  ".stamp/**":
    require_capability: admin
    minimum_signatures: 1
    bypass_review_cycle: true
`;

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
      pathRulesYaml,
    ].join("\n"),
  );
  writeFileSync(
    path.join(repo, ".stamp", "reviewers", "security.md"),
    REVIEWER_PROMPT,
  );

  // Server pubkey + operator pubkey + admin pubkeys, manifest entries
  // binding their capabilities. Filename mirrors what the verifier's
  // enumerator expects (fingerprint with colon replaced by underscore).
  const writePub = (k: Ed25519Key): string => {
    const file = k.fingerprint.replace(":", "_") + ".pub";
    writeFileSync(path.join(repo, ".stamp", "trusted-keys", file), k.publicPem);
    return file;
  };
  writePub(serverKey);
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", operatorFingerprint.replace(":", "_") + ".pub"),
    operatorKp.publicKeyPem,
  );
  for (const a of adminKeys) writePub(a);

  const manifestLines = [
    "keys:",
    "  review-server-test:",
    `    fingerprint: ${serverKey.fingerprint}`,
    "    capabilities: [server]",
    "  operator-test:",
    `    fingerprint: ${operatorFingerprint}`,
    "    capabilities: [operator]",
  ];
  adminKeys.forEach((a, i) => {
    manifestLines.push(`  admin-${i}:`);
    manifestLines.push(`    fingerprint: ${a.fingerprint}`);
    manifestLines.push(`    capabilities: [admin]`);
  });
  manifestLines.push("");
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", "manifest.yml"),
    manifestLines.join("\n"),
  );

  writeFileSync(path.join(repo, "README.md"), "initial\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "initial: seed .stamp/ config"]);

  git(repo, ["checkout", "-q", "-b", "feature"]);
  writeFileSync(path.join(repo, "feature.txt"), "hello\n");
  if (args.touchStamp) {
    // A trivial .stamp/** edit — enough to make the changed-files set
    // intersect the `.stamp/**` path-rule.
    writeFileSync(path.join(repo, ".stamp", "reviewers", "security.md"), REVIEWER_PROMPT + "edited\n");
  }
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "feature change"]);

  return {
    root,
    repo,
    home,
    prevHome,
    serverKey,
    adminKeys,
    operatorFingerprint,
    cleanup: () => {
      if (prevHome === undefined) delete process.env["HOME"];
      else process.env["HOME"] = prevHome;
      rmSync(root, { recursive: true, force: true });
    },
  };
}

/** Seed a server-signed approval row mirroring what
 *  `requestServerReview` writes after a successful SSH review. */
function seedServerSignedReview(args: {
  repo: string;
  reviewer: string;
  baseSha: string;
  headSha: string;
  diffSha256: string;
  serverKey: Ed25519Key;
}): { approval: ApprovalV4; entry: ApprovalEntryV4 } {
  const approval: ApprovalV4 = {
    reviewer: args.reviewer,
    verdict: "approved",
    prompt_sha256: sha256Hex(REVIEWER_PROMPT),
    diff_sha256: args.diffSha256,
    base_sha: args.baseSha,
    head_sha: args.headSha,
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
      verdict: "approved",
      issues: `${args.reviewer} approved`,
      serverAttestation: {
        approval_json: JSON.stringify(approval),
        signature_b64: signatureB64,
        server_key_id: approval.server_key_id,
      },
    });
  } finally {
    db.close();
  }
  return {
    approval,
    entry: {
      approval,
      server_attestation: {
        server_key_id: approval.server_key_id,
        signature: signatureB64,
      },
    },
  };
}

/**
 * Pre-seed an admin signature into the trust-anchor notes-ref keyed
 * by the feature-branch head SHA — exactly what `stamp admin sign
 * --pending` would write. Admins sign `trustAnchorSigningBytes` (the
 * v4 payload with trust_anchor_signatures: []), which is the same
 * target the collector + verifier both check against.
 *
 * `payloadOverrides` lets a test deliberately make the signature
 * stale (e.g. signing against a different diff_sha256) so we exercise
 * the "stale signature" rejection.
 */
function seedAdminSignature(args: {
  repo: string;
  baseSha: string;
  headSha: string;
  targetBranch: string;
  diffSha256: string;
  manifestSnapshotSha256: string;
  approvals: ApprovalEntryV4[];
  checks: CheckAttestationV4[];
  operatorFingerprint: string;
  admin: Ed25519Key;
  /** Bytes the admin signs over. Default is the canonical signing
   *  target; override to forge a stale signature. */
  signingTargetOverride?: Buffer;
}): { signatureB64: string } {
  const signingTarget = args.signingTargetOverride ?? trustAnchorSigningBytes({
    baseSha: args.baseSha,
    headSha: args.headSha,
    targetBranch: args.targetBranch,
    diffSha256: args.diffSha256,
    manifestSnapshotSha256: args.manifestSnapshotSha256,
    approvals: args.approvals,
    checks: args.checks,
    signerKeyId: args.operatorFingerprint,
    // PR-mode: match the schema_version the verifier reads from the
    // wire envelope (3, not the v4-trailer's 5).
    schemaVersion: PR_ATTESTATION_SCHEMA_VERSION,
  });
  const signatureB64 = signBytes(args.admin.privatePem, signingTarget);

  // Append to the notes-ref the same way `stamp admin sign --pending`
  // would — read-modify-write through noteWithAppendedSignature so
  // multi-admin tests can stack signatures.
  const existing = readNote(args.repo, args.headSha);
  const note = existing ?? emptyNote({
    head_sha: args.headSha,
    base_sha: args.baseSha,
    diff_sha256: args.diffSha256,
    target_branch: args.targetBranch,
  });
  const { note: updated } = noteWithAppendedSignature(note, {
    signer_key_id: args.admin.fingerprint,
    signature: signatureB64,
  });
  writeNote(args.repo, args.headSha, updated);
  return { signatureB64 };
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

/** Construct a PhaseInputV4 from a produced v3 envelope, suitable for
 *  driving the trust-anchor + path-rules verifier phases standalone.
 *  Mirrors `runVerifyPr`'s wiring (in `src/commands/verifyPr.ts`). */
function buildPhaseInputForEnvelope(args: {
  repo: string;
  envelopePayload: {
    base_sha: string;
    head_sha: string;
    target_branch: string;
    diff_sha256: string;
    manifest_snapshot_sha256: string;
    approvals: ApprovalEntryV4[];
    checks: CheckAttestationV4[];
    trust_anchor_signatures: TrustAnchorSignatureV4[];
    signer_key_id: string;
    schema_version: number;
  };
  signatureB64: string;
}): PhaseInputV4 {
  const payloadV4: AttestationPayloadV4 = {
    schema_version: args.envelopePayload.schema_version,
    base_sha: args.envelopePayload.base_sha,
    head_sha: args.envelopePayload.head_sha,
    target_branch: args.envelopePayload.target_branch,
    diff_sha256: args.envelopePayload.diff_sha256,
    manifest_snapshot_sha256: args.envelopePayload.manifest_snapshot_sha256,
    approvals: args.envelopePayload.approvals,
    checks: args.envelopePayload.checks,
    trust_anchor_signatures: args.envelopePayload.trust_anchor_signatures,
    signer_key_id: args.envelopePayload.signer_key_id,
  };
  const manifestYaml = git(args.repo, [
    "show",
    `${payloadV4.base_sha}:.stamp/trusted-keys/manifest.yml`,
  ]);
  const manifest = parseManifest(manifestYaml);
  assert.ok(manifest, "manifest at base_sha must parse");

  const lsOut = git(args.repo, [
    "ls-tree",
    "--name-only",
    payloadV4.base_sha,
    ".stamp/trusted-keys/",
  ]);
  const pubFiles = lsOut
    .split("\n")
    .filter((l) => l.length > 0)
    .map((l) => l.replace(/^\.stamp\/trusted-keys\//, ""))
    .filter((n) => n.endsWith(".pub"));
  const pubkeyByFingerprint = buildPubkeyMap(pubFiles, (relPath) =>
    git(args.repo, ["show", `${payloadV4.base_sha}:${relPath}`]),
  );

  // path_rules at base_sha — same source-of-truth as the verifier.
  const configYaml = git(args.repo, [
    "show",
    `${payloadV4.base_sha}:.stamp/config.yml`,
  ]);
  let pathRules: PathRule[] = [];
  const rawCfg = parseYaml(configYaml) as { path_rules?: unknown } | null;
  if (rawCfg && typeof rawCfg === "object") {
    pathRules = parsePathRules(rawCfg.path_rules).rules;
  }

  const diffOut = git(args.repo, [
    "diff",
    "--name-only",
    "-z",
    `${payloadV4.base_sha}...${payloadV4.head_sha}`,
  ]);
  const changedFiles = diffOut.split("\0").filter((s) => s.length > 0);

  // payloadBytes is the v4 canonical bytes — used by the outer-sig
  // phase. Not needed by trust-anchor / paths-guard phases, but the
  // interface requires it. Leave empty Buffer; the phases we drive
  // here don't read it.
  return {
    sha: payloadV4.head_sha, // synthetic — verifier uses for error context only here
    branch: payloadV4.target_branch,
    rule: { required: ["security"] },
    payload: payloadV4,
    payloadBytes: Buffer.alloc(0),
    signatureBase64: args.signatureB64,
    manifest,
    pubkeyByFingerprint,
    pathRules,
    changedFiles,
  };
}

describe("WS1 — stamp attest PR-mode admin trust-anchor signatures", () => {
  it("solo admin: a .stamp/** diff produces a v3 envelope carrying the admin signature, and the verifier accepts it", () => {
    const h = setupHarness({ adminCount: 1, touchStamp: true });
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "feature");
      const diff = git(h.repo, ["diff", `${base}...${head}`]);
      const diffSha256 = sha256Hex(diff);
      const manifest = parseManifest(
        git(h.repo, ["show", `${base}:.stamp/trusted-keys/manifest.yml`]),
      );
      assert.ok(manifest);
      const manifestSnapshot = snapshotSha256(manifest);

      const { entry } = seedServerSignedReview({
        repo: h.repo,
        reviewer: "security",
        baseSha: base,
        headSha: head,
        diffSha256,
        serverKey: h.serverKey,
      });

      seedAdminSignature({
        repo: h.repo,
        baseSha: base,
        headSha: head,
        targetBranch: "main",
        diffSha256,
        manifestSnapshotSha256: manifestSnapshot,
        approvals: [entry],
        checks: [],
        operatorFingerprint: h.operatorFingerprint,
        admin: h.adminKeys[0]!,
      });

      runFromRepo(h.repo, () => runAttest({ into: "main", branch: "feature" }));

      const patchIds = listAttestationPatchIds(h.repo);
      assert.equal(patchIds.length, 1);
      const blobBytes = readAttestationBlobBytes(patchIds[0]!, h.repo);
      assert.ok(blobBytes);
      const envelope = parseEnvelope(blobBytes);
      assert.ok(envelope);
      assert.equal(envelope.payload.schema_version, PR_ATTESTATION_SCHEMA_VERSION);
      assert.equal(envelope.payload.trust_anchor_signatures.length, 1);
      const ts = envelope.payload.trust_anchor_signatures[0]!;
      assert.equal(ts.signer_key_id, h.adminKeys[0]!.fingerprint);
      assert.ok(typeof ts.signature === "string" && ts.signature.length > 0);

      // Drive the verifier phases directly. If these pass, the GH
      // Action will accept the envelope: same code path.
      const phaseInput = buildPhaseInputForEnvelope({
        repo: h.repo,
        envelopePayload: {
          ...envelope.payload,
          approvals: envelope.payload.approvals as ApprovalEntryV4[],
          checks: envelope.payload.checks as CheckAttestationV4[],
          trust_anchor_signatures: envelope.payload.trust_anchor_signatures as TrustAnchorSignatureV4[],
          diff_sha256: envelope.payload.diff_sha256!,
          manifest_snapshot_sha256: envelope.payload.manifest_snapshot_sha256!,
        },
        signatureB64: envelope.signature,
      });
      const sigsResult = verifyV4TrustAnchorSignatures(phaseInput);
      assert.ok(sigsResult.ok, `verifyV4TrustAnchorSignatures: ${"reason" in sigsResult ? sigsResult.reason : ""}`);
      const guardResult = verifyV4StampPathsGuard(phaseInput);
      assert.ok(guardResult.ok, `verifyV4StampPathsGuard: ${"reason" in guardResult ? guardResult.reason : ""}`);
    } finally {
      h.cleanup();
    }
  });

  it("multi-admin: two admin signatures satisfy minimum_signatures: 2 and both land in the envelope", () => {
    const customRules = `path_rules:
  ".stamp/**":
    require_capability: admin
    minimum_signatures: 2
    bypass_review_cycle: true
`;
    const h = setupHarness({ adminCount: 2, touchStamp: true, pathRules: customRules });
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "feature");
      const diff = git(h.repo, ["diff", `${base}...${head}`]);
      const diffSha256 = sha256Hex(diff);
      const manifest = parseManifest(
        git(h.repo, ["show", `${base}:.stamp/trusted-keys/manifest.yml`]),
      );
      assert.ok(manifest);
      const manifestSnapshot = snapshotSha256(manifest);

      const { entry } = seedServerSignedReview({
        repo: h.repo,
        reviewer: "security",
        baseSha: base,
        headSha: head,
        diffSha256,
        serverKey: h.serverKey,
      });

      for (const admin of h.adminKeys) {
        seedAdminSignature({
          repo: h.repo,
          baseSha: base,
          headSha: head,
          targetBranch: "main",
          diffSha256,
          manifestSnapshotSha256: manifestSnapshot,
          approvals: [entry],
          checks: [],
          operatorFingerprint: h.operatorFingerprint,
          admin,
        });
      }

      runFromRepo(h.repo, () => runAttest({ into: "main", branch: "feature" }));

      const patchIds = listAttestationPatchIds(h.repo);
      assert.equal(patchIds.length, 1);
      const blobBytes = readAttestationBlobBytes(patchIds[0]!, h.repo);
      assert.ok(blobBytes);
      const envelope = parseEnvelope(blobBytes);
      assert.ok(envelope);
      const ts = envelope.payload.trust_anchor_signatures as TrustAnchorSignatureV4[];
      assert.equal(ts.length, 2);
      const collected = new Set(ts.map((s) => s.signer_key_id));
      for (const admin of h.adminKeys) {
        assert.ok(collected.has(admin.fingerprint), `${admin.fingerprint} missing from collected sigs`);
      }

      const phaseInput = buildPhaseInputForEnvelope({
        repo: h.repo,
        envelopePayload: {
          ...envelope.payload,
          approvals: envelope.payload.approvals as ApprovalEntryV4[],
          checks: envelope.payload.checks as CheckAttestationV4[],
          trust_anchor_signatures: ts,
          diff_sha256: envelope.payload.diff_sha256!,
          manifest_snapshot_sha256: envelope.payload.manifest_snapshot_sha256!,
        },
        signatureB64: envelope.signature,
      });
      assert.ok(verifyV4TrustAnchorSignatures(phaseInput).ok);
      assert.ok(verifyV4StampPathsGuard(phaseInput).ok);
    } finally {
      h.cleanup();
    }
  });

  it("non-.stamp/** diff: trust_anchor_signatures is empty and the envelope verifies cleanly", () => {
    const h = setupHarness({ adminCount: 1, touchStamp: false });
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "feature");
      const diff = git(h.repo, ["diff", `${base}...${head}`]);
      const diffSha256 = sha256Hex(diff);

      seedServerSignedReview({
        repo: h.repo,
        reviewer: "security",
        baseSha: base,
        headSha: head,
        diffSha256,
        serverKey: h.serverKey,
      });

      runFromRepo(h.repo, () => runAttest({ into: "main", branch: "feature" }));

      const patchIds = listAttestationPatchIds(h.repo);
      assert.equal(patchIds.length, 1);
      const blobBytes = readAttestationBlobBytes(patchIds[0]!, h.repo);
      assert.ok(blobBytes);
      const envelope = parseEnvelope(blobBytes);
      assert.ok(envelope);
      assert.deepEqual(envelope.payload.trust_anchor_signatures, []);

      // Guard still no-ops because no rule matches a non-.stamp diff.
      const phaseInput = buildPhaseInputForEnvelope({
        repo: h.repo,
        envelopePayload: {
          ...envelope.payload,
          approvals: envelope.payload.approvals as ApprovalEntryV4[],
          checks: envelope.payload.checks as CheckAttestationV4[],
          trust_anchor_signatures: [],
          diff_sha256: envelope.payload.diff_sha256!,
          manifest_snapshot_sha256: envelope.payload.manifest_snapshot_sha256!,
        },
        signatureB64: envelope.signature,
      });
      assert.ok(verifyV4TrustAnchorSignatures(phaseInput).ok);
      assert.ok(verifyV4StampPathsGuard(phaseInput).ok);
    } finally {
      h.cleanup();
    }
  });

  it("missing signatures: .stamp/** diff with no admin signatures throws an actionable error before envelope is signed", () => {
    const h = setupHarness({ adminCount: 1, touchStamp: true });
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "feature");
      const diff = git(h.repo, ["diff", `${base}...${head}`]);
      const diffSha256 = sha256Hex(diff);
      seedServerSignedReview({
        repo: h.repo,
        reviewer: "security",
        baseSha: base,
        headSha: head,
        diffSha256,
        serverKey: h.serverKey,
      });

      // Deliberately do NOT seed an admin signature.
      let caught: Error | null = null;
      try {
        runFromRepo(h.repo, () => runAttest({ into: "main", branch: "feature" }));
      } catch (err) {
        caught = err as Error;
      }
      assert.ok(caught, "missing-sigs case must throw");
      assert.match(caught.message, /requires 1 admin signature/);
      assert.match(caught.message, /stamp admin sign --pending/);
      assert.match(caught.message, /re-run `stamp attest`/);
      // No envelope should have been written.
      assert.equal(listAttestationPatchIds(h.repo).length, 0);
    } finally {
      h.cleanup();
    }
  });

  it("stale signature: an admin signature against a different diff_sha256 is rejected with a 're-sign' error", () => {
    const h = setupHarness({ adminCount: 1, touchStamp: true });
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "feature");
      const diff = git(h.repo, ["diff", `${base}...${head}`]);
      const diffSha256 = sha256Hex(diff);
      const manifest = parseManifest(
        git(h.repo, ["show", `${base}:.stamp/trusted-keys/manifest.yml`]),
      );
      assert.ok(manifest);
      const manifestSnapshot = snapshotSha256(manifest);
      const { entry } = seedServerSignedReview({
        repo: h.repo,
        reviewer: "security",
        baseSha: base,
        headSha: head,
        diffSha256,
        serverKey: h.serverKey,
      });

      // Sign over the WRONG bytes — different diff_sha256 simulates a
      // rebased base after the admin signed.
      const staleTarget = trustAnchorSigningBytes({
        baseSha: base,
        headSha: head,
        targetBranch: "main",
        diffSha256: "0".repeat(64),
        manifestSnapshotSha256: manifestSnapshot,
        approvals: [entry],
        checks: [],
        signerKeyId: h.operatorFingerprint,
        schemaVersion: PR_ATTESTATION_SCHEMA_VERSION,
      });
      seedAdminSignature({
        repo: h.repo,
        baseSha: base,
        headSha: head,
        targetBranch: "main",
        diffSha256,
        manifestSnapshotSha256: manifestSnapshot,
        approvals: [entry],
        checks: [],
        operatorFingerprint: h.operatorFingerprint,
        admin: h.adminKeys[0]!,
        signingTargetOverride: staleTarget,
      });

      let caught: Error | null = null;
      try {
        runFromRepo(h.repo, () => runAttest({ into: "main", branch: "feature" }));
      } catch (err) {
        caught = err as Error;
      }
      assert.ok(caught, "stale-sig case must throw");
      // The collector throws the threshold-not-met error with the
      // stale-sig rejection embedded in the failures summary.
      assert.match(caught.message, /requires 1 admin signature/);
      assert.match(caught.message, /stale — re-sign after refresh/);
      assert.equal(listAttestationPatchIds(h.repo).length, 0);
    } finally {
      h.cleanup();
    }
  });

  it("non-admin signer: a signature by a key without 'admin' capability is rejected", () => {
    // Build a harness with no admin keys; manually inject a server
    // key (which has capability [server], NOT admin) as the
    // "signer." The collector should reject it under the lacks-admin
    // path and then fail the threshold check.
    const h = setupHarness({ adminCount: 0, touchStamp: true });
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "feature");
      const diff = git(h.repo, ["diff", `${base}...${head}`]);
      const diffSha256 = sha256Hex(diff);
      const manifest = parseManifest(
        git(h.repo, ["show", `${base}:.stamp/trusted-keys/manifest.yml`]),
      );
      assert.ok(manifest);
      const manifestSnapshot = snapshotSha256(manifest);
      const { entry } = seedServerSignedReview({
        repo: h.repo,
        reviewer: "security",
        baseSha: base,
        headSha: head,
        diffSha256,
        serverKey: h.serverKey,
      });

      // Forge a note signed by the server key. Server key has
      // capability [server], NOT admin — must be rejected.
      seedAdminSignature({
        repo: h.repo,
        baseSha: base,
        headSha: head,
        targetBranch: "main",
        diffSha256,
        manifestSnapshotSha256: manifestSnapshot,
        approvals: [entry],
        checks: [],
        operatorFingerprint: h.operatorFingerprint,
        admin: h.serverKey, // server, not admin — that's the point of the test
      });

      let caught: Error | null = null;
      try {
        runFromRepo(h.repo, () => runAttest({ into: "main", branch: "feature" }));
      } catch (err) {
        caught = err as Error;
      }
      assert.ok(caught, "non-admin-signer case must throw");
      assert.match(caught.message, /requires 1 admin signature/);
      assert.match(caught.message, /lacks 'admin' capability/);
      assert.equal(listAttestationPatchIds(h.repo).length, 0);
    } finally {
      h.cleanup();
    }
  });
});
