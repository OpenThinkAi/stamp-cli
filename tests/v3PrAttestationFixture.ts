/**
 * Test helper: fabricate v3 PR-attestation envelopes against a fixture
 * repo, byte-for-byte the shape AGT-355 will eventually produce
 * server-side. AGT-338 ships the verifier; the producer side is not
 * yet implemented, so these tests construct the envelope manually
 * (server key + operator key in memory, sign each layer, write the
 * blob to `refs/stamp/attestations/<patch-id>` via the same
 * writeAttestationRef helper the legacy 1.x attest command uses).
 *
 * Kept under `tests/` (not `src/lib/`) because nothing in production
 * should fabricate envelopes — AGT-355 produces them inside
 * stamp-server. Co-locating with the verifier tests keeps the
 * fixture-shape contract in the same review surface as the verifier
 * it exercises.
 */

import { execFileSync } from "node:child_process";
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
} from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  canonicalSerializeApproval,
  canonicalSerializePayload,
  type ApprovalEntryV4,
  type ApprovalV4,
  type AttestationPayloadV4,
  type CheckAttestationV4,
  type TrustAnchorSignatureV4,
} from "../src/lib/attestationV4.ts";
import { fingerprintFromPem } from "../src/lib/keys.ts";
import { patchIdForSpan } from "../src/lib/patchId.ts";
import {
  PR_ATTESTATION_SCHEMA_VERSION,
  attestationRefName,
  serializePayload,
  writeAttestationRef,
  type PrAttestationEnvelope,
} from "../src/lib/prAttestation.ts";
import { signBytes } from "../src/lib/signing.ts";
import { snapshotSha256, parseManifest } from "../src/lib/trustedKeysManifest.ts";

const REVIEWER_PROMPT = "You are the security reviewer. Approve everything.\n";

export interface KeyPair {
  privatePem: string;
  publicPem: string;
  fingerprint: string;
}

export function generateKey(): KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  return { privatePem, publicPem, fingerprint: fingerprintFromPem(publicPem) };
}

export function git(repo: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd: repo,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

export function shaOf(repo: string, ref: string): string {
  return git(repo, ["rev-parse", ref]).trim();
}

export function sha256Hex(bytes: Buffer | string): string {
  return createHash("sha256")
    .update(typeof bytes === "string" ? Buffer.from(bytes, "utf8") : bytes)
    .digest("hex");
}

export interface FixtureOpts {
  /** When true, the feature branch touches `.stamp/config.yml` so a
   *  `.stamp/**` path-rule fires. Configures path_rules accordingly. */
  touchesStamp?: boolean;
  /** When set, also writes a path_rules section requiring N admin
   *  signatures on `.stamp/**`. */
  pathRule?: { minimumSignatures: number; bypassReviewCycle: boolean };
  /** Add a second admin key + entry so multi-sig scenarios can sign
   *  with two admins. */
  withSecondAdmin?: boolean;
}

export interface Fixture {
  root: string;
  repo: string;
  serverKey: KeyPair;
  operatorKey: KeyPair;
  /** Present when `withSecondAdmin: true`. */
  adminKey?: KeyPair;
  /** SHA of the merge-base (base of the diff) — written by initial commit. */
  baseSha: string;
  /** SHA of the feature branch tip. */
  headSha: string;
  diffText: string;
  diffSha256: string;
  cleanup: () => void;
}

/**
 * Build a v3-ready fixture repo: server pubkey + operator pubkey
 * committed with manifest entries (server has `server`, operator has
 * `operator`, optional admin has `admin`), a security reviewer prompt,
 * and a feature branch with one code change (or a `.stamp/`-touching
 * change when `touchesStamp` is set).
 */
export function setupV3Fixture(opts: FixtureOpts = {}): Fixture {
  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-prattv3-"));
  const repo = path.join(root, "repo");
  mkdirSync(repo, { recursive: true });

  const serverKey = generateKey();
  const operatorKey = generateKey();
  const adminKey = opts.withSecondAdmin ? generateKey() : undefined;

  git(repo, ["init", "-q", "-b", "main"]);
  git(repo, ["config", "user.name", "Test"]);
  git(repo, ["config", "user.email", "test@example.invalid"]);
  git(repo, ["config", "commit.gpgsign", "false"]);

  mkdirSync(path.join(repo, ".stamp", "reviewers"), { recursive: true });
  mkdirSync(path.join(repo, ".stamp", "trusted-keys"), { recursive: true });

  // config.yml: single branch rule + optional path_rules.
  const cfgLines: string[] = [
    "branches:",
    "  main:",
    "    required: [security]",
    "reviewers:",
    "  security:",
    "    prompt: .stamp/reviewers/security.md",
    "    tools: []",
  ];
  if (opts.pathRule) {
    cfgLines.push(
      "path_rules:",
      '  ".stamp/**":',
      "    require_capability: admin",
      `    minimum_signatures: ${opts.pathRule.minimumSignatures}`,
      `    bypass_review_cycle: ${opts.pathRule.bypassReviewCycle}`,
    );
  }
  cfgLines.push("");
  writeFileSync(path.join(repo, ".stamp", "config.yml"), cfgLines.join("\n"));
  writeFileSync(
    path.join(repo, ".stamp", "reviewers", "security.md"),
    REVIEWER_PROMPT,
  );

  // Manifest binding fingerprints to capabilities. Lookups by
  // fingerprint, not name, so the order in the file doesn't matter.
  const manifestLines: string[] = [
    "keys:",
    "  review-server-test:",
    `    fingerprint: ${serverKey.fingerprint}`,
    "    capabilities: [server]",
    "  operator-test:",
    `    fingerprint: ${operatorKey.fingerprint}`,
    "    capabilities: [operator]",
  ];
  if (adminKey) {
    manifestLines.push(
      "  admin-test:",
      `    fingerprint: ${adminKey.fingerprint}`,
      "    capabilities: [admin]",
    );
  }
  manifestLines.push("");
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", "manifest.yml"),
    manifestLines.join("\n"),
  );

  // Commit each pubkey under a fingerprint-derived filename so the
  // verifier's `git ls-tree .stamp/trusted-keys/` enumeration picks it
  // up. fingerprint format is `sha256:<hex>`; we substitute the colon
  // to keep the filename portable.
  const fingerprintFilename = (fp: string) => fp.replace(":", "_") + ".pub";
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", fingerprintFilename(serverKey.fingerprint)),
    serverKey.publicPem,
  );
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", fingerprintFilename(operatorKey.fingerprint)),
    operatorKey.publicPem,
  );
  if (adminKey) {
    writeFileSync(
      path.join(repo, ".stamp", "trusted-keys", fingerprintFilename(adminKey.fingerprint)),
      adminKey.publicPem,
    );
  }

  writeFileSync(path.join(repo, "README.md"), "initial\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "initial: seed .stamp/ config + trust"]);
  const baseSha = shaOf(repo, "main");

  // Feature branch with a small change.
  git(repo, ["checkout", "-q", "-b", "feature"]);
  if (opts.touchesStamp) {
    // Touch a `.stamp/` path so path_rules guard fires.
    writeFileSync(
      path.join(repo, ".stamp", "reviewers", "security.md"),
      REVIEWER_PROMPT + "Be extra paranoid.\n",
    );
    git(repo, ["add", "-A"]);
    git(repo, ["commit", "-q", "-m", "feature: tighten security prompt"]);
  } else {
    writeFileSync(path.join(repo, "feature.txt"), "hello\n");
    git(repo, ["add", "-A"]);
    git(repo, ["commit", "-q", "-m", "add feature"]);
  }
  const headSha = shaOf(repo, "HEAD");

  // Move back to main so the PR-mode verifier's `git rev-parse main`
  // resolves to the same SHA whether main is checked out or not.
  git(repo, ["checkout", "-q", "main"]);

  const diffText = git(repo, ["diff", `${baseSha}...${headSha}`]);
  const diffSha256 = sha256Hex(diffText);

  return {
    root,
    repo,
    serverKey,
    operatorKey,
    adminKey,
    baseSha,
    headSha,
    diffText,
    diffSha256,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

export interface BuildEnvelopeOpts {
  fixture: Fixture;
  /** Operator key used to sign the OUTER envelope. Defaults to the
   *  fixture's operatorKey. Override when testing wrong-key paths. */
  operatorOverride?: KeyPair;
  /** Server key used to sign each approval. Defaults to fixture.serverKey. */
  serverOverride?: KeyPair;
  /** Override approvals (e.g. to drop required reviewer for gate-closed test). */
  approvalsOverride?: ApprovalEntryV4[];
  /** Override the top-level diff_sha256 (e.g. to test mismatch path). */
  diffSha256Override?: string;
  /** Override checks list. */
  checksOverride?: CheckAttestationV4[];
  /** Mutate the canonical payload BEFORE signing the outer. Useful for
   *  building envelopes whose outer signature stays valid but whose
   *  inner per-approval body has been tampered with. */
  payloadMutator?: (p: AttestationPayloadV4) => AttestationPayloadV4;
  /** Trust-anchor signatures to attach. Defaults to []. */
  trustAnchorSignatures?: TrustAnchorSignatureV4[];
}

/**
 * Fabricate a v3 PR-attestation envelope against the given fixture.
 * Mirrors AGT-355's eventual server-side production exactly — same
 * canonical bytes (`canonicalSerializeApproval` for the inner per-
 * approval, plain `JSON.stringify` for the outer envelope), same
 * trust artifacts read from base_sha.
 */
export function buildV3Envelope(opts: BuildEnvelopeOpts): PrAttestationEnvelope {
  const { fixture } = opts;
  const operatorKey = opts.operatorOverride ?? fixture.operatorKey;
  const serverKey = opts.serverOverride ?? fixture.serverKey;

  // Compute the manifest snapshot at base_sha — same value the server
  // would have computed when signing each approval at attest time.
  const manifestYaml = git(fixture.repo, [
    "show",
    `${fixture.baseSha}:.stamp/trusted-keys/manifest.yml`,
  ]);
  const manifest = parseManifest(manifestYaml);
  if (!manifest) throw new Error("manifest must parse at base_sha");
  const manifestSnapshot = snapshotSha256(manifest);

  // Default approval: security reviewer, approved, signed by serverKey
  // over the canonical inner approval bytes.
  let approvals: ApprovalEntryV4[];
  if (opts.approvalsOverride) {
    approvals = opts.approvalsOverride;
  } else {
    const approval: ApprovalV4 = {
      reviewer: "security",
      verdict: "approved",
      prompt_sha256: sha256Hex(REVIEWER_PROMPT),
      diff_sha256: fixture.diffSha256,
      base_sha: fixture.baseSha,
      head_sha: fixture.headSha,
      trusted_keys_snapshot_sha256: manifestSnapshot,
      issued_at: "2026-05-18T12:00:00Z",
      server_key_id: serverKey.fingerprint,
    };
    const serverSignature = signBytes(
      serverKey.privatePem,
      canonicalSerializeApproval(approval),
    );
    approvals = [
      {
        approval,
        server_attestation: {
          server_key_id: serverKey.fingerprint,
          signature: serverSignature,
        },
      },
    ];
  }

  // Build the v4 payload view — same fields as AGT-355 will produce
  // server-side. Verifier reads these.
  let payloadV4: AttestationPayloadV4 = {
    schema_version: PR_ATTESTATION_SCHEMA_VERSION,
    base_sha: fixture.baseSha,
    head_sha: fixture.headSha,
    target_branch: "main",
    diff_sha256: opts.diffSha256Override ?? fixture.diffSha256,
    approvals,
    checks: opts.checksOverride ?? [],
    trust_anchor_signatures: opts.trustAnchorSignatures ?? [],
    signer_key_id: operatorKey.fingerprint,
  };
  if (opts.payloadMutator) {
    payloadV4 = opts.payloadMutator(payloadV4);
  }

  // PR-envelope payload merges the v4 fields + PR-mode-only fields
  // (patch_id, target_branch_tip_sha). schema_version comes from v3
  // constant, NOT the v4 module's constant — see prAttestation.ts
  // docstring on the independent version axes.
  const patchId = patchIdForSpan(
    fixture.baseSha,
    fixture.headSha,
    fixture.repo,
  );
  const prPayload = {
    schema_version: PR_ATTESTATION_SCHEMA_VERSION,
    patch_id: patchId,
    base_sha: payloadV4.base_sha,
    head_sha: payloadV4.head_sha,
    target_branch: payloadV4.target_branch,
    target_branch_tip_sha: fixture.baseSha, // base IS the tip in the fixture
    diff_sha256: payloadV4.diff_sha256,
    approvals: payloadV4.approvals,
    checks: payloadV4.checks,
    trust_anchor_signatures: payloadV4.trust_anchor_signatures,
    signer_key_id: payloadV4.signer_key_id,
  };

  // Outer signature: same bytes the verifier re-derives via
  // serializePayload(envelope.payload). Plain JSON.stringify, NOT
  // canonical — matches the v2 envelope convention. The verifier
  // re-stringifies envelope.payload to recompute these bytes.
  const outerBytes = serializePayload(prPayload);
  const outerSignature = signBytes(operatorKey.privatePem, outerBytes);

  return { payload: prPayload, signature: outerSignature };
}

/**
 * Sign a trust-anchor signature over the canonical payload-without-
 * trust_anchor_signatures (the documented signing target per
 * attestationV4.ts). Helper for path_rules guard tests.
 */
export function signTrustAnchor(
  signerKey: KeyPair,
  payload: AttestationPayloadV4,
): TrustAnchorSignatureV4 {
  const stripped: AttestationPayloadV4 = {
    ...payload,
    trust_anchor_signatures: [],
  };
  const bytes = canonicalSerializePayload(stripped);
  return {
    signer_key_id: signerKey.fingerprint,
    signature: signBytes(signerKey.privatePem, bytes),
  };
}

/**
 * Write an envelope to the fixture's repo at the patch-id ref. Returns
 * the patch_id so callers can locate the ref again later.
 */
export function writeFixtureEnvelope(
  fixture: Fixture,
  envelope: PrAttestationEnvelope,
): { ref: string; patchId: string } {
  const written = writeAttestationRef(envelope, fixture.repo);
  return { ref: written.ref, patchId: envelope.payload.patch_id };
}

/**
 * Lower-level: write arbitrary bytes as a blob and point an
 * attestation ref at them. Used by tests that fabricate envelopes
 * that wouldn't pass `serializeEnvelope`'s shape (e.g. v2 envelopes
 * exercising the rejection path).
 */
export function writeRawAttestationBlob(
  repo: string,
  patchId: string,
  bytes: string,
): { ref: string } {
  const ref = attestationRefName(patchId);
  const newSha = execFileSync(
    "git",
    ["hash-object", "-w", "--stdin"],
    { cwd: repo, input: bytes, encoding: "utf8" },
  ).trim();
  execFileSync("git", ["update-ref", ref, newSha], {
    cwd: repo,
    stdio: ["ignore", "pipe", "pipe"],
  });
  return { ref };
}

/**
 * Re-export for convenience so tests pull from one place.
 */
export { createPublicKey };
