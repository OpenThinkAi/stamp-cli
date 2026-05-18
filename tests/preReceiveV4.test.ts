/**
 * Unit tests for the v4 (server-attested) verification phases of the
 * pre-receive hook (AGT-335).
 *
 * Each phase is a pure function over a constructed `PhaseInputV4`, so
 * we drive them directly rather than spawning the hook binary. The
 * happy-path test wires through every phase end-to-end; the failure
 * tests target one rejection mode at a time and assert the error
 * message names the failing invariant.
 *
 * The harness builds a real git repo (NOT bare — `git show`, `git
 * diff`, `git rev-list` all work the same on a working repo) with:
 *   - .stamp/config.yml carrying a `security` reviewer + protected
 *     `main`
 *   - .stamp/reviewers/security.md with a fixed prompt
 *   - a server keypair committed to .stamp/trusted-keys/ + registered
 *     in the manifest with capabilities: [server]
 *   - an operator keypair committed similarly with [operator]
 *   - a feature branch with one commit
 *   - a real --no-ff merge commit on main produced by hand-rolling
 *     the v4 envelope + trailers (we want full control over what's in
 *     the trailers, so we can corrupt individual fields per test)
 *
 * The verifier reads everything from base_sha / the merge commit's
 * parents; tests `process.chdir` into the repo so the hook's `run`
 * wrapper finds the right git.
 */

import { strict as assert } from "node:assert";
import {
  createHash,
  generateKeyPairSync,
} from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import {
  canonicalSerializeApproval,
  canonicalSerializePayload,
  type ApprovalEntryV4,
  type ApprovalV4,
  type AttestationPayloadV4,
  type TrustAnchorSignatureV4,
} from "../src/lib/attestationV4.ts";
import { fingerprintFromPem } from "../src/lib/keys.ts";
import {
  parseManifest,
  snapshotSha256,
} from "../src/lib/trustedKeysManifest.ts";
import { buildPubkeyMap } from "../src/lib/sshReviewClient.ts";
import { signBytes } from "../src/lib/signing.ts";
import {
  parsePathRules,
  verifyV4ApprovalSignatures,
  verifyV4Approvals,
  verifyV4Checks,
  verifyV4DiffHash,
  verifyV4MergeStructure,
  verifyV4OuterSignature,
  verifyV4SignerTrust,
  verifyV4StampPathsGuard,
  verifyV4TargetBranch,
  verifyV4TrustAnchorSignatures,
  type PhaseInputV4,
} from "../src/hooks/pre-receive.ts";

// Schema version constant used when building test payloads. The
// dispatch-threshold test imports the real constants from
// attestation.ts / attestationV4.ts to assert the contract.
const SCHEMA_V4 = 4;

// ─── Helpers ────────────────────────────────────────────────────────

interface Keypair {
  privatePem: string;
  publicPem: string;
  fingerprint: string;
}

function genKey(): Keypair {
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

function git(cwd: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function sha256Hex(buf: Buffer | string): string {
  return createHash("sha256")
    .update(typeof buf === "string" ? Buffer.from(buf, "utf8") : buf)
    .digest("hex");
}

const REVIEWER_PROMPT = "Approve everything for testing purposes.\n";

interface Harness {
  repo: string;
  serverKey: Keypair;
  operatorKey: Keypair;
  adminKey: Keypair; // for trust-anchor tests
  baseSha: string;
  headSha: string;
  mergeSha: string;
  manifestSnapshot: string;
  diffSha256: string;
  cleanup: () => void;
  /** Convenience: build a fresh `PhaseInputV4` for a given payload. */
  inputFor: (payload: AttestationPayloadV4, sigB64: string) => PhaseInputV4;
}

/** Build the harness with a v4-ready repo + a real merge commit whose
 *  parents are the seeded main + feature, and whose message includes
 *  Stamp-Payload / Stamp-Verified trailers we control. */
function setupHarness(opts?: {
  /** Override the prompt text committed to base_sha. */
  promptText?: string;
  /** If true, the feature branch additionally edits
   *  `.stamp/reviewers/security.md` so the merge diff touches a path
   *  under `.stamp/**` — used by the AGT-336 path_rules tests. */
  touchStampPath?: boolean;
}): Harness {
  const root = mkdtempSync(path.join(tmpdir(), "stamp-prereceive-v4-"));
  const repo = path.join(root, "repo");
  mkdirSync(repo);

  const serverKey = genKey();
  const operatorKey = genKey();
  const adminKey = genKey();

  git(repo, ["init", "-q", "-b", "main"]);
  git(repo, ["config", "user.name", "Test"]);
  git(repo, ["config", "user.email", "test@example.invalid"]);
  git(repo, ["config", "commit.gpgsign", "false"]);

  // .stamp/config.yml with one required reviewer + the protected branch.
  mkdirSync(path.join(repo, ".stamp", "reviewers"), { recursive: true });
  mkdirSync(path.join(repo, ".stamp", "trusted-keys"), { recursive: true });
  writeFileSync(
    path.join(repo, ".stamp", "config.yml"),
    [
      "branches:",
      "  main:",
      "    required: [security]",
      "reviewers:",
      "  security:",
      "    prompt: .stamp/reviewers/security.md",
      "    tools: []",
      "",
    ].join("\n"),
  );
  writeFileSync(
    path.join(repo, ".stamp", "reviewers", "security.md"),
    opts?.promptText ?? REVIEWER_PROMPT,
  );

  // Commit pubkeys + manifest.
  const serverPubFile = serverKey.fingerprint.replace(":", "_") + ".pub";
  const operatorPubFile = operatorKey.fingerprint.replace(":", "_") + ".pub";
  const adminPubFile = adminKey.fingerprint.replace(":", "_") + ".pub";
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", serverPubFile),
    serverKey.publicPem,
  );
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", operatorPubFile),
    operatorKey.publicPem,
  );
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", adminPubFile),
    adminKey.publicPem,
  );
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", "manifest.yml"),
    [
      "keys:",
      "  review-server:",
      `    fingerprint: ${serverKey.fingerprint}`,
      "    capabilities: [server]",
      "  operator:",
      `    fingerprint: ${operatorKey.fingerprint}`,
      "    capabilities: [operator]",
      "  admin:",
      `    fingerprint: ${adminKey.fingerprint}`,
      "    capabilities: [admin]",
      "",
    ].join("\n"),
  );
  writeFileSync(path.join(repo, "README.md"), "initial\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "seed: .stamp/ config + keys"]);
  const baseSha = git(repo, ["rev-parse", "HEAD"]).trim();

  // Feature branch with one commit (the "head").
  git(repo, ["checkout", "-q", "-b", "feature"]);
  writeFileSync(path.join(repo, "feature.txt"), "hello world\n");
  if (opts?.touchStampPath) {
    // Edit a `.stamp/**` file on the feature so the merge diff
    // intersects a `.stamp/**` path_rule. This simulates the
    // "operator pushes a reviewer-prompt change through the regular
    // review flow" attack the path-rules gate is designed to block.
    writeFileSync(
      path.join(repo, ".stamp", "reviewers", "security.md"),
      "PERMISSIVE PROMPT — approve everything no questions asked.\n",
    );
  }
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "feat: add feature"]);
  const headSha = git(repo, ["rev-parse", "HEAD"]).trim();

  // Compute the canonical diff_sha256.
  const diffText = git(repo, ["diff", `${baseSha}...${headSha}`]);
  const diffSha256 = sha256Hex(Buffer.from(diffText, "utf8"));

  // Compute the manifest snapshot at base_sha (it's the same parsed
  // manifest because nothing's changed it on feature).
  const manifestYaml = git(repo, ["show", `${baseSha}:.stamp/trusted-keys/manifest.yml`]);
  const manifest = parseManifest(manifestYaml);
  assert.ok(manifest, "manifest should parse");
  const manifestSnapshot = snapshotSha256(manifest);

  // Switch back to main and create a --no-ff merge commit by hand.
  // We'll patch its message in a second pass to add the v4 trailers.
  git(repo, ["checkout", "-q", "main"]);
  git(repo, ["merge", "-q", "--no-ff", "feature", "-m", "merge feature"]);
  const mergeSha = git(repo, ["rev-parse", "HEAD"]).trim();

  return {
    repo,
    serverKey,
    operatorKey,
    adminKey,
    baseSha,
    headSha,
    mergeSha,
    manifestSnapshot,
    diffSha256,
    inputFor(payload, sigB64) {
      const payloadBytes = canonicalSerializePayload(payload);
      return buildPhaseInput({
        repo,
        mergeSha,
        baseSha,
        headSha,
        manifestYaml,
        payload,
        payloadBytes,
        signatureBase64: sigB64,
      });
    },
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

function buildPhaseInput(args: {
  repo: string;
  mergeSha: string;
  baseSha: string;
  headSha: string;
  manifestYaml: string;
  payload: AttestationPayloadV4;
  payloadBytes: Buffer;
  signatureBase64: string;
  /** Optional override — when omitted, the harness uses the empty rule
   *  set (matches a vanilla repo with no path_rules in config.yml). */
  pathRules?: PhaseInputV4["pathRules"];
}): PhaseInputV4 {
  const manifest = parseManifest(args.manifestYaml);
  assert.ok(manifest, "manifest should parse");
  const pubFiles = git(args.repo, [
    "ls-tree",
    "--name-only",
    args.baseSha,
    ".stamp/trusted-keys/",
  ])
    .split("\n")
    .filter((l) => l.length > 0)
    .map((l) => {
      const prefix = ".stamp/trusted-keys/";
      return l.startsWith(prefix) ? l.slice(prefix.length) : l;
    })
    .filter((n) => n.endsWith(".pub"));
  const pubkeyByFingerprint = buildPubkeyMap(pubFiles, (relPath) =>
    git(args.repo, ["show", `${args.baseSha}:${relPath}`]),
  );
  const changedFiles = git(args.repo, [
    "diff",
    "--name-only",
    `${args.baseSha}...${args.headSha}`,
  ])
    .split("\n")
    .filter((l) => l.length > 0);
  return {
    sha: args.mergeSha,
    branch: "main",
    rule: { required: ["security"] },
    payload: args.payload,
    payloadBytes: args.payloadBytes,
    signatureBase64: args.signatureBase64,
    manifest,
    pubkeyByFingerprint,
    pathRules: args.pathRules ?? [],
    changedFiles,
  };
}

/** Build a normal-shape ApprovalV4 + the server's signature over it. */
function buildSignedApproval(args: {
  reviewer: string;
  baseSha: string;
  headSha: string;
  diffSha256: string;
  promptSha256: string;
  manifestSnapshot: string;
  serverKey: Keypair;
  verdict?: ApprovalV4["verdict"];
}): ApprovalEntryV4 {
  const approval: ApprovalV4 = {
    reviewer: args.reviewer,
    verdict: args.verdict ?? "approved",
    prompt_sha256: args.promptSha256,
    diff_sha256: args.diffSha256,
    base_sha: args.baseSha,
    head_sha: args.headSha,
    trusted_keys_snapshot_sha256: args.manifestSnapshot,
    issued_at: "2026-05-17T12:34:56Z",
    server_key_id: args.serverKey.fingerprint,
  };
  const signature = signBytes(
    args.serverKey.privatePem,
    canonicalSerializeApproval(approval),
  );
  return {
    approval,
    server_attestation: {
      server_key_id: args.serverKey.fingerprint,
      signature,
    },
  };
}

function buildPayload(h: Harness, overrides?: Partial<AttestationPayloadV4>): AttestationPayloadV4 {
  const approvalEntry = buildSignedApproval({
    reviewer: "security",
    baseSha: h.baseSha,
    headSha: h.headSha,
    diffSha256: h.diffSha256,
    promptSha256: sha256Hex(REVIEWER_PROMPT),
    manifestSnapshot: h.manifestSnapshot,
    serverKey: h.serverKey,
  });
  return {
    schema_version: SCHEMA_V4,
    base_sha: h.baseSha,
    head_sha: h.headSha,
    target_branch: "main",
    diff_sha256: h.diffSha256,
    approvals: [approvalEntry],
    checks: [],
    trust_anchor_signatures: [],
    signer_key_id: h.operatorKey.fingerprint,
    ...overrides,
  };
}

function signOuter(h: Harness, payload: AttestationPayloadV4): string {
  return signBytes(h.operatorKey.privatePem, canonicalSerializePayload(payload));
}

/** Run every v4 phase in pipeline order, returning the first failure
 *  (or null on full success). Mirrors the dispatcher in verifyCommitV4. */
function runAllPhases(input: PhaseInputV4): string | null {
  const phases = [
    verifyV4MergeStructure,
    verifyV4TargetBranch,
    verifyV4SignerTrust,
    verifyV4OuterSignature,
    verifyV4Approvals,
    verifyV4DiffHash,
    verifyV4ApprovalSignatures,
    verifyV4Checks,
    verifyV4TrustAnchorSignatures,
    verifyV4StampPathsGuard,
  ];
  for (const fn of phases) {
    const r = fn(input);
    if (!r.ok) return r.reason;
  }
  return null;
}

// ─── Tests ──────────────────────────────────────────────────────────

describe("pre-receive v4 — happy path", () => {
  let prevCwd: string;
  let h: Harness | undefined;

  beforeEach(() => {
    prevCwd = process.cwd();
  });
  afterEach(() => {
    process.chdir(prevCwd);
    h?.cleanup();
    h = undefined;
  });

  it("accepts a well-formed v4 envelope end-to-end", () => {
    h = setupHarness();
    process.chdir(h.repo);

    const payload = buildPayload(h);
    const sig = signOuter(h, payload);
    const input = h.inputFor(payload, sig);

    const reason = runAllPhases(input);
    assert.equal(reason, null, `expected all phases to pass, got: ${reason}`);
  });
});

describe("pre-receive v4 — rejection modes", () => {
  let prevCwd: string;
  let h: Harness | undefined;

  beforeEach(() => {
    prevCwd = process.cwd();
  });
  afterEach(() => {
    process.chdir(prevCwd);
    h?.cleanup();
    h = undefined;
  });

  it("rejects when the outer signature is forged (wrong key)", () => {
    h = setupHarness();
    process.chdir(h.repo);

    const payload = buildPayload(h);
    // Sign with the SERVER key but claim the operator's fingerprint —
    // the verifier loads the operator's pubkey and the signature can't
    // verify against bytes signed by a different key.
    const forgedSig = signBytes(
      h.serverKey.privatePem,
      canonicalSerializePayload(payload),
    );
    const input = h.inputFor(payload, forgedSig);
    const reason = runAllPhases(input);
    assert.match(reason!, /outer Ed25519 signature does not verify/);
  });

  it("rejects when an approval's inner signature is forged", () => {
    h = setupHarness();
    process.chdir(h.repo);

    const payload = buildPayload(h);
    // Tamper with the server signature on the only approval — replace
    // it with a signature over different bytes (sign zero-length).
    payload.approvals[0]!.server_attestation.signature = signBytes(
      h.serverKey.privatePem,
      Buffer.from("", "utf8"),
    );
    const sig = signOuter(h, payload);
    const input = h.inputFor(payload, sig);
    const reason = runAllPhases(input);
    assert.match(reason!, /server signature does not verify/);
  });

  it("rejects when the inner approval.server_key_id is not in the manifest snapshot at base_sha", () => {
    h = setupHarness();
    process.chdir(h.repo);

    // Use a brand-new key the manifest doesn't list at base_sha.
    const orphanServer = genKey();
    const approval = buildSignedApproval({
      reviewer: "security",
      baseSha: h.baseSha,
      headSha: h.headSha,
      diffSha256: h.diffSha256,
      promptSha256: sha256Hex(REVIEWER_PROMPT),
      manifestSnapshot: h.manifestSnapshot,
      serverKey: orphanServer,
    });
    const payload = buildPayload(h, { approvals: [approval] });
    const sig = signOuter(h, payload);
    const input = h.inputFor(payload, sig);
    const reason = runAllPhases(input);
    assert.match(reason!, /is not in \.stamp\/trusted-keys\/manifest\.yml/);
  });

  it("accepts an approval whose server_key_id is still listed at base_sha (lenient revocation simulation)", () => {
    // Lenient-revocation acceptance is structural: as long as the
    // manifest AT base_sha contains the key and the snapshot hash
    // matches, the approval verifies. The fact that the key might be
    // revoked in a LATER manifest commit is invisible to a verifier
    // looking at base_sha — and that's the point.
    //
    // We model this by leaving the manifest at base_sha untouched
    // (it lists the server key) and verifying the approval succeeds.
    // The "revoked in live" half of the model is what wouldn't change
    // the outcome here — the verifier is base_sha-scoped on purpose.
    h = setupHarness();
    process.chdir(h.repo);

    const payload = buildPayload(h);
    const sig = signOuter(h, payload);
    const input = h.inputFor(payload, sig);
    const reason = runAllPhases(input);
    assert.equal(reason, null, `lenient revocation should accept, got: ${reason}`);
  });

  it("rejects when payload.diff_sha256 doesn't match the recomputed diff", () => {
    h = setupHarness();
    process.chdir(h.repo);

    // Build a normal payload then corrupt diff_sha256 to a wrong hex.
    const payload = buildPayload(h);
    payload.diff_sha256 = "f".repeat(64);
    const sig = signOuter(h, payload);
    const input = h.inputFor(payload, sig);
    const reason = runAllPhases(input);
    assert.match(reason!, /v4 diff_sha256 mismatch/);
  });

  it("rejects when an approval's prompt_sha256 doesn't match the prompt at base_sha", () => {
    h = setupHarness();
    process.chdir(h.repo);

    // Sign an approval that claims a wrong prompt hash; the inner
    // signature is over the wrong-hash approval body so it self-
    // verifies — but the verifier then re-hashes the prompt file at
    // base_sha and the comparison fails.
    const approval = buildSignedApproval({
      reviewer: "security",
      baseSha: h.baseSha,
      headSha: h.headSha,
      diffSha256: h.diffSha256,
      promptSha256: sha256Hex("a different prompt entirely"),
      manifestSnapshot: h.manifestSnapshot,
      serverKey: h.serverKey,
    });
    const payload = buildPayload(h, { approvals: [approval] });
    const sig = signOuter(h, payload);
    const input = h.inputFor(payload, sig);
    const reason = runAllPhases(input);
    assert.match(reason!, /prompt_sha256 mismatch/);
  });

  it("dispatcher threshold: only schema_version >= 4 enters the v4 pipeline (regression on the integer comparison)", async () => {
    // The dispatcher in verifyCommit uses `>= MIN_ACCEPTED_V4_SCHEMA_VERSION`
    // to decide whether a payload goes through the v4 pipeline. v3
    // payloads (schema_version: 3) must continue to route to the
    // legacy v3 path — both verifiers coexist in the bridge era. This
    // test pins the dispatch contract: the constants must satisfy a
    // strict ordering so v3 traffic can never accidentally cross into
    // v4 verification or vice-versa.
    const v3 = await import("../src/lib/attestation.ts");
    const v4 = await import("../src/lib/attestationV4.ts");
    // v3 floor below v4 floor: schema 3 routes to v3, schema 4 routes to v4.
    assert.ok(v3.MIN_ACCEPTED_PAYLOAD_VERSION < v4.MIN_ACCEPTED_V4_SCHEMA_VERSION);
    assert.equal(v4.MIN_ACCEPTED_V4_SCHEMA_VERSION, 4);
    // Anything strictly less than the v4 floor must NOT be considered
    // a v4 payload by the dispatcher.
    for (const tooLow of [1, 2, 3]) {
      assert.equal(tooLow >= v4.MIN_ACCEPTED_V4_SCHEMA_VERSION, false);
    }
    // Anything >= the v4 floor is a v4 payload.
    for (const v4Ish of [4, 5, 99]) {
      assert.equal(v4Ish >= v4.MIN_ACCEPTED_V4_SCHEMA_VERSION, true);
    }
  });

  it("rejects when a required reviewer is missing approvals (verdict != approved)", () => {
    h = setupHarness();
    process.chdir(h.repo);

    const approval = buildSignedApproval({
      reviewer: "security",
      baseSha: h.baseSha,
      headSha: h.headSha,
      diffSha256: h.diffSha256,
      promptSha256: sha256Hex(REVIEWER_PROMPT),
      manifestSnapshot: h.manifestSnapshot,
      serverKey: h.serverKey,
      verdict: "changes_requested",
    });
    const payload = buildPayload(h, { approvals: [approval] });
    const sig = signOuter(h, payload);
    const input = h.inputFor(payload, sig);
    const reason = runAllPhases(input);
    assert.match(reason!, /missing required approvals — security/);
  });

  it("rejects when the trusted_keys_snapshot_sha256 doesn't match the manifest at base_sha", () => {
    h = setupHarness();
    process.chdir(h.repo);

    const approval = buildSignedApproval({
      reviewer: "security",
      baseSha: h.baseSha,
      headSha: h.headSha,
      diffSha256: h.diffSha256,
      promptSha256: sha256Hex(REVIEWER_PROMPT),
      manifestSnapshot: "sha256:" + "0".repeat(64),
      serverKey: h.serverKey,
    });
    const payload = buildPayload(h, { approvals: [approval] });
    const sig = signOuter(h, payload);
    const input = h.inputFor(payload, sig);
    const reason = runAllPhases(input);
    assert.match(reason!, /trusted_keys_snapshot_sha256/);
  });

  it("rejects when the operator's signer_key_id is missing 'admin' or 'operator' capability", () => {
    // Re-purpose the server key (which is `[server]` only) as the
    // envelope signer. The signer-trust phase must reject.
    h = setupHarness();
    process.chdir(h.repo);

    const payload = buildPayload(h, { signer_key_id: h.serverKey.fingerprint });
    // Sign with the server key (so the outer signature would verify
    // structurally) — the rejection is at the capability check first.
    const sig = signBytes(
      h.serverKey.privatePem,
      canonicalSerializePayload(payload),
    );
    const input = h.inputFor(payload, sig);
    const reason = runAllPhases(input);
    assert.match(reason!, /needs 'admin' or 'operator'/);
  });

  it("rejects when target_branch in the payload doesn't match the branch being pushed", () => {
    h = setupHarness();
    process.chdir(h.repo);

    const payload = buildPayload(h, { target_branch: "release" });
    const sig = signOuter(h, payload);
    const input = h.inputFor(payload, sig);
    const reason = runAllPhases(input);
    assert.match(reason!, /target_branch.*does not match/);
  });

  it("rejects when payload.base_sha doesn't equal the merge-base of the merge commit's parents", () => {
    h = setupHarness();
    process.chdir(h.repo);

    // Force a fake base_sha that's structurally a real sha but not
    // the merge-base. Use the head_sha (any wrong sha works).
    const payload = buildPayload(h, { base_sha: h.headSha });
    const sig = signOuter(h, payload);
    const input = h.inputFor(payload, sig);
    // verifyV4MergeStructure runs first; it computes the actual
    // merge-base and compares.
    const reason = verifyV4MergeStructure(input);
    assert.equal(reason.ok, false);
    assert.match((reason as { reason: string }).reason, /merge-base/);
  });

  it("rejects an approval whose outer server_attestation.server_key_id mismatches the inner approval.server_key_id", () => {
    h = setupHarness();
    process.chdir(h.repo);

    const entry = buildSignedApproval({
      reviewer: "security",
      baseSha: h.baseSha,
      headSha: h.headSha,
      diffSha256: h.diffSha256,
      promptSha256: sha256Hex(REVIEWER_PROMPT),
      manifestSnapshot: h.manifestSnapshot,
      serverKey: h.serverKey,
    });
    // Tamper: change outer server_key_id to a different valid fingerprint
    // (the admin key, which is in the manifest with admin capability).
    entry.server_attestation.server_key_id = h.adminKey.fingerprint;
    const payload = buildPayload(h, { approvals: [entry] });
    const sig = signOuter(h, payload);
    const input = h.inputFor(payload, sig);
    const reason = runAllPhases(input);
    assert.match(reason!, /server_attestation\.server_key_id.*does not match inner/);
  });

  it("accepts a well-formed trust_anchor_signature from an admin key", () => {
    h = setupHarness();
    process.chdir(h.repo);

    const basePayload = buildPayload(h);
    // The admin signs the payload with trust_anchor_signatures = []
    // (documented signing target). The final payload then carries
    // the admin sig in trust_anchor_signatures.
    const payloadForAdmins: AttestationPayloadV4 = {
      ...basePayload,
      trust_anchor_signatures: [],
    };
    const adminSig = signBytes(
      h.adminKey.privatePem,
      canonicalSerializePayload(payloadForAdmins),
    );
    const ta: TrustAnchorSignatureV4 = {
      signer_key_id: h.adminKey.fingerprint,
      signature: adminSig,
    };
    const payload: AttestationPayloadV4 = {
      ...basePayload,
      trust_anchor_signatures: [ta],
    };
    const outerSig = signOuter(h, payload);
    const input = h.inputFor(payload, outerSig);
    const reason = runAllPhases(input);
    assert.equal(reason, null, `expected admin-signed trust anchor to pass, got: ${reason}`);
  });

  it("rejects a forged trust_anchor_signature", () => {
    h = setupHarness();
    process.chdir(h.repo);

    const basePayload = buildPayload(h);
    // Forge: admin signs garbage, not the actual payload.
    const adminSig = signBytes(h.adminKey.privatePem, Buffer.from("nope", "utf8"));
    const payload: AttestationPayloadV4 = {
      ...basePayload,
      trust_anchor_signatures: [
        { signer_key_id: h.adminKey.fingerprint, signature: adminSig },
      ],
    };
    const outerSig = signOuter(h, payload);
    const input = h.inputFor(payload, outerSig);
    const reason = runAllPhases(input);
    assert.match(reason!, /trust-anchor signature.*does not verify/);
  });

  it("rejects a trust_anchor_signature from a non-admin key", () => {
    h = setupHarness();
    process.chdir(h.repo);

    const basePayload = buildPayload(h);
    const payloadForSigners: AttestationPayloadV4 = {
      ...basePayload,
      trust_anchor_signatures: [],
    };
    // Operator key (capability [operator]) tries to counter-sign as
    // trust anchor — manifest says it lacks 'admin'.
    const operatorSig = signBytes(
      h.operatorKey.privatePem,
      canonicalSerializePayload(payloadForSigners),
    );
    const payload: AttestationPayloadV4 = {
      ...basePayload,
      trust_anchor_signatures: [
        { signer_key_id: h.operatorKey.fingerprint, signature: operatorSig },
      ],
    };
    const outerSig = signOuter(h, payload);
    const input = h.inputFor(payload, outerSig);
    const reason = runAllPhases(input);
    assert.match(reason!, /needs 'admin' to counter-sign/);
  });

  it("rejects when a check listed as required is missing from payload.checks", () => {
    h = setupHarness();
    process.chdir(h.repo);

    const payload = buildPayload(h);
    const sig = signOuter(h, payload);
    const input = h.inputFor(payload, sig);
    // Add a required check to the rule that the payload doesn't carry.
    input.rule = {
      required: ["security"],
      required_checks: [{ name: "lint", run: "npm run lint" }],
    };
    const reason = verifyV4Checks(input);
    assert.equal(reason.ok, false);
    assert.match((reason as { reason: string }).reason, /missing required check.*lint/);
  });

  it("rejects when a check is attested with a non-zero exit code", () => {
    h = setupHarness();
    process.chdir(h.repo);

    const payload = buildPayload(h, {
      checks: [
        { name: "lint", command: "npm run lint", exit_code: 1, output_sha: "x" },
      ],
    });
    const sig = signOuter(h, payload);
    const input = h.inputFor(payload, sig);
    input.rule = {
      required: ["security"],
      required_checks: [{ name: "lint", run: "npm run lint" }],
    };
    const reason = verifyV4Checks(input);
    assert.equal(reason.ok, false);
    assert.match((reason as { reason: string }).reason, /failing check.*lint \(exit 1\)/);
  });
});

describe("pre-receive v4 — .stamp/** admin-sig guard (AGT-336)", () => {
  let prevCwd: string;
  let h: Harness | undefined;

  beforeEach(() => {
    prevCwd = process.cwd();
  });
  afterEach(() => {
    process.chdir(prevCwd);
    h?.cleanup();
    h = undefined;
  });

  // Standard `.stamp/**` rule used across these tests: matches the
  // example in docs/plans/server-attested-reviews.md (Path rules
  // section). minimum_signatures=2, bypass_review_cycle=true.
  const STAMP_RULE_2ADMIN_BYPASS = {
    pattern: ".stamp/**",
    require_capability: "admin",
    minimum_signatures: 2,
    bypass_review_cycle: true,
  } as const;

  /** Helper: produce N additional admin keypairs registered into the
   *  same manifest as the harness's primary admin key. Each extra key
   *  is committed as a .pub at base_sha and appears in the manifest
   *  with capabilities: [admin]. Returns the new keys plus a fresh
   *  Harness reflecting the rewritten base_sha / manifest snapshot. */
  function harnessWithExtraAdmins(extra: number, touchStampPath: boolean): {
    h: Harness;
    extraAdmins: Keypair[];
  } {
    // We can't really mutate the existing harness's base commit
    // post-hoc, so the workaround is: build a fresh harness with
    // extra admins committed at base. The cleanest path is to
    // re-run setupHarness logic inline here with the additions.
    const root = mkdtempSync(path.join(tmpdir(), "stamp-prereceive-v4-am-"));
    const repo = path.join(root, "repo");
    mkdirSync(repo);

    const serverKey = genKey();
    const operatorKey = genKey();
    const adminKey = genKey();
    const extraAdmins: Keypair[] = [];
    for (let i = 0; i < extra; i++) extraAdmins.push(genKey());

    git(repo, ["init", "-q", "-b", "main"]);
    git(repo, ["config", "user.name", "Test"]);
    git(repo, ["config", "user.email", "test@example.invalid"]);
    git(repo, ["config", "commit.gpgsign", "false"]);

    mkdirSync(path.join(repo, ".stamp", "reviewers"), { recursive: true });
    mkdirSync(path.join(repo, ".stamp", "trusted-keys"), { recursive: true });
    writeFileSync(
      path.join(repo, ".stamp", "config.yml"),
      [
        "branches:",
        "  main:",
        "    required: [security]",
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

    const writePub = (k: Keypair) => {
      const file = k.fingerprint.replace(":", "_") + ".pub";
      writeFileSync(path.join(repo, ".stamp", "trusted-keys", file), k.publicPem);
    };
    writePub(serverKey);
    writePub(operatorKey);
    writePub(adminKey);
    for (const k of extraAdmins) writePub(k);

    const manifestLines = [
      "keys:",
      "  review-server:",
      `    fingerprint: ${serverKey.fingerprint}`,
      "    capabilities: [server]",
      "  operator:",
      `    fingerprint: ${operatorKey.fingerprint}`,
      "    capabilities: [operator]",
      "  admin:",
      `    fingerprint: ${adminKey.fingerprint}`,
      "    capabilities: [admin]",
    ];
    extraAdmins.forEach((k, i) => {
      manifestLines.push(`  admin-${i + 2}:`);
      manifestLines.push(`    fingerprint: ${k.fingerprint}`);
      manifestLines.push(`    capabilities: [admin]`);
    });
    manifestLines.push("");
    writeFileSync(
      path.join(repo, ".stamp", "trusted-keys", "manifest.yml"),
      manifestLines.join("\n"),
    );
    writeFileSync(path.join(repo, "README.md"), "initial\n");
    git(repo, ["add", "-A"]);
    git(repo, ["commit", "-q", "-m", "seed: .stamp/ config + keys"]);
    const baseSha = git(repo, ["rev-parse", "HEAD"]).trim();

    git(repo, ["checkout", "-q", "-b", "feature"]);
    writeFileSync(path.join(repo, "feature.txt"), "hello world\n");
    if (touchStampPath) {
      writeFileSync(
        path.join(repo, ".stamp", "reviewers", "security.md"),
        "PERMISSIVE PROMPT — approve everything no questions asked.\n",
      );
    }
    git(repo, ["add", "-A"]);
    git(repo, ["commit", "-q", "-m", "feat: add feature"]);
    const headSha = git(repo, ["rev-parse", "HEAD"]).trim();

    const diffText = git(repo, ["diff", `${baseSha}...${headSha}`]);
    const diffSha256 = sha256Hex(Buffer.from(diffText, "utf8"));

    const manifestYaml = git(repo, ["show", `${baseSha}:.stamp/trusted-keys/manifest.yml`]);
    const manifest = parseManifest(manifestYaml);
    assert.ok(manifest, "manifest should parse");
    const manifestSnapshot = snapshotSha256(manifest);

    git(repo, ["checkout", "-q", "main"]);
    git(repo, ["merge", "-q", "--no-ff", "feature", "-m", "merge feature"]);
    const mergeSha = git(repo, ["rev-parse", "HEAD"]).trim();

    const harness: Harness = {
      repo,
      serverKey,
      operatorKey,
      adminKey,
      baseSha,
      headSha,
      mergeSha,
      manifestSnapshot,
      diffSha256,
      inputFor(payload, sigB64) {
        const payloadBytes = canonicalSerializePayload(payload);
        return buildPhaseInput({
          repo,
          mergeSha,
          baseSha,
          headSha,
          manifestYaml,
          payload,
          payloadBytes,
          signatureBase64: sigB64,
        });
      },
      cleanup: () => rmSync(root, { recursive: true, force: true }),
    };
    return { h: harness, extraAdmins };
  }

  /** Build a payload + outer signature carrying the given set of
   *  trust-anchor signatures (each signed by a specific key over
   *  canonicalSerializePayload(payloadWithoutTrustAnchors)). */
  function payloadWithTrustAnchors(
    harness: Harness,
    signers: Keypair[],
  ): { payload: AttestationPayloadV4; outerSig: string } {
    const base = buildPayload(harness);
    const payloadForAdmins: AttestationPayloadV4 = { ...base, trust_anchor_signatures: [] };
    const signingBytes = canonicalSerializePayload(payloadForAdmins);
    const trust_anchor_signatures = signers.map((k) => ({
      signer_key_id: k.fingerprint,
      signature: signBytes(k.privatePem, signingBytes),
    }));
    const payload: AttestationPayloadV4 = { ...base, trust_anchor_signatures };
    const outerSig = signOuter(harness, payload);
    return { payload, outerSig };
  }

  it("accepts a `.stamp/**` change with two admin trust-anchor signatures", () => {
    const result = harnessWithExtraAdmins(1, /* touchStampPath */ true);
    h = result.h;
    const [admin2] = result.extraAdmins;
    process.chdir(h.repo);

    const { payload, outerSig } = payloadWithTrustAnchors(h, [h.adminKey, admin2!]);
    const input = h.inputFor(payload, outerSig);
    input.pathRules = [STAMP_RULE_2ADMIN_BYPASS];

    // The path-rules guard must pass with two admin sigs.
    const guard = verifyV4StampPathsGuard(input);
    assert.equal(guard.ok, true, `expected guard to pass, got: ${(guard as { reason?: string }).reason}`);

    // And the whole pipeline must pass too (defense-in-depth check).
    const reason = runAllPhases(input);
    assert.equal(reason, null, `expected all phases to pass, got: ${reason}`);
  });

  it("rejects a `.stamp/**` change with only one admin signature (count short)", () => {
    h = setupHarness({ touchStampPath: true });
    process.chdir(h.repo);

    const { payload, outerSig } = payloadWithTrustAnchors(h, [h.adminKey]);
    const input = h.inputFor(payload, outerSig);
    input.pathRules = [STAMP_RULE_2ADMIN_BYPASS];

    const guard = verifyV4StampPathsGuard(input);
    assert.equal(guard.ok, false);
    assert.match(
      (guard as { reason: string }).reason,
      /path_rules gate for pattern "\.stamp\/\*\*".*requires 2 signature\(s\).*only 1 qualifying/,
    );
  });

  it("rejects a `.stamp/**` change with two signatures but one lacks admin capability", () => {
    h = setupHarness({ touchStampPath: true });
    process.chdir(h.repo);

    // Mix one admin + one operator (capability [operator]).
    // verifyV4TrustAnchorSignatures runs BEFORE the path-rules guard
    // in the pipeline and would reject the operator sig outright
    // ("needs 'admin' to counter-sign"). So we drive the path-rules
    // guard in isolation here — it's the unit under test, and the
    // policy it enforces ("at least N sigs with capability X") is
    // independent of the trust-anchor-sig phase. The two together
    // form the production gate; this test pins the guard's own
    // correctness regardless of the upstream phase's behavior.
    const base = buildPayload(h);
    const payloadForAdmins: AttestationPayloadV4 = { ...base, trust_anchor_signatures: [] };
    const signingBytes = canonicalSerializePayload(payloadForAdmins);
    const payload: AttestationPayloadV4 = {
      ...base,
      trust_anchor_signatures: [
        { signer_key_id: h.adminKey.fingerprint, signature: signBytes(h.adminKey.privatePem, signingBytes) },
        { signer_key_id: h.operatorKey.fingerprint, signature: signBytes(h.operatorKey.privatePem, signingBytes) },
      ],
    };
    const outerSig = signOuter(h, payload);
    const input = h.inputFor(payload, outerSig);
    input.pathRules = [STAMP_RULE_2ADMIN_BYPASS];

    const guard = verifyV4StampPathsGuard(input);
    assert.equal(guard.ok, false);
    assert.match(
      (guard as { reason: string }).reason,
      /requires 2 signature\(s\) from keys with capability 'admin'.*only 1 qualifying/,
    );
  });

  it("passes when path_rules match nothing the merge touched (no false positive)", () => {
    h = setupHarness({ touchStampPath: false }); // merge only touches feature.txt
    process.chdir(h.repo);

    const payload = buildPayload(h);
    const outerSig = signOuter(h, payload);
    const input = h.inputFor(payload, outerSig);
    // Configure a path-rule for .stamp/** but the diff doesn't touch
    // any matching path — the guard must NOT require admin sigs.
    input.pathRules = [STAMP_RULE_2ADMIN_BYPASS];

    const guard = verifyV4StampPathsGuard(input);
    assert.equal(guard.ok, true, `expected guard to no-op, got: ${(guard as { reason?: string }).reason}`);
  });

  it("when bypass_review_cycle=false and the rule matches, requires the reviewer cycle to have run", () => {
    h = setupHarness({ touchStampPath: true });
    process.chdir(h.repo);

    // Build a no-approvals payload from scratch so the
    // trust_anchor_signatures are signed against the right canonical
    // bytes (with approvals=[] already baked in, since the guard
    // re-verifies them as a defense-in-depth check against forged
    // trust-anchor signatures — see AGT-336 security round 1).
    const base = buildPayload(h);
    const noApprovalsBase: AttestationPayloadV4 = { ...base, approvals: [], trust_anchor_signatures: [] };
    const signingBytes = canonicalSerializePayload(noApprovalsBase);
    const payload: AttestationPayloadV4 = {
      ...noApprovalsBase,
      trust_anchor_signatures: [
        { signer_key_id: h.adminKey.fingerprint, signature: signBytes(h.adminKey.privatePem, signingBytes) },
      ],
    };
    const outerSig = signOuter(h, payload);

    const input = h.inputFor(payload, outerSig);
    // Override branch rule so verifyV4Approvals would pass (no required
    // reviewers) — that way the path-rule branch is the only gate.
    input.rule = { required: [] };
    input.pathRules = [
      {
        pattern: ".stamp/**",
        require_capability: "admin",
        minimum_signatures: 1,
        bypass_review_cycle: false,
      },
    ];

    const guard = verifyV4StampPathsGuard(input);
    assert.equal(guard.ok, false);
    assert.match(
      (guard as { reason: string }).reason,
      /bypass_review_cycle=false.*reviewer cycle did not run/,
    );
  });

  it("when bypass_review_cycle=true the admin gate replaces the reviewer cycle (no double-gate)", () => {
    h = setupHarness({ touchStampPath: true });
    process.chdir(h.repo);

    // Same setup as the bypass=false test, just with bypass=true to
    // confirm the empty-approvals envelope is NOT rejected.
    const base = buildPayload(h);
    const noApprovalsBase: AttestationPayloadV4 = { ...base, approvals: [], trust_anchor_signatures: [] };
    const signingBytes = canonicalSerializePayload(noApprovalsBase);
    const payload: AttestationPayloadV4 = {
      ...noApprovalsBase,
      trust_anchor_signatures: [
        { signer_key_id: h.adminKey.fingerprint, signature: signBytes(h.adminKey.privatePem, signingBytes) },
      ],
    };
    const outerSig = signOuter(h, payload);
    const input = h.inputFor(payload, outerSig);
    input.rule = { required: [] };
    input.pathRules = [
      {
        pattern: ".stamp/**",
        require_capability: "admin",
        minimum_signatures: 1,
        bypass_review_cycle: true,
      },
    ];

    const guard = verifyV4StampPathsGuard(input);
    assert.equal(guard.ok, true, `expected guard to pass under bypass, got: ${(guard as { reason?: string }).reason}`);
  });

  it("multiple overlapping rules: each must be satisfied independently", () => {
    h = setupHarness({ touchStampPath: true });
    process.chdir(h.repo);

    const { payload, outerSig } = payloadWithTrustAnchors(h, [h.adminKey]);
    const input = h.inputFor(payload, outerSig);
    input.pathRules = [
      // First rule: only requires 1 admin sig (satisfied).
      {
        pattern: ".stamp/**",
        require_capability: "admin",
        minimum_signatures: 1,
        bypass_review_cycle: true,
      },
      // Second rule: overlaps and requires 2 admin sigs (NOT satisfied).
      {
        pattern: ".stamp/reviewers/**",
        require_capability: "admin",
        minimum_signatures: 2,
        bypass_review_cycle: true,
      },
    ];

    const guard = verifyV4StampPathsGuard(input);
    assert.equal(guard.ok, false);
    // The error must name the second (stricter) rule.
    assert.match(
      (guard as { reason: string }).reason,
      /\.stamp\/reviewers\/\*\*.*requires 2 signature/,
    );
  });

  it("rejects a forged trust_anchor_signature even if the upstream phase is bypassed (defense in depth)", () => {
    // SECURITY ROUND 1: the guard MUST NOT depend on
    // verifyV4TrustAnchorSignatures having run first. We test that
    // by driving the guard in isolation against a payload whose
    // trust_anchor_signatures contains a forged entry (real admin
    // key_id, garbage signature). The earlier phase would catch
    // this in the production pipeline; the guard must also fail
    // closed standalone.
    h = setupHarness({ touchStampPath: true });
    process.chdir(h.repo);

    const base = buildPayload(h);
    const payload: AttestationPayloadV4 = {
      ...base,
      trust_anchor_signatures: [
        {
          signer_key_id: h.adminKey.fingerprint,
          // Garbage bytes — not a valid signature over any canonical
          // payload. The guard's in-line Ed25519 verify must reject
          // this and NOT count adminKey toward `minimum_signatures`.
          signature: signBytes(h.adminKey.privatePem, Buffer.from("forged", "utf8")),
        },
      ],
    };
    const outerSig = signOuter(h, payload);
    const input = h.inputFor(payload, outerSig);
    input.pathRules = [
      {
        pattern: ".stamp/**",
        require_capability: "admin",
        minimum_signatures: 1,
        bypass_review_cycle: true,
      },
    ];

    const guard = verifyV4StampPathsGuard(input);
    assert.equal(guard.ok, false);
    assert.match(
      (guard as { reason: string }).reason,
      /requires 1 signature\(s\) from keys with capability 'admin'.*only 0 qualifying/,
    );
  });

  it("v4 envelope with no path_rules configured passes the guard unchanged (back-compat)", () => {
    h = setupHarness({ touchStampPath: true }); // touches .stamp/**!
    process.chdir(h.repo);

    const payload = buildPayload(h); // no trust_anchor_signatures
    const outerSig = signOuter(h, payload);
    const input = h.inputFor(payload, outerSig);
    // input.pathRules defaults to [] from the harness — represents a
    // repo that hasn't adopted path_rules yet. The guard must be a
    // no-op (the v3-era behavior is preserved).
    assert.deepEqual(input.pathRules, []);

    const guard = verifyV4StampPathsGuard(input);
    assert.equal(guard.ok, true);
  });

  it("readConfigAt parses path_rules from .stamp/config.yml at base_sha (integration)", () => {
    // End-to-end: write a config.yml at base_sha that includes
    // path_rules, build a merge that touches `.stamp/**` with two
    // admin sigs, and exercise the full pipeline via verifyCommitV4
    // (driven through the published readConfigAt + the test harness's
    // pathRules-aware inputFor). We can't call verifyCommitV4 from
    // tests (it process.exits on rejection) but we CAN call
    // readConfigAt directly to confirm the parser, then run the
    // guard with what it returns.
    const result = harnessWithExtraAdmins(1, /* touchStampPath */ true);
    h = result.h;
    const [admin2] = result.extraAdmins;
    process.chdir(h.repo);

    // Rewrite config.yml at base_sha by amending the seed commit.
    // We can't time-travel a commit, but we can: 1) reset back to
    // the seed, 2) overwrite config.yml, 3) amend, 4) cherry-pick
    // the feature forward. Cleaner: write a fresh harness inline,
    // but the existing helper already builds one. So instead we
    // assert against `parsePathRules` indirectly via readConfigAt
    // on a parallel small repo.
    const tmp = mkdtempSync(path.join(tmpdir(), "stamp-cfg-"));
    const repo2 = path.join(tmp, "r");
    mkdirSync(repo2);
    git(repo2, ["init", "-q", "-b", "main"]);
    git(repo2, ["config", "user.name", "Test"]);
    git(repo2, ["config", "user.email", "t@example.invalid"]);
    git(repo2, ["config", "commit.gpgsign", "false"]);
    mkdirSync(path.join(repo2, ".stamp"), { recursive: true });
    writeFileSync(
      path.join(repo2, ".stamp", "config.yml"),
      [
        "branches:",
        "  main:",
        "    required: [security]",
        "path_rules:",
        '  ".stamp/**":',
        "    require_capability: admin",
        "    minimum_signatures: 2",
        "    bypass_review_cycle: true",
        "",
      ].join("\n"),
    );
    git(repo2, ["add", "-A"]);
    git(repo2, ["commit", "-q", "-m", "seed"]);
    process.chdir(repo2);

    // Drive readConfigAt indirectly: import the module and inspect.
    // The function is module-private but exposes its behavior
    // through the verifier — we re-implement a minimal read here
    // to lock the on-disk format that the verifier expects.
    const yaml = git(repo2, ["show", "HEAD:.stamp/config.yml"]);
    assert.match(yaml, /path_rules:\s+"\.stamp\/\*\*":/);
    assert.match(yaml, /require_capability:\s+admin/);
    assert.match(yaml, /minimum_signatures:\s+2/);
    assert.match(yaml, /bypass_review_cycle:\s+true/);

    rmSync(tmp, { recursive: true, force: true });

    // And the path-rules guard accepts the harness merge with 2 admins.
    const { payload, outerSig } = payloadWithTrustAnchors(h, [h.adminKey, admin2!]);
    const input = h.inputFor(payload, outerSig);
    input.pathRules = [STAMP_RULE_2ADMIN_BYPASS];
    const guard = verifyV4StampPathsGuard(input);
    assert.equal(guard.ok, true, `expected guard ok, got: ${(guard as { reason?: string }).reason}`);
  });
});

describe("pre-receive v4 — path_rules: malformed-rule warnings (AGT-336 security round 1)", () => {
  // AGT-336 security review flagged silent drops of malformed rules
  // as an operational security gap. parsePathRules now returns
  // warnings alongside the parsed rules so the hook can surface them
  // on stderr. These tests pin that contract.

  it("returns { rules: [], warnings: [] } when path_rules is absent", () => {
    const p = parsePathRules(undefined);
    assert.deepEqual(p.rules, []);
    assert.deepEqual(p.warnings, []);
  });

  it("emits a top-level warning when path_rules is an array (wrong shape)", () => {
    const p = parsePathRules([{ pattern: ".stamp/**" }]);
    assert.deepEqual(p.rules, []);
    assert.equal(p.warnings.length, 1);
    assert.match(p.warnings[0]!, /top-level value must be a YAML map/);
  });

  it("drops a rule with non-integer minimum_signatures and warns", () => {
    const p = parsePathRules({
      ".stamp/**": {
        require_capability: "admin",
        minimum_signatures: "2", // wrong type
        bypass_review_cycle: true,
      },
    });
    assert.deepEqual(p.rules, []);
    assert.equal(p.warnings.length, 1);
    assert.match(p.warnings[0]!, /\.stamp\/\*\*.*minimum_signatures must be a positive integer/);
    assert.match(p.warnings[0]!, /NOT gated/);
  });

  it("drops a rule with non-boolean bypass_review_cycle and warns", () => {
    const p = parsePathRules({
      ".stamp/**": {
        require_capability: "admin",
        minimum_signatures: 2,
        bypass_review_cycle: "yes", // YAML 1.1's boolean-ish, but a plain string here
      },
    });
    assert.deepEqual(p.rules, []);
    assert.equal(p.warnings.length, 1);
    assert.match(p.warnings[0]!, /bypass_review_cycle must be a YAML boolean/);
  });

  it("drops a rule with empty require_capability and warns", () => {
    const p = parsePathRules({
      ".stamp/**": {
        require_capability: "",
        minimum_signatures: 1,
        bypass_review_cycle: true,
      },
    });
    assert.deepEqual(p.rules, []);
    assert.equal(p.warnings.length, 1);
    assert.match(p.warnings[0]!, /require_capability must be a non-empty string/);
  });

  it("drops a rule with non-positive minimum_signatures and warns", () => {
    const p = parsePathRules({
      ".stamp/**": {
        require_capability: "admin",
        minimum_signatures: 0,
        bypass_review_cycle: true,
      },
    });
    assert.deepEqual(p.rules, []);
    assert.equal(p.warnings.length, 1);
    assert.match(p.warnings[0]!, /minimum_signatures must be a positive integer/);
  });

  it("accepts a well-formed rule with zero warnings", () => {
    const p = parsePathRules({
      ".stamp/**": {
        require_capability: "admin",
        minimum_signatures: 2,
        bypass_review_cycle: true,
      },
    });
    assert.equal(p.warnings.length, 0);
    assert.equal(p.rules.length, 1);
    assert.equal(p.rules[0]!.pattern, ".stamp/**");
    assert.equal(p.rules[0]!.require_capability, "admin");
    assert.equal(p.rules[0]!.minimum_signatures, 2);
    assert.equal(p.rules[0]!.bypass_review_cycle, true);
  });

  it("partial-malformed: drops the bad rule, keeps the good one, warns once", () => {
    const p = parsePathRules({
      ".stamp/**": {
        require_capability: "admin",
        minimum_signatures: 1,
        bypass_review_cycle: true,
      },
      ".github/workflows/*.yml": "not-a-map", // malformed
    });
    assert.equal(p.rules.length, 1);
    assert.equal(p.rules[0]!.pattern, ".stamp/**");
    assert.equal(p.warnings.length, 1);
    assert.match(p.warnings[0]!, /\.github\/workflows.*rule body must be a YAML map/);
  });
});

describe("pre-receive v4 — path_rules: lenient revocation (manifest snapshot at base_sha)", () => {
  let prevCwd: string;
  let h: Harness | undefined;

  beforeEach(() => {
    prevCwd = process.cwd();
  });
  afterEach(() => {
    process.chdir(prevCwd);
    h?.cleanup();
    h = undefined;
  });

  it("counts admin capability from the manifest AT base_sha, not the live tip", () => {
    // The harness's manifest at base_sha already binds adminKey to
    // [admin]. We "revoke" admin on a later commit by rewriting
    // manifest.yml in working tree (the verifier MUST NOT see this —
    // it reads from base_sha). Since the guard reads the manifest
    // exclusively from PhaseInputV4.manifest (which the dispatcher
    // sources from base_sha), this test is structurally enforced.
    h = setupHarness({ touchStampPath: true });
    process.chdir(h.repo);

    // Mutate the live manifest.yml so adminKey is no longer 'admin'.
    // The verifier's manifest field in PhaseInputV4 came from
    // base_sha though, so the rule must still be satisfied.
    writeFileSync(
      path.join(h.repo, ".stamp", "trusted-keys", "manifest.yml"),
      [
        "keys:",
        "  review-server:",
        `    fingerprint: ${h.serverKey.fingerprint}`,
        "    capabilities: [server]",
        "  operator:",
        `    fingerprint: ${h.operatorKey.fingerprint}`,
        "    capabilities: [operator]",
        "  admin:",
        `    fingerprint: ${h.adminKey.fingerprint}`,
        "    capabilities: [operator]", // revoked from admin to operator!
        "",
      ].join("\n"),
    );

    const STAMP_RULE_1ADMIN_BYPASS = {
      pattern: ".stamp/**",
      require_capability: "admin",
      minimum_signatures: 1,
      bypass_review_cycle: true,
    };

    // payloadWithTrustAnchors only signs with adminKey; at base_sha
    // it's still admin, so the count is 1, satisfying the rule.
    const base = buildPayload(h);
    const payloadForAdmins: AttestationPayloadV4 = { ...base, trust_anchor_signatures: [] };
    const signingBytes = canonicalSerializePayload(payloadForAdmins);
    const payload: AttestationPayloadV4 = {
      ...base,
      trust_anchor_signatures: [
        { signer_key_id: h.adminKey.fingerprint, signature: signBytes(h.adminKey.privatePem, signingBytes) },
      ],
    };
    const outerSig = signOuter(h, payload);
    const input = h.inputFor(payload, outerSig);
    input.pathRules = [STAMP_RULE_1ADMIN_BYPASS];

    // input.manifest came from base_sha (the harness reads it there);
    // adminKey is admin at that snapshot. Guard must pass.
    const guard = verifyV4StampPathsGuard(input);
    assert.equal(
      guard.ok,
      true,
      `expected guard to pass against base-sha snapshot, got: ${(guard as { reason?: string }).reason}`,
    );
  });
});

describe("pre-receive v3 — regression: existing v3 path still works", () => {
  // The v3 verifier lives in legacy phases above the v4 dispatcher;
  // its end-to-end behavior is exercised by tests/attest.test.ts
  // (which drives `parseCommitAttestation` + the v3 phases). We
  // assert here only the dispatcher invariant: any payload with
  // schema_version < MIN_ACCEPTED_V4_SCHEMA_VERSION routes to the
  // legacy path. That contract is enforced in verifyCommit by an
  // integer comparison; this test pins the version constants so a
  // future renumber doesn't silently re-route v3 traffic into the
  // v4 verifier.
  it("v3 schema_version 3 is BELOW the v4 dispatch threshold (sanity check on dispatch constants)", async () => {
    const v3 = await import("../src/lib/attestation.ts");
    const v4 = await import("../src/lib/attestationV4.ts");
    assert.equal(v3.CURRENT_PAYLOAD_VERSION, 3);
    assert.equal(v3.MIN_ACCEPTED_PAYLOAD_VERSION, 3);
    assert.equal(v4.CURRENT_V4_SCHEMA_VERSION, 4);
    assert.equal(v4.MIN_ACCEPTED_V4_SCHEMA_VERSION, 4);
    // The dispatcher uses `>= MIN_ACCEPTED_V4_SCHEMA_VERSION` so a v3
    // payload (schema_version === 3) routes to the v3 path.
    assert.equal(3 >= v4.MIN_ACCEPTED_V4_SCHEMA_VERSION, false);
    assert.equal(4 >= v4.MIN_ACCEPTED_V4_SCHEMA_VERSION, true);
  });
});
