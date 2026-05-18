/**
 * AGT-354 — v4 attestation round-trip E2E smoke harness.
 *
 * The verification-harness ticket. Until this lands, the two halves of
 * the v4 attestation flow have never been touched by the same test:
 *   - AGT-334 (`stamp merge` folding server-signed approvals into a v4
 *     envelope) lives in `tests/mergeV4.test.ts` and verifies trailer
 *     output with a handwritten verifier — independent of the real hook.
 *   - AGT-335 (the pre-receive v4 phases) lives in `tests/preReceiveV4.test.ts`
 *     and drives the phase functions directly with handwritten merge
 *     commits — independent of the real `runMerge`.
 *
 * This file closes the loop: it runs `runMerge` against a real fixture
 * repo and feeds the resulting merge-commit trailers through the REAL
 * `verifyV4*` phases imported from `src/hooks/pre-receive.ts`. A break
 * in either half — schema drift between the merge-time producer and the
 * verifier, a column mismatch between AGT-333's DB and AGT-334's read,
 * a canonicalization-byte disagreement between the server and operator
 * sides — surfaces here as a phase rejection rather than as a green
 * unit suite that passes both ends in isolation.
 *
 * The harness is intentionally distinct from `mergeV4.test.ts`:
 *   - mergeV4 verifies trailer ASSEMBLY (the bytes runMerge writes).
 *   - v4Roundtrip verifies that ASSEMBLY + the real VERIFIER agree on
 *     the bytes — the integration property neither isolated test can
 *     observe. We deliberately duplicate a small amount of fixture
 *     setup rather than extract a shared helper: the two tests can
 *     drift independently when the contract evolves, and a shared
 *     helper would couple them.
 *
 * Hermetic: temp dirs, ephemeral keypairs, no network, no real
 * stamp-server, full suite well under 2s per the test budget. The
 * fixture commits the operator pubkey + manifest entry at base_sha so
 * the v4 verifier can resolve `signer_key_id` to a real key with
 * `[operator]` capability — this differs from mergeV4 (which only
 * commits the server's key, because mergeV4 verifies the outer
 * signature directly without going through `verifyV4SignerTrust`).
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  createPublicKey,
  verify as cryptoVerify,
} from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

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
  type Verdict,
} from "../src/lib/db.ts";
import { ensureUserKeypair, fingerprintFromPem } from "../src/lib/keys.ts";
import { stampStateDbPath } from "../src/lib/paths.ts";
import { signBytes } from "../src/lib/signing.ts";
import { buildPubkeyMap } from "../src/lib/sshReviewClient.ts";
import { parseManifest, snapshotSha256 } from "../src/lib/trustedKeysManifest.ts";
import {
  verifyV4Approvals,
  verifyV4ApprovalSignatures,
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

// ─── Helpers ────────────────────────────────────────────────────────

interface ServerKey {
  privatePem: string;
  publicPem: string;
  fingerprint: string;
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

const REVIEWER_PROMPT = "You are the security reviewer. Approve everything.\n";

// Use the no-TTY opt-out so requireHumanMerge doesn't block tests.
process.env["STAMP_REQUIRE_HUMAN_MERGE"] = "0";

/**
 * Extract the two v4 trailer values out of a commit message.
 * Standalone (not importing parseCommitAttestation from v3) to keep
 * this E2E test's "what the hook sees" path explicit.
 */
function extractTrailers(commitMsg: string): {
  payloadB64: string;
  signatureB64: string;
} {
  const payloadMatch = commitMsg.match(/^Stamp-Payload:\s*(.+)$/m);
  const sigMatch = commitMsg.match(/^Stamp-Verified:\s*(.+)$/m);
  assert.ok(payloadMatch, "Stamp-Payload trailer missing from merge commit");
  assert.ok(sigMatch, "Stamp-Verified trailer missing from merge commit");
  return {
    payloadB64: payloadMatch[1]!.trim(),
    signatureB64: sigMatch[1]!.trim(),
  };
}

/**
 * Build a `PhaseInputV4` directly from a produced merge commit's
 * trailers + a working repo. This is exactly the wiring the real
 * pre-receive hook does in `verifyCommitV4` (in `src/hooks/pre-receive.ts`)
 * — re-implemented here using the test's `git` wrapper because the
 * hook's `run` function is a private file-local helper. Re-using
 * `verifyV4*` against this input asserts the same code path the bare
 * repo would execute.
 */
function buildPhaseInput(args: {
  repo: string;
  mergeSha: string;
  branch: string;
  required: string[];
  payloadB64: string;
  signatureB64: string;
}): PhaseInputV4 {
  const payloadBytes = trailerValueToPayloadBytes(args.payloadB64);
  const payload = JSON.parse(payloadBytes.toString("utf8")) as AttestationPayloadV4;

  const manifestYaml = git(args.repo, [
    "show",
    `${payload.base_sha}:.stamp/trusted-keys/manifest.yml`,
  ]);
  const manifest = parseManifest(manifestYaml);
  assert.ok(manifest, "manifest at base_sha must parse");

  const lsOut = git(args.repo, [
    "ls-tree",
    "--name-only",
    payload.base_sha,
    ".stamp/trusted-keys/",
  ]);
  const pubFiles = lsOut
    .split("\n")
    .filter((l) => l.length > 0)
    .map((l) => {
      const prefix = ".stamp/trusted-keys/";
      return l.startsWith(prefix) ? l.slice(prefix.length) : l;
    })
    .filter((n) => n.endsWith(".pub"));
  const pubkeyByFingerprint = buildPubkeyMap(pubFiles, (relPath) =>
    git(args.repo, ["show", `${payload.base_sha}:${relPath}`]),
  );

  return {
    sha: args.mergeSha,
    branch: args.branch,
    rule: { required: args.required },
    payload,
    payloadBytes,
    signatureBase64: args.signatureB64,
    manifest,
    pubkeyByFingerprint,
  };
}

/**
 * Drive every v4 phase in pipeline order, returning the first failure
 * reason or null on full success. Mirrors `verifyCommitV4`'s
 * COMMIT_PHASES_V4 list (in `src/hooks/pre-receive.ts`). When that
 * pipeline order changes, this list must follow — pin the order rather
 * than `Object.values`-style to keep "which phase rejected" stable.
 */
function runAllV4Phases(input: PhaseInputV4): { phase: string; reason: string } | null {
  const phases: ReadonlyArray<{ name: string; fn: (i: PhaseInputV4) => { ok: true } | { ok: false; reason: string } }> = [
    { name: "verifyV4MergeStructure", fn: verifyV4MergeStructure },
    { name: "verifyV4TargetBranch", fn: verifyV4TargetBranch },
    { name: "verifyV4SignerTrust", fn: verifyV4SignerTrust },
    { name: "verifyV4OuterSignature", fn: verifyV4OuterSignature },
    { name: "verifyV4Approvals", fn: verifyV4Approvals },
    { name: "verifyV4DiffHash", fn: verifyV4DiffHash },
    { name: "verifyV4ApprovalSignatures", fn: verifyV4ApprovalSignatures },
    { name: "verifyV4Checks", fn: verifyV4Checks },
    { name: "verifyV4TrustAnchorSignatures", fn: verifyV4TrustAnchorSignatures },
    { name: "verifyV4StampPathsGuard", fn: verifyV4StampPathsGuard },
  ];
  for (const phase of phases) {
    const r = phase.fn(input);
    if (!r.ok) return { phase: phase.name, reason: r.reason };
  }
  return null;
}

// ─── Harness ────────────────────────────────────────────────────────

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
 * Build a v4-ready fixture repo and HOME.
 *
 * Differs from mergeV4's setupHarness in one key way: we commit the
 * operator's pubkey to `.stamp/trusted-keys/` and register it in the
 * manifest with `capabilities: [operator]`. mergeV4 doesn't do this
 * because its handwritten verifier checks the operator's signature
 * against the pubkey it pulls from `ensureUserKeypair()` directly —
 * but the REAL pre-receive verifier (which we drive in this test)
 * loads the operator pubkey from the manifest at base_sha. Without
 * the operator entry there, `verifyV4SignerTrust` would reject the
 * fully-correct merge, masking real-world breakage behind a fixture
 * gap.
 */
function setupHarness(): Harness {
  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-v4-roundtrip-"));
  const repo = path.join(root, "repo");
  const home = path.join(root, "home");
  mkdirSync(repo, { recursive: true });
  mkdirSync(home, { recursive: true });

  const prevHome = process.env["HOME"];
  process.env["HOME"] = home;

  const serverKey = generateServerKey();

  // Mint the operator keypair via the same code path runMerge will
  // hit at merge time. Because HOME is redirected, this writes to the
  // temp dir and runMerge picks up the same key — no second mint, no
  // fingerprint mismatch.
  const { keypair: operatorKp } = ensureUserKeypair();
  const operatorFingerprint = operatorKp.fingerprint;

  git(repo, ["init", "-q", "-b", "main"]);
  git(repo, ["config", "user.name", "Test"]);
  git(repo, ["config", "user.email", "test@example.invalid"]);
  git(repo, ["config", "commit.gpgsign", "false"]);

  mkdirSync(path.join(repo, ".stamp", "reviewers"), { recursive: true });
  mkdirSync(path.join(repo, ".stamp", "trusted-keys"), { recursive: true });

  // review_server set on main triggers the v4 dispatch in runMerge.
  // The value is opaque to the merge command (no SSH connection is
  // made by runMerge itself — it only consults the local DB).
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

  // Commit the server's pubkey + the operator's pubkey, both with
  // manifest entries binding the fingerprint to the right capability.
  // The pre-receive verifier consults the manifest at base_sha as the
  // trust root for BOTH the outer signer (must have admin or operator)
  // and each inner approval signer (must have server).
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

  // Feature branch with a small code change.
  git(repo, ["checkout", "-q", "-b", "feature"]);
  writeFileSync(path.join(repo, "feature.txt"), "hello\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "add feature"]);

  // Switch back to main — `stamp merge` requires being on the target.
  git(repo, ["checkout", "-q", "main"]);

  return {
    root,
    repo,
    home,
    prevHome,
    serverKey,
    operatorFingerprint,
    cleanup: () => {
      if (prevHome === undefined) {
        delete process.env["HOME"];
      } else {
        process.env["HOME"] = prevHome;
      }
      rmSync(root, { recursive: true, force: true });
    },
  };
}

/**
 * Compute the canonical manifest snapshot hash at base_sha — exactly
 * what the verifier compares the approval's
 * `trusted_keys_snapshot_sha256` against in `verifyV4ApprovalSignatures`.
 */
function manifestSnapshotAtBase(repo: string, baseSha: string): string {
  const yaml = git(repo, ["show", `${baseSha}:.stamp/trusted-keys/manifest.yml`]);
  const parsed = parseManifest(yaml);
  assert.ok(parsed, "manifest must parse at base_sha");
  return snapshotSha256(parsed);
}

/** Seed a server-signed approval row at (base, head) for `reviewer`. */
function seedV4Review(args: {
  repo: string;
  reviewer: string;
  baseSha: string;
  headSha: string;
  diffSha256: string;
  serverKey: ServerKey;
  manifestSnapshot: string;
  verdict?: Verdict;
  /** Optionally override the approval body before it's signed (negative-test hook). */
  mutate?: (a: ApprovalV4) => ApprovalV4;
  /** Optionally replace the signature with arbitrary bytes (negative-test hook). */
  forgeSignatureB64?: string;
}): { approval: ApprovalV4; signatureB64: string } {
  const approval = (args.mutate ?? ((a) => a))({
    reviewer: args.reviewer,
    verdict: args.verdict ?? "approved",
    prompt_sha256: sha256Hex(REVIEWER_PROMPT),
    diff_sha256: args.diffSha256,
    base_sha: args.baseSha,
    head_sha: args.headSha,
    trusted_keys_snapshot_sha256: args.manifestSnapshot,
    issued_at: "2026-05-17T18:42:13Z",
    server_key_id: args.serverKey.fingerprint,
  });
  const signatureB64 =
    args.forgeSignatureB64 ??
    signBytes(args.serverKey.privatePem, canonicalSerializeApproval(approval));

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

// ─── Tests ──────────────────────────────────────────────────────────

describe("v4 attestation round-trip — happy path", () => {
  let h: Harness | undefined;
  let prevCwd = process.cwd();

  beforeEach(() => {
    prevCwd = process.cwd();
  });
  afterEach(() => {
    process.chdir(prevCwd);
    h?.cleanup();
    h = undefined;
  });

  it("runMerge → trailers → real verifyV4 phases all pass; shape + hashes + signatures agree", () => {
    h = setupHarness();
    const base = shaOf(h.repo, "main");
    const head = shaOf(h.repo, "feature");
    const diff = git(h.repo, ["diff", `${base}...${head}`]);
    const diffSha256 = sha256Hex(diff);
    const manifestSnapshot = manifestSnapshotAtBase(h.repo, base);

    seedV4Review({
      repo: h.repo,
      reviewer: "security",
      baseSha: base,
      headSha: head,
      diffSha256,
      serverKey: h.serverKey,
      manifestSnapshot,
    });

    // ① Drive the real merge command end-to-end.
    runFromRepo(h.repo, () =>
      runMerge({ branch: "feature", into: "main", yes: true }),
    );

    // ② Extract the trailers the way the pre-receive hook will see them.
    const mergeSha = shaOf(h.repo, "main");
    const mergeMsg = git(h.repo, ["log", "-1", "--pretty=%B"]);
    const { payloadB64, signatureB64 } = extractTrailers(mergeMsg);

    // ③ Decode the payload + assert envelope shape against
    //    attestationV4.ts contract. Top-level invariants only —
    //    field-level cryptography is the next step.
    const payloadBytes = trailerValueToPayloadBytes(payloadB64);
    const payload: AttestationPayloadV4 = JSON.parse(payloadBytes.toString("utf8"));
    assert.equal(payload.schema_version, 4, "schema_version must be 4");
    assert.equal(payload.base_sha, base, "payload.base_sha must equal merge-base");
    assert.equal(payload.head_sha, head, "payload.head_sha must equal feature tip");
    assert.equal(payload.target_branch, "main");
    assert.equal(payload.diff_sha256, diffSha256, "payload.diff_sha256 must equal recomputed");
    assert.equal(payload.approvals.length, 1, "exactly one approval folded");
    assert.equal(payload.checks.length, 0, "no checks in this fixture");
    assert.deepEqual(payload.trust_anchor_signatures, [], "no .stamp/** touches → no admin sigs");
    assert.equal(payload.signer_key_id, h.operatorFingerprint);

    // ④ Verify the outer (operator) signature against the operator's
    //    pubkey via the same Buffer.from(b64) byte path the real hook
    //    uses. We don't import verifyV4OuterSignature here — that's
    //    step ⑦. This is the standalone-bytes check.
    const { keypair } = ensureUserKeypair();
    const outerOk = cryptoVerify(
      null,
      payloadBytes,
      createPublicKey(keypair.publicKeyPem),
      Buffer.from(signatureB64, "base64"),
    );
    assert.ok(outerOk, "outer signature must verify against operator pubkey");

    // ⑤ Verify each inner approval signature against its server key
    //    via canonicalSerializeApproval — the contract both the server
    //    (AGT-330/331) and the merge folder (AGT-334) write against.
    const entry = payload.approvals[0]!;
    assert.equal(entry.approval.reviewer, "security");
    assert.equal(entry.approval.verdict, "approved");
    assert.equal(entry.approval.base_sha, base);
    assert.equal(entry.approval.head_sha, head);
    assert.equal(entry.approval.diff_sha256, diffSha256);
    assert.equal(entry.approval.server_key_id, h.serverKey.fingerprint);
    assert.equal(
      entry.server_attestation.server_key_id,
      entry.approval.server_key_id,
      "outer server_attestation.server_key_id must equal inner approval.server_key_id (settled decision #9)",
    );
    const innerOk = cryptoVerify(
      null,
      canonicalSerializeApproval(entry.approval),
      createPublicKey(h.serverKey.publicPem),
      Buffer.from(entry.server_attestation.signature, "base64"),
    );
    assert.ok(innerOk, "inner server signature must verify against server pubkey");

    // ⑥ diff_sha256 round-trip: the payload value MUST equal a fresh
    //    hash of `git diff base...head`. This pins the contract the
    //    server (AGT-331), the merge folder (AGT-334), and the hook
    //    (AGT-335) all share — bytes from `Buffer.from(diff, "utf8")`.
    const recomputed = sha256Hex(diff);
    assert.equal(payload.diff_sha256, recomputed, "payload.diff_sha256 must equal recomputed hash of base...head");
    assert.equal(entry.approval.diff_sha256, recomputed, "inner approval.diff_sha256 must equal recomputed hash");

    // ⑦ BONUS — drive the REAL AGT-335 verifier against the produced
    //    trailer. This is the cross-ticket integration property the
    //    isolated suites can't see: if AGT-334's writer and AGT-335's
    //    verifier disagree on any byte, this rejects. Happy path must
    //    accept.
    process.chdir(h.repo); // the v4 phases shell out via git, so cwd matters
    const input = buildPhaseInput({
      repo: h.repo,
      mergeSha,
      branch: "main",
      required: ["security"],
      payloadB64,
      signatureB64,
    });
    const failure = runAllV4Phases(input);
    assert.equal(
      failure,
      null,
      `every v4 phase must accept the produced trailer (failed: ${failure?.phase} — ${failure?.reason})`,
    );
  });
});

describe("v4 attestation round-trip — failure modes (verifier rejects on tamper)", () => {
  let h: Harness | undefined;
  let prevCwd = process.cwd();

  beforeEach(() => {
    prevCwd = process.cwd();
  });
  afterEach(() => {
    process.chdir(prevCwd);
    h?.cleanup();
    h = undefined;
  });

  /** Build a fully-valid merge + trailers, then return the harness +
   *  decoded trailer bits so each negative test can corrupt one piece
   *  and assert exactly one phase rejects. */
  function setupAndMerge(): {
    h: Harness;
    mergeSha: string;
    payloadB64: string;
    signatureB64: string;
    diffSha256: string;
  } {
    const harness = setupHarness();
    const base = shaOf(harness.repo, "main");
    const head = shaOf(harness.repo, "feature");
    const diff = git(harness.repo, ["diff", `${base}...${head}`]);
    const diffSha256 = sha256Hex(diff);
    const manifestSnapshot = manifestSnapshotAtBase(harness.repo, base);
    seedV4Review({
      repo: harness.repo,
      reviewer: "security",
      baseSha: base,
      headSha: head,
      diffSha256,
      serverKey: harness.serverKey,
      manifestSnapshot,
    });
    runFromRepo(harness.repo, () =>
      runMerge({ branch: "feature", into: "main", yes: true }),
    );
    const mergeSha = shaOf(harness.repo, "main");
    const mergeMsg = git(harness.repo, ["log", "-1", "--pretty=%B"]);
    const { payloadB64, signatureB64 } = extractTrailers(mergeMsg);
    return { h: harness, mergeSha, payloadB64, signatureB64, diffSha256 };
  }

  it("rejects when the outer signature is corrupted (verifyV4OuterSignature)", () => {
    const fx = setupAndMerge();
    h = fx.h;
    process.chdir(fx.h.repo);

    // Flip the last byte of the operator signature. Base64 of an
    // Ed25519 signature is well-formed but the bytes won't verify.
    const sigBytes = Buffer.from(fx.signatureB64, "base64");
    sigBytes[sigBytes.length - 1] = sigBytes[sigBytes.length - 1]! ^ 0xff;
    const corruptedSigB64 = sigBytes.toString("base64");

    const input = buildPhaseInput({
      repo: fx.h.repo,
      mergeSha: fx.mergeSha,
      branch: "main",
      required: ["security"],
      payloadB64: fx.payloadB64,
      signatureB64: corruptedSigB64,
    });
    const failure = runAllV4Phases(input);
    assert.ok(failure, "verifier must reject corrupted outer signature");
    assert.equal(failure.phase, "verifyV4OuterSignature");
    assert.match(failure.reason, /v4 outer Ed25519 signature does not verify/);
  });

  it("rejects when payload.diff_sha256 is mutated (verifyV4DiffHash)", () => {
    const fx = setupAndMerge();
    h = fx.h;
    process.chdir(fx.h.repo);

    // Decode payload, mutate diff_sha256, re-encode as the trailer
    // would carry it. The OUTER signature won't match the mutated
    // bytes — but we want to catch the diff-hash mismatch, which is
    // gated AFTER verifyV4OuterSignature in the pipeline. So we
    // bypass the outer check by re-signing the mutated payload with
    // the operator key (the v4 pipeline's invariant is that EACH
    // phase rejects independently — proving verifyV4DiffHash works
    // requires the upstream phases to pass).
    const payload: AttestationPayloadV4 = JSON.parse(
      trailerValueToPayloadBytes(fx.payloadB64).toString("utf8"),
    );
    payload.diff_sha256 = "f".repeat(64);
    const reBytes = canonicalSerializePayload(payload);
    const { keypair } = ensureUserKeypair();
    const reSig = signBytes(keypair.privateKeyPem, reBytes);
    const reB64 = reBytes.toString("base64");

    const input = buildPhaseInput({
      repo: fx.h.repo,
      mergeSha: fx.mergeSha,
      branch: "main",
      required: ["security"],
      payloadB64: reB64,
      signatureB64: reSig,
    });
    const failure = runAllV4Phases(input);
    assert.ok(failure, "verifier must reject mutated diff_sha256");
    // Could fire at either verifyV4DiffHash (top-level mismatch) or
    // verifyV4ApprovalSignatures (inner approval still references the
    // original diff, but it's signed by the server). The pipeline
    // order puts DiffHash before ApprovalSignatures, so DiffHash wins.
    assert.equal(failure.phase, "verifyV4DiffHash");
    assert.match(failure.reason, /v4 diff_sha256 mismatch/);
  });

  it("rejects when an inner approval signature is corrupted (verifyV4ApprovalSignatures)", () => {
    const fx = setupAndMerge();
    h = fx.h;
    process.chdir(fx.h.repo);

    // Decode payload, flip a byte in the inner approval signature,
    // re-sign the (mutated) payload with the operator so the outer
    // gate passes and we reach the per-approval signature check.
    const payload: AttestationPayloadV4 = JSON.parse(
      trailerValueToPayloadBytes(fx.payloadB64).toString("utf8"),
    );
    const innerSigBytes = Buffer.from(payload.approvals[0]!.server_attestation.signature, "base64");
    innerSigBytes[0] = innerSigBytes[0]! ^ 0x01;
    payload.approvals[0]!.server_attestation.signature = innerSigBytes.toString("base64");
    const reBytes = canonicalSerializePayload(payload);
    const { keypair } = ensureUserKeypair();
    const reSig = signBytes(keypair.privateKeyPem, reBytes);

    const input = buildPhaseInput({
      repo: fx.h.repo,
      mergeSha: fx.mergeSha,
      branch: "main",
      required: ["security"],
      payloadB64: reBytes.toString("base64"),
      signatureB64: reSig,
    });
    const failure = runAllV4Phases(input);
    assert.ok(failure, "verifier must reject corrupted inner signature");
    assert.equal(failure.phase, "verifyV4ApprovalSignatures");
    assert.match(failure.reason, /server signature does not verify/);
  });

  it("rejects (at merge time) when no server-signed approval row exists for a required reviewer", () => {
    // This is the "missing approval row" golden assertion — caught
    // by runMerge BEFORE any trailer is written. The merge command
    // refuses to produce a v4 envelope without a signed row, so the
    // attack surface (a "trust me bro" merge) never reaches the
    // verifier. The error message names the exact recovery action.
    h = setupHarness();
    // Seed only a legacy (non-server-signed) approved row, so the gate
    // check passes (it doesn't require a server signature) but the v4
    // fold step fails.
    const base = shaOf(h.repo, "main");
    const head = shaOf(h.repo, "feature");
    const db = openDb(stampStateDbPath(h.repo));
    try {
      recordReview(db, {
        reviewer: "security",
        base_sha: base,
        head_sha: head,
        verdict: "approved",
        issues: "legacy approved",
      });
    } finally {
      db.close();
    }

    const before = shaOf(h.repo, "main");
    assert.throws(
      () =>
        runFromRepo(h!.repo, () =>
          runMerge({ branch: "feature", into: "main", yes: true }),
        ),
      /missing server signature for reviewer "security"/,
    );
    assert.equal(
      shaOf(h.repo, "main"),
      before,
      "merge must roll back HEAD when v4 fold fails — no half-stamped commit allowed",
    );
  });

  it("rejects (at merge time) when the row's diff_sha256 is stale", () => {
    // The "stale diff_sha256" golden assertion. The SSH client (in
    // production) refuses to write a row whose signed diff_sha256
    // doesn't match the diff at write time, but buildV4Trailers
    // re-checks at merge time — closing the "DB tampered after
    // write" gap.
    h = setupHarness();
    const base = shaOf(h.repo, "main");
    const head = shaOf(h.repo, "feature");
    const manifestSnapshot = manifestSnapshotAtBase(h.repo, base);
    const staleDiff = "ab".repeat(32);
    seedV4Review({
      repo: h.repo,
      reviewer: "security",
      baseSha: base,
      headSha: head,
      diffSha256: staleDiff,
      serverKey: h.serverKey,
      manifestSnapshot,
    });
    const before = shaOf(h.repo, "main");
    assert.throws(
      () =>
        runFromRepo(h!.repo, () =>
          runMerge({ branch: "feature", into: "main", yes: true }),
        ),
      /stale signature/,
    );
    assert.equal(shaOf(h.repo, "main"), before);
  });
});

describe("v4 attestation round-trip — hermeticity", () => {
  // The harness is the test: confirm temp dirs are cleaned up on
  // success. If this test fails after the rest pass, setupHarness's
  // cleanup is leaking.
  it("temp fixture is removed after the test exits", () => {
    const h = setupHarness();
    const root = h.root;
    assert.ok(existsSync(root), "harness root must exist while test holds it");
    h.cleanup();
    assert.ok(!existsSync(root), "harness root must be deleted by cleanup()");
  });
});
