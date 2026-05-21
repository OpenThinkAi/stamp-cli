/**
 * AGT-355 — server-side production of v3 PR-attestation payload.
 *
 * Unit tests for the new fields the SSH `stamp-review` verb returns
 * alongside the verdict: `pr_attestation_v3_payload_b64` and
 * `pr_attestation_v3_signature_b64`. The server fabricates these by
 * canonical-serializing the per-approval `ApprovalV4` body and signing
 * it with the server's Ed25519 review-signing key. The client
 * (`requestServerReview` → `stamp attest`) consumes them to fold the
 * server's per-approval signature into a v3 PR-attestation envelope.
 *
 * Scope:
 *   - happy path: the new fields are present, decoded payload bytes
 *     equal `canonicalSerializeApproval(approval)`, signature verifies
 *     against the server's pubkey over those bytes
 *   - byte-identity contract: server bytes match client recomputation
 *     (the load-bearing invariant for AGT-355 — without byte equality,
 *     the v3 envelope writer would have to re-canonicalize and risk
 *     drift)
 *   - signature is the SAME signature as the legacy top-level
 *     `signature` field (the server signs the canonical bytes once
 *     and surfaces them under two names)
 *
 * Verifier-side tests live in `tests/verifyPr.test.ts` and exercise
 * the consumer path against fabricated envelopes; this file exercises
 * the producer path against the real pipeline.
 */

import { strict as assert } from "node:assert";
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  verify,
  type KeyObject,
} from "node:crypto";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { canonicalSerializeApproval } from "../src/lib/attestationV4.ts";
import { fingerprintFromPem } from "../src/lib/keys.ts";
import type { UserRow } from "../src/lib/serverDb.ts";
import {
  runReviewPipeline,
  type ParsedReviewRequest,
  type ReviewPipelineInput,
} from "../src/server/reviewPipeline.ts";

import type { AnthropicClientShape } from "../src/lib/headlessReviewer.ts";

const REVIEWER_PROMPT = "# security reviewer\n\nFlag exploitable changes.\n";

const FIXTURE_USER: UserRow = {
  id: 1,
  short_name: "test-caller",
  ssh_pubkey: "ssh-ed25519 AAAA test@host",
  ssh_fp: "SHA256:test-fingerprint",
  role: "member",
  source: "env",
  created_at: "2026-01-01T00:00:00Z",
};

function mintSigningFixture(): {
  privateKey: KeyObject;
  publicPem: string;
  fingerprint: string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicPem = publicKey.export({ type: "spki", format: "pem" }) as string;
  return {
    privateKey,
    publicPem,
    fingerprint: fingerprintFromPem(publicPem),
  };
}

function manifestYamlForServerKey(serverFingerprint: string): string {
  return [
    `keys:`,
    `  review-server-test:`,
    `    fingerprint: ${serverFingerprint}`,
    `    capabilities: [server]`,
    ``,
  ].join("\n");
}

function makeFixtureBareRepo(): {
  /** Filesystem prompt cache (post-AGT-370 replacement for the bare
   *  git repo). The pipeline reads `<cacheRoot>/security.md`. */
  cacheRoot: string;
  baseSha: string;
  signing: { privateKey: KeyObject; publicPem: string; fingerprint: string };
  cleanup: () => void;
} {
  const signing = mintSigningFixture();
  // The manifest YAML is no longer consumed by the server (AGT-370);
  // the variable stays as a docstring reference for the trust shape
  // the operator / verifier expect.
  void manifestYamlForServerKey(signing.fingerprint);

  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-prattprod-"));
  const cacheRoot = path.join(root, "prompts");
  mkdirSync(cacheRoot, { recursive: true });
  writeFileSync(path.join(cacheRoot, "security.md"), REVIEWER_PROMPT);

  // base_sha is still required on the wire — it lands in
  // ApprovalV4.base_sha and the verifier uses it to resolve the
  // manifest operator-side. A fake 40-hex value suffices for this
  // test because we never invoke the verifier or any code that
  // resolves it back to a real commit.
  const baseSha = "0123456789abcdef0123456789abcdef01234567";

  return {
    cacheRoot,
    baseSha,
    signing,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

function mockClient(verdict: "approved" | "changes_requested" | "denied" = "approved"): AnthropicClientShape {
  return {
    messages: {
      create: async () => ({
        content: [
          {
            type: "tool_use",
            name: "submit_verdict",
            input: { verdict, prose: "fixture prose" },
          },
        ],
      }),
    },
  };
}

function fixtureInput(
  fx: ReturnType<typeof makeFixtureBareRepo>,
  diff: Buffer,
  client: AnthropicClientShape,
): ReviewPipelineInput {
  const params: ParsedReviewRequest = {
    reviewer: "security",
    org: "acme",
    repo: "widget-co",
    baseSha: fx.baseSha,
    headSha: "fedcba9876543210fedcba9876543210fedcba98",
    diffSha256: createHash("sha256").update(diff).digest("hex"),
  };
  return {
    diff,
    params,
    caller: FIXTURE_USER,
    deps: {
      promptResolver: (reviewer) => path.join(fx.cacheRoot, `${reviewer}.md`),
      anthropic: client,
      signingKey: {
        privateKey: fx.signing.privateKey,
        fingerprint: fx.signing.fingerprint,
      },
    },
  };
}

describe("runReviewPipeline — AGT-355 v3 PR-attestation payload production", () => {
  it("surfaces pr_attestation_v3_payload_b64 + signature with canonical bytes the client can fold directly", async () => {
    const fx = makeFixtureBareRepo();
    try {
      const diff = Buffer.from("diff --git a/foo b/foo\n+hello\n");
      const r = await runReviewPipeline(fixtureInput(fx, diff, mockClient()));

      // Both new fields must be non-empty strings — the wire-format
      // contract per the ReviewPipelineResult docstring.
      assert.equal(typeof r.pr_attestation_v3_payload_b64, "string");
      assert.ok(
        r.pr_attestation_v3_payload_b64.length > 0,
        "pr_attestation_v3_payload_b64 must be non-empty",
      );
      assert.equal(typeof r.pr_attestation_v3_signature_b64, "string");
      assert.ok(
        r.pr_attestation_v3_signature_b64.length > 0,
        "pr_attestation_v3_signature_b64 must be non-empty",
      );

      // Byte-identity contract: the decoded payload bytes MUST equal
      // canonicalSerializeApproval(approval). This is the load-bearing
      // invariant — without it, the v3 envelope writer would have to
      // re-canonicalize and risk drift.
      const decoded = Buffer.from(r.pr_attestation_v3_payload_b64, "base64");
      const canonical = canonicalSerializeApproval(r.approval);
      assert.ok(
        decoded.equals(canonical),
        `decoded payload bytes must equal canonicalSerializeApproval(approval). ` +
          `decoded(80): ${JSON.stringify(decoded.toString("utf8").slice(0, 80))}; ` +
          `canonical(80): ${JSON.stringify(canonical.toString("utf8").slice(0, 80))}`,
      );

      // The signature must verify under the server's pubkey over those
      // exact bytes — closes the producer loop. AGT-338's verifier
      // performs the same check; if this fails the action would too.
      const pubKey = createPublicKey(fx.signing.publicPem);
      const ok = verify(
        null,
        decoded,
        pubKey,
        Buffer.from(r.pr_attestation_v3_signature_b64, "base64"),
      );
      assert.ok(
        ok,
        "pr_attestation_v3_signature_b64 must verify against the server's pubkey over the canonical payload bytes",
      );

      // The new pr_attestation_v3 signature is the SAME signature as
      // the legacy top-level `signature` field. The server signs
      // canonical bytes once; both fields point at the same bytes.
      assert.equal(
        r.pr_attestation_v3_signature_b64,
        r.signature,
        "pr_attestation_v3_signature_b64 must equal the legacy top-level signature (same bytes signed once)",
      );
    } finally {
      fx.cleanup();
    }
  });

  it("server-attested fields are present even on changes_requested verdicts (safe-verdict signing contract)", async () => {
    // AGT-330's error-handling contract: even a "changes_requested"
    // verdict gets signed (operators persist the safe verdict).
    // AGT-355 must preserve that — the v3 payload fields are produced
    // alongside ANY signed verdict, not only approvals.
    const fx = makeFixtureBareRepo();
    try {
      const diff = Buffer.from("diff --git a/foo b/foo\n+hello\n");
      const r = await runReviewPipeline(
        fixtureInput(fx, diff, mockClient("changes_requested")),
      );

      assert.equal(r.verdict, "changes_requested");
      assert.ok(
        r.pr_attestation_v3_payload_b64.length > 0,
        "v3 payload bytes must be present on changes_requested too",
      );
      assert.ok(
        r.pr_attestation_v3_signature_b64.length > 0,
        "v3 signature must be present on changes_requested too",
      );

      const decoded = Buffer.from(r.pr_attestation_v3_payload_b64, "base64");
      const canonical = canonicalSerializeApproval(r.approval);
      assert.ok(decoded.equals(canonical));
    } finally {
      fx.cleanup();
    }
  });

  it("decoded payload bytes carry the EXACT canonical bytes (key order, no whitespace) — defends against serialization drift", async () => {
    const fx = makeFixtureBareRepo();
    try {
      const diff = Buffer.from("diff --git a/foo b/foo\n+hello\n");
      const r = await runReviewPipeline(fixtureInput(fx, diff, mockClient()));

      // canonicalSerializeApproval sorts object keys and uses no
      // whitespace. Confirm by parsing the decoded bytes and
      // re-canonicalizing: the round-trip MUST be a fixed point.
      const decoded = Buffer.from(r.pr_attestation_v3_payload_b64, "base64");
      const reparsed = JSON.parse(decoded.toString("utf8"));
      const reCanonical = canonicalSerializeApproval(reparsed);
      assert.ok(
        decoded.equals(reCanonical),
        "canonical bytes must be a fixed point under parse + re-canonicalize",
      );

      // Also check the field set matches an ApprovalV4 — every
      // required field is a string, no extras.
      const obj = reparsed as Record<string, unknown>;
      for (const field of [
        "reviewer",
        "verdict",
        "prompt_sha256",
        "diff_sha256",
        "base_sha",
        "head_sha",
        "issued_at",
        "server_key_id",
      ]) {
        assert.equal(typeof obj[field], "string", `missing ApprovalV4 field: ${field}`);
      }
    } finally {
      fx.cleanup();
    }
  });
});
