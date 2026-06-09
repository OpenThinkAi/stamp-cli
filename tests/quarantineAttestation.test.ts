/**
 * Tests for the AGT-476 flake-quarantine field on the attestation
 * envelopes (v3 and v4):
 *
 *   - a CheckAttestation / CheckAttestationV4 WITHOUT quarantine
 *     serializes byte-identically to a pre-AGT-476 envelope
 *     (load-bearing: repos that don't use quarantine must see zero
 *     attestation churn, so existing chains remain verifiable and
 *     pre-existing fixtures aren't invalidated).
 *   - a CheckAttestation / CheckAttestationV4 WITH quarantine
 *     round-trips through the trailer encoder/decoder.
 *   - v4 canonical serialization sorts the additive field
 *     deterministically.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  payloadToTrailerValue,
  serializePayload,
  trailerValueToPayload,
  type AttestationPayload,
  type CheckAttestation,
} from "../src/lib/attestation.ts";
import {
  canonicalSerializePayload,
  parseEnvelope,
  serializeEnvelope,
  type AttestationEnvelopeV4,
  type AttestationPayloadV4,
  type CheckAttestationV4,
} from "../src/lib/attestationV4.ts";

const V3_BASE_PAYLOAD: AttestationPayload = {
  schema_version: 3,
  base_sha: "a".repeat(40),
  head_sha: "b".repeat(40),
  target_branch: "main",
  approvals: [
    {
      reviewer: "security",
      verdict: "approved",
      review_sha: "c".repeat(64),
      prompt_sha256: "d".repeat(64),
      tools_sha256: "e".repeat(64),
      mcp_sha256: "f".repeat(64),
    },
  ],
  checks: [],
  signer_key_id: "sha256:" + "1".repeat(64),
};

describe("AGT-476 v3 attestation byte-identity for repos without quarantine", () => {
  it("a CheckAttestation without quarantine serializes byte-identically to pre-AGT-476", () => {
    // Synthesize the EXACT bytes a pre-AGT-476 envelope would have
    // produced (no `quarantine` key on the check). If the type change
    // had accidentally added the field at all times, JSON output would
    // include a stray `quarantine` key and this assertion would fail.
    const check: CheckAttestation = {
      name: "test",
      command: "npm test",
      exit_code: 0,
      output_sha: "0".repeat(64),
    };
    const payload: AttestationPayload = {
      ...V3_BASE_PAYLOAD,
      checks: [check],
    };
    const bytes = serializePayload(payload);
    const json = JSON.parse(bytes.toString("utf8"));
    assert.deepEqual(json.checks[0], {
      name: "test",
      command: "npm test",
      exit_code: 0,
      output_sha: "0".repeat(64),
    });
    // Defensive: no `quarantine` key smuggled in.
    assert.equal("quarantine" in json.checks[0], false);
  });

  it("a CheckAttestation with quarantine round-trips through the trailer encoder", () => {
    const check: CheckAttestation = {
      name: "test",
      command: "npm test",
      exit_code: 0,
      output_sha: "0".repeat(64),
      quarantine: [
        { test: "tests/daemon/status.test.ts", reason: "vitest fork-pool flake (GH#49)" },
      ],
    };
    const payload: AttestationPayload = {
      ...V3_BASE_PAYLOAD,
      checks: [check],
    };
    const b64 = payloadToTrailerValue(payload);
    const decoded = trailerValueToPayload(b64);
    assert.deepEqual(decoded.checks[0]?.quarantine, [
      { test: "tests/daemon/status.test.ts", reason: "vitest fork-pool flake (GH#49)" },
    ]);
  });
});

const V4_BASE_PAYLOAD: AttestationPayloadV4 = {
  schema_version: 5,
  base_sha: "a".repeat(40),
  head_sha: "b".repeat(40),
  target_branch: "main",
  diff_sha256: "d".repeat(64),
  manifest_snapshot_sha256: "sha256:" + "m".repeat(64),
  approvals: [],
  checks: [],
  trust_anchor_signatures: [],
  signer_key_id: "sha256:" + "1".repeat(64),
};

describe("AGT-476 v4 attestation byte-identity for repos without quarantine", () => {
  it("a CheckAttestationV4 without quarantine serializes byte-identically to pre-AGT-476", () => {
    const check: CheckAttestationV4 = {
      name: "test",
      command: "npm test",
      exit_code: 0,
      output_sha: "0".repeat(64),
    };
    const payload: AttestationPayloadV4 = {
      ...V4_BASE_PAYLOAD,
      checks: [check],
    };
    const bytes = canonicalSerializePayload(payload);
    const json = JSON.parse(bytes.toString("utf8"));
    // Same byte-identity property as v3: no stray `quarantine` key.
    assert.deepEqual(json.checks[0], {
      command: "npm test",
      exit_code: 0,
      name: "test",
      output_sha: "0".repeat(64),
    });
    assert.equal("quarantine" in json.checks[0], false);
  });

  it("a CheckAttestationV4 with quarantine survives envelope round-trip", () => {
    const check: CheckAttestationV4 = {
      name: "test",
      command: "npm test",
      exit_code: 0,
      output_sha: "0".repeat(64),
      quarantine: [
        { test: "tests/daemon/status.test.ts", reason: "vitest fork-pool flake" },
        { test: "tests/integration/slow.test.ts", reason: "timing-sensitive" },
      ],
    };
    const payload: AttestationPayloadV4 = {
      ...V4_BASE_PAYLOAD,
      checks: [check],
    };
    const envelope: AttestationEnvelopeV4 = {
      payload,
      // Realistic-shape Ed25519 base64 signature (64 bytes → ~88 chars).
      signature: "A".repeat(88),
    };
    const bytes = serializeEnvelope(envelope);
    // parseEnvelope re-derives the envelope from the wire bytes and
    // its `isCheck` shape-validator must accept the additive
    // `quarantine` field (it's optional, so the parser's existing
    // required-field check passes through unchanged).
    const parsed = parseEnvelope(bytes);
    assert.ok(parsed, "envelope with quarantine must parse");
    assert.deepEqual(parsed.payload.checks[0]?.quarantine, [
      { test: "tests/daemon/status.test.ts", reason: "vitest fork-pool flake" },
      { test: "tests/integration/slow.test.ts", reason: "timing-sensitive" },
    ]);
  });

  it("v4 canonical serialization sorts the new quarantine field deterministically", () => {
    // Build two semantically-identical checks with different key
    // insertion order. canonicalSerializePayload sortKeys-deep, so both
    // should produce identical bytes — the two-signer correctness
    // property v4 depends on extends to the new field.
    const check1: CheckAttestationV4 = {
      name: "test",
      command: "npm test",
      exit_code: 0,
      output_sha: "0".repeat(64),
      quarantine: [{ test: "t1", reason: "r1" }],
    };
    const check2: CheckAttestationV4 = {
      quarantine: [{ reason: "r1", test: "t1" }],
      output_sha: "0".repeat(64),
      exit_code: 0,
      command: "npm test",
      name: "test",
    } as CheckAttestationV4;
    const p1: AttestationPayloadV4 = { ...V4_BASE_PAYLOAD, checks: [check1] };
    const p2: AttestationPayloadV4 = { ...V4_BASE_PAYLOAD, checks: [check2] };
    assert.equal(
      canonicalSerializePayload(p1).toString("utf8"),
      canonicalSerializePayload(p2).toString("utf8"),
    );
  });
});
