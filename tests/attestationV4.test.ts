/**
 * Tests for the v4 attestation envelope.
 *
 * Three families of concern, matched to the load-bearing properties of
 * the v4 module:
 *
 *   1. Canonical-serializer determinism — the two-signer property
 *      (server signs approvals, operator signs the envelope) only
 *      works if both parties produce byte-identical signing inputs
 *      regardless of how they constructed the object. Key-order
 *      independence is the explicit test.
 *
 *   2. Round-trip safety — `serializeEnvelope` → `parseEnvelope` →
 *      `canonicalSerializePayload` must produce byte-equal output to
 *      what the operator originally signed. If it doesn't, a verifier
 *      who parses a stored envelope and re-derives signing bytes will
 *      fail to verify a valid signature.
 *
 *   3. Structural rejection — `parseEnvelope` runs in the pre-receive
 *      hook BEFORE cryptography. Empty / oversized / wrong-version /
 *      missing-field envelopes must return null without throwing.
 *
 * The "worked examples" cluster at the bottom exercises the three
 * documented envelope shapes from the design doc: an approval-only
 * envelope, a `.stamp/**` merge with `trust_anchor_signatures`, and
 * the `trusted_keys_snapshot_sha256` field surviving round-trip.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  canonicalSerializeApproval,
  canonicalSerializePayload,
  CURRENT_V4_SCHEMA_VERSION,
  formatTrailers,
  MAX_V4_ENVELOPE_BYTES,
  MIN_ACCEPTED_V4_SCHEMA_VERSION,
  parseEnvelope,
  payloadToTrailerValue,
  serializeEnvelope,
  STAMP_PAYLOAD_TRAILER_V4,
  STAMP_VERIFIED_TRAILER_V4,
  trailerValueToPayloadBytes,
  type ApprovalEntryV4,
  type ApprovalV4,
  type AttestationEnvelopeV4,
  type AttestationPayloadV4,
  type TrustAnchorSignatureV4,
} from "../src/lib/attestationV4.ts";

function makeApproval(overrides: Partial<ApprovalV4> = {}): ApprovalV4 {
  return {
    reviewer: "security",
    verdict: "approved",
    prompt_sha256: "a".repeat(64),
    diff_sha256: "b".repeat(64),
    base_sha: "c".repeat(40),
    head_sha: "d".repeat(40),
    issued_at: "2026-05-17T18:42:13Z",
    server_key_id: "sha256:" + "f".repeat(64),
    ...overrides,
  };
}

function makeApprovalEntry(overrides: Partial<ApprovalV4> = {}): ApprovalEntryV4 {
  const approval = makeApproval(overrides);
  return {
    approval,
    server_attestation: {
      server_key_id: approval.server_key_id,
      signature: "fake-server-sig==",
    },
  };
}

function makePayload(
  overrides: Partial<AttestationPayloadV4> = {},
): AttestationPayloadV4 {
  return {
    schema_version: CURRENT_V4_SCHEMA_VERSION,
    base_sha: "c".repeat(40),
    head_sha: "d".repeat(40),
    target_branch: "main",
    diff_sha256: "b".repeat(64),
    manifest_snapshot_sha256: "sha256:" + "e".repeat(64),
    approvals: [makeApprovalEntry()],
    checks: [],
    trust_anchor_signatures: [],
    signer_key_id: "sha256:" + "9".repeat(64),
    ...overrides,
  };
}

function makeEnvelope(
  payload: AttestationPayloadV4 = makePayload(),
): AttestationEnvelopeV4 {
  return {
    payload,
    signature: "fake-operator-sig==",
  };
}

describe("v4 schema constants", () => {
  it("locks the schema integer to 5 — bumped in AGT-370 (manifest binding lifted to outer envelope)", () => {
    // Hard-coded asserts on both constants so a future bump consciously
    // updates both this test and the dispatcher logic that routes
    // by schema_version. Silent drift is the failure mode we're guarding.
    //
    // The v4 → v5 bump is breaking by design: per-approval
    // `trusted_keys_snapshot_sha256` removed, top-level
    // `manifest_snapshot_sha256` added. Verifiers reject v4 envelopes
    // because they lack the new outer field; the floor moves in
    // lockstep with the current version.
    assert.equal(CURRENT_V4_SCHEMA_VERSION, 5);
    assert.equal(MIN_ACCEPTED_V4_SCHEMA_VERSION, 5);
  });

  it("caps envelope size at 64 KB to match legacy v3 DoS rationale", () => {
    assert.equal(MAX_V4_ENVELOPE_BYTES, 64 * 1024);
  });

  it("reuses the legacy Stamp-Payload / Stamp-Verified trailer keys", () => {
    // Both envelopes share the same trailer keys; the dispatcher
    // disambiguates by parsing the base64 payload and inspecting
    // schema_version. Pinning the strings here documents the shared
    // contract.
    assert.equal(STAMP_PAYLOAD_TRAILER_V4, "Stamp-Payload");
    assert.equal(STAMP_VERIFIED_TRAILER_V4, "Stamp-Verified");
  });
});

describe("canonicalSerializeApproval — byte determinism", () => {
  it("returns identical bytes for the same approval built two ways", () => {
    const a1 = makeApproval();
    const a2 = makeApproval();
    assert.deepEqual(canonicalSerializeApproval(a1), canonicalSerializeApproval(a2));
  });

  it("produces identical bytes when object keys are in different orders", () => {
    // This is THE property the two-signer model depends on: the
    // server constructs the approval one way and the operator's
    // verifier constructs it another. If JSON.stringify key order
    // leaked through, signature verification would fail for no
    // semantic reason. Build the same logical approval as two
    // distinct JS objects with reversed insertion order to prove
    // the canonical serializer doesn't care.
    const original = makeApproval();
    const reordered: ApprovalV4 = {
      // Intentionally reversed insertion order vs makeApproval.
      server_key_id: original.server_key_id,
      issued_at: original.issued_at,
      head_sha: original.head_sha,
      base_sha: original.base_sha,
      diff_sha256: original.diff_sha256,
      prompt_sha256: original.prompt_sha256,
      verdict: original.verdict,
      reviewer: original.reviewer,
    };
    assert.deepEqual(
      canonicalSerializeApproval(original),
      canonicalSerializeApproval(reordered),
    );
  });

  it("emits keys in lexicographically sorted order in the JSON output", () => {
    const a = makeApproval();
    const json = canonicalSerializeApproval(a).toString("utf8");
    // The first key in the serialized output should be alphabetically
    // first among the approval's keys. "base_sha" sorts before all
    // other top-level keys on ApprovalV4.
    assert.match(json, /^\{"base_sha":/);
  });
});

describe("canonicalSerializePayload — byte determinism", () => {
  it("produces identical bytes regardless of nested object key order", () => {
    // Two payloads with identical content but different field
    // insertion order at multiple levels (top-level + nested approval +
    // nested server_attestation). Canonical serializer must collapse
    // all three layers into the same byte string.
    const base = makePayload();

    const reordered: AttestationPayloadV4 = {
      signer_key_id: base.signer_key_id,
      trust_anchor_signatures: base.trust_anchor_signatures,
      checks: base.checks,
      approvals: base.approvals.map((e) => ({
        server_attestation: {
          signature: e.server_attestation.signature,
          server_key_id: e.server_attestation.server_key_id,
        },
        approval: {
          server_key_id: e.approval.server_key_id,
          issued_at: e.approval.issued_at,
          head_sha: e.approval.head_sha,
          base_sha: e.approval.base_sha,
          diff_sha256: e.approval.diff_sha256,
          prompt_sha256: e.approval.prompt_sha256,
          verdict: e.approval.verdict,
          reviewer: e.approval.reviewer,
        },
      })),
      manifest_snapshot_sha256: base.manifest_snapshot_sha256,
      diff_sha256: base.diff_sha256,
      target_branch: base.target_branch,
      head_sha: base.head_sha,
      base_sha: base.base_sha,
      schema_version: base.schema_version,
    };

    assert.deepEqual(
      canonicalSerializePayload(base),
      canonicalSerializePayload(reordered),
    );
  });

  it("preserves array order — approvals and trust_anchor_signatures are semantic sequences", () => {
    // Array order is meaningful (approvals match request order;
    // trust-anchor sigs are collected in counter-sign order). The
    // canonicalizer must NOT reorder array elements.
    const a1 = makeApprovalEntry({ reviewer: "security" });
    const a2 = makeApprovalEntry({ reviewer: "standards" });
    const forward = makePayload({ approvals: [a1, a2] });
    const reversed = makePayload({ approvals: [a2, a1] });
    assert.notDeepEqual(
      canonicalSerializePayload(forward),
      canonicalSerializePayload(reversed),
    );
  });
});

describe("parseEnvelope — round-trip", () => {
  it("serializeEnvelope → parseEnvelope yields the same payload bytes under canonical re-serialize", () => {
    // The verifier's flow: pull trailer bytes, parse envelope, re-
    // derive signing target from the parsed payload, check signature.
    // This test pins that the re-derived bytes equal the originals,
    // which is what makes the signature check possible at all.
    const env = makeEnvelope();
    const wireBytes = serializeEnvelope(env);
    const parsed = parseEnvelope(wireBytes);
    assert.ok(parsed);
    assert.deepEqual(
      canonicalSerializePayload(parsed.payload),
      canonicalSerializePayload(env.payload),
    );
  });

  it("preserves signature, schema version, and core SHAs through round-trip", () => {
    const env = makeEnvelope();
    const parsed = parseEnvelope(serializeEnvelope(env));
    assert.ok(parsed);
    assert.equal(parsed.signature, env.signature);
    assert.equal(parsed.payload.schema_version, CURRENT_V4_SCHEMA_VERSION);
    assert.equal(parsed.payload.base_sha, env.payload.base_sha);
    assert.equal(parsed.payload.head_sha, env.payload.head_sha);
    assert.equal(parsed.payload.diff_sha256, env.payload.diff_sha256);
    assert.equal(parsed.payload.target_branch, "main");
  });
});

describe("parseEnvelope — rejection", () => {
  it("rejects an empty blob", () => {
    assert.equal(parseEnvelope(Buffer.alloc(0)), null);
  });

  it("rejects an oversized blob without parsing", () => {
    // 64 KB + 1 byte. parseEnvelope runs before signature verification
    // in the pre-receive hook; without a cap an attacker who can push
    // a commit could force JSON.parse on multi-megabyte payloads.
    const oversized = Buffer.alloc(MAX_V4_ENVELOPE_BYTES + 1);
    assert.equal(parseEnvelope(oversized), null);
  });

  it("rejects malformed JSON", () => {
    assert.equal(parseEnvelope(Buffer.from("{not json")), null);
  });

  it("rejects a non-object top-level value", () => {
    assert.equal(parseEnvelope(Buffer.from('"string"')), null);
    assert.equal(parseEnvelope(Buffer.from("[]")), null);
    assert.equal(parseEnvelope(Buffer.from("null")), null);
    assert.equal(parseEnvelope(Buffer.from("42")), null);
  });

  it("rejects envelope missing signature", () => {
    const bytes = Buffer.from(JSON.stringify({ payload: makePayload() }));
    assert.equal(parseEnvelope(bytes), null);
  });

  it("rejects envelope missing payload", () => {
    const bytes = Buffer.from(JSON.stringify({ signature: "x" }));
    assert.equal(parseEnvelope(bytes), null);
  });

  it("rejects payload with schema_version below the accepted floor", () => {
    // schema_version: 3 is the legacy in-code value (different module);
    // the v4 parser must refuse to interpret it as v4. Disambiguation
    // by schema_version integer alone — no content sniffing.
    const env = { payload: { ...makePayload(), schema_version: 3 }, signature: "x" };
    assert.equal(parseEnvelope(Buffer.from(JSON.stringify(env))), null);
  });

  it("rejects pre-AGT-370 v4 envelopes (schema_version=4) — the manifest-binding reshape is breaking", () => {
    // v4 envelopes lack `manifest_snapshot_sha256` and carry the
    // (now-removed) per-approval `trusted_keys_snapshot_sha256`. The
    // verifier refuses them with the same null-return as any other
    // below-floor schema. Operators see a "schema_version too old"
    // surface in the dispatcher.
    const env = { payload: { ...makePayload(), schema_version: 4 }, signature: "x" };
    assert.equal(parseEnvelope(Buffer.from(JSON.stringify(env))), null);
  });

  it("rejects payload missing required top-level fields", () => {
    // Each test drops one required field; all should return null.
    const required: Array<keyof AttestationPayloadV4> = [
      "base_sha",
      "head_sha",
      "target_branch",
      "diff_sha256",
      "manifest_snapshot_sha256",
      "approvals",
      "checks",
      "trust_anchor_signatures",
      "signer_key_id",
    ];
    for (const field of required) {
      const p = makePayload();
      // Delete the field via a typed cast to keep TS happy.
      delete (p as Partial<AttestationPayloadV4>)[field];
      const bytes = Buffer.from(JSON.stringify({ payload: p, signature: "x" }));
      assert.equal(parseEnvelope(bytes), null, `expected rejection when missing ${field}`);
    }
  });

  it("rejects an approval entry with a bad verdict value", () => {
    const bad = makeApprovalEntry();
    (bad.approval as unknown as { verdict: string }).verdict = "maybe";
    const env = makeEnvelope(makePayload({ approvals: [bad] }));
    assert.equal(parseEnvelope(serializeEnvelope(env)), null);
  });

  it("rejects an approval entry missing server_attestation.signature", () => {
    const bad = makeApprovalEntry();
    delete (bad.server_attestation as Partial<typeof bad.server_attestation>).signature;
    const env = makeEnvelope(makePayload({ approvals: [bad] }));
    assert.equal(parseEnvelope(serializeEnvelope(env)), null);
  });

  it("rejects a trust_anchor_signatures entry missing signer_key_id", () => {
    const bad = { signature: "x" } as TrustAnchorSignatureV4;
    const env = makeEnvelope(makePayload({ trust_anchor_signatures: [bad] }));
    assert.equal(parseEnvelope(serializeEnvelope(env)), null);
  });
});

describe("trailer helpers", () => {
  it("payloadToTrailerValue → trailerValueToPayloadBytes round-trips canonical bytes", () => {
    const p = makePayload();
    const b64 = payloadToTrailerValue(p);
    const bytes = trailerValueToPayloadBytes(b64);
    assert.deepEqual(bytes, canonicalSerializePayload(p));
  });

  it("formatTrailers emits both keys on separate lines", () => {
    const p = makePayload();
    const out = formatTrailers(p, "sig==");
    const lines = out.split("\n");
    assert.equal(lines.length, 2);
    assert.match(lines[0]!, /^Stamp-Payload: /);
    assert.match(lines[1]!, /^Stamp-Verified: sig==$/);
  });
});

// ─── Worked examples from design.md ─────────────────────────────────

describe("worked example: approval with server_attestation", () => {
  it("parses, round-trips, and preserves the inner server signature", () => {
    // The canonical "Phase 1 happy path" envelope: one reviewer
    // approved, no checks, no .stamp/** modifications, no trust
    // anchor sigs. The single approval carries a server signature
    // that must survive both wire serialization and re-parsing.
    const approval = makeApproval({
      reviewer: "security",
      verdict: "approved",
      prompt_sha256: "01" + "23".repeat(31),
      diff_sha256: "ab" + "cd".repeat(31),
    });
    const entry: ApprovalEntryV4 = {
      approval,
      server_attestation: {
        server_key_id: approval.server_key_id,
        signature: "base64-server-sig-for-security-approval==",
      },
    };
    const env = makeEnvelope(makePayload({ approvals: [entry] }));

    const parsed = parseEnvelope(serializeEnvelope(env));
    assert.ok(parsed);
    assert.equal(parsed.payload.approvals.length, 1);
    const got = parsed.payload.approvals[0]!;
    assert.equal(got.approval.reviewer, "security");
    assert.equal(got.approval.verdict, "approved");
    assert.equal(got.approval.prompt_sha256, approval.prompt_sha256);
    assert.equal(
      got.server_attestation.signature,
      "base64-server-sig-for-security-approval==",
    );
    // Server's signing bytes match what we'd re-derive at verify time.
    assert.deepEqual(
      canonicalSerializeApproval(got.approval),
      canonicalSerializeApproval(approval),
    );
  });
});

describe("worked example: merge touching .stamp/** with trust_anchor_signatures", () => {
  it("parses an envelope with multi-sig admin signatures and preserves signer key ids in order", () => {
    // From the design doc: when the merge modifies any .stamp/** path,
    // trust_anchor_signatures is non-empty, each entry signed by an
    // admin-capability key per the manifest at base_sha, count must
    // meet the path rule's minimum_signatures. Array order is the
    // counter-sign order admins applied; the canonical serializer
    // must preserve it.
    const tas: TrustAnchorSignatureV4[] = [
      { signer_key_id: "sha256:" + "a1".repeat(32), signature: "alice-sig==" },
      { signer_key_id: "sha256:" + "b2".repeat(32), signature: "bob-sig==" },
    ];
    const env = makeEnvelope(
      makePayload({
        trust_anchor_signatures: tas,
      }),
    );

    const parsed = parseEnvelope(serializeEnvelope(env));
    assert.ok(parsed);
    assert.equal(parsed.payload.trust_anchor_signatures.length, 2);
    assert.equal(
      parsed.payload.trust_anchor_signatures[0]!.signer_key_id,
      tas[0]!.signer_key_id,
    );
    assert.equal(
      parsed.payload.trust_anchor_signatures[1]!.signer_key_id,
      tas[1]!.signer_key_id,
    );
  });
});

describe("worked example: manifest_snapshot_sha256 round-trips intact (AGT-370)", () => {
  it("preserves the outer envelope snapshot hash through serialize → parse → canonicalize", () => {
    // The lenient revocation property hinges on this field surviving
    // intact through the wire. A bit-flip or silent normalization
    // here would break the manifest-at-base_sha check the verifier
    // does to grandfather older verdicts past key rotation. AGT-370
    // moved the binding from per-approval (server-signed) to the
    // outer payload (operator-signed) so the server no longer needs
    // to read the manifest.
    const snapshot = "sha256:" + "deadbeef".repeat(8); // 64 hex chars
    const env = makeEnvelope(
      makePayload({ manifest_snapshot_sha256: snapshot }),
    );

    const parsed = parseEnvelope(serializeEnvelope(env));
    assert.ok(parsed);
    assert.equal(parsed.payload.manifest_snapshot_sha256, snapshot);
  });

  it("manifest_snapshot_sha256 participates in canonical key ordering", () => {
    // The new field must sort lexicographically with the rest of the
    // payload's keys. Two payloads with the field inserted in
    // different positions must serialize identically.
    const base = makePayload({ manifest_snapshot_sha256: "sha256:" + "ab".repeat(32) });
    const reordered: AttestationPayloadV4 = {
      manifest_snapshot_sha256: base.manifest_snapshot_sha256,
      signer_key_id: base.signer_key_id,
      schema_version: base.schema_version,
      base_sha: base.base_sha,
      head_sha: base.head_sha,
      target_branch: base.target_branch,
      diff_sha256: base.diff_sha256,
      approvals: base.approvals,
      checks: base.checks,
      trust_anchor_signatures: base.trust_anchor_signatures,
    };
    assert.deepEqual(
      canonicalSerializePayload(base),
      canonicalSerializePayload(reordered),
    );
  });
});
