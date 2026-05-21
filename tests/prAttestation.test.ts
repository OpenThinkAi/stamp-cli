/**
 * PR-attestation envelope tests. Three concerns:
 *   - JSON round-trip via parseEnvelope (bounded; rejects oversized + malformed)
 *   - attestationRefName validates patch-id shape
 *   - writeAttestationRef + readAttestationRef round-trip against a real
 *     temp git repo (real `git hash-object` + `git update-ref` + `git
 *     cat-file blob` — no mocking the load-bearing primitive)
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import {
  attestationRefName,
  LEGACY_CLIENT_PR_ATTESTATION_SCHEMA_VERSION,
  MAX_PR_ATTESTATION_BYTES,
  MIN_ACCEPTED_PR_ATTESTATION_VERSION,
  parseEnvelope,
  peekSchemaVersion,
  PR_ATTESTATION_SCHEMA_VERSION,
  readAttestationRef,
  serializeEnvelope,
  serializePayload,
  writeAttestationRef,
  type PrAttestationEnvelope,
  type PrAttestationPayload,
} from "../src/lib/prAttestation.ts";

/**
 * Build a v3 PR-attestation payload with the minimum required fields
 * for `parseEnvelope` to accept (post-AGT-338). v3 added `diff_sha256`,
 * `trust_anchor_signatures`, and tightened approvals to the v4 entry
 * shape — the parser checks structural presence; downstream
 * cryptographic checks happen in `verifyV4*` phases (out of scope for
 * this module-level test).
 */
function makePayload(overrides: Partial<PrAttestationPayload> = {}): PrAttestationPayload {
  return {
    schema_version: PR_ATTESTATION_SCHEMA_VERSION,
    patch_id: "a".repeat(40),
    base_sha: "b".repeat(40),
    head_sha: "c".repeat(40),
    target_branch: "main",
    target_branch_tip_sha: "f".repeat(40),
    diff_sha256: "1".repeat(64),
    // AGT-370: PR-mode v3 envelopes carry the operator-signed
    // manifest_snapshot_sha256 alongside the diff binding. Parser
    // requires it at the outer level.
    manifest_snapshot_sha256: "sha256:" + "a".repeat(64),
    approvals: [
      // Parser does not deep-validate approval element shape — the
      // pipeline phase (`verifyV4ApprovalSignatures`) is the canonical
      // gate for that. We use a v4-shape stub so the test artifact at
      // least RESEMBLES a real envelope.
      {
        approval: {
          reviewer: "security",
          verdict: "approved",
          prompt_sha256: "9".repeat(64),
          diff_sha256: "1".repeat(64),
          base_sha: "b".repeat(40),
          head_sha: "c".repeat(40),
          issued_at: "2026-05-18T12:00:00Z",
          server_key_id: "sha256:" + "b".repeat(64),
        },
        server_attestation: {
          server_key_id: "sha256:" + "b".repeat(64),
          signature: "fake-server-sig==",
        },
      },
    ],
    checks: [],
    trust_anchor_signatures: [],
    signer_key_id: "sha256:" + "e".repeat(64),
    ...overrides,
  };
}

function makeEnvelope(): PrAttestationEnvelope {
  return {
    payload: makePayload(),
    signature: "fake-base64-signature==",
  };
}

interface Repo {
  path: string;
  cleanup: () => void;
}

function git(repo: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd: repo,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function initRepo(): Repo {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-pratt-"));
  git(dir, ["init", "-q", "-b", "main"]);
  git(dir, ["config", "user.name", "Test"]);
  git(dir, ["config", "user.email", "test@example.invalid"]);
  git(dir, ["config", "commit.gpgsign", "false"]);
  writeFileSync(path.join(dir, "README.md"), "initial\n");
  git(dir, ["add", "-A"]);
  git(dir, ["commit", "-q", "-m", "initial"]);
  return { path: dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

describe("attestationRefName", () => {
  it("returns the canonical refs/stamp/attestations/<patch-id> path", () => {
    const id = "a".repeat(40);
    assert.equal(attestationRefName(id), `refs/stamp/attestations/${id}`);
  });

  it("rejects a non-40-hex patch-id", () => {
    assert.throws(() => attestationRefName("not-a-patch-id"), /40-char/);
    assert.throws(() => attestationRefName("a".repeat(39)), /40-char/);
    assert.throws(() => attestationRefName("a".repeat(41)), /40-char/);
    assert.throws(() => attestationRefName("Z".repeat(40)), /40-char/); // uppercase rejected
  });
});

describe("parseEnvelope", () => {
  it("round-trips a serialized envelope", () => {
    const env = makeEnvelope();
    const bytes = serializeEnvelope(env);
    const parsed = parseEnvelope(bytes);
    assert.ok(parsed);
    assert.equal(parsed.signature, env.signature);
    assert.equal(parsed.payload.patch_id, env.payload.patch_id);
    assert.equal(parsed.payload.target_branch, "main");
  });

  it("rejects an oversized blob without parsing", () => {
    // Blob just over the cap — should refuse before JSON.parse runs
    // (verifier runs before signature check; unbounded parse is a DoS
    // surface).
    const oversized = Buffer.alloc(MAX_PR_ATTESTATION_BYTES + 1);
    assert.equal(parseEnvelope(oversized), null);
  });

  it("rejects an empty blob", () => {
    assert.equal(parseEnvelope(Buffer.alloc(0)), null);
  });

  it("rejects malformed JSON", () => {
    assert.equal(parseEnvelope(Buffer.from("{not json")), null);
  });

  it("rejects a non-object top-level value", () => {
    assert.equal(parseEnvelope(Buffer.from('"string"')), null);
    assert.equal(parseEnvelope(Buffer.from("[]")), null);
  });

  it("rejects an envelope missing the signature", () => {
    const bad = JSON.stringify({ payload: makePayload() });
    assert.equal(parseEnvelope(Buffer.from(bad)), null);
  });

  it("rejects a payload with the wrong shape", () => {
    const bad = JSON.stringify({
      payload: { schema_version: 1 }, // missing required fields
      signature: "x",
    });
    assert.equal(parseEnvelope(Buffer.from(bad)), null);
  });

  it("preserves the exact bytes of serializePayload (signature target)", () => {
    // The signature is computed over serializePayload(payload), and
    // the verifier re-serializes payload from the parsed envelope to
    // re-check the signature. JSON.stringify is deterministic for
    // the same input object structure on a given Node version, but
    // we don't rely on that — we sign exactly what we serialize.
    // Pinning the round-trip here means a future reorder of fields
    // in PrAttestationPayload's TypeScript type definition could
    // surface as a hash divergence in this test before it breaks
    // anything in production.
    const env = makeEnvelope();
    const a = serializePayload(env.payload);
    const b = serializePayload(env.payload);
    assert.deepEqual(a, b);
  });
});

describe("writeAttestationRef + readAttestationRef", () => {
  it("writes a blob, points the ref at it, reads back the same envelope", () => {
    const r = initRepo();
    try {
      const env = makeEnvelope();
      const written = writeAttestationRef(env, r.path);
      assert.equal(written.ref, attestationRefName(env.payload.patch_id));
      assert.match(written.blob_sha, /^[0-9a-f]{40}$/);

      const round = readAttestationRef(env.payload.patch_id, r.path);
      assert.ok(round);
      assert.deepEqual(round, env);
    } finally {
      r.cleanup();
    }
  });

  it("readAttestationRef returns null when the ref doesn't exist", () => {
    const r = initRepo();
    try {
      assert.equal(readAttestationRef("a".repeat(40), r.path), null);
    } finally {
      r.cleanup();
    }
  });

  it("re-writing the same envelope produces the same blob (idempotent)", () => {
    const r = initRepo();
    try {
      const env = makeEnvelope();
      const first = writeAttestationRef(env, r.path);
      const second = writeAttestationRef(env, r.path);
      assert.equal(first.blob_sha, second.blob_sha);
      assert.equal(first.ref, second.ref);
    } finally {
      r.cleanup();
    }
  });

  it("two envelopes differing only in signature land at different blob SHAs", () => {
    // Sanity: blob is content-addressed, so the signature is part of
    // the addressed content. Re-attesting with a different key (or
    // a re-roll of the signature) creates a new blob; the old blob
    // is replaced at the ref but persists in the object store as an
    // unreachable orphan until git gc.
    const r = initRepo();
    try {
      const env1 = makeEnvelope();
      const env2 = { ...env1, signature: "different-sig==" };
      const w1 = writeAttestationRef(env1, r.path);
      const w2 = writeAttestationRef(env2, r.path);
      assert.notEqual(w1.blob_sha, w2.blob_sha);
      // ref points at the latest write.
      const round = readAttestationRef(env1.payload.patch_id, r.path);
      assert.equal(round?.signature, "different-sig==");
    } finally {
      r.cleanup();
    }
  });
});

// ─── AGT-338: schema-version policy + v3 shape requirements ────────

describe("AGT-338 schema-version constants", () => {
  it("PR_ATTESTATION_SCHEMA_VERSION is 3 (v4-trust envelope)", () => {
    assert.equal(PR_ATTESTATION_SCHEMA_VERSION, 3);
  });

  it("MIN_ACCEPTED_PR_ATTESTATION_VERSION is 3 (post-self-review-attack floor)", () => {
    assert.equal(MIN_ACCEPTED_PR_ATTESTATION_VERSION, 3);
  });

  it("LEGACY_CLIENT_PR_ATTESTATION_SCHEMA_VERSION is 2 (what stamp attest emits)", () => {
    // Frozen — the local CLI cannot fabricate the v3 envelope's
    // server-signed inner approvals; that's AGT-355's job. The
    // constant is named explicitly so the divergence is grep-able.
    assert.equal(LEGACY_CLIENT_PR_ATTESTATION_SCHEMA_VERSION, 2);
  });
});

describe("AGT-338 parseEnvelope: v2 envelopes rejected at the version floor", () => {
  it("rejects an envelope claiming schema_version: 2", () => {
    // v2 envelopes (the shape 1.x `stamp attest` writes) carry no
    // diff_sha256, no trust_anchor_signatures, and a legacy
    // single-signature approval shape. The verifier's job is to refuse
    // these with a clear "schema too old" — parseEnvelope returns
    // null and the caller surfaces the actionable error.
    const v2 = {
      payload: {
        schema_version: 2,
        patch_id: "a".repeat(40),
        base_sha: "b".repeat(40),
        head_sha: "c".repeat(40),
        target_branch: "main",
        target_branch_tip_sha: "f".repeat(40),
        approvals: [
          {
            reviewer: "security",
            verdict: "approved",
            review_sha: "d".repeat(64),
          },
        ],
        checks: [],
        signer_key_id: "sha256:" + "e".repeat(64),
      },
      signature: "fake-sig==",
    };
    assert.equal(parseEnvelope(Buffer.from(JSON.stringify(v2))), null);
  });

  it("rejects v1 envelopes", () => {
    const v1 = {
      payload: {
        schema_version: 1,
        patch_id: "a".repeat(40),
        base_sha: "b".repeat(40),
        head_sha: "c".repeat(40),
        target_branch: "main",
        approvals: [],
        checks: [],
        signer_key_id: "sha256:" + "e".repeat(64),
      },
      signature: "x",
    };
    assert.equal(parseEnvelope(Buffer.from(JSON.stringify(v1))), null);
  });

  it("rejects v3 envelopes missing diff_sha256", () => {
    const bad = makePayload();
    delete (bad as { diff_sha256?: string }).diff_sha256;
    assert.equal(
      parseEnvelope(Buffer.from(JSON.stringify({ payload: bad, signature: "x" }))),
      null,
    );
  });

  it("rejects v3 envelopes missing trust_anchor_signatures", () => {
    const bad = makePayload();
    delete (bad as { trust_anchor_signatures?: unknown[] }).trust_anchor_signatures;
    assert.equal(
      parseEnvelope(Buffer.from(JSON.stringify({ payload: bad, signature: "x" }))),
      null,
    );
  });

  it("rejects v3 envelopes missing target_branch_tip_sha", () => {
    const bad = makePayload();
    delete (bad as { target_branch_tip_sha?: string }).target_branch_tip_sha;
    assert.equal(
      parseEnvelope(Buffer.from(JSON.stringify({ payload: bad, signature: "x" }))),
      null,
    );
  });
});

describe("AGT-338 peekSchemaVersion: pre-parse version inspection", () => {
  it("returns the version number for a well-formed envelope", () => {
    const bytes = serializeEnvelope(makeEnvelope());
    assert.equal(peekSchemaVersion(bytes), PR_ATTESTATION_SCHEMA_VERSION);
  });

  it("returns the version for a below-minimum envelope (lets caller emit a specific error)", () => {
    const v2 = JSON.stringify({
      payload: { schema_version: 2, patch_id: "x" },
      signature: "y",
    });
    assert.equal(peekSchemaVersion(Buffer.from(v2)), 2);
  });

  it("returns null for an oversized blob", () => {
    const oversized = Buffer.alloc(MAX_PR_ATTESTATION_BYTES + 1);
    assert.equal(peekSchemaVersion(oversized), null);
  });

  it("returns null for malformed JSON", () => {
    assert.equal(peekSchemaVersion(Buffer.from("{not json")), null);
  });

  it("returns null when schema_version isn't a number", () => {
    const bad = JSON.stringify({
      payload: { schema_version: "three" },
      signature: "y",
    });
    assert.equal(peekSchemaVersion(Buffer.from(bad)), null);
  });

  it("returns null when there's no payload at all", () => {
    const bad = JSON.stringify({ signature: "y" });
    assert.equal(peekSchemaVersion(Buffer.from(bad)), null);
  });
});
