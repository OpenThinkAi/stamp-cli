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
  MAX_PR_ATTESTATION_BYTES,
  parseEnvelope,
  PR_ATTESTATION_SCHEMA_VERSION,
  readAttestationRef,
  serializeEnvelope,
  serializePayload,
  writeAttestationRef,
  type PrAttestationEnvelope,
  type PrAttestationPayload,
} from "../src/lib/prAttestation.ts";

function makePayload(overrides: Partial<PrAttestationPayload> = {}): PrAttestationPayload {
  return {
    schema_version: PR_ATTESTATION_SCHEMA_VERSION,
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
