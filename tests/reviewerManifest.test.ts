/**
 * Tests for src/lib/reviewerManifest.ts — schema parsing, canonical
 * serialization, sign/verify round-trip, and determinism invariants.
 *
 * Also covers src/lib/verifyingKeys.ts — findVerifyingKey and
 * hasVerifyingKeyAllowlist.
 *
 * AGT-113 acceptance criteria:
 *   - sign/verify round-trip succeeds with a valid key pair
 *   - canonical form is deterministic (two equivalent manifests → same bytes)
 *   - G5: canonical form reuses the `canonicalize` (sort-keys) pattern,
 *     not a new form — verified by cross-checking against `canonicalize`
 *     from reviewerHash.ts
 *   - `findVerifyingKey` returns null when directory is absent (TOFU)
 *   - `findVerifyingKey` returns the PEM for an allowlisted key
 *   - multi-key allowlist: returns the correct key when multiple .pub files
 *     are present (rotation overlap scenario)
 */

import { strict as assert } from "node:assert";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import { generateKeypair, publicKeyFingerprintFilename } from "../src/lib/keys.ts";
import { canonicalize } from "../src/lib/reviewerHash.ts";
import {
  manifestSha256,
  parseReviewerManifest,
  serializeManifestCanonical,
  signManifest,
  verifyManifestSignature,
  type ReviewerManifest,
} from "../src/lib/reviewerManifest.ts";
import { stampVerifyingKeysDir } from "../src/lib/paths.ts";
import {
  findVerifyingKey,
  hasVerifyingKeyAllowlist,
} from "../src/lib/verifyingKeys.ts";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeManifest(overrides?: Partial<ReviewerManifest>): ReviewerManifest {
  return {
    version: 1,
    source: "acme/stamp-personas",
    reviewers: {
      security: {
        prompt_sha256: "a".repeat(64),
        tools_sha256: "b".repeat(64),
        mcp_sha256: "c".repeat(64),
      },
      standards: {
        prompt_sha256: "d".repeat(64),
        tools_sha256: "e".repeat(64),
        mcp_sha256: "f".repeat(64),
      },
    },
    signed_by: "sha256:" + "0".repeat(64),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// parseReviewerManifest
// ---------------------------------------------------------------------------

describe("parseReviewerManifest", () => {
  it("parses a valid manifest JSON", () => {
    const m = makeManifest();
    const json = JSON.stringify(m);
    const parsed = parseReviewerManifest(json);
    assert.ok(parsed);
    assert.equal(parsed.version, 1);
    assert.equal(parsed.source, "acme/stamp-personas");
    assert.equal(Object.keys(parsed.reviewers).length, 2);
    assert.equal(parsed.signed_by, "sha256:" + "0".repeat(64));
  });

  it("returns null for non-JSON input", () => {
    assert.equal(parseReviewerManifest("not json"), null);
  });

  it("returns null when version is wrong", () => {
    const m = { ...makeManifest(), version: 2 };
    assert.equal(parseReviewerManifest(JSON.stringify(m)), null);
  });

  it("returns null when source is missing", () => {
    const { source: _s, ...rest } = makeManifest();
    assert.equal(parseReviewerManifest(JSON.stringify(rest)), null);
  });

  it("returns null when signed_by is malformed", () => {
    const m = { ...makeManifest(), signed_by: "notafingerprint" };
    assert.equal(parseReviewerManifest(JSON.stringify(m)), null);
  });

  it("returns null when a reviewer entry has a bad hash", () => {
    const m = makeManifest();
    m.reviewers.security = { ...m.reviewers.security, prompt_sha256: "tooshort" };
    assert.equal(parseReviewerManifest(JSON.stringify(m)), null);
  });

  it("accepts an empty reviewers object", () => {
    const m = { ...makeManifest(), reviewers: {} };
    const parsed = parseReviewerManifest(JSON.stringify(m));
    assert.ok(parsed);
    assert.deepEqual(parsed.reviewers, {});
  });
});

// ---------------------------------------------------------------------------
// serializeManifestCanonical + G5 invariant
// ---------------------------------------------------------------------------

describe("serializeManifestCanonical", () => {
  it("produces deterministic bytes for the same logical manifest", () => {
    const m1 = makeManifest();
    // m2 has reviewers in a different insertion order
    const m2: ReviewerManifest = {
      ...makeManifest(),
      reviewers: {
        standards: m1.reviewers.standards,
        security: m1.reviewers.security,
      },
    };
    const b1 = serializeManifestCanonical(m1);
    const b2 = serializeManifestCanonical(m2);
    // Canonical form sorts keys — reviewer order shouldn't matter.
    assert.deepEqual(b1, b2, "canonical bytes should be identical regardless of field order");
  });

  it("G5: canonical form is JSON.stringify(canonicalize(manifest)) (no new form)", () => {
    const m = makeManifest();
    const expected = Buffer.from(JSON.stringify(canonicalize(m)), "utf8");
    const actual = serializeManifestCanonical(m);
    assert.deepEqual(actual, expected, "must reuse the existing canonicalize() pattern");
  });

  it("produces different bytes for logically different manifests", () => {
    const m1 = makeManifest();
    const m2 = makeManifest({ source: "other/source" });
    const b1 = serializeManifestCanonical(m1);
    const b2 = serializeManifestCanonical(m2);
    assert.notDeepEqual(b1, b2);
  });
});

// ---------------------------------------------------------------------------
// manifestSha256
// ---------------------------------------------------------------------------

describe("manifestSha256", () => {
  it("returns a sha256: prefixed hex string", () => {
    const sha = manifestSha256(makeManifest());
    assert.match(sha, /^sha256:[0-9a-f]{64}$/);
  });

  it("is stable across calls with the same manifest", () => {
    const m = makeManifest();
    assert.equal(manifestSha256(m), manifestSha256(m));
  });
});

// ---------------------------------------------------------------------------
// signManifest / verifyManifestSignature round-trip
// ---------------------------------------------------------------------------

describe("signManifest + verifyManifestSignature", () => {
  it("round-trip: sign then verify succeeds", () => {
    const kp = generateKeypair();
    const m = makeManifest({ signed_by: kp.fingerprint });
    const sig = signManifest(m, kp.privateKeyPem);
    assert.ok(typeof sig === "string" && sig.length > 0);
    const valid = verifyManifestSignature(m, sig, kp.publicKeyPem);
    assert.ok(valid, "signature should verify with the correct public key");
  });

  it("verification fails with a different public key", () => {
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();
    const m = makeManifest({ signed_by: kp1.fingerprint });
    const sig = signManifest(m, kp1.privateKeyPem);
    const valid = verifyManifestSignature(m, sig, kp2.publicKeyPem);
    assert.equal(valid, false, "signature should not verify with a different public key");
  });

  it("verification fails when the manifest is mutated after signing", () => {
    const kp = generateKeypair();
    const m = makeManifest({ signed_by: kp.fingerprint });
    const sig = signManifest(m, kp.privateKeyPem);
    const tampered: ReviewerManifest = {
      ...m,
      reviewers: {
        ...m.reviewers,
        security: { ...m.reviewers.security, prompt_sha256: "1".repeat(64) },
      },
    };
    const valid = verifyManifestSignature(tampered, sig, kp.publicKeyPem);
    assert.equal(valid, false, "signature should not verify after tampering");
  });

  it("verification fails with a corrupt base64 signature", () => {
    const kp = generateKeypair();
    const m = makeManifest({ signed_by: kp.fingerprint });
    const valid = verifyManifestSignature(m, "AAAA", kp.publicKeyPem);
    assert.equal(valid, false);
  });
});

// ---------------------------------------------------------------------------
// findVerifyingKey + hasVerifyingKeyAllowlist
// ---------------------------------------------------------------------------

describe("findVerifyingKey / hasVerifyingKeyAllowlist", () => {
  let tmp: string;
  let repoRoot: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "stamp-verifyingkeys-"));
    repoRoot = tmp;
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("returns null and hasVerifyingKeyAllowlist=false when directory is absent (TOFU)", () => {
    assert.equal(findVerifyingKey(repoRoot, "sha256:" + "a".repeat(64)), null);
    assert.equal(hasVerifyingKeyAllowlist(repoRoot), false);
  });

  it("returns null when the directory exists but is empty", () => {
    mkdirSync(stampVerifyingKeysDir(repoRoot), { recursive: true });
    assert.equal(findVerifyingKey(repoRoot, "sha256:" + "a".repeat(64)), null);
    assert.equal(hasVerifyingKeyAllowlist(repoRoot), false);
  });

  it("returns null when directory has only non-.pub files", () => {
    const dir = stampVerifyingKeysDir(repoRoot);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "readme.txt"), "not a key");
    assert.equal(findVerifyingKey(repoRoot, "sha256:" + "a".repeat(64)), null);
    assert.equal(hasVerifyingKeyAllowlist(repoRoot), false);
  });

  it("finds the correct key by fingerprint", () => {
    const kp = generateKeypair();
    const dir = stampVerifyingKeysDir(repoRoot);
    mkdirSync(dir, { recursive: true });
    const filename = publicKeyFingerprintFilename(kp.fingerprint);
    writeFileSync(join(dir, filename), kp.publicKeyPem);

    const result = findVerifyingKey(repoRoot, kp.fingerprint);
    assert.equal(result, kp.publicKeyPem);
    assert.equal(hasVerifyingKeyAllowlist(repoRoot), true);
  });

  it("returns null for an unknown fingerprint even when the dir has other keys", () => {
    const kp = generateKeypair();
    const dir = stampVerifyingKeysDir(repoRoot);
    mkdirSync(dir, { recursive: true });
    const filename = publicKeyFingerprintFilename(kp.fingerprint);
    writeFileSync(join(dir, filename), kp.publicKeyPem);

    const unknownFp = "sha256:" + "f".repeat(64);
    assert.equal(findVerifyingKey(repoRoot, unknownFp), null);
    // Directory has a .pub file → allowlist is present
    assert.equal(hasVerifyingKeyAllowlist(repoRoot), true);
  });

  it("multi-key allowlist: returns the correct key in a rotation-overlap scenario", () => {
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();
    const dir = stampVerifyingKeysDir(repoRoot);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, publicKeyFingerprintFilename(kp1.fingerprint)), kp1.publicKeyPem);
    writeFileSync(join(dir, publicKeyFingerprintFilename(kp2.fingerprint)), kp2.publicKeyPem);

    // Both keys should be individually findable
    assert.equal(findVerifyingKey(repoRoot, kp1.fingerprint), kp1.publicKeyPem);
    assert.equal(findVerifyingKey(repoRoot, kp2.fingerprint), kp2.publicKeyPem);
    assert.equal(hasVerifyingKeyAllowlist(repoRoot), true);
  });

  it("skips malformed .pub files", () => {
    const kp = generateKeypair();
    const dir = stampVerifyingKeysDir(repoRoot);
    mkdirSync(dir, { recursive: true });
    // A malformed key file
    writeFileSync(join(dir, "bad.pub"), "not a pem");
    // A valid key file
    writeFileSync(join(dir, publicKeyFingerprintFilename(kp.fingerprint)), kp.publicKeyPem);

    const result = findVerifyingKey(repoRoot, kp.fingerprint);
    assert.equal(result, kp.publicKeyPem);
  });
});
