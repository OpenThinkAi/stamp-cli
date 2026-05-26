/**
 * Tests for src/commands/manifest.ts — `stamp manifest sign` and
 * `stamp manifest verify` publisher tooling.
 *
 * AGT-113 acceptance criteria:
 *   - runManifestSign produces a valid signature file
 *   - runManifestVerify confirms a valid signature and rejects a bad one
 *   - Mismatched signed_by fingerprint is rejected before signing
 */

import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import { generateKeypair } from "../src/lib/keys.ts";
import { parseReviewerManifest, verifyManifestSignature, type ReviewerManifest } from "../src/lib/reviewerManifest.ts";
import { runManifestSign, runManifestVerify } from "../src/commands/manifest.ts";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeManifestJson(signerFp: string): ReviewerManifest {
  return {
    version: 1,
    source: "acme/stamp-personas",
    reviewers: {
      security: {
        prompt_sha256: "a".repeat(64),
        tools_sha256: "b".repeat(64),
        mcp_sha256: "c".repeat(64),
      },
    },
    signed_by: signerFp,
  };
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe("stamp manifest sign / verify (AGT-113)", () => {
  let tmp: string;
  let manifestPath: string;
  let sigPath: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "stamp-manifest-cmd-"));
    manifestPath = join(tmp, "manifest.json");
    sigPath = join(tmp, "manifest.json.sig");
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  // -----------------------------------------------------------------------
  // runManifestSign
  // -----------------------------------------------------------------------

  describe("runManifestSign", () => {
    it("produces a .sig file when called with a valid --key path", () => {
      const kp = generateKeypair();
      const m = makeManifestJson(kp.fingerprint);
      writeFileSync(manifestPath, JSON.stringify(m, null, 2));

      const keyPath = join(tmp, "key.pem");
      writeFileSync(keyPath, kp.privateKeyPem);

      runManifestSign({ manifestPath, keyPath, outputPath: sigPath });

      assert.ok(existsSync(sigPath), "signature file should be created");
      const sig = readFileSync(sigPath, "utf8").trim();
      assert.ok(sig.length > 0, "signature should be non-empty");

      // Verify the signature manually
      const manifest = parseReviewerManifest(JSON.stringify(m));
      assert.ok(manifest);
      assert.ok(verifyManifestSignature(manifest, sig, kp.publicKeyPem));
    });

    it("writes <manifestPath>.sig by default when --output is not supplied", () => {
      const kp = generateKeypair();
      const m = makeManifestJson(kp.fingerprint);
      writeFileSync(manifestPath, JSON.stringify(m, null, 2));

      const keyPath = join(tmp, "key.pem");
      writeFileSync(keyPath, kp.privateKeyPem);

      runManifestSign({ manifestPath, keyPath }); // no outputPath

      const defaultSigPath = `${manifestPath}.sig`;
      assert.ok(existsSync(defaultSigPath), "default .sig path should be written");
    });

    it("throws when manifest file does not exist", () => {
      const kp = generateKeypair();
      const keyPath = join(tmp, "key.pem");
      writeFileSync(keyPath, kp.privateKeyPem);

      assert.throws(
        () => runManifestSign({ manifestPath: join(tmp, "nonexistent.json"), keyPath }),
        /manifest file not found/,
      );
    });

    it("throws when manifest is malformed JSON", () => {
      writeFileSync(manifestPath, "this is not json");
      const kp = generateKeypair();
      const keyPath = join(tmp, "key.pem");
      writeFileSync(keyPath, kp.privateKeyPem);

      assert.throws(
        () => runManifestSign({ manifestPath, keyPath }),
        /not a valid reviewer manifest/,
      );
    });

    it("throws when signed_by does not match the key's fingerprint", () => {
      const kp1 = generateKeypair();
      const kp2 = generateKeypair();
      // Manifest says signed_by=kp1.fingerprint but we pass kp2's private key
      const m = makeManifestJson(kp1.fingerprint);
      writeFileSync(manifestPath, JSON.stringify(m, null, 2));
      const keyPath = join(tmp, "key.pem");
      writeFileSync(keyPath, kp2.privateKeyPem);

      assert.throws(
        () => runManifestSign({ manifestPath, keyPath }),
        /does not match/,
      );
    });

    it("throws when --key file does not exist", () => {
      const kp = generateKeypair();
      const m = makeManifestJson(kp.fingerprint);
      writeFileSync(manifestPath, JSON.stringify(m, null, 2));

      assert.throws(
        () => runManifestSign({ manifestPath, keyPath: join(tmp, "missing.pem") }),
        /signing key not found/,
      );
    });
  });

  // -----------------------------------------------------------------------
  // runManifestVerify
  // -----------------------------------------------------------------------

  describe("runManifestVerify", () => {
    it("succeeds with a valid manifest + signature + public key", () => {
      const kp = generateKeypair();
      const m = makeManifestJson(kp.fingerprint);
      writeFileSync(manifestPath, JSON.stringify(m, null, 2));

      // Produce the signature
      const keyPath = join(tmp, "key.pem");
      writeFileSync(keyPath, kp.privateKeyPem);
      runManifestSign({ manifestPath, keyPath, outputPath: sigPath });

      // Verify with the public key
      const pubKeyPath = join(tmp, "key.pub.pem");
      writeFileSync(pubKeyPath, kp.publicKeyPem);
      assert.doesNotThrow(() =>
        runManifestVerify({ manifestPath, sigPath, keyPath: pubKeyPath }),
      );
    });

    it("throws when signature is invalid (tampered manifest)", () => {
      const kp = generateKeypair();
      const m = makeManifestJson(kp.fingerprint);
      writeFileSync(manifestPath, JSON.stringify(m, null, 2));

      const keyPath = join(tmp, "key.pem");
      writeFileSync(keyPath, kp.privateKeyPem);
      runManifestSign({ manifestPath, keyPath, outputPath: sigPath });

      // Tamper with the manifest after signing
      const tampered = { ...m, source: "evil/source" };
      writeFileSync(manifestPath, JSON.stringify(tampered, null, 2));

      const pubKeyPath = join(tmp, "key.pub.pem");
      writeFileSync(pubKeyPath, kp.publicKeyPem);
      assert.throws(
        () => runManifestVerify({ manifestPath, sigPath, keyPath: pubKeyPath }),
        /signature verification failed/,
      );
    });

    it("throws when signature file is missing", () => {
      const kp = generateKeypair();
      const m = makeManifestJson(kp.fingerprint);
      writeFileSync(manifestPath, JSON.stringify(m, null, 2));

      assert.throws(
        () => runManifestVerify({ manifestPath, sigPath: join(tmp, "missing.sig") }),
        /signature file not found/,
      );
    });

    it("throws when manifest file is missing", () => {
      assert.throws(
        () => runManifestVerify({ manifestPath: join(tmp, "missing.json") }),
        /manifest file not found/,
      );
    });

    it("throws when --key does not exist", () => {
      const kp = generateKeypair();
      const m = makeManifestJson(kp.fingerprint);
      writeFileSync(manifestPath, JSON.stringify(m, null, 2));

      const keyPath = join(tmp, "key.pem");
      writeFileSync(keyPath, kp.privateKeyPem);
      runManifestSign({ manifestPath, keyPath, outputPath: sigPath });

      assert.throws(
        () => runManifestVerify({ manifestPath, sigPath, keyPath: join(tmp, "missing.pub.pem") }),
        /public key not found/,
      );
    });

    it("throws when the wrong public key is used for verification", () => {
      const kp1 = generateKeypair();
      const kp2 = generateKeypair();
      const m = makeManifestJson(kp1.fingerprint);
      writeFileSync(manifestPath, JSON.stringify(m, null, 2));

      const keyPath = join(tmp, "key.pem");
      writeFileSync(keyPath, kp1.privateKeyPem);
      runManifestSign({ manifestPath, keyPath, outputPath: sigPath });

      // Verify with kp2's public key (wrong key)
      const wrongPubKey = join(tmp, "wrong.pub.pem");
      writeFileSync(wrongPubKey, kp2.publicKeyPem);
      assert.throws(
        () => runManifestVerify({ manifestPath, sigPath, keyPath: wrongPubKey }),
        /signature verification failed/,
      );
    });
  });
});
