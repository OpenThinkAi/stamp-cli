/**
 * `stamp manifest sign` / `stamp manifest verify` — publisher tooling for
 * signed reviewer manifests (AGT-113 G6).
 *
 * These commands are the producer-side complement to the consumer-side
 * verification that `stamp reviewers fetch` performs. A persona-source
 * maintainer uses `stamp manifest sign` to produce the detached signature
 * that consumers verify; `stamp manifest verify` lets anyone check a
 * manifest+sig pair against a specific public key (for local debugging,
 * CI pipelines, or third-party auditing).
 *
 * Wire format recap:
 *   - manifest.json: a JSON file listing `{ version, source, reviewers, signed_by }`
 *   - manifest.json.sig: base64-encoded detached Ed25519 signature over the
 *     CANONICAL bytes of the manifest (sorted keys, JSON-encoded — same
 *     canonicalization as reviewerHash.ts / trustedKeysManifest.ts).
 */

import { createPublicKey } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import {
  fingerprintFromPem,
  loadUserKeypair,
} from "../lib/keys.js";
import {
  manifestSha256,
  parseReviewerManifest,
  signManifest,
  verifyManifestSignature,
} from "../lib/reviewerManifest.js";

// --------------------------------------------------------------------------
// stamp manifest sign
// --------------------------------------------------------------------------

export interface ManifestSignOptions {
  /** Path to the manifest.json file to sign. */
  manifestPath: string;
  /**
   * Override the signing key. When absent, uses the operator's local key
   * at ~/.stamp/keys/ed25519. Accepts a path to a private key PEM file.
   */
  keyPath?: string;
  /**
   * Where to write the signature. Defaults to <manifestPath>.sig
   * (i.e. alongside the manifest file).
   */
  outputPath?: string;
}

export function runManifestSign(opts: ManifestSignOptions): void {
  const { manifestPath, keyPath, outputPath } = opts;

  if (!existsSync(manifestPath)) {
    throw new Error(`manifest file not found: ${manifestPath}`);
  }

  const manifestText = readFileSync(manifestPath, "utf8");
  const manifest = parseReviewerManifest(manifestText);
  if (!manifest) {
    throw new Error(
      `${manifestPath} is not a valid reviewer manifest. ` +
        `Expected JSON with fields: version (1), source, reviewers, signed_by.`,
    );
  }

  // Load the signing key.
  let privateKeyPem: string;
  let fingerprint: string;

  if (keyPath) {
    if (!existsSync(keyPath)) {
      throw new Error(`signing key not found: ${keyPath}`);
    }
    privateKeyPem = readFileSync(keyPath, "utf8");
    // Derive the fingerprint from the private key's public component.
    // createPublicKey(<private PEM>) returns the public KeyObject — naming
    // it as such avoids the appearance of exporting private material.
    const derivedPub = createPublicKey(privateKeyPem);
    const publicKeyPem = derivedPub.export({ type: "spki", format: "pem" }) as string;
    fingerprint = fingerprintFromPem(publicKeyPem);
  } else {
    const kp = loadUserKeypair();
    if (!kp) {
      throw new Error(
        `no signing key found at ~/.stamp/keys/. ` +
          `Generate one with \`stamp keys generate\` or pass --key <path>.`,
      );
    }
    privateKeyPem = kp.privateKeyPem;
    fingerprint = kp.fingerprint;
  }

  // Verify that the manifest's signed_by matches the key we're about to sign with.
  if (manifest.signed_by !== fingerprint) {
    throw new Error(
      `manifest.signed_by (${manifest.signed_by}) does not match ` +
        `the fingerprint of the signing key (${fingerprint}). ` +
        `Update manifest.signed_by to ${fingerprint} before signing, ` +
        `or pass --key pointing at the key whose fingerprint is ${manifest.signed_by}.`,
    );
  }

  const sigBase64 = signManifest(manifest, privateKeyPem);
  const sigPath = outputPath ?? `${manifestPath}.sig`;
  writeFileSync(sigPath, sigBase64 + "\n", "utf8");

  const sha = manifestSha256(manifest);
  const bar = "─".repeat(72);
  console.log(bar);
  console.log(`signed manifest`);
  console.log(bar);
  console.log(`  manifest:     ${manifestPath}`);
  console.log(`  signature:    ${sigPath}`);
  console.log(`  signer:       ${fingerprint}`);
  console.log(`  manifest sha: ${sha}`);
  console.log(bar);
}

// --------------------------------------------------------------------------
// stamp manifest verify
// --------------------------------------------------------------------------

export interface ManifestVerifyOptions {
  /** Path to the manifest.json file. */
  manifestPath: string;
  /**
   * Path to the signature file. Defaults to <manifestPath>.sig.
   */
  sigPath?: string;
  /**
   * Path to the public key PEM file to verify against. When absent,
   * derives from the `signed_by` field using the operator's local key
   * (useful for maintainers verifying their own manifests). Accepts any
   * SPKI Ed25519 PEM.
   */
  keyPath?: string;
}

export function runManifestVerify(opts: ManifestVerifyOptions): void {
  const { manifestPath } = opts;
  const sigPath = opts.sigPath ?? `${manifestPath}.sig`;

  if (!existsSync(manifestPath)) {
    throw new Error(`manifest file not found: ${manifestPath}`);
  }
  if (!existsSync(sigPath)) {
    throw new Error(
      `signature file not found: ${sigPath}. ` +
        `Run \`stamp manifest sign ${manifestPath}\` to produce one, ` +
        `or pass --sig pointing at the signature file.`,
    );
  }

  const manifestText = readFileSync(manifestPath, "utf8");
  const manifest = parseReviewerManifest(manifestText);
  if (!manifest) {
    throw new Error(
      `${manifestPath} is not a valid reviewer manifest. ` +
        `Expected JSON with fields: version (1), source, reviewers, signed_by.`,
    );
  }

  const sigBase64 = readFileSync(sigPath, "utf8").trim();
  if (!sigBase64) {
    throw new Error(`signature file ${sigPath} is empty.`);
  }

  // Resolve the verification key.
  let publicKeyPem: string;
  if (opts.keyPath) {
    if (!existsSync(opts.keyPath)) {
      throw new Error(`public key not found: ${opts.keyPath}`);
    }
    publicKeyPem = readFileSync(opts.keyPath, "utf8");
  } else {
    // Fall back to the operator's local keypair for self-verification.
    const kp = loadUserKeypair();
    if (!kp) {
      throw new Error(
        `no key found. Pass --key <pub-file> to verify against a specific public key, ` +
          `or generate a local key with \`stamp keys generate\`.`,
      );
    }
    publicKeyPem = kp.publicKeyPem;
    // Sanity-check: does the local key match the manifest's signed_by?
    if (kp.fingerprint !== manifest.signed_by) {
      throw new Error(
        `manifest.signed_by (${manifest.signed_by}) does not match ` +
          `your local key fingerprint (${kp.fingerprint}). ` +
          `Pass --key <path-to-the-signer's-pub-file> to verify with the correct key.`,
      );
    }
  }

  const valid = verifyManifestSignature(manifest, sigBase64, publicKeyPem);
  const sha = manifestSha256(manifest);
  const bar = "─".repeat(72);

  if (valid) {
    console.log(bar);
    console.log(`manifest signature: VALID`);
    console.log(bar);
    console.log(`  manifest:     ${manifestPath}`);
    console.log(`  signature:    ${sigPath}`);
    console.log(`  signed by:    ${manifest.signed_by}`);
    console.log(`  manifest sha: ${sha}`);
    console.log(`  reviewers:    ${Object.keys(manifest.reviewers).join(", ")}`);
    console.log(bar);
  } else {
    // Structural blocks ALWAYS go to stdout; only the `error: ` prefix line
    // (emitted by handleCliError from the thrown Error) belongs on stderr.
    // Label padding matches the VALID block above (14 chars) for consistency.
    console.log(bar);
    console.log(`manifest signature: INVALID`);
    console.log(bar);
    console.log(`  manifest:     ${manifestPath}`);
    console.log(`  signature:    ${sigPath}`);
    console.log(bar);
    throw new Error(
      `signature verification failed for ${manifestPath} (signature: ${sigPath}). ` +
        `The manifest may have been modified after signing, ` +
        `or the wrong key was used for verification.`,
    );
  }
}
