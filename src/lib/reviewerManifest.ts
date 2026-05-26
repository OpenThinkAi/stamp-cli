/**
 * Reviewer manifest: schema, canonical serialization, sign, and verify.
 *
 * A reviewer manifest is a JSON file (`personas/manifest.json`) that a
 * persona source publishes alongside its individual persona files. It lists
 * the expected SHA-256 hashes for every reviewer the source provides, plus a
 * `signed_by` fingerprint that the consumer can use to locate the signing key
 * in its `.stamp/verifying-keys/` allowlist.
 *
 * A detached Ed25519 signature (`personas/manifest.json.sig`, base64) covers
 * the CANONICAL BYTES of the manifest JSON (not the raw file bytes). The
 * canonical form is computed by `serializeManifestCanonical`, which applies
 * the SAME JSON-sort-then-serialize pattern used by `reviewerHash.ts`
 * (`canonicalize`) and `trustedKeysManifest.ts` (`serializeManifestCanonical`)
 * — a single canonicalization story, NOT a fourth divergent form (AGT-113 G5).
 *
 * Wire format (manifest.json):
 *   {
 *     "version": 1,
 *     "source": "<owner>/<repo> or full https:// URL>",
 *     "reviewers": {
 *       "<name>": {
 *         "prompt_sha256": "<64-hex>",
 *         "tools_sha256": "<64-hex>",
 *         "mcp_sha256": "<64-hex>"
 *       },
 *       ...
 *     },
 *     "signed_by": "sha256:<64-hex>"   // fingerprint of the signing key
 *   }
 *
 * Signature file (manifest.json.sig): base64-encoded raw Ed25519 signature
 * over the canonical bytes of the manifest object.
 */

import { createHash } from "node:crypto";
import { canonicalize } from "./reviewerHash.js";
import { signBytes, verifyBytes } from "./signing.js";

export const MANIFEST_VERSION = 1;

/** Per-reviewer hash entry in the manifest. */
export interface ReviewerManifestEntry {
  prompt_sha256: string;
  tools_sha256: string;
  mcp_sha256: string;
}

/** The full reviewer manifest object (parsed from manifest.json). */
export interface ReviewerManifest {
  version: number;
  source: string;
  reviewers: Record<string, ReviewerManifestEntry>;
  /** Fingerprint of the signing key (sha256:<64-hex>). */
  signed_by: string;
}

// -------------------------------------------------------------------------
// Parsing
// -------------------------------------------------------------------------

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const FINGERPRINT_RE = /^sha256:[0-9a-f]{64}$/;

/**
 * Parse and validate a reviewer manifest from JSON text. Returns `null` on
 * any structural or field-shape error (callers surface their own messages).
 */
export function parseReviewerManifest(jsonText: string): ReviewerManifest | null {
  let raw: unknown;
  try {
    raw = JSON.parse(jsonText);
  } catch {
    return null;
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const obj = raw as Record<string, unknown>;

  if (obj.version !== MANIFEST_VERSION) return null;
  if (typeof obj.source !== "string" || !obj.source) return null;
  if (typeof obj.signed_by !== "string" || !FINGERPRINT_RE.test(obj.signed_by)) {
    return null;
  }
  if (!obj.reviewers || typeof obj.reviewers !== "object" || Array.isArray(obj.reviewers)) {
    return null;
  }

  const reviewers: Record<string, ReviewerManifestEntry> = {};
  for (const [name, entry] of Object.entries(obj.reviewers as Record<string, unknown>)) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return null;
    const e = entry as Record<string, unknown>;
    if (typeof e.prompt_sha256 !== "string" || !SHA256_HEX_RE.test(e.prompt_sha256)) {
      return null;
    }
    if (typeof e.tools_sha256 !== "string" || !SHA256_HEX_RE.test(e.tools_sha256)) {
      return null;
    }
    if (typeof e.mcp_sha256 !== "string" || !SHA256_HEX_RE.test(e.mcp_sha256)) {
      return null;
    }
    reviewers[name] = {
      prompt_sha256: e.prompt_sha256,
      tools_sha256: e.tools_sha256,
      mcp_sha256: e.mcp_sha256,
    };
  }

  return {
    version: MANIFEST_VERSION,
    source: obj.source as string,
    reviewers,
    signed_by: obj.signed_by as string,
  };
}

// -------------------------------------------------------------------------
// Canonicalization (G5: reuse the existing `canonicalize` from reviewerHash)
// -------------------------------------------------------------------------

/**
 * Produce the canonical bytes of a reviewer manifest for signing or
 * verification. Uses the SAME `canonicalize` (recursive key-sort) pattern
 * from `reviewerHash.ts` — NOT a new form. This is the G5 constraint from
 * AGT-113: do NOT introduce a fourth divergent canonical form.
 *
 * The canonical bytes are:
 *   UTF-8-encoded JSON of `canonicalize(manifest)` (sorted keys at every
 *   level, values untouched).
 */
export function serializeManifestCanonical(manifest: ReviewerManifest): Buffer {
  const sorted = canonicalize(manifest);
  return Buffer.from(JSON.stringify(sorted), "utf8");
}

/**
 * Compute sha256:<hex> of the canonical bytes of a reviewer manifest.
 * Useful for displaying a manifest hash in logs or for spot-checking.
 */
export function manifestSha256(manifest: ReviewerManifest): string {
  const bytes = serializeManifestCanonical(manifest);
  const hex = createHash("sha256").update(bytes).digest("hex");
  return `sha256:${hex}`;
}

// -------------------------------------------------------------------------
// Sign / verify
// -------------------------------------------------------------------------

/**
 * Sign a reviewer manifest with the given private key PEM.
 * Returns a base64-encoded detached Ed25519 signature over the manifest's
 * canonical bytes.
 */
export function signManifest(
  manifest: ReviewerManifest,
  privateKeyPem: string,
): string {
  const bytes = serializeManifestCanonical(manifest);
  return signBytes(privateKeyPem, bytes);
}

/**
 * Verify a detached manifest signature against the given public key PEM.
 * Returns `true` if the signature is valid, `false` otherwise.
 */
export function verifyManifestSignature(
  manifest: ReviewerManifest,
  signatureBase64: string,
  publicKeyPem: string,
): boolean {
  const bytes = serializeManifestCanonical(manifest);
  return verifyBytes(publicKeyPem, bytes, signatureBase64);
}

// -------------------------------------------------------------------------
// Wire path convention (G4)
// -------------------------------------------------------------------------

/** URL suffix for the manifest JSON file relative to the source root. */
export const MANIFEST_URL_SUFFIX = "personas/manifest.json";

/** URL suffix for the detached signature file. */
export const MANIFEST_SIG_URL_SUFFIX = "personas/manifest.json.sig";
