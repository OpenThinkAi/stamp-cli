/**
 * Allowlist lookup for the `.stamp/verifying-keys/` trust plane.
 *
 * This is the CONSUMER side of the AGT-113 signed-manifest feature (Option B
 * custody design). The producer side (`stamp manifest sign`) writes detached
 * Ed25519 signatures; this module finds the corresponding public key in the
 * repo's `.stamp/verifying-keys/<fingerprint>.pub` directory before the
 * verifier validates the signature.
 *
 * KEY-SPACE SEPARATION: `.stamp/verifying-keys/` is intentionally DISTINCT
 * from `.stamp/trusted-keys/` (merge-signing trust). The two directories
 * carry separate authorities:
 *   - `trusted-keys/`: "this key may sign a stamp merge for this repo"
 *   - `verifying-keys/`: "this key may publish canonical org personas"
 *
 * A second maintainer's key must be explicitly added to BOTH allowlists
 * (separately) — implicit transitivity is deliberately rejected to minimize
 * blast radius (AGT-113 G1, G2 decisions).
 *
 * When the allowlist directory is EMPTY (or absent), `findVerifyingKey`
 * returns `null`, triggering the fail-open TOFU fallback in the caller
 * (AGT-113 G3 decision).
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fingerprintFromPem } from "./keys.js";
import { stampVerifyingKeysDir } from "./paths.js";

/**
 * Look up a public key PEM in a repo's `.stamp/verifying-keys/` directory by
 * fingerprint. Returns `null` if:
 *   - the directory does not exist (no allowlist → fail-open/TOFU)
 *   - no file in the directory has a fingerprint that matches
 *
 * Near-copy of `findTrustedKey` in `src/lib/keys.ts`, scoped to the
 * verifying-keys trust plane.
 */
export function findVerifyingKey(
  repoRoot: string,
  fingerprint: string,
): string | null {
  const dir = stampVerifyingKeysDir(repoRoot);
  let files: string[];
  try {
    files = readdirSync(dir);
  } catch {
    // Directory absent → no allowlist → TOFU fallback
    return null;
  }
  for (const f of files) {
    if (!f.endsWith(".pub")) continue;
    let pem: string;
    try {
      pem = readFileSync(join(dir, f), "utf8");
    } catch {
      continue;
    }
    try {
      if (fingerprintFromPem(pem) === fingerprint) return pem;
    } catch {
      // skip malformed keys
    }
  }
  return null;
}

/**
 * Return `true` if `.stamp/verifying-keys/` exists and contains at least one
 * `.pub` file. Used by the TOFU-vs-closed-policy decision in `reviewersFetch`:
 * the allowlist's presence is the opt-in signal that activates fail-closed
 * behavior for manifests (AGT-113 G3).
 */
export function hasVerifyingKeyAllowlist(repoRoot: string): boolean {
  const dir = stampVerifyingKeysDir(repoRoot);
  let files: string[];
  try {
    files = readdirSync(dir);
  } catch {
    return false;
  }
  return files.some((f) => f.endsWith(".pub"));
}
