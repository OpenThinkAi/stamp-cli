/**
 * Parse OpenSSH-format public keys and compute their SHA256 fingerprints
 * in the exact format sshd emits via the `%f` format specifier passed to
 * AuthorizedKeysCommand. That format is `SHA256:<base64-no-padding>`,
 * distinct from the `sha256:<hex>` form used elsewhere in stamp for stamp
 * signing keys (PEM/SPKI). Both formats exist; this module is the SSH
 * side only.
 *
 * The lookup keyed on this fingerprint is the load-bearing path for
 * sshd-based authentication of users stored in the membership sqlite —
 * any drift between this fingerprint and what sshd computes breaks
 * every connection. Test coverage pins the format to a known OpenSSH
 * fixture so the next regression here is loud.
 */

import { createHash } from "node:crypto";

export interface SshPubkey {
  /** Key algorithm token, e.g. "ssh-ed25519", "ecdsa-sha2-nistp256". */
  algorithm: string;
  /** Base64-decoded key blob (the bytes between the algorithm token and
   *  the trailing comment in a public-key line). */
  keyBlob: Buffer;
  /** Trailing comment, typically "user@host". May be empty. */
  comment: string;
  /** The original single-line representation, trimmed of leading/trailing
   *  whitespace. Stored verbatim in the membership DB so the value sshd
   *  later prints back via AuthorizedKeysCommand is bit-identical to what
   *  the operator submitted. */
  full: string;
  /** OpenSSH-style fingerprint: "SHA256:<base64-no-padding>". Matches the
   *  `%f` value sshd passes to AuthorizedKeysCommand. */
  fingerprint: string;
}

const ALLOWED_ALGOS = new Set([
  "ssh-ed25519",
  "ssh-rsa",
  "ecdsa-sha2-nistp256",
  "ecdsa-sha2-nistp384",
  "ecdsa-sha2-nistp521",
]);

/**
 * Parse a single OpenSSH-format public-key line into its components.
 * Rejects empty/blank lines and lines whose algorithm token is not on the
 * conservative allowlist (above) — keeps malformed input out of the DB
 * before we ever try to hand it to sshd.
 */
export function parseSshPubkey(line: string): SshPubkey {
  const trimmed = line.trim();
  if (trimmed.length === 0) {
    throw new Error("ssh pubkey line is empty");
  }
  if (trimmed.startsWith("#")) {
    throw new Error("ssh pubkey line is a comment");
  }

  const parts = trimmed.split(/\s+/);
  if (parts.length < 2) {
    throw new Error(
      "ssh pubkey line must have at least <algorithm> <base64> tokens",
    );
  }

  const [algorithm, b64, ...rest] = parts as [string, string, ...string[]];
  if (!ALLOWED_ALGOS.has(algorithm)) {
    throw new Error(`unsupported ssh pubkey algorithm: ${algorithm}`);
  }

  // Buffer.from(string, "base64") does NOT throw on invalid input — it
  // silently strips non-base64 characters. So a try/catch around this
  // call is dead code; the real validation is the re-encode comparison
  // below, which catches a paste with a stray quote/character that
  // would otherwise produce a key blob mismatched against sshd's view.
  const keyBlob = Buffer.from(b64, "base64");
  if (keyBlob.length === 0) {
    throw new Error("ssh pubkey base64 blob is empty");
  }
  if (keyBlob.toString("base64").replace(/=+$/, "") !== b64.replace(/=+$/, "")) {
    throw new Error("ssh pubkey base64 blob has trailing junk");
  }

  return {
    algorithm,
    keyBlob,
    comment: rest.join(" "),
    full: trimmed,
    fingerprint: sshFingerprintFromBlob(keyBlob),
  };
}

/**
 * SHA256 fingerprint of a raw key blob in OpenSSH wire format. Output is
 * `SHA256:<base64-no-padding>` — the exact form sshd emits in logs and via
 * the `%f` format specifier.
 */
export function sshFingerprintFromBlob(keyBlob: Buffer): string {
  const hash = createHash("sha256").update(keyBlob).digest();
  const b64 = hash.toString("base64").replace(/=+$/, "");
  return `SHA256:${b64}`;
}

/**
 * Split a multi-line authorized_keys-style blob into individual valid pubkey
 * lines, dropping blanks and `#` comments. Returns parsed pubkeys and any
 * parse failures alongside their source line numbers — callers decide
 * whether to abort or log-and-continue.
 */
export function parseSshPubkeyList(blob: string): {
  pubkeys: SshPubkey[];
  errors: Array<{ lineNumber: number; line: string; error: string }>;
} {
  const pubkeys: SshPubkey[] = [];
  const errors: Array<{ lineNumber: number; line: string; error: string }> = [];
  const lines = blob.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] ?? "";
    const stripped = raw.trim();
    if (stripped.length === 0 || stripped.startsWith("#")) continue;
    try {
      pubkeys.push(parseSshPubkey(stripped));
    } catch (e) {
      errors.push({
        lineNumber: i + 1,
        line: stripped,
        error: (e as Error).message,
      });
    }
  }
  return { pubkeys, errors };
}
