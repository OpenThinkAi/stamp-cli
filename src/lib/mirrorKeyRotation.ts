/**
 * Decide what `stamp provision --migrate-bypass` does with the
 * `stamp-mirror` deploy key on the GitHub mirror (AGT-2242).
 *
 * The per-repo deploy key is a Ruleset bypass actor: whoever holds its
 * private half can push straight to the mirror's protected branches and
 * skip the stamp gate. The key the migration registers comes from the
 * stamp server (`stamp-server-pubkey <owner>/<repo>`), and a git-shell
 * escape on that server can overwrite the per-repo key file. Before this
 * module, a mismatch between the registered key and whatever the server
 * reported was "fixed" automatically: delete the registered key, register
 * the server's. A routine post-restart reconciliation loop would then
 * register an attacker-substituted key as a bypass actor with no human in
 * the loop.
 *
 * Now a mismatch is refused by default. Rotating the registered key needs
 * BOTH `--replace-key` (intent) and `--expect-fingerprint <SHA256:...>`
 * (the fingerprint the operator verified out-of-band); the key the server
 * returns must hash to exactly that fingerprint. The refusal prints the
 * old and new fingerprints so the operator has something concrete to
 * verify.
 *
 * Pure: no gh / ssh calls. The command layer does the I/O and acts on the
 * returned decision.
 */

import { parseSshPubkey, type SshPubkey } from "./sshKeys.js";

/** OpenSSH SHA256 fingerprint: `SHA256:` + 43 chars of unpadded base64. */
const SSH_FINGERPRINT_RE = /^SHA256:[A-Za-z0-9+/]{43}$/;

export type MirrorKeyDecision =
  /** A key under the canonical title already matches the server's key. */
  | { action: "reuse"; fingerprint: string }
  /** No key is registered under the canonical title; register the server's. */
  | { action: "register"; fingerprint: string }
  /**
   * The registered key differs and the operator explicitly approved the
   * rotation to a key matching their pinned fingerprint.
   */
  | { action: "replace"; oldFingerprint: string; fingerprint: string };

export interface MirrorKeyDecisionInput {
  owner: string;
  repo: string;
  /**
   * Whether a deploy key exists under the canonical `stamp-mirror` title.
   * `existingBody` may still be null when it exists but its body could not
   * be read — treated as a mismatch (never as "safe to overwrite").
   */
  existingRegistered: boolean;
  existingBody: string | null;
  /** The public-key line the stamp server returned for this repo. */
  serverPubkey: string;
  /** `--replace-key`: operator intends to rotate the registered key. */
  replaceKey?: boolean;
  /** `--expect-fingerprint`: out-of-band pin for the server's key. */
  expectFingerprint?: string;
}

/**
 * Validate an `--expect-fingerprint` value. Accepts exactly the token
 * `ssh-keygen -lf <file>` prints (`SHA256:<base64-no-padding>`).
 */
export function validateExpectFingerprint(fp: string): string {
  const trimmed = fp.trim();
  if (!SSH_FINGERPRINT_RE.test(trimmed)) {
    throw new Error(
      `--expect-fingerprint must be an OpenSSH SHA256 fingerprint ` +
        `(SHA256: followed by 43 base64 characters, as printed by ` +
        `\`ssh-keygen -lf <key>.pub\`); got ${JSON.stringify(fp)}`,
    );
  }
  return trimmed;
}

function parseOrThrow(line: string, what: string): SshPubkey {
  try {
    return parseSshPubkey(line);
  } catch (err) {
    throw new Error(
      `${what} is not a valid OpenSSH public key: ` +
        `${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

function sameKey(a: SshPubkey, b: SshPubkey): boolean {
  return a.algorithm === b.algorithm && a.keyBlob.equals(b.keyBlob);
}

export function decideMirrorKeyAction(
  input: MirrorKeyDecisionInput,
): MirrorKeyDecision {
  const target = `${input.owner}/${input.repo}`;
  const server = parseOrThrow(
    input.serverPubkey,
    `the stamp server's per-repo key for ${target}`,
  );
  const newFp = server.fingerprint;

  // The pin, when given, is checked on EVERY path — first registration
  // and no-op re-runs included — so `--expect-fingerprint` always means
  // "only proceed if the server's key is the one I verified".
  if (input.expectFingerprint !== undefined) {
    const pinned = validateExpectFingerprint(input.expectFingerprint);
    if (pinned !== newFp) {
      throw new Error(
        `the stamp server's per-repo key for ${target} has fingerprint ${newFp}, ` +
          `but --expect-fingerprint is ${pinned}. Refusing to register it. ` +
          `If the server key changed unexpectedly, treat the stamp server as ` +
          `possibly compromised and investigate before registering anything.`,
      );
    }
  }

  if (!input.existingRegistered) {
    return { action: "register", fingerprint: newFp };
  }

  let existing: SshPubkey | null = null;
  if (input.existingBody !== null) {
    try {
      existing = parseSshPubkey(input.existingBody);
    } catch {
      existing = null;
    }
  }
  if (existing !== null && sameKey(existing, server)) {
    return { action: "reuse", fingerprint: newFp };
  }

  const oldFp = existing?.fingerprint ?? "(unreadable)";
  const fpLines =
    `  registered on GitHub: ${oldFp}\n` +
    `  stamp server reports: ${newFp}\n`;

  if (!input.replaceKey) {
    throw new Error(
      `the "stamp-mirror" deploy key registered on ${target} does not match ` +
        `the key the stamp server reports. Refusing to replace it ` +
        `automatically: that key is a Ruleset bypass actor, and a substituted ` +
        `server-side key would let its holder push past the stamp gate.\n` +
        fpLines +
        `Verify the new fingerprint out-of-band (e.g. \`ssh-keygen -lf ` +
        `/srv/git/.ssh-client-keys/${input.owner}_${input.repo}_ed25519.pub\` ` +
        `from your hosting platform's console, and confirm why the key ` +
        `changed). If the rotation is expected, re-run with the fingerprint you ` +
        `verified (deliberately not pre-filled — copying the server's value ` +
        `would skip the check):\n` +
        `  stamp provision --migrate-bypass --replace-key --expect-fingerprint SHA256:<verified>`,
    );
  }
  if (input.expectFingerprint === undefined) {
    throw new Error(
      `--replace-key requires --expect-fingerprint <SHA256:...>: the ` +
        `fingerprint of the new key, verified out-of-band.\n` +
        fpLines +
        `Re-run with --expect-fingerprint set to the fingerprint you verified.`,
    );
  }
  // Pin was already checked against newFp above.
  return { action: "replace", oldFingerprint: oldFp, fingerprint: newFp };
}
