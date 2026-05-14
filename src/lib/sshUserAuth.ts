/**
 * Parse the SSH_USER_AUTH file that sshd writes during connection setup
 * when `ExposeAuthInfo yes` is set in sshd_config. Each line is one
 * auth method that successfully authenticated the user; for pubkey auth
 * the line looks like:
 *
 *   publickey ssh-ed25519 AAAA... user@host
 *
 * The pubkey blob portion is the same wire format AuthorizedKeysFile
 * lines use, so we hand it through parseSshPubkey to compute the
 * fingerprint that keys the membership DB lookup.
 *
 * This is the load-bearing identity-binding step for SSH-invoked admin
 * commands (stamp-mint-invite, future user-management wrappers): without
 * it, a connected client could claim any role at the wrapper level. With
 * it, the wrapper trusts only sshd's already-completed pubkey auth.
 */

import { readFileSync } from "node:fs";
import { parseSshPubkey, type SshPubkey } from "./sshKeys.js";

/**
 * Read SSH_USER_AUTH from the process env and return the first publickey
 * entry's parsed pubkey. Returns null when:
 *   - SSH_USER_AUTH is unset (not run under sshd with ExposeAuthInfo)
 *   - the file is missing or unreadable
 *   - no `publickey` line is present (auth via a non-publickey method)
 *
 * Callers should treat null as "no authenticated identity available" and
 * refuse to proceed with admin actions — the absence of an identity is
 * never a green-light, only an opt-out-of-the-action signal.
 */
export function readAuthenticatedPubkey(): SshPubkey | null {
  const path = process.env["SSH_USER_AUTH"];
  if (!path) return null;

  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return null;
  }

  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("publickey ")) continue;
    // Strip the leading "publickey " token; the rest is a normal pubkey line.
    const pubkeyLine = trimmed.slice("publickey ".length).trim();
    try {
      return parseSshPubkey(pubkeyLine);
    } catch {
      // Malformed line — keep looking; sshd may emit multiple successful
      // methods if more than one is configured.
      continue;
    }
  }
  return null;
}
