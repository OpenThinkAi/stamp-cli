/**
 * The authorized_keys line the stamp server hands sshd for an enrolled key
 * (AGT-2265). Kept apart from src/lib/sshGate.ts so the AuthorizedKeysCommand
 * resolver — which runs on every SSH handshake — doesn't bundle the gate's
 * yaml/git dependencies.
 */

/**
 * Key options every session gets (AGT-2265). `command=` forces the session
 * through the stamp-gate verb whatever the client asked for (sshd keeps the
 * client's command in SSH_ORIGINAL_COMMAND); `restrict` turns off pty, all
 * forwarding and ~/.ssh/rc. The user id lets the gate check the key it sees
 * in SSH_USER_AUTH is the one this line was issued for.
 */
export function gatedAuthorizedKeysLine(userId: number, storedKey: string): string | null {
  const key = storedKey.trim();
  // The stored line must be a bare `<algorithm> <base64> [comment]` (what
  // invite-accept and the seeder store). Anything else — options of its
  // own, an embedded newline — is refused rather than merged with ours.
  if (!/^(ssh-|ecdsa-|sk-)[A-Za-z0-9@._-]+ [A-Za-z0-9+/]+={0,3}( [^\r\n]*)?$/.test(key)) {
    return null;
  }
  if (!Number.isSafeInteger(userId) || userId <= 0) return null;
  return `command="stamp-gate ${userId}",restrict ${key}`;
}
