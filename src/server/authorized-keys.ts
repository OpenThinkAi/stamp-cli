/**
 * sshd AuthorizedKeysCommand resolver.
 *
 * Invoked by sshd at connection time as:
 *   /usr/local/sbin/stamp-authorized-keys <username> <fingerprint>
 *
 * where <fingerprint> is sshd's %f format specifier — "SHA256:<base64>".
 * Looks the fingerprint up in the membership sqlite (read-only) and, if
 * matched, prints the matching authorized_keys line to stdout. Exits 0
 * regardless of whether a match was found — sshd treats empty stdout as
 * "no key matched, try the next auth method (AuthorizedKeysFile)", which
 * is exactly the behavior we want during the env-var → sqlite transition.
 *
 * Constraints sshd enforces on this script:
 *   - Must be owned by root, no group/other write bits (sshd validates).
 *   - Must produce its output quickly — every SSH handshake invokes us.
 *   - Runs as AuthorizedKeysCommandUser (we use `git`), which has READ-ONLY
 *     access to the DB via the root:git 0640 mode bits. Opening the DB
 *     read-only here means even a future bug that tries to mutate state
 *     fails at open time instead of corrupting authz.
 *
 * Failure handling: ANY error (DB open failure, malformed arguments, etc.)
 * is logged to stderr and the script exits 0 with empty stdout. That hands
 * the auth attempt off to sshd's AuthorizedKeysFile fallback rather than
 * locking everyone out if the DB is briefly unavailable (rebuild window,
 * volume not yet mounted, etc.). The legacy /home/git/.ssh/authorized_keys
 * path remains populated by entrypoint.sh during the transition, so a
 * DB-side failure degrades to "legacy AUTHORIZED_KEYS env var keys still
 * work" rather than "nobody can SSH in."
 */

import { findUserBySshFingerprint, openServerDb } from "../lib/serverDb.js";

function main(): void {
  // argv: [node, script, username, fingerprint]
  const argv = process.argv.slice(2);
  if (argv.length < 2) {
    console.error(
      "stamp-authorized-keys: expected 2 args (username, fingerprint); got " + argv.length,
    );
    process.exit(0);
  }

  const username = argv[0]!;
  const fingerprint = argv[1]!;

  // Only the git user is a valid SSH target on this server. Any other
  // username is a misconfiguration or a probe; emit nothing.
  if (username !== "git") {
    process.exit(0);
  }

  // Fingerprint sanity check before we hit the DB. sshd's %f format is
  // strict; anything that doesn't match is either a probe or a future
  // sshd version we don't know how to handle yet — fail open to the
  // AuthorizedKeysFile fallback.
  if (!fingerprint.startsWith("SHA256:") || fingerprint.length < 10) {
    process.exit(0);
  }

  let db;
  try {
    db = openServerDb({ readOnly: true });
  } catch (e) {
    console.error(
      `stamp-authorized-keys: could not open membership DB: ${(e as Error).message}`,
    );
    process.exit(0);
  }

  try {
    const user = findUserBySshFingerprint(db, fingerprint);
    if (user) {
      // Print the stored authorized_keys line verbatim. sshd parses this
      // exactly as it would a line from AuthorizedKeysFile — algorithm,
      // base64, optional comment.
      process.stdout.write(user.ssh_pubkey + "\n");
    }
  } catch (e) {
    console.error(
      `stamp-authorized-keys: lookup failed for ${fingerprint}: ${(e as Error).message}`,
    );
  } finally {
    try {
      db.close();
    } catch {
      // ignore — the process is exiting anyway
    }
  }

  process.exit(0);
}

main();
