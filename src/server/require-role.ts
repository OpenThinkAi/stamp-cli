/**
 * `stamp-require-role` — role gate for the shell SSH verbs (AGT-2259).
 *
 * The repo-management verbs new-stamp-repo, delete-stamp-repo (incl.
 * --purge) and restore-stamp-repo are POSIX shell scripts symlinked into
 * git-shell-commands. Every SSH user runs them as the one Unix user `git`,
 * so they can't tell a `member` from an `admin` on their own. Each script
 * calls this helper before it touches /srv/git:
 *
 *   /usr/local/sbin/stamp-require-role admin "delete repos" || exit $?
 *
 * It resolves the caller from SSH_USER_AUTH against users.db (the same
 * identity binding stamp-mint-invite and purge-trash use) and exits:
 *
 *   0 — caller's role meets the minimum
 *   1 — no authenticated identity / caller not enrolled / config error
 *   2 — usage error (bad arguments)
 *   3 — authority denial (role below the minimum)
 *
 * Installed in /usr/local/sbin, NOT in git-shell-commands: it is a helper
 * the verbs call, not a verb itself.
 */

import { checkCallerRole } from "../lib/sshRoleGate.js";

function fail(message: string, code: number): never {
  process.stderr.write(`error: ${message}\n`);
  process.exit(code);
}

function main(): void {
  const [min, action, ...rest] = process.argv.slice(2);
  if ((min !== "admin" && min !== "owner") || !action || rest.length > 0) {
    process.stderr.write('usage: stamp-require-role <admin|owner> "<action>"\n');
    process.exit(2);
  }
  // A DB error throws out of here; Node exits 1 on an uncaught throw, so
  // the gate fails closed, same as purge-trash.
  const result = checkCallerRole(min, action);
  if (!result.ok) fail(result.message, result.kind === "denied" ? 3 : 1);
}

main();
