/**
 * `stamp-gate-check` — the decision half of the SSH session gate (AGT-2265).
 *
 * sshd runs every session as the forced command `stamp-gate <user-id>`
 * (from the AuthorizedKeysCommand resolver) or `stamp-gate legacy` (keys
 * entrypoint.sh writes to the AuthorizedKeysFile). `stamp-gate` is a thin
 * shell verb in git-shell-commands that calls this helper and, on success,
 * execs `git-shell -c "<the command this helper printed>"`.
 *
 * This helper:
 *   1. resolves the caller from SSH_USER_AUTH against users.db, and checks
 *      it matches the user id the resolver baked into the forced command;
 *   2. parses SSH_ORIGINAL_COMMAND (src/lib/sshGate.ts) — path rule and
 *      verb allowlist;
 *   3. applies the repo rule / verb policy;
 *   4. prints the canonical, re-quoted command on stdout.
 *
 * Exit codes: 0 allowed (command on stdout); 1 no/unenrolled identity or
 * config error; 2 refused command (shape, path, unknown verb); 3 denied
 * by role or grants. Installed in /usr/local/sbin, not a verb.
 */

import { listRepoGrants } from "../lib/repoAccess.js";
import { findUserBySshFingerprint, openServerDb } from "../lib/serverDb.js";
import {
  canonicalCommand,
  decideRepoAccess,
  decideVerbAccess,
  isLiveBareRepo,
  parseOriginalCommand,
  readServerRepoMapping,
  type GateCaller,
} from "../lib/sshGate.js";
import { readAuthenticatedPubkey } from "../lib/sshUserAuth.js";

function fail(message: string, code: number): never {
  process.stderr.write(`error: ${message}\n`);
  process.exit(code);
}

function main(): void {
  const argv = process.argv.slice(2);
  const bound = argv[0];
  if (argv.length !== 1 || !bound || !(bound === "legacy" || /^[1-9][0-9]{0,15}$/.test(bound))) {
    fail("usage: stamp-gate-check <user-id|legacy>", 1);
  }

  const parsed = parseOriginalCommand(process.env["SSH_ORIGINAL_COMMAND"]);
  if (!parsed.ok) fail(parsed.message, 2);

  const pk = readAuthenticatedPubkey();
  if (!pk) {
    fail(
      "could not determine authenticated identity (SSH_USER_AUTH unset or has no publickey entry).",
      1,
    );
  }

  // Read-only: this runs on every SSH session. A DB error throws, and an
  // uncaught throw exits 1 — the gate fails closed.
  const db = openServerDb({ readOnly: true });
  let caller: GateCaller;
  try {
    const row = findUserBySshFingerprint(db, pk.fingerprint);
    if (!row) fail(`caller fingerprint ${pk.fingerprint} is not in the membership DB.`, 1);
    if (bound !== "legacy" && String(row.id) !== bound) {
      fail("authenticated key does not match the user this session was issued for.", 1);
    }
    caller = { role: row.role, grants: listRepoGrants(db, row.id) };
  } finally {
    db.close();
  }

  const cmd = parsed.cmd;
  if (cmd.kind === "git") {
    const live = isLiveBareRepo(cmd.repoPath);
    // A scoped member gets the same refusal for a missing repo as for a
    // repo they can't use, so the gate doesn't confirm which names exist.
    const d = decideRepoAccess(caller, cmd.name, () =>
      live ? readServerRepoMapping(cmd.repoPath) : null,
    );
    if (!d.ok) fail(d.message, 3);
    if (!live) fail(`repository '${cmd.name}' not found.`, 3);
  } else {
    const d = decideVerbAccess(caller, cmd.verb);
    if (!d.ok) fail(d.message, 3);
  }

  process.stdout.write(canonicalCommand(cmd));
}

main();
