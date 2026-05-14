/**
 * SSH-invoked user-management dispatcher, reachable as:
 *
 *   ssh git@<host> stamp-users list
 *   ssh git@<host> stamp-users promote <name> --to <admin|owner>
 *   ssh git@<host> stamp-users demote  <name> --to <admin|member>
 *   ssh git@<host> stamp-users remove  <name>
 *
 * Symlinked into /home/git/git-shell-commands/stamp-users on the server.
 * Authenticates the caller by reading SSH_USER_AUTH (requires
 * ExposeAuthInfo yes in sshd_config — already enabled by phase 2) and
 * dispatches to the authority-matrix-aware lib operations in userOps.ts.
 *
 * Exit codes (consumed by the CLI client for specific operator prose):
 *
 *   0 — success
 *   1 — server-side config error (DB unreadable, identity binding
 *       failure, etc.)
 *   2 — usage error (missing/bad argv, unknown subcommand)
 *   3 — authority denial (caller's role doesn't permit the action)
 *   4 — target not found
 *   5 — last-owner-would-be-lost guard
 *   6 — cannot remove self
 *
 * stdout = machine-readable payload (a JSON object for `list`, an empty
 * body for write operations). stderr = human-readable prose using the
 * lowercase `note:` / `error:` convention that crosses the SSH boundary
 * unchanged into the operator's terminal.
 */

import {
  listUsersForCaller,
  removeUser,
  setUserRole,
  type ListUsersDenial,
  type RemoveUserDenial,
  type SetRoleDenial,
} from "../lib/userOps.js";
import {
  findUserByShortName,
  findUserBySshFingerprint,
  openServerDb,
  type Role,
  type UserRow,
} from "../lib/serverDb.js";
import { readAuthenticatedPubkey } from "../lib/sshUserAuth.js";

const EXIT = {
  OK: 0,
  CONFIG: 1,
  USAGE: 2,
  AUTHORITY: 3,
  NOT_FOUND: 4,
  LAST_OWNER: 5,
  CANNOT_REMOVE_SELF: 6,
} as const;

function fail(message: string, code: number): never {
  process.stderr.write(`error: ${message}\n`);
  process.exit(code);
}

function usage(): never {
  process.stderr.write(
    "usage:\n" +
      "  stamp-users list\n" +
      "  stamp-users promote          <short_name> --to <admin|owner>\n" +
      "  stamp-users demote           <short_name> --to <admin|member>\n" +
      "  stamp-users remove           <short_name>\n" +
      "  stamp-users get-stamp-pubkey <short_name>\n",
  );
  process.exit(EXIT.USAGE);
}

interface ParsedSetRole {
  subcommand: "promote" | "demote";
  short_name: string;
  to: Role;
}

interface ParsedRemove {
  subcommand: "remove";
  short_name: string;
}

interface ParsedList {
  subcommand: "list";
}

interface ParsedGetStampPubkey {
  subcommand: "get-stamp-pubkey";
  short_name: string;
}

type Parsed =
  | ParsedSetRole
  | ParsedRemove
  | ParsedList
  | ParsedGetStampPubkey;

const VALID_PROMOTE_TARGETS: ReadonlySet<Role> = new Set(["admin", "owner"]);
const VALID_DEMOTE_TARGETS: ReadonlySet<Role> = new Set(["admin", "member"]);

function parseArgs(argv: string[]): Parsed {
  if (argv.length === 0) usage();
  const [sub, ...rest] = argv as [string, ...string[]];
  if (sub === "list") {
    if (rest.length > 0) fail(`'list' takes no arguments (got ${rest.length})`, EXIT.USAGE);
    return { subcommand: "list" };
  }
  if (sub === "promote" || sub === "demote") {
    let short_name = "";
    let to: Role | "" = "";
    for (let i = 0; i < rest.length; i++) {
      const arg = rest[i]!;
      if (arg === "--to") {
        const next = rest[i + 1];
        if (!next) fail(`'--to' requires a value`, EXIT.USAGE);
        if (next !== "admin" && next !== "member" && next !== "owner") {
          fail(`--to must be 'admin', 'member', or 'owner' (got ${JSON.stringify(next)})`, EXIT.USAGE);
        }
        to = next;
        i++;
      } else if (arg.startsWith("--")) {
        fail(`unknown flag: ${arg}`, EXIT.USAGE);
      } else if (!short_name) {
        short_name = arg;
      } else {
        fail(`unexpected positional argument: ${arg}`, EXIT.USAGE);
      }
    }
    if (!short_name) fail(`missing <short_name>`, EXIT.USAGE);
    if (!to) fail(`'${sub}' requires --to <role>`, EXIT.USAGE);
    if (sub === "promote" && !VALID_PROMOTE_TARGETS.has(to)) {
      fail(`promote --to must be 'admin' or 'owner' (got '${to}')`, EXIT.USAGE);
    }
    if (sub === "demote" && !VALID_DEMOTE_TARGETS.has(to)) {
      fail(`demote --to must be 'admin' or 'member' (got '${to}')`, EXIT.USAGE);
    }
    return { subcommand: sub, short_name, to };
  }
  if (sub === "remove") {
    if (rest.length === 0) fail(`missing <short_name>`, EXIT.USAGE);
    if (rest.length > 1) fail(`unexpected positional argument: ${rest[1]}`, EXIT.USAGE);
    return { subcommand: "remove", short_name: rest[0]! };
  }
  if (sub === "get-stamp-pubkey") {
    if (rest.length === 0) fail(`missing <short_name>`, EXIT.USAGE);
    if (rest.length > 1) fail(`unexpected positional argument: ${rest[1]}`, EXIT.USAGE);
    return { subcommand: "get-stamp-pubkey", short_name: rest[0]! };
  }
  fail(`unknown subcommand: ${sub}`, EXIT.USAGE);
}

function exitFromSetRoleDenial(reason: SetRoleDenial): number {
  switch (reason) {
    case "target_not_found":
      return EXIT.NOT_FOUND;
    case "caller_lacks_authority":
      return EXIT.AUTHORITY;
    case "last_owner_would_be_lost":
      return EXIT.LAST_OWNER;
    case "invalid_target_role":
      return EXIT.USAGE;
  }
}

function exitFromRemoveDenial(reason: RemoveUserDenial): number {
  switch (reason) {
    case "target_not_found":
      return EXIT.NOT_FOUND;
    case "caller_lacks_authority":
      return EXIT.AUTHORITY;
    case "last_owner_would_be_lost":
      return EXIT.LAST_OWNER;
    case "cannot_remove_self":
      return EXIT.CANNOT_REMOVE_SELF;
  }
}

function exitFromListDenial(_reason: ListUsersDenial): number {
  return EXIT.AUTHORITY;
}

function resolveCaller(): UserRow {
  const pubkey = readAuthenticatedPubkey();
  if (!pubkey) {
    fail(
      "could not determine authenticated identity (SSH_USER_AUTH unset or has no publickey entry). " +
        "Server may be missing 'ExposeAuthInfo yes' in sshd_config.",
      EXIT.CONFIG,
    );
  }
  // skipChmod: this wrapper runs as the git user, root-owned file; entrypoint.sh
  // handles boot-time perm tightening. See src/lib/serverDb.ts comment.
  const db = openServerDb({ skipChmod: true });
  try {
    const caller = findUserBySshFingerprint(db, pubkey.fingerprint);
    if (!caller) {
      fail(
        `caller fingerprint ${pubkey.fingerprint} is not in the membership DB. ` +
          `Likely cause: phase-1 env-var sync hasn't run on this server yet.`,
        EXIT.CONFIG,
      );
    }
    return caller;
  } finally {
    db.close();
  }
}

function runList(): void {
  const caller = resolveCaller();
  const db = openServerDb({ skipChmod: true });
  try {
    const result = listUsersForCaller(db, caller);
    if (!result.ok) {
      fail(`listing users failed: ${result.reason}`, exitFromListDenial(result.reason));
    }
    // JSON output for the CLI to format. Includes ssh_pubkey for
    // human-readable comment but excludes any future secret-bearing
    // fields (last_seen_at is operational metadata, included).
    const payload = result.users.map((u) => ({
      id: u.id,
      short_name: u.short_name,
      role: u.role,
      source: u.source,
      ssh_fp: u.ssh_fp,
      has_stamp_pubkey: u.stamp_pubkey !== null,
      invited_by: u.invited_by,
      created_at: u.created_at,
      last_seen_at: u.last_seen_at,
    }));
    process.stdout.write(JSON.stringify({ users: payload }) + "\n");
  } finally {
    db.close();
  }
}

function runSetRole(parsed: ParsedSetRole): void {
  const caller = resolveCaller();
  const db = openServerDb({ skipChmod: true });
  try {
    const result = setUserRole(db, caller, parsed.short_name, parsed.to);
    if (!result.ok) {
      fail(
        `${parsed.subcommand} ${parsed.short_name} --to ${parsed.to}: ${result.reason}`,
        exitFromSetRoleDenial(result.reason),
      );
    }
    if (result.no_change) {
      process.stderr.write(
        `note: ${parsed.short_name} was already ${result.new_role} (no change)\n`,
      );
    } else {
      process.stderr.write(
        `note: ${parsed.short_name} ${result.old_role} → ${result.new_role}\n`,
      );
    }
  } finally {
    db.close();
  }
}

function runRemove(parsed: ParsedRemove): void {
  const caller = resolveCaller();
  const db = openServerDb({ skipChmod: true });
  try {
    const result = removeUser(db, caller, parsed.short_name);
    if (!result.ok) {
      fail(
        `remove ${parsed.short_name}: ${result.reason}`,
        exitFromRemoveDenial(result.reason),
      );
    }
    process.stderr.write(
      `note: removed ${result.removed.short_name} (was ${result.removed.role})\n`,
    );
  } finally {
    db.close();
  }
}

function runGetStampPubkey(parsed: ParsedGetStampPubkey): void {
  // Identity binding still required (so this surface stays consistent
  // with the rest of stamp-users — only authenticated users can read
  // the membership DB) but no role check beyond "you're enrolled".
  // The phase-4 trust-grant flow goes through the standard stamp gate
  // anyway, so an enrolled member who fetches a peer's stamp_pubkey
  // can't unilaterally widen anyone's trust.
  resolveCaller();
  const db = openServerDb({ skipChmod: true });
  try {
    const target = findUserByShortName(db, parsed.short_name);
    if (!target) {
      fail(`user ${JSON.stringify(parsed.short_name)} not found`, EXIT.NOT_FOUND);
    }
    if (target.stamp_pubkey === null) {
      fail(
        `user ${JSON.stringify(parsed.short_name)} has no stamp signing pubkey on file ` +
          `— ask them to re-enroll via stamp invites accept with --stamp-pubkey`,
        EXIT.NOT_FOUND,
      );
    }
    // PEM goes to stdout exactly as stored. The receiving CLI pipes
    // this verbatim into the repo's .stamp/trusted-keys/<name>.pub
    // file, so any drift here is observable in the next diff review.
    process.stdout.write(target.stamp_pubkey);
    if (!target.stamp_pubkey.endsWith("\n")) {
      process.stdout.write("\n");
    }
  } finally {
    db.close();
  }
}

function main(): void {
  const parsed = parseArgs(process.argv.slice(2));
  switch (parsed.subcommand) {
    case "list":
      runList();
      break;
    case "promote":
    case "demote":
      runSetRole(parsed);
      break;
    case "remove":
      runRemove(parsed);
      break;
    case "get-stamp-pubkey":
      runGetStampPubkey(parsed);
      break;
  }
}

main();
