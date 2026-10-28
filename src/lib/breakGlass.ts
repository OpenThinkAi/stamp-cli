/**
 * `stamp-break-glass` — root-only recovery CLI inside the stamp server
 * container (AGT-2260).
 *
 * users.db is the only source of SSH access (sshd_config sets
 * `AuthorizedKeysFile none`, and AUTHORIZED_KEYS only bootstraps an empty
 * server). If every admin/owner key is lost or removed, nobody can get in
 * over SSH to fix it. This CLI is the way back: an operator opens a root
 * shell in the container through the hosting platform (e.g. `railway ssh`,
 * `docker exec`) and enrolls or re-promotes a key directly in users.db.
 *
 *   stamp-break-glass add [--role admin|owner] <pubkey-file | ->
 *   stamp-break-glass list
 *
 * `add` reads one or more OpenSSH public-key lines. A key not in the table
 * is inserted (source=manual); a key already there has its role set to
 * --role (default admin). Nothing is ever removed.
 *
 * It is not reachable over SSH: it lives in /usr/local/sbin (not in
 * git-shell-commands, and not on the stamp-gate verb allowlist), the file
 * is root:root 0700 so the git user can't execute it, and main() refuses
 * any uid other than 0.
 *
 * Exit codes: 0 ok, 1 not root / runtime error, 2 usage or no valid key.
 */

import { readFileSync } from "node:fs";
import type { DatabaseSync } from "node:sqlite";
import {
  findUserBySshFingerprint,
  insertUser,
  listUsers,
  openServerDb,
  suggestUniqueShortName,
  type Role,
} from "./serverDb.js";
import { contentAddressedShortName, parseSshPubkeyList, sshPubkeyBody } from "./sshKeys.js";

export interface BreakGlassIo {
  /** Effective uid of the caller; anything but 0 is refused. */
  uid: number;
  /** DB path override (tests). Defaults to the server path resolution. */
  dbPath?: string;
  /** Skip chmod of the DB (tests on tmpfs). */
  skipChmod?: boolean;
  readStdin: () => string;
  out: (s: string) => void;
  err: (s: string) => void;
}

const USAGE =
  "usage: stamp-break-glass add [--role admin|owner] <pubkey-file | ->\n" +
  "       stamp-break-glass list\n";

function openDb(io: BreakGlassIo): DatabaseSync {
  return openServerDb({ path: io.dbPath, skipChmod: io.skipChmod });
}

function add(argv: string[], io: BreakGlassIo): number {
  let role: Role = "admin";
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--role") {
      const v = argv[++i];
      if (v !== "admin" && v !== "owner") {
        io.err(`error: --role must be admin or owner\n${USAGE}`);
        return 2;
      }
      role = v;
    } else {
      rest.push(a);
    }
  }
  if (rest.length !== 1) {
    io.err(`error: add takes exactly one <pubkey-file | -> argument\n${USAGE}`);
    return 2;
  }
  const src = rest[0]!;
  let blob: string;
  try {
    blob = src === "-" ? io.readStdin() : readFileSync(src, "utf8");
  } catch (e) {
    io.err(`error: could not read ${src}: ${(e as Error).message}\n`);
    return 1;
  }
  const { pubkeys, errors } = parseSshPubkeyList(blob);
  for (const e of errors) io.err(`warning: ignoring malformed key on line ${e.lineNumber}: ${e.error}\n`);
  if (pubkeys.length === 0) {
    io.err("error: no valid SSH public key given\n");
    return 2;
  }

  const db = openDb(io);
  try {
    db.exec("BEGIN IMMEDIATE");
    try {
      for (const pk of pubkeys) {
        const existing = findUserBySshFingerprint(db, pk.fingerprint);
        if (existing) {
          if (existing.role === role) {
            io.out(`unchanged ${existing.short_name} ${pk.fingerprint} role=${role}\n`);
          } else {
            db.prepare(`UPDATE users SET role = ? WHERE id = ?`).run(role, existing.id);
            io.out(`set-role ${existing.short_name} ${pk.fingerprint} ${existing.role} -> ${role}\n`);
          }
          continue;
        }
        const short_name = suggestUniqueShortName(db, contentAddressedShortName(pk));
        insertUser(db, {
          short_name,
          ssh_pubkey: sshPubkeyBody(pk),
          ssh_fp: pk.fingerprint,
          role,
          source: "manual",
        });
        io.out(`added ${short_name} ${pk.fingerprint} role=${role}\n`);
      }
      db.exec("COMMIT");
    } catch (e) {
      db.exec("ROLLBACK");
      throw e;
    }
  } finally {
    db.close();
  }
  return 0;
}

function list(io: BreakGlassIo): number {
  // Writable on purpose: a missing users.db is created (empty, with schema)
  // rather than erroring, and the entry point re-pins its ownership.
  const db = openDb(io);
  try {
    for (const u of listUsers(db)) {
      io.out(`${u.id}\t${u.role}\t${u.source}\t${u.ssh_fp}\t${u.short_name}\n`);
    }
  } finally {
    db.close();
  }
  return 0;
}

export function runBreakGlass(argv: string[], io: BreakGlassIo): number {
  if (io.uid !== 0) {
    io.err("error: stamp-break-glass must run as root inside the server container\n");
    return 1;
  }
  const [cmd, ...rest] = argv;
  if (cmd === "add") return add(rest, io);
  if (cmd === "list" && rest.length === 0) return list(io);
  io.err(
    cmd === "list"
      ? `error: list takes no arguments\n${USAGE}`
      : `error: unknown command '${cmd ?? ""}'\n${USAGE}`,
  );
  return 2;
}
