/**
 * `stamp users {list, promote, demote, remove}` — client-side CLI for the
 * server-side user-management surface.
 *
 * Each subcommand SSHes to the configured stamp server and invokes
 * `stamp-users <subcommand> <args>` (one bundled wrapper on the server
 * dispatching via argv). The wrapper's exit codes 0–6 map to specific
 * client-side prose so operators see actionable next steps instead of
 * a generic "exit 3".
 *
 * Authority and last-owner-guard enforcement lives entirely on the
 * server (src/lib/userOps.ts); this file is thin SSH glue + output
 * formatting.
 */

import { spawnSync } from "node:child_process";
import {
  loadServerConfig,
  type ServerConfig,
} from "../lib/serverConfig.js";
import { UsageError } from "./serverRepo.js";

// Wire contract with src/server/users-cli.ts. Kept in sync with that
// file's EXIT constant; both sides reference the same codes so a
// divergence is loud at a stamp-review boundary.
const EXIT = {
  OK: 0,
  CONFIG: 1,
  USAGE: 2,
  AUTHORITY: 3,
  NOT_FOUND: 4,
  LAST_OWNER: 5,
  CANNOT_REMOVE_SELF: 6,
} as const;

interface ListUsersOptions {
  /** When true, dump the raw JSON the server emitted instead of the table. */
  json?: boolean;
}

export interface PromoteUserOptions {
  shortName: string;
  to: "admin" | "owner";
}

export interface DemoteUserOptions {
  shortName: string;
  to: "admin" | "member";
}

export interface RemoveUserOptions {
  shortName: string;
}

function resolveServer(): ServerConfig {
  const server = loadServerConfig();
  if (!server) {
    throw new UsageError(
      "no ~/.stamp/server.yml — run `stamp server config <host>:<port>` first",
    );
  }
  return server;
}

function sshArgs(server: ServerConfig, remoteArgs: string[]): string[] {
  // -- before destination terminates ssh's option processing.
  return [
    "-p",
    String(server.port),
    "--",
    `${server.user}@${server.host}`,
    "stamp-users",
    ...remoteArgs,
  ];
}

interface RemoteResult {
  status: number | null;
  stdout: string;
}

function callRemote(server: ServerConfig, remoteArgs: string[]): RemoteResult {
  const result = spawnSync("ssh", sshArgs(server, remoteArgs), {
    // Stdout is always piped: `list` needs it for JSON parsing; write
    // ops don't emit on stdout so an empty pipe is harmless. Stderr is
    // always inherited so server-side `note:` confirmations and
    // `error:` prose land in the operator's terminal verbatim.
    stdio: ["ignore", "pipe", "inherit"],
    encoding: "utf8",
  });
  return { status: result.status, stdout: result.stdout ?? "" };
}

function explainExit(
  status: number | null,
  context: string,
  details: { shortName?: string; server: ServerConfig },
): Error {
  switch (status) {
    case EXIT.AUTHORITY:
      return new UsageError(
        `${context}: your role on ${details.server.host} doesn't permit this action. ` +
          `Owners may manage any user; admins may manage members only (and may ` +
          `self-promote to owner if no owners exist yet — the bootstrap path). ` +
          `Ask an existing owner to perform this action.`,
      );
    case EXIT.NOT_FOUND:
      return new UsageError(
        `${context}: short_name ${JSON.stringify(details.shortName ?? "?")} ` +
          `isn't in the membership DB on ${details.server.host}. ` +
          `Run \`stamp users list\` to see who's enrolled.`,
      );
    case EXIT.LAST_OWNER:
      return new UsageError(
        `${context}: this would leave the server with zero owners. ` +
          `Promote another user to owner first (\`stamp users promote <name> --to owner\`).`,
      );
    case EXIT.CANNOT_REMOVE_SELF:
      return new UsageError(
        `${context}: you can't remove your own account. Ask another admin ` +
          `or owner to do it — prevents accidentally locking yourself out.`,
      );
    case EXIT.USAGE:
      return new UsageError(
        `${context}: server rejected the request as a usage error. ` +
          `Double-check the short_name (alphanumerics + . _ -, must start with ` +
          `alnum, max 63 chars) and --to value.`,
      );
    case EXIT.CONFIG:
      return new Error(
        `${context}: server-side configuration error on ${details.server.host}. ` +
          `Most likely your account isn't in the membership DB yet, or the ` +
          `server is missing 'ExposeAuthInfo yes' in sshd_config. See ` +
          `server logs for specifics.`,
      );
    default:
      return new Error(
        `${context}: failed against ${details.server.user}@${details.server.host}:${details.server.port} ` +
          `(exit ${status}). Common causes: server unreachable, your SSH key ` +
          `isn't enrolled, or the server image is older than the user-management feature.`,
      );
  }
}

// ─── list ──────────────────────────────────────────────────────────────

interface RemoteUserRow {
  id: number;
  short_name: string;
  role: "owner" | "admin" | "member";
  source: "env" | "bootstrap" | "invite" | "manual";
  ssh_fp: string;
  has_stamp_pubkey: boolean;
  invited_by: number | null;
  created_at: number;
  last_seen_at: number | null;
}

function pad(s: string, width: number): string {
  return s.length >= width ? s : s + " ".repeat(width - s.length);
}

function formatUsersTable(rows: RemoteUserRow[]): string {
  if (rows.length === 0) return "(no users)\n";
  const widths = {
    short_name: Math.max(10, ...rows.map((r) => r.short_name.length)),
    role: Math.max(6, ...rows.map((r) => r.role.length)),
    source: Math.max(6, ...rows.map((r) => r.source.length)),
  };
  const out: string[] = [];
  out.push(
    pad("short_name", widths.short_name) +
      "  " +
      pad("role", widths.role) +
      "  " +
      pad("source", widths.source) +
      "  ssh_fp",
  );
  out.push(
    pad("-".repeat(widths.short_name), widths.short_name) +
      "  " +
      pad("-".repeat(widths.role), widths.role) +
      "  " +
      pad("-".repeat(widths.source), widths.source) +
      "  " +
      "-".repeat(20),
  );
  for (const r of rows) {
    out.push(
      pad(r.short_name, widths.short_name) +
        "  " +
        pad(r.role, widths.role) +
        "  " +
        pad(r.source, widths.source) +
        "  " +
        r.ssh_fp,
    );
  }
  return out.join("\n") + "\n";
}

export function runUsersList(opts: ListUsersOptions): void {
  const server = resolveServer();
  const result = callRemote(server, ["list"]);
  if (result.status !== 0) {
    throw explainExit(result.status, "stamp users list", { server });
  }
  if (opts.json) {
    // --json is the agent escape hatch: deliberately suppress the
    // ownerless warning so machine-parseable output isn't mixed with
    // human prose. Agents that care about ownership status can read
    // it from the parsed JSON directly.
    process.stdout.write(result.stdout);
    return;
  }
  let payload: { users?: RemoteUserRow[] };
  try {
    payload = JSON.parse(result.stdout) as { users?: RemoteUserRow[] };
  } catch (e) {
    throw new Error(
      `server returned non-JSON output: ${(e as Error).message}. ` +
        `Raw: ${JSON.stringify(result.stdout.slice(0, 200))}`,
    );
  }
  const rows = payload.users ?? [];
  const warning = ownerlessWarning(rows);
  if (warning) process.stderr.write(warning);
  process.stdout.write(formatUsersTable(rows));
}

/**
 * Compose the loud reminder to claim ownership when a server has
 * enrolled users but no owner. Returns the warning text (multi-line,
 * `warning:`-prefixed) or null when no warning applies.
 *
 * Without an owner the server can't promote anyone to admin or
 * appoint other owners, and any admin (yours or someone else's) can
 * race to claim ownership via the one-shot bootstrap path. Operators
 * who skip this step silently end up with a degraded server.
 *
 * Returns null on an empty users table — no admin has been imported
 * yet so there's nothing to bootstrap from. Exported for unit tests
 * that pin the wording so a future polish pass doesn't accidentally
 * weaken the message.
 */
export function ownerlessWarning(rows: RemoteUserRow[]): string | null {
  if (rows.length === 0) return null;
  const hasOwner = rows.some((r) => r.role === "owner");
  if (hasOwner) return null;
  return (
    "warning: this stamp server has NO OWNER configured.\n" +
    "warning: an admin can self-promote to owner ONCE, but only while no\n" +
    "warning: owner exists — and any admin (yours or someone else's) can\n" +
    "warning: race to claim it. Until you do, the server can't promote\n" +
    "warning: anyone to admin or appoint other owners.\n" +
    "warning:\n" +
    "warning: claim ownership now from THIS machine before anyone beats you:\n" +
    "warning:   stamp users promote <your-short-name> --to owner\n" +
    "warning:\n"
  );
}

// ─── promote / demote ─────────────────────────────────────────────────

export function runUsersPromote(opts: PromoteUserOptions): void {
  const server = resolveServer();
  const result = callRemote(server, [
    "promote",
    opts.shortName,
    "--to",
    opts.to,
  ]);
  if (result.status !== 0) {
    throw explainExit(result.status, `stamp users promote ${opts.shortName}`, {
      server,
      shortName: opts.shortName,
    });
  }
  // Success prose lands on the operator's terminal via the SSH stderr
  // passthrough from the server-side wrapper. Nothing more to print.
}

export function runUsersDemote(opts: DemoteUserOptions): void {
  const server = resolveServer();
  const result = callRemote(server, [
    "demote",
    opts.shortName,
    "--to",
    opts.to,
  ]);
  if (result.status !== 0) {
    throw explainExit(result.status, `stamp users demote ${opts.shortName}`, {
      server,
      shortName: opts.shortName,
    });
  }
}

// ─── remove ──────────────────────────────────────────────────────────

export function runUsersRemove(opts: RemoveUserOptions): void {
  const server = resolveServer();
  const result = callRemote(server, ["remove", opts.shortName]);
  if (result.status !== 0) {
    throw explainExit(result.status, `stamp users remove ${opts.shortName}`, {
      server,
      shortName: opts.shortName,
    });
  }
}
