/**
 * `stamp invite <short_name> [--role admin|member]`
 *
 * Asks the configured stamp server to mint a single-use invite token for
 * a teammate. The token + share URL is printed for the operator to relay
 * via whatever channel they trust (Slack DM, Signal, magic-wormhole,
 * iMessage, etc.). 15-minute TTL on the server side.
 *
 * Authentication is reused from the operator's existing SSH key — same
 * key that authorizes `stamp push` / `new-stamp-repo`. The server-side
 * wrapper (stamp-mint-invite) checks that key's role in the membership
 * DB and refuses to mint unless the caller is an admin or owner.
 *
 * No `--server` flag here on purpose: server config lives in
 * ~/.stamp/server.yml (same source `stamp provision` reads). An operator
 * who manages multiple stamp servers can switch via `stamp server config`
 * before running this.
 */

import { spawnSync } from "node:child_process";
import { loadServerConfig } from "../lib/serverConfig.js";
import { UsageError } from "./serverRepo.js";

export type InviteRole = "admin" | "member";

export interface InviteCliOptions {
  shortName: string;
  role: InviteRole;
}

export function runInvite(opts: InviteCliOptions): void {
  const server = loadServerConfig();
  if (!server) {
    throw new UsageError(
      "no ~/.stamp/server.yml — run `stamp server config <host>:<port>` first " +
        "(or `stamp provision` to set up a new server)",
    );
  }

  // ssh -p <port> -- git@host stamp-mint-invite <name> --role <role>
  // The `--` before the destination terminates ssh's option processing —
  // belt-and-suspenders against any future code path that lets a
  // `-`-leading host slip past validateField in serverConfig.ts.
  const result = spawnSync(
    "ssh",
    [
      "-p",
      String(server.port),
      "--",
      `${server.user}@${server.host}`,
      "stamp-mint-invite",
      opts.shortName,
      "--role",
      opts.role,
    ],
    {
      // Capture stdout (the share URL) so we can re-emit it cleanly; let
      // stderr flow through to the operator's terminal verbatim — the
      // server-side wrapper writes the human-readable diagnostic there.
      stdio: ["ignore", "pipe", "inherit"],
      encoding: "utf8",
    },
  );

  if (result.status !== 0) {
    throw new Error(
      `stamp invite ${opts.shortName} failed (exit ${result.status}) against ` +
        `${server.user}@${server.host}:${server.port}. Common causes: server ` +
        `unreachable, your SSH key isn't in the membership DB, you're not an ` +
        `admin/owner, the short_name is already taken, or the server image ` +
        `predates phase 2 of multi-user onboarding — redeploy if so.`,
    );
  }

  const shareUrl = result.stdout.trim();
  if (!shareUrl.startsWith("stamp+invite://")) {
    throw new Error(
      `stamp invite: unexpected server output (no stamp+invite:// URL on stdout). ` +
        `Got: ${JSON.stringify(shareUrl.slice(0, 120))}`,
    );
  }

  // Print the URL on its own line for easy copy-paste. The server-side
  // diagnostic already landed on the operator's terminal via stderr
  // passthrough above; no need to re-format it here.
  process.stdout.write(shareUrl + "\n");
}
