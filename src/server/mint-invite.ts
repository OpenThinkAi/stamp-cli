/**
 * SSH-invoked invite mint command, reachable as:
 *
 *   ssh -p <port> git@<host> stamp-mint-invite <short_name> [--role admin|member]
 *
 * Symlinked into /home/git/git-shell-commands/ on the server image so
 * git-shell will dispatch to it. Authenticates the caller by reading the
 * SSH_USER_AUTH file sshd wrote during connection setup (requires
 * ExposeAuthInfo yes in sshd_config) and looking up their fingerprint in
 * the membership DB. Refuses to mint if:
 *
 *   - SSH_USER_AUTH is unset or has no publickey entry (no identity)
 *   - the caller isn't an admin or owner (role check)
 *   - <short_name> is malformed or already taken in the users table
 *   - STAMP_PUBLIC_URL env var is unset (we'd have no way to print a
 *     shareable URL for the invitee to use)
 *
 * On success, prints a single line on stdout:
 *
 *   stamp+invite://<public-host>/<token>
 *
 * The CLI side (`stamp invites mint`) captures that stdout and prints
 * it verbatim along with the server's stderr (which carries the
 * `note:`-prefixed diagnostic prose). Because this stderr crosses the
 * SSH boundary and lands in the operator's terminal as CLI output, it
 * follows the lowercase `error:` / `note:` prefix convention rather
 * than the unix-style program-name prefix used by daemon logs.
 *
 * Exit codes (consumed by the CLI to produce specific operator prose):
 *
 *   0 — success; share URL on stdout
 *   1 — server-side config error (STAMP_PUBLIC_URL unset, ExposeAuthInfo
 *       missing, etc.)
 *   2 — usage error (missing/bad argv)
 *   3 — caller's role doesn't permit minting (not admin/owner)
 *   4 — short_name already taken in users table
 *   5 — rate limited: caller is over the per-hour invite cap (AGT-420)
 */

import { mintInvite } from "../lib/invites.js";
import {
  checkAndConsumeToken,
  findUserByShortName,
  findUserBySshFingerprint,
  openServerDb,
  resolveInviteRateCap,
  type InviteRole,
} from "../lib/serverDb.js";
import { readAuthenticatedPubkey } from "../lib/sshUserAuth.js";

const SHORT_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;

interface ParsedArgs {
  short_name: string;
  role: InviteRole;
}

function fail(message: string, exitCode: number): never {
  // Lowercase prose prefix matches the CLI convention: this stderr
  // crosses the SSH boundary and lands in the operator's terminal.
  console.error(`error: ${message}`);
  process.exit(exitCode);
}

function parseArgs(argv: string[]): ParsedArgs {
  if (argv.length < 1) {
    fail("usage: stamp-mint-invite <short_name> [--role admin|member]", 2);
  }
  let short_name = "";
  let role: InviteRole = "member";
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "--role") {
      const next = argv[i + 1];
      if (next !== "admin" && next !== "member") {
        fail(`--role expects 'admin' or 'member' (got ${JSON.stringify(next)})`, 2);
      }
      role = next;
      i++;
    } else if (arg.startsWith("--")) {
      fail(`unknown flag: ${arg}`, 2);
    } else if (!short_name) {
      short_name = arg;
    } else {
      fail(`unexpected positional argument: ${arg}`, 2);
    }
  }
  if (!short_name) {
    fail("missing required <short_name> argument", 2);
  }
  if (!SHORT_NAME_RE.test(short_name)) {
    fail(
      `<short_name> ${JSON.stringify(short_name)} has an invalid shape (allowed: ` +
        `alphanumerics + . _ -, must start with alnum, max 63 chars)`,
      2,
    );
  }
  return { short_name, role };
}

function publicHostFromUrl(url: string): { host: string; isHttp: boolean } {
  // STAMP_PUBLIC_URL examples:
  //   https://stamp.example.com           (port implicit at 443)
  //   https://stamp.example.com:8443
  //   http://localhost:8080               (dev / self-hosted-on-LAN)
  // The invite URL omits scheme AND carries no transport marker (AGT-416):
  // the receiving CLI defaults to HTTPS and an invitee must opt into plain
  // HTTP explicitly. `isHttp` is used ONLY to append a dev-ergonomics hint
  // to the stderr note — it never changes the emitted URL.
  try {
    const u = new URL(url);
    const host = u.host;
    if (!host) throw new Error("URL has no host");
    return { host, isHttp: u.protocol === "http:" };
  } catch (e) {
    fail(`STAMP_PUBLIC_URL is malformed: ${(e as Error).message}`, 1);
  }
}

function main(): void {
  const publicUrl = process.env["STAMP_PUBLIC_URL"];
  if (!publicUrl) {
    fail(
      "STAMP_PUBLIC_URL is not set on the server — operator must configure " +
        "the externally-reachable HTTP URL before minting invites",
      1,
    );
  }
  const publicEndpoint = publicHostFromUrl(publicUrl);

  const args = parseArgs(process.argv.slice(2));

  const caller = readAuthenticatedPubkey();
  if (!caller) {
    fail(
      "could not determine authenticated identity (SSH_USER_AUTH unset or " +
        "has no publickey entry). Server may be missing 'ExposeAuthInfo yes' " +
        "in sshd_config.",
      1,
    );
  }

  // skipChmod: this wrapper runs as the git user via git-shell, but the
  // DB file is root-owned (chmod fails with EPERM unless caller is owner).
  // entrypoint.sh already tightened perms at boot; the in-process chmod
  // would be redundant even if it could succeed.
  const db = openServerDb({ skipChmod: true });
  try {
    const callerRow = findUserBySshFingerprint(db, caller.fingerprint);
    if (!callerRow) {
      fail(
        `caller fingerprint ${caller.fingerprint} is not in the membership ` +
          `DB — this should be impossible after sshd authenticated them. ` +
          `Likely cause: phase-1 env-var sync hasn't run on this server yet.`,
        1,
      );
    }
    if (callerRow.role !== "owner" && callerRow.role !== "admin") {
      fail(
        `role ${callerRow.role} is not permitted to mint invites (need owner or admin)`,
        3,
      );
    }
    // Strict authority matrix: admins may invite members only. Inviting
    // an admin is "creating a peer with equal authority" — that's
    // owner-only by design, so a compromised admin's blast radius
    // stays member-level. Owners can mint any invite role.
    if (callerRow.role === "admin" && args.role === "admin") {
      fail(
        "admins may only mint --role member invites; only owners may mint admin invites",
        3,
      );
    }

    const existing = findUserByShortName(db, args.short_name);
    if (existing) {
      fail(
        `short_name ${JSON.stringify(args.short_name)} is already in use (id=${existing.id} role=${existing.role}). ` +
          `Pick a different name or remove the existing user first.`,
        4,
      );
    }

    // AGT-420: per-admin invite rate limit — bounds a compromised admin
    // key's ability to flood invites. Same token-bucket as stamp-review;
    // exit 5 = back off.
    if (!checkAndConsumeToken(db, callerRow.id, "mint_invite", resolveInviteRateCap())) {
      fail(
        `rate limit exceeded: ${callerRow.short_name} is over the per-hour invite cap ` +
          `(${resolveInviteRateCap()}/hour). Back off and retry later; an operator can raise ` +
          `MAX_INVITES_PER_HOUR on the server if this is legitimate.`,
        5,
      );
    }

    const minted = mintInvite(db, {
      role: args.role,
      invited_by: callerRow.id,
    });

    // AGT-416: bare URL, no transport marker. Transport is the invitee's
    // client-side decision (defaults to HTTPS).
    const shareUrl = `stamp+invite://${publicEndpoint.host}/${minted.token}`;
    // stdout = the URL only — that's the machine-readable contract the
    // calling CLI captures and prints to the operator.
    process.stdout.write(shareUrl + "\n");
    // stderr = human-readable diagnostic, surfaced inline by the CLI.
    const expiresInMin = Math.round((minted.expires_at - Math.floor(Date.now() / 1000)) / 60);
    process.stderr.write(
      `note: minted invite for short_name=${args.short_name} role=${args.role} ` +
        `(expires in ~${expiresInMin}m, invited_by=${callerRow.short_name})\n`,
    );
    // On a plain-HTTP (dev/LAN) server the invitee must opt into plaintext
    // transport explicitly — surface the exact command so they don't hit a
    // cryptic HTTPS-connection failure against an http-only endpoint.
    const acceptHint = publicEndpoint.isHttp
      ? ` --insecure-http-for-dev --accept-insecure`
      : "";
    process.stderr.write(
      `note: invitee runs:  stamp invites accept "${shareUrl}"${acceptHint}\n`,
    );
  } finally {
    db.close();
  }
}

main();
