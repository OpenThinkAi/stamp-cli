/**
 * `stamp invites mint` and `stamp invites accept` — the two halves of the
 * teammate-onboarding flow.
 *
 *   stamp invites mint <short-name> [--role admin|member]
 *
 *   Admin/owner asks the configured stamp server to mint a single-use
 *   invite token. Auth reused from the operator's existing SSH key —
 *   same key that authorizes `stamp push`. The server-side wrapper
 *   (stamp-mint-invite) checks the caller's role in the membership DB
 *   and refuses non-admins. Output is a stamp+invite://<host>/<token>
 *   URL the operator relays via any channel they trust (Slack, Signal,
 *   magic-wormhole, etc.). 15-minute TTL.
 *
 *   stamp invites accept <share-url-or-token>
 *
 *   Invitee redeems the token: auto-detects ~/.ssh/id_ed25519.pub and
 *   ~/.stamp/keys/ed25519.pub (the latter optional in phase 2 — phase 4
 *   consumes it), confirms via prompt (--yes for scripted use), POSTs
 *   to POST /invite/accept on the server.
 */

import { spawnSync } from "node:child_process";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { existsSync, readFileSync } from "node:fs";
import { homedir, hostname, userInfo } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";
import {
  parseShareUrl,
  ShareUrlError,
  type ParsedShareTarget,
} from "../lib/inviteUrl.js";
import { fingerprintFromPem } from "../lib/keys.js";
import { loadServerConfig } from "../lib/serverConfig.js";
import { parseSshPubkey } from "../lib/sshKeys.js";
import { UsageError } from "./serverRepo.js";

// ─── stamp invites mint ────────────────────────────────────────────────

export type InviteRole = "admin" | "member";

export interface InvitesMintOptions {
  shortName: string;
  role: InviteRole;
}

/**
 * Exit-code contract between server-side stamp-mint-invite and this CLI.
 * Must stay in sync with the codes in src/server/mint-invite.ts:
 *
 *   1 — config / identity / public-URL setup error (server-side)
 *   2 — usage error (missing arg, bad --role, malformed short_name)
 *   3 — caller's role is not permitted to mint invites
 *   4 — short_name collides with an existing user
 *
 * Any other non-zero exit is treated as "unknown failure" and falls
 * through to a generic hint.
 */
const MINT_EXIT = {
  CONFIG: 1,
  USAGE: 2,
  ROLE_FORBIDDEN: 3,
  NAME_TAKEN: 4,
} as const;

export function runInvitesMint(opts: InvitesMintOptions): void {
  const server = loadServerConfig();
  if (!server) {
    throw new UsageError(
      "no ~/.stamp/server.yml — run `stamp server config <host>:<port>` first " +
        "(or `stamp provision` to set up a new server)",
    );
  }

  // `--` before the destination terminates ssh's option processing —
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
      // Capture stdout (the share URL) for clean re-emit; let stderr
      // flow through to the operator's terminal verbatim — the
      // server-side wrapper writes its prose there.
      stdio: ["ignore", "pipe", "inherit"],
      encoding: "utf8",
    },
  );

  if (result.status === 0) {
    const shareUrl = result.stdout.trim();
    if (!shareUrl.startsWith("stamp+invite://")) {
      throw new Error(
        `unexpected server output (no stamp+invite:// URL on stdout). ` +
          `Got: ${JSON.stringify(shareUrl.slice(0, 120))}`,
      );
    }
    process.stdout.write(shareUrl + "\n");
    return;
  }

  // Branch on the server's exit code so the operator gets actionable
  // prose tied to the specific failure mode rather than a kitchen-sink
  // list of possible causes.
  switch (result.status) {
    case MINT_EXIT.ROLE_FORBIDDEN:
      throw new UsageError(
        `your account on ${server.host} doesn't permit minting invites ` +
          "(role must be admin or owner). Ask an admin to mint the invite " +
          "for you, or to promote your account.",
      );
    case MINT_EXIT.NAME_TAKEN:
      throw new UsageError(
        `short_name ${JSON.stringify(opts.shortName)} is already in use on ` +
          `${server.host}. Pick a different name.`,
      );
    case MINT_EXIT.USAGE:
      throw new UsageError(
        `server rejected the mint request (usage error). Verify the ` +
          `short_name is alphanumerics + . _ - (max 63 chars) and --role is ` +
          `'admin' or 'member'.`,
      );
    case MINT_EXIT.CONFIG:
      throw new Error(
        `server-side configuration error against ${server.host}. The ` +
          `server may be missing STAMP_PUBLIC_URL or 'ExposeAuthInfo yes' in ` +
          `sshd_config. See server-side log for specifics.`,
      );
    default:
      throw new Error(
        `mint failed against ${server.user}@${server.host}:${server.port} ` +
          `(exit ${result.status}). Common causes: server unreachable, your ` +
          `SSH key isn't enrolled, or the server image is older than the ` +
          `invite-mint feature — redeploy if so.`,
      );
  }
}

// ─── stamp invites accept ─────────────────────────────────────────────

export interface InvitesAcceptOptions {
  urlOrToken: string;
  server?: string;
  sshPubkeyPath?: string;
  stampPubkeyPath?: string;
  shortName?: string;
  yes?: boolean;
}

function defaultSshPubkeyPath(): string {
  return join(homedir(), ".ssh", "id_ed25519.pub");
}

function defaultStampPubkeyPath(): string {
  return join(homedir(), ".stamp", "keys", "ed25519.pub");
}

function defaultShortName(): string {
  const u = userInfo().username || "user";
  const h = hostname().split(".")[0] || "host";
  return `${u}-${h}`
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63);
}

interface DetectedSsh {
  path: string;
  full: string;
  fingerprint: string;
}

function loadSshPubkey(path: string): DetectedSsh {
  if (!existsSync(path)) {
    throw new UsageError(
      `SSH pubkey not found at ${path}. Generate one with ` +
        `\`ssh-keygen -t ed25519\` or pass --ssh-pubkey <path>.`,
    );
  }
  const raw = readFileSync(path, "utf8");
  const parsed = parseSshPubkey(raw);
  return { path, full: parsed.full, fingerprint: parsed.fingerprint };
}

interface DetectedStamp {
  path: string;
  pem: string;
  fingerprint: string;
}

function loadStampPubkey(path: string): DetectedStamp | null {
  if (!existsSync(path)) return null;
  const pem = readFileSync(path, "utf8");
  try {
    const fp = fingerprintFromPem(pem);
    return { path, pem, fingerprint: fp };
  } catch (e) {
    throw new UsageError(
      `stamp signing pubkey at ${path} is malformed: ${(e as Error).message}`,
    );
  }
}

async function postAccept(
  target: ParsedShareTarget,
  body: {
    token: string;
    ssh_pubkey: string;
    stamp_pubkey: string | null;
    short_name: string;
  },
): Promise<{ status: number; body: unknown }> {
  const payload = Buffer.from(JSON.stringify(body), "utf8");
  const requestFn = target.insecure ? httpRequest : httpsRequest;
  return new Promise((resolve, reject) => {
    const req = requestFn(
      `${target.insecure ? "http" : "https"}://${target.host}/invite/accept`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Content-Length": payload.length.toString(),
          Accept: "application/json",
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let parsed: unknown;
          try {
            parsed = JSON.parse(text);
          } catch {
            parsed = { raw: text };
          }
          resolve({ status: res.statusCode ?? 0, body: parsed });
        });
      },
    );
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

/**
 * Map server-side error codes to actionable next-step prose. Keeps the
 * agent-facing failure surface useful — agents react differently to a
 * collision than to an expired token.
 */
function nextStepForError(error: string, opts: InvitesAcceptOptions): string {
  switch (error) {
    case "invite_not_found":
      return "the token doesn't match any pending invite. Ask the inviter to mint a fresh one.";
    case "invite_expired":
      return "the invite expired (15-minute TTL). Ask the inviter to mint a fresh one.";
    case "invite_already_consumed":
      return "the invite has already been redeemed. Ask the inviter to mint a fresh one.";
    case "ssh_pubkey_already_registered":
      return (
        "your SSH public key is already enrolled on this server. Try `git push` / " +
        "`stamp` directly — you may already have access. If not, ask an admin to " +
        "look up the existing account."
      );
    case "short_name_taken":
      return `pass --short-name <other-name> (current attempt: ${JSON.stringify(opts.shortName ?? defaultShortName())}).`;
    case "short_name_malformed":
      return "pass --short-name with alphanumerics + . _ - (must start with alnum, max 63 chars).";
    case "ssh_pubkey_required":
    case "token_required":
      return "this is a client bug — file an issue at https://github.com/OpenThinkAi/stamp-cli/issues with the command you ran.";
    case "content_type_must_be_application_json":
    case "body_too_large":
    case "body_not_json":
    case "body_read_failed":
      return "this is a client bug — file an issue at https://github.com/OpenThinkAi/stamp-cli/issues with the command you ran.";
    default:
      if (error.startsWith("ssh_pubkey_invalid")) {
        return "the SSH pubkey is malformed. Verify ~/.ssh/id_ed25519.pub or pass --ssh-pubkey <path>.";
      }
      return "see the server error code above for context.";
  }
}

export async function runInvitesAccept(opts: InvitesAcceptOptions): Promise<void> {
  let target: ParsedShareTarget;
  try {
    target = parseShareUrl(opts.urlOrToken, opts.server);
  } catch (e) {
    if (e instanceof ShareUrlError) throw new UsageError(e.message);
    throw e;
  }

  const sshPath = opts.sshPubkeyPath ?? defaultSshPubkeyPath();
  const ssh = loadSshPubkey(sshPath);

  const stampPath = opts.stampPubkeyPath ?? defaultStampPubkeyPath();
  // Stamp pubkey is optional at accept time; phase 4's trust grants
  // consume it when present. If missing now, the operator can re-enroll
  // it later via the same path.
  const stamp = loadStampPubkey(stampPath);

  const shortName = opts.shortName ?? defaultShortName();

  const isInteractive = process.stdin.isTTY === true;
  let confirmed = opts.yes === true;

  if (!confirmed) {
    if (!isInteractive) {
      throw new UsageError(
        "non-interactive stdin: pass --yes to skip confirmation (after " +
          "supplying any overrides via --ssh-pubkey / --stamp-pubkey / " +
          "--short-name)",
      );
    }

    const rl = createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    try {
      process.stdout.write(
        `Accepting invite at ${target.insecure ? "http" : "https"}://${target.host}\n` +
          `\n` +
          `  ssh pubkey:     ${ssh.path}\n` +
          `                  ${ssh.fingerprint}\n` +
          (stamp
            ? `  stamp pubkey:   ${stamp.path}\n` +
              `                  ${stamp.fingerprint}\n`
            : `  stamp pubkey:   (none detected at ${stampPath} — okay; trust grants need it later)\n`) +
          `  short_name:     ${shortName}\n` +
          `\n`,
      );
      const answer = (await rl.question("Send these to the server? [Y/n] "))
        .trim()
        .toLowerCase();
      if (answer === "" || answer === "y" || answer === "yes") {
        confirmed = true;
      } else {
        process.stdout.write("aborted.\n");
        return;
      }
    } finally {
      rl.close();
    }
  }

  const response = await postAccept(target, {
    token: target.token,
    ssh_pubkey: ssh.full,
    stamp_pubkey: stamp?.pem ?? null,
    short_name: shortName,
  });

  const body = response.body as {
    ok?: boolean;
    error?: string;
    role?: string;
    user_id?: number;
  };
  if (response.status === 200 && body.ok) {
    // ✓ for a primary success outcome — `note:` would read like a
    // footnote on the headline of the whole command.
    process.stdout.write(
      `✓ enrolled as ${body.role} (user_id=${body.user_id}). You can now ` +
        `\`git push\` and \`stamp\` against ${target.host}.\n`,
    );
    return;
  }
  const errorText = body.error ?? `http_${response.status}`;
  const nextStep = nextStepForError(errorText, opts);
  throw new Error(
    `accept-invite failed: ${errorText} (status ${response.status}). ${nextStep}`,
  );
}
