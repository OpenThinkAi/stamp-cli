/**
 * `stamp accept-invite <share-url-or-token>`
 *
 * Redeems a single-use invite token against the stamp server. Interactive
 * by default — auto-detects ~/.ssh/id_ed25519.pub and ~/.stamp/keys/ed25519.pub,
 * confirms each with the operator, prompts for a short_name, then POSTs to
 * the server's HTTP endpoint.
 *
 * The share URL has the form:
 *
 *   stamp+invite://<host>[:<port>]/<token>[?insecure=1]
 *
 * The `?insecure=1` query param flips the POST from https → http; the
 * server-side mint command emits it only when STAMP_PUBLIC_URL is
 * http:// (dev/self-hosted-on-LAN). Plain `<token>` is accepted too,
 * but then the operator must pass `--server <host>:<port>` to say where
 * to POST.
 *
 * Non-interactive shape (for CI / scripted use):
 *
 *   stamp accept-invite <url> --ssh-pubkey <path> --short-name <name> [--stamp-pubkey <path>]
 *
 * If stdin is not a TTY and any required input is missing, this errors
 * out rather than dropping into prompts.
 */

import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { existsSync, readFileSync } from "node:fs";
import { homedir, hostname, userInfo } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";
import { fingerprintFromPem } from "../lib/keys.js";
import { parseSshPubkey } from "../lib/sshKeys.js";
import { UsageError } from "./serverRepo.js";

export interface AcceptInviteCliOptions {
  /** The first positional arg — either a stamp+invite:// URL or a bare token. */
  urlOrToken: string;
  /** With a bare token, supply the server host:port. */
  server?: string;
  /** Override the SSH pubkey path (default ~/.ssh/id_ed25519.pub). */
  sshPubkeyPath?: string;
  /** Override the stamp signing pubkey path (default ~/.stamp/keys/ed25519.pub). */
  stampPubkeyPath?: string;
  /** Override the short_name. Default derived from OS username + hostname. */
  shortName?: string;
  /** Skip interactive confirmation prompts. Required when stdin is non-TTY. */
  yes?: boolean;
}

interface ParsedTarget {
  host: string;
  token: string;
  insecure: boolean;
}

const TOKEN_RE = /^[A-Za-z0-9_-]{20,128}$/;

export function parseShareUrl(input: string, serverFlag?: string): ParsedTarget {
  const trimmed = input.trim();
  if (trimmed.startsWith("stamp+invite://")) {
    const remainder = trimmed.slice("stamp+invite://".length);
    // Split off the path (token) from the host.
    const firstSlash = remainder.indexOf("/");
    if (firstSlash < 0) {
      throw new UsageError(
        `share URL has no token: ${JSON.stringify(input)}`,
      );
    }
    const host = remainder.slice(0, firstSlash);
    let tokenPart = remainder.slice(firstSlash + 1);
    let insecure = false;
    const queryIdx = tokenPart.indexOf("?");
    if (queryIdx >= 0) {
      // Only one supported query param today: insecure=1
      const query = tokenPart.slice(queryIdx + 1);
      tokenPart = tokenPart.slice(0, queryIdx);
      if (query === "insecure=1") insecure = true;
    }
    if (!TOKEN_RE.test(tokenPart)) {
      throw new UsageError(
        `share URL has a malformed token: ${JSON.stringify(tokenPart)}`,
      );
    }
    if (host.length === 0) {
      throw new UsageError(`share URL has no host: ${JSON.stringify(input)}`);
    }
    return { host, token: tokenPart, insecure };
  }

  // Bare token; needs --server.
  if (!TOKEN_RE.test(trimmed)) {
    throw new UsageError(
      `expected a stamp+invite:// URL or a bare token (got ${JSON.stringify(input)})`,
    );
  }
  if (!serverFlag) {
    throw new UsageError(
      "bare token requires --server <host>:<port> so we know where to POST",
    );
  }
  return { host: serverFlag, token: trimmed, insecure: false };
}

function defaultSshPubkeyPath(): string {
  return join(homedir(), ".ssh", "id_ed25519.pub");
}

function defaultStampPubkeyPath(): string {
  return join(homedir(), ".stamp", "keys", "ed25519.pub");
}

function defaultShortName(): string {
  // Best-effort: <username>-<hostname-first-segment>. Operator can
  // override at the prompt.
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
  target: ParsedTarget,
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

export async function runAcceptInvite(opts: AcceptInviteCliOptions): Promise<void> {
  const target = parseShareUrl(opts.urlOrToken, opts.server);

  const sshPath = opts.sshPubkeyPath ?? defaultSshPubkeyPath();
  const ssh = loadSshPubkey(sshPath);

  const stampPath = opts.stampPubkeyPath ?? defaultStampPubkeyPath();
  // For phase 2 the stamp pubkey is optional — it's only consumed during
  // phase-4 trust grants. Auto-detect if present, let it ride if not.
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
            : `  stamp pubkey:   (none detected at ${stampPath} — okay; phase 4 needs it)\n`) +
          `  short_name:     ${shortName}\n` +
          `\n`,
      );
      const answer = (await rl.question("Send these to the server? [Y/n] ")).trim().toLowerCase();
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

  const body = response.body as { ok?: boolean; error?: string; role?: string; user_id?: number };
  if (response.status === 200 && body.ok) {
    process.stdout.write(
      `note: enrolled as ${body.role} (user_id=${body.user_id}). You can now ` +
        `\`git push\` and \`stamp\` against ${target.host}.\n`,
    );
    return;
  }
  const errorText = body.error ?? `http_${response.status}`;
  throw new Error(
    `accept-invite failed: ${errorText} (status ${response.status})`,
  );
}
