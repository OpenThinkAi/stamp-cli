/**
 * Stamp server HTTP listener — runs alongside sshd, exposes the invite-
 * accept endpoint so a new operator can redeem a token without first
 * having SSH access.
 *
 * Started by entrypoint.sh as the `git` user (which owns write access to
 * the membership sqlite via the root:git 0660 mode bits). Plain HTTP on
 * STAMP_HTTP_PORT (default 8080); TLS is the hosting platform's job
 * (Railway terminates TLS at its edge proxy; self-hosters terminate at
 * their own reverse proxy).
 *
 * Endpoints:
 *
 *   POST /invite/accept
 *     body: {token, ssh_pubkey, short_name, stamp_pubkey?}
 *     200: {ok:true, user_id, role, short_name}
 *     4xx: {ok:false, error:"<reason>"}
 *
 *   GET /healthz
 *     200: {ok:true} — for orchestrator probes
 *
 * Hard cap on request body at 16 KiB. Sshd-style fail-open does NOT apply
 * here: this surface is the only path that mutates the users table from a
 * non-root context, so we surface real status codes and refuse the request
 * on any malformed input.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { consumeInviteToken, markInviteConsumer } from "../lib/invites.js";
import { insertUser, openServerDb } from "../lib/serverDb.js";
import { parseSshPubkey } from "../lib/sshKeys.js";

const DEFAULT_PORT = 8080;
const MAX_BODY_BYTES = 16 * 1024;
const SHORT_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
// Stamp signing pubkeys are PEM-wrapped SPKI. Loose shape check here
// (anchored so trailing/leading garbage doesn't slip in); the real
// validation happens at trust-grant time when the key is consumed.
const STAMP_PUBKEY_PEM_RE =
  /^\s*-----BEGIN PUBLIC KEY-----[A-Za-z0-9+/=\s]+-----END PUBLIC KEY-----\s*$/;

interface AcceptBody {
  token?: unknown;
  ssh_pubkey?: unknown;
  stamp_pubkey?: unknown;
  short_name?: unknown;
}

function logLine(level: "info" | "warn" | "error", msg: string): void {
  const ts = new Date().toISOString();
  const stream = level === "error" ? process.stderr : process.stdout;
  stream.write(`stamp-http-server ${ts} ${level} ${msg}\n`);
}

function sendJson(
  res: ServerResponse,
  status: number,
  body: Record<string, unknown>,
): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload).toString(),
    // Hint to any future reverse proxy that responses here aren't cacheable
    // (they reflect single-use token state).
    "Cache-Control": "no-store",
  });
  res.end(payload);
}

interface ReadBodyResult {
  buf: Buffer;
  tooLarge: boolean;
}

async function readBody(req: IncomingMessage): Promise<ReadBodyResult> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let tooLarge = false;
    req.on("data", (chunk: Buffer) => {
      if (tooLarge) return;
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        // Stop accumulating; the caller produces a 413 keyed on
        // `tooLarge` so the status-code contract is preserved. We don't
        // destroy the connection here — the response body still needs
        // to land.
        tooLarge = true;
        chunks.length = 0;
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve({ buf: Buffer.concat(chunks), tooLarge }));
    req.on("error", reject);
  });
}

interface ValidatedAccept {
  token: string;
  ssh_pubkey: string;
  ssh_fp: string;
  short_name: string;
  stamp_pubkey: string | null;
}

function validateAcceptBody(body: AcceptBody):
  | { ok: true; data: ValidatedAccept }
  | { ok: false; status: number; error: string } {
  if (typeof body.token !== "string" || body.token.length === 0) {
    return { ok: false, status: 400, error: "token_required" };
  }
  // Bound the token length to defeat anyone passing a 16KB-shaped token
  // as a side-channel timing probe. Real tokens are 43 chars (32 bytes
  // base64url no padding).
  if (body.token.length > 128) {
    return { ok: false, status: 400, error: "token_malformed" };
  }
  if (typeof body.ssh_pubkey !== "string" || body.ssh_pubkey.length === 0) {
    return { ok: false, status: 400, error: "ssh_pubkey_required" };
  }
  if (typeof body.short_name !== "string" || !SHORT_NAME_RE.test(body.short_name)) {
    return { ok: false, status: 400, error: "short_name_malformed" };
  }
  let parsed;
  try {
    parsed = parseSshPubkey(body.ssh_pubkey);
  } catch (e) {
    return {
      ok: false,
      status: 400,
      error: `ssh_pubkey_invalid: ${(e as Error).message}`,
    };
  }

  let stamp_pubkey: string | null = null;
  if (body.stamp_pubkey !== undefined && body.stamp_pubkey !== null) {
    if (typeof body.stamp_pubkey !== "string") {
      return { ok: false, status: 400, error: "stamp_pubkey_malformed" };
    }
    if (!STAMP_PUBKEY_PEM_RE.test(body.stamp_pubkey)) {
      return { ok: false, status: 400, error: "stamp_pubkey_not_pem" };
    }
    stamp_pubkey = body.stamp_pubkey;
  }

  return {
    ok: true,
    data: {
      token: body.token,
      ssh_pubkey: parsed.full,
      ssh_fp: parsed.fingerprint,
      short_name: body.short_name,
      stamp_pubkey,
    },
  };
}

interface AcceptOutcome {
  status: number;
  body: Record<string, unknown>;
}

function acceptInvite(data: ValidatedAccept): AcceptOutcome {
  const db = openServerDb();
  try {
    const consumed = consumeInviteToken(db, data.token);
    if (!consumed.ok) {
      const statusByReason: Record<typeof consumed.reason, number> = {
        not_found: 404,
        expired: 410,
        already_consumed: 410,
      };
      return {
        status: statusByReason[consumed.reason],
        body: { ok: false, error: `invite_${consumed.reason}` },
      };
    }

    // The consume above committed its own transaction; a failure on the
    // user insert below leaves the token consumed but no user row
    // created. We treat that as "operator must mint a new invite"
    // rather than rolling back — preserves the single-use property
    // against retry storms. UNIQUE-constraint collisions on
    // short_name / ssh_fp are operator/input errors (the invitee picked
    // a name already taken, or is trying to enroll a key already in the
    // table); other failures are propagated as internal_error upstream.
    let user_id: number;
    try {
      user_id = insertUser(db, {
        short_name: data.short_name,
        ssh_pubkey: data.ssh_pubkey,
        ssh_fp: data.ssh_fp,
        stamp_pubkey: data.stamp_pubkey,
        role: consumed.row.role,
        source: "invite",
        invited_by: consumed.row.invited_by,
      });
    } catch (e) {
      const msg = (e as Error).message;
      if (msg.includes("users.ssh_fp")) {
        return {
          status: 409,
          body: { ok: false, error: "ssh_pubkey_already_registered" },
        };
      }
      if (msg.includes("users.short_name")) {
        return {
          status: 409,
          body: { ok: false, error: "short_name_taken" },
        };
      }
      throw e;
    }

    markInviteConsumer(db, data.token, user_id);

    return {
      status: 200,
      body: {
        ok: true,
        user_id,
        role: consumed.row.role,
        short_name: data.short_name,
      },
    };
  } finally {
    db.close();
  }
}

async function handlePost(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.headers["content-type"]?.split(";")[0]?.trim() !== "application/json") {
    sendJson(res, 415, { ok: false, error: "content_type_must_be_application_json" });
    return;
  }
  let read: ReadBodyResult;
  try {
    read = await readBody(req);
  } catch (e) {
    logLine("warn", `read body failed: ${(e as Error).message}`);
    sendJson(res, 400, { ok: false, error: "body_read_failed" });
    return;
  }
  if (read.tooLarge) {
    sendJson(res, 413, { ok: false, error: "body_too_large" });
    return;
  }
  let body: AcceptBody;
  try {
    body = JSON.parse(read.buf.toString("utf8")) as AcceptBody;
  } catch {
    sendJson(res, 400, { ok: false, error: "body_not_json" });
    return;
  }
  const v = validateAcceptBody(body);
  if (!v.ok) {
    sendJson(res, v.status, { ok: false, error: v.error });
    return;
  }
  try {
    const outcome = acceptInvite(v.data);
    logLine(
      outcome.status === 200 ? "info" : "warn",
      `invite/accept short_name=${v.data.short_name} status=${outcome.status}`,
    );
    sendJson(res, outcome.status, outcome.body);
  } catch (e) {
    logLine("error", `invite/accept internal error: ${(e as Error).message}`);
    sendJson(res, 500, { ok: false, error: "internal_error" });
  }
}

export const HTTP_DEFAULT_PORT = DEFAULT_PORT;

export function startServer(port = DEFAULT_PORT): ReturnType<typeof createServer> {
  const server = createServer((req, res) => {
    const url = req.url ?? "";
    if (req.method === "GET" && (url === "/healthz" || url === "/")) {
      sendJson(res, 200, { ok: true });
      return;
    }
    if (req.method === "POST" && url === "/invite/accept") {
      void handlePost(req, res);
      return;
    }
    sendJson(res, 404, { ok: false, error: "not_found" });
  });
  server.listen(port, () => {
    logLine("info", `listening on :${port}`);
  });
  return server;
}
