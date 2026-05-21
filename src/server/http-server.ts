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
 *   POST /webhook/prompts                                   (AGT-374, Phase B)
 *     headers: X-Hub-Signature-256, X-GitHub-Delivery, X-GitHub-Event
 *     body:    github push-event JSON (we don't introspect it — the HMAC over
 *              the raw bytes is the only thing this endpoint trusts)
 *     202: {ok:true} — refresh scheduled (or coalesced with a recent one)
 *     401: {ok:false, error:"invalid_signature"} — HMAC mismatch
 *     503: {ok:false, error:"webhook_secret_unconfigured"}
 *
 *   GET /healthz
 *     200: {ok:true} — for orchestrator probes
 *
 * Hard cap on request body at 16 KiB for invite-accept, 64 KiB for the
 * prompts webhook (github push deliveries can exceed 16 KiB on busy repos).
 * Sshd-style fail-open does NOT apply here: this surface is the only path
 * that mutates the users table from a non-root context, so we surface real
 * status codes and refuse the request on any malformed input.
 */

import {
  createHmac,
  timingSafeEqual,
  type BinaryLike,
} from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { consumeInviteToken, markInviteConsumer } from "../lib/invites.js";
import { insertUser, openServerDb } from "../lib/serverDb.js";
import { parseSshPubkey } from "../lib/sshKeys.js";
import {
  cloneOrFetchPromptsCache,
  type CloneOrFetchOpts,
  type RefreshResult,
} from "./prompts-cache.js";

const DEFAULT_PORT = 8080;
const MAX_BODY_BYTES = 16 * 1024;
// Github push-event deliveries on large repos (many tags, big release pushes,
// hundreds of commits in one push) routinely run 20-40 KiB. 64 KiB is a
// comfortable headroom that still bounds the worst-case allocation an
// unauthenticated request can force us into BEFORE we've HMAC-validated.
const WEBHOOK_MAX_BODY_BYTES = 64 * 1024;
// 5-second coalescing window — see `scheduleWebhookRefresh` below.
const WEBHOOK_COALESCE_WINDOW_MS = 5_000;
// Default cache location matches the project README + AGT-375's entrypoint
// volume layout. Overridable via STAMP_PROMPTS_CACHE_ROOT.
const DEFAULT_PROMPTS_CACHE_ROOT = "/srv/git/.prompts-cache";
// Default deploy-key location matches AGT-375's entrypoint provisioning.
// Resolved lazily inside `buildRefreshOpts` so a missing key path doesn't
// crash import.
const DEFAULT_DEPLOY_KEY_PATH = "/srv/git/.ssh-client-keys/prompts_repo_key";
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

async function readBody(
  req: IncomingMessage,
  maxBytes: number = MAX_BODY_BYTES,
): Promise<ReadBodyResult> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let tooLarge = false;
    req.on("data", (chunk: Buffer) => {
      if (tooLarge) return;
      total += chunk.length;
      if (total > maxBytes) {
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
  // skipChmod: HTTP server runs as the git user, but the DB file is
  // root-owned (chmod fails with EPERM unless caller is owner).
  // entrypoint.sh handles boot-time perm tightening as root; the
  // in-process chmod would be redundant even if it could succeed.
  const db = openServerDb({ skipChmod: true });
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

// ─── POST /webhook/prompts (AGT-374, Phase B) ─────────────────────────

/**
 * Delivery-ID shape used for log redaction. Github sends a UUID4; we accept
 * any reasonable opaque token and reject obvious garbage (CRLF, null bytes,
 * absurd length) before logging it — the value goes straight into a stdout
 * line where a malicious sender could otherwise inject a fake log entry.
 */
const DELIVERY_ID_RE = /^[A-Za-z0-9._:-]{1,200}$/;

/**
 * Coalescing state for `POST /webhook/prompts`.
 *
 * Github fires a `push` event on every push to the prompts repo, including
 * fast-follow CI / squash-merge / release-tag bursts. We don't need a fetch
 * per delivery — one fetch per ~5 s is plenty and matches the operator's
 * mental model of "the cache is eventually consistent with the prompts repo
 * within seconds of a push."
 *
 *   - `lastKickoffAt`  — monotonic ms (from `Date.now()`) at which the most
 *                       recent refresh was scheduled. A new delivery within
 *                       WINDOW_MS of this timestamp does NOT kick off a
 *                       fresh refresh.
 *   - `pendingTrailingRefresh` — set to true when a delivery arrives inside
 *                       the window. When the active refresh settles, we
 *                       schedule one more refresh to capture the trailing
 *                       edge of the burst — otherwise the very last push of
 *                       a 5-deliveries-in-1s burst could be lost between the
 *                       fetch we already started and the throttle window.
 *   - `inflight`       — the promise of the currently-running refresh, if
 *                       any. Settling this promise drains the pending
 *                       trailing flag.
 *
 * NOTE: AGT-372's `prompts-cache` module already coalesces concurrent calls
 * inside a single process via its own `inflightRefreshes` map. This route-
 * level throttle layers on TOP of that to avoid even ENTERING the cache
 * module on every delivery — saves the lock-file acquire/release + the git
 * fetch even when it would have been a no-op.
 */
interface WebhookCoalesceState {
  lastKickoffAt: number;
  pendingTrailingRefresh: boolean;
  inflight: Promise<RefreshResult> | null;
}

const webhookState: WebhookCoalesceState = {
  lastKickoffAt: 0,
  pendingTrailingRefresh: false,
  inflight: null,
};

/**
 * Dependency-injection seam for tests: the production implementation is
 * `cloneOrFetchPromptsCache` from the prompts-cache module; tests swap in
 * a counter-bumping stub so they can assert on coalescing without spinning
 * up a real git fixture for every webhook test.
 *
 * Internal — exported only via `__setRefreshFnForTests` below.
 */
let refreshFn: (opts: CloneOrFetchOpts) => Promise<RefreshResult> =
  cloneOrFetchPromptsCache;

/**
 * Test-only override of the refresh function. Call with `null` to restore the
 * production binding. Mirrors the env-var-override seam invite-accept uses
 * for `STAMP_SERVER_DB_PATH` — DI without a constructor argument keeps the
 * `startServer(port)` shape stable for the bin script.
 */
export function __setRefreshFnForTests(
  fn: ((opts: CloneOrFetchOpts) => Promise<RefreshResult>) | null,
): void {
  refreshFn = fn ?? cloneOrFetchPromptsCache;
}

/**
 * Test-only reset of the coalescing state. Two tests fired back-to-back
 * would otherwise see each other's `lastKickoffAt` and skip a refresh that
 * the second test expects to run. Production code never calls this — the
 * server boots with a fresh state object and the throttle works from there.
 */
export function __resetWebhookStateForTests(): void {
  webhookState.lastKickoffAt = 0;
  webhookState.pendingTrailingRefresh = false;
  webhookState.inflight = null;
}

/**
 * Build the `CloneOrFetchOpts` block for a webhook-triggered refresh from
 * env vars. Returns null if `STAMP_PROMPTS_REPO_URL` is unset — that's a
 * misconfiguration (we got a webhook delivery for a repo we don't have a
 * URL for) but we treat it the same way as a missing secret: 503 with a
 * clear operator-actionable error rather than a silent no-op. The webhook
 * receiver can't usefully proceed without knowing what to fetch.
 *
 * `STAMP_PROMPTS_REPO_REF` defaults to `main`. `STAMP_PROMPTS_CACHE_ROOT`
 * defaults to `/srv/git/.prompts-cache` (the path AGT-375's entrypoint
 * provisions on the persistent volume). The deploy-key path defaults to the
 * AGT-375 location; passing it for an HTTPS URL is harmless — the cache
 * module ignores it when the URL isn't SSH-shaped.
 */
function buildRefreshOpts(): CloneOrFetchOpts | null {
  const url = process.env["STAMP_PROMPTS_REPO_URL"];
  if (!url) return null;
  const ref = process.env["STAMP_PROMPTS_REPO_REF"] || "main";
  const cacheRoot =
    process.env["STAMP_PROMPTS_CACHE_ROOT"] || DEFAULT_PROMPTS_CACHE_ROOT;
  const deployKeyPath =
    process.env["STAMP_PROMPTS_DEPLOY_KEY_PATH"] || DEFAULT_DEPLOY_KEY_PATH;
  return { url, ref, cacheRoot, deployKeyPath };
}

/**
 * Validate `X-Hub-Signature-256` against the raw request body. Returns true
 * iff the header parses as `sha256=<64-hex-chars>` AND the decoded digest
 * matches the HMAC-SHA256 of `body` under `secret`.
 *
 * Implementation notes:
 *
 *   - `timingSafeEqual` requires equal-length buffers; we length-check
 *     BEFORE handing them off so a malformed signature can't crash the
 *     handler.
 *   - The HMAC computation uses the raw body bytes — NOT the parsed JSON
 *     string. Github computes the HMAC over the wire payload; any
 *     re-stringification would change the bytes and break the check.
 *   - The supplied signature is never logged. The caller logs ONLY the
 *     delivery ID + remote address on rejection (per AC bullet 3).
 */
function verifyWebhookSignature(
  body: BinaryLike,
  signatureHeader: string | undefined,
  secret: string,
): boolean {
  if (!signatureHeader || !signatureHeader.startsWith("sha256=")) {
    return false;
  }
  const providedHex = signatureHeader.slice("sha256=".length);
  // Hex-decode is strict: an odd-length or non-hex character produces a
  // shorter buffer than expected, which the length check below catches.
  // (Node's Buffer.from with 'hex' silently truncates at the first invalid
  // character — we therefore reject anything that isn't exactly 64 hex
  // characters upstream of the decode, so the length check is belt-and-
  // suspenders rather than the primary defense.)
  if (!/^[0-9a-fA-F]{64}$/.test(providedHex)) {
    return false;
  }
  const provided = Buffer.from(providedHex, "hex");
  const expected = createHmac("sha256", secret).update(body).digest();
  if (provided.length !== expected.length) {
    return false;
  }
  return timingSafeEqual(provided, expected);
}

/**
 * Schedule (or coalesce) a prompts-cache refresh. Called from the webhook
 * handler AFTER the response has been sent — github expects a fast 202 and
 * will retry on a timeout. The refresh runs in the background.
 *
 * Throttle rules:
 *
 *   - If the previous refresh kickoff was >= WINDOW_MS ago, kick off
 *     immediately. Update `lastKickoffAt`.
 *   - If the previous refresh kickoff was < WINDOW_MS ago AND a refresh is
 *     currently in flight, set `pendingTrailingRefresh = true`. The
 *     in-flight refresh's `.finally` will fire one more refresh after it
 *     settles — captures the trailing-edge delivery of a burst.
 *   - If the previous refresh kickoff was < WINDOW_MS ago AND nothing is
 *     in flight (the previous one already settled), just no-op — the cache
 *     is already at HEAD as of <WINDOW_MS ago, the next push will refresh
 *     it again. Setting `pendingTrailingRefresh` here would create a
 *     debounce-without-leading-edge pattern that's surprising.
 *
 * Errors thrown by `refreshFn` are caught and logged but never propagated
 * — the response has already been sent, and an unhandled rejection from a
 * setImmediate callback would crash the listener.
 */
function scheduleWebhookRefresh(opts: CloneOrFetchOpts, deliveryId: string): void {
  const now = Date.now();
  const elapsed = now - webhookState.lastKickoffAt;

  if (elapsed >= WEBHOOK_COALESCE_WINDOW_MS) {
    kickoffRefresh(opts, deliveryId);
    return;
  }

  // Inside the throttle window.
  if (webhookState.inflight) {
    // A refresh is still running — mark a trailing-edge re-fire so the
    // burst's last delivery isn't lost.
    if (!webhookState.pendingTrailingRefresh) {
      logLine(
        "info",
        `webhook/prompts coalesced delivery=${deliveryId} (refresh in flight, trailing scheduled)`,
      );
    }
    webhookState.pendingTrailingRefresh = true;
    return;
  }

  // Previous refresh has settled within the window; the cache is fresh
  // enough. No-op.
  logLine(
    "info",
    `webhook/prompts coalesced delivery=${deliveryId} (refresh ${Math.round(elapsed)}ms ago, within ${WEBHOOK_COALESCE_WINDOW_MS}ms window)`,
  );
}

function kickoffRefresh(opts: CloneOrFetchOpts, deliveryId: string): void {
  webhookState.lastKickoffAt = Date.now();
  const promise = refreshFn(opts);
  webhookState.inflight = promise;
  logLine("info", `webhook/prompts refresh start delivery=${deliveryId}`);

  promise
    .then((result) => {
      logLine(
        "info",
        `webhook/prompts refresh ok delivery=${deliveryId} sha=${result.commitSha} at=${result.refreshedAt}`,
      );
    })
    .catch((err: unknown) => {
      // The cache module throws on operator-actionable errors (bad URL,
      // missing deploy key, git failure). We log the message and keep
      // running — the operator can inspect the log, fix the misconfig,
      // and the next webhook delivery will retry.
      const msg = err instanceof Error ? err.message : String(err);
      logLine(
        "error",
        `webhook/prompts refresh failed delivery=${deliveryId}: ${msg}`,
      );
    })
    .finally(() => {
      if (webhookState.inflight === promise) {
        webhookState.inflight = null;
      }
      if (webhookState.pendingTrailingRefresh) {
        webhookState.pendingTrailingRefresh = false;
        // Drain the trailing flag with a fresh kickoff, tagged so logs
        // make the burst-collapse pattern visible.
        kickoffRefresh(opts, `${deliveryId}+trailing`);
      }
    });
}

async function handleWebhookPrompts(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  // Sanitize the delivery ID before it touches any log line. A missing
  // header is fine (we log `none`); a malformed value is replaced with
  // `malformed` so we still get a record of the request without injecting
  // arbitrary bytes into our log stream.
  const rawDelivery = req.headers["x-github-delivery"];
  const deliveryId =
    typeof rawDelivery === "string" && DELIVERY_ID_RE.test(rawDelivery)
      ? rawDelivery
      : rawDelivery
        ? "malformed"
        : "none";

  // Remote address is informational only — used for ops to spot a misconfig
  // (e.g. someone pointed an external scanner at our /webhook/prompts URL).
  // Behind a reverse proxy this will be the proxy IP; that's fine, the
  // proxy's access log carries the original.
  const remoteAddr = req.socket.remoteAddress ?? "unknown";

  // 503: missing secret. Done BEFORE reading the body — an unconfigured
  // server shouldn't allocate up to 64 KiB for every webhook delivery.
  const secret = process.env["STAMP_PROMPTS_WEBHOOK_SECRET"];
  if (!secret) {
    logLine(
      "error",
      `webhook/prompts delivery=${deliveryId} rejected: STAMP_PROMPTS_WEBHOOK_SECRET not configured`,
    );
    sendJson(res, 503, {
      ok: false,
      error: "webhook_secret_unconfigured",
      detail:
        "STAMP_PROMPTS_WEBHOOK_SECRET env var must be set on stamp-server to accept prompt-repo webhooks",
    });
    return;
  }

  // Read the raw bytes — the HMAC is over the wire payload, NOT the parsed
  // JSON, so we must compute the digest on the buffer before any parsing.
  let read: ReadBodyResult;
  try {
    read = await readBody(req, WEBHOOK_MAX_BODY_BYTES);
  } catch (e) {
    logLine("warn", `webhook/prompts read body failed delivery=${deliveryId}: ${(e as Error).message}`);
    sendJson(res, 400, { ok: false, error: "body_read_failed" });
    return;
  }
  if (read.tooLarge) {
    // Payload over the cap: don't even attempt HMAC. An attacker who
    // doesn't know the secret can't fabricate a valid signature on a
    // body we never read past 64 KiB; an oversized body from a real
    // sender is an operator problem (someone hooked us into the wrong
    // event) that should surface as 413.
    logLine(
      "warn",
      `webhook/prompts delivery=${deliveryId} from=${remoteAddr} body too large (> ${WEBHOOK_MAX_BODY_BYTES} bytes)`,
    );
    sendJson(res, 413, { ok: false, error: "body_too_large" });
    return;
  }

  // 401: signature mismatch. We do NOT log the supplied signature value —
  // it could be either an honest header from a misconfigured webhook OR an
  // attacker's probe; either way it has no diagnostic value and writing it
  // to logs is just a foot-gun.
  const sigHeader = req.headers["x-hub-signature-256"];
  const sigValue = Array.isArray(sigHeader) ? sigHeader[0] : sigHeader;
  if (!verifyWebhookSignature(read.buf, sigValue, secret)) {
    logLine(
      "warn",
      `webhook/prompts delivery=${deliveryId} from=${remoteAddr} rejected: invalid signature`,
    );
    sendJson(res, 401, { ok: false, error: "invalid_signature" });
    return;
  }

  // 202: signature valid. Schedule the refresh in the background and
  // respond fast — github retries on 5xx OR on response timeout, so we
  // want this round-trip to complete before the refresh's git fetch
  // could possibly stall.
  const opts = buildRefreshOpts();
  if (!opts) {
    // The HMAC validated against our configured secret, so this is our
    // operator's misconfiguration — webhook is wired but no repo URL is
    // set. Returning 503 (not 202) is louder; github will retry, and the
    // operator will see repeated failures in the webhook delivery log
    // until they set STAMP_PROMPTS_REPO_URL. 503 also matches the missing-
    // secret case for operator-actionable misconfig.
    logLine(
      "error",
      `webhook/prompts delivery=${deliveryId} rejected: STAMP_PROMPTS_REPO_URL not configured`,
    );
    sendJson(res, 503, {
      ok: false,
      error: "prompts_repo_url_unconfigured",
      detail:
        "STAMP_PROMPTS_REPO_URL env var must be set on stamp-server to accept prompt-repo webhooks",
    });
    return;
  }

  // Send 202 immediately, THEN schedule. setImmediate so the response
  // flushes before the (potentially long) git fetch begins; even though
  // the cache module is non-blocking, the lock-acquire + execFileSync
  // chain inside it can hold the event loop for a few ms on a cold cache.
  sendJson(res, 202, { ok: true });
  logLine(
    "info",
    `webhook/prompts delivery=${deliveryId} accepted (signature valid)`,
  );

  setImmediate(() => {
    try {
      scheduleWebhookRefresh(opts, deliveryId);
    } catch (e) {
      // scheduleWebhookRefresh's own .catch handles refreshFn rejections.
      // This try/catch covers synchronous throws from the scheduling
      // bookkeeping itself — should be impossible but a crashed listener
      // here would take out invite/accept too.
      logLine(
        "error",
        `webhook/prompts schedule error delivery=${deliveryId}: ${(e as Error).message}`,
      );
    }
  });
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
    if (req.method === "POST" && url === "/webhook/prompts") {
      void handleWebhookPrompts(req, res);
      return;
    }
    sendJson(res, 404, { ok: false, error: "not_found" });
  });
  server.listen(port, () => {
    logLine("info", `listening on :${port}`);
  });
  return server;
}
