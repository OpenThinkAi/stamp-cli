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
import {
  findPeerReviewEventsAfter,
  findUserByStampPubkey,
  insertUser,
  maxPeerReviewEventId,
  openServerDb,
  sweepExpiredSeats,
} from "../lib/serverDb.js";
import { parseSshPubkey } from "../lib/sshKeys.js";
import { verifyBytes } from "../lib/signing.js";
import { fingerprintFromPem } from "../lib/keys.js";
import {
  DEFAULT_TRASH_DIR,
  purgeTrash,
  resolveTrashTtlDays,
} from "./trashPurge.js";
import {
  cloneOrFetchPromptsCache,
  scrubGitUrlCredentials,
  type CloneOrFetchOpts,
  type RefreshResult,
} from "./prompts-cache.js";
import {
  resolvePeerReviewsEnabled,
  resolvePeerReviewLimit,
  registerListener,
  unregisterListener,
  SEAT_TTL_SECONDS_DEFAULT,
} from "./peerReviews.js";
import type { PeerReviewEvent } from "../lib/peerReviewEvent.js";

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

// ─── Periodic-poll backstop (AGT-376, Phase B) ───────────────────────

/**
 * Default poll interval in seconds. One hour matches the project README's
 * "optional periodic-poll fallback (every ~hour) as backstop" line and is
 * the default named in the AGT-376 acceptance criteria. The whole point of
 * the backstop is to recover from a missed webhook within a bounded window
 * without adding meaningful load — github webhook deliveries cover the
 * common case sub-second; the poll only matters when a delivery was
 * missed/delayed.
 *
 * Operators tune via `STAMP_PROMPTS_POLL_INTERVAL_SEC`. Set to `0` to
 * disable polling entirely (e.g. in test deploys where the webhook is
 * the only source and an hourly fetch would clutter logs). Negative or
 * non-integer values fall back to the default.
 */
export const DEFAULT_PROMPTS_POLL_INTERVAL_SEC = 3600;

/**
 * Floor on the poll interval. Five seconds matches the webhook-route
 * coalescing window — a poll that fires more often than the webhook can
 * coalesce its own bursts would be pointless overhead. Tests set values
 * below this (via the test-only override) to keep fake-timer runs fast,
 * but production values are clamped.
 */
const MIN_PROMPTS_POLL_INTERVAL_SEC = 5;

/**
 * Poll-worker state, module-scoped so it survives across the request
 * handlers without leaking into the request itself. Two pieces:
 *
 *   - `handle` — the `setInterval` timer handle, or null when polling is
 *                disabled / not yet started. Cleared on `stopPromptsPollWorker`.
 *   - `inflight` — set to true while a poll-triggered refresh is awaiting
 *                  the cache module. Skips the next tick if a previous
 *                  refresh is still running (defensive — the cache module
 *                  has its own in-process coalescing, but firing two
 *                  parallel ticks is wasted work and produces confusing
 *                  log lines).
 */
interface PollWorkerState {
  handle: ReturnType<typeof setInterval> | null;
  inflight: boolean;
  /**
   * Bumped on every poll-triggered refresh attempt (successful or not).
   * Test-only — production code doesn't read this. Lets the test assert
   * "advancing fake time by N intervals fired the refresh fn N times"
   * without spelunking the cache module's internal counters.
   */
  tickCount: number;
}

const pollState: PollWorkerState = {
  handle: null,
  inflight: false,
  tickCount: 0,
};

/**
 * Resolve the poll interval from env. Returns 0 when polling should be
 * disabled (env value `"0"`, exactly) and a positive integer otherwise.
 * Defensive parsing: a typo'd value falls back to the default rather
 * than silently disabling — only the literal `"0"` disables.
 *
 * Exported so operator-docs / diagnostic tools can mirror the same
 * resolution shape without re-parsing the env var.
 */
export function resolvePromptsPollIntervalSec(): number {
  const raw = process.env["STAMP_PROMPTS_POLL_INTERVAL_SEC"];
  if (raw === undefined || raw === "") {
    return DEFAULT_PROMPTS_POLL_INTERVAL_SEC;
  }
  // Exact "0" is the documented opt-out signal.
  if (raw === "0") return 0;
  // Require an explicit integer shape. `Number("   ")` and `Number("\n")`
  // both return 0, which would otherwise sneak through as "disable
  // polling" — silent disable on whitespace is exactly the failure mode
  // the AC explicitly avoids ("setting interval to 0 prevents fetches").
  // Operators get the disable behavior ONLY by writing the literal "0".
  if (!/^-?\d+$/.test(raw)) {
    logLine(
      "warn",
      `STAMP_PROMPTS_POLL_INTERVAL_SEC=${JSON.stringify(raw)} is not a non-negative integer; falling back to default ${DEFAULT_PROMPTS_POLL_INTERVAL_SEC}s`,
    );
    return DEFAULT_PROMPTS_POLL_INTERVAL_SEC;
  }
  const n = Number(raw);
  // n <= 0 (NOT n < 0): the literal "0" exited above, so any other
  // input that parses to a non-positive integer ("00", "000", "-5",
  // "-0", etc.) is operator-error territory. Fall back to the default
  // rather than silently disabling — the standards reviewer flagged
  // "00" silently disabling polling as an invariant violation; this
  // is the one-character fix that closes it. `!Number.isInteger(n)`
  // is unreachable here (the regex above already rejected non-
  // integers) but kept as belt-and-suspenders in case a future
  // refactor loosens the regex.
  if (!Number.isInteger(n) || n <= 0) {
    logLine(
      "warn",
      `STAMP_PROMPTS_POLL_INTERVAL_SEC=${JSON.stringify(raw)} is not a positive integer (and not the literal '0' opt-out); falling back to default ${DEFAULT_PROMPTS_POLL_INTERVAL_SEC}s`,
    );
    return DEFAULT_PROMPTS_POLL_INTERVAL_SEC;
  }
  // Clamp tiny non-zero values to the floor. Operators who want polling
  // disabled use 0 explicitly; values like 1 or 2 are almost certainly
  // a mistake (the cache module's lock file would still serialize them,
  // but the resulting log noise has no diagnostic value).
  if (n > 0 && n < MIN_PROMPTS_POLL_INTERVAL_SEC) {
    logLine(
      "warn",
      `STAMP_PROMPTS_POLL_INTERVAL_SEC=${n} is below the floor of ${MIN_PROMPTS_POLL_INTERVAL_SEC}s; clamping to floor`,
    );
    return MIN_PROMPTS_POLL_INTERVAL_SEC;
  }
  return n;
}

/**
 * Run one poll tick: invoke the shared `refreshFn` (same DI seam the
 * webhook route uses; production = `cloneOrFetchPromptsCache`). Errors are
 * caught and logged — the next tick will retry, so a transient network
 * failure doesn't crash the worker.
 *
 * `inflight` guards against the case where a prior tick's refresh hasn't
 * settled yet (e.g. operator set a 10s interval and the first git fetch
 * over a slow link took 12s). The cache module would coalesce internally,
 * but skipping at this layer avoids the second log line entirely.
 *
 * Exported (`__runPollTickForTests`) so tests can fire a tick without
 * having to drive `setInterval` directly — fake timers + an async tick
 * handler is a known-finicky combination, and a direct invocation keeps
 * each test's intent crisp.
 */
async function runPollTick(opts: CloneOrFetchOpts): Promise<void> {
  if (pollState.inflight) {
    logLine(
      "info",
      "prompts-poll: skipping tick — previous refresh still in flight",
    );
    return;
  }
  pollState.inflight = true;
  pollState.tickCount += 1;
  try {
    const result = await refreshFn(opts);
    logLine(
      "info",
      `prompts-poll: refresh ok sha=${result.commitSha} at=${result.refreshedAt}`,
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logLine("error", `prompts-poll: refresh failed: ${msg}`);
  } finally {
    pollState.inflight = false;
  }
}

/**
 * Start the periodic-poll backstop. Idempotent — calling twice without an
 * intervening stop is a no-op (logs a warning so the duplicate call is
 * visible during refactoring but doesn't double-arm the interval).
 *
 * Gating logic per AGT-376 ACs:
 *
 *   1. `STAMP_PROMPTS_REPO_URL` unset → no-op. The whole feature is opt-in;
 *      Phase A deployments (bundled prompts at `/etc/stamp/reviewers/`)
 *      don't need a polling worker.
 *   2. `STAMP_PROMPTS_POLL_INTERVAL_SEC=0` → no-op. Explicit operator
 *      opt-out — typical when the webhook is the only source and an
 *      hourly fetch would clutter logs.
 *   3. Otherwise → arm `setInterval` against `runPollTick`. The handle is
 *      `unref()`'d so an idle daemon (no traffic, no webhooks) can still
 *      exit cleanly under SIGTERM; the listener's `close` callback calls
 *      `stopPromptsPollWorker` for symmetric shutdown.
 *
 * The poll worker shares the `refreshFn` DI seam with the webhook route,
 * so tests that override `refreshFn` via `__setRefreshFnForTests` see
 * both surfaces drive the same stub. Production callers get
 * `cloneOrFetchPromptsCache` which has its own lock + coalescing — a poll
 * tick that races a webhook-triggered refresh collapses to a single
 * fetch without further coordination at this layer.
 */
export function startPromptsPollWorker(): void {
  if (pollState.handle !== null) {
    logLine("warn", "prompts-poll: already started — ignoring duplicate start");
    return;
  }

  // AC bullet 4: only run when STAMP_PROMPTS_REPO_URL is set.
  const opts = buildRefreshOpts();
  if (!opts) {
    // Phase A deployment — Phase B feature isn't engaged. Don't even log;
    // the bootstrap binary's silent no-op shape (AGT-375) is the
    // precedent here.
    return;
  }

  // AC bullet 2: STAMP_PROMPTS_POLL_INTERVAL_SEC=0 disables.
  const intervalSec = resolvePromptsPollIntervalSec();
  if (intervalSec === 0) {
    logLine(
      "info",
      "prompts-poll: disabled (STAMP_PROMPTS_POLL_INTERVAL_SEC=0)",
    );
    return;
  }

  const intervalMs = intervalSec * 1000;
  const handle = setInterval(() => {
    // Don't propagate the rejection — runPollTick already catches and
    // logs. The void cast keeps eslint/tsc happy about the unhandled
    // promise from an async callback.
    void runPollTick(opts);
  }, intervalMs);
  // unref so the daemon can still exit cleanly when nothing else is
  // keeping the event loop alive (CI, ephemeral test harnesses).
  handle.unref();
  pollState.handle = handle;

  logLine(
    "info",
    `prompts-poll: started (interval=${intervalSec}s, url=${scrubGitUrlCredentials(opts.url)}, ref=${opts.ref}, cacheRoot=${opts.cacheRoot})`,
  );
}

/**
 * Stop the periodic-poll backstop. Safe to call when not started (no-op).
 * Production callers invoke from `server.close()` for clean shutdown;
 * tests call between cases to reset state.
 */
export function stopPromptsPollWorker(): void {
  if (pollState.handle === null) return;
  clearInterval(pollState.handle);
  pollState.handle = null;
  pollState.inflight = false;
}

/**
 * Test-only reset of the poll-worker state. Tests fire back-to-back
 * intervals from one test case to the next, and a stale `tickCount` /
 * `inflight` flag would otherwise leak across cases. Production code
 * never calls this — the daemon starts with a fresh state object.
 */
export function __resetPollStateForTests(): void {
  if (pollState.handle !== null) {
    clearInterval(pollState.handle);
  }
  pollState.handle = null;
  pollState.inflight = false;
  pollState.tickCount = 0;
}

// ─── trash-sweep worker (AGT-423) ────────────────────────────────────
//
// Periodically purge soft-deleted bare repos older than STAMP_TRASH_TTL_DAYS.
// In-process (not a system cron — there's no cron in the image) and mirrors
// the poll-worker shape above: unref'd interval, inflight guard, a tick
// counter + test seams. The purge logic + destructive-delete containment
// live in trashPurge.ts (shared with the on-demand `purge-trash` verb).

/** Default sweep cadence: every 6 hours. Trash TTL is in days, so a sub-day
 *  sweep interval is plenty timely without log noise. */
export const DEFAULT_TRASH_SWEEP_INTERVAL_SEC = 6 * 3600;
const MIN_TRASH_SWEEP_INTERVAL_SEC = 60;

interface TrashSweepState {
  handle: ReturnType<typeof setInterval> | null;
  inflight: boolean;
  /** Test-only: bumped per tick so a test can assert ticks fired. */
  tickCount: number;
}

const trashSweepState: TrashSweepState = {
  handle: null,
  inflight: false,
  tickCount: 0,
};

/**
 * Resolve the sweep interval from STAMP_TRASH_SWEEP_INTERVAL_SEC. Literal
 * `"0"` disables the sweep; anything non-integer/non-positive falls back to
 * the default (never silently disables on a typo — same discipline as the
 * poll interval). Sub-floor values clamp up.
 */
export function resolveTrashSweepIntervalSec(): number {
  const raw = process.env["STAMP_TRASH_SWEEP_INTERVAL_SEC"];
  if (raw === undefined || raw === "") return DEFAULT_TRASH_SWEEP_INTERVAL_SEC;
  if (raw === "0") return 0;
  if (!/^-?\d+$/.test(raw)) {
    logLine(
      "warn",
      `STAMP_TRASH_SWEEP_INTERVAL_SEC=${JSON.stringify(raw)} is not an integer; falling back to default ${DEFAULT_TRASH_SWEEP_INTERVAL_SEC}s`,
    );
    return DEFAULT_TRASH_SWEEP_INTERVAL_SEC;
  }
  const n = Number(raw);
  if (!Number.isInteger(n) || n <= 0) return DEFAULT_TRASH_SWEEP_INTERVAL_SEC;
  if (n < MIN_TRASH_SWEEP_INTERVAL_SEC) return MIN_TRASH_SWEEP_INTERVAL_SEC;
  return n;
}

/** One sweep tick: purge trash older than the TTL. Errors are caught +
 *  logged so a transient fs hiccup never crashes the listener. Exported
 *  (`__runTrashSweepTickForTests`) so tests fire a tick without setInterval. */
function runTrashSweepTick(): void {
  if (trashSweepState.inflight) return;
  trashSweepState.inflight = true;
  trashSweepState.tickCount += 1;
  try {
    const trashDir = process.env["STAMP_TRASH_DIR"] || DEFAULT_TRASH_DIR;
    const ttlDays = resolveTrashTtlDays();
    const { purged, skipped } = purgeTrash(trashDir, ttlDays);
    if (purged.length > 0) {
      logLine(
        "info",
        `trash-sweep: purged ${purged.length} trashed repo(s) older than ${ttlDays}d: ${purged.join(", ")}`,
      );
    }
    if (skipped.length > 0) {
      logLine(
        "warn",
        `trash-sweep: skipped ${skipped.length} entr(y/ies) that failed a containment check: ${skipped.join(", ")}`,
      );
    }
  } catch (err) {
    logLine(
      "error",
      `trash-sweep: tick failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  } finally {
    trashSweepState.inflight = false;
  }
}

export const __runTrashSweepTickForTests = runTrashSweepTick;

/** Arm the periodic trash sweep. Idempotent; disabled by
 *  STAMP_TRASH_SWEEP_INTERVAL_SEC=0. unref'd so an idle daemon still exits. */
export function startTrashSweepWorker(): void {
  if (trashSweepState.handle !== null) {
    logLine("warn", "trash-sweep: already started — ignoring duplicate start");
    return;
  }
  const intervalSec = resolveTrashSweepIntervalSec();
  if (intervalSec === 0) {
    logLine("info", "trash-sweep: disabled (STAMP_TRASH_SWEEP_INTERVAL_SEC=0)");
    return;
  }
  const handle = setInterval(() => runTrashSweepTick(), intervalSec * 1000);
  handle.unref();
  trashSweepState.handle = handle;
  logLine(
    "info",
    `trash-sweep: started (interval=${intervalSec}s, ttl=${resolveTrashTtlDays()}d)`,
  );
}

export function stopTrashSweepWorker(): void {
  if (trashSweepState.handle === null) return;
  clearInterval(trashSweepState.handle);
  trashSweepState.handle = null;
  trashSweepState.inflight = false;
}

export function __resetTrashSweepStateForTests(): void {
  if (trashSweepState.handle !== null) clearInterval(trashSweepState.handle);
  trashSweepState.handle = null;
  trashSweepState.inflight = false;
  trashSweepState.tickCount = 0;
}

export function __getTrashSweepTickCountForTests(): number {
  return trashSweepState.tickCount;
}

// ─── Seat-TTL sweep worker (AGT-454, G3) ─────────────────────────────
//
// Periodically clear expired peer-review seats (those whose heartbeat is
// older than SEAT_TTL_SECONDS). Mirrors the trash-sweep worker shape.
// Cadence: every 5 minutes (well under the 10-min default TTL).
// Disabled when STAMP_PEER_REVIEWS_ENABLED is not exactly "1".

const DEFAULT_SEAT_SWEEP_INTERVAL_SEC = 300; // 5 min

interface SeatSweepState {
  handle: ReturnType<typeof setInterval> | null;
}

const seatSweepState: SeatSweepState = { handle: null };

/** Arm the periodic seat-TTL sweep. Idempotent; only runs when peer reviews
 *  are enabled. unref'd so an idle daemon still exits. */
export function startSeatSweepWorker(): void {
  if (seatSweepState.handle !== null) return; // already running
  if (!resolvePeerReviewsEnabled()) return;    // feature dark — no-op

  const intervalSec = DEFAULT_SEAT_SWEEP_INTERVAL_SEC;
  const handle = setInterval(() => {
    const ttlSec = resolvePeerReviewLimit("SEAT_TTL_SECONDS", SEAT_TTL_SECONDS_DEFAULT);
    try {
      const db = openServerDb({ skipChmod: true });
      try {
        const cleared = sweepExpiredSeats(db, ttlSec);
        if (cleared > 0) {
          logLine("info", `seat-sweep: cleared ${cleared} expired seat(s) (ttl=${ttlSec}s)`);
        }
      } finally {
        db.close();
      }
    } catch (err) {
      logLine("error", `seat-sweep: tick failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }, intervalSec * 1000);
  handle.unref();
  seatSweepState.handle = handle;
  logLine("info", `seat-sweep: started (interval=${intervalSec}s)`);
}

export function stopSeatSweepWorker(): void {
  if (seatSweepState.handle === null) return;
  clearInterval(seatSweepState.handle);
  seatSweepState.handle = null;
}

/**
 * Test-only direct fire of one poll tick. Fake timers + an async
 * `setInterval` callback is a known-finicky combination — driving the
 * tick directly keeps each test's intent crisp. Returns the same promise
 * the interval callback would have awaited.
 *
 * Returns `null` when polling would be a no-op (URL unset). Tests that
 * exercise the disabled paths assert on `pollState.tickCount` staying
 * at 0 across `tick()` advances rather than calling this.
 */
export async function __runPollTickForTests(): Promise<void | null> {
  const opts = buildRefreshOpts();
  if (!opts) return null;
  await runPollTick(opts);
  return;
}

/**
 * Test-only introspection of the poll worker's state. Lets tests assert
 * "the interval was armed" / "tickCount bumped after N ticks" without
 * mutating module-private state. Returns a snapshot, not the live
 * object, so callers can't accidentally mutate it.
 */
export function __getPollStateForTests(): {
  armed: boolean;
  inflight: boolean;
  tickCount: number;
} {
  return {
    armed: pollState.handle !== null,
    inflight: pollState.inflight,
    tickCount: pollState.tickCount,
  };
}

// ─── Peer-events poll worker (peer-events-delivery) ──────────────────
//
// Bridges the cross-process delivery gap: `pr-opened` and `re-review-request`
// verbs write rows to `peer_review_events` AND call `fanoutEvent()` in their
// own short-lived process, but `fanoutEvent` only reaches in-process listeners
// — which are always ZERO in a verb process. The SSE listeners are connected
// to this long-running http-server process.
//
// This worker polls the `peer_review_events` table every N seconds, picks up
// rows written by verb processes since the previous tick, and pushes them to
// connected SSE clients whose subscribed orgs match the event's org.
//
// Design invariants:
//   - Cursor initialised to MAX(id) at startup → no history replay.
//   - Each new event is pushed to each matching SSE client exactly once.
//   - `fanoutEvent()` still fires for in-process tests (no double-delivery
//     risk: an in-process `fanoutEvent` call writes the SSE frame via the
//     `registerListener` onEvent callback; the poll worker only sees rows
//     persisted to DB, which never happens in-process tests).
//   - Gate: worker only starts when `resolvePeerReviewsEnabled()` is true.

/** Default poll interval: 2 seconds — fast enough for interactive feel. */
export const DEFAULT_PEER_EVENTS_POLL_INTERVAL_SEC = 2;
const MIN_PEER_EVENTS_POLL_INTERVAL_SEC = 1;

interface PeerEventsPollState {
  handle: ReturnType<typeof setInterval> | null;
  /** Inclusive lower bound: only rows with id > cursor are delivered. */
  cursor: number;
  inflight: boolean;
  /** Test-only: bumped per tick. */
  tickCount: number;
}

const peerEventsPollState: PeerEventsPollState = {
  handle: null,
  cursor: 0,
  inflight: false,
  tickCount: 0,
};

/**
 * Resolve the peer-events poll interval from
 * `STAMP_PEER_EVENTS_POLL_INTERVAL_SEC`. Literal `"0"` disables; non-integer
 * or non-positive values fall back to the default (never silently disable on
 * a typo — same discipline as the other poll intervals).
 */
export function resolvePeerEventsPollIntervalSec(): number {
  const raw = process.env["STAMP_PEER_EVENTS_POLL_INTERVAL_SEC"];
  if (raw === undefined || raw === "") return DEFAULT_PEER_EVENTS_POLL_INTERVAL_SEC;
  if (raw === "0") return 0;
  if (!/^-?\d+$/.test(raw)) {
    logLine(
      "warn",
      `STAMP_PEER_EVENTS_POLL_INTERVAL_SEC=${JSON.stringify(raw)} is not an integer; falling back to default ${DEFAULT_PEER_EVENTS_POLL_INTERVAL_SEC}s`,
    );
    return DEFAULT_PEER_EVENTS_POLL_INTERVAL_SEC;
  }
  const n = Number(raw);
  if (!Number.isInteger(n) || n <= 0) {
    logLine(
      "warn",
      `STAMP_PEER_EVENTS_POLL_INTERVAL_SEC=${JSON.stringify(raw)} is not a positive integer (and not the literal '0' opt-out); falling back to default ${DEFAULT_PEER_EVENTS_POLL_INTERVAL_SEC}s`,
    );
    return DEFAULT_PEER_EVENTS_POLL_INTERVAL_SEC;
  }
  if (n < MIN_PEER_EVENTS_POLL_INTERVAL_SEC) return MIN_PEER_EVENTS_POLL_INTERVAL_SEC;
  return n;
}

/**
 * One poll tick: fetch new peer_review_events rows since the last cursor,
 * derive the org from the `repo` field, and push each event to SSE clients
 * subscribed to that org. Advances the cursor to the max id seen.
 *
 * Exported as `__runPeerEventsPollTickForTests` so tests can fire a tick
 * synchronously without driving `setInterval`.
 */
function runPeerEventsPollTick(): void {
  if (peerEventsPollState.inflight) return;
  peerEventsPollState.inflight = true;
  peerEventsPollState.tickCount += 1;
  try {
    const db = openServerDb({ readOnly: true });
    try {
      const rows = findPeerReviewEventsAfter(db, peerEventsPollState.cursor);
      for (const row of rows) {
        // Derive org from repo ("org/repo" → "org").
        const org = row.repo.split("/")[0] ?? "";
        // Parse the stored payload JSON; fall back to empty object on corrupt data.
        let payload: object;
        try {
          payload = JSON.parse(row.payload) as object;
        } catch {
          payload = {};
        }
        const event = {
          event_type: row.event_type,
          patch_id: row.patch_id,
          actor_fp: row.actor_fp,
          payload,
        };
        // Deliver to every SSE client subscribed to this org.
        for (const [fp, client] of sseConnections) {
          if (client.orgs.includes(org)) {
            pushEventToSseClient(fp, event);
          }
        }
        // Advance cursor past this row.
        if (row.id > peerEventsPollState.cursor) {
          peerEventsPollState.cursor = row.id;
        }
      }
    } finally {
      db.close();
    }
  } catch (err) {
    logLine(
      "error",
      `peer-events-poll: tick failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  } finally {
    peerEventsPollState.inflight = false;
  }
}

export const __runPeerEventsPollTickForTests = runPeerEventsPollTick;

/**
 * Arm the peer-events poll worker. Idempotent; gated on
 * `resolvePeerReviewsEnabled()`. Initializes the cursor to MAX(id) so the
 * worker only delivers events created after it starts — no history replay.
 */
export function startPeerEventsPollWorker(): void {
  if (peerEventsPollState.handle !== null) {
    logLine("warn", "peer-events-poll: already started — ignoring duplicate start");
    return;
  }
  if (!resolvePeerReviewsEnabled()) return; // feature dark — no-op

  const intervalSec = resolvePeerEventsPollIntervalSec();
  if (intervalSec === 0) {
    logLine("info", "peer-events-poll: disabled (STAMP_PEER_EVENTS_POLL_INTERVAL_SEC=0)");
    return;
  }

  // Initialize cursor: don't replay history.
  try {
    const db = openServerDb({ readOnly: true });
    try {
      peerEventsPollState.cursor = maxPeerReviewEventId(db);
    } finally {
      db.close();
    }
  } catch (err) {
    // If we can't read the max id, start from 0 (safer than not starting).
    logLine(
      "warn",
      `peer-events-poll: could not read max event id (starting cursor at 0): ${err instanceof Error ? err.message : String(err)}`,
    );
    peerEventsPollState.cursor = 0;
  }

  const handle = setInterval(() => runPeerEventsPollTick(), intervalSec * 1000);
  handle.unref();
  peerEventsPollState.handle = handle;
  logLine("info", `peer-events-poll: started (interval=${intervalSec}s, cursor=${peerEventsPollState.cursor})`);
}

export function stopPeerEventsPollWorker(): void {
  if (peerEventsPollState.handle === null) return;
  clearInterval(peerEventsPollState.handle);
  peerEventsPollState.handle = null;
  peerEventsPollState.inflight = false;
}

export function __resetPeerEventsPollStateForTests(): void {
  if (peerEventsPollState.handle !== null) clearInterval(peerEventsPollState.handle);
  peerEventsPollState.handle = null;
  peerEventsPollState.cursor = 0;
  peerEventsPollState.inflight = false;
  peerEventsPollState.tickCount = 0;
}

export function __getPeerEventsPollStateForTests(): {
  armed: boolean;
  cursor: number;
  inflight: boolean;
  tickCount: number;
} {
  return {
    armed: peerEventsPollState.handle !== null,
    cursor: peerEventsPollState.cursor,
    inflight: peerEventsPollState.inflight,
    tickCount: peerEventsPollState.tickCount,
  };
}

// ─── SSE peer-review event transport (AGT-454; SSE replaces WS) ───────
//
// Mounted on the same HTTP server as the invite-accept and webhook endpoints.
// The endpoint is dark unless STAMP_PEER_REVIEWS_ENABLED=1. When enabled:
//
//   GET /peer/events?org=<a>&org=<b>
//     headers:
//       x-stamp-pubkey     SPKI PEM (raw, or base64 of the PEM)
//       x-stamp-timestamp  ISO-8601 timestamp
//       x-stamp-signature  base64 Ed25519 signature over the canonical string
//                          `peer-events\n<x-stamp-timestamp>`
//     200: text/event-stream — periodic `: heartbeat` comments + `data: <json>`
//          event frames for the caller's subscribed orgs.
//     401: {ok:false,error:<reason>} — bad signature, stale timestamp, or the
//          key is not an enrolled user.
//
// The WS signed-challenge handshake was retired: it authenticated against an
// unpopulated `/srv/git/.stamp/trusted-keys/<fp>.pub` store that was never
// written. The SSE auth is self-contained: a fresh-timestamp signature proves
// key possession (no nonce store needed for a read-only stream), and the
// `users` table lookup proves enrollment.

/** Heartbeat comment interval — keeps Railway's idle-proxy from closing the
 *  stream. Comment lines (`:`-prefixed) are ignored by EventSource parsers. */
const SSE_HEARTBEAT_MS = 25_000;
/** Allowed clock skew for the signed timestamp (replay window). */
const SSE_TIMESTAMP_WINDOW_MS = 300_000;
/** The path `stamp pr listen` connects to for the SSE event stream. */
export const SSE_PEER_EVENTS_PATH = "/peer/events";

/** Per-connection SSE state bound after successful auth. */
interface SseClientState {
  res: ServerResponse;
  orgs: string[];
  heartbeat: ReturnType<typeof setInterval>;
}

/** Active SSE connections keyed by fingerprint (for event fanout). */
const sseConnections = new Map<string, SseClientState>();

/**
 * Canonical string the client signs (and the server reconstructs) to prove
 * key possession for the SSE stream. Bound to a timestamp so a captured
 * signature falls out of the replay window quickly.
 */
function sseCanonicalString(timestamp: string): Buffer {
  return Buffer.from(`peer-events\n${timestamp}`, "utf8");
}

/**
 * Decode the `x-stamp-pubkey` header into an SPKI PEM string. The header may
 * carry the PEM verbatim (multi-line, possibly with literal `\n`), or the
 * base64 of the PEM. Returns null when neither form yields a PEM.
 */
function decodePubkeyHeader(raw: string): string | null {
  const direct = raw.includes("BEGIN PUBLIC KEY") ? raw.replace(/\\n/g, "\n") : null;
  if (direct) return direct;
  try {
    const decoded = Buffer.from(raw, "base64").toString("utf8");
    if (decoded.includes("BEGIN PUBLIC KEY")) return decoded;
  } catch {
    // fall through
  }
  return null;
}

/**
 * Authenticate + authorize an inbound `/peer/events` request.
 *   1. verifyBytes(pubkey, `peer-events\n<ts>`, signature) — proof of key
 *      possession (self-contained; no nonce store).
 *   2. timestamp within ±SSE_TIMESTAMP_WINDOW_MS — replay defense.
 *   3. the key belongs to an enrolled user (users.stamp_pubkey lookup).
 *
 * Returns `{ ok: true, fingerprint }` or `{ ok: false, status, reason }`.
 */
function authenticateSseRequest(
  req: IncomingMessage,
): { ok: true; pubkeyPem: string } | { ok: false; reason: string } {
  const rawPubkey = headerValue(req, "x-stamp-pubkey");
  const timestamp = headerValue(req, "x-stamp-timestamp");
  const signature = headerValue(req, "x-stamp-signature");
  if (!rawPubkey || !timestamp || !signature) {
    return { ok: false, reason: "missing auth headers" };
  }

  const pubkeyPem = decodePubkeyHeader(rawPubkey);
  if (!pubkeyPem) {
    return { ok: false, reason: "x-stamp-pubkey is not an SPKI PEM" };
  }

  // (2) Timestamp window — reject stale/future signatures.
  const ts = Date.parse(timestamp);
  if (Number.isNaN(ts)) {
    return { ok: false, reason: "x-stamp-timestamp is not a valid ISO-8601 timestamp" };
  }
  if (Math.abs(Date.now() - ts) > SSE_TIMESTAMP_WINDOW_MS) {
    return { ok: false, reason: "x-stamp-timestamp outside the allowed window" };
  }

  // (1) Signature — proof of key possession.
  let validSig: boolean;
  try {
    validSig = verifyBytes(pubkeyPem, sseCanonicalString(timestamp), signature);
  } catch (err) {
    return {
      ok: false,
      reason: `signature verify threw: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  if (!validSig) {
    return { ok: false, reason: "signature invalid" };
  }

  // (3) Enrollment — the key must belong to a known user.
  let enrolled = false;
  try {
    const db = openServerDb({ readOnly: true });
    try {
      enrolled = findUserByStampPubkey(db, pubkeyPem) !== null;
    } finally {
      db.close();
    }
  } catch (err) {
    return {
      ok: false,
      reason: `user lookup failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  if (!enrolled) {
    return { ok: false, reason: "key is not an enrolled user" };
  }

  return { ok: true, pubkeyPem };
}

/** Read a request header as a single string (first value if repeated). */
function headerValue(req: IncomingMessage, name: string): string | null {
  const v = req.headers[name];
  if (Array.isArray(v)) return v[0] ?? null;
  return typeof v === "string" ? v : null;
}

/** Parse `?org=a&org=b` (repeated) into a deduped org list. */
function parseOrgQuery(url: string): string[] {
  const q = url.indexOf("?");
  if (q < 0) return [];
  const params = new URLSearchParams(url.slice(q + 1));
  return [...new Set(params.getAll("org").filter((o) => o.length > 0))];
}

/**
 * Push a PeerReviewEvent to the SSE client identified by `fingerprint`.
 * Returns true when the stream was found and the frame was written; false
 * when no active SSE connection exists for that fingerprint.
 */
export function pushEventToSseClient(
  fingerprint: string,
  event: PeerReviewEvent,
): boolean {
  const client = sseConnections.get(fingerprint);
  if (!client) return false;
  try {
    client.res.write(`data: ${JSON.stringify(event)}\n\n`);
    return true;
  } catch {
    return false;
  }
}

/**
 * Handle a `GET /peer/events` request: authenticate (sign-with-key against the
 * users store), register the response stream keyed by fingerprint, and stream
 * events for the caller's subscribed orgs. The whole endpoint is gated on
 * `resolvePeerReviewsEnabled()` by the caller. Exported for test access.
 *
 * Delivery reuses the in-process listener registry (registerListener /
 * fanoutEvent) — the registered `onEvent` callback writes a `data:` frame to
 * this response, so `pr-opened` / re-review fanout reaches SSE clients without
 * a separate fanout path.
 */
export function handlePeerEventsRequest(
  req: IncomingMessage,
  res: ServerResponse,
): void {
  const auth = authenticateSseRequest(req);
  if (!auth.ok) {
    logLine("warn", `SSE /peer/events: auth failed: ${auth.reason}`);
    sendJson(res, 401, { ok: false, error: "unauthorized", reason: auth.reason });
    return;
  }

  // Fingerprint binds the stream to the verified pubkey (same namespace the
  // listener registry / seat verbs use).
  const fingerprint = fingerprintFromPem(auth.pubkeyPem);
  const orgs = parseOrgQuery(req.url ?? "");

  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-store",
    Connection: "keep-alive",
  });
  // Open the stream with a comment so proxies flush headers immediately.
  res.write(`: connected ${fingerprint}\n\n`);

  const heartbeat = setInterval(() => {
    try {
      res.write(`: heartbeat\n\n`);
    } catch {
      // The close handler will tear the registration down.
    }
  }, SSE_HEARTBEAT_MS);
  // Don't let the heartbeat timer keep the event loop alive on its own.
  if (typeof heartbeat.unref === "function") heartbeat.unref();

  const state: SseClientState = { res, orgs, heartbeat };
  // Replace any prior stream for this fingerprint (a reconnect supersedes).
  const prior = sseConnections.get(fingerprint);
  if (prior) {
    clearInterval(prior.heartbeat);
    unregisterListener(fingerprint);
    try { prior.res.end(); } catch { /* ignore */ }
  }
  sseConnections.set(fingerprint, state);

  // Wire delivery: fanoutEvent calls this onEvent, which writes the SSE frame.
  registerListener(fingerprint, {
    orgs,
    onEvent: (event: PeerReviewEvent) => {
      try {
        res.write(`data: ${JSON.stringify(event)}\n\n`);
      } catch {
        // Best-effort; cleanup happens on close.
      }
    },
  });

  logLine(
    "info",
    `SSE /peer/events: connected fp=${fingerprint} orgs=[${orgs.join(",")}]`,
  );

  const cleanup = (): void => {
    clearInterval(heartbeat);
    // Only tear down the registry entry if it's still ours (a reconnect may
    // have already replaced it).
    if (sseConnections.get(fingerprint) === state) {
      sseConnections.delete(fingerprint);
      unregisterListener(fingerprint);
      logLine("info", `SSE /peer/events: disconnected fp=${fingerprint}`);
    }
  };
  req.on("close", cleanup);
  res.on("close", cleanup);
}

/** Test-only: snapshot of active SSE fingerprints. */
export function __getSseConnectionsForTests(): string[] {
  return [...sseConnections.keys()];
}

/**
 * Test-only: inject a fake SSE connection into the sseConnections map so
 * that the peer-events poll worker can deliver events to it without requiring
 * a real HTTP server + auth round-trip. The injected client must supply a
 * `res.write` that captures frames and an `orgs` list for org filtering.
 * Call `__clearSseConnectionsForTests` in afterEach to clean up.
 */
export function __injectSseConnectionForTests(
  fingerprint: string,
  client: { res: ServerResponse; orgs: string[] },
): void {
  // Create a minimal heartbeat interval that does nothing (unref'd so it
  // doesn't keep the test process alive). The real cleanup path calls
  // clearInterval, so we must provide a handle.
  const heartbeat = setInterval(() => { /* noop heartbeat for test */ }, 1_000_000);
  if (typeof heartbeat.unref === "function") heartbeat.unref();
  sseConnections.set(fingerprint, { res: client.res, orgs: client.orgs, heartbeat });
}

/** Test-only: clear all SSE connections (for teardown). */
export function __clearSseConnectionsForTests(): void {
  for (const [fp, client] of sseConnections) {
    clearInterval(client.heartbeat);
    unregisterListener(fp);
    try { client.res.end(); } catch { /* ignore */ }
  }
  sseConnections.clear();
}

// ─── Server lifecycle ─────────────────────────────────────────────────

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
    // AGT-454: SSE peer-review event stream. Gated on the feature flag — when
    // disabled the endpoint is inert (404), so standard HTTP-only deploys see
    // no behaviour change.
    if (req.method === "GET" && (url === SSE_PEER_EVENTS_PATH || url.startsWith(`${SSE_PEER_EVENTS_PATH}?`))) {
      if (!resolvePeerReviewsEnabled()) {
        sendJson(res, 404, { ok: false, error: "not_found" });
        return;
      }
      handlePeerEventsRequest(req, res);
      return;
    }
    sendJson(res, 404, { ok: false, error: "not_found" });
  });
  server.listen(port, () => {
    logLine("info", `listening on :${port}`);
    // Arm the periodic-poll backstop AFTER the listen-success callback
    // — keeps the boot ordering predictable (listener up, then the
    // worker that depends on the same env-var fan-out). The worker is
    // a no-op when STAMP_PROMPTS_REPO_URL is unset, so Phase A
    // deployments see no behavior change.
    startPromptsPollWorker();
    // AGT-423: arm the trash-retention sweep (independent of Phase B; runs
    // whenever STAMP_TRASH_SWEEP_INTERVAL_SEC != 0).
    startTrashSweepWorker();
    // AGT-454: the SSE peer-review event stream (GET /peer/events) is mounted
    // inline in the request handler above, gated on resolvePeerReviewsEnabled().
    // No separate attach step is needed (it replaced the WS upgrade handler).
    // AGT-454 G3: arm the seat-TTL sweeper when peer reviews are enabled.
    startSeatSweepWorker();
    // peer-events-delivery: arm the cross-process event poll worker so SSE
    // clients receive events written by verb processes (pr-opened, re-review).
    startPeerEventsPollWorker();
  });
  // Symmetric shutdown: when the server closes (operator-driven or test
  // cleanup), stop the poll worker so the interval doesn't leak into
  // the next listener instance. `unref` already lets the process exit;
  // this is belt-and-suspenders for test reuse + future graceful-
  // shutdown supervisors.
  server.once("close", () => {
    stopPromptsPollWorker();
    stopTrashSweepWorker();
    stopSeatSweepWorker();
    stopPeerEventsPollWorker();
    // Tear down any live SSE streams so their heartbeat timers + registry
    // entries don't leak into the next listener instance (test reuse).
    __clearSseConnectionsForTests();
  });
  return server;
}
