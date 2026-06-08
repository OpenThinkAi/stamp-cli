/**
 * Client-side HTTP transport for the five peer-review seat verbs (AGT-453):
 *   claim-seat / heartbeat / release-seat / re-review-request / register-extra
 *
 * Replaces the former SSH-subprocess transport (see AGT-429 / AGT-451).
 * Each function posts to the corresponding HTTP endpoint on the stamp server
 * using the signed-timestamp auth pattern from GET /peer/events, extended with
 * a body-binding canonical string:
 *
 *   peer-<verb>\n<x-stamp-timestamp>\n<sha256-hex(body)>
 *
 * The public call signatures and return types are unchanged so call sites in
 * prListen.ts and prPing.ts require no edits.
 *
 * Test seam: `HttpFetchFn` replaces the old `SshSpawnFn` — inject via the
 * `_fetchForTest` field on each input object.
 */

import { createHash } from "node:crypto";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import type { ServerConfig } from "./serverConfig.js";
import { signBytes } from "./signing.js";

// ─── Re-export SshSpawnFn for back-compat ─────────────────────────────
//
// prListen.ts and prPing.ts import `SshSpawnFn` from this module for their
// test-seam type annotations. To avoid a cascade of import-site changes we
// re-export a compatibility type alias.  The new seam is HttpFetchFn below.

/** @deprecated Use HttpFetchFn instead — SshSpawnFn is kept only for
 *  back-compat with test files that reference the name. Will be removed
 *  once those tests are updated to the HTTP seam. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type SshSpawnFn = (...args: any[]) => any;

// ─── HTTP fetch seam ─────────────────────────────────────────────────

export interface HttpFetchResult {
  status: number;
  body: string;
}

/**
 * Test-only injection seam.  Matches the signature of the internal `doFetch`
 * helper so tests can intercept any POST without a real network.
 */
export type HttpFetchFn = (
  url: string,
  headers: Record<string, string>,
  bodyJson: string,
) => Promise<HttpFetchResult>;

// ─── HTTP helpers ─────────────────────────────────────────────────────

/**
 * Build the base HTTP URL for the stamp server from a ServerConfig.
 * Requires `cfg.httpUrl` — callers that have no `httpUrl` set cannot
 * reach the HTTP seat endpoints (they must configure `http_url` in
 * ~/.stamp/server.yml).
 */
function serverHttpBase(cfg: ServerConfig): string {
  if (!cfg.httpUrl) {
    throw new Error(
      "stamp server config is missing `http_url` — required for HTTP seat-protocol " +
      "endpoints. Add `http_url: https://<your-server>` to ~/.stamp/server.yml.",
    );
  }
  return cfg.httpUrl.replace(/\/$/, "");
}

/**
 * Build the canonical bytes the client signs for a POST /peer/<verb> request.
 * Matches the server's `postCanonicalBytes` in http-server.ts.
 */
function postCanonicalBytes(verb: string, timestamp: string, bodyHex: string): Buffer {
  return Buffer.from(`peer-${verb}\n${timestamp}\n${bodyHex}`, "utf8");
}

/**
 * Post a JSON body to a peer endpoint with stamp-key signed-timestamp auth
 * headers.  Returns `{ status, body }`.
 *
 * Signs: `peer-<verb>\n<timestamp>\n<sha256-hex(bodyJson)>` using the
 * caller's stamp private key.
 */
async function doFetch(
  url: string,
  headers: Record<string, string>,
  bodyJson: string,
): Promise<HttpFetchResult> {
  const parsed = new URL(url);
  const requestFn = parsed.protocol === "https:" ? httpsRequest : httpRequest;
  const bodyBuf = Buffer.from(bodyJson, "utf8");

  return new Promise<HttpFetchResult>((resolve, reject) => {
    const req = requestFn(
      parsed,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Content-Length": String(bodyBuf.length),
          ...headers,
        },
      },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk: string) => { body += chunk; });
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
      },
    );
    req.on("error", reject);
    req.write(bodyBuf);
    req.end();
  });
}

/**
 * Build the stamp-key signed-timestamp auth headers for a POST /peer/<verb>.
 * Requires:
 *   - `privateKeyPem`: stamp signing private key (Ed25519 PKCS#8 PEM)
 *   - `publicKeyPem`: corresponding SPKI PEM (sent as x-stamp-pubkey)
 *   - `verb`: the endpoint verb name (e.g. "claim-seat")
 *   - `bodyJson`: the serialised JSON body (for sha256 binding)
 */
function buildAuthHeaders(
  privateKeyPem: string,
  publicKeyPem: string,
  verb: string,
  bodyJson: string,
): Record<string, string> {
  const timestamp = new Date().toISOString();
  const bodyHex = createHash("sha256").update(Buffer.from(bodyJson, "utf8")).digest("hex");
  const canonical = postCanonicalBytes(verb, timestamp, bodyHex);
  const signature = signBytes(privateKeyPem, canonical);
  return {
    "x-stamp-pubkey": Buffer.from(publicKeyPem, "utf8").toString("base64"),
    "x-stamp-timestamp": timestamp,
    "x-stamp-signature": signature,
  };
}

// ─── Shared keypair type reference ────────────────────────────────────
//
// Each input interface carries privateKeyPem + publicKeyPem directly to
// avoid a circular import with keys.ts.  Call sites (prListen.ts,
// prPing.ts) already have the Keypair object and can spread the fields.

// ─── claim-seat ───────────────────────────────────────────────────────

/** Claim-seat rejection reasons parsed from the server's 409 response body. */
export type ClaimRejectionReason =
  | "seats_full"
  | "author_cannot_claim_own_pr"
  | "already_holds_other_seat"
  | "unknown";

export interface ClaimSeatSuccess {
  ok: true;
  seat: number;
  patch_id: string;
}

export interface ClaimSeatRejected {
  ok: false;
  reason: "claim_rejected";
  claimRejectionReason: ClaimRejectionReason;
  message: string;
  serverStderr: string;
}

export interface ClaimSeatFailure {
  ok: false;
  reason: "claim_failed" | "peer_reviews_not_configured";
  message: string;
  serverStderr: string;
}

export type ClaimSeatResult = ClaimSeatSuccess | ClaimSeatRejected | ClaimSeatFailure;

export interface ClaimSeatInput {
  patch_id: string;
  claimant_fp: string;
  base_sha: string;
  repo: string;
  /** SPKI PEM of the stamp signing key (AGT-454). Included in canonical signed bytes. */
  pubkey: string;
  signature: string;
  serverConfig: ServerConfig;
  /** @deprecated SSH spawn seam — ignored by the HTTP transport. */
  _sshSpawnForTest?: SshSpawnFn;
  /** Test-only: inject a fake HTTP fetch to avoid real network calls. */
  _fetchForTest?: HttpFetchFn;
  /** Private key PEM for signing HTTP canonical bytes. Passed by prListen.ts. */
  _privateKeyPemForHttp?: string;
  /** Public key PEM for x-stamp-pubkey header. Passed by prListen.ts. */
  _publicKeyPemForHttp?: string;
}

/** Parse the known rejection reasons from a claim-seat 409 error string. */
function parseClaimRejectionReason(error: string): ClaimRejectionReason {
  if (error === "seats_full") return "seats_full";
  if (error === "author_cannot_claim_own_pr") return "author_cannot_claim_own_pr";
  if (error === "already_holds_other_seat") return "already_holds_other_seat";
  return "unknown";
}

export async function callClaimSeat(input: ClaimSeatInput): Promise<ClaimSeatResult> {
  const fetchFn = input._fetchForTest ?? doFetch;
  // When a test fetch seam is injected, use a placeholder base URL — the
  // seam intercepts before any real network call and ignores the host.
  let base: string;
  if (input._fetchForTest) {
    base = "http://test-seam";
  } else {
    try {
      base = serverHttpBase(input.serverConfig);
    } catch (err) {
      return {
        ok: false, reason: "claim_failed",
        message: err instanceof Error ? err.message : String(err),
        serverStderr: "",
      };
    }
  }

  const bodyJson = JSON.stringify({
    patch_id: input.patch_id,
    claimant_fp: input.claimant_fp,
    base_sha: input.base_sha,
    repo: input.repo,
    pubkey: input.pubkey,
    signature: input.signature,
  });

  const authHeaders = input._privateKeyPemForHttp
    ? buildAuthHeaders(input._privateKeyPemForHttp, input.pubkey, "claim-seat", bodyJson)
    : {};

  let result: HttpFetchResult;
  try {
    result = await fetchFn(`${base}/peer/claim-seat`, authHeaders, bodyJson);
  } catch (err) {
    return {
      ok: false, reason: "claim_failed",
      message: `HTTP fetch failed: ${err instanceof Error ? err.message : String(err)}`,
      serverStderr: "",
    };
  }

  if (result.status === 404) {
    return {
      ok: false, reason: "peer_reviews_not_configured",
      message: "stamp-server has peer reviews disabled",
      serverStderr: "",
    };
  }

  let obj: Record<string, unknown>;
  try {
    obj = JSON.parse(result.body) as Record<string, unknown>;
  } catch {
    return {
      ok: false, reason: "claim_failed",
      message: `stamp-server returned malformed JSON: ${JSON.stringify(result.body.slice(0, 200))}`,
      serverStderr: "",
    };
  }

  if (result.status === 409) {
    const error = typeof obj.error === "string" ? obj.error : "unknown";
    const claimRejectionReason = parseClaimRejectionReason(error);
    return {
      ok: false,
      reason: "claim_rejected",
      claimRejectionReason,
      message: `claim rejected: ${error}`,
      serverStderr: "",
    };
  }

  if (result.status !== 200) {
    return {
      ok: false, reason: "claim_failed",
      message: `stamp-server claim-seat returned status ${result.status}: ${JSON.stringify(result.body.slice(0, 200))}`,
      serverStderr: "",
    };
  }

  if (obj.ok === true) {
    const seat = typeof obj.seat === "number" ? obj.seat : 1;
    const patch_id = typeof obj.patch_id === "string" ? obj.patch_id : input.patch_id;
    return { ok: true, seat, patch_id };
  }

  if (obj.ok === false && obj.error === "peer_reviews_not_configured") {
    return {
      ok: false, reason: "peer_reviews_not_configured",
      message: "stamp-server has peer reviews disabled",
      serverStderr: "",
    };
  }

  const errMsg = typeof obj.error === "string" ? obj.error : JSON.stringify(obj);
  return {
    ok: false, reason: "claim_failed",
    message: `stamp-server returned error: ${errMsg}`,
    serverStderr: "",
  };
}

// ─── heartbeat ────────────────────────────────────────────────────────

export interface HeartbeatSuccess {
  ok: true;
  seat: number;
  patch_id: string;
}

export interface HeartbeatFailure {
  ok: false;
  reason: "heartbeat_failed" | "peer_reviews_not_configured";
  message: string;
  serverStderr: string;
}

export type HeartbeatResult = HeartbeatSuccess | HeartbeatFailure;

export interface HeartbeatInput {
  patch_id: string;
  claimant_fp: string;
  signature: string;
  serverConfig: ServerConfig;
  /** @deprecated SSH spawn seam — ignored by the HTTP transport. */
  _sshSpawnForTest?: SshSpawnFn;
  /** Test-only: inject a fake HTTP fetch. */
  _fetchForTest?: HttpFetchFn;
  /** Private key PEM for signing HTTP canonical bytes. */
  _privateKeyPemForHttp?: string;
  /** Public key PEM for x-stamp-pubkey header. */
  _publicKeyPemForHttp?: string;
}

export async function callHeartbeat(input: HeartbeatInput): Promise<HeartbeatResult> {
  const fetchFn = input._fetchForTest ?? doFetch;
  let base: string;
  if (input._fetchForTest) {
    base = "http://test-seam";
  } else {
    try {
      base = serverHttpBase(input.serverConfig);
    } catch (err) {
      return {
        ok: false, reason: "heartbeat_failed",
        message: err instanceof Error ? err.message : String(err),
        serverStderr: "",
      };
    }
  }

  const bodyJson = JSON.stringify({
    patch_id: input.patch_id,
    claimant_fp: input.claimant_fp,
    signature: input.signature,
  });

  const authHeaders = input._privateKeyPemForHttp && input._publicKeyPemForHttp
    ? buildAuthHeaders(input._privateKeyPemForHttp, input._publicKeyPemForHttp, "heartbeat", bodyJson)
    : {};

  let result: HttpFetchResult;
  try {
    result = await fetchFn(`${base}/peer/heartbeat`, authHeaders, bodyJson);
  } catch (err) {
    return {
      ok: false, reason: "heartbeat_failed",
      message: `HTTP fetch failed: ${err instanceof Error ? err.message : String(err)}`,
      serverStderr: "",
    };
  }

  if (result.status === 404) {
    return {
      ok: false, reason: "peer_reviews_not_configured",
      message: "stamp-server has peer reviews disabled",
      serverStderr: "",
    };
  }

  let obj: Record<string, unknown>;
  try {
    obj = JSON.parse(result.body) as Record<string, unknown>;
  } catch {
    return {
      ok: false, reason: "heartbeat_failed",
      message: `stamp-server returned malformed JSON: ${JSON.stringify(result.body.slice(0, 200))}`,
      serverStderr: "",
    };
  }

  if (result.status !== 200) {
    return {
      ok: false, reason: "heartbeat_failed",
      message: `stamp-server heartbeat returned status ${result.status}: ${typeof obj.error === "string" ? obj.error : result.body.slice(0, 200)}`,
      serverStderr: "",
    };
  }

  if (obj.ok === true) {
    const seat = typeof obj.seat === "number" ? obj.seat : 1;
    const patch_id = typeof obj.patch_id === "string" ? obj.patch_id : input.patch_id;
    return { ok: true, seat, patch_id };
  }

  const errMsg = typeof obj.error === "string" ? obj.error : JSON.stringify(obj);
  return {
    ok: false, reason: "heartbeat_failed",
    message: `stamp-server returned error: ${errMsg}`,
    serverStderr: "",
  };
}

// ─── release-seat ─────────────────────────────────────────────────────

export interface ReleaseSeatSuccess {
  ok: true;
  released: boolean;
  patch_id: string;
}

export interface ReleaseSeatFailure {
  ok: false;
  reason: "release_failed" | "peer_reviews_not_configured";
  message: string;
  serverStderr: string;
}

export type ReleaseSeatResult = ReleaseSeatSuccess | ReleaseSeatFailure;

export interface ReleaseSeatInput {
  patch_id: string;
  claimant_fp: string;
  signature: string;
  serverConfig: ServerConfig;
  /** @deprecated SSH spawn seam — ignored by the HTTP transport. */
  _sshSpawnForTest?: SshSpawnFn;
  /** Test-only: inject a fake HTTP fetch. */
  _fetchForTest?: HttpFetchFn;
  /** Private key PEM for signing HTTP canonical bytes. */
  _privateKeyPemForHttp?: string;
  /** Public key PEM for x-stamp-pubkey header. */
  _publicKeyPemForHttp?: string;
}

export async function callReleaseSeat(input: ReleaseSeatInput): Promise<ReleaseSeatResult> {
  const fetchFn = input._fetchForTest ?? doFetch;
  let base: string;
  if (input._fetchForTest) {
    base = "http://test-seam";
  } else {
    try {
      base = serverHttpBase(input.serverConfig);
    } catch (err) {
      return {
        ok: false, reason: "release_failed",
        message: err instanceof Error ? err.message : String(err),
        serverStderr: "",
      };
    }
  }

  const bodyJson = JSON.stringify({
    patch_id: input.patch_id,
    claimant_fp: input.claimant_fp,
    signature: input.signature,
  });

  const authHeaders = input._privateKeyPemForHttp && input._publicKeyPemForHttp
    ? buildAuthHeaders(input._privateKeyPemForHttp, input._publicKeyPemForHttp, "release-seat", bodyJson)
    : {};

  let result: HttpFetchResult;
  try {
    result = await fetchFn(`${base}/peer/release-seat`, authHeaders, bodyJson);
  } catch (err) {
    return {
      ok: false, reason: "release_failed",
      message: `HTTP fetch failed: ${err instanceof Error ? err.message : String(err)}`,
      serverStderr: "",
    };
  }

  if (result.status === 404) {
    return {
      ok: false, reason: "peer_reviews_not_configured",
      message: "stamp-server has peer reviews disabled",
      serverStderr: "",
    };
  }

  let obj: Record<string, unknown>;
  try {
    obj = JSON.parse(result.body) as Record<string, unknown>;
  } catch {
    return {
      ok: false, reason: "release_failed",
      message: `stamp-server returned malformed JSON: ${JSON.stringify(result.body.slice(0, 200))}`,
      serverStderr: "",
    };
  }

  if (result.status !== 200) {
    return {
      ok: false, reason: "release_failed",
      message: `stamp-server release-seat returned status ${result.status}: ${typeof obj.error === "string" ? obj.error : result.body.slice(0, 200)}`,
      serverStderr: "",
    };
  }

  if (obj.ok === true) {
    const released = obj.released === true;
    const patch_id = typeof obj.patch_id === "string" ? obj.patch_id : input.patch_id;
    return { ok: true, released, patch_id };
  }

  const errMsg = typeof obj.error === "string" ? obj.error : JSON.stringify(obj);
  return {
    ok: false, reason: "release_failed",
    message: `stamp-server returned error: ${errMsg}`,
    serverStderr: "",
  };
}

// ─── re-review-request ────────────────────────────────────────────────

export interface ReReviewRequestSuccess {
  ok: true;
  patch_id: string;
  seat_holders_notified: number;
}

export interface ReReviewRequestFailure {
  ok: false;
  reason: "not_author" | "patch_not_found" | "re_review_failed" | "peer_reviews_not_configured";
  message: string;
  serverStderr: string;
}

export type ReReviewRequestResult = ReReviewRequestSuccess | ReReviewRequestFailure;

export interface ReReviewRequestInput {
  patch_id: string;
  requester_fp: string;
  /** Raw reviewer short_names forwarded verbatim; resolved server-side. */
  reviewer_filter: string[];
  /** SPKI PEM of the stamp signing key (AGT-454). Included in canonical signed bytes. */
  pubkey: string;
  signature: string;
  serverConfig: ServerConfig;
  /** @deprecated SSH spawn seam — ignored by the HTTP transport. */
  _sshSpawnForTest?: SshSpawnFn;
  /** Test-only: inject a fake HTTP fetch. */
  _fetchForTest?: HttpFetchFn;
  /** Private key PEM for signing HTTP canonical bytes. */
  _privateKeyPemForHttp?: string;
}

export async function callReReviewRequest(
  input: ReReviewRequestInput,
): Promise<ReReviewRequestResult> {
  const fetchFn = input._fetchForTest ?? doFetch;
  let base: string;
  if (input._fetchForTest) {
    base = "http://test-seam";
  } else {
    try {
      base = serverHttpBase(input.serverConfig);
    } catch (err) {
      return {
        ok: false, reason: "re_review_failed",
        message: err instanceof Error ? err.message : String(err),
        serverStderr: "",
      };
    }
  }

  const bodyJson = JSON.stringify({
    patch_id: input.patch_id,
    requester_fp: input.requester_fp,
    reviewer_filter: input.reviewer_filter,
    pubkey: input.pubkey,
    signature: input.signature,
  });

  const authHeaders = input._privateKeyPemForHttp
    ? buildAuthHeaders(input._privateKeyPemForHttp, input.pubkey, "re-review-request", bodyJson)
    : {};

  let result: HttpFetchResult;
  try {
    result = await fetchFn(`${base}/peer/re-review-request`, authHeaders, bodyJson);
  } catch (err) {
    return {
      ok: false, reason: "re_review_failed",
      message: `HTTP fetch failed: ${err instanceof Error ? err.message : String(err)}`,
      serverStderr: "",
    };
  }

  let obj: Record<string, unknown>;
  try {
    obj = JSON.parse(result.body) as Record<string, unknown>;
  } catch {
    return {
      ok: false, reason: "re_review_failed",
      message: `stamp-server returned malformed JSON: ${JSON.stringify(result.body.slice(0, 200))}`,
      serverStderr: "",
    };
  }

  // 404 can mean either: feature disabled (error: "not_found") or patch not found.
  // Discriminate by the error field in the body.
  if (result.status === 404) {
    if (obj.error === "not_found") {
      return {
        ok: false, reason: "peer_reviews_not_configured",
        message: "stamp-server has peer reviews disabled",
        serverStderr: "",
      };
    }
    return {
      ok: false, reason: "patch_not_found",
      message: `patch_id resolution failed or payload invalid. ${typeof obj.error === "string" ? obj.error : ""}`,
      serverStderr: "",
    };
  }

  if (result.status === 403) {
    return {
      ok: false, reason: "not_author",
      message: `re-review refused: caller is not the PR author. ${typeof obj.reason === "string" ? obj.reason : ""}`,
      serverStderr: "",
    };
  }

  if (result.status !== 200) {
    return {
      ok: false, reason: "re_review_failed",
      message: `stamp-server re-review-request returned status ${result.status}: ${typeof obj.error === "string" ? obj.error : result.body.slice(0, 200)}`,
      serverStderr: "",
    };
  }

  if (obj.ok === true) {
    const seat_holders_notified =
      typeof obj.seat_holders_notified === "number" ? obj.seat_holders_notified : 0;
    const patch_id =
      typeof obj.patch_id === "string" ? obj.patch_id : input.patch_id;
    return { ok: true, patch_id, seat_holders_notified };
  }

  const errMsg = typeof obj.error === "string" ? obj.error : JSON.stringify(obj);
  return {
    ok: false, reason: "re_review_failed",
    message: `stamp-server returned error: ${errMsg}`,
    serverStderr: "",
  };
}

// ─── register-extra ──────────────────────────────────────────────────
//
// Migrated from SSH stamp-register-extra (AGT-451) to HTTP POST in this PR
// (AGT-453). Same business logic as the SSH verb; only transport changes.

export interface RegisterExtraSuccess {
  ok: true;
  patch_id: string;
}

export interface RegisterExtraFailure {
  ok: false;
  reason: "register_failed" | "register_rejected" | "peer_reviews_not_configured";
  message: string;
  serverStderr: string;
}

export type RegisterExtraResult = RegisterExtraSuccess | RegisterExtraFailure;

export interface RegisterExtraInput {
  patch_id: string;
  claimant_fp: string;
  base_sha: string;
  repo: string;
  /** SPKI PEM of the stamp signing key (AGT-454). Included in canonical signed bytes. */
  pubkey: string;
  signature: string;
  serverConfig: ServerConfig;
  /** @deprecated SSH spawn seam — ignored by the HTTP transport. */
  _sshSpawnForTest?: SshSpawnFn;
  /** Test-only: inject a fake HTTP fetch. */
  _fetchForTest?: HttpFetchFn;
  /** Private key PEM for signing HTTP canonical bytes. */
  _privateKeyPemForHttp?: string;
  /** Public key PEM for x-stamp-pubkey header (unused for register-extra, kept for API symmetry). */
  _publicKeyPemForHttp?: string;
}

export async function callRegisterExtra(
  input: RegisterExtraInput,
): Promise<RegisterExtraResult> {
  const fetchFn = input._fetchForTest ?? doFetch;
  let base: string;
  if (input._fetchForTest) {
    base = "http://test-seam";
  } else {
    try {
      base = serverHttpBase(input.serverConfig);
    } catch (err) {
      return {
        ok: false, reason: "register_failed",
        message: err instanceof Error ? err.message : String(err),
        serverStderr: "",
      };
    }
  }

  const bodyJson = JSON.stringify({
    patch_id: input.patch_id,
    claimant_fp: input.claimant_fp,
    base_sha: input.base_sha,
    repo: input.repo,
    pubkey: input.pubkey,
    signature: input.signature,
  });

  const authHeaders = input._privateKeyPemForHttp
    ? buildAuthHeaders(input._privateKeyPemForHttp, input.pubkey, "register-extra", bodyJson)
    : {};

  let result: HttpFetchResult;
  try {
    result = await fetchFn(`${base}/peer/register-extra`, authHeaders, bodyJson);
  } catch (err) {
    return {
      ok: false, reason: "register_failed",
      message: `HTTP fetch failed: ${err instanceof Error ? err.message : String(err)}`,
      serverStderr: "",
    };
  }

  if (result.status === 404) {
    return {
      ok: false, reason: "peer_reviews_not_configured",
      message: "stamp-server has peer reviews disabled",
      serverStderr: "",
    };
  }

  let obj: Record<string, unknown>;
  try {
    obj = JSON.parse(result.body) as Record<string, unknown>;
  } catch {
    return {
      ok: false, reason: "register_failed",
      message: `stamp-server returned malformed JSON: ${JSON.stringify(result.body.slice(0, 200))}`,
      serverStderr: "",
    };
  }

  if (result.status === 409) {
    // author_cannot_review_own_pr or similar rejection.
    const error = typeof obj.error === "string" ? obj.error : "unknown";
    return {
      ok: false, reason: "register_rejected",
      message: `register-extra rejected: ${error}`,
      serverStderr: "",
    };
  }

  if (result.status === 429) {
    return {
      ok: false, reason: "register_rejected",
      message: "register-extra rejected: rate limit exceeded",
      serverStderr: "",
    };
  }

  if (result.status !== 200) {
    return {
      ok: false, reason: "register_failed",
      message: `stamp-server register-extra returned status ${result.status}: ${typeof obj.error === "string" ? obj.error : result.body.slice(0, 200)}`,
      serverStderr: "",
    };
  }

  if (obj.ok === true) {
    const patch_id = typeof obj.patch_id === "string" ? obj.patch_id : input.patch_id;
    return { ok: true, patch_id };
  }

  const errMsg = typeof obj.error === "string" ? obj.error : JSON.stringify(obj);
  return {
    ok: false, reason: "register_failed",
    message: `stamp-server returned error: ${errMsg}`,
    serverStderr: "",
  };
}

// ─── subscribe (removed from protocol; kept as no-op stub) ────────────
//
// callSubscribe was the SSH subscribe verb client. POST /peer/subscribe was
// dropped from the server-side (plan-gate decision: no stub needed; older
// clients can't reach a server that's also dropped the SSH verb). The
// function is removed; any lingering call site would be a compile error.
// This comment documents the intentional removal for future readers.
