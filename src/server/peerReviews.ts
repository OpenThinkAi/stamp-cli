/**
 * Shared module for peer-agentic review SSH-verb endpoints (AGT-427).
 *
 * Provides:
 *   - Feature-gate check (`resolvePeerReviewsEnabled`)
 *   - Safety-limit parsers (`resolvePeerReviewLimit`)
 *   - Bare-repo path resolution (`bareRepoPath`)
 *   - Operator-at-base-sha manifest verification (`verifyOperatorAtBase`)
 *   - In-memory listener registry + synchronous fanout
 *     NOTE: The in-memory registry is scoped to a SINGLE PROCESS. Each
 *     SSH-verb invocation is its own short-lived process (the AGT-420
 *     invariant), so a subscriber recorded in one process cannot receive
 *     events from a different process's `pr-opened` fanout. This is a
 *     documented limitation of the SSH-verb transport. WebSocket transport
 *     (Step h, AGT-434) replaces this synchronous in-process stub with
 *     real cross-process delivery. Until then, fanout over SSH is a no-op
 *     in production against real separate-process subscribers.
 *
 * IMPORTANT: `verifyOperatorAtBase` re-introduces a server-side manifest
 * read that the live `stamp-review` verb deliberately dropped (AGT-370 moved
 * that read operator-side). Keep this function SCOPED HERE — do NOT refactor
 * it into a shared place that `reviewPipeline.ts` could accidentally pick up.
 */

import path from "node:path";

import { showAtRef } from "../lib/git.js";
import {
  parseManifest,
  resolveCapability,
  MANIFEST_RELATIVE_PATH,
} from "../lib/trustedKeysManifest.js";
import { verifyBytes } from "../lib/signing.js";

// ─── Feature gate ───────────────────────────────────────────────────

/**
 * Returns true when peer-agentic reviews are enabled on this server.
 * Requires `STAMP_PEER_REVIEWS_ENABLED=1` in the environment; any other
 * value (including absent) treats the feature as dark.
 *
 * The SQLite migration (peer_review_patches + peer_review_events) is NOT
 * gated — it runs on every boot regardless, so an operator enabling the
 * feature on a running deploy finds the tables already present.
 * Only the SSH-verb behaviour is gated here.
 */
export function resolvePeerReviewsEnabled(): boolean {
  return process.env["STAMP_PEER_REVIEWS_ENABLED"] === "1";
}

// ─── Safety limits ──────────────────────────────────────────────────

/**
 * Defensive positive-int env reader for peer-review limits (AGT-427).
 * Bad/absent value falls back to the provided default — a typo must NOT
 * crash the server boot or verb path (the AGT-411 discipline).
 */
export function resolvePeerReviewLimit(envName: string, def: number): number {
  const raw = process.env[envName];
  if (!raw) return def;
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 ? n : def;
}

/** Max request-body bytes for `pr-opened` (default 64 KB). */
export const MAX_PR_OPENED_BODY_BYTES_DEFAULT = 65536;
/** Max `paths_changed` entries in a `pr-opened` payload (default 1000). */
export const MAX_PATHS_CHANGED_DEFAULT = 1000;
/** Max org subscriptions per `subscribe` call (default 10). */
export const MAX_SUBSCRIBED_ORGS_DEFAULT = 10;
/** Seat TTL in seconds (default 600 = 10 min). Used by future sweep. */
export const SEAT_TTL_SECONDS_DEFAULT = 600;
/** Rate-limit cap for `pr-opened` per author (60/hr per design doc). */
export const PR_OPENED_RATE_CAP_DEFAULT = 60;

// ─── Bare-repo path resolution ──────────────────────────────────────

/** Server-side bare-repo layout: `/srv/git/<org>/<repo>.git`.
 *  Matches the `new-stamp-repo` and `delete-stamp-repo` convention. */
export function bareRepoPath(repo: string): string {
  // `repo` is expected to be `<org>/<name>` (e.g. "acme/widget-co").
  // Callers must validate the shape before calling — we don't sanitise here.
  return path.join("/srv/git", `${repo}.git`);
}

// ─── Operator-at-base-sha manifest verification ─────────────────────

/**
 * Verify that `fingerprint` appears in the repo's `.stamp/trusted-keys/manifest.yml`
 * at `base_sha` with the `operator` capability.
 *
 * Returns `{ ok: true }` on success, or `{ ok: false, reason }` on any
 * failure (manifest missing/unparseable, fingerprint absent, capability not
 * operator).
 *
 * SCOPING NOTE: This is the only caller of `showAtRef` for the manifest on
 * the server side. The live `stamp-review` verb is deliberately manifest-
 * blind (AGT-370). Keep this wrapper in peerReviews.ts ONLY.
 */
export function verifyOperatorAtBase(
  repoGitDir: string,
  base_sha: string,
  fingerprint: string,
): { ok: true } | { ok: false; reason: string } {
  let manifestYaml: string;
  try {
    manifestYaml = showAtRef(base_sha, MANIFEST_RELATIVE_PATH, repoGitDir);
  } catch (err) {
    return {
      ok: false,
      reason: `manifest not found at ${base_sha}:${MANIFEST_RELATIVE_PATH}: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  const manifest = parseManifest(manifestYaml);
  if (!manifest) {
    return {
      ok: false,
      reason: `manifest at ${base_sha} failed to parse`,
    };
  }

  const caps = resolveCapability(manifest, fingerprint);
  if (!caps) {
    return {
      ok: false,
      reason: `fingerprint ${fingerprint} is not in manifest at ${base_sha}`,
    };
  }

  if (!caps.includes("operator")) {
    return {
      ok: false,
      reason: `fingerprint ${fingerprint} has capabilities [${caps.join(", ")}] at ${base_sha} — 'operator' required`,
    };
  }

  return { ok: true };
}

// ─── Payload signature verification ─────────────────────────────────

/**
 * Verify an Ed25519 signature over the canonical form of a JSON payload.
 * The canonical form is JSON.stringify with sorted keys (shallow — callers
 * own deep-sort if needed). Returns true on valid signature, false otherwise.
 *
 * The signing convention for peer-review payloads: the client signs
 * `JSON.stringify(payloadWithoutSignature)` as UTF-8 bytes.
 */
export function verifyPayloadSignature(
  pubkeyPem: string,
  payloadWithoutSig: object,
  signatureBase64: string,
): boolean {
  const data = Buffer.from(JSON.stringify(payloadWithoutSig), "utf8");
  try {
    return verifyBytes(pubkeyPem, data, signatureBase64);
  } catch {
    return false;
  }
}

// ─── In-memory listener registry ────────────────────────────────────
//
// NOTE: This registry is scoped to a single process. Because each SSH-verb
// invocation is its own short-lived process (AGT-420 invariant), a
// subscriber registered in one process cannot receive events emitted by
// a different process's `pr-opened` verb. This is intentional for the
// SSH-verb spike — the registry and synchronous fanout satisfy AC 7's
// letter (in-process mock subscriber for tests). Real cross-process delivery
// is out of scope until WebSocket transport (Step h, AGT-434) replaces this
// stub. A code comment like this one is the documented handoff point.

export interface ListenerHandle {
  /** Org slugs this listener is subscribed to. */
  orgs: string[];
  /** Callback invoked synchronously by fanout in the same process. */
  onEvent: (event: PeerReviewEvent) => void;
}

export interface PeerReviewEvent {
  event_type: string;
  patch_id: string;
  actor_fp: string;
  payload: object;
}

// Module-scoped registry: fingerprint → listener handle.
const listenerRegistry = new Map<string, ListenerHandle>();

/** Register (or replace) a listener for the given fingerprint. */
export function registerListener(
  fingerprint: string,
  handle: ListenerHandle,
): void {
  listenerRegistry.set(fingerprint, handle);
}

/** Unregister a listener (used by subscribe-verb teardown / tests). */
export function unregisterListener(fingerprint: string): void {
  listenerRegistry.delete(fingerprint);
}

/** Retrieve a listener handle by fingerprint (null when not registered). */
export function getListener(fingerprint: string): ListenerHandle | null {
  return listenerRegistry.get(fingerprint) ?? null;
}

/**
 * Fan out an event synchronously to all in-process listeners that are
 * subscribed to the event's org. `org` is derived from the `repo` field
 * (`<org>/<repo>`). Returns the count of listeners notified.
 *
 * STUB: cross-process delivery is not implemented (see module-level note).
 */
export function fanoutEvent(org: string, event: PeerReviewEvent): number {
  let notified = 0;
  for (const [, handle] of listenerRegistry) {
    if (handle.orgs.includes(org)) {
      try {
        handle.onEvent(event);
      } catch {
        // Listener errors must not abort the caller's transaction.
      }
      notified++;
    }
  }
  return notified;
}

/**
 * Fan out an event synchronously to the listeners that currently hold seats
 * for a given patch. Used by `re-review-request` to notify active reviewers.
 * Returns the fingerprints of the notified listeners.
 */
export function fanoutToSeatHolders(
  seatHolders: (string | null)[],
  event: PeerReviewEvent,
): string[] {
  const notified: string[] = [];
  for (const fp of seatHolders) {
    if (!fp) continue;
    const handle = listenerRegistry.get(fp);
    if (handle) {
      try {
        handle.onEvent(event);
        notified.push(fp);
      } catch {
        // Listener errors must not abort the caller.
      }
    }
  }
  return notified;
}

/** Clear the in-memory registry (test teardown helper). */
export function clearListenerRegistry(): void {
  listenerRegistry.clear();
}

// ─── Structured error response helpers ──────────────────────────────

/** Emit the "feature not configured" response (AC 8). */
export function notConfiguredResponse(): string {
  return JSON.stringify({ ok: false, error: "peer_reviews_not_configured" });
}
