/**
 * Shared module for peer-agentic review SSH-verb endpoints (AGT-427/AGT-454).
 *
 * Provides:
 *   - Feature-gate check (`resolvePeerReviewsEnabled`)
 *   - Safety-limit parsers (`resolvePeerReviewLimit`)
 *   - Pure-crypto peer-payload signature verification (`verifyPeerPayloadSignatureFromPubkey`)
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
 * AGT-454: server is a GitHub-blind broker. All repo-access functions
 * (`bareRepoPath`, `verifyOperatorAtBase`, `verifyPeerPayloadSignature`,
 * `readTrustedKeysAtRepo`, `STAMP_BARE_REPOS_DIR`) have been removed.
 * Operator-ness @ base_sha is now verified client-side (in prListen.ts)
 * against the listener's own local clone.
 */

import { fingerprintFromPem } from "../lib/keys.js";
import { verifyBytes } from "../lib/signing.js";
export type { PeerReviewEvent } from "../lib/peerReviewEvent.js";

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

// ─── Pure-crypto peer-payload signature verification (AGT-454) ──────
//
// Replaces the old repo-access-based `verifyPeerPayloadSignature` and
// `readTrustedKeysAtRepo`. The caller carries their stamp signing pubkey
// (SPKI PEM) in the payload; the server:
//   1. Recomputes the fingerprint from the carried pubkey (fingerprintFromPem).
//   2. Rejects unless it equals the claimed fp (fp-recompute bind).
//   3. Verifies the Ed25519 signature over the canonical bytes.
//
// This triple is the entire server crypto check — zero repo access required.

/**
 * Verify a peer-payload Ed25519 signature using the pubkey carried inline in
 * the payload (AGT-454 pure-crypto path, no repo access).
 *
 * Steps:
 *   1. Recompute `fingerprintFromPem(pubkeyPem)` and reject if it ≠ `claimedFp`
 *      (prevents a pubkey/fp swap attack).
 *   2. `verifyBytes(pubkeyPem, canonicalBytes, signatureBase64)`.
 *
 * Returns `{ ok: true }` on success, `{ ok: false, reason }` on any failure.
 * Callers treat any non-OK as an auth failure and reject the request.
 */
export function verifyPeerPayloadSignatureFromPubkey(
  pubkeyPem: string,
  claimedFp: string,
  canonicalBytes: Buffer,
  signatureBase64: string,
): { ok: true } | { ok: false; reason: string } {
  // Step 1: recompute fingerprint from the carried pubkey.
  let recomputedFp: string;
  try {
    recomputedFp = fingerprintFromPem(pubkeyPem);
  } catch (err) {
    return {
      ok: false,
      reason: `carried pubkey is not a valid SPKI PEM: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  if (recomputedFp !== claimedFp) {
    return {
      ok: false,
      reason: `fp mismatch: recomputed ${recomputedFp} from carried pubkey but payload claims ${claimedFp}`,
    };
  }

  // Step 2: verify the Ed25519 signature.
  let valid: boolean;
  try {
    valid = verifyBytes(pubkeyPem, canonicalBytes, signatureBase64);
  } catch (err) {
    return {
      ok: false,
      reason: `signature verification threw: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  if (!valid) {
    return { ok: false, reason: "signature verification failed" };
  }
  return { ok: true };
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

// PeerReviewEvent is re-exported from src/lib/peerReviewEvent.ts (AGT-434).
// The re-export at the top of this file (via `export type { PeerReviewEvent }`)
// preserves back-compat for any import that still uses this path.
import type { PeerReviewEvent } from "../lib/peerReviewEvent.js";

// Module-scoped registry: fingerprint → listener handle.
const listenerRegistry = new Map<string, ListenerHandle>();

/**
 * Register (or replace) a listener for the given fingerprint. Org slugs in
 * `handle.orgs` are lowercased on storage so that `fanoutEvent` comparisons
 * are case-insensitive by construction. Callers may pass any-case orgs.
 */
export function registerListener(
  fingerprint: string,
  handle: ListenerHandle,
): void {
  listenerRegistry.set(fingerprint, {
    ...handle,
    orgs: handle.orgs.map((o) => o.toLowerCase()),
  });
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
 * Org matching is case-insensitive: the incoming `org` is lowercased on
 * entry; listener orgs are stored in lowercase via `parseOrgQuery`. This
 * means a listener subscribed as "micromediasites" will receive events
 * broadcast under "MicroMediaSites" (and vice versa).
 *
 * STUB: cross-process delivery is not implemented (see module-level note).
 */
export function fanoutEvent(org: string, event: PeerReviewEvent): number {
  const orgLower = org.toLowerCase();
  let notified = 0;
  for (const [, handle] of listenerRegistry) {
    if (handle.orgs.includes(orgLower)) {
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

/**
 * Fan out an event to seat-holders with optional reviewer_filter support
 * (AGT-431). `seatMap` is an array of `{ fp, seat }` pairs for the patch;
 * `reviewerFilter` is a list of fingerprints to restrict delivery to (empty
 * = deliver to all seat-holders). Each delivered event gets a per-receiver
 * `seat` field injected into the payload so the listener knows which seat it
 * holds. Returns the fingerprints of the notified listeners.
 *
 * Deliberately a sibling helper, not a replacement, so the existing
 * `fanoutToSeatHolders` caller (tests + pr-opened path) is unaffected.
 */
export function fanoutToSeatHoldersFiltered(
  seatMap: Array<{ fp: string; seat: 1 | 2 }>,
  event: Omit<PeerReviewEvent, "payload"> & { payload: object },
  reviewerFilter: string[],
): string[] {
  const notified: string[] = [];
  for (const { fp, seat } of seatMap) {
    // Apply reviewer_filter: skip if filter is non-empty and fp not listed.
    if (reviewerFilter.length > 0 && !reviewerFilter.includes(fp)) continue;
    const handle = listenerRegistry.get(fp);
    if (handle) {
      try {
        const enrichedEvent: PeerReviewEvent = {
          ...event,
          payload: { ...(event.payload as Record<string, unknown>), seat },
        };
        handle.onEvent(enrichedEvent);
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

