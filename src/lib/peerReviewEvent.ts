/**
 * Shared type for peer-review events (AGT-434).
 *
 * Previously defined inline in `src/server/peerReviews.ts` (AGT-427).
 * Re-homed here so both the server-side SSH/WS handlers and the client-side
 * listener (`prListen.ts`) can import from a shared lib path without a
 * circular dependency through `src/server/`.
 *
 * `src/server/peerReviews.ts` re-exports this type for back-compat with any
 * import that still uses the old path.
 */

export interface PeerReviewEvent {
  event_type: string;
  patch_id: string;
  actor_fp: string;
  payload: object;
}
