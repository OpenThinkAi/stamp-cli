/**
 * Canonical SSH verb names for the peer-agentic-review protocol.
 *
 * These are the names that git-shell-commands exposes on the stamp server
 * (see server/Dockerfile, the `ln -s … /home/git/git-shell-commands/…` block).
 * Client code MUST use these constants — NOT bare string literals — so that
 * the guard test in `tests/peerSshVerbs.test.ts` can assert client↔server
 * agreement at the source level without any network I/O.
 *
 * Adding or renaming a verb here will fail `npm test` until the Dockerfile
 * symlink block is updated to match (and vice-versa).
 */

export const PEER_SSH_VERBS = {
  prOpened: "stamp-pr-opened",
  subscribe: "stamp-subscribe",
  claimSeat: "stamp-claim-seat",
  heartbeat: "stamp-heartbeat",
  releaseSeat: "stamp-release-seat",
  reReviewRequest: "stamp-re-review-request",
} as const;

export type PeerSshVerb = (typeof PEER_SSH_VERBS)[keyof typeof PEER_SSH_VERBS];
