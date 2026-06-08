/**
 * Canonical SSH verb names for the peer-agentic-review protocol.
 *
 * AGT-453: the six seat-protocol verbs (subscribe, claim-seat, heartbeat,
 * release-seat, re-review-request, register-extra) have been migrated to
 * HTTP POST endpoints and their SSH handlers retired. Only `prOpened`
 * remains as an SSH verb — it is the broadcaster path (not seat protocol)
 * and is intentionally out of scope for this migration.
 *
 * The constant is kept here (rather than inlined) so the guard test in
 * `tests/peerSshVerbs.test.ts` can assert client↔server agreement at the
 * source level without any network I/O.
 *
 * Adding or renaming a verb here will fail `npm test` until the Dockerfile
 * symlink block is updated to match (and vice-versa).
 */

export const PEER_SSH_VERBS = {
  prOpened: "stamp-pr-opened",
} as const;

export type PeerSshVerb = (typeof PEER_SSH_VERBS)[keyof typeof PEER_SSH_VERBS];
