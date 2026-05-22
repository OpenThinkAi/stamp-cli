/**
 * Fetch the stamp server's review-signing public key over SSH.
 *
 * Wraps the same wire protocol as `stamp server pubkey --review-signing`
 * (see src/commands/server.ts:fetchServerPubkey): one SSH call to the
 * server-side `stamp-server-pubkey --review-signing` wrapper, which
 * returns the SPKI PEM bytes of the server's review-signing key. Trust
 * model is TOFU — same as the rest of stamp's SSH surface. Operators
 * harden out-of-band by independently verifying the server's host-key
 * fingerprint via the docs walkthrough.
 *
 * Pulled into its own module so the WS2 init flow can mock the SSH call
 * via the `__setFetchForTests` seam (mirrors the Phase B
 * `__setRefreshFnForTests` pattern) without spinning up a real SSH
 * fixture.
 */

import { spawnSync } from "node:child_process";

import type { ServerConfig } from "./serverConfig.js";

/** Function signature the migration flow uses to retrieve the server's
 *  review-signing pubkey. Production wires it to the real SSH call;
 *  tests replace it via `__setFetchForTests`. */
export type ReviewSigningPubkeyFetcher = (server: ServerConfig) => string;

let activeFetcher: ReviewSigningPubkeyFetcher = realFetch;

/**
 * Public entry point. Calls the active fetcher (real SSH in production,
 * a fake in tests). Returns the SPKI PEM string emitted by
 * `stamp-server-pubkey --review-signing`. Throws with an actionable
 * message if the SSH call fails.
 */
export function fetchServerReviewSigningPubkey(server: ServerConfig): string {
  return activeFetcher(server);
}

/** Test seam: replace the fetcher. Tests MUST call the returned restore
 *  fn in a `finally` so a later test doesn't inherit the fake. */
export function __setFetchForTests(
  fn: ReviewSigningPubkeyFetcher,
): () => void {
  const prev = activeFetcher;
  activeFetcher = fn;
  return () => {
    activeFetcher = prev;
  };
}

/** Production SSH call. Mirrors `fetchServerPubkey` in src/commands/server.ts:
 *  same `--` guard before destination, same error-message shape. */
function realFetch(server: ServerConfig): string {
  const sshArgs = [
    "-p",
    String(server.port),
    "--",
    `${server.user}@${server.host}`,
    "stamp-server-pubkey",
    "--review-signing",
  ];
  const result = spawnSync("ssh", sshArgs, {
    stdio: ["ignore", "pipe", "inherit"],
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(
      `stamp server pubkey --review-signing failed (exit ${result.status}) against ` +
        `${server.user}@${server.host}:${server.port}. If you see ` +
        `"command not found", the server image predates the review-signing ` +
        `feature — redeploy it first. If you see ` +
        `"review-signing pubkey not found", the server hasn't booted ` +
        `with stamp-bootstrap-review-key yet (ANTHROPIC_API_KEY may be unset).`,
    );
  }
  // The server emits the SPKI PEM bytes verbatim; do NOT trim — a PEM
  // file ends with a newline by convention and the manifest fingerprint
  // computation is whitespace-insensitive but the on-disk .pub file
  // should round-trip cleanly.
  return result.stdout;
}
