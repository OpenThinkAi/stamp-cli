/**
 * Boot-time entrypoint: ensure the server's Ed25519 review-signing key
 * exists and (on first generation) advertise its fingerprint loudly so
 * the operator can commit it to `.stamp/trusted-keys/manifest.yml`.
 *
 * Runs once per container boot, as root, from /entrypoint.sh — after
 * stamp-seed-users, before sshd is exec'd. The bootstrap is gated on
 * `ANTHROPIC_API_KEY`: if the env var is unset, review capability is
 * disabled by design and we skip the keygen entirely. This matches the
 * design doc's contract ("Absent ANTHROPIC_API_KEY → stamp-server runs
 * as today, rejecting review requests with a clear 'review capability
 * not configured' error. Reviews are opt-in.").
 *
 * Path resolution (in priority order):
 *   1. REVIEW_SIGNING_KEY_PATH env var — full path override, lets
 *      operators stash the key in a platform-specific mount (secrets
 *      manager fuse, etc.) without touching code.
 *   2. $STAMP_STATE_DIR/review-signing-key.pem — the convention the
 *      design doc names ("review signing key lives at
 *      $STATE_DIR/review-signing-key.pem"). The shell var
 *      STAMP_STATE_DIR is exported by entrypoint.sh and points at
 *      /srv/git/.stamp-state on the standard container; we honor it
 *      so a future entrypoint that moves the state dir doesn't
 *      require an in-code update here.
 *   3. /srv/git/.stamp-state/review-signing-key.pem — last-resort
 *      default for invocations outside the container (rare; tests
 *      always override path 1).
 *
 * Output streams follow the standard CLI convention: prose and
 * operational status (including the first-boot banner) go to stdout;
 * errors go to stderr with the `error: ` prefix. The first-boot
 * fingerprint advertisement is operator-instruction prose, not an
 * error, so it lives on stdout. On re-boot we print a one-line
 * "reused existing key" log so operators see something during normal
 * boots without re-spamming the loud block.
 *
 * Failure handling:
 *   - ReviewSigningKeyError (wrong mode, unreadable, unparseable):
 *     print to stderr with the `error: ` prefix and exit 1.
 *     Entrypoint.sh treats this as a fatal startup failure — the
 *     trust model requires a stable server identity, and silently
 *     regenerating on a wrong-mode file would rotate that identity
 *     without operator consent.
 *   - Generic FS errors (write fail on volume not mounted, etc.):
 *     bubble with original message + non-zero exit. These are
 *     orchestration bugs the operator needs to see verbatim.
 */

import { ensureReviewSigningKey, ReviewSigningKeyError } from "../lib/reviewSigningKey.js";

const DEFAULT_STATE_DIR = "/srv/git/.stamp-state";
const DEFAULT_KEY_FILENAME = "review-signing-key.pem";

function resolveKeyPath(): string {
  const override = process.env["REVIEW_SIGNING_KEY_PATH"];
  if (override && override.length > 0) return override;
  const stateDir = process.env["STAMP_STATE_DIR"] ?? DEFAULT_STATE_DIR;
  // Path join via string concat — Node's `path.join` would normalize
  // out a trailing slash but the input is always a directory and the
  // filename is a literal, so concatenation with an explicit "/" keeps
  // the code obvious.
  return stateDir.replace(/\/+$/, "") + "/" + DEFAULT_KEY_FILENAME;
}

function printGeneratedBanner(fingerprint: string, publicKeyPath: string): void {
  // Visually distinct border + the instruction line that AC #2
  // requires. The instruction text matches the exact phrasing in the
  // ticket so operators searching their logs for the docs cue can
  // find it. Border uses U+2500 (BOX DRAWINGS LIGHT HORIZONTAL) to
  // match the established structural-marker convention used by
  // `stamp status`, `stamp review`, etc. Goes to stdout — this is
  // operator-instruction prose, not an error.
  const border =
    "────────────────────────────────────────────────────────────────────";
  const lines = [
    "",
    border,
    "  STAMP-SERVER: review-signing key generated (first boot)",
    border,
    "  fingerprint:  " + fingerprint,
    "  public key:   " + publicKeyPath,
    "",
    "  Next step — commit this fingerprint to",
    "  `.stamp/trusted-keys/manifest.yml` with `capabilities: [server]`",
    "  in every repo that delegates reviews to this server.",
    "",
    "  See `docs/plans/server-attested-reviews.md` (Trust model section)",
    "  for the manifest entry format. The pubkey is also fetchable via",
    "  `ssh git@<host> stamp-server-pubkey --review-signing`.",
    border,
    "",
  ];
  process.stdout.write(lines.join("\n"));
}

function main(): void {
  const apiKey = process.env["ANTHROPIC_API_KEY"];
  if (!apiKey || apiKey.length === 0) {
    // Review capability disabled — design contract says do nothing.
    // We still emit a brief log line so operators investigating "why
    // is there no review key on disk?" can find the explanation in
    // boot logs.
    console.log(
      "stamp-bootstrap-review-key: ANTHROPIC_API_KEY unset; review capability disabled, skipping keygen",
    );
    return;
  }

  const privateKeyPath = resolveKeyPath();

  let result;
  try {
    result = ensureReviewSigningKey({ privateKeyPath });
  } catch (err) {
    if (err instanceof ReviewSigningKeyError) {
      // stderr + lowercase `error: ` prefix per the codebase
      // convention; the domain-specific message body (which path,
      // what's wrong, what to do) is already constructed by
      // ReviewSigningKeyError.
      process.stderr.write("error: " + err.message + "\n");
      process.exit(1);
    }
    throw err;
  }

  if (result.created) {
    printGeneratedBanner(result.fingerprint, result.publicKeyPath);
  } else {
    console.log(
      `stamp-bootstrap-review-key: reusing existing review-signing key at ${result.privateKeyPath} (fingerprint: ${result.fingerprint})`,
    );
  }
}

main();
