/**
 * SSH-invoked review command, reachable as:
 *
 *   ssh -p <port> git@<host> stamp-review \
 *     --reviewer security \
 *     --org acme --repo widget-co \
 *     --base-sha <40-hex> --head-sha <40-hex> \
 *     --diff-sha256 <64-hex> \
 *     < diff.patch
 *
 * Symlinked into /home/git/git-shell-commands/ on the server image so
 * git-shell dispatches to it. Authenticates the caller via
 * SSH_USER_AUTH (sshd writes it during connection setup when
 * `ExposeAuthInfo yes` is set) and looks the fingerprint up in the
 * membership DB.
 *
 * AGT-328 lands the SCAFFOLD: the request parser, auth resolver,
 * stdin reader (with `MAX_DIFF_BYTES` cap and `--diff-sha256` cross-
 * check), the shared `runReviewPipeline` call (currently returns
 * obvious placeholders — see `src/server/reviewPipeline.ts`), and the
 * JSON response shape from design.md. The Anthropic call lands in
 * AGT-330 inside the pipeline; the real signature lands in AGT-331
 * (which also makes `approval.diff_sha256` come from the server's hash
 * of the streamed bytes rather than echoing the client's claimed
 * sha — see the verb's stdin-cross-check below, kept as a fast-fail
 * surface that rejects mismatched input before the LLM call).
 *
 * Refuses to run if:
 *
 *   - SSH_USER_AUTH is unset or has no publickey entry (no identity)
 *   - the caller isn't in users.db OR has a role below `member`
 *   - any required flag is missing / malformed
 *   - the diff content on stdin exceeds MAX_DIFF_BYTES (default 5MB)
 *   - the streamed diff's sha256 doesn't match `--diff-sha256`
 *
 * On success, prints the JSON response to stdout:
 *
 *   { "verdict": "...", "prose": "...",
 *     "approval": { ... }, "signature": "..." }
 *
 * Stderr carries human-readable diagnostics; like `stamp-mint-invite`,
 * stderr crosses the SSH boundary into the operator's terminal so the
 * prose convention is lowercase `error:` / `note:` rather than the
 * unix-style program-name prefix used in daemon logs.
 *
 * Exit codes (consumed by the future client-side SSH transport to
 * produce specific operator prose):
 *
 *   0 — success; JSON response on stdout
 *   1 — server-side config error (ExposeAuthInfo missing, etc.)
 *   2 — usage error (missing/bad argv)
 *   3 — caller's role doesn't permit reviews (below member)
 *   4 — request validation failure (diff size cap, sha mismatch)
 */

import { createHash } from "node:crypto";

import {
  findUserBySshFingerprint,
  openServerDb,
  type Role,
  type UserRow,
} from "../lib/serverDb.js";
import { readAuthenticatedPubkey } from "../lib/sshUserAuth.js";

import {
  type ParsedReviewRequest,
  resolveMaxDiffBytes,
  type ReviewPipelineResult,
  runReviewPipeline,
} from "./reviewPipeline.js";

// Read the diff-size cap once at module load so a hypothetical
// future HTTP entrypoint that imports this file shares one constant
// across all requests (operators tune via restart, never per-call).
// Today's SSH verb is one process per invocation, so the distinction
// is forward-looking — pinned at module scope to enforce the contract
// by call-site placement rather than by comment.
const MAX_DIFF_BYTES = resolveMaxDiffBytes();

// ─── Shape validators ───────────────────────────────────────────────
//
// Mirrors the validators in `src/server/promptFetch.ts` so a request
// that reaches the pipeline has already cleared the same checks the
// prompt fetch will apply. Duplicated rather than imported because
// the verb wants to fail with usage-level errors (exit 2) before the
// pipeline (and its promptFetch import) is even loaded — keeps the
// validation surface visible at this layer for code review.

const REVIEWER_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/;
const ORG_NAME_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]*$/;
const REPO_NAME_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]*$/;
const FULL_SHA_RE = /^[0-9a-f]{40}$/;
const DIFF_SHA256_RE = /^[0-9a-f]{64}$/;

/**
 * Roles permitted to invoke `stamp-review`. The Set form makes the
 * "below member" rejection structural — anything not in the allowlist
 * (a hypothetical future `Role` value, a typo, etc.) gets rejected with
 * the same clear error, no per-role branching to forget to update.
 */
const ALLOWED_ROLES: ReadonlySet<Role> = new Set<Role>(["owner", "admin", "member"]);

function fail(message: string, exitCode: number): never {
  // Lowercase prose prefix matches the CLI convention: this stderr
  // crosses the SSH boundary and lands in the operator's terminal.
  process.stderr.write(`error: ${message}\n`);
  process.exit(exitCode);
}

/** Single source of truth for the usage line. Surfaced both by the
 *  missing-flags error and by the `--help` short-circuit so the two
 *  prose paths can't drift. Trailing newline omitted; callers add
 *  their own. */
const USAGE =
  "usage: stamp-review --reviewer <name> --org <org> --repo <repo> " +
  "--base-sha <40-hex> --head-sha <40-hex> --diff-sha256 <64-hex> < diff";

// ─── parseRequest ───────────────────────────────────────────────────

/**
 * Parse the SSH verb's flag set into a structured request. Refuses on
 * malformed input rather than coercing — every shape rejection here
 * surfaces as a clean usage error to the client (exit 2) instead of
 * reaching the pipeline. The pipeline's job is to fail on real
 * conditions (no such ref, LLM error); the verb's job is to refuse
 * obviously-bad input early.
 */
export function parseRequest(argv: string[]): ParsedReviewRequest {
  let reviewer: string | undefined;
  let org: string | undefined;
  let repo: string | undefined;
  let baseSha: string | undefined;
  let headSha: string | undefined;
  let diffSha256: string | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    const takeNext = (flagName: string): string => {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("--")) {
        fail(`${flagName} requires a value`, 2);
      }
      i++;
      return next;
    };

    switch (arg) {
      case "--help":
      case "-h":
        // Help short-circuits the parser: print usage to stdout (it's
        // not an error — operators SSH'ing in to read the surface
        // shouldn't see exit 2 + stderr) and exit clean.
        process.stdout.write(USAGE + "\n");
        process.exit(0);
        break; // unreachable; satisfies no-fallthrough lint
      case "--reviewer":
        reviewer = takeNext("--reviewer");
        break;
      case "--org":
        org = takeNext("--org");
        break;
      case "--repo":
        repo = takeNext("--repo");
        break;
      case "--base-sha":
        baseSha = takeNext("--base-sha");
        break;
      case "--head-sha":
        headSha = takeNext("--head-sha");
        break;
      case "--diff-sha256":
        diffSha256 = takeNext("--diff-sha256");
        break;
      default:
        fail(`unknown flag: ${arg}`, 2);
    }
  }

  // Required-field check happens after the flag walk so the operator
  // sees a single list of what's missing on the first attempt rather
  // than having to fix one missing flag at a time.
  const missing: string[] = [];
  if (!reviewer) missing.push("--reviewer");
  if (!org) missing.push("--org");
  if (!repo) missing.push("--repo");
  if (!baseSha) missing.push("--base-sha");
  if (!headSha) missing.push("--head-sha");
  if (!diffSha256) missing.push("--diff-sha256");
  if (missing.length > 0) {
    fail(`missing required flag(s): ${missing.join(", ")}. ${USAGE}`, 2);
  }

  // Shape validation — fail loud on anything that wouldn't make it
  // through the pipeline's downstream checks. Doing the checks here
  // means the operator's terminal sees a usage-flavored error rather
  // than a pipeline-flavored one for inputs that never had a chance
  // of succeeding.
  if (!REVIEWER_NAME_RE.test(reviewer!)) {
    fail(`--reviewer ${JSON.stringify(reviewer)} has invalid shape (must match ${REVIEWER_NAME_RE.source})`, 2);
  }
  if (!ORG_NAME_RE.test(org!)) {
    fail(`--org ${JSON.stringify(org)} has invalid shape (must match ${ORG_NAME_RE.source})`, 2);
  }
  if (!REPO_NAME_RE.test(repo!)) {
    fail(`--repo ${JSON.stringify(repo)} has invalid shape (must match ${REPO_NAME_RE.source})`, 2);
  }
  if (!FULL_SHA_RE.test(baseSha!)) {
    fail(`--base-sha must be a full 40-char lowercase hex SHA (got ${JSON.stringify(baseSha)})`, 2);
  }
  if (!FULL_SHA_RE.test(headSha!)) {
    fail(`--head-sha must be a full 40-char lowercase hex SHA (got ${JSON.stringify(headSha)})`, 2);
  }
  if (!DIFF_SHA256_RE.test(diffSha256!)) {
    fail(
      `--diff-sha256 must be a bare 64-char lowercase hex sha256 (got ${JSON.stringify(diffSha256)})`,
      2,
    );
  }

  return {
    reviewer: reviewer!,
    org: org!,
    repo: repo!,
    baseSha: baseSha!,
    headSha: headSha!,
    diffSha256: diffSha256!,
  };
}

// ─── resolveAuth ────────────────────────────────────────────────────

interface AuthContext {
  caller: UserRow;
  /** The db handle the caller resolved against; held so the main
   *  function can close it in `finally`. */
  db: ReturnType<typeof openServerDb>;
}

/**
 * Read sshd's authenticated pubkey (via SSH_USER_AUTH) and look up the
 * caller in the membership DB. Mirrors the pattern in
 * `src/server/mint-invite.ts:130-154`; the structural difference is
 * the role check uses the `ALLOWED_ROLES` set so anything below
 * `member` is rejected with the same message, no per-role branching.
 *
 * Returns the resolved `UserRow` + the open DB handle (so the caller
 * can close it on exit). Aborts via `fail()` on every refusal path.
 */
function resolveAuth(): AuthContext {
  const caller = readAuthenticatedPubkey();
  if (!caller) {
    fail(
      "could not determine authenticated identity (SSH_USER_AUTH unset or " +
        "has no publickey entry). Server may be missing 'ExposeAuthInfo yes' " +
        "in sshd_config.",
      1,
    );
  }

  // skipChmod: matches mint-invite.ts — the verb runs as the git user
  // via git-shell; the DB file is root-owned and chmod would fail with
  // EPERM. entrypoint.sh already tightened perms at boot.
  const db = openServerDb({ skipChmod: true });
  const callerRow = findUserBySshFingerprint(db, caller.fingerprint);
  if (!callerRow) {
    db.close();
    fail(
      `caller fingerprint ${caller.fingerprint} is not in the membership ` +
        `DB — this should be impossible after sshd authenticated them. ` +
        `Likely cause: phase-1 env-var sync hasn't run on this server yet.`,
      1,
    );
  }
  if (!ALLOWED_ROLES.has(callerRow.role)) {
    db.close();
    fail(
      `role ${callerRow.role} is not permitted to request reviews (need member or higher)`,
      3,
    );
  }

  return { caller: callerRow, db };
}

// ─── stdin reader ───────────────────────────────────────────────────

/**
 * Read stdin in chunks, aborting the moment cumulative bytes exceed
 * `maxBytes`. Streamed rather than accumulate-then-check so a hostile
 * client can't push the server toward OOM before the cap rejects.
 *
 * Returns the assembled `Buffer` on success; calls `fail()` (exit 4)
 * the instant the cap is breached.
 */
async function readBoundedStdin(maxBytes: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunkRaw of process.stdin) {
    // process.stdin in object-mode-off (the default for binary stdin)
    // yields Buffer chunks; cast defensively in case a future Node
    // version surfaces strings under encoding hints.
    const chunk =
      typeof chunkRaw === "string" ? Buffer.from(chunkRaw, "utf8") : (chunkRaw as Buffer);
    total += chunk.length;
    if (total > maxBytes) {
      fail(
        `diff content exceeds MAX_DIFF_BYTES (${maxBytes} bytes); ` +
          `refusing to buffer further input`,
        4,
      );
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, total);
}

// ─── response shape ─────────────────────────────────────────────────

/**
 * The JSON shape design.md pins for the SSH `stamp-review` response
 * is the same four-field bag the pipeline already returns. Re-exported
 * here under a wire-format-flavored name so callers reading verb code
 * have a local-feeling alias without a duplicate type definition.
 *
 * The wrapper is just a transport envelope; the `signature` inside it
 * commits to the canonical bytes of `approval`
 * (`canonicalSerializeApproval(approval)`), NOT to this envelope's own
 * serialization. The signing call lives inside `runReviewPipeline`
 * (AGT-331); this verb is unaware of the Ed25519 mechanism.
 */
export type StampReviewResponse = ReviewPipelineResult;

// ─── main ───────────────────────────────────────────────────────────

async function main(): Promise<void> {
  // parseRequest → resolveAuth → runReviewPipeline (stubbed) →
  // emit JSON to stdout. The flow is intentionally linear so a
  // future HTTP entrypoint can fold the same steps into a request
  // handler without inheriting any stdin/stdout assumption.
  const params = parseRequest(process.argv.slice(2));
  const { caller, db } = resolveAuth();

  try {
    const diff = await readBoundedStdin(MAX_DIFF_BYTES);

    // Cross-check the streamed diff against the client's claimed
    // sha256 BEFORE invoking the pipeline. A mismatch here is either
    // a transport corruption or an attempted attestation-detached-
    // from-content attack; either way it's a clean exit-4 reject
    // rather than a pipeline-flavored failure.
    //
    // The pipeline itself rehashes the diff and uses ITS hash to bake
    // `approval.diff_sha256` into the signed bytes — this verb-level
    // check is the operator-facing fast-fail so a corrupt diff doesn't
    // burn an Anthropic API call before being rejected.
    const observedDiffSha = createHash("sha256").update(diff).digest("hex");
    if (observedDiffSha !== params.diffSha256) {
      fail(
        `diff content sha256 mismatch: --diff-sha256=${params.diffSha256} ` +
          `but server-computed sha256=${observedDiffSha}`,
        4,
      );
    }

    const result: StampReviewResponse = await runReviewPipeline({
      diff,
      params,
      caller,
    });
    process.stdout.write(JSON.stringify(result) + "\n");
  } finally {
    db.close();
  }
}

main().catch((err: unknown) => {
  // Unexpected error path — pipeline or stdin reader threw something
  // we didn't explicitly fail() on. Surface verbatim so operators see
  // the underlying cause; map to exit 1 (server-side config /
  // unexpected condition) since exit 4 is reserved for explicit
  // request-validation refusals.
  process.stderr.write(
    `error: stamp-review crashed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`,
  );
  process.exit(1);
});
