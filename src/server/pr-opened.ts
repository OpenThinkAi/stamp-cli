/**
 * SSH verb: broadcast a newly-opened PR to peer-review listeners.
 *
 * Reachable as `git@<host> pr-opened` with the JSON payload on stdin.
 *
 * Payload fields (JSON, max MAX_PR_OPENED_BODY_BYTES):
 *   repo, patch_id, base_sha, head_sha, requested_by_fp,
 *   paths_changed (string[]), title, body, pr_url, signature
 *
 * Auth: verifies the Ed25519 `signature` against the repo's
 * `.stamp/trusted-keys/manifest.yml` at `base_sha`, confirming
 * `requested_by_fp` has `operator` capability.
 *
 * Rate limit: 60/hr per author (`pr-opened` rate bucket) via AGT-420
 * `checkAndConsumeToken`.
 *
 * On success:
 *   - persists a row to `peer_review_patches`
 *   - appends a `pr-opened` row to `peer_review_events`
 *   - fans out the event to any in-process subscribed listeners for the
 *     event's org (in-process stub only — see peerReviews.ts for scope note)
 *   - emits `{ ok: true, patch_id }` to stdout
 *
 * Returns `{ ok: false, error: "peer_reviews_not_configured" }` when
 * STAMP_PEER_REVIEWS_ENABLED is not exactly "1".
 *
 * Exit codes:
 *   0 — success (or feature-not-configured)
 *   1 — server-side / unexpected error
 *   4 — request validation failure (oversize body, bad shape, auth failure,
 *        excess paths)
 *   5 — rate limited
 */

import {
  appendEvent,
  checkAndConsumeToken,
  findUserBySshFingerprint,
  insertPatch,
  openServerDb,
  touchLastSeen,
} from "../lib/serverDb.js";
import { loadServerEnvFile } from "../lib/serverEnvFile.js";
import { readAuthenticatedPubkey } from "../lib/sshUserAuth.js";

import {
  bareRepoPath,
  fanoutEvent,
  notConfiguredResponse,
  resolvePeerReviewLimit,
  resolvePeerReviewsEnabled,
  verifyOperatorAtBase,
  PR_OPENED_RATE_CAP_DEFAULT,
  MAX_PR_OPENED_BODY_BYTES_DEFAULT,
  MAX_PATHS_CHANGED_DEFAULT,
} from "./peerReviews.js";

function fail(message: string, exitCode: number): never {
  process.stderr.write(`error: ${message}\n`);
  process.exit(exitCode);
}

async function readBoundedStdin(maxBytes: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunkRaw of process.stdin) {
    const chunk =
      typeof chunkRaw === "string" ? Buffer.from(chunkRaw, "utf8") : (chunkRaw as Buffer);
    total += chunk.length;
    if (total > maxBytes) {
      fail(
        `pr-opened payload exceeds MAX_PR_OPENED_BODY_BYTES (${maxBytes} bytes)`,
        4,
      );
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, total);
}

interface PrOpenedPayload {
  repo: string;
  patch_id: string;
  base_sha: string;
  head_sha: string;
  requested_by_fp: string;
  paths_changed: string[];
  title: string;
  body: string;
  pr_url: string;
  signature: string;
}

function parsePayload(raw: Buffer): PrOpenedPayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch (e) {
    fail(`pr-opened payload is not valid JSON: ${e instanceof Error ? e.message : String(e)}`, 4);
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    fail("pr-opened payload must be a JSON object", 4);
  }

  const p = parsed as Record<string, unknown>;
  const required = [
    "repo", "patch_id", "base_sha", "head_sha", "requested_by_fp",
    "paths_changed", "title", "body", "pr_url", "signature",
  ];
  for (const k of required) {
    if (!(k in p)) fail(`pr-opened payload missing required field: ${k}`, 4);
  }

  if (typeof p["repo"] !== "string") fail("repo must be a string", 4);
  if (typeof p["patch_id"] !== "string") fail("patch_id must be a string", 4);
  if (typeof p["base_sha"] !== "string" || !/^[0-9a-f]{40}$/.test(p["base_sha"]!))
    fail("base_sha must be a 40-char lowercase hex SHA", 4);
  if (typeof p["head_sha"] !== "string" || !/^[0-9a-f]{40}$/.test(p["head_sha"]!))
    fail("head_sha must be a 40-char lowercase hex SHA", 4);
  if (typeof p["requested_by_fp"] !== "string") fail("requested_by_fp must be a string", 4);
  if (!Array.isArray(p["paths_changed"]) || !p["paths_changed"].every((x) => typeof x === "string"))
    fail("paths_changed must be an array of strings", 4);
  if (typeof p["title"] !== "string") fail("title must be a string", 4);
  if (typeof p["body"] !== "string") fail("body must be a string", 4);
  if (typeof p["pr_url"] !== "string") fail("pr_url must be a string", 4);
  if (typeof p["signature"] !== "string") fail("signature must be a string", 4);

  return p as unknown as PrOpenedPayload;
}

async function main(): Promise<void> {
  loadServerEnvFile();

  if (!resolvePeerReviewsEnabled()) {
    process.stderr.write(
      "note: STAMP_PEER_REVIEWS_ENABLED is not set; pr-opened is a no-op\n",
    );
    process.stdout.write(notConfiguredResponse() + "\n");
    process.exit(0);
  }

  const maxBodyBytes = resolvePeerReviewLimit(
    "MAX_PR_OPENED_BODY_BYTES",
    MAX_PR_OPENED_BODY_BYTES_DEFAULT,
  );
  const maxPaths = resolvePeerReviewLimit(
    "MAX_PATHS_CHANGED",
    MAX_PATHS_CHANGED_DEFAULT,
  );
  const rateCap = resolvePeerReviewLimit(
    "PR_OPENED_RATE_CAP",
    PR_OPENED_RATE_CAP_DEFAULT,
  );

  // Authenticate the SSH caller (the operator sending the PR broadcast).
  const caller = readAuthenticatedPubkey();
  if (!caller) {
    fail(
      "could not determine authenticated identity (SSH_USER_AUTH unset or " +
        "has no publickey entry). Server may be missing 'ExposeAuthInfo yes' " +
        "in sshd_config.",
      1,
    );
  }

  const db = openServerDb({ skipChmod: true });
  try {
    const callerRow = findUserBySshFingerprint(db, caller.fingerprint);
    if (!callerRow) {
      fail(
        `caller fingerprint ${caller.fingerprint} is not in the membership DB`,
        1,
      );
    }
    touchLastSeen(db, callerRow.id);

    // AGT-427: rate-limit pr-opened broadcasts (60/hr per author, per design doc).
    if (!checkAndConsumeToken(db, callerRow.id, "pr-opened", rateCap)) {
      fail(
        `rate limit exceeded: ${callerRow.short_name} is over the pr-opened cap (${rateCap}/hour)`,
        5,
      );
    }

    const raw = await readBoundedStdin(maxBodyBytes);
    const payload = parsePayload(raw);

    // Security: bind the payload fingerprint to the SSH-authenticated caller.
    // Without this check any legitimate operator can impersonate another by
    // supplying a different `requested_by_fp` in the JSON payload.
    if (payload.requested_by_fp !== caller.fingerprint) {
      fail(
        `requested_by_fp in payload (${payload.requested_by_fp}) does not match ` +
          `the SSH-authenticated caller's fingerprint (${caller.fingerprint})`,
        4,
      );
    }

    if (payload.paths_changed.length > maxPaths) {
      fail(
        `paths_changed has ${payload.paths_changed.length} entries — exceeds MAX_PATHS_CHANGED (${maxPaths})`,
        4,
      );
    }

    // Validate repo format before path resolution to prevent path traversal.
    if (!/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(payload.repo)) {
      fail(
        `repo must be <org>/<name> with alphanumeric/dash/dot/underscore only (got ${JSON.stringify(payload.repo)})`,
        4,
      );
    }

    // Auth: verify operator capability at base_sha via manifest.
    const gitDir = bareRepoPath(payload.repo);
    const authResult = verifyOperatorAtBase(
      gitDir,
      payload.base_sha,
      payload.requested_by_fp,
    );
    if (!authResult.ok) {
      fail(`auth failure: ${authResult.reason}`, 4);
    }

    // Persist patch row + event.
    const now = Date.now();
    insertPatch(db, {
      patch_id: payload.patch_id,
      requested_by_fp: payload.requested_by_fp,
      base_sha: payload.base_sha,
      head_sha: payload.head_sha,
      repo: payload.repo,
    }, now);

    const { signature: _sig, ...payloadWithoutSig } = payload;
    appendEvent(db, payload.patch_id, "pr-opened", payload.requested_by_fp, payloadWithoutSig, now);

    // Fan out to subscribed listeners for this org (in-process stub only).
    const org = payload.repo.split("/")[0] ?? payload.repo;
    fanoutEvent(org, {
      event_type: "pr-opened",
      patch_id: payload.patch_id,
      actor_fp: payload.requested_by_fp,
      payload: payloadWithoutSig,
    });

    process.stdout.write(
      JSON.stringify({ ok: true, patch_id: payload.patch_id }) + "\n",
    );
  } finally {
    db.close();
  }
}

main().catch((err: unknown) => {
  process.stderr.write(
    `error: pr-opened crashed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`,
  );
  process.exit(1);
});
