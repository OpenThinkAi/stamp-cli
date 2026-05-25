/**
 * `stamp pr ping [<pr-url>] [--reviewer <name>...]` — send a signed
 * `re-review-request` to the stamp-server for an open PR (AGT-431).
 *
 * Resolves the `patch_id`:
 *   - With `<pr-url>`: looks up the PR's headRefName + baseRefName via
 *     `gh pr view --json` then calls `patchIdForSpan`.
 *   - Without: looks up the current branch's PR via `gh pr view --json`
 *     then calls `patchIdForRevspec`.
 *
 * Forwards `--reviewer <name>` values verbatim in the payload's
 * `reviewer_filter` (server resolves names → fingerprints server-side).
 *
 * Exit codes (AC #4):
 *   0  — success (including the case where no active seat-holders exist)
 *   1  — auth failure: operator key not found, or fingerprint ≠ requested_by_fp
 *        (server exit 5 → "not_author")
 *   2  — reserved for arg-parse errors by Commander convention (never set here)
 *   3  — patch_id resolution failed: no PR detectable from HEAD, or <pr-url>
 *        does not resolve to a known patch_id (server exit 4)
 */

import { spawnSync } from "node:child_process";
import { findRepoRoot } from "../lib/paths.js";
import { loadUserKeypair, type Keypair } from "../lib/keys.js";
import { signBytes } from "../lib/signing.js";
import { patchIdForRevspec } from "../lib/patchId.js";
import { loadServerConfig } from "../lib/serverConfig.js";
import type { ServerConfig } from "../lib/serverConfig.js";
import {
  callReReviewRequest,
  type ReReviewRequestResult,
  type SshSpawnFn,
} from "../lib/seatClient.js";

// ─── Options ─────────────────────────────────────────────────────────

export interface PrPingOptions {
  /** Optional positional: explicit PR URL. When absent, resolved from HEAD. */
  prUrl?: string;
  /** `--reviewer <name>` values (repeatable). Forwarded verbatim to server. */
  reviewer: string[];
  /** `--server <host:port>` override. */
  server?: string;
  /** Test-only: inject a fake SSH spawn function. */
  _sshSpawnForTest?: SshSpawnFn;
  /** Test-only: inject a keypair directly. `null` → simulate missing keypair. */
  _keypairForTest?: Keypair | null;
  /** Test-only: inject a fake `gh pr view` result for the HEAD PR lookup. */
  _ghPrViewForTest?: () => { stdout: string; status: number };
  /** Test-only: inject a fake patch-id result (skips git operations). */
  _patchIdForTest?: () => { patch_id: string; base_sha: string; head_sha: string } | null;
  /** Test-only: inject a fake server config. */
  _serverConfigForTest?: ServerConfig | null;
}

// ─── Implementation ───────────────────────────────────────────────────

/**
 * Core implementation. Exposed for testing (tests call this directly with
 * injected seams; Commander calls it via `runPrPing`).
 */
export async function runPrPing(opts: PrPingOptions): Promise<void> {
  // ─── Load keypair ──────────────────────────────────────────────────
  const keypair: Keypair | null =
    opts._keypairForTest !== undefined
      ? (opts._keypairForTest as Keypair | null)
      : loadUserKeypair();

  if (!keypair) {
    process.stderr.write(
      `error: no stamp signing key found at ~/.stamp/keys/ed25519. ` +
        `Run 'stamp keys generate' to create one.\n`,
    );
    process.exit(1);
  }

  // ─── Resolve server config ─────────────────────────────────────────
  let serverCfg: ServerConfig | null;
  if (opts._serverConfigForTest !== undefined) {
    serverCfg = opts._serverConfigForTest;
  } else if (opts.server) {
    const m = opts.server.trim().match(/^([^:]+):(\d+)$/);
    if (!m) {
      process.stderr.write(
        `error: --server must be <host>:<port> (got ${JSON.stringify(opts.server)})\n`,
      );
      process.exit(1);
    }
    const port = Number(m[2]);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      process.stderr.write(
        `error: --server port must be 1..65535 (got ${JSON.stringify(m[2])})\n`,
      );
      process.exit(1);
    }
    serverCfg = { host: m[1]!, port, user: "git", repoRootPrefix: "/srv/git" };
  } else {
    serverCfg = loadServerConfig();
  }

  if (!serverCfg) {
    process.stderr.write(
      `error: no stamp-server configured. Run 'stamp server config <host:port>' or pass --server.\n`,
    );
    process.exit(1);
  }

  // ─── Resolve patch_id ─────────────────────────────────────────────
  // Two paths: explicit <pr-url> or HEAD-based lookup.
  let patchId: string;

  if (opts._patchIdForTest !== undefined) {
    // Injected seam: skips all git/gh operations.
    const fakePatch = opts._patchIdForTest();
    if (!fakePatch) {
      process.stderr.write(
        `error: patch_id resolution failed — no PR detectable from HEAD.\n`,
      );
      process.exit(3);
    }
    patchId = fakePatch.patch_id;
  } else if (opts.prUrl) {
    // Explicit PR URL: extract headRef + baseRef via `gh pr view`.
    const ghView = spawnSync(
      "gh",
      ["pr", "view", opts.prUrl, "--json", "headRefName,baseRefName"],
      {
        stdio: ["ignore", "pipe", "pipe"],
        encoding: "utf8",
        cwd: findRepoRoot(),
      },
    );
    if (ghView.status !== 0) {
      process.stderr.write(
        `error: 'gh pr view' failed for ${opts.prUrl} — cannot resolve patch_id.\n` +
          (ghView.stderr?.trim() ? `  ${ghView.stderr.trim()}\n` : ""),
      );
      process.exit(3);
    }
    let prMeta: { headRefName?: string; baseRefName?: string };
    try {
      prMeta = JSON.parse(ghView.stdout ?? "{}") as { headRefName?: string; baseRefName?: string };
    } catch {
      process.stderr.write(
        `error: could not parse 'gh pr view' output for ${opts.prUrl}.\n`,
      );
      process.exit(3);
    }
    const { headRefName, baseRefName } = prMeta;
    if (!headRefName || !baseRefName) {
      process.stderr.write(
        `error: 'gh pr view' did not return headRefName/baseRefName for ${opts.prUrl}.\n`,
      );
      process.exit(3);
    }
    try {
      const info = patchIdForRevspec(
        `origin/${baseRefName}..origin/${headRefName}`,
        findRepoRoot(),
      );
      patchId = info.patch_id;
    } catch (err) {
      process.stderr.write(
        `error: could not compute patch_id for ${opts.prUrl}: ` +
          `${err instanceof Error ? err.message : String(err)}\n`,
      );
      process.exit(3);
    }
  } else {
    // HEAD-based: look up current branch's PR.
    const repoRoot = findRepoRoot();
    const ghView = spawnSync(
      "gh",
      ["pr", "view", "--json", "headRefName,baseRefName,url"],
      {
        stdio: ["ignore", "pipe", "pipe"],
        encoding: "utf8",
        cwd: repoRoot,
      },
    );
    if (ghView.status !== 0) {
      process.stderr.write(
        `error: no PR found for current HEAD — run from a branch with an open PR, ` +
          `or pass <pr-url>.\n` +
          (ghView.stderr?.trim() ? `  ${ghView.stderr.trim()}\n` : ""),
      );
      process.exit(3);
    }
    let prMeta: { headRefName?: string; baseRefName?: string; url?: string };
    try {
      prMeta = JSON.parse(ghView.stdout ?? "{}") as {
        headRefName?: string;
        baseRefName?: string;
        url?: string;
      };
    } catch {
      process.stderr.write(`error: could not parse 'gh pr view' output.\n`);
      process.exit(3);
    }
    const { headRefName, baseRefName } = prMeta;
    if (!headRefName || !baseRefName) {
      process.stderr.write(
        `error: 'gh pr view' did not return headRefName/baseRefName for current HEAD.\n`,
      );
      process.exit(3);
    }
    try {
      const info = patchIdForRevspec(`origin/${baseRefName}..${headRefName}`, repoRoot);
      patchId = info.patch_id;
    } catch (err) {
      process.stderr.write(
        `error: could not compute patch_id for current HEAD: ` +
          `${err instanceof Error ? err.message : String(err)}\n`,
      );
      process.exit(3);
    }
  }

  // ─── Sign the payload ─────────────────────────────────────────────
  // Canonical form: JSON.stringify of the fields (same signing discipline
  // as other verbs — payload body without `signature`).
  const payloadBody = {
    patch_id: patchId,
    requester_fp: keypair.fingerprint,
    reviewer_filter: opts.reviewer,
  };
  const canonicalBytes = Buffer.from(JSON.stringify(payloadBody), "utf8");
  const signature = signBytes(keypair.privateKeyPem, canonicalBytes);

  // ─── Call server ──────────────────────────────────────────────────
  const callResult: ReReviewRequestResult = await callReReviewRequest({
    patch_id: patchId,
    requester_fp: keypair.fingerprint,
    reviewer_filter: opts.reviewer,
    signature,
    serverConfig: serverCfg,
    _sshSpawnForTest: opts._sshSpawnForTest,
  });

  // ─── Map result → exit code ───────────────────────────────────────
  if (callResult.ok) {
    if (callResult.seat_holders_notified === 0) {
      process.stderr.write(
        `note: no active seat-holders to notify for patch_id ${patchId}\n`,
      );
    } else {
      process.stdout.write(
        `✓ sent re-review-requested to ${callResult.seat_holders_notified} seat-holder(s)\n`,
      );
    }
    process.exit(0);
  }

  if (callResult.reason === "not_author") {
    // AC #4 exit 1: auth failure / operator is not author.
    process.stderr.write(
      `error: re-review request refused — operator fingerprint does not match ` +
        `the original PR author.\n` +
        `  ${callResult.serverStderr || callResult.message}\n`,
    );
    process.exit(1);
  }

  if (callResult.reason === "patch_not_found") {
    // AC #4 exit 3: patch_id resolution failed (server exit 4).
    process.stderr.write(
      `error: patch_id ${patchId} not found on the stamp-server — ` +
        `was the PR opened with 'stamp pr open'?\n` +
        `  ${callResult.serverStderr || callResult.message}\n`,
    );
    process.exit(3);
  }

  if (callResult.reason === "peer_reviews_not_configured") {
    // Server has peer reviews disabled — informational, exit 0.
    process.stderr.write(
      `note: stamp-server has peer reviews disabled; re-review request acknowledged\n`,
    );
    process.exit(0);
  }

  // Generic failure.
  process.stderr.write(
    `error: re-review-request failed — ${callResult.message}\n`,
  );
  process.exit(1);
}
