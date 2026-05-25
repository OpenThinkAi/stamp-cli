/**
 * `stamp pr open <branch>` — open a GitHub PR and broadcast a signed
 * `pr-opened` event to the stamp-server in one opt-in command (AGT-428).
 *
 * Three-step sequence (strictly in order):
 *   0. Gate: verify `gh` is on PATH (exit 127 if absent)
 *   1. `git push origin <branch>` (exit 1 on failure; passes git stderr through)
 *   2. `gh pr create --head <branch> --fill` (exit 3 on failure; notes push landed)
 *   3. Build + sign + broadcast signed `pr-opened` payload to stamp-server (exit 4 on failure)
 *
 * On full success: prints three `✓` glyph lines to stderr and exits 0.
 *
 * Exit codes (AC #10):
 *   0   — success (or server has peer reviews disabled — informational only)
 *   1   — `git push` failed
 *   2   — (reserved for arg-parse errors by stamp convention; not used here)
 *   3   — `gh pr create` failed (push already landed)
 *   4   — broadcast to stamp-server failed (PR is live on GitHub)
 *   127 — `gh` not found on PATH
 */

import { spawnSync } from "node:child_process";
import { findRepoRoot } from "../lib/paths.js";
import { loadUserKeypair, type Keypair } from "../lib/keys.js";
import { signBytes } from "../lib/signing.js";
import {
  canonicalSerializePrOpened,
  type PrOpenedPayloadBody,
} from "../lib/attestationV4.js";
import { patchIdForRevspec } from "../lib/patchId.js";
import { deriveOrgRepoFromRemote } from "../lib/remote.js";
import {
  broadcastPrOpened,
  type BroadcastPrOpenedInput,
  type SshSpawnFn,
} from "../lib/prOpenedClient.js";
import { loadServerConfig } from "../lib/serverConfig.js";

export interface PrOpenOptions {
  branch: string;
  /** `--server <host:port>` override for the stamp-server endpoint. */
  server?: string;
  /** Test-only: override the default remote (defaults to "origin"). */
  remote?: string;
  /** Test-only: inject a fake SSH spawn function to avoid real network calls. */
  _sshSpawnForTest?: SshSpawnFn;
  /** Test-only: inject a fake `gh pr create` spawn result. */
  _ghCreateForTest?: () => { stdout: string; status: number; stderr: string };
  /** Test-only: inject a fake `git push` spawn result. */
  _gitPushForTest?: () => { status: number };
  /** Test-only: inject a fake `gh pr view` spawn result. */
  _ghViewForTest?: () => { stdout: string; status: number };
  /** Test-only: inject a fake `git diff --name-only` result. */
  _gitDiffNamesForTest?: () => { stdout: string; status: number };
  /** Test-only: inject a fake patch-id result to skip git operations. */
  _patchIdForTest?: () => { patch_id: string; base_sha: string; head_sha: string };
  /** Test-only: inject a keypair directly to skip reading from disk. */
  _keypairForTest?: import("../lib/keys.js").Keypair;
  /** Test-only: inject org/repo to skip `git remote get-url` calls. */
  _orgRepoForTest?: { org: string; repo: string };
  /** Test-only: simulate `gh --version` result to test the 127 path. */
  _ghVersionForTest?: () => { error?: Error; status: number };
}

export async function runPrOpen(opts: PrOpenOptions): Promise<void> {
  const { branch } = opts;
  const remote = opts.remote ?? "origin";

  // ─── Step 0: gate on `gh` presence ─────────────────────────────────
  // AC #3: exit 127 before any git/gh work if `gh` is not on PATH.
  // We only 127 on ENOENT / "not on PATH"; installed-but-unauthenticated
  // surfaces later as a gh pr create failure → exit 3.
  const ghVersionResult = opts._ghVersionForTest
    ? opts._ghVersionForTest()
    : spawnSync("gh", ["--version"], {
        stdio: ["ignore", "pipe", "pipe"],
        encoding: "utf8",
      });
  if ("error" in ghVersionResult && ghVersionResult.error) {
    // spawn error = ENOENT, i.e. gh is not on PATH at all.
    process.stderr.write(
      `error: 'gh' (GitHub CLI) not found on PATH\n` +
        `  install: https://cli.github.com\n` +
        `  then re-run: stamp pr open ${branch}\n`,
    );
    process.exit(127);
  }
  // Note: a non-zero exit from `gh --version` (e.g. alias conflict) is
  // uncommon and more ambiguous than ENOENT; treat it as "gh is present
  // but broken" rather than "not on PATH." We let `gh pr create` fail
  // explicitly with its own error message (exit 3) in that case rather
  // than 127, which is strictly "not found."

  // ─── Step 1: `git push origin <branch>` ────────────────────────────
  // AC #4: on non-zero, git's stderr is already visible via inherit;
  // exit 1 and do NOT proceed.
  const repoRoot = findRepoRoot();

  let gitPushStatus: number;
  if (opts._gitPushForTest) {
    gitPushStatus = opts._gitPushForTest().status;
  } else {
    const pushResult = spawnSync("git", ["push", remote, branch], {
      cwd: repoRoot,
      stdio: "inherit",
    });
    gitPushStatus = pushResult.status ?? 1;
  }

  if (gitPushStatus !== 0) {
    process.exit(1);
  }

  process.stderr.write(`✓ pushed ${remote}/${branch}\n`);

  // ─── Step 2: `gh pr create --head <branch> --fill` ─────────────────
  // AC #5: on failure, exit 3 and note the push already landed.
  let prUrl: string;
  if (opts._ghCreateForTest) {
    const fake = opts._ghCreateForTest();
    if (fake.status !== 0) {
      process.stderr.write(
        `error: 'gh pr create' failed (exit ${fake.status})\n` +
          `  The push to ${remote}/${branch} has already landed.\n` +
          `  Open the PR manually on GitHub or re-run: stamp pr open ${branch}\n`,
      );
      process.exit(3);
    }
    prUrl = fake.stdout.trim();
  } else {
    const ghCreate = spawnSync(
      "gh",
      ["pr", "create", "--head", branch, "--fill"],
      {
        cwd: repoRoot,
        stdio: ["ignore", "pipe", "pipe"],
        encoding: "utf8",
      },
    );

    if (ghCreate.status !== 0) {
      const ghStderr = ghCreate.stderr?.trim() ?? "";
      process.stderr.write(
        `error: 'gh pr create' failed (exit ${ghCreate.status ?? "?"})\n` +
          (ghStderr ? `  ${ghStderr.split("\n").join("\n  ")}\n` : "") +
          `  The push to ${remote}/${branch} has already landed.\n` +
          `  Open the PR manually on GitHub or re-run: stamp pr open ${branch}\n`,
      );
      process.exit(3);
    }

    // gh pr create prints the PR URL as the last (or only) line of stdout.
    prUrl = ghCreate.stdout.trim().split("\n").pop() ?? "";
  }

  process.stderr.write(`✓ opened PR via gh\n`);

  // ─── Step 3: build + sign + broadcast the `pr-opened` payload ────────
  // AC #6: on broadcast failure, exit 4 and note the PR is live.
  // AC #7: build the payload with canonical Ed25519 signature.
  // AC #8: `peer_reviews_not_configured` → exit 0 + informational note.

  // Resolve the stamp-server config.
  const serverCfg = opts.server
    ? (() => {
        const m = opts.server!.trim().match(/^([^:]+):(\d+)$/);
        if (!m) {
          process.stderr.write(
            `error: --server must be <host>:<port> (got ${JSON.stringify(opts.server)})\n`,
          );
          process.exit(4);
        }
        const port = Number(m[2]);
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
          process.stderr.write(
            `error: --server port must be 1..65535 (got ${JSON.stringify(m[2])})\n`,
          );
          process.exit(4);
        }
        return { host: m[1]!, port, user: "git", repoRootPrefix: "/srv/git" };
      })()
    : loadServerConfig();

  if (!serverCfg) {
    process.stderr.write(
      `error: no stamp-server configured. Run 'stamp server config <host:port>' or pass --server.\n`,
    );
    process.exit(4);
  }

  // Derive org/repo from the remote URL.
  const orgRepo = opts._orgRepoForTest ?? deriveOrgRepoFromRemote(remote, repoRoot);
  if (!orgRepo) {
    process.stderr.write(
      `error: could not derive <org>/<repo> from remote '${remote}'. ` +
        `Ensure '${remote}' is set to a <host>:<org>/<repo>.git shape.\n`,
    );
    process.exit(4);
  }
  const repoField = `${orgRepo.org}/${orgRepo.repo}`;

  // Compute patch_id / base_sha / head_sha for the branch vs. origin/HEAD.
  // We use `origin/HEAD` as the base, which resolves to the default branch.
  let patchInfo: { patch_id: string; base_sha: string; head_sha: string };
  if (opts._patchIdForTest) {
    patchInfo = opts._patchIdForTest();
  } else {
    try {
      patchInfo = patchIdForRevspec(`origin/HEAD..${branch}`, repoRoot);
    } catch (err) {
      process.stderr.write(
        `error: could not compute patch-id for origin/HEAD..${branch}: ` +
          `${err instanceof Error ? err.message : String(err)}\n` +
          `  Ensure your branch has commits on top of origin/HEAD.\n`,
      );
      process.exit(4);
    }
  }

  // Compute paths_changed via `git diff --name-only`.
  let pathsChanged: string[];
  if (opts._gitDiffNamesForTest) {
    const fake = opts._gitDiffNamesForTest();
    pathsChanged =
      fake.status === 0
        ? fake.stdout.trim().split("\n").filter(Boolean)
        : [];
  } else {
    const diffNames = spawnSync(
      "git",
      ["diff", "--name-only", `${patchInfo.base_sha}..${patchInfo.head_sha}`],
      {
        cwd: repoRoot,
        stdio: ["ignore", "pipe", "pipe"],
        encoding: "utf8",
      },
    );
    pathsChanged =
      diffNames.status === 0
        ? (diffNames.stdout ?? "").trim().split("\n").filter(Boolean)
        : [];
  }

  // Read title + body from `gh pr view --json title,body`.
  let prTitle = `${branch}`;
  let prBody = "";
  if (opts._ghViewForTest) {
    const fake = opts._ghViewForTest();
    if (fake.status === 0) {
      try {
        const obj = JSON.parse(fake.stdout) as { title?: string; body?: string };
        if (typeof obj.title === "string") prTitle = obj.title;
        if (typeof obj.body === "string") prBody = obj.body;
      } catch {
        // ignore parse errors; fallback defaults are fine
      }
    }
  } else {
    const ghView = spawnSync(
      "gh",
      ["pr", "view", "--head", branch, "--json", "title,body"],
      {
        cwd: repoRoot,
        stdio: ["ignore", "pipe", "pipe"],
        encoding: "utf8",
      },
    );
    if (ghView.status === 0) {
      try {
        const obj = JSON.parse(ghView.stdout ?? "{}") as {
          title?: string;
          body?: string;
        };
        if (typeof obj.title === "string") prTitle = obj.title;
        if (typeof obj.body === "string") prBody = obj.body;
      } catch {
        // ignore; fallback defaults are fine
      }
    }
  }

  // Load the operator keypair.
  const keypair: Keypair | null = opts._keypairForTest ?? loadUserKeypair();
  if (!keypair) {
    process.stderr.write(
      `error: no stamp signing key found at ~/.stamp/keys/ed25519. ` +
        `Run 'stamp keys generate' to create one.\n`,
    );
    process.exit(4);
  }

  // Build the payload body (all fields excluding `signature`).
  // AGT-454: include pubkey (SPKI PEM) so the server can verify without repo access.
  const payloadBody: PrOpenedPayloadBody = {
    repo: repoField,
    patch_id: patchInfo.patch_id,
    base_sha: patchInfo.base_sha,
    head_sha: patchInfo.head_sha,
    requested_by_fp: keypair.fingerprint,
    paths_changed: pathsChanged,
    title: prTitle,
    body: prBody,
    pr_url: prUrl,
    pubkey: keypair.publicKeyPem,
  };

  // Sign the canonical bytes (all fields excluding `signature`).
  const canonicalBytes = canonicalSerializePrOpened(payloadBody);
  const signature = signBytes(keypair.privateKeyPem, canonicalBytes);

  // Assemble the full payload (payload body + signature).
  const fullPayload = { ...payloadBody, signature };
  const payloadJson = JSON.stringify(fullPayload);

  // Broadcast via SSH.
  const broadcastInput: BroadcastPrOpenedInput = {
    payloadJson,
    serverConfig: serverCfg,
    _sshSpawnForTest: opts._sshSpawnForTest,
  };

  const broadcastResult = await broadcastPrOpened(broadcastInput);

  if (broadcastResult.ok) {
    // Full success. Print the PR URL to stdout (primary artifact; agents capture stdout).
    process.stdout.write(`${prUrl}\n`);
    process.stderr.write(
      `✓ broadcast pr-opened to stamp-server (patch_id ${broadcastResult.patch_id})\n`,
    );
    process.exit(0);
  }

  if (broadcastResult.reason === "peer_reviews_not_configured") {
    // AC #8: server has peer reviews disabled — informational, not an error.
    // Still print the PR URL so the caller can capture it.
    process.stdout.write(`${prUrl}\n`);
    process.stderr.write(
      `note: stamp-server has peer reviews disabled; broadcast acknowledged but no fanout will occur\n`,
    );
    process.exit(0);
  }

  // Broadcast failed — AC #6. The PR is already live; do NOT suggest
  // `stamp pr open` as a retry path — that would re-run `gh pr create`
  // which would fail with "PR already exists" and exit 3, leaving the
  // caller confused about whether the PR was opened. A dedicated broadcast-
  // only recovery path (e.g. `stamp pr broadcast <url>`) is planned for a
  // future ticket.
  process.stderr.write(
    `error: broadcast to stamp-server failed.\n` +
      `  ${broadcastResult.message.split("\n").join("\n  ")}\n` +
      `  The PR is live on GitHub but listeners were not notified.\n` +
      `  A broadcast-only retry path is not yet available; contact your stamp-server operator.\n`,
  );
  process.exit(4);
}
