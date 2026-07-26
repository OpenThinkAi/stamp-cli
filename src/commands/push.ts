import { spawnSync } from "node:child_process";
import { maybeWarnAgentsMdDrift } from "../lib/agentsMd.js";
import { runGit } from "../lib/git.js";
import { findRepoRoot } from "../lib/paths.js";
import { classifyRemote } from "../lib/remote.js";
import { parseBareRepoSshUrl } from "../lib/serverConfig.js";

export interface PushOptions {
  target: string;
  remote?: string;
  /**
   * After the push, ask the stamp server to re-run the GitHub mirror leg
   * for <target>'s tip via the server-side `resync-mirror` verb — even
   * when the push itself was a no-op because the server was already up
   * to date. This is the recovery path for a mirror stranded by an
   * earlier failed mirror push (issue #64): the post-receive hook only
   * fires when a ref moves, so without this the mirror stays stale until
   * the next real push.
   */
  resyncMirror?: boolean;
}

/**
 * Thin wrapper around `git push <remote> <target>`. The server-side
 * stamp-verify hook does the actual verification; this command just
 * forwards the push and surfaces the hook's stderr to the agent.
 *
 * Before pushing, surfaces a non-blocking stderr warning when the live
 * AGENTS.md mode disagrees with what the remote shape implies (e.g. a
 * repo init'd local-only that later had its origin re-pointed at a stamp
 * server still carries the stale "the agent is the gate" body). The
 * warning is informational — the push proceeds either way. Suppress with
 * `STAMP_SUPPRESS_AGENTS_MD_DRIFT_WARNING=1`.
 */
export function runPush(opts: PushOptions): void {
  const repoRoot = findRepoRoot();
  const remote = opts.remote ?? "origin";

  const classification = classifyRemote(remote, repoRoot);
  maybeWarnAgentsMdDrift({
    repoRoot,
    remoteShape: classification.shape,
    command: "push",
    remote,
  });

  const result = spawnSync("git", ["push", remote, opts.target], {
    cwd: repoRoot,
    stdio: "inherit",
  });

  if (result.status !== 0) {
    // stderr has already been forwarded to the user via inherit.
    // The hook's rejection message (prefixed "stamp-verify:") is now visible.
    process.exit(result.status ?? 1);
  }

  if (opts.resyncMirror) {
    resyncMirror(remote, opts.target, repoRoot);
  }
}

/**
 * Invoke the server-side `resync-mirror` verb over SSH against the repo's
 * own remote. Runs AFTER a successful push: when the push moved the ref,
 * the post-receive hook already ran the mirror leg and this re-run is a
 * cheap idempotent second push of the same tip; when the push was a
 * no-op, this is the only thing that fires the mirror leg at all — which
 * is the whole point of the flag.
 *
 * Failures here exit non-zero: the operator passed --resync-mirror
 * because they specifically need the mirror caught up, so a silently
 * skipped resync would recreate the exact "looks fine, mirror stale"
 * state the flag exists to fix.
 */
function resyncMirror(remote: string, target: string, repoRoot: string): void {
  let url: string;
  try {
    url = runGit(["remote", "get-url", remote], repoRoot).trim();
  } catch {
    console.error(`error: --resync-mirror: remote "${remote}" has no URL`);
    process.exit(1);
  }
  const parsed = parseBareRepoSshUrl(url);
  if (!parsed) {
    console.error(
      `error: --resync-mirror: remote "${remote}" (${url}) doesn't look like a ` +
        `stamp-server ssh:// URL. The mirror leg runs on the stamp server, so this ` +
        `flag only applies to server-gated repos.`,
    );
    process.exit(1);
  }
  // `stamp push` targets are branch names in normal use; a refspec form
  // (src:dst) resyncs the DESTINATION branch — that's the ref that moved
  // (or failed to mirror) on the server.
  const branch = target.includes(":")
    ? target.slice(target.indexOf(":") + 1)
    : target;

  console.log(
    `Asking ${parsed.user}@${parsed.host}:${parsed.port} to re-run the mirror leg for ${branch}`,
  );
  // `--` terminates ssh option processing before the destination — same
  // defense as every other ssh call site (serverConfig.ts shape rules are
  // the first layer; parseBareRepoSshUrl only accepts those shapes).
  const result = spawnSync(
    "ssh",
    [
      "-p",
      String(parsed.port),
      "--",
      `${parsed.user}@${parsed.host}`,
      "resync-mirror",
      parsed.repoName,
      branch,
    ],
    { stdio: ["ignore", "inherit", "inherit"] },
  );
  if (result.status !== 0) {
    console.error(
      `error: resync-mirror failed (exit ${result.status}). If you see "command not ` +
        `found", the server image predates the resync-mirror verb — redeploy it first.`,
    );
    process.exit(1);
  }
}
