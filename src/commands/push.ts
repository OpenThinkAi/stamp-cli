import { spawnSync } from "node:child_process";
import { maybeWarnAgentsMdDrift } from "../lib/agentsMd.js";
import { findRepoRoot } from "../lib/paths.js";
import { classifyRemote } from "../lib/remote.js";

export interface PushOptions {
  target: string;
  remote?: string;
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
}
