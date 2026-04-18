import { spawnSync } from "node:child_process";
import { findRepoRoot } from "../lib/paths.js";

export interface PushOptions {
  target: string;
  remote?: string;
}

/**
 * Thin wrapper around `git push <remote> <target>`. The server-side
 * stamp-verify hook does the actual verification; this command just
 * forwards the push and surfaces the hook's stderr to the agent.
 */
export function runPush(opts: PushOptions): void {
  const repoRoot = findRepoRoot();
  const remote = opts.remote ?? "origin";

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
