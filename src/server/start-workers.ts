/**
 * Bundled entry point for the stamp server's git-user background workers
 * (AGT-2264). Ships as /usr/local/sbin/stamp-workers; entrypoint.sh starts
 * it as the `git` user, with an explicit allowlisted environment, alongside
 * the HTTP listener.
 *
 * These workers used to run inside stamp-http-server. They need the git
 * user's file access — the prompts deploy key and the git-owned prompts
 * cache, and the git-owned trashed repos — which the internet-facing
 * listener no longer has (it runs as the unprivileged stamp-http user). This
 * process opens no socket:
 *
 *   - prompts poll backstop     (STAMP_PROMPTS_POLL_INTERVAL_SEC; no-op
 *                                without STAMP_PROMPTS_REPO_URL)
 *   - prompts refresh trigger   (STAMP_PROMPTS_REFRESH_TRIGGER: the file
 *                                the listener replaces on a valid webhook)
 *   - trash-retention sweep     (STAMP_TRASH_SWEEP_INTERVAL_SEC)
 */

import {
  setLogPrefix,
  startPromptsPollWorker,
  startPromptsRefreshTriggerWatcher,
  startTrashSweepWorker,
} from "./http-server.js";

setLogPrefix("stamp-workers");
startPromptsPollWorker();
startPromptsRefreshTriggerWatcher();
startTrashSweepWorker();

// Every worker timer is unref'd (so the listener's tests can exit); this
// process has nothing else holding the event loop open, so keep it alive
// explicitly. sshd is PID 1; if this process dies the workers stop until the
// next redeploy, same as the listener.
setInterval(() => {}, 1 << 30);
process.stderr.write("stamp-workers: started\n");
