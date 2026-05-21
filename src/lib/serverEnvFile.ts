/**
 * Helper for reading secrets the server entrypoint persists to /etc/stamp/env.
 *
 * sshd strips most env vars from user sessions by default, so any
 * server-side script invoked via SSH (the `stamp-review` verb, the
 * receive hooks, future stamp-* verbs) does not see the container's
 * full process env. The entrypoint addresses this by writing
 * `KEY=value` lines into `/etc/stamp/env` (mode 0640, owner root,
 * group git) for any var the runtime needs but sshd would otherwise
 * strip — `GITHUB_BOT_TOKEN`, `ANTHROPIC_API_KEY`, etc.
 *
 * Call `loadServerEnvFile()` once near the top of an SSH-invoked
 * script's main() before any code reads `process.env`. It merges
 * unset keys into `process.env`; vars already set on the session (a
 * rare case — only those in sshd_config's `SetEnv` or AcceptEnv list)
 * win.
 *
 * The file might not exist (local dev / test) — that's a no-op return,
 * not an error. The format is the minimum subset that's safe across
 * both POSIX sh-style assignment and Node.js: lines matching
 * `^[A-Z_][A-Z0-9_]*=<value>$`, value taken as-is up to the next
 * newline, trimmed for trailing whitespace. No quoting, no escaping —
 * the entrypoint's `write_env_var` shell helper never produces them.
 */

import { existsSync, readFileSync } from "node:fs";

const DEFAULT_PATH = "/etc/stamp/env";

export function loadServerEnvFile(path: string = DEFAULT_PATH): void {
  if (!existsSync(path)) return;
  let content: string;
  try {
    content = readFileSync(path, "utf8");
  } catch {
    return;
  }
  for (const line of content.split("\n")) {
    const m = line.match(/^\s*([A-Z_][A-Z0-9_]*)=(.*)$/);
    if (!m) continue;
    const key = m[1]!;
    if (process.env[key] === undefined) {
      process.env[key] = (m[2] ?? "").trim();
    }
  }
}
