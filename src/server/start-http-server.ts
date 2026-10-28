/**
 * Bundled entry point for the stamp server's HTTP listener.
 *
 * Ships as /usr/local/sbin/stamp-http-server. Entrypoint.sh spawns this
 * in the background, before exec-ing sshd, as the unprivileged
 * `stamp-http` user with an explicit allowlisted environment (AGT-2264;
 * see server/README.md "What the HTTP listener can reach"). The server
 * reads STAMP_HTTP_PORT (default 8080) for the listening port.
 *
 * The workers that need the git user's file access (prompts poll,
 * trash sweep) are NOT armed here — they run in the separate git-user
 * stamp-workers process (start-workers.ts).
 *
 * Kept as a separate file from http-server.ts so the latter can be
 * imported by tests without spinning up a real socket at import time.
 */

import { HTTP_DEFAULT_PORT, startServer } from "./http-server.js";

const rawPort = process.env["STAMP_HTTP_PORT"];
const port = rawPort ? Number(rawPort) : HTTP_DEFAULT_PORT;
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  process.stderr.write(
    `stamp-http-server: STAMP_HTTP_PORT must be an integer 1..65535 (got ${JSON.stringify(rawPort)})\n`,
  );
  process.exit(2);
}
startServer(port, { gitWorkers: false });
