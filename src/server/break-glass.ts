/**
 * `stamp-break-glass` entry point (AGT-2260). See src/lib/breakGlass.ts.
 *
 * Installed root:root 0700 at /usr/local/sbin/stamp-break-glass; run it
 * from a root shell in the container (`railway ssh`, `docker exec`).
 * After a write it re-pins users.db to root:git 0660 — the git-run SSH
 * helpers and HTTP server must keep reading it, and a DB this CLI created
 * from scratch would otherwise be root-only and lock everyone out.
 */

import { chownSync, existsSync, readFileSync, statSync } from "node:fs";
import { dirname } from "node:path";
import { runBreakGlass } from "../lib/breakGlass.js";
import { resolveServerDbPath } from "../lib/serverDb.js";

const code = runBreakGlass(process.argv.slice(2), {
  uid: process.getuid ? process.getuid() : -1,
  readStdin: () => readFileSync(0, "utf8"),
  out: (s) => process.stdout.write(s),
  err: (s) => process.stderr.write(s),
});

if (code === 0) {
  const dbPath = resolveServerDbPath();
  if (existsSync(dbPath)) {
    // The state dir is root:git (entrypoint.sh); reuse its group.
    chownSync(dbPath, 0, statSync(dirname(dbPath)).gid);
  }
}
process.exit(code);
