/**
 * `stamp-sign-approval` — root signing helper (AGT-2263).
 *
 * Installed root:root 0755 at /usr/local/sbin/stamp-sign-approval and
 * reachable by the git user ONLY through the sudoers rule
 * `git ALL=(root) NOPASSWD: /usr/local/sbin/stamp-sign-approval ""`
 * (no arguments). It is NOT a git-shell verb: not symlinked into
 * git-shell-commands and not on stamp-gate's allowlist, so it cannot be
 * reached over SSH. `stamp-review` (running as git) pipes the canonical
 * approval in and gets the signature back; the private key stays
 * root:root 0600 and is never readable by git. See
 * src/lib/approvalSigning.ts for exactly what it will sign and why.
 *
 * Key path: resolved from this process's env plus /etc/stamp/env
 * (root-written). Under sudo the caller's environment is reset
 * (env_reset, no SETENV tag), so the git user cannot redirect the
 * helper at another file; it would also fail the root-owner check.
 */

import { appendFileSync, readSync } from "node:fs";

import { MAX_APPROVAL_PAYLOAD_BYTES } from "../lib/approvalSigning.js";
import { resolveReviewSigningKeyPath } from "../lib/reviewSigningKey.js";
import { loadServerEnvFile } from "../lib/serverEnvFile.js";
import { runSignApproval } from "../lib/signApprovalHelper.js";

/** Backing word for the EAGAIN back-off; allocated once, not per wait. */
const WAIT_CELL = new Int32Array(new SharedArrayBuffer(4));

/** Read stdin, but never more than cap+1 bytes (the +1 lets the
 *  validator report "too large" instead of silently truncating). */
function readBoundedStdin(cap: number): Buffer {
  const chunks: Buffer[] = [];
  let total = 0;
  const buf = Buffer.alloc(1024);
  for (;;) {
    let n: number;
    try {
      n = readSync(0, buf, 0, buf.length, null);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "EAGAIN") {
        // Non-blocking stdin with no data yet: wait briefly, don't spin.
        Atomics.wait(WAIT_CELL, 0, 0, 10);
        continue;
      }
      if (code === "EOF") break;
      throw err;
    }
    if (n === 0) break;
    chunks.push(Buffer.from(buf.subarray(0, n)));
    total += n;
    if (total > cap) break;
  }
  return Buffer.concat(chunks);
}

loadServerEnvFile();

const code = runSignApproval({
  argv: process.argv.slice(2),
  stdin: readBoundedStdin(MAX_APPROVAL_PAYLOAD_BYTES),
  privateKeyPath: resolveReviewSigningKeyPath(),
  out: (s) => process.stdout.write(s),
  err: (s) => process.stderr.write(s),
  audit: (line) => {
    // Container log stream (PID 1 = sshd's stderr after the entrypoint's
    // exec). Only root can open it, which is the point: the git user
    // cannot erase the record. Skipped off-container / as non-root.
    if (process.getuid?.() === 0) appendFileSync("/proc/1/fd/2", line);
  },
});
process.exitCode = code;
