/**
 * Guard test: client↔server peer SSH verb agreement.
 *
 * Parses `server/Dockerfile` for the `git-shell-commands` symlink block and
 * asserts that every entry in `PEER_SSH_VERBS` has a matching server-side
 * symlink, and that every peer symlink present in the Dockerfile is covered by
 * a constant in `PEER_SSH_VERBS`.
 *
 * This test is hermetic (reads the Dockerfile at a relative path, no network).
 * Adding or renaming a verb on either side without updating the other will
 * cause this test to fail.
 */

import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { PEER_SSH_VERBS } from "../src/lib/peerSshVerbs.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");

// ── Parse the Dockerfile for git-shell-commands peer verb symlinks ────────────
//
// We look for lines of the form:
//   && ln -s /usr/local/bin/stamp-<verb> /home/git/git-shell-commands/stamp-<verb>
// Only capture the peer-review verbs (those whose binary name starts with
// "stamp-" and whose target is in /home/git/git-shell-commands/stamp-*).
//
// Non-peer verbs (new-stamp-repo, delete-stamp-repo, stamp-review, etc.) are
// intentionally excluded — this test is specifically about the peer protocol.

const PEER_VERB_PREFIXES: ReadonlySet<string> = new Set([
  "stamp-pr-opened",
  "stamp-subscribe",
  "stamp-claim-seat",
  "stamp-heartbeat",
  "stamp-release-seat",
  "stamp-re-review-request",
]);

function parseDockerfilePeerVerbs(): Set<string> {
  const dockerfilePath = resolve(repoRoot, "server", "Dockerfile");
  const contents = readFileSync(dockerfilePath, "utf-8");

  const found = new Set<string>();
  // Match symlink lines: ln -s .../stamp-<verb> /home/git/git-shell-commands/stamp-<verb>
  const re =
    /ln\s+-s\s+\S+\/(stamp-[a-z-]+)\s+\/home\/git\/git-shell-commands\/(stamp-[a-z-]+)/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(contents)) !== null) {
    const binaryName = match[1]!;
    const symlinkName = match[2]!;
    // Sanity: binary name and symlink name should agree
    assert.equal(
      binaryName,
      symlinkName,
      `Dockerfile mismatch: binary '${binaryName}' != symlink '${symlinkName}'`,
    );
    // Only track the six peer verbs we care about
    if (PEER_VERB_PREFIXES.has(symlinkName)) {
      found.add(symlinkName);
    }
  }
  return found;
}

describe("peerSshVerbs: client↔server verb agreement", () => {
  const serverVerbs = parseDockerfilePeerVerbs();

  it("Dockerfile exposes all six expected peer-verb symlinks", () => {
    for (const expected of PEER_VERB_PREFIXES) {
      assert.ok(
        serverVerbs.has(expected),
        `server/Dockerfile is missing git-shell-commands symlink for '${expected}'`,
      );
    }
    assert.equal(
      serverVerbs.size,
      PEER_VERB_PREFIXES.size,
      `Expected ${PEER_VERB_PREFIXES.size} peer verb symlinks in Dockerfile, found ${serverVerbs.size}: ${[...serverVerbs].join(", ")}`,
    );
  });

  it("every PEER_SSH_VERBS constant matches a server git-shell-commands symlink", () => {
    for (const [key, verb] of Object.entries(PEER_SSH_VERBS)) {
      assert.ok(
        serverVerbs.has(verb),
        `PEER_SSH_VERBS.${key} = '${verb}' has no matching git-shell-commands symlink in server/Dockerfile`,
      );
    }
  });

  it("every server peer-verb symlink is covered by a PEER_SSH_VERBS constant", () => {
    const clientVerbs = new Set(Object.values(PEER_SSH_VERBS));
    for (const verb of serverVerbs) {
      assert.ok(
        clientVerbs.has(verb),
        `server/Dockerfile symlink '${verb}' is not covered by any PEER_SSH_VERBS constant`,
      );
    }
  });

  it("PEER_SSH_VERBS has exactly as many entries as the peer verb witness set", () => {
    const count = Object.keys(PEER_SSH_VERBS).length;
    assert.equal(
      count,
      PEER_VERB_PREFIXES.size,
      `Expected ${PEER_VERB_PREFIXES.size} PEER_SSH_VERBS entries, got ${count}`,
    );
  });
});
