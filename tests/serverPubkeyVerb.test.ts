/**
 * Integration tests for `server/stamp-server-pubkey` — specifically
 * the `--review-signing` mode added in AGT-327.
 *
 * The shell script runs inside the stamp-server container as the git
 * user's SSH-dispatched verb. We invoke it directly via /bin/sh to
 * cover the path resolution + suffix-swap logic that's expressed in
 * shell (and not reachable from Node unit tests). Two properties
 * matter:
 *
 *   1. The .pem → .pub suffix swap on the resolved path actually
 *      fires (security review #756 caught a similar dead-suffix-swap
 *      bug in the initial implementation; this test pins the
 *      behavior so future shell edits don't regress it).
 *   2. When the pub file is missing, the script exits 1 with the
 *      `error: ` prefix on stderr — matching the codebase-wide
 *      stderr-error convention.
 *
 * We intentionally do NOT test the legacy back-compat path (no SPEC)
 * or the per-repo path (<owner>/<repo>) here — those predate AGT-327
 * and are exercised by the existing deployment workflow.
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import {
  chmodSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

const PUBKEY_SCRIPT = path.resolve(
  import.meta.dirname,
  "..",
  "server",
  "stamp-server-pubkey",
);

interface RunResult {
  stdout: string;
  stderr: string;
  status: number | null;
}

function runScript(args: string[], env: Record<string, string>): RunResult {
  const childEnv: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined) childEnv[k] = v;
  }
  // Wipe the keys that could leak from the developer's shell.
  delete childEnv["REVIEW_SIGNING_KEY_PATH"];
  delete childEnv["STAMP_STATE_DIR"];
  for (const [k, v] of Object.entries(env)) childEnv[k] = v;

  const result = spawnSync("/bin/sh", [PUBKEY_SCRIPT, ...args], {
    env: childEnv,
    encoding: "utf8",
  });
  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    status: result.status,
  };
}

function tmpDir(): { dir: string; cleanup: () => void } {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-pubkey-verb-"));
  return {
    dir,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function writeKeyPair(privPath: string, pubPath: string): string {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const privPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const pubPem = publicKey.export({ type: "spki", format: "pem" }) as string;
  writeFileSync(privPath, privPem, { mode: 0o600 });
  chmodSync(privPath, 0o600);
  writeFileSync(pubPath, pubPem, { mode: 0o644 });
  chmodSync(pubPath, 0o644);
  return pubPem;
}

describe("stamp-server-pubkey --review-signing", () => {
  it("emits the .pub sibling derived via the .pem → .pub suffix swap", () => {
    const t = tmpDir();
    try {
      // Mimic the production layout: the private key path ends in .pem,
      // the public sibling lives at the same base path with .pub. The
      // shell script must derive REVIEW_PUB_PATH from REVIEW_KEY_PATH
      // (not from the literal "--review-signing" arg, which was a
      // real bug security review caught in the initial implementation).
      const privPath = path.join(t.dir, "review-signing-key.pem");
      const pubPath = path.join(t.dir, "review-signing-key.pub");
      const expectedPubPem = writeKeyPair(privPath, pubPath);

      const r = runScript(["--review-signing"], {
        REVIEW_SIGNING_KEY_PATH: privPath,
      });

      assert.equal(r.status, 0, `non-zero exit; stderr=${r.stderr}`);
      assert.equal(r.stderr, "", `expected empty stderr; got ${r.stderr}`);
      assert.equal(r.stdout, expectedPubPem);
    } finally {
      t.cleanup();
    }
  });

  it("falls back to <STAMP_STATE_DIR>/review-signing-key.pem when no override is set", () => {
    const t = tmpDir();
    try {
      const privPath = path.join(t.dir, "review-signing-key.pem");
      const pubPath = path.join(t.dir, "review-signing-key.pub");
      const expectedPubPem = writeKeyPair(privPath, pubPath);

      const r = runScript(["--review-signing"], {
        STAMP_STATE_DIR: t.dir,
      });

      assert.equal(r.status, 0, `non-zero exit; stderr=${r.stderr}`);
      assert.equal(r.stdout, expectedPubPem);
    } finally {
      t.cleanup();
    }
  });

  it("exits 1 with the `error: ` prefix when the pubkey is missing", () => {
    const t = tmpDir();
    try {
      // No key files written — the script should refuse cleanly with
      // a stderr message that an operator can read, exit code 1.
      const r = runScript(["--review-signing"], {
        REVIEW_SIGNING_KEY_PATH: path.join(t.dir, "missing.pem"),
      });
      assert.equal(r.status, 1);
      assert.match(r.stderr, /^error: /);
      assert.match(r.stderr, /pubkey not found/);
      assert.match(r.stderr, /ANTHROPIC_API_KEY/);
      assert.equal(r.stdout, "");
    } finally {
      t.cleanup();
    }
  });
});
