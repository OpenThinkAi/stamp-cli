/**
 * Integration tests for the path-traversal hardening added to
 * scripts/setup-repo.sh's `--from-tarball` mode (AGT-033 / audit M2).
 *
 * Scope: the rejection path. We craft tarballs whose entries contain
 * absolute paths or `..` segments and assert setup-repo.sh exits non-zero
 * with a clear "unsafe entry" error and writes nothing to the target
 * REPO_DIR. The successful-extraction path uses GNU-tar-only flags
 * (`--no-overwrite-dir`) and is exercised by the Alpine container in
 * production; running it on a developer's BSD-tar macOS box would fail
 * for tar-version reasons unrelated to the fix.
 */

import { strict as assert } from "node:assert";
import { execFileSync, spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCRIPT = resolve(__dirname, "..", "scripts", "setup-repo.sh");

describe("setup-repo.sh --from-tarball entry-name validation", () => {
  let tmp: string;

  beforeEach(() => {
    tmp = realpathSync(mkdtempSync(join(tmpdir(), "stamp-setuprepo-")));
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  function makePubKey(): string {
    const path = join(tmp, "trusted.pub");
    const { publicKey } = generateKeyPairSync("ed25519");
    writeFileSync(path, publicKey.export({ type: "spki", format: "pem" }) as string);
    return path;
  }

  function makeHook(): string {
    const path = join(tmp, "fake-pre-receive.cjs");
    writeFileSync(path, "#!/usr/bin/env node\n");
    return path;
  }

  function runSetup(repo: string, tarball: string): { status: number | null; stderr: string } {
    const res = spawnSync(
      "bash",
      [SCRIPT, repo, makeHook(), makePubKey(), "--from-tarball", tarball],
      { encoding: "utf8" },
    );
    return { status: res.status, stderr: res.stderr };
  }

  it("rejects a tarball with an absolute-path entry (e.g. /etc/hosts-shaped)", () => {
    const inner = join(tmp, "stage-abs");
    mkdirSync(inner);
    const tarball = join(tmp, "abs.tgz");
    // -P preserves the leading slash on both BSD and GNU tar; we don't
    // actually read /etc/hosts at extract time (the tarball just records
    // the name), but it's the canonical shape an attacker would use.
    execFileSync("tar", ["-czf", tarball, "-P", "/etc/hosts"], {
      cwd: inner,
      stdio: "pipe",
    });

    const repo = join(tmp, "out-abs.git");
    const { status, stderr } = runSetup(repo, tarball);

    assert.notStrictEqual(status, 0, "setup-repo.sh must reject absolute-path entries");
    assert.match(stderr, /unsafe entry/);
    assert.ok(
      !existsSync(repo) || readdirSync(repo).length === 0,
      "REPO_DIR must contain no extraction artifacts after rejection",
    );
  });

  it("rejects a tarball with a `..` traversal entry (e.g. ../sibling)", () => {
    // Stage `inner/good.txt` and a sibling `escape.txt`, then tar from
    // inside `inner/` referencing `../escape.txt` so the entry is
    // recorded literally as "../escape.txt" in the archive.
    const inner = join(tmp, "stage-rel");
    mkdirSync(inner);
    writeFileSync(join(inner, "good.txt"), "ok");
    writeFileSync(join(tmp, "escape.txt"), "evil");
    const tarball = join(tmp, "rel.tgz");
    execFileSync("tar", ["-czf", tarball, "good.txt", "../escape.txt"], {
      cwd: inner,
      stdio: "pipe",
    });

    const repo = join(tmp, "out-rel.git");
    const { status, stderr } = runSetup(repo, tarball);

    assert.notStrictEqual(status, 0, "setup-repo.sh must reject `..` traversal entries");
    assert.match(stderr, /unsafe entry/);
    assert.ok(
      !existsSync(repo) || readdirSync(repo).length === 0,
      "REPO_DIR must contain no extraction artifacts after rejection",
    );
  });
});
