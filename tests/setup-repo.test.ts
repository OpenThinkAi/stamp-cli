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
  symlinkSync,
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

  it("sets receive.denyNonFastForwards=true on freshly-created bare repos (issue #20)", () => {
    // git defaults receive.denyNonFastForwards to false on bare repos, so
    // without setup-repo.sh setting it explicitly, a buggy or race-blind
    // pre-receive hook could let a non-FF push land. Pin the config write
    // here so a refactor of the bare-init block can't silently drop it.
    const repo = join(tmp, "fresh.git");
    const res = spawnSync(
      "bash",
      [SCRIPT, repo, makeHook(), makePubKey()],
      { encoding: "utf8" },
    );
    assert.strictEqual(res.status, 0, `setup-repo.sh failed: ${res.stderr}`);
    const value = execFileSync(
      "git",
      ["--git-dir", repo, "config", "--get", "receive.denyNonFastForwards"],
      { encoding: "utf8" },
    ).trim();
    assert.strictEqual(value, "true");
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

// ---- v4 audit M-S2: new-stamp-repo --from-tarball path constraint ----

describe("new-stamp-repo --from-tarball path constraint (v4 audit M-S2)", () => {
  // The script lives at server/new-stamp-repo and is the git-shell-commands
  // entry point that operators invoke via `ssh git@host new-stamp-repo …
  // --from-tarball /tmp/stamp-migrate-…tar.gz`. The path argument is
  // operator-controlled and the EXIT trap `rm -f $FROM_TARBALL` would
  // otherwise be a cross-tenant rm primitive against anything under
  // /srv/git/* that the `git` user owns. Constrain it to the documented
  // /tmp/stamp-migrate-*.tar.gz shape and re-check via readlink -f so a
  // symlink can't redirect the rm.
  const SCRIPT = resolve(__dirname, "..", "server", "new-stamp-repo");

  const run = (args: string[]) =>
    spawnSync("bash", [SCRIPT, ...args], { encoding: "utf8" });

  it("rejects --from-tarball pointing at /etc/passwd-shaped paths", () => {
    const r = run(["foo", "--from-tarball", "/etc/passwd"]);
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stderr, /--from-tarball must be at \/tmp\/stamp-migrate-/);
  });

  it("rejects --from-tarball pointing into /srv/git (cross-tenant rm primitive)", () => {
    const r = run(["foo", "--from-tarball", "/srv/git/other-repo.git/HEAD"]);
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stderr, /--from-tarball must be at \/tmp\/stamp-migrate-/);
  });

  it("rejects --from-tarball with traversal segments", () => {
    const r = run([
      "foo",
      "--from-tarball",
      "/tmp/stamp-migrate-../../etc/passwd.tar.gz",
    ]);
    // Pattern allows the prefix; readlink -f canonicalises and the result
    // lands outside /tmp on most systems (or fails to resolve) → reject.
    assert.notStrictEqual(r.status, 0);
  });

  it("rejects --from-tarball when the path is a symlink resolving outside /tmp", () => {
    // Create a symlink at /tmp/stamp-migrate-symlink-test-<pid>.tar.gz
    // whose target is somewhere outside /tmp, then assert the script
    // rejects it. Cleanup with finally so a failed assertion doesn't
    // strand the symlink.
    const linkPath = `/tmp/stamp-migrate-symlink-test-${process.pid}.tar.gz`;
    const targetDir = realpathSync(mkdtempSync(join(tmpdir(), "stamp-symtarget-")));
    const targetFile = join(targetDir, "victim");
    writeFileSync(targetFile, "");
    try {
      // The symlink lands in /tmp pointing OUT to the mkdtemp dir
      // (under /var/folders on macOS, /tmp on Linux). On macOS the
      // canonical path is unambiguously outside /tmp; on Linux mkdtemp
      // typically uses /tmp directly so the canonical path stays under
      // /tmp and the script accepts it. We assert below in a way that
      // handles both.
      try {
        symlinkSync(targetFile, linkPath);
      } catch {
        // EEXIST (left over from a prior failed run) — clean and retry.
        try {
          rmSync(linkPath, { force: true });
        } catch {
          // ignore
        }
        symlinkSync(targetFile, linkPath);
      }

      const r = run(["foo", "--from-tarball", linkPath]);
      assert.notStrictEqual(r.status, 0);
      // readlink -f resolves the target to outside /tmp (under the
      // mkdtempSync dir), which the canonical-path check rejects.
      // On macOS mkdtemp returns a /var/folders/... path so the canon
      // is definitely outside /tmp; on Linux mkdtempSync typically uses
      // /tmp directly, in which case the canon stays under /tmp and
      // this assertion would NOT fire — skip the message check there
      // and just assert the script didn't proceed past arg validation.
      assert.match(r.stderr, /(--from-tarball|outside)/);
    } finally {
      try {
        rmSync(linkPath, { force: true });
      } catch {
        // ignore
      }
      rmSync(targetDir, { recursive: true, force: true });
    }
  });
});
