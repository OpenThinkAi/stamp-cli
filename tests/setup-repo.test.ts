/**
 * Integration tests for the path-traversal hardening added to
 * scripts/setup-repo.sh's `--from-tarball` mode (AGT-033 / audit M2).
 *
 * Scope: the rejection path. We craft tarballs whose entries contain
 * absolute paths or `..` segments and assert setup-repo.sh exits non-zero
 * with a clear "unsafe entry" error and writes nothing to the target
 * REPO_DIR. The successful-extraction path uses a GNU-tar-only flag
 * (`--no-overwrite-dir`); the AGT-2266 suite below runs it through a PATH
 * shim that drops that flag so it works on BSD-tar macOS boxes too.
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
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

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
    // whose target is under the operator's home dir — outside /tmp on
    // every supported platform (macOS, Linux). Earlier revision used
    // mkdtempSync(tmpdir()) which lands in /tmp on Linux, so the
    // canonical path stayed under /tmp and the script accepted it →
    // false negative on Linux CI. homedir() dodges that.
    const linkPath = `/tmp/stamp-migrate-symlink-test-${process.pid}.tar.gz`;
    const targetDir = realpathSync(mkdtempSync(join(homedir(), ".stamp-symtarget-")));
    const targetFile = join(targetDir, "victim");
    writeFileSync(targetFile, "");
    try {
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
      // The canonical-path check resolves the symlink to under homedir
      // (outside /tmp) and refuses with the "outside /tmp" message.
      // Pin the message so a future regression where the readlink
      // re-check is removed surfaces here, not just by way of a
      // not-zero exit (which the bare prefix-match would also produce).
      assert.match(r.stderr, /outside \/tmp/);
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

// ---- AGT-2266 (+ folded AGT-2268, AGT-2269): tarball config/hooks stripped ----

describe("setup-repo.sh --from-tarball does not trust the tarball's config or hooks (AGT-2266)", () => {
  let tmp: string;
  let shimDir: string;

  beforeEach(() => {
    tmp = realpathSync(mkdtempSync(join(tmpdir(), "stamp-setuprepo-2266-")));
    // The script passes GNU-tar-only `--no-overwrite-dir`; macOS bsdtar
    // rejects it outright. A PATH shim drops that one flag so the success
    // path runs on every dev box. Production (Alpine, GNU tar) is
    // unaffected; the flag is irrelevant to what these tests assert.
    shimDir = join(tmp, "shim");
    mkdirSync(shimDir);
    const realTar = execFileSync("sh", ["-c", "command -v tar"], { encoding: "utf8" }).trim();
    writeFileSync(
      join(shimDir, "tar"),
      `#!/usr/bin/env bash\nargs=()\nfor a in "$@"; do [[ "$a" == --no-overwrite-dir ]] || args+=("$a"); done\nexec ${JSON.stringify(realTar)} "\${args[@]}"\n`,
      { mode: 0o755 },
    );
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  const git = (args: string[], cwd?: string, env?: NodeJS.ProcessEnv): string =>
    execFileSync("git", args, { cwd, encoding: "utf8", env: env ?? process.env, stdio: "pipe" }).trim();

  function makePubKey(): string {
    const path = join(tmp, "trusted.pub");
    const { publicKey } = generateKeyPairSync("ed25519");
    writeFileSync(path, publicKey.export({ type: "spki", format: "pem" }) as string);
    return path;
  }

  // Stand-in for the stamp-verify hook: rejects every push and leaves a
  // marker, so a test can tell whether git actually ran it.
  function makeRejectingHook(): { hook: string; marker: string } {
    const marker = join(tmp, "stamp-hook-ran");
    const hook = join(tmp, "hooks-src", "pre-receive.cjs");
    mkdirSync(dirname(hook), { recursive: true });
    writeFileSync(hook, `#!/bin/sh\ntouch ${JSON.stringify(marker)}\necho stamp-verify-rejected >&2\nexit 1\n`, { mode: 0o755 });
    return { hook, marker };
  }

  /** A work repo with history on `trunk` + a `feature` branch and a tag. */
  function makeWorkRepo(): string {
    const work = join(tmp, "work");
    mkdirSync(work);
    git(["init", "-q", "--initial-branch=trunk"], work);
    git(["config", "user.email", "t@example.com"], work);
    git(["config", "user.name", "t"], work);
    writeFileSync(join(work, "a.txt"), "one\n");
    git(["add", "."], work);
    git(["commit", "-q", "-m", "one"], work);
    git(["branch", "feature"], work);
    git(["tag", "v1"], work);
    writeFileSync(join(work, "a.txt"), "two\n");
    git(["commit", "-q", "-am", "two"], work);
    return work;
  }

  /** Bare clone of `work`, poisoned the ways the audit findings describe. */
  function makeHostileTarball(work: string): { tarball: string; evilHooks: string } {
    const stage = join(tmp, "stage");
    mkdirSync(stage);
    const bare = join(stage, "proj.git");
    git(["clone", "-q", "--bare", work, bare]);

    // (1) core.hooksPath pointing at an attacker dir with an accept-all
    //     pre-receive — git would run that instead of the stamp hook.
    const evilHooks = join(tmp, "evil-hooks");
    mkdirSync(evilHooks);
    writeFileSync(join(evilHooks, "pre-receive"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    git(["--git-dir", bare, "config", "core.hooksPath", evilHooks]);
    // (2) receive.* weakening + an include of an arbitrary file.
    git(["--git-dir", bare, "config", "receive.denyNonFastForwards", "false"]);
    git(["--git-dir", bare, "config", "receive.denyDeletes", "false"]);
    writeFileSync(join(tmp, "included.cfg"), `[core]\n\thooksPath = ${evilHooks}\n`);
    git(["--git-dir", bare, "config", "include.path", join(tmp, "included.cfg")]);
    // (3) extra executable hooks that would run server-side on every push.
    for (const h of ["update", "post-update", "reference-transaction", "proc-receive", "post-receive"]) {
      writeFileSync(join(bare, "hooks", h), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    }
    // (4) alternates / commondir / grafts redirecting lookups elsewhere.
    mkdirSync(join(bare, "objects", "info"), { recursive: true });
    writeFileSync(join(bare, "objects", "info", "alternates"), join(tmp, "elsewhere.git", "objects") + "\n");
    writeFileSync(join(bare, "info", "grafts"), "");

    const tarball = join(tmp, "proj.tar.gz");
    execFileSync("tar", ["-czf", tarball, "-C", stage, "proj.git"], { stdio: "pipe" });
    return { tarball, evilHooks };
  }

  function runSetup(repo: string, hook: string, tarball: string, extraEnv: NodeJS.ProcessEnv = {}) {
    return spawnSync("bash", [SCRIPT, repo, hook, makePubKey(), "--from-tarball", tarball], {
      encoding: "utf8",
      env: { ...process.env, PATH: `${shimDir}:${process.env.PATH}`, ...extraEnv },
    });
  }

  it("imports history but drops the tarball's config, hooks and alternates; the stamp hook gates pushes", () => {
    const work = makeWorkRepo();
    const { tarball, evilHooks } = makeHostileTarball(work);
    const { hook, marker } = makeRejectingHook();
    const repo = join(tmp, "out.git");

    const res = runSetup(repo, hook, tarball);
    assert.strictEqual(res.status, 0, `setup-repo.sh failed: ${res.stderr}`);

    // History, branches, tags and the default branch survive the import.
    assert.strictEqual(git(["--git-dir", repo, "rev-parse", "refs/heads/trunk"]), git(["rev-parse", "trunk"], work));
    assert.strictEqual(git(["--git-dir", repo, "rev-parse", "refs/heads/feature"]), git(["rev-parse", "feature"], work));
    assert.strictEqual(git(["--git-dir", repo, "rev-parse", "refs/tags/v1"]), git(["rev-parse", "v1"], work));
    assert.strictEqual(git(["--git-dir", repo, "symbolic-ref", "HEAD"]), "refs/heads/trunk");

    // Tarball config is gone; server settings are applied.
    const cfg = spawnSync("git", ["--git-dir", repo, "config", "--get", "core.hooksPath"], { encoding: "utf8" });
    assert.notStrictEqual(cfg.status, 0, `core.hooksPath must be unset, got: ${cfg.stdout}`);
    assert.strictEqual(git(["--git-dir", repo, "config", "--get", "receive.denyNonFastForwards"]), "true");
    const deletes = spawnSync("git", ["--git-dir", repo, "config", "--get", "receive.denyDeletes"], { encoding: "utf8" });
    assert.notStrictEqual(deletes.status, 0, "tarball receive.* settings must not survive");
    const inc = spawnSync("git", ["--git-dir", repo, "config", "--get", "include.path"], { encoding: "utf8" });
    assert.notStrictEqual(inc.status, 0, "tarball include.path must not survive");

    // Only stamp's hook is live; tarball hooks are gone. (git never runs
    // `*.sample` files, which `git init` may template in executable.)
    const execHooks = readdirSync(join(repo, "hooks")).filter(
      (h) => !h.endsWith(".sample") && (statSync(join(repo, "hooks", h)).mode & 0o111) !== 0,
    );
    assert.deepStrictEqual(execHooks, ["pre-receive"]);
    assert.ok(!existsSync(join(repo, "objects", "info", "alternates")), "alternates must not survive");
    assert.ok(!existsSync(join(repo, "info", "grafts")), "grafts must not survive");
    assert.ok(!existsSync(join(repo, "commondir")), "commondir must not survive");

    // End to end: a push runs the installed stamp hook, not the tarball's
    // accept-all hooksPath, and is rejected.
    writeFileSync(join(work, "a.txt"), "three\n");
    git(["commit", "-q", "-am", "three"], work);
    const push = spawnSync("git", ["push", repo, "trunk"], { cwd: work, encoding: "utf8" });
    assert.notStrictEqual(push.status, 0, "push must be rejected by the stamp hook");
    assert.match(push.stderr, /stamp-verify-rejected/);
    assert.ok(existsSync(marker), "stamp pre-receive must have run");
    assert.ok(existsSync(join(evilHooks, "pre-receive")));
  });

  it("rejects a tarball that contains a symlink", () => {
    const stage = join(tmp, "stage-link");
    const bare = join(stage, "proj.git");
    mkdirSync(stage);
    git(["init", "-q", "--bare", bare]);
    rmSync(join(bare, "hooks"), { recursive: true, force: true });
    const target = join(tmp, "elsewhere-hooks");
    mkdirSync(target);
    symlinkSync(target, join(bare, "hooks"));
    const tarball = join(tmp, "link.tar.gz");
    execFileSync("tar", ["-czf", tarball, "-C", stage, "proj.git"], { stdio: "pipe" });

    const { hook } = makeRejectingHook();
    const repo = join(tmp, "out-link.git");
    const res = runSetup(repo, hook, tarball);
    assert.notStrictEqual(res.status, 0);
    // Refused by the pre-extraction entry check (AGT-2267).
    assert.match(res.stderr, /contains a link or special-file entry: .*proj\.git\/hooks/);
    assert.ok(!existsSync(repo), "REPO_DIR must not be created");
  });

  it("refuses to report ready when core.hooksPath comes from another config source", () => {
    const work = makeWorkRepo();
    const { tarball, evilHooks } = makeHostileTarball(work);
    const { hook } = makeRejectingHook();
    const globalCfg = join(tmp, "global.gitconfig");
    writeFileSync(globalCfg, `[core]\n\thooksPath = ${evilHooks}\n`);
    const res = runSetup(join(tmp, "out-global.git"), hook, tarball, { GIT_CONFIG_GLOBAL: globalCfg });
    assert.notStrictEqual(res.status, 0);
    assert.match(res.stderr, /core\.hooksPath is set/);
    assert.doesNotMatch(res.stdout, /repo ready/);
    assert.ok(!existsSync(join(tmp, "out-global.git")), "half-built REPO_DIR must be removed");
  });

  it("ignores a `.git` gitfile that would redirect the import to another repo on the host", () => {
    // upload-pack's non-strict path discovery tries `<path>/.git` first and
    // follows gitfiles, so a tarball shipping `.git: gitdir: <victim>` could
    // make the import copy another tenant's history. The allowlist copy (and
    // `upload-pack --strict`) must keep that from happening.
    const victimWork = join(tmp, "victim-work");
    mkdirSync(victimWork);
    git(["init", "-q", "--initial-branch=main"], victimWork);
    git(["config", "user.email", "v@example.com"], victimWork);
    git(["config", "user.name", "v"], victimWork);
    writeFileSync(join(victimWork, "secret.txt"), "secret\n");
    git(["add", "."], victimWork);
    git(["commit", "-q", "-m", "secret"], victimWork);
    git(["branch", "victim-secret"], victimWork);
    const victim = join(tmp, "victim.git");
    git(["clone", "-q", "--bare", victimWork, victim]);
    const victimSha = git(["--git-dir", victim, "rev-parse", "refs/heads/victim-secret"]);

    const work = makeWorkRepo();
    const stage = join(tmp, "stage-gitfile");
    mkdirSync(stage);
    const bare = join(stage, "proj.git");
    git(["clone", "-q", "--bare", work, bare]);
    writeFileSync(join(bare, ".git"), `gitdir: ${victim}\n`);
    const tarball = join(tmp, "gitfile.tar.gz");
    execFileSync("tar", ["-czf", tarball, "-C", stage, "proj.git"], { stdio: "pipe" });

    const { hook } = makeRejectingHook();
    const repo = join(tmp, "out-gitfile.git");
    const res = runSetup(repo, hook, tarball);
    assert.strictEqual(res.status, 0, `setup-repo.sh failed: ${res.stderr}`);
    const refs = git(["--git-dir", repo, "for-each-ref", "--format=%(refname)"]);
    assert.doesNotMatch(refs, /victim-secret/, "victim refs must not be imported");
    const has = spawnSync("git", ["--git-dir", repo, "cat-file", "-e", victimSha], { encoding: "utf8" });
    assert.notStrictEqual(has.status, 0, "victim objects must not be imported");
    assert.strictEqual(git(["--git-dir", repo, "rev-parse", "refs/heads/trunk"]), git(["rev-parse", "trunk"], work));
  });

  it("rejects a shallow clone with a clear message", () => {
    const work = makeWorkRepo();
    const stage = join(tmp, "stage-shallow");
    mkdirSync(stage);
    const bare = join(stage, "proj.git");
    git(["clone", "-q", "--bare", "--depth=1", `file://${work}`, bare]);
    const tarball = join(tmp, "shallow.tar.gz");
    execFileSync("tar", ["-czf", tarball, "-C", stage, "proj.git"], { stdio: "pipe" });
    const { hook } = makeRejectingHook();
    const res = runSetup(join(tmp, "out-shallow.git"), hook, tarball);
    assert.notStrictEqual(res.status, 0);
    assert.match(res.stderr, /shallow clone/);
  });
});

// ---- AGT-2267: link / special entries refused BEFORE extraction ----

/** One entry of a hand-built ustar archive (full control over type + names). */
type TarEntry = { name: string; type: "0" | "1" | "2" | "5" | "6"; data?: string; linkname?: string };

/**
 * Minimal ustar writer. System tar won't emit hostile shapes (a symlink
 * followed by a file written through it, a regular entry carrying a link
 * name), so the tests build the bytes themselves.
 */
function ustar(entries: TarEntry[]): Buffer {
  const blocks: Buffer[] = [];
  for (const e of entries) {
    const body = Buffer.from(e.data ?? "");
    const h = Buffer.alloc(512);
    const put = (off: number, len: number, v: string) => h.write(v, off, len, "utf8");
    const oct = (off: number, len: number, n: number) => put(off, len, n.toString(8).padStart(len - 1, "0") + "\0");
    put(0, 100, e.name);
    oct(100, 8, e.type === "5" ? 0o755 : 0o644);
    oct(108, 8, 0);
    oct(116, 8, 0);
    oct(124, 12, e.type === "0" ? body.length : 0);
    oct(136, 12, 1_700_000_000);
    h.fill(0x20, 148, 156); // checksum field counts as spaces while summing
    put(156, 1, e.type);
    put(157, 100, e.linkname ?? "");
    put(257, 6, "ustar\0");
    put(263, 2, "00");
    let sum = 0;
    for (const b of h) sum += b;
    put(148, 8, sum.toString(8).padStart(6, "0") + "\0 ");
    blocks.push(h);
    if (e.type === "0" && body.length > 0) {
      const padded = Buffer.alloc(Math.ceil(body.length / 512) * 512);
      body.copy(padded);
      blocks.push(padded);
    }
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
}

describe("setup-repo.sh --from-tarball refuses link and special entries before extraction (AGT-2267)", () => {
  let tmp: string;
  let shimDir: string;
  let outside: string;

  beforeEach(() => {
    tmp = realpathSync(mkdtempSync(join(tmpdir(), "stamp-setuprepo-2267-")));
    // Same --no-overwrite-dir shim as the AGT-2266 suite (bsdtar lacks it).
    shimDir = join(tmp, "shim");
    mkdirSync(shimDir);
    const realTar = execFileSync("sh", ["-c", "command -v tar"], { encoding: "utf8" }).trim();
    writeFileSync(
      join(shimDir, "tar"),
      `#!/usr/bin/env bash\nargs=()\nfor a in "$@"; do [[ "$a" == --no-overwrite-dir ]] || args+=("$a"); done\nexec ${JSON.stringify(realTar)} "\${args[@]}"\n`,
      { mode: 0o755 },
    );
    // Stand-in for "another repo's hooks dir on the host": must stay empty.
    outside = join(tmp, "victim-hooks");
    mkdirSync(outside);
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  function runSetup(repo: string, tarball: string, path = `${shimDir}:${process.env.PATH}`) {
    const pub = join(tmp, "trusted.pub");
    const { publicKey } = generateKeyPairSync("ed25519");
    writeFileSync(pub, publicKey.export({ type: "spki", format: "pem" }) as string);
    const hook = join(tmp, "pre-receive.cjs");
    writeFileSync(hook, "#!/bin/sh\nexit 1\n", { mode: 0o755 });
    return spawnSync("bash", [SCRIPT, repo, hook, pub, "--from-tarball", tarball], {
      encoding: "utf8",
      env: { ...process.env, PATH: path },
    });
  }

  const base: TarEntry[] = [
    { name: "proj.git/", type: "5" },
    { name: "proj.git/HEAD", type: "0", data: "ref: refs/heads/main\n" },
    { name: "proj.git/refs/", type: "5" },
    { name: "proj.git/objects/", type: "5" },
  ];

  function assertRefused(entries: TarEntry[], stderrPattern: RegExp) {
    const tarball = join(tmp, "hostile.tar.gz");
    writeFileSync(tarball, ustar(entries));
    const repo = join(tmp, "out.git");
    const res = runSetup(repo, tarball);
    assert.notStrictEqual(res.status, 0, `must be refused; stdout: ${res.stdout}`);
    assert.match(res.stderr, stderrPattern);
    // Refused before extraction: nothing reached the host.
    assert.doesNotMatch(res.stdout, /extracting/);
    assert.ok(!existsSync(repo), "REPO_DIR must not be created");
    assert.deepStrictEqual(readdirSync(outside), [], "nothing may be written outside the scratch dir");
  }

  it("refuses a symlink entry followed by a file written through it", () => {
    assertRefused(
      [
        ...base,
        { name: "proj.git/hooks", type: "2", linkname: outside },
        { name: "proj.git/hooks/post-update", type: "0", data: "#!/bin/sh\necho pwned\n" },
      ],
      /link or special-file entry: .*proj\.git\/hooks/,
    );
  });

  it("refuses a hardlink entry", () => {
    const victim = join(outside, "..", "victim-file");
    writeFileSync(victim, "do not touch\n");
    assertRefused(
      [...base, { name: "proj.git/packed-refs", type: "1", linkname: victim }],
      /link or special-file entry: .*proj\.git\/packed-refs/,
    );
  });

  it("refuses a fifo entry", () => {
    assertRefused([...base, { name: "proj.git/fifo", type: "6" }], /link or special-file entry: .*proj\.git\/fifo/);
  });

  it("refuses an absolute-path entry", () => {
    assertRefused([...base, { name: `${outside}/abs`, type: "0", data: "x" }], /unsafe entry: \//);
  });

  it("refuses a `..` path entry", () => {
    assertRefused([...base, { name: "proj.git/../../victim-hooks/rel", type: "0", data: "x" }], /unsafe entry: .*\.\./);
  });

  it("still catches a symlink after extraction if a tar's listing misses it (defense in depth)", () => {
    // A tar whose listings come back empty: the pre-extraction checks see
    // nothing, so only the post-extraction allowlist scan stands between
    // the symlink and the import.
    const lying = join(tmp, "lying-shim");
    mkdirSync(lying);
    writeFileSync(
      join(lying, "tar"),
      `#!/usr/bin/env bash\nfor a in "$@"; do [[ "$a" == -t* ]] && exit 0; done\nexec ${JSON.stringify(join(shimDir, "tar"))} "$@"\n`,
      { mode: 0o755 },
    );
    const tarball = join(tmp, "dangling.tar.gz");
    writeFileSync(tarball, ustar([...base, { name: "proj.git/refs/evil", type: "2", linkname: outside }]));
    const repo = join(tmp, "out-dangling.git");
    const res = runSetup(repo, tarball, `${lying}:${process.env.PATH}`);
    assert.notStrictEqual(res.status, 0);
    assert.match(res.stderr, /extracted a symlink, hardlink or special file: refs\/evil/);
    assert.ok(!existsSync(repo), "REPO_DIR must not be created");
  });

  it("still imports a clean hand-built tarball", () => {
    const work = join(tmp, "work");
    mkdirSync(work);
    const git = (args: string[], cwd?: string) => execFileSync("git", args, { cwd, encoding: "utf8", stdio: "pipe" }).trim();
    git(["init", "-q", "--initial-branch=main"], work);
    git(["config", "user.email", "t@example.com"], work);
    git(["config", "user.name", "t"], work);
    writeFileSync(join(work, "a.txt"), "one\n");
    git(["add", "."], work);
    git(["commit", "-q", "-m", "one"], work);
    const stage = join(tmp, "stage");
    mkdirSync(stage);
    git(["clone", "-q", "--bare", work, join(stage, "proj.git")]);
    const tarball = join(tmp, "clean.tar.gz");
    execFileSync("tar", ["-czf", tarball, "-C", stage, "proj.git"], { stdio: "pipe" });
    const repo = join(tmp, "out-clean.git");
    const res = runSetup(repo, tarball);
    assert.strictEqual(res.status, 0, `setup-repo.sh failed: ${res.stderr}`);
    assert.strictEqual(git(["--git-dir", repo, "rev-parse", "refs/heads/main"]), git(["rev-parse", "main"], work));
  });
});
