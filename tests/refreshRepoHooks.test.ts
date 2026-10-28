/**
 * AGT-2261: Shell-level tests for server/lib/refresh-repo-hooks.sh.
 *
 * The entrypoint runs `_refresh_repo_hooks` as root over git-owned repos,
 * so anything inside a repo may have been planted by the git user. These
 * tests plant the shapes an attacker would (symlinked hooks/, symlinked or
 * hard-linked hook files, a symlinked repo path, a pre-planted staging
 * entry) and assert the refresh installs real hooks without ever writing
 * through, re-owning or re-moding what the planted entries point at.
 *
 * Runs unprivileged: the owner knobs are pointed at the current uid:gid and
 * the roots at a tmpdir the test owns. The real root/git ownership and the
 * container wiring are covered by scripts/docker-boot-smoke.sh.
 */

import { strict as assert } from "node:assert";
import {
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";

const LIB = path.resolve(import.meta.dirname, "..", "server", "lib", "refresh-repo-hooks.sh");

const PRE = "#!/bin/sh\n# fresh pre-receive\n";
const POST = "#!/bin/sh\n# fresh post-receive\n";
const SENTINEL = "sentinel: must never change\n";

interface Harness {
  dir: string;
  gitRoot: string;
  srcDir: string;
  outside: string;
  cleanup: () => void;
}

function setup(opts: { post?: boolean } = {}): Harness {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-refresh-hooks-"));
  const gitRoot = path.join(dir, "srv-git");
  const srcDir = path.join(dir, "etc-stamp");
  const outside = path.join(dir, "outside");
  mkdirSync(gitRoot);
  mkdirSync(srcDir);
  mkdirSync(outside);
  writeFileSync(path.join(srcDir, "pre-receive.cjs"), PRE, { mode: 0o644 });
  if (opts.post !== false) writeFileSync(path.join(srcDir, "post-receive.cjs"), POST, { mode: 0o644 });
  return { dir, gitRoot, srcDir, outside, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function bareRepo(h: Harness, name: string, withHooksDir = true): string {
  const repo = path.join(h.gitRoot, `${name}.git`);
  mkdirSync(repo);
  writeFileSync(path.join(repo, "HEAD"), "ref: refs/heads/main\n");
  if (withHooksDir) mkdirSync(path.join(repo, "hooks"));
  return repo;
}

function sentinelFile(h: Harness, name: string): string {
  const p = path.join(h.outside, name);
  writeFileSync(p, SENTINEL, { mode: 0o600 });
  return p;
}

function run(h: Harness): { status: number | null; stderr: string } {
  const owner = `${process.getuid!()}:${process.getgid!()}`;
  const r = spawnSync("sh", ["-c", `. "${LIB}" && _refresh_repo_hooks`], {
    env: {
      PATH: process.env["PATH"],
      STAMP_GIT_ROOT: h.gitRoot,
      STAMP_HOOK_SRC_DIR: h.srcDir,
      STAMP_HOOK_OWNER: owner,
      STAMP_HOOKS_DIR_OWNER: owner,
      // Edit repo config as the current (unprivileged) user, not via su.
      STAMP_REPO_CONFIG_USER: "",
      STAMP_GIT_HOME: path.join(h.dir, "home-git"),
    },
    encoding: "utf8",
  });
  return { status: r.status, stderr: r.stderr ?? "" };
}

function assertInstalled(repo: string, hook: "pre-receive" | "post-receive", body: string): void {
  const p = path.join(repo, "hooks", hook);
  const st = lstatSync(p);
  assert.ok(st.isFile() && !st.isSymbolicLink(), `${p} should be a regular file`);
  assert.equal(st.mode & 0o7777, 0o755, `${p} mode`);
  assert.equal(st.nlink, 1, `${p} should not share an inode`);
  assert.equal(readFileSync(p, "utf8"), body);
}

function assertSentinel(p: string): void {
  assert.equal(readFileSync(p, "utf8"), SENTINEL, `${p} content changed`);
  assert.equal(statSync(p).mode & 0o7777, 0o600, `${p} mode changed`);
}

describe("AGT-2261: refresh-repo-hooks.sh", () => {
  it("replaces stale hooks with the bundle, mode 0755, and leaves no staging dir", () => {
    const h = setup();
    try {
      const repo = bareRepo(h, "a");
      writeFileSync(path.join(repo, "hooks", "pre-receive"), "stale\n", { mode: 0o777 });
      const r = run(h);
      assert.equal(r.status, 0, r.stderr);
      assertInstalled(repo, "pre-receive", PRE);
      assertInstalled(repo, "post-receive", POST);
      assert.ok(!existsSync(path.join(h.gitRoot, ".stamp-hook-staging")));
    } finally {
      h.cleanup();
    }
  });

  it("replaces a symlinked hook file without writing through or re-moding its target", () => {
    const h = setup();
    try {
      const repo = bareRepo(h, "a");
      const pre = sentinelFile(h, "pre-target");
      const post = sentinelFile(h, "post-target");
      symlinkSync(pre, path.join(repo, "hooks", "pre-receive"));
      symlinkSync(post, path.join(repo, "hooks", "post-receive"));
      const r = run(h);
      assert.equal(r.status, 0, r.stderr);
      assertSentinel(pre);
      assertSentinel(post);
      assertInstalled(repo, "pre-receive", PRE);
      assertInstalled(repo, "post-receive", POST);
      assert.match(r.stderr, /was a symlink; replacing the link/);
    } finally {
      h.cleanup();
    }
  });

  it("replaces a hook symlink that points at a directory; the directory gains nothing", () => {
    const h = setup();
    try {
      const repo = bareRepo(h, "a");
      const targetDir = path.join(h.outside, "hook-link-dir");
      mkdirSync(targetDir);
      symlinkSync(targetDir, path.join(repo, "hooks", "pre-receive"));
      symlinkSync(targetDir, path.join(repo, "hooks", "post-receive"));
      const r = run(h);
      assert.equal(r.status, 0, r.stderr);
      assert.deepEqual(readdirSync(targetDir), [], "mv followed the link into its target dir");
      assertInstalled(repo, "pre-receive", PRE);
      assertInstalled(repo, "post-receive", POST);
    } finally {
      h.cleanup();
    }
  });

  it("replaces a dangling hook symlink without creating its target", () => {
    const h = setup();
    try {
      const repo = bareRepo(h, "a");
      const target = path.join(h.outside, "would-be-created");
      symlinkSync(target, path.join(repo, "hooks", "pre-receive"));
      const r = run(h);
      assert.equal(r.status, 0, r.stderr);
      assert.ok(!existsSync(target), "root created the dangling link's target");
      assertInstalled(repo, "pre-receive", PRE);
    } finally {
      h.cleanup();
    }
  });

  it("replaces a hard-linked hook file without modifying the shared inode", () => {
    const h = setup();
    try {
      const repo = bareRepo(h, "a");
      const target = sentinelFile(h, "hard-target");
      linkSync(target, path.join(repo, "hooks", "pre-receive"));
      const r = run(h);
      assert.equal(r.status, 0, r.stderr);
      assertSentinel(target);
      assert.equal(statSync(target).nlink, 1);
      assertInstalled(repo, "pre-receive", PRE);
    } finally {
      h.cleanup();
    }
  });

  it("replaces a symlinked hooks/ dir with a real one; the target dir gains nothing", () => {
    const h = setup();
    try {
      const repo = bareRepo(h, "a", false);
      const targetDir = path.join(h.outside, "hookdir");
      mkdirSync(targetDir);
      const marker = sentinelFile(h, path.join("hookdir", "marker"));
      symlinkSync(targetDir, path.join(repo, "hooks"));
      const r = run(h);
      assert.equal(r.status, 0, r.stderr);
      assert.deepEqual(readdirSync(targetDir), ["marker"]);
      assertSentinel(marker);
      const st = lstatSync(path.join(repo, "hooks"));
      assert.ok(st.isDirectory() && !st.isSymbolicLink());
      assertInstalled(repo, "pre-receive", PRE);
      assertInstalled(repo, "post-receive", POST);
      assert.match(r.stderr, /is not a real directory; replacing it/);
    } finally {
      h.cleanup();
    }
  });

  it("replaces a hooks/ that is a regular file, and creates a missing hooks/", () => {
    const h = setup();
    try {
      const fileHooks = bareRepo(h, "a", false);
      writeFileSync(path.join(fileHooks, "hooks"), "not a dir\n");
      const noHooks = bareRepo(h, "b", false);
      const r = run(h);
      assert.equal(r.status, 0, r.stderr);
      for (const repo of [fileHooks, noHooks]) {
        assert.ok(lstatSync(path.join(repo, "hooks")).isDirectory());
        assertInstalled(repo, "pre-receive", PRE);
      }
    } finally {
      h.cleanup();
    }
  });

  it("replaces a hook entry that is a directory", () => {
    const h = setup();
    try {
      const repo = bareRepo(h, "a");
      mkdirSync(path.join(repo, "hooks", "post-receive"));
      writeFileSync(path.join(repo, "hooks", "post-receive", "x"), "x");
      const r = run(h);
      assert.equal(r.status, 0, r.stderr);
      assertInstalled(repo, "post-receive", POST);
    } finally {
      h.cleanup();
    }
  });

  it("skips a symlinked repo path; nothing is written under its target", () => {
    const h = setup();
    try {
      const realElsewhere = path.join(h.outside, "elsewhere.git");
      mkdirSync(path.join(realElsewhere, "hooks"), { recursive: true });
      symlinkSync(realElsewhere, path.join(h.gitRoot, "evil.git"));
      const good = bareRepo(h, "good");
      const r = run(h);
      assert.equal(r.status, 0, r.stderr);
      assert.deepEqual(readdirSync(path.join(realElsewhere, "hooks")), []);
      assertInstalled(good, "pre-receive", PRE);
      assert.match(r.stderr, /skipping symlinked repo path/);
    } finally {
      h.cleanup();
    }
  });

  it("clears a pre-planted staging symlink without touching its target", () => {
    const h = setup();
    try {
      const repo = bareRepo(h, "a");
      const targetDir = path.join(h.outside, "stage-target");
      mkdirSync(targetDir);
      symlinkSync(targetDir, path.join(h.gitRoot, ".stamp-hook-staging"));
      const r = run(h);
      assert.equal(r.status, 0, r.stderr);
      assert.deepEqual(readdirSync(targetDir), []);
      assert.ok(!existsSync(path.join(h.gitRoot, ".stamp-hook-staging")));
      assertInstalled(repo, "pre-receive", PRE);
    } finally {
      h.cleanup();
    }
  });

  it("installs only the hooks present in the bundle; an empty volume is a no-op", () => {
    const h = setup({ post: false });
    try {
      let r = run(h);
      assert.equal(r.status, 0, r.stderr);
      const repo = bareRepo(h, "a");
      r = run(h);
      assert.equal(r.status, 0, r.stderr);
      assertInstalled(repo, "pre-receive", PRE);
      assert.ok(!existsSync(path.join(repo, "hooks", "post-receive")));
    } finally {
      h.cleanup();
    }
  });

  // ─── AGT-2249: hook-redirecting config keys ───────────────────────

  function gitCfg(repo: string, ...args: string[]): { status: number | null; stdout: string } {
    const r = spawnSync("git", ["config", "--file", path.join(repo, "config"), ...args], {
      encoding: "utf8",
    });
    return { status: r.status, stdout: r.stdout ?? "" };
  }

  it("removes core.hooksPath and include paths from a repo's config, keeping other keys", () => {
    const h = setup();
    try {
      const repo = bareRepo(h, "redirected");
      writeFileSync(
        path.join(repo, "config"),
        "[core]\n\tbare = true\n\thooksPath = /tmp/evil-hooks\n" +
          "[include]\n\tpath = /tmp/evil.cfg\n" +
          '[includeIf "gitdir:/srv/"]\n\tpath = /tmp/evil2.cfg\n' +
          "[receive]\n\tfsckObjects = true\n",
      );
      const r = run(h);
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stderr, /removed 'core\.hookspath' from .*redirected\.git\/config/);
      assert.match(r.stderr, /removed 'include\.path'/);
      assert.match(r.stderr, /removed 'includeif\.gitdir:\/srv\/\.path'/);
      assert.notEqual(gitCfg(repo, "--get", "core.hooksPath").status, 0);
      assert.notEqual(gitCfg(repo, "--get", "include.path").status, 0);
      assert.equal(gitCfg(repo, "--get", "core.bare").stdout.trim(), "true");
      assert.equal(gitCfg(repo, "--get", "receive.fsckObjects").stdout.trim(), "true");
      // Hooks were still installed.
      assert.equal(readFileSync(path.join(repo, "hooks", "pre-receive"), "utf8"), PRE);
    } finally {
      h.cleanup();
    }
  });

  it("leaves a clean config untouched and says nothing", () => {
    const h = setup();
    try {
      const repo = bareRepo(h, "clean");
      const body = "[core]\n\tbare = true\n";
      writeFileSync(path.join(repo, "config"), body);
      const r = run(h);
      assert.equal(r.status, 0, r.stderr);
      assert.doesNotMatch(r.stderr, /removed/);
      assert.equal(readFileSync(path.join(repo, "config"), "utf8"), body);
    } finally {
      h.cleanup();
    }
  });

  it("warns (does not fail) on a config git cannot parse", () => {
    const h = setup();
    try {
      const repo = bareRepo(h, "garbled");
      writeFileSync(path.join(repo, "config"), "[core\n\thooksPath = /tmp/x\n");
      const r = run(h);
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stderr, /is not readable as git config/);
    } finally {
      h.cleanup();
    }
  });

  it("removes core.hooksPath from the git user's global config", () => {
    const h = setup();
    try {
      const home = path.join(h.dir, "home-git");
      mkdirSync(path.join(home, ".config", "git"), { recursive: true });
      writeFileSync(path.join(home, ".gitconfig"), "[core]\n\thooksPath = /tmp/evil\n[user]\n\tname = git\n");
      writeFileSync(path.join(home, ".config", "git", "config"), "[core]\n\thooksPath = /tmp/evil2\n");
      const r = run(h);
      assert.equal(r.status, 0, r.stderr);
      for (const f of [path.join(home, ".gitconfig"), path.join(home, ".config", "git", "config")]) {
        const g = spawnSync("git", ["config", "--file", f, "--get", "core.hooksPath"], { encoding: "utf8" });
        assert.notEqual(g.status, 0, `${f} still sets core.hooksPath`);
      }
      assert.match(readFileSync(path.join(home, ".gitconfig"), "utf8"), /name = git/);
      assert.match(r.stderr, /removed 'core\.hookspath' from .*\.gitconfig/);
    } finally {
      h.cleanup();
    }
  });
});
