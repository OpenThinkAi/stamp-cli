/**
 * AGT-2277: server/lib/prompts-cache-config.sh (the entrypoint's cache-root
 * check and deploy-key fallback) and src/server/promptsCachePaths.ts (the
 * same answers for the bootstrap, stamp-workers and stamp-review).
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import {
  DEFAULT_PROMPTS_CACHE_ROOT,
  DEFAULT_PROMPTS_DEPLOY_KEY_PATH,
  resolvePromptsCacheRoot,
  resolvePromptsDeployKeyPath,
} from "../src/server/promptsCachePaths.ts";

const ROOT = path.resolve(import.meta.dirname, "..");
const LIB = path.join(ROOT, "server", "lib", "prompts-cache-config.sh");

function sh(snippet: string, env: Record<string, string> = {}) {
  const r = spawnSync("sh", ["-c", `. "${LIB}" && ${snippet}`], {
    env: { PATH: process.env["PATH"] ?? "/usr/bin:/bin", ...env },
    encoding: "utf8",
  });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

describe("prompts-cache-config.sh (AGT-2277)", () => {
  it("shares its defaults with promptsCachePaths.ts", () => {
    assert.equal(sh(`printf %s "$DEFAULT_PROMPTS_CACHE_ROOT"`).stdout, DEFAULT_PROMPTS_CACHE_ROOT);
    assert.equal(sh(`printf %s "$DEFAULT_PROMPTS_DEPLOY_KEY_PATH"`).stdout, DEFAULT_PROMPTS_DEPLOY_KEY_PATH);
  });

  it("accepts unset/empty and dot-dirs directly under /srv/git", () => {
    for (const v of ["", "/srv/git/.prompts-cache", "/srv/git/.prompts-alt", "/srv/git/.p_2.x"]) {
      const r = sh("check_prompts_cache_root", { STAMP_PROMPTS_CACHE_ROOT: v });
      assert.equal(r.status, 0, `${v}: ${r.stderr}`);
    }
  });

  it("leaves no temporaries behind, including on the unset/empty early return", () => {
    for (const v of ["", "/srv/git/.prompts-alt", "/srv/git/prompts.git"]) {
      const r = sh(
        `check_prompts_cache_root 2>/dev/null; printf '%s' "\${_pcr+x}\${_pcr_name+x}\${_pcr_ok+x}"`,
        { STAMP_PROMPTS_CACHE_ROOT: v },
      );
      assert.equal(r.stdout, "", `${JSON.stringify(v)}: temporaries left set`);
    }
  });

  it("refuses anything the SSH gate could serve, the server's own dot-dirs and odd paths", () => {
    for (const v of [
      "/srv/git/prompts.git", // gate serves /srv/git/<name>.git
      "/srv/git/prompts",
      "/var/cache/prompts",
      "relative/.prompts",
      "/srv/git/.prompts/nested",
      "/srv/git/.prompts/",
      "/srv/git/..",
      "/srv/git/.x/../.stamp-state",
      "/srv/git/.",
      "/srv/git/.stamp-state",
      "/srv/git/.ssh-client-keys",
      "/srv/git/.ssh-host-keys",
      "/srv/git/.trash",
      "/srv/git/.trash.old",
      "/srv/git/.prompts-cache.old",
      "/srv/git/.prompts-cache.tmp",
      "/srv/git/.p rompts",
      "/srv/git/.p\nrompts",
      "/srv/git//.prompts",
    ]) {
      const r = sh("check_prompts_cache_root", { STAMP_PROMPTS_CACHE_ROOT: v });
      assert.equal(r.status, 1, `${JSON.stringify(v)} should be refused`);
      assert.match(r.stderr, /^error: STAMP_PROMPTS_CACHE_ROOT=/);
    }
  });

  it("resolve_prompts_deploy_key: explicit wins; else the default only when a key is there", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "stamp-pkey-"));
    try {
      const def = path.join(dir, "prompts_repo_key");
      const over = `DEFAULT_PROMPTS_DEPLOY_KEY_PATH="${def}"; resolve_prompts_deploy_key`;
      assert.equal(sh(over, { STAMP_PROMPTS_DEPLOY_KEY_PATH: "/x/key" }).stdout, "/x/key");
      assert.equal(sh(over, { STAMP_PROMPTS_DEPLOY_KEY_PATH: "" }).stdout, "");
      writeFileSync(def, "k\n");
      assert.equal(sh(over, { STAMP_PROMPTS_DEPLOY_KEY_PATH: "" }).stdout, def);
      assert.equal(sh(over).stdout, def);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("promptsCachePaths.ts (AGT-2277)", () => {
  it("resolvePromptsCacheRoot honours STAMP_PROMPTS_CACHE_ROOT; empty means default", () => {
    assert.equal(resolvePromptsCacheRoot({}), DEFAULT_PROMPTS_CACHE_ROOT);
    assert.equal(resolvePromptsCacheRoot({ STAMP_PROMPTS_CACHE_ROOT: "" }), DEFAULT_PROMPTS_CACHE_ROOT);
    assert.equal(resolvePromptsCacheRoot({ STAMP_PROMPTS_CACHE_ROOT: "/srv/git/.alt" }), "/srv/git/.alt");
  });

  it("resolvePromptsDeployKeyPath: explicit wins; default only if present", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "stamp-pkey-ts-"));
    try {
      const def = path.join(dir, "prompts_repo_key");
      assert.equal(resolvePromptsDeployKeyPath({ STAMP_PROMPTS_DEPLOY_KEY_PATH: "/x/key" }, def), "/x/key");
      assert.equal(resolvePromptsDeployKeyPath({}, def), undefined);
      assert.equal(resolvePromptsDeployKeyPath({ STAMP_PROMPTS_DEPLOY_KEY_PATH: "" }, def), undefined);
      writeFileSync(def, "k\n");
      assert.equal(resolvePromptsDeployKeyPath({}, def), def);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
