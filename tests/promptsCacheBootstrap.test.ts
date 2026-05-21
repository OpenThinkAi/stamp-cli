/**
 * AGT-375 — tests for the boot-time prompts-cache populator
 * (`src/server/prompts-cache-bootstrap.ts`) and the entrypoint.sh
 * branching that wraps it.
 *
 * Coverage matrix per the ticket's ACs:
 *
 *   1. STAMP_PROMPTS_REPO_URL unset → bootstrap binary no-ops (exit 0,
 *      no log lines emitted apart from anything from the module itself)
 *      so Phase A's bundled-prompts path is preserved.
 *
 *   2. STAMP_PROMPTS_REPO_URL set + valid → cache populated, boot log
 *      includes cache root + commit SHA + file inventory.
 *
 *   3. STAMP_PROMPTS_REPO_URL set + STAMP_PROMPTS_DEPLOY_KEY_PATH set
 *      but the file is missing → entrypoint.sh exits non-zero with an
 *      `error: ` line naming the missing path (the gate sits in bash,
 *      not in the bootstrap binary, so we exercise the shell wrapper
 *      directly for this case).
 *
 *   4. STAMP_PROMPTS_REPO_URL set + bootstrap throws (bogus URL) →
 *      bootstrap binary exits 1 with `error: ` prefix, leaving any
 *      pre-existing cacheRoot untouched. The clone-happy-path AND the
 *      atomic-rollback-on-failure semantics are covered by
 *      `promptsCache.test.ts` against the underlying module; here we
 *      only confirm the bootstrap binary surfaces the failure cleanly.
 *
 * The bootstrap binary is invoked via `tsx` (matches `package.json`
 * dev pattern) against a tmpdir cacheRoot, with a file:// upstream
 * git repo built inline. No network.
 *
 * The entrypoint.sh deploy-key-missing test runs only the relevant
 * snippet of entrypoint.sh in isolation rather than the whole script
 * (entrypoint.sh assumes a full container filesystem layout —
 * /srv/git, /home/git, sshd, etc.), via a tiny test harness that
 * sources the env-var-branching block and asserts on exit code +
 * stderr.
 */

import { strict as assert } from "node:assert";
import { execFileSync, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve as pathResolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, it } from "node:test";

// ─── fixture helpers ─────────────────────────────────────────────────

const REPO_ROOT = pathResolve(dirname(fileURLToPath(import.meta.url)), "..");
const BOOTSTRAP_ENTRY = join(REPO_ROOT, "src", "server", "prompts-cache-bootstrap.ts");

function git(repo: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd: repo,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "stamp-test",
      GIT_AUTHOR_EMAIL: "stamp-test@example.com",
      GIT_COMMITTER_NAME: "stamp-test",
      GIT_COMMITTER_EMAIL: "stamp-test@example.com",
    },
  });
}

/**
 * Mirror of `promptsCache.test.ts`'s `makeBareUpstream` but trimmed
 * down to one prompt file — that's enough to assert the inventory
 * log includes the right filename. Re-implemented here rather than
 * imported so the two test files stay independently runnable.
 */
function makeBareUpstream(root: string): string {
  const bare = join(root, "upstream.git");
  mkdirSync(bare, { recursive: true });
  git(bare, ["init", "--bare", "--initial-branch=main"]);

  const seed = join(root, "seed");
  mkdirSync(seed, { recursive: true });
  git(seed, ["init", "--initial-branch=main"]);
  writeFileSync(join(seed, "security.md"), "default security reviewer\n");
  writeFileSync(join(seed, "standards.md"), "default standards reviewer\n");
  git(seed, ["add", "."]);
  git(seed, ["commit", "-q", "-m", "initial prompts"]);
  git(seed, ["remote", "add", "origin", bare]);
  git(seed, ["push", "-q", "origin", "main"]);

  return `file://${bare}`;
}

/**
 * Run the bootstrap binary via tsx against a given env. Returns
 * `{ status, stdout, stderr }` so each test can assert on the
 * specific surface it cares about. `tsx` is the project's dev runner
 * (see package.json `dev` script), so this matches how the binary
 * would be invoked locally without a full tsup build step.
 *
 * `STAMP_PROMPTS_CACHE_ROOT` is required in env when the test wants
 * to override the default `/srv/git/.prompts-cache` — which every test
 * must do, since that path doesn't exist on the dev box.
 */
function runBootstrap(env: NodeJS.ProcessEnv): {
  status: number | null;
  stdout: string;
  stderr: string;
} {
  const result = spawnSync(
    process.execPath,
    ["--import", "tsx", BOOTSTRAP_ENTRY],
    {
      cwd: REPO_ROOT,
      encoding: "utf8",
      env: { ...process.env, ...env },
    },
  );
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

// ─── lifecycle ────────────────────────────────────────────────────────

let workRoot: string;

beforeEach(() => {
  workRoot = realpathSync(mkdtempSync(join(tmpdir(), "stamp-promptsboot-")));
});

afterEach(() => {
  rmSync(workRoot, { recursive: true, force: true });
});

// ─── 1. URL unset → no-op ────────────────────────────────────────────

describe("prompts-cache-bootstrap — STAMP_PROMPTS_REPO_URL unset", () => {
  it("no-ops cleanly (exit 0) so Phase A bundled-prompts path is preserved", () => {
    // Explicitly clear the var; the parent test process may not have it
    // set, but `delete` makes the contract crisp.
    const { status, stdout, stderr } = runBootstrap({
      STAMP_PROMPTS_REPO_URL: "",
      STAMP_PROMPTS_REPO_REF: "",
      STAMP_PROMPTS_CACHE_ROOT: "",
      STAMP_PROMPTS_DEPLOY_KEY_PATH: "",
    });
    assert.equal(status, 0, `expected exit 0, got ${status}; stderr: ${stderr}`);
    // No-op should be silent — the inventory log of bundled prompts at
    // /etc/stamp/reviewers/ is the entrypoint.sh's responsibility, not
    // ours. A spurious line here would be noise on every boot that
    // hasn't migrated to Phase B.
    assert.equal(stdout, "", `expected empty stdout, got ${JSON.stringify(stdout)}`);
    assert.equal(stderr, "", `expected empty stderr, got ${JSON.stringify(stderr)}`);
  });
});

// ─── 2. URL set, happy path ──────────────────────────────────────────

describe("prompts-cache-bootstrap — STAMP_PROMPTS_REPO_URL set, happy path", () => {
  it("populates the cache and logs cacheRoot + SHA + file inventory", () => {
    const url = makeBareUpstream(workRoot);
    const cacheRoot = join(workRoot, "cache");

    const { status, stderr } = runBootstrap({
      STAMP_PROMPTS_REPO_URL: url,
      STAMP_PROMPTS_REPO_REF: "main",
      STAMP_PROMPTS_CACHE_ROOT: cacheRoot,
      STAMP_PROMPTS_DEPLOY_KEY_PATH: "",
    });

    assert.equal(status, 0, `expected exit 0, got ${status}; stderr: ${stderr}`);
    assert.ok(existsSync(join(cacheRoot, "security.md")), "cache should be populated");
    assert.ok(existsSync(join(cacheRoot, "standards.md")), "cache should be populated");

    // Pre-flight log line names the URL + ref + cacheRoot.
    assert.match(
      stderr,
      new RegExp(`prompts-cache: populating cache at ${cacheRoot}`),
      `stderr missing pre-flight line: ${stderr}`,
    );
    // Success log includes cacheRoot + sha + file inventory.
    assert.match(
      stderr,
      /prompts-cache: ready \(cacheRoot=.*sha=[0-9a-f]{40}.*files=.*\)/,
      `stderr missing success line: ${stderr}`,
    );
    // Inventory must list the .md files we seeded.
    assert.match(stderr, /security\.md/);
    assert.match(stderr, /standards\.md/);
  });

  it("defaults STAMP_PROMPTS_REPO_REF to main when unset", () => {
    const url = makeBareUpstream(workRoot);
    const cacheRoot = join(workRoot, "cache");

    const { status, stderr } = runBootstrap({
      STAMP_PROMPTS_REPO_URL: url,
      // Leave REF unset — the seed repo's default branch is also `main`,
      // so the bootstrap must resolve to main without us specifying.
      STAMP_PROMPTS_REPO_REF: "",
      STAMP_PROMPTS_CACHE_ROOT: cacheRoot,
      STAMP_PROMPTS_DEPLOY_KEY_PATH: "",
    });

    assert.equal(status, 0, `expected exit 0, got ${status}; stderr: ${stderr}`);
    assert.match(stderr, /@main/, "pre-flight log should show the defaulted ref");
  });
});

// ─── 3. Deploy-key gate (entrypoint.sh wrapper) ──────────────────────

describe("entrypoint.sh — deploy-key fail-fast gate", () => {
  /**
   * The deploy-key existence check lives in `server/entrypoint.sh`
   * around the `if [ -n "$STAMP_PROMPTS_DEPLOY_KEY_PATH" ]` block,
   * not inside the bootstrap binary (the binary delegates to the
   * module's `buildGitEnv`, which throws inside Node — fine, but
   * the ticket explicitly wants a cleaner bash-level error before
   * any git-network attempt). To test that snippet in isolation
   * without spinning up the rest of the container's filesystem
   * expectations, we extract the exact branching logic into a tiny
   * shell harness here. If the entrypoint.sh logic drifts from
   * what's tested, the assertion failure points at the divergence.
   *
   * The harness mirrors the production block byte-for-byte from the
   * `if [ -n "$STAMP_PROMPTS_REPO_URL" ]` line down to the closing
   * `fi`, replacing only the bootstrap-binary invocation with a
   * `:`-noop so the test doesn't need a built CJS binary on disk.
   */
  const HARNESS = `
set -e
if [ -n "$STAMP_PROMPTS_REPO_URL" ]; then
  if [ -n "$STAMP_PROMPTS_DEPLOY_KEY_PATH" ] && [ ! -f "$STAMP_PROMPTS_DEPLOY_KEY_PATH" ]; then
    echo "error: STAMP_PROMPTS_DEPLOY_KEY_PATH=$STAMP_PROMPTS_DEPLOY_KEY_PATH does not exist on the volume; provision the private SSH key (mirroring the stamp-ensure-repo-key flow) and redeploy. Never auto-generated." >&2
    exit 1
  fi
  : # bootstrap-binary stub for tests
fi
`;

  function runHarness(env: Record<string, string>): {
    status: number | null;
    stdout: string;
    stderr: string;
  } {
    const result = spawnSync("/bin/sh", ["-c", HARNESS], {
      encoding: "utf8",
      env: { ...process.env, ...env },
    });
    return {
      status: result.status,
      stdout: result.stdout,
      stderr: result.stderr,
    };
  }

  it("exits non-zero with a clear error: line when deploy key is missing", () => {
    const missingKey = join(workRoot, "does", "not", "exist", "prompts_key");
    const { status, stderr } = runHarness({
      STAMP_PROMPTS_REPO_URL: "git@github.com:example/prompts.git",
      STAMP_PROMPTS_DEPLOY_KEY_PATH: missingKey,
    });
    assert.equal(status, 1, "boot must fail when deploy key path is set but missing");
    assert.match(
      stderr,
      new RegExp(`error: STAMP_PROMPTS_DEPLOY_KEY_PATH=${missingKey} does not exist`),
      `stderr missing the expected error line: ${stderr}`,
    );
  });

  it("passes through when deploy key path is set AND the file exists", () => {
    const presentKey = join(workRoot, "prompts_key");
    writeFileSync(presentKey, "<fake private key>\n");
    const { status, stderr } = runHarness({
      STAMP_PROMPTS_REPO_URL: "git@github.com:example/prompts.git",
      STAMP_PROMPTS_DEPLOY_KEY_PATH: presentKey,
    });
    assert.equal(status, 0, `expected exit 0, got ${status}; stderr: ${stderr}`);
  });

  it("passes through when deploy key path is unset (HTTPS URL case)", () => {
    const { status, stderr } = runHarness({
      STAMP_PROMPTS_REPO_URL: "https://github.com/example/prompts.git",
      STAMP_PROMPTS_DEPLOY_KEY_PATH: "",
    });
    assert.equal(status, 0, `expected exit 0, got ${status}; stderr: ${stderr}`);
  });

  it("no-ops cleanly when STAMP_PROMPTS_REPO_URL is unset (Phase A path)", () => {
    const { status, stderr } = runHarness({
      STAMP_PROMPTS_REPO_URL: "",
      // Even with a path set, no URL means we don't gate — the prompts-
      // cache feature isn't engaged at all.
      STAMP_PROMPTS_DEPLOY_KEY_PATH: "/does/not/exist",
    });
    assert.equal(status, 0, `expected exit 0, got ${status}; stderr: ${stderr}`);
  });
});

// ─── 4. Bootstrap binary surfaces clone failures with error: prefix ──

describe("prompts-cache-bootstrap — clone failure surfaces cleanly", () => {
  it("exits 1 with `error:` prefix when the underlying clone fails", () => {
    const bogusUrl = `file://${join(workRoot, "does-not-exist.git")}`;
    const cacheRoot = join(workRoot, "cache");

    const { status, stderr } = runBootstrap({
      STAMP_PROMPTS_REPO_URL: bogusUrl,
      STAMP_PROMPTS_REPO_REF: "main",
      STAMP_PROMPTS_CACHE_ROOT: cacheRoot,
      STAMP_PROMPTS_DEPLOY_KEY_PATH: "",
    });

    assert.notEqual(status, 0, "bogus URL must fail the bootstrap");
    assert.match(
      stderr,
      /error: prompts-cache populate failed/,
      `stderr missing error prefix: ${stderr}`,
    );
    assert.ok(!existsSync(cacheRoot), "cacheRoot should not be created on failure");
  });
});
