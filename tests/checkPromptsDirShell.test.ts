/**
 * AGT-411: Shell-level tests for server/lib/check-prompts-dir.sh.
 *
 * Exercises the sourceable `check_prompts_dir` function via node:child_process
 * so the entrypoint refusal logic (AC #1 and AC #4) can be asserted without
 * booting the whole container.  Each test case sources the file and calls
 * check_prompts_dir with a specific env; we assert exit code and stderr.
 *
 * Nine-case matrix (mirrors serverReviewPipeline.test.ts AGT-411 block):
 *
 *   Prod context (STAMP_ENV absent or 'production'):
 *     1. default dir, no override           → exit 0
 *     2. non-default dir, no toggle          → exit 1, stderr match
 *     3. non-default dir + toggle set        → exit 1 (toggle unrecognised in prod)
 *     4. Phase B URL set + stale DIR         → exit 0 (Phase B carve-out)
 *
 *   Non-prod context (STAMP_ENV=dev or STAMP_ENV=test):
 *     5. default dir, no toggle              → exit 0
 *     6. non-default dir, no toggle          → exit 1 (toggle required)
 *     7. non-default dir + toggle set        → exit 0 (allowed)
 *     8. Phase B URL + non-default DIR       → exit 0 (Phase B carve-out)
 *     9. STAMP_ENV=production explicit       → exit 1 for non-default dir
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { describe, it } from "node:test";

const CHECK_SCRIPT = path.resolve(
  import.meta.dirname,
  "..",
  "server",
  "lib",
  "check-prompts-dir.sh",
);

const DEFAULT_DIR = "/etc/stamp/reviewers";
const CUSTOM_DIR = "/tmp/ci-prompts";

/**
 * Source check-prompts-dir.sh and invoke check_prompts_dir in a subshell.
 * Returns { status, stderr }.
 */
function runCheck(env: Record<string, string | undefined>): {
  status: number | null;
  stderr: string;
} {
  // Build a shell snippet that sources the lib and calls the function.
  const snippet = `. "${CHECK_SCRIPT}" && check_prompts_dir`;
  const result = spawnSync("sh", ["-c", snippet], {
    env: {
      PATH: process.env["PATH"],
      ...env,
    },
    encoding: "utf8",
  });
  return {
    status: result.status,
    stderr: result.stderr ?? "",
  };
}

describe("AGT-411: check-prompts-dir.sh boot-time guard", () => {
  it("case 1: prod (STAMP_ENV absent) + default dir → exit 0", () => {
    const r = runCheck({
      STAMP_PROMPTS_DIR: DEFAULT_DIR,
      // No STAMP_ENV, no STAMP_PROMPTS_REPO_URL, no toggle.
    });
    assert.equal(r.status, 0, `Expected exit 0, got ${r.status}. stderr: ${r.stderr}`);
  });

  it("case 2: prod (STAMP_ENV absent) + non-default dir + no toggle → exit 1 with error", () => {
    const r = runCheck({
      STAMP_PROMPTS_DIR: CUSTOM_DIR,
    });
    assert.equal(r.status, 1, `Expected exit 1, got ${r.status}. stderr: ${r.stderr}`);
    assert.match(r.stderr, /error:.*non-default path/i);
  });

  it("case 3: prod (STAMP_ENV absent) + non-default dir + toggle set → exit 1 (production refuses override even with toggle)", () => {
    // The shell guard treats absent STAMP_ENV as production and refuses non-default
    // dir regardless of the toggle (the toggle is for non-prod only).
    const r = runCheck({
      STAMP_PROMPTS_DIR: CUSTOM_DIR,
      STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY: "1",
    });
    assert.equal(r.status, 1, `Expected exit 1, got ${r.status}. stderr: ${r.stderr}`);
  });

  it("case 4: Phase B URL set + stale non-default STAMP_PROMPTS_DIR → exit 0 (Phase B carve-out)", () => {
    const r = runCheck({
      STAMP_PROMPTS_REPO_URL: "git@github.com:acme/stamp-prompts.git",
      STAMP_PROMPTS_DIR: CUSTOM_DIR,
      // No toggle, prod context — still allowed because Phase B carve-out fires first.
    });
    assert.equal(r.status, 0, `Expected exit 0, got ${r.status}. stderr: ${r.stderr}`);
  });

  it("case 5: non-prod (STAMP_ENV=test) + default dir → exit 0", () => {
    const r = runCheck({
      STAMP_ENV: "test",
      STAMP_PROMPTS_DIR: DEFAULT_DIR,
    });
    assert.equal(r.status, 0, `Expected exit 0, got ${r.status}. stderr: ${r.stderr}`);
  });

  it("case 6: non-prod (STAMP_ENV=dev) + non-default dir + no toggle → exit 1 (toggle required)", () => {
    const r = runCheck({
      STAMP_ENV: "dev",
      STAMP_PROMPTS_DIR: CUSTOM_DIR,
    });
    assert.equal(r.status, 1, `Expected exit 1, got ${r.status}. stderr: ${r.stderr}`);
    assert.match(r.stderr, /error:/i);
  });

  it("case 7: non-prod (STAMP_ENV=test) + non-default dir + toggle set → exit 0 (allowed)", () => {
    const r = runCheck({
      STAMP_ENV: "test",
      STAMP_PROMPTS_DIR: CUSTOM_DIR,
      STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY: "1",
    });
    assert.equal(r.status, 0, `Expected exit 0, got ${r.status}. stderr: ${r.stderr}`);
  });

  it("case 8: Phase B URL + non-default STAMP_PROMPTS_DIR in non-prod → exit 0 (Phase B carve-out)", () => {
    const r = runCheck({
      STAMP_ENV: "dev",
      STAMP_PROMPTS_REPO_URL: "git@github.com:acme/stamp-prompts.git",
      STAMP_PROMPTS_DIR: CUSTOM_DIR,
    });
    assert.equal(r.status, 0, `Expected exit 0, got ${r.status}. stderr: ${r.stderr}`);
  });

  it("case 9: STAMP_ENV=production explicit + non-default dir + no toggle → exit 1", () => {
    const r = runCheck({
      STAMP_ENV: "production",
      STAMP_PROMPTS_DIR: CUSTOM_DIR,
    });
    assert.equal(r.status, 1, `Expected exit 1, got ${r.status}. stderr: ${r.stderr}`);
    assert.match(r.stderr, /error:.*non-default path/i);
  });
});
