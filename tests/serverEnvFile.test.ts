/**
 * Tests for the /etc/stamp/env loader that the SSH-verb path (stamp-review,
 * receive hooks) uses to recover env vars sshd strips on session startup.
 *
 * The entrypoint.sh `write_env_var` block is the WRITE side of this
 * contract; loadServerEnvFile is the READ side. Both sides have to agree
 * on which keys are persisted, or the verb code silently sees `undefined`
 * for vars that the operator believes are set — which is how Phase B
 * (AGT-373) shipped half-broken: the prompt cache populated correctly,
 * but the SSH-verb resolver read STAMP_PROMPTS_REPO_URL as unset and
 * fell through to the bundled-prompts fallback path.
 *
 * These tests pin both ends of that contract:
 *   - the loader correctly populates process.env from a file fixture
 *   - the Phase B env vars (STAMP_PROMPTS_REPO_URL, STAMP_PROMPTS_DIR)
 *     ARE part of the entrypoint's write list, so the file the loader
 *     reads in production actually contains them
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadServerEnvFile } from "../src/lib/serverEnvFile.js";

const REPO_ROOT = fileURLToPath(new URL("..", import.meta.url));
const ENTRYPOINT_PATH = join(REPO_ROOT, "server", "entrypoint.sh");

function withTempEnvFile(content: string, fn: (path: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "stamp-env-test-"));
  const path = join(dir, "env");
  writeFileSync(path, content);
  try {
    fn(path);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function withSavedEnv(keys: string[], fn: () => void): void {
  const saved: Record<string, string | undefined> = {};
  for (const k of keys) saved[k] = process.env[k];
  try {
    fn();
  } finally {
    for (const k of keys) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

describe("loadServerEnvFile — populates process.env from /etc/stamp/env", () => {
  it("no-ops when the file does not exist", () => {
    withSavedEnv(["STAMP_TEST_NONEXISTENT"], () => {
      delete process.env.STAMP_TEST_NONEXISTENT;
      loadServerEnvFile("/nonexistent/path/that/cannot/exist");
      assert.equal(process.env.STAMP_TEST_NONEXISTENT, undefined);
    });
  });

  it("populates unset keys from a file", () => {
    withTempEnvFile("STAMP_TEST_A=alpha\nSTAMP_TEST_B=bravo\n", (path) => {
      withSavedEnv(["STAMP_TEST_A", "STAMP_TEST_B"], () => {
        delete process.env.STAMP_TEST_A;
        delete process.env.STAMP_TEST_B;
        loadServerEnvFile(path);
        assert.equal(process.env.STAMP_TEST_A, "alpha");
        assert.equal(process.env.STAMP_TEST_B, "bravo");
      });
    });
  });

  it("does not override session-set keys (sshd SetEnv / AcceptEnv wins)", () => {
    withTempEnvFile("STAMP_TEST_OVERRIDE=from-file\n", (path) => {
      withSavedEnv(["STAMP_TEST_OVERRIDE"], () => {
        process.env.STAMP_TEST_OVERRIDE = "from-session";
        loadServerEnvFile(path);
        assert.equal(process.env.STAMP_TEST_OVERRIDE, "from-session");
      });
    });
  });

  it("ignores malformed lines without crashing", () => {
    const content =
      "STAMP_TEST_OK=fine\n" +
      "not an env line at all\n" +
      "lowercase=ignored\n" +
      "9STARTS_WITH_DIGIT=ignored\n" +
      "STAMP_TEST_OK2=also-fine\n";
    withTempEnvFile(content, (path) => {
      withSavedEnv(
        [
          "STAMP_TEST_OK",
          "STAMP_TEST_OK2",
          "lowercase",
          "9STARTS_WITH_DIGIT",
        ],
        () => {
          delete process.env.STAMP_TEST_OK;
          delete process.env.STAMP_TEST_OK2;
          delete process.env.lowercase;
          loadServerEnvFile(path);
          assert.equal(process.env.STAMP_TEST_OK, "fine");
          assert.equal(process.env.STAMP_TEST_OK2, "also-fine");
          assert.equal(process.env.lowercase, undefined);
          assert.equal(process.env["9STARTS_WITH_DIGIT"], undefined);
        },
      );
    });
  });

  it("trims trailing whitespace from values", () => {
    withTempEnvFile("STAMP_TEST_TRIM=spaced   \n", (path) => {
      withSavedEnv(["STAMP_TEST_TRIM"], () => {
        delete process.env.STAMP_TEST_TRIM;
        loadServerEnvFile(path);
        assert.equal(process.env.STAMP_TEST_TRIM, "spaced");
      });
    });
  });
});

describe("entrypoint.sh ↔ loadServerEnvFile contract for SSH-verb env vars", () => {
  // These tests assert that the WRITE side (entrypoint.sh) lists every
  // env var the READ side (stamp-review.cjs via loadServerEnvFile) needs
  // at request time. The list is small and stable, but the failure mode
  // when it falls out of sync is silent and confusing (the SSH-verb
  // resolver reads `undefined` and falls through to defaults that don't
  // match operator intent). Pinning the list here makes future
  // additions explicit.
  //
  // To keep this test simple and not parse shell, we grep the entrypoint
  // for the `write_env_var <name>` lines. If the entrypoint switches to
  // a different write mechanism, update this test to match.

  it("entrypoint.sh writes every env var the SSH verb's resolvePromptCacheRoot reads", () => {
    const content = readFileSync(ENTRYPOINT_PATH, "utf8");
    const written = new Set<string>();
    for (const line of content.split("\n")) {
      const m = line.match(/^\s*write_env_var\s+([A-Z_][A-Z0-9_]*)/);
      if (m) written.add(m[1]!);
    }

    // resolvePromptCacheRoot in src/server/reviewPipeline.ts reads these
    // two vars at request time. If the entrypoint doesn't persist them,
    // the SSH-verb path sees them as undefined and the Phase B toggle
    // silently fails closed.
    const sshVerbReads = ["STAMP_PROMPTS_REPO_URL", "STAMP_PROMPTS_DIR"];
    for (const v of sshVerbReads) {
      assert.ok(
        written.has(v),
        `entrypoint.sh must call \`write_env_var ${v}\` so the SSH-verb path sees it after loadServerEnvFile() restores /etc/stamp/env. ` +
          `Add it next to the existing GITHUB_BOT_TOKEN / ANTHROPIC_API_KEY lines. ` +
          `Currently written: ${[...written].sort().join(", ")}`,
      );
    }
  });

  it("entrypoint.sh writes the env vars the receive hook reads", () => {
    // Sibling assertion for the Phase A vars the post-receive hook
    // reads via loadServerEnvFile(). Pinned here so any refactor that
    // accidentally drops them surfaces immediately.
    const content = readFileSync(ENTRYPOINT_PATH, "utf8");
    const written = new Set<string>();
    for (const line of content.split("\n")) {
      const m = line.match(/^\s*write_env_var\s+([A-Z_][A-Z0-9_]*)/);
      if (m) written.add(m[1]!);
    }
    for (const v of ["GITHUB_BOT_TOKEN", "ANTHROPIC_API_KEY"]) {
      assert.ok(
        written.has(v),
        `entrypoint.sh must persist ${v} to /etc/stamp/env (load-bearing for the SSH-invoked hook path).`,
      );
    }
  });
});
