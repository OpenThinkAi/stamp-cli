/**
 * End-to-end test for the boot-time review-signing-key bootstrap script
 * (`src/server/bootstrap-review-key.ts`).
 *
 * The script runs as root from entrypoint.sh once per container boot,
 * after stamp-seed-users and before sshd. It's gated on
 * ANTHROPIC_API_KEY (review capability opt-in), resolves the key path
 * via REVIEW_SIGNING_KEY_PATH / STAMP_STATE_DIR / default, and exits
 * non-zero on a wrong-mode key — entrypoint.sh treats that as fatal.
 *
 * Critical properties exercised below:
 *
 *   - No ANTHROPIC_API_KEY → script skips keygen, exits 0, leaves
 *     nothing on disk
 *   - With ANTHROPIC_API_KEY set + no prior key → generates, exits 0,
 *     prints the loud fingerprint banner to stderr including the
 *     manifest-instruction line, writes the .pem mode 0600
 *   - Second invocation against the same path reuses, exits 0, prints
 *     a one-line reuse log (not the banner)
 *   - REVIEW_SIGNING_KEY_PATH env overrides the default path
 *   - STAMP_STATE_DIR env shifts the default base directory
 *   - Wrong-mode key file → exit 1 with a clear chmod-hint message
 *   - Empty ANTHROPIC_API_KEY value is treated as unset (matches the
 *     standard "env var set to empty string == not configured"
 *     convention used by other capability gates)
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

const BOOTSTRAP_TS = path.resolve(
  import.meta.dirname,
  "..",
  "src",
  "server",
  "bootstrap-review-key.ts",
);

interface RunResult {
  stdout: string;
  stderr: string;
  status: number | null;
}

function runBootstrap(env: Record<string, string | undefined>): RunResult {
  // Clear the apiKey-controlling env vars from the parent process by
  // default so test cases don't inherit ANTHROPIC_API_KEY from the
  // developer's shell. Caller-supplied env wins via spread.
  const childEnv: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined) childEnv[k] = v;
  }
  delete childEnv["ANTHROPIC_API_KEY"];
  delete childEnv["REVIEW_SIGNING_KEY_PATH"];
  delete childEnv["STAMP_STATE_DIR"];

  for (const [k, v] of Object.entries(env)) {
    if (v === undefined) {
      delete childEnv[k];
    } else {
      childEnv[k] = v;
    }
  }

  const result = spawnSync(
    process.execPath,
    ["--import", "tsx", BOOTSTRAP_TS],
    {
      env: childEnv,
      encoding: "utf8",
    },
  );
  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    status: result.status,
  };
}

function tmpDir(): { dir: string; cleanup: () => void } {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-bootstrap-"));
  return {
    dir,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

describe("stamp-bootstrap-review-key", () => {
  it("skips keygen when ANTHROPIC_API_KEY is unset", () => {
    const t = tmpDir();
    try {
      const keyPath = path.join(t.dir, "review-signing-key.pem");
      const r = runBootstrap({
        REVIEW_SIGNING_KEY_PATH: keyPath,
        // ANTHROPIC_API_KEY intentionally absent
      });
      assert.equal(r.status, 0, `stderr=${r.stderr}`);
      assert.match(r.stdout, /ANTHROPIC_API_KEY unset/);
      assert.equal(existsSync(keyPath), false, "must not create a key");
    } finally {
      t.cleanup();
    }
  });

  it("treats an empty ANTHROPIC_API_KEY value as unset", () => {
    const t = tmpDir();
    try {
      const keyPath = path.join(t.dir, "review-signing-key.pem");
      const r = runBootstrap({
        REVIEW_SIGNING_KEY_PATH: keyPath,
        ANTHROPIC_API_KEY: "",
      });
      assert.equal(r.status, 0);
      assert.match(r.stdout, /ANTHROPIC_API_KEY unset/);
      assert.equal(existsSync(keyPath), false);
    } finally {
      t.cleanup();
    }
  });

  it("generates a fresh keypair on first boot and prints the loud banner", () => {
    const t = tmpDir();
    try {
      const keyPath = path.join(t.dir, "review-signing-key.pem");
      const pubPath = path.join(t.dir, "review-signing-key.pub");

      const r = runBootstrap({
        REVIEW_SIGNING_KEY_PATH: keyPath,
        ANTHROPIC_API_KEY: "sk-test-not-real",
      });

      assert.equal(r.status, 0, `non-zero exit; stderr=${r.stderr}`);

      // Banner lines: AC #2 names the visually-distinct block + the
      // manifest-commit instruction. We assert on those concrete phrases.
      assert.match(r.stderr, /review-signing key generated/);
      assert.match(r.stderr, /sha256:[0-9a-f]{64}/);
      assert.match(r.stderr, /capabilities: \[server\]/);
      assert.match(r.stderr, /\.stamp\/trusted-keys\/manifest\.yml/);

      // Disk state.
      assert.equal(existsSync(keyPath), true);
      assert.equal(existsSync(pubPath), true);
      assert.equal(statSync(keyPath).mode & 0o777, 0o600);
      assert.equal(statSync(pubPath).mode & 0o777, 0o644);

      // The .pub file's content is the SPKI PEM the SSH verb will
      // serve — a quick sanity check that it parses as a PEM block.
      const pubContent = readFileSync(pubPath, "utf8");
      assert.match(pubContent, /-----BEGIN PUBLIC KEY-----/);
      assert.match(pubContent, /-----END PUBLIC KEY-----/);
    } finally {
      t.cleanup();
    }
  });

  it("reuses the existing key on the second boot and prints a one-line log", () => {
    const t = tmpDir();
    try {
      const keyPath = path.join(t.dir, "review-signing-key.pem");

      const first = runBootstrap({
        REVIEW_SIGNING_KEY_PATH: keyPath,
        ANTHROPIC_API_KEY: "sk-test-not-real",
      });
      assert.equal(first.status, 0);
      const firstFingerprint = extractFingerprint(first.stderr);
      assert.ok(firstFingerprint, "could not extract fingerprint from banner");

      const second = runBootstrap({
        REVIEW_SIGNING_KEY_PATH: keyPath,
        ANTHROPIC_API_KEY: "sk-test-not-real",
      });
      assert.equal(second.status, 0);

      // Reuse path: no banner, single-line log on stdout that
      // includes the same fingerprint.
      assert.doesNotMatch(second.stderr, /review-signing key generated/);
      assert.match(second.stdout, /reusing existing review-signing key/);
      assert.match(second.stdout, new RegExp(firstFingerprint!));
    } finally {
      t.cleanup();
    }
  });

  it("honors STAMP_STATE_DIR as the default key location", () => {
    const t = tmpDir();
    try {
      // No REVIEW_SIGNING_KEY_PATH override — script must derive
      // <STAMP_STATE_DIR>/review-signing-key.pem.
      const expectedKey = path.join(t.dir, "review-signing-key.pem");
      const r = runBootstrap({
        STAMP_STATE_DIR: t.dir,
        ANTHROPIC_API_KEY: "sk-test-not-real",
      });
      assert.equal(r.status, 0, `stderr=${r.stderr}`);
      assert.equal(existsSync(expectedKey), true);
      assert.equal(statSync(expectedKey).mode & 0o777, 0o600);
    } finally {
      t.cleanup();
    }
  });

  it("aborts with exit 1 when the existing key has wrong permissions", () => {
    const t = tmpDir();
    try {
      const keyPath = path.join(t.dir, "review-signing-key.pem");

      // First boot creates the key cleanly.
      const first = runBootstrap({
        REVIEW_SIGNING_KEY_PATH: keyPath,
        ANTHROPIC_API_KEY: "sk-test-not-real",
      });
      assert.equal(first.status, 0);

      // Simulate a backup-restore that didn't preserve perms.
      chmodSync(keyPath, 0o644);

      const second = runBootstrap({
        REVIEW_SIGNING_KEY_PATH: keyPath,
        ANTHROPIC_API_KEY: "sk-test-not-real",
      });

      assert.equal(second.status, 1, `expected exit 1; stderr=${second.stderr}`);
      assert.match(second.stderr, /has mode/);
      assert.match(second.stderr, /chmod 600/);
      // Critical: NO regeneration on the wrong-mode path. The file
      // must still be there at mode 0644 with its original content
      // (the bootstrap refused rather than silently rotating the
      // identity).
      assert.equal(statSync(keyPath).mode & 0o777, 0o644);
    } finally {
      t.cleanup();
    }
  });

  it("REVIEW_SIGNING_KEY_PATH overrides STAMP_STATE_DIR", () => {
    const stateT = tmpDir();
    const overrideT = tmpDir();
    try {
      const overridePath = path.join(overrideT.dir, "custom.pem");
      const wouldBeDefault = path.join(stateT.dir, "review-signing-key.pem");

      const r = runBootstrap({
        STAMP_STATE_DIR: stateT.dir,
        REVIEW_SIGNING_KEY_PATH: overridePath,
        ANTHROPIC_API_KEY: "sk-test-not-real",
      });
      assert.equal(r.status, 0, `stderr=${r.stderr}`);
      assert.equal(existsSync(overridePath), true, "override path should be created");
      assert.equal(
        existsSync(wouldBeDefault),
        false,
        "default path under STAMP_STATE_DIR should NOT be created when override is set",
      );
    } finally {
      stateT.cleanup();
      overrideT.cleanup();
    }
  });
});

function extractFingerprint(stderr: string): string | null {
  const m = stderr.match(/sha256:[0-9a-f]{64}/);
  return m ? m[0] : null;
}
