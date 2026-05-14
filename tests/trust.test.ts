/**
 * End-to-end tests for `stamp trust grant`.
 *
 * Drives the real runTrustGrant logic in-process — git operations
 * against a real local repo, real PEM validation, real filesystem
 * writes — and only stubs the SSH-to-server call via PATH-injection
 * (a fake `ssh` binary that emits canned PEMs / exit codes).
 *
 * Each test builds a fresh temp dir containing:
 *   - HOME with ~/.stamp/server.yml so loadServerConfig() succeeds
 *   - bin/ with the fake ssh script (prepended to PATH)
 *   - repo/ with a git-initialized stamp-shaped repository
 *
 * Covers: success path, no-op (already trusted), missing user, dirty
 * working tree, existing branch collision, non-git target, non-stamp
 * target.
 */

import { strict as assert } from "node:assert";
import { execFileSync, spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { runTrustGrant } from "../src/commands/trust.ts";

// A real ed25519 PEM produced once via openssl; pinned so PEM-validation
// drift is loud (the test asserts the PEM lands verbatim in the
// trusted-keys file).
const VALID_STAMP_PEM = [
  "-----BEGIN PUBLIC KEY-----",
  "MCowBQYDK2VwAyEAN1u4GpICcmqg4xydF2IQmdQbwBfp+JXiV4EiD10EuzE=",
  "-----END PUBLIC KEY-----",
  "",
].join("\n");

interface Harness {
  root: string;
  repoRoot: string;
  fakeSshDir: string;
  homeDir: string;
  prevEnv: { HOME: string | undefined; PATH: string | undefined };
  cleanup: () => void;
}

function writeFakeSsh(
  dir: string,
  scenario:
    | { kind: "ok"; pem: string }
    | { kind: "not_found" }
    | { kind: "config_err" }
    | { kind: "unknown_err"; exitCode: number },
): void {
  let script: string;
  switch (scenario.kind) {
    case "ok": {
      // Write the PEM verbatim to a sidecar file so the shell stub can
      // `cat` it without juggling backslash-escapes. sh's `printf '%s'`
      // doesn't interpret \n inside double-quoted strings, so embedding
      // multi-line PEM via JSON.stringify produces literal \n that
      // breaks PEM decoding downstream.
      const pemPath = path.join(dir, "pubkey.pem");
      writeFileSync(pemPath, scenario.pem);
      script = `#!/bin/sh\ncat ${JSON.stringify(pemPath)}\nexit 0\n`;
      break;
    }
    case "not_found":
      script = `#!/bin/sh\necho "error: user not found" >&2\nexit 4\n`;
      break;
    case "config_err":
      script = `#!/bin/sh\necho "error: identity binding failed" >&2\nexit 1\n`;
      break;
    case "unknown_err":
      script = `#!/bin/sh\necho "error: surprise" >&2\nexit ${scenario.exitCode}\n`;
      break;
  }
  const p = path.join(dir, "ssh");
  writeFileSync(p, script, { mode: 0o755 });
  chmodSync(p, 0o755);
}

function buildHarness(): Harness {
  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-trust-"));
  const homeDir = path.join(root, "home");
  const fakeSshDir = path.join(root, "bin");
  const repoRoot = path.join(root, "repo");
  mkdirSync(homeDir, { recursive: true });
  mkdirSync(fakeSshDir, { recursive: true });
  mkdirSync(path.join(homeDir, ".stamp"), { recursive: true });

  // Minimal valid ~/.stamp/server.yml for loadServerConfig.
  writeFileSync(
    path.join(homeDir, ".stamp", "server.yml"),
    "host: stamp.example.com\nport: 12345\n",
    { mode: 0o600 },
  );

  // git init + initial commit + .stamp/ skeleton so the repo passes
  // the trust-grant pre-flight checks.
  mkdirSync(repoRoot, { recursive: true });
  execFileSync("git", ["init", "-q", "-b", "main", repoRoot]);
  // Set local identity so commits don't pick up a missing-config error.
  execFileSync("git", ["-C", repoRoot, "config", "user.name", "Stamp Test"]);
  execFileSync("git", [
    "-C",
    repoRoot,
    "config",
    "user.email",
    "test@example.invalid",
  ]);
  execFileSync("git", [
    "-C",
    repoRoot,
    "config",
    "commit.gpgsign",
    "false",
  ]);
  mkdirSync(path.join(repoRoot, ".stamp"), { recursive: true });
  writeFileSync(path.join(repoRoot, ".stamp", ".gitkeep"), "");
  writeFileSync(path.join(repoRoot, "README.md"), "test repo\n");
  execFileSync("git", ["-C", repoRoot, "add", "-A"]);
  execFileSync("git", ["-C", repoRoot, "commit", "-q", "-m", "initial"]);

  const prevEnv = {
    HOME: process.env["HOME"],
    PATH: process.env["PATH"],
  };
  process.env["HOME"] = homeDir;
  process.env["PATH"] = `${fakeSshDir}${path.delimiter}${prevEnv.PATH ?? ""}`;

  return {
    root,
    repoRoot,
    fakeSshDir,
    homeDir,
    prevEnv,
    cleanup: () => {
      process.env["HOME"] = prevEnv.HOME;
      process.env["PATH"] = prevEnv.PATH;
      rmSync(root, { recursive: true, force: true });
    },
  };
}

function readBranch(repoRoot: string): string {
  return execFileSync("git", ["-C", repoRoot, "rev-parse", "--abbrev-ref", "HEAD"], {
    encoding: "utf8",
  }).trim();
}

function commitLog(repoRoot: string, ref: string): string {
  return execFileSync("git", ["-C", repoRoot, "log", "--format=%B", "-n", "1", ref], {
    encoding: "utf8",
  });
}

describe("runTrustGrant — success path", () => {
  it("creates the branch, writes the pubkey file, commits", () => {
    const h = buildHarness();
    try {
      writeFakeSsh(h.fakeSshDir, { kind: "ok", pem: VALID_STAMP_PEM });

      runTrustGrant({ shortName: "alice", repoPath: h.repoRoot });

      // Branch was created and is the current HEAD.
      assert.equal(readBranch(h.repoRoot), "stamp-trust/alice");

      // File landed at the expected path with the PEM body.
      const keyPath = path.join(
        h.repoRoot,
        ".stamp",
        "trusted-keys",
        "alice.pub",
      );
      assert.ok(existsSync(keyPath), "trusted-keys file should exist");
      assert.equal(readFileSync(keyPath, "utf8"), VALID_STAMP_PEM);

      // Commit message names the user + carries the source hint.
      const msg = commitLog(h.repoRoot, "HEAD");
      assert.match(msg, /Trust grant: add alice/);
      assert.match(msg, /stamp trust grant alice/);
    } finally {
      h.cleanup();
    }
  });

  it("returns silently as a no-op when the key is already trusted under any name", () => {
    const h = buildHarness();
    try {
      // Pre-seed a trusted-keys/<other>.pub with the same PEM. The grant
      // should detect the fingerprint match and skip the branch.
      const trustedKeysDir = path.join(h.repoRoot, ".stamp", "trusted-keys");
      mkdirSync(trustedKeysDir, { recursive: true });
      writeFileSync(path.join(trustedKeysDir, "operator.pub"), VALID_STAMP_PEM);
      execFileSync("git", ["-C", h.repoRoot, "add", "-A"]);
      execFileSync("git", ["-C", h.repoRoot, "commit", "-q", "-m", "seed trust"]);

      writeFakeSsh(h.fakeSshDir, { kind: "ok", pem: VALID_STAMP_PEM });

      runTrustGrant({ shortName: "alice", repoPath: h.repoRoot });

      // Still on main; no stamp-trust/alice branch created.
      assert.equal(readBranch(h.repoRoot), "main");
      const branches = execFileSync("git", [
        "-C",
        h.repoRoot,
        "branch",
        "--list",
        "stamp-trust/alice",
      ], { encoding: "utf8" });
      assert.equal(branches.trim(), "");
    } finally {
      h.cleanup();
    }
  });
});

describe("runTrustGrant — error paths", () => {
  it("rejects when the user has no stamp_pubkey on file (server returns NOT_FOUND)", () => {
    const h = buildHarness();
    try {
      writeFakeSsh(h.fakeSshDir, { kind: "not_found" });
      assert.throws(
        () => runTrustGrant({ shortName: "alice", repoPath: h.repoRoot }),
        /not enrolled.*no stamp signing pubkey/s,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects on server-side config error", () => {
    const h = buildHarness();
    try {
      writeFakeSsh(h.fakeSshDir, { kind: "config_err" });
      assert.throws(
        () => runTrustGrant({ shortName: "alice", repoPath: h.repoRoot }),
        /identity binding failed|missing 'ExposeAuthInfo/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("surfaces an unknown exit code with a generic hint", () => {
    const h = buildHarness();
    try {
      writeFakeSsh(h.fakeSshDir, { kind: "unknown_err", exitCode: 99 });
      assert.throws(
        () => runTrustGrant({ shortName: "alice", repoPath: h.repoRoot }),
        /exit 99/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects when the working tree has uncommitted changes", () => {
    const h = buildHarness();
    try {
      writeFakeSsh(h.fakeSshDir, { kind: "ok", pem: VALID_STAMP_PEM });
      writeFileSync(path.join(h.repoRoot, "dirty.txt"), "uncommitted\n");
      assert.throws(
        () => runTrustGrant({ shortName: "alice", repoPath: h.repoRoot }),
        /uncommitted changes/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("forceDirty bypasses the dirty-tree check", () => {
    const h = buildHarness();
    try {
      writeFakeSsh(h.fakeSshDir, { kind: "ok", pem: VALID_STAMP_PEM });
      writeFileSync(path.join(h.repoRoot, "dirty.txt"), "uncommitted\n");
      // Doesn't throw — but the resulting branch carries the dirty file
      // as well as the trusted-keys add. That's the documented trade.
      runTrustGrant({
        shortName: "alice",
        repoPath: h.repoRoot,
        forceDirty: true,
      });
      assert.equal(readBranch(h.repoRoot), "stamp-trust/alice");
    } finally {
      h.cleanup();
    }
  });

  it("rejects when the stamp-trust/<name> branch already exists", () => {
    const h = buildHarness();
    try {
      writeFakeSsh(h.fakeSshDir, { kind: "ok", pem: VALID_STAMP_PEM });
      // Pre-create the branch.
      execFileSync("git", [
        "-C",
        h.repoRoot,
        "branch",
        "stamp-trust/alice",
      ]);
      assert.throws(
        () => runTrustGrant({ shortName: "alice", repoPath: h.repoRoot }),
        /branch stamp-trust\/alice already exists/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects when --repo points at a non-git directory", () => {
    const h = buildHarness();
    try {
      const notARepo = path.join(h.root, "plain-dir");
      mkdirSync(notARepo, { recursive: true });
      writeFakeSsh(h.fakeSshDir, { kind: "ok", pem: VALID_STAMP_PEM });
      assert.throws(
        () => runTrustGrant({ shortName: "alice", repoPath: notARepo }),
        /not a git repository/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects when the git repo has no .stamp/ directory", () => {
    const h = buildHarness();
    try {
      const plainGit = path.join(h.root, "plain-git");
      mkdirSync(plainGit, { recursive: true });
      execFileSync("git", ["init", "-q", "-b", "main", plainGit]);
      execFileSync("git", ["-C", plainGit, "config", "user.email", "x@y"]);
      execFileSync("git", ["-C", plainGit, "config", "user.name", "x"]);
      execFileSync("git", ["-C", plainGit, "commit", "--allow-empty", "-q", "-m", "init"]);

      writeFakeSsh(h.fakeSshDir, { kind: "ok", pem: VALID_STAMP_PEM });
      assert.throws(
        () => runTrustGrant({ shortName: "alice", repoPath: plainGit }),
        /no \.stamp\/ directory/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects malformed short_name before reaching the server", () => {
    const h = buildHarness();
    try {
      writeFakeSsh(h.fakeSshDir, { kind: "ok", pem: VALID_STAMP_PEM });
      assert.throws(
        () =>
          runTrustGrant({
            shortName: "has spaces!",
            repoPath: h.repoRoot,
          }),
        /invalid shape/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects when ~/.stamp/server.yml is missing", () => {
    const h = buildHarness();
    try {
      writeFakeSsh(h.fakeSshDir, { kind: "ok", pem: VALID_STAMP_PEM });
      // Wipe the seeded server.yml.
      rmSync(path.join(h.homeDir, ".stamp", "server.yml"));
      assert.throws(
        () => runTrustGrant({ shortName: "alice", repoPath: h.repoRoot }),
        /no ~\/\.stamp\/server\.yml/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects an invalid PEM returned by the server", () => {
    const h = buildHarness();
    try {
      writeFakeSsh(h.fakeSshDir, {
        kind: "ok",
        pem: "-----BEGIN PUBLIC KEY-----\nnot real base64\n-----END PUBLIC KEY-----\n",
      });
      assert.throws(
        () => runTrustGrant({ shortName: "alice", repoPath: h.repoRoot }),
        /invalid PEM/,
      );
    } finally {
      h.cleanup();
    }
  });
});
