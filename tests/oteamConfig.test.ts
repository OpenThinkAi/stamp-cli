/**
 * Unit tests for src/lib/oteamConfig.ts.
 *
 * Both readOteamConfig and patchStampHost accept an optional configPath
 * parameter so tests can direct them at a temp file without touching the
 * real ~/.open-team/config.json.
 */

import { strict as assert } from "node:assert";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { readOteamConfig, patchStampHost } from "../src/lib/oteamConfig.ts";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeTempConfig(): { configPath: string; cleanup: () => void } {
  const dir = mkdtempSync(path.join(os.tmpdir(), "oteam-test-"));
  const configPath = path.join(dir, "config.json");
  return {
    configPath,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function writeConfig(configPath: string, content: unknown): void {
  mkdirSync(path.dirname(configPath), { recursive: true });
  writeFileSync(configPath, JSON.stringify(content, null, 2) + "\n", "utf8");
}

function readConfigRaw(configPath: string): Record<string, unknown> {
  return JSON.parse(readFileSync(configPath, "utf8")) as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// readOteamConfig
// ---------------------------------------------------------------------------

describe("readOteamConfig", () => {
  it("returns null when the config file does not exist", () => {
    const { configPath, cleanup } = makeTempConfig();
    try {
      // Config file not written — just the temp dir.
      const result = readOteamConfig(configPath);
      assert.equal(result, null);
    } finally {
      cleanup();
    }
  });

  it("returns the parsed object when the file exists and is valid JSON", () => {
    const { configPath, cleanup } = makeTempConfig();
    try {
      writeConfig(configPath, { stamp: { host: "example.com" }, repos: {} });
      const result = readOteamConfig(configPath);
      assert.ok(result !== null);
      const cfg = result as Record<string, unknown>;
      assert.deepEqual(cfg.stamp, { host: "example.com" });
    } finally {
      cleanup();
    }
  });

  it("throws with the file path in the message when JSON is malformed", () => {
    const { configPath, cleanup } = makeTempConfig();
    try {
      mkdirSync(path.dirname(configPath), { recursive: true });
      writeFileSync(configPath, "{ not valid json", "utf8");
      assert.throws(
        () => readOteamConfig(configPath),
        (err: Error) => {
          assert.match(err.message, /config\.json/);
          return true;
        },
      );
    } finally {
      cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// patchStampHost
// ---------------------------------------------------------------------------

describe("patchStampHost", () => {
  it("sets stamp.host when oteam config exists without a stamp section", () => {
    const { configPath, cleanup } = makeTempConfig();
    try {
      writeConfig(configPath, { repos: { "open-team": "git@github.com:org/repo.git" } });
      patchStampHost("stamp.example.com", configPath);
      const cfg = readConfigRaw(configPath);
      const stamp = cfg.stamp as Record<string, unknown>;
      assert.equal(stamp.host, "stamp.example.com");
      // Preserved the repos key.
      assert.ok("repos" in cfg);
    } finally {
      cleanup();
    }
  });

  it("sets stamp.host when oteam config exists with a stamp section but no host", () => {
    const { configPath, cleanup } = makeTempConfig();
    try {
      writeConfig(configPath, { stamp: { enforce: true }, repos: {} });
      patchStampHost("stamp.example.com", configPath);
      const cfg = readConfigRaw(configPath);
      const stamp = cfg.stamp as Record<string, unknown>;
      assert.equal(stamp.host, "stamp.example.com");
      // Other stamp keys preserved.
      assert.equal(stamp.enforce, true);
    } finally {
      cleanup();
    }
  });

  it("overwrites an existing stamp.host", () => {
    const { configPath, cleanup } = makeTempConfig();
    try {
      writeConfig(configPath, { stamp: { host: "old.example.com" } });
      patchStampHost("new.example.com", configPath);
      const cfg = readConfigRaw(configPath);
      assert.equal((cfg.stamp as Record<string, unknown>).host, "new.example.com");
    } finally {
      cleanup();
    }
  });

  it("creates the config file (with stamp.host) when none exists", () => {
    const { configPath, cleanup } = makeTempConfig();
    try {
      // configPath does not exist yet — patchStampHost should create it.
      patchStampHost("stamp.example.com", configPath);
      const cfg = readConfigRaw(configPath);
      assert.equal((cfg.stamp as Record<string, unknown>).host, "stamp.example.com");
    } finally {
      cleanup();
    }
  });

  it("preserves all non-stamp keys verbatim after the patch", () => {
    const { configPath, cleanup } = makeTempConfig();
    try {
      writeConfig(configPath, {
        workspace: "/home/user/vault",
        repos: { "my-repo": "git@github.com:org/my-repo.git" },
        push: { enabled: true },
        stamp: { enforce: false },
      });
      patchStampHost("stamp.example.com", configPath);
      const cfg = readConfigRaw(configPath);
      assert.equal(cfg.workspace, "/home/user/vault");
      assert.deepEqual(cfg.push, { enabled: true });
      assert.deepEqual(cfg.repos, { "my-repo": "git@github.com:org/my-repo.git" });
      assert.equal((cfg.stamp as Record<string, unknown>).host, "stamp.example.com");
      assert.equal((cfg.stamp as Record<string, unknown>).enforce, false);
    } finally {
      cleanup();
    }
  });
});
