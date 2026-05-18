/**
 * Tests for AGT-342: `stamp init --migrate-to-server-attested`. The
 * pure helpers (manifest serializer, config rewriter) are unit-tested
 * against fixtures; the orchestrator's idempotency and dry-run paths
 * are tested end-to-end against a tmp repo with synthetic pubkeys.
 */

import { strict as assert } from "node:assert";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { generateKeypair } from "../src/lib/keys.ts";
import {
  DEFAULT_PATH_RULES_BLOCK,
  detectExistingKeys,
  disambiguateNames,
  nameFromFilename,
  rewriteConfigForMigration,
  serializeManifest,
} from "../src/lib/migrateServerAttested.ts";
import { runMigrateToServerAttested } from "../src/commands/migrateServerAttested.ts";
import { parseManifest } from "../src/lib/trustedKeysManifest.ts";

interface TmpRepo {
  path: string;
  cleanup: () => void;
}

/**
 * Build a tmp directory that looks enough like a repo root for the
 * migration command: contains `.git/` (so `findRepoRoot` resolves
 * here) and `.stamp/{config.yml,trusted-keys/}` populated by the
 * caller. We don't run `git init` — the command never touches git
 * state, only the file tree.
 */
function tmpRepo(): TmpRepo {
  const dir = mkdtempSync(join(tmpdir(), "stamp-migrate-"));
  mkdirSync(join(dir, ".git"));
  mkdirSync(join(dir, ".stamp", "trusted-keys"), { recursive: true });
  return {
    path: dir,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function withCwd<T>(dir: string, fn: () => T): T {
  const prev = process.cwd();
  process.chdir(dir);
  try {
    return fn();
  } finally {
    process.chdir(prev);
  }
}

/** Drop a synthetic pubkey at `.stamp/trusted-keys/<filename>` and
 *  return its computed fingerprint so the test can assert against it. */
function dropKey(repoPath: string, filename: string): string {
  const kp = generateKeypair();
  writeFileSync(
    join(repoPath, ".stamp", "trusted-keys", filename),
    kp.publicKeyPem,
  );
  return kp.fingerprint;
}

describe("nameFromFilename", () => {
  it("strips the .pub suffix", () => {
    assert.equal(nameFromFilename("alice.pub"), "alice");
  });
  it("preserves digits/dots/underscores/dashes", () => {
    assert.equal(
      nameFromFilename("sha256_abc.def-1.pub"),
      "sha256_abc.def-1",
    );
  });
  it("sanitizes characters outside the manifest name pattern", () => {
    assert.equal(
      nameFromFilename("ed25519@host:1.example.com.pub"),
      "ed25519_host_1.example.com",
    );
  });
  it("falls back to `key` when sanitization empties the stem", () => {
    // Empty stem (e.g. a `.pub` file with no name at all) is the only
    // way to hit the empty-output fallback — punctuation characters
    // get substituted with `_`, which is itself in the allow set.
    assert.equal(nameFromFilename(".pub"), "key");
  });
});

describe("disambiguateNames", () => {
  it("appends _2, _3 ... to repeated names while preserving order", () => {
    const out = disambiguateNames([
      { name: "alice", filename: "alice.pub", fingerprint: "sha256:a" },
      { name: "alice", filename: "alice2.pub", fingerprint: "sha256:b" },
      { name: "alice", filename: "alice3.pub", fingerprint: "sha256:c" },
      { name: "bob", filename: "bob.pub", fingerprint: "sha256:d" },
    ]);
    assert.deepEqual(
      out.map((k) => k.name),
      ["alice", "alice_2", "alice_3", "bob"],
    );
  });
});

describe("detectExistingKeys", () => {
  it("errors when the trusted-keys directory is empty", () => {
    const r = tmpRepo();
    try {
      assert.throws(
        () => detectExistingKeys(r.path),
        /no existing keys to migrate/,
      );
    } finally {
      r.cleanup();
    }
  });

  it("errors when the trusted-keys directory does not exist", () => {
    const dir = mkdtempSync(join(tmpdir(), "stamp-migrate-empty-"));
    try {
      assert.throws(
        () => detectExistingKeys(dir),
        /no existing keys to migrate/,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("returns one entry per readable .pub file, sorted by filename", () => {
    const r = tmpRepo();
    try {
      const fpBob = dropKey(r.path, "bob.pub");
      const fpAlice = dropKey(r.path, "alice.pub");
      const keys = detectExistingKeys(r.path);
      assert.equal(keys.length, 2);
      assert.equal(keys[0]!.name, "alice");
      assert.equal(keys[0]!.fingerprint, fpAlice);
      assert.equal(keys[1]!.name, "bob");
      assert.equal(keys[1]!.fingerprint, fpBob);
    } finally {
      r.cleanup();
    }
  });

  it("skips malformed PEMs via onSkip rather than throwing", () => {
    const r = tmpRepo();
    try {
      dropKey(r.path, "alice.pub");
      writeFileSync(
        join(r.path, ".stamp", "trusted-keys", "junk.pub"),
        "not a pem\n",
      );
      const skipped: Array<{ filename: string; reason: string }> = [];
      const keys = detectExistingKeys(r.path, (filename, reason) =>
        skipped.push({ filename, reason }),
      );
      assert.equal(keys.length, 1);
      assert.equal(keys[0]!.name, "alice");
      assert.equal(skipped.length, 1);
      assert.equal(skipped[0]!.filename, "junk.pub");
    } finally {
      r.cleanup();
    }
  });
});

describe("serializeManifest", () => {
  it("emits valid YAML the canonical parser accepts", () => {
    const fpAlice = "sha256:" + "a".repeat(64);
    const fpBob = "sha256:" + "b".repeat(64);
    const out = serializeManifest(
      [
        { name: "alice", filename: "alice.pub", fingerprint: fpAlice },
        { name: "bob", filename: "bob.pub", fingerprint: fpBob },
      ],
      new Set([fpAlice]),
    );
    const parsed = parseManifest(out);
    assert.ok(parsed, "serialized manifest must round-trip through parseManifest");
    assert.equal(parsed!.entries.length, 2);
    const byName = Object.fromEntries(
      parsed!.entries.map((e) => [e.name, e]),
    );
    assert.deepEqual(byName["alice"]!.capabilities, ["admin", "operator"]);
    assert.deepEqual(byName["bob"]!.capabilities, ["operator"]);
  });

  it("is deterministic across runs with the same input", () => {
    const fpAlice = "sha256:" + "a".repeat(64);
    const fpBob = "sha256:" + "b".repeat(64);
    const inputs = [
      { name: "bob", filename: "bob.pub", fingerprint: fpBob },
      { name: "alice", filename: "alice.pub", fingerprint: fpAlice },
    ];
    const out1 = serializeManifest(inputs, new Set([fpAlice]));
    const out2 = serializeManifest(inputs, new Set([fpAlice]));
    assert.equal(out1, out2);
    // And reverse input order produces the same output (entries
    // sorted by name).
    const reversed = [...inputs].reverse();
    const out3 = serializeManifest(reversed, new Set([fpAlice]));
    assert.equal(out3, out1);
  });

  it("defaults every key to [operator] when no admins are selected", () => {
    const fp = "sha256:" + "f".repeat(64);
    const out = serializeManifest(
      [{ name: "solo", filename: "solo.pub", fingerprint: fp }],
      new Set(),
    );
    assert.match(out, /capabilities: \[operator\]/);
    // No capability list mentions admin (header comment text does, by
    // design — that's documentation, not a capability assignment).
    assert.doesNotMatch(out, /capabilities:.*admin/);
  });
});

describe("rewriteConfigForMigration", () => {
  const baseCfg = `branches:
  main:
    required: [security, standards, product]
reviewers:
  security:
    prompt: .stamp/reviewers/security.md
  standards:
    prompt: .stamp/reviewers/standards.md
`;

  it("appends the default path_rules block when missing", () => {
    const result = rewriteConfigForMigration(baseCfg);
    assert.equal(result.changed, true);
    assert.equal(result.pathRulesAppended, true);
    assert.deepEqual(result.commentedBlocks, []);
    assert.ok(
      result.text.includes(DEFAULT_PATH_RULES_BLOCK),
      "default path_rules block must appear in output",
    );
    assert.ok(
      result.text.includes("bypass_review_cycle: true"),
      "appended block must include bypass_review_cycle: true",
    );
  });

  it("comments out reviewer-nested mcp_servers blocks", () => {
    const input = `${baseCfg.trimEnd()}
    mcp_servers:
      linear:
        command: npx
        args: ["@linear/mcp"]
`;
    const result = rewriteConfigForMigration(input);
    assert.deepEqual(result.commentedBlocks, ["mcp_servers"]);
    assert.ok(result.text.includes("    # mcp_servers:"));
    // Body lines keep their original indent + gain a `# ` prefix at
    // the indent point.
    assert.ok(result.text.includes("      # linear:"));
    // Nothing of the original block survives uncommented.
    const uncommented = result.text
      .split("\n")
      .filter((l) => !/^\s*#/.test(l))
      .join("\n");
    assert.doesNotMatch(uncommented, /mcp_servers:/);
  });

  it("comments out top-level + reviewer-nested tools blocks", () => {
    const input = `${baseCfg.trimEnd()}
    tools:
      - Read
      - Grep
      - name: WebFetch
        allowed_hosts: [linear.app]
`;
    const result = rewriteConfigForMigration(input);
    assert.deepEqual(result.commentedBlocks, ["tools"]);
    assert.ok(result.text.includes("    # tools:"));
    // Body line `      - Read` keeps its indent + gains `# ` at column 6.
    assert.ok(result.text.includes("      # - Read"));
  });

  it("comments BOTH mcp_servers and tools when both are present", () => {
    const input = `${baseCfg.trimEnd()}
    tools:
      - Read
    mcp_servers:
      linear:
        command: npx
`;
    const result = rewriteConfigForMigration(input);
    assert.deepEqual(result.commentedBlocks.sort(), ["mcp_servers", "tools"]);
  });

  it("is idempotent: a second pass over the rewritten text is a no-op for path_rules", () => {
    const once = rewriteConfigForMigration(baseCfg);
    const twice = rewriteConfigForMigration(once.text);
    assert.equal(twice.pathRulesAppended, false);
    assert.deepEqual(twice.commentedBlocks, []);
    assert.equal(twice.changed, false);
    assert.equal(twice.text, once.text);
    assert.deepEqual(twice.warnings, []);
  });

  it("warns when an existing path_rules block has a different .stamp/** rule", () => {
    const input = `${baseCfg.trimEnd()}
path_rules:
  ".stamp/**":
    require_capability: operator
    minimum_signatures: 1
`;
    const result = rewriteConfigForMigration(input);
    assert.equal(result.pathRulesAppended, false);
    assert.ok(
      result.warnings.some((w) => w.includes("path_rules:")),
      `expected a warning mentioning path_rules; got ${JSON.stringify(result.warnings)}`,
    );
    // The existing block stays untouched.
    assert.ok(result.text.includes("require_capability: operator"));
  });

  it("does NOT re-warn when an existing path_rules block already matches the default", () => {
    const input = `${baseCfg.trimEnd()}

${DEFAULT_PATH_RULES_BLOCK}
`;
    const result = rewriteConfigForMigration(input);
    assert.equal(result.pathRulesAppended, false);
    assert.deepEqual(result.warnings, []);
    assert.equal(result.changed, false);
  });

  it("does not re-comment lines already prefixed with `#`", () => {
    const input = `${baseCfg.trimEnd()}
    # tools:
    #   - Read
`;
    const result = rewriteConfigForMigration(input);
    assert.deepEqual(result.commentedBlocks, []);
    assert.doesNotMatch(result.text, /# #/);
  });
});

describe("runMigrateToServerAttested — end-to-end", () => {
  it("writes manifest + rewrites config + appends path_rules", () => {
    const r = tmpRepo();
    try {
      const fpAlice = dropKey(r.path, "alice.pub");
      const fpBob = dropKey(r.path, "bob.pub");
      writeFileSync(
        join(r.path, ".stamp", "config.yml"),
        `branches:
  main:
    required: [security]
reviewers:
  security:
    prompt: .stamp/reviewers/security.md
    tools:
      - Read
    mcp_servers:
      linear:
        command: npx
`,
      );
      withCwd(r.path, () =>
        runMigrateToServerAttested({ selectAdminIndexes: [1] }),
      );
      // Manifest landed with alice promoted.
      const manifestText = readFileSync(
        join(r.path, ".stamp", "trusted-keys", "manifest.yml"),
        "utf8",
      );
      const parsed = parseManifest(manifestText);
      assert.ok(parsed, "manifest must parse");
      const byFp = Object.fromEntries(
        parsed!.entries.map((e) => [e.fingerprint, e.capabilities]),
      );
      assert.deepEqual(byFp[fpAlice], ["admin", "operator"]);
      assert.deepEqual(byFp[fpBob], ["operator"]);

      // Config rewrite: tools + mcp_servers commented, path_rules appended.
      const cfgText = readFileSync(
        join(r.path, ".stamp", "config.yml"),
        "utf8",
      );
      assert.ok(cfgText.includes("    # tools:"));
      assert.ok(cfgText.includes("    # mcp_servers:"));
      assert.ok(cfgText.includes(DEFAULT_PATH_RULES_BLOCK));
    } finally {
      r.cleanup();
    }
  });

  it("--dry-run writes nothing to disk", () => {
    const r = tmpRepo();
    try {
      dropKey(r.path, "alice.pub");
      const initialCfg = `branches:
  main:
    required: [security]
reviewers:
  security:
    prompt: .stamp/reviewers/security.md
    tools: [Read]
`;
      writeFileSync(join(r.path, ".stamp", "config.yml"), initialCfg);
      withCwd(r.path, () => runMigrateToServerAttested({ dryRun: true }));
      const manifestPath = join(
        r.path,
        ".stamp",
        "trusted-keys",
        "manifest.yml",
      );
      assert.equal(
        existsSync(manifestPath),
        false,
        "dry-run must not create manifest.yml",
      );
      const cfgAfter = readFileSync(
        join(r.path, ".stamp", "config.yml"),
        "utf8",
      );
      assert.equal(
        cfgAfter,
        initialCfg,
        "dry-run must not modify .stamp/config.yml",
      );
    } finally {
      r.cleanup();
    }
  });

  it("is idempotent: a second run preserves the operator's admin choices", () => {
    const r = tmpRepo();
    try {
      const fpAlice = dropKey(r.path, "alice.pub");
      dropKey(r.path, "bob.pub");
      writeFileSync(
        join(r.path, ".stamp", "config.yml"),
        `branches:
  main:
    required: [security]
reviewers:
  security:
    prompt: .stamp/reviewers/security.md
`,
      );
      // First run promotes alice.
      withCwd(r.path, () =>
        runMigrateToServerAttested({ selectAdminIndexes: [1] }),
      );
      const firstManifest = readFileSync(
        join(r.path, ".stamp", "trusted-keys", "manifest.yml"),
        "utf8",
      );
      const firstCfg = readFileSync(
        join(r.path, ".stamp", "config.yml"),
        "utf8",
      );

      // Second run with no selection: should preserve alice as admin,
      // not demote her.
      withCwd(r.path, () =>
        runMigrateToServerAttested({ selectAdminIndexes: [] }),
      );
      const secondManifest = readFileSync(
        join(r.path, ".stamp", "trusted-keys", "manifest.yml"),
        "utf8",
      );
      const secondCfg = readFileSync(
        join(r.path, ".stamp", "config.yml"),
        "utf8",
      );
      assert.equal(
        firstManifest,
        secondManifest,
        "re-running must not alter the manifest",
      );
      assert.equal(
        firstCfg,
        secondCfg,
        "re-running must not alter the config",
      );
      const parsed = parseManifest(secondManifest);
      assert.deepEqual(
        parsed!.entries.find((e) => e.fingerprint === fpAlice)!.capabilities,
        ["admin", "operator"],
      );
    } finally {
      r.cleanup();
    }
  });

  it("throws when .stamp/config.yml is missing", () => {
    const r = tmpRepo();
    try {
      dropKey(r.path, "alice.pub");
      assert.throws(
        () =>
          withCwd(r.path, () =>
            runMigrateToServerAttested({ selectAdminIndexes: [] }),
          ),
        /expected \.stamp\/config\.yml/,
      );
    } finally {
      r.cleanup();
    }
  });

  it("--dry-run on an empty .stamp/trusted-keys/ surfaces the no-keys error", () => {
    const r = tmpRepo();
    try {
      writeFileSync(
        join(r.path, ".stamp", "config.yml"),
        "branches: {}\nreviewers: {}\n",
      );
      assert.throws(
        () =>
          withCwd(r.path, () =>
            runMigrateToServerAttested({ dryRun: true }),
          ),
        /no existing keys to migrate/,
      );
    } finally {
      r.cleanup();
    }
  });

});
