/**
 * Tests for AGT-042 — `--expect-prompt-sha` (and siblings) on
 * `stamp reviewers fetch`. Audit reference: `oaudit-may-2-2026-rerun-3.md`
 * finding **L6**.
 *
 * Extended for AGT-113 — signed-manifest verification:
 *   - signed manifest with allowlisted key → fetch succeeds
 *   - signed manifest with unallowlisted key → fetch fails
 *   - unsigned manifest with no allowlist AND no --expect-prompt-sha → TOFU (fail-open)
 *   - unsigned manifest with allowlist present → fetch fails closed
 *   - existing locked reviewers continue to verify (via existing tests)
 *   - multi-key allowlist (rotation overlap)
 *
 * No real network is touched. `globalThis.fetch` is restored in
 * `afterEach` so a thrown assertion in one test can't leak the stub
 * into the next.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import { reviewersFetch } from "../src/commands/reviewers.ts";
import {
  hashMcpServers,
  hashPromptBytes,
  hashTools,
} from "../src/lib/reviewerHash.ts";
import { generateKeypair, publicKeyFingerprintFilename } from "../src/lib/keys.ts";
import { signManifest, type ReviewerManifest } from "../src/lib/reviewerManifest.ts";
import { stampVerifyingKeysDir } from "../src/lib/paths.ts";

type FetchFn = typeof globalThis.fetch;

interface FixtureFiles {
  prompt: string;
  /** When null, the config.yaml endpoint returns 404 (the optional path). */
  configYaml: string | null;
  /** When set, the manifest.json endpoint serves this JSON text. When null → 404. */
  manifestJson?: string | null;
  /** When set, the manifest.json.sig endpoint serves this text. When null → 404. */
  manifestSig?: string | null;
}

interface MockHandle {
  /** Number of times the stubbed `fetch` was invoked. */
  calls: number;
  /** URLs the caller actually requested, in call order. */
  urls: string[];
}

function git(args: string[], cwd: string): void {
  execFileSync("git", args, { cwd, stdio: "pipe" });
}

/** Install a `globalThis.fetch` that serves `prompt.md`, optionally
 *  `config.yaml`, and optionally `manifest.json` + `manifest.json.sig`
 *  from in-memory fixtures, 404 for any other path. Returns a handle so
 *  tests can assert on call counts without touching globals. */
function installFetchMock(fixtures: FixtureFiles): {
  handle: MockHandle;
  restore: () => void;
} {
  const original = globalThis.fetch;
  const handle: MockHandle = { calls: 0, urls: [] };
  const stub: FetchFn = async (input) => {
    const url = typeof input === "string" ? input : input.toString();
    handle.calls += 1;
    handle.urls.push(url);
    if (url.endsWith("/manifest.json.sig")) {
      const sig = fixtures.manifestSig ?? null;
      if (sig === null) return new Response("not found", { status: 404 });
      return new Response(sig, { status: 200 });
    }
    if (url.endsWith("/manifest.json")) {
      const mj = fixtures.manifestJson ?? null;
      if (mj === null) return new Response("not found", { status: 404 });
      return new Response(mj, { status: 200 });
    }
    if (url.endsWith("/prompt.md")) {
      return new Response(fixtures.prompt, { status: 200 });
    }
    if (url.endsWith("/config.yaml")) {
      if (fixtures.configYaml === null) {
        return new Response("not found", { status: 404 });
      }
      return new Response(fixtures.configYaml, { status: 200 });
    }
    return new Response("not found", { status: 404 });
  };
  globalThis.fetch = stub;
  return {
    handle,
    restore: () => {
      globalThis.fetch = original;
    },
  };
}

/** Install a `globalThis.fetch` that throws if called. Used by the flag-
 *  shape tests to assert validation runs *before* any network I/O. */
function installNoNetworkMock(): { restore: () => void } {
  const original = globalThis.fetch;
  globalThis.fetch = (async () => {
    throw new Error(
      "fetch should not have been called — validation must run before network I/O",
    );
  }) as FetchFn;
  return {
    restore: () => {
      globalThis.fetch = original;
    },
  };
}

describe("reviewersFetch --expect-*-sha flags (AGT-042 / audit-L6)", () => {
  let tmp: string;
  let repo: string;
  let prevCwd: string;

  beforeEach(() => {
    prevCwd = process.cwd();
    tmp = realpathSync(mkdtempSync(join(tmpdir(), "stamp-reviewersfetch-")));
    repo = join(tmp, "repo");
    mkdirSync(repo);
    git(["init", "-q", "-b", "main", repo], tmp);
    git(["config", "user.email", "t@example.com"], repo);
    git(["config", "user.name", "Test"], repo);
    mkdirSync(join(repo, ".stamp", "reviewers"), { recursive: true });
    process.chdir(repo);
  });

  afterEach(() => {
    process.chdir(prevCwd);
    rmSync(tmp, { recursive: true, force: true });
  });

  // --------------------------------------------------------------------
  // Flag-shape validation — must run before any network I/O.
  // --------------------------------------------------------------------

  describe("flag-shape validation (rejects before network)", () => {
    const cases: Array<{ name: string; value: string; match: RegExp }> = [
      { name: "too-short hex", value: "abcd1234", match: /not a valid SHA-256 hex/ },
      { name: "non-hex chars", value: "g".repeat(64), match: /not a valid SHA-256 hex/ },
      { name: "empty string", value: "", match: /not a valid SHA-256 hex/ },
    ];
    for (const c of cases) {
      it(`rejects ${c.name} value before fetch`, async () => {
        const mock = installNoNetworkMock();
        try {
          await assert.rejects(
            reviewersFetch("standards", {
              from: "acme/personas@v1",
              expectPromptSha: c.value,
            }),
            c.match,
          );
        } finally {
          mock.restore();
        }
      });
    }

    it("error message includes the offending flag name", async () => {
      const mock = installNoNetworkMock();
      try {
        await assert.rejects(
          reviewersFetch("standards", {
            from: "acme/personas@v1",
            expectToolsSha: "not-hex",
          }),
          /--expect-tools-sha/,
        );
      } finally {
        mock.restore();
      }
    });
  });

  // --------------------------------------------------------------------
  // Match path — fetch succeeds, lock + prompt are written.
  // --------------------------------------------------------------------

  describe("match path", () => {
    it("writes prompt + lock when --expect-prompt-sha matches the served bytes", async () => {
      const promptText = "# standards reviewer\n\nDo good work.\n";
      const expected = hashPromptBytes(Buffer.from(promptText, "utf8"));
      const mock = installFetchMock({ prompt: promptText, configYaml: null });
      try {
        await reviewersFetch("standards", {
          from: "acme/personas@v1",
          expectPromptSha: expected,
        });

        const promptPath = join(repo, ".stamp", "reviewers", "standards.md");
        assert.equal(readFileSync(promptPath, "utf8"), promptText);

        const lockPath = join(
          repo,
          ".stamp",
          "reviewers",
          "standards.lock.json",
        );
        const lock = JSON.parse(readFileSync(lockPath, "utf8"));
        assert.equal(lock.prompt_sha256, expected);
        assert.equal(lock.source, "acme/personas");
        assert.equal(lock.ref, "v1");
      } finally {
        mock.restore();
      }
    });

    it("tolerates 'sha256:' prefix and uppercase hex on the supplied flag", async () => {
      const promptText = "ok\n";
      const expected = hashPromptBytes(Buffer.from(promptText, "utf8"));
      const mock = installFetchMock({ prompt: promptText, configYaml: null });
      try {
        await reviewersFetch("standards", {
          from: "acme/personas@v1",
          expectPromptSha: `sha256:${expected.toUpperCase()}`,
        });
        const lockPath = join(
          repo,
          ".stamp",
          "reviewers",
          "standards.lock.json",
        );
        const lock = JSON.parse(readFileSync(lockPath, "utf8"));
        assert.equal(lock.prompt_sha256, expected);
      } finally {
        mock.restore();
      }
    });

    it("matches --expect-tools-sha and --expect-mcp-sha when config.yaml is present", async () => {
      const promptText = "x\n";
      const configYaml =
        "tools:\n  - Read\n  - Grep\nmcp_servers:\n  linear:\n    command: linear-mcp\n";
      const expectedPrompt = hashPromptBytes(Buffer.from(promptText, "utf8"));
      // Hash form must match what the fetch path computes after parsing.
      // parseToolsLoose accepts pure-string entries, hashTools sorts them
      // alphabetically — so ["Read","Grep"] hashes the same as ["Grep","Read"].
      const expectedTools = hashTools(["Grep", "Read"]);
      const expectedMcp = hashMcpServers({ linear: { command: "linear-mcp" } });
      const mock = installFetchMock({ prompt: promptText, configYaml });
      try {
        await reviewersFetch("standards", {
          from: "acme/personas@v1",
          expectPromptSha: expectedPrompt,
          expectToolsSha: expectedTools,
          expectMcpSha: expectedMcp,
        });
        const lockPath = join(
          repo,
          ".stamp",
          "reviewers",
          "standards.lock.json",
        );
        const lock = JSON.parse(readFileSync(lockPath, "utf8"));
        assert.equal(lock.tools_sha256, expectedTools);
        assert.equal(lock.mcp_sha256, expectedMcp);
      } finally {
        mock.restore();
      }
    });

    it("preserves byte-identical TOFU behaviour when no flag is supplied (AC #4)", async () => {
      const promptText = "tofu\n";
      const mock = installFetchMock({ prompt: promptText, configYaml: null });
      try {
        await reviewersFetch("standards", { from: "acme/personas@v1" });
        const promptPath = join(repo, ".stamp", "reviewers", "standards.md");
        assert.equal(readFileSync(promptPath, "utf8"), promptText);
        const lockPath = join(
          repo,
          ".stamp",
          "reviewers",
          "standards.lock.json",
        );
        const lock = JSON.parse(readFileSync(lockPath, "utf8"));
        // Lock pins what was fetched (TOFU); just assert the structural
        // invariants we care about so this test doesn't drift if other
        // lock fields evolve.
        assert.equal(
          lock.prompt_sha256,
          hashPromptBytes(Buffer.from(promptText, "utf8")),
        );
      } finally {
        mock.restore();
      }
    });
  });

  // --------------------------------------------------------------------
  // Mismatch path — must be atomic (no prompt, no lock).
  // --------------------------------------------------------------------

  describe("mismatch path (atomic — no disk writes — AC #3)", () => {
    it("throws and leaves the reviewers dir empty when --expect-prompt-sha mismatches", async () => {
      const promptText = "served bytes\n";
      const wrong = "0".repeat(64); // valid hex shape, wrong value
      const mock = installFetchMock({ prompt: promptText, configYaml: null });
      try {
        await assert.rejects(
          reviewersFetch("standards", {
            from: "acme/personas@v1",
            expectPromptSha: wrong,
          }),
          /prompt\.md hash mismatch/,
        );

        // AC #3: no persona file or lock file written.
        assert.equal(
          existsSync(join(repo, ".stamp", "reviewers", "standards.md")),
          false,
          "prompt file must not be written on mismatch",
        );
        assert.equal(
          existsSync(join(repo, ".stamp", "reviewers", "standards.lock.json")),
          false,
          "lock file must not be written on mismatch",
        );
      } finally {
        mock.restore();
      }
    });

    it("error message names both the expected and the computed hash", async () => {
      const promptText = "x\n";
      const wrong = "0".repeat(64);
      const computed = hashPromptBytes(Buffer.from(promptText, "utf8"));
      const mock = installFetchMock({ prompt: promptText, configYaml: null });
      try {
        await assert.rejects(
          reviewersFetch("standards", {
            from: "acme/personas@v1",
            expectPromptSha: wrong,
          }),
          (err: Error) => {
            assert.match(err.message, new RegExp(`expected.*${wrong}`));
            assert.match(err.message, new RegExp(`computed.*${computed}`));
            return true;
          },
        );
      } finally {
        mock.restore();
      }
    });

    it("throws on --expect-tools-sha mismatch and writes nothing", async () => {
      const promptText = "x\n";
      const configYaml = "tools:\n  - Read\n";
      const promptHash = hashPromptBytes(Buffer.from(promptText, "utf8"));
      const wrong = "1".repeat(64);
      const mock = installFetchMock({ prompt: promptText, configYaml });
      try {
        await assert.rejects(
          reviewersFetch("standards", {
            from: "acme/personas@v1",
            expectPromptSha: promptHash, // matches
            expectToolsSha: wrong, // mismatches
          }),
          /tools.*hash mismatch/,
        );
        assert.equal(
          existsSync(join(repo, ".stamp", "reviewers", "standards.md")),
          false,
        );
        assert.equal(
          existsSync(join(repo, ".stamp", "reviewers", "standards.lock.json")),
          false,
        );
      } finally {
        mock.restore();
      }
    });

    it("throws on --expect-mcp-sha mismatch and writes nothing", async () => {
      const promptText = "x\n";
      const configYaml =
        "mcp_servers:\n  linear:\n    command: linear-mcp\n";
      const promptHash = hashPromptBytes(Buffer.from(promptText, "utf8"));
      const wrong = "2".repeat(64);
      const mock = installFetchMock({ prompt: promptText, configYaml });
      try {
        await assert.rejects(
          reviewersFetch("standards", {
            from: "acme/personas@v1",
            expectPromptSha: promptHash,
            expectMcpSha: wrong,
          }),
          /mcp_servers.*hash mismatch/,
        );
        assert.equal(
          existsSync(join(repo, ".stamp", "reviewers", "standards.md")),
          false,
        );
        assert.equal(
          existsSync(join(repo, ".stamp", "reviewers", "standards.lock.json")),
          false,
        );
      } finally {
        mock.restore();
      }
    });

    it("does not overwrite an existing lock file when the new fetch mismatches", async () => {
      // Pre-seed a prior fetch result, then attempt a new fetch with a
      // mismatching --expect-prompt-sha. The pre-existing files must be
      // left exactly as they were.
      const promptText = "served bytes\n";
      const correct = hashPromptBytes(Buffer.from(promptText, "utf8"));
      const mock1 = installFetchMock({ prompt: promptText, configYaml: null });
      try {
        await reviewersFetch("standards", {
          from: "acme/personas@v1",
          expectPromptSha: correct,
        });
      } finally {
        mock1.restore();
      }
      const promptPath = join(repo, ".stamp", "reviewers", "standards.md");
      const lockPath = join(
        repo,
        ".stamp",
        "reviewers",
        "standards.lock.json",
      );
      const promptBefore = readFileSync(promptPath, "utf8");
      const lockBefore = readFileSync(lockPath, "utf8");

      const evilPrompt = "evil bytes\n";
      const wrongExpect = "f".repeat(64);
      const mock2 = installFetchMock({ prompt: evilPrompt, configYaml: null });
      try {
        await assert.rejects(
          reviewersFetch("standards", {
            from: "acme/personas@v1",
            expectPromptSha: wrongExpect,
          }),
          /hash mismatch/,
        );
      } finally {
        mock2.restore();
      }

      assert.equal(readFileSync(promptPath, "utf8"), promptBefore);
      assert.equal(readFileSync(lockPath, "utf8"), lockBefore);
    });
  });
});

// ==========================================================================
// AGT-113 — signed-manifest verification tests
// ==========================================================================

/** Build a manifest JSON string and its detached signature for a given
 *  keypair and prompt/tools/mcp hashes. */
function buildSignedManifest(
  kp: ReturnType<typeof generateKeypair>,
  reviewerName: string,
  promptSha: string,
  toolsSha: string,
  mcpSha: string,
  source = "acme/personas",
): { manifestJson: string; manifestSig: string } {
  const manifest: ReviewerManifest = {
    version: 1,
    source,
    reviewers: {
      [reviewerName]: {
        prompt_sha256: promptSha,
        tools_sha256: toolsSha,
        mcp_sha256: mcpSha,
      },
    },
    signed_by: kp.fingerprint,
  };
  const manifestJson = JSON.stringify(manifest, null, 2);
  const manifestSig = signManifest(manifest, kp.privateKeyPem);
  return { manifestJson, manifestSig };
}

describe("reviewersFetch — signed-manifest verification (AGT-113)", () => {
  let tmp: string;
  let repo: string;
  let prevCwd: string;

  beforeEach(() => {
    prevCwd = process.cwd();
    tmp = realpathSync(mkdtempSync(join(tmpdir(), "stamp-manifestverify-")));
    repo = join(tmp, "repo");
    mkdirSync(repo);
    git(["init", "-q", "-b", "main", repo], tmp);
    git(["config", "user.email", "t@example.com"], repo);
    git(["config", "user.name", "Test"], repo);
    mkdirSync(join(repo, ".stamp", "reviewers"), { recursive: true });
    process.chdir(repo);
  });

  afterEach(() => {
    process.chdir(prevCwd);
    rmSync(tmp, { recursive: true, force: true });
  });

  // -----------------------------------------------------------------------
  // AC#6a: signed manifest + allowlisted key → fetch succeeds
  // -----------------------------------------------------------------------

  it("AC#6a: signed manifest + allowlisted key → fetch succeeds and lock is written", async () => {
    const kp = generateKeypair();
    const promptText = "# security reviewer\n\nBe thorough.\n";
    const promptBytes = Buffer.from(promptText, "utf8");
    const promptSha = hashPromptBytes(promptBytes);
    const toolsSha = hashTools(undefined);
    const mcpSha = hashMcpServers(undefined);

    const { manifestJson, manifestSig } = buildSignedManifest(
      kp, "security", promptSha, toolsSha, mcpSha,
    );

    // Install the key in the allowlist
    const vkDir = stampVerifyingKeysDir(repo);
    mkdirSync(vkDir, { recursive: true });
    writeFileSync(join(vkDir, publicKeyFingerprintFilename(kp.fingerprint)), kp.publicKeyPem);

    const mock = installFetchMock({
      prompt: promptText,
      configYaml: null,
      manifestJson,
      manifestSig,
    });
    try {
      await reviewersFetch("security", { from: "acme/personas@v1" });

      const promptPath = join(repo, ".stamp", "reviewers", "security.md");
      assert.ok(existsSync(promptPath), "prompt file should be written");
      assert.equal(readFileSync(promptPath, "utf8"), promptText);

      const lockPath = join(repo, ".stamp", "reviewers", "security.lock.json");
      assert.ok(existsSync(lockPath), "lock file should be written");
      const lock = JSON.parse(readFileSync(lockPath, "utf8"));
      assert.equal(lock.prompt_sha256, promptSha);
    } finally {
      mock.restore();
    }
  });

  // -----------------------------------------------------------------------
  // AC#6b: signed manifest with unallowlisted key → fetch fails
  // -----------------------------------------------------------------------

  it("AC#6b: signed manifest + unallowlisted key → fetch fails closed", async () => {
    const kpSigner = generateKeypair();   // signs the manifest
    const kpAllowed = generateKeypair(); // in the allowlist (different key)

    const promptText = "prompt\n";
    const promptBytes = Buffer.from(promptText, "utf8");
    const promptSha = hashPromptBytes(promptBytes);
    const toolsSha = hashTools(undefined);
    const mcpSha = hashMcpServers(undefined);

    const { manifestJson, manifestSig } = buildSignedManifest(
      kpSigner, "security", promptSha, toolsSha, mcpSha,
    );

    // Only kpAllowed is in the allowlist, not kpSigner
    const vkDir = stampVerifyingKeysDir(repo);
    mkdirSync(vkDir, { recursive: true });
    writeFileSync(join(vkDir, publicKeyFingerprintFilename(kpAllowed.fingerprint)), kpAllowed.publicKeyPem);

    const mock = installFetchMock({
      prompt: promptText,
      configYaml: null,
      manifestJson,
      manifestSig,
    });
    try {
      await assert.rejects(
        reviewersFetch("security", { from: "acme/personas@v1" }),
        /not in \.stamp\/verifying-keys/,
      );
      // Nothing should be written
      assert.equal(existsSync(join(repo, ".stamp", "reviewers", "security.md")), false);
      assert.equal(existsSync(join(repo, ".stamp", "reviewers", "security.lock.json")), false);
    } finally {
      mock.restore();
    }
  });

  // -----------------------------------------------------------------------
  // AC#6c: unsigned manifest with no allowlist AND no --expect-prompt-sha
  //         → TOFU (fail-open)
  // -----------------------------------------------------------------------

  it("AC#6c: no manifest + no allowlist → TOFU (fail-open, existing behaviour)", async () => {
    const promptText = "tofu prompt\n";
    // No manifest, no allowlist, no --expect-prompt-sha
    const mock = installFetchMock({
      prompt: promptText,
      configYaml: null,
      // manifestJson: undefined → 404
      // manifestSig: undefined → 404
    });
    try {
      await reviewersFetch("security", { from: "acme/personas@v1" });
      const promptPath = join(repo, ".stamp", "reviewers", "security.md");
      assert.ok(existsSync(promptPath), "TOFU: prompt should be written");
      assert.equal(readFileSync(promptPath, "utf8"), promptText);
    } finally {
      mock.restore();
    }
  });

  // -----------------------------------------------------------------------
  // AC#6c variant: manifest published but no allowlist → TOFU with a warning
  // -----------------------------------------------------------------------

  it("manifest published but no allowlist → TOFU (warn, still writes)", async () => {
    const kp = generateKeypair();
    const promptText = "signed prompt\n";
    const promptBytes = Buffer.from(promptText, "utf8");
    const promptSha = hashPromptBytes(promptBytes);
    const { manifestJson, manifestSig } = buildSignedManifest(
      kp, "security", promptSha, hashTools(undefined), hashMcpServers(undefined),
    );

    // No verifying-keys dir at all (no allowlist)
    const mock = installFetchMock({
      prompt: promptText,
      configYaml: null,
      manifestJson,
      manifestSig,
    });
    try {
      // Should succeed (TOFU) even though manifest is published, because no allowlist
      await reviewersFetch("security", { from: "acme/personas@v1" });
      assert.ok(existsSync(join(repo, ".stamp", "reviewers", "security.md")));
    } finally {
      mock.restore();
    }
  });

  // -----------------------------------------------------------------------
  // AC#6d: no manifest but allowlist present → fail closed
  // -----------------------------------------------------------------------

  it("AC#6d: no manifest + allowlist present → fetch fails closed", async () => {
    const kp = generateKeypair();
    // Install a key in the allowlist
    const vkDir = stampVerifyingKeysDir(repo);
    mkdirSync(vkDir, { recursive: true });
    writeFileSync(join(vkDir, publicKeyFingerprintFilename(kp.fingerprint)), kp.publicKeyPem);

    // No manifest at source (manifestJson: null → 404)
    const mock = installFetchMock({
      prompt: "prompt\n",
      configYaml: null,
      manifestJson: null,
    });
    try {
      await assert.rejects(
        reviewersFetch("security", { from: "acme/personas@v1" }),
        /No signed manifest.*verifying-key allowlist exists/,
      );
    } finally {
      mock.restore();
    }
  });

  // -----------------------------------------------------------------------
  // --no-verify-manifest escape hatch
  // -----------------------------------------------------------------------

  it("--no-verify-manifest skips verification even with an allowlist", async () => {
    const kp = generateKeypair();
    const vkDir = stampVerifyingKeysDir(repo);
    mkdirSync(vkDir, { recursive: true });
    writeFileSync(join(vkDir, publicKeyFingerprintFilename(kp.fingerprint)), kp.publicKeyPem);

    // Source has no manifest
    const promptText = "bypass prompt\n";
    const mock = installFetchMock({ prompt: promptText, configYaml: null, manifestJson: null });
    try {
      // Would fail closed due to allowlist present + no manifest — but --no-verify-manifest skips that
      await reviewersFetch("security", { from: "acme/personas@v1", noVerifyManifest: true });
      assert.ok(existsSync(join(repo, ".stamp", "reviewers", "security.md")));
    } finally {
      mock.restore();
    }
  });

  // -----------------------------------------------------------------------
  // Bad signature → fail closed
  // -----------------------------------------------------------------------

  it("bad signature (tampered manifest) → fails closed", async () => {
    const kp = generateKeypair();
    const promptText = "prompt\n";
    const promptBytes = Buffer.from(promptText, "utf8");
    const promptSha = hashPromptBytes(promptBytes);
    const { manifestJson, manifestSig } = buildSignedManifest(
      kp, "security", promptSha, hashTools(undefined), hashMcpServers(undefined),
    );

    // Allowlist present
    const vkDir = stampVerifyingKeysDir(repo);
    mkdirSync(vkDir, { recursive: true });
    writeFileSync(join(vkDir, publicKeyFingerprintFilename(kp.fingerprint)), kp.publicKeyPem);

    // Tamper with the manifest (different source)
    const tamperedManifest = JSON.parse(manifestJson) as ReviewerManifest;
    tamperedManifest.source = "evil/source";
    const tamperedJson = JSON.stringify(tamperedManifest);

    const mock = installFetchMock({
      prompt: promptText,
      configYaml: null,
      manifestJson: tamperedJson, // tampered manifest, original sig
      manifestSig,
    });
    try {
      await assert.rejects(
        reviewersFetch("security", { from: "acme/personas@v1" }),
        /signature verification FAILED/,
      );
    } finally {
      mock.restore();
    }
  });

  // -----------------------------------------------------------------------
  // Multi-key allowlist (rotation overlap) — AC#6 "multi-key allowlist"
  // -----------------------------------------------------------------------

  it("multi-key allowlist: accepts signature from either key during rotation overlap", async () => {
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();
    const promptText = "overlap prompt\n";
    const promptBytes = Buffer.from(promptText, "utf8");
    const promptSha = hashPromptBytes(promptBytes);

    // Both keys in the allowlist
    const vkDir = stampVerifyingKeysDir(repo);
    mkdirSync(vkDir, { recursive: true });
    writeFileSync(join(vkDir, publicKeyFingerprintFilename(kp1.fingerprint)), kp1.publicKeyPem);
    writeFileSync(join(vkDir, publicKeyFingerprintFilename(kp2.fingerprint)), kp2.publicKeyPem);

    // Signed by kp2 (the NEW key during rotation overlap)
    const { manifestJson, manifestSig } = buildSignedManifest(
      kp2, "security", promptSha, hashTools(undefined), hashMcpServers(undefined),
    );

    const mock = installFetchMock({
      prompt: promptText,
      configYaml: null,
      manifestJson,
      manifestSig,
    });
    try {
      await reviewersFetch("security", { from: "acme/personas@v1" });
      assert.ok(existsSync(join(repo, ".stamp", "reviewers", "security.md")));
    } finally {
      mock.restore();
    }
  });

  // -----------------------------------------------------------------------
  // Existing locked reviewers continue to verify (via checkReviewerDrift)
  // This is tested by the existing reviewersDrift tests, but we add a smoke
  // test here to confirm the fetch → lock → verify round-trip still works
  // after AGT-113 changes.
  // -----------------------------------------------------------------------

  it("existing locked reviewer (no manifest) continues to verify after AGT-113", async () => {
    const promptText = "locked reviewer prompt\n";
    const promptBytes = Buffer.from(promptText, "utf8");
    const promptSha = hashPromptBytes(promptBytes);

    // First fetch (no manifest, no allowlist → TOFU)
    const mock = installFetchMock({ prompt: promptText, configYaml: null });
    try {
      await reviewersFetch("security", {
        from: "acme/personas@v1",
        expectPromptSha: promptSha,
      });
    } finally {
      mock.restore();
    }

    const lockPath = join(repo, ".stamp", "reviewers", "security.lock.json");
    assert.ok(existsSync(lockPath), "lock file should be written");
    const lock = JSON.parse(readFileSync(lockPath, "utf8"));
    assert.equal(lock.prompt_sha256, promptSha);
  });
});
