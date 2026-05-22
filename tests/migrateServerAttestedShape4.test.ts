/**
 * WS2 — one-PR Shape 4 init flow tests.
 *
 * Exercises `stamp init --migrate-to-server-attested` end-to-end against
 * a hermetic git repo, with the SSH pubkey fetch stubbed via the
 * `__setFetchForTests` seam. The critical AC the brief calls out is the
 * end-to-end: after the scaffold lands in a feature branch, the produced
 * diff must pass `validateShape4ActivationDiff` cleanly so
 * `stamp attest --migrate-existing` accepts it. That AC is exercised in
 * `accepts validation` below.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import {
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

import { runMigrateToServerAttested } from "../src/commands/migrateServerAttested.ts";
import { ensureUserKeypair, generateKeypair } from "../src/lib/keys.ts";
import { validateShape4ActivationDiff } from "../src/lib/migrationBootstrap.ts";
import { __setFetchForTests } from "../src/lib/serverPubkeyFetch.ts";
import { parseManifest } from "../src/lib/trustedKeysManifest.ts";

// ─── helpers ───────────────────────────────────────────────────────

function git(repo: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd: repo,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function shaOf(repo: string, ref: string): string {
  return git(repo, ["rev-parse", ref]).trim();
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

interface Harness {
  /** Repo root with .git initialized and a "1.x-shaped" baseline on main. */
  repo: string;
  /** $HOME override used for stamp's per-user state. */
  home: string;
  /** Operator keypair that backs `.stamp/trusted-keys/operator-test.pub`
   *  at HEAD (and ~/.stamp/keys/ed25519). */
  operatorFingerprint: string;
  /** Server keypair the stubbed fetcher returns. */
  serverPubkeyPem: string;
  serverFingerprint: string;
  /** Restores HOME + the fetcher stub. */
  cleanup: () => void;
}

/**
 * Stand up a "Shape 2 (or pre-Shape-4)" repo: existing operator pubkey
 * + `path_rules` + a per-repo reviewer prompt at .stamp/reviewers/security.md.
 * The bootstrap whitelist requires path_rules at base to cover .stamp/**
 * with bypass_review_cycle: true, so we install that here too.
 */
function setupShape2Repo(opts: {
  /** When >1, baseline manifest carries two admin-cap entries (alice +
   *  bob) and path_rules min_sigs matches. Default 1 (single-admin). */
  multiAdmin?: boolean;
}): Harness {
  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-ws2-"));
  const repo = path.join(root, "repo");
  const home = path.join(root, "home");
  mkdirSync(repo, { recursive: true });
  mkdirSync(home, { recursive: true });

  const prevHome = process.env["HOME"];
  process.env["HOME"] = home;

  const { keypair: operatorKp } = ensureUserKeypair();
  const operatorFingerprint = operatorKp.fingerprint;

  git(repo, ["init", "-q", "-b", "main"]);
  git(repo, ["config", "user.name", "Test"]);
  git(repo, ["config", "user.email", "test@example.invalid"]);
  git(repo, ["config", "commit.gpgsign", "false"]);

  mkdirSync(path.join(repo, ".stamp", "reviewers"), { recursive: true });
  mkdirSync(path.join(repo, ".stamp", "trusted-keys"), { recursive: true });

  // Per-repo reviewer prompt + tools, the shape Phase A repos carry.
  writeFileSync(
    path.join(repo, ".stamp", "reviewers", "security.md"),
    "be paranoid\n",
  );

  // Drop operator pubkey under canonical filename.
  const operatorPubFile = operatorFingerprint.replace(":", "_") + ".pub";
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", operatorPubFile),
    operatorKp.publicKeyPem,
  );

  // Multi-admin variant: also drop a bob pubkey (no need to bind it as
  // admin in the manifest; the migration scaffolder will rewrite the
  // manifest based on the indexes we pass in).
  const bobKp = opts.multiAdmin ? generateKeypair() : null;
  if (bobKp) {
    writeFileSync(
      path.join(repo, ".stamp", "trusted-keys", "bob.pub"),
      bobKp.publicKeyPem,
    );
  }

  const minSigs = opts.multiAdmin ? 2 : 1;
  writeFileSync(
    path.join(repo, ".stamp", "config.yml"),
    [
      "branches:",
      "  main:",
      "    required: [security]",
      "reviewers:",
      "  security:",
      "    prompt: .stamp/reviewers/security.md",
      "    tools: []",
      "path_rules:",
      "  \".stamp/**\":",
      "    require_capability: admin",
      `    minimum_signatures: ${minSigs}`,
      "    bypass_review_cycle: true",
      "",
    ].join("\n"),
  );
  // Pre-existing manifest binding the operator (and optionally bob) as
  // admin so the path_rules check in --migrate-existing finds an admin.
  const manifestEntries = [
    "  operator-test:",
    `    fingerprint: ${operatorFingerprint}`,
    "    capabilities: [admin, operator]",
  ];
  if (bobKp) {
    manifestEntries.push(
      "  bob:",
      `    fingerprint: ${bobKp.fingerprint}`,
      "    capabilities: [admin, operator]",
    );
  }
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", "manifest.yml"),
    ["keys:", ...manifestEntries, ""].join("\n"),
  );
  writeFileSync(path.join(repo, "README.md"), "hello\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "initial"]);

  // Stub the SSH fetch to return a fresh server keypair.
  const serverKp = generateKeypair();
  const restoreFetch = __setFetchForTests(() => serverKp.publicKeyPem);

  return {
    repo,
    home,
    operatorFingerprint,
    serverPubkeyPem: serverKp.publicKeyPem,
    serverFingerprint: serverKp.fingerprint,
    cleanup: () => {
      restoreFetch();
      if (prevHome === undefined) delete process.env["HOME"];
      else process.env["HOME"] = prevHome;
      rmSync(root, { recursive: true, force: true });
    },
  };
}

const SERVER_ARG = "stamp.test.invalid:22";

// ─── 1. happy path ─────────────────────────────────────────────────

describe("runMigrateToServerAttested — Shape 4 one-PR happy path", () => {
  it("single admin: writes complete scaffold with minimum_signatures=1", () => {
    const h = setupShape2Repo({ multiAdmin: false });
    try {
      withCwd(h.repo, () =>
        runMigrateToServerAttested({
          server: SERVER_ARG,
          selectAdminIndexes: [1],
        }),
      );

      // Manifest: operator (admin+operator) + server entry.
      const manifestText = readFileSync(
        path.join(h.repo, ".stamp", "trusted-keys", "manifest.yml"),
        "utf8",
      );
      const parsed = parseManifest(manifestText);
      assert.ok(parsed, "manifest must parse");
      const byName = Object.fromEntries(
        parsed!.entries.map((e) => [e.name, e]),
      );
      assert.ok(byName["review-server-prod"], "server entry must be present");
      assert.deepEqual(byName["review-server-prod"]!.capabilities, ["server"]);
      assert.equal(
        byName["review-server-prod"]!.fingerprint,
        h.serverFingerprint,
      );

      // Pubkey file landed.
      const pubPath = path.join(
        h.repo,
        ".stamp",
        "trusted-keys",
        "review-server-prod.pub",
      );
      assert.equal(readFileSync(pubPath, "utf8"), h.serverPubkeyPem);

      // Config: review_server on main, reviewers in {} form, min_sigs=1.
      const cfg = readFileSync(
        path.join(h.repo, ".stamp", "config.yml"),
        "utf8",
      );
      assert.ok(
        cfg.includes(`review_server: ssh://git@stamp.test.invalid:22`),
        "review_server must be added to main branch rule",
      );
      assert.ok(cfg.includes("security: {}"), "reviewers rewritten to {}");
      assert.ok(
        cfg.includes("minimum_signatures: 1"),
        "single-admin smart-default kicks in",
      );

      // Workflow file.
      assert.equal(
        existsSync(
          path.join(h.repo, ".github", "workflows", "stamp-verify.yml"),
        ),
        true,
      );

      // .stamp/reviewers/security.md removed.
      assert.equal(
        existsSync(path.join(h.repo, ".stamp", "reviewers", "security.md")),
        false,
        "in-repo reviewer prompt must be removed",
      );
    } finally {
      h.cleanup();
    }
  });

  it("multi-admin: minimum_signatures=2", () => {
    const h = setupShape2Repo({ multiAdmin: true });
    try {
      withCwd(h.repo, () =>
        runMigrateToServerAttested({
          server: SERVER_ARG,
          selectAdminIndexes: [1, 2], // promote both detected keys
        }),
      );
      const cfg = readFileSync(
        path.join(h.repo, ".stamp", "config.yml"),
        "utf8",
      );
      assert.ok(cfg.includes("minimum_signatures: 2"));
    } finally {
      h.cleanup();
    }
  });
});

// ─── 2. flag resolution ────────────────────────────────────────────

describe("runMigrateToServerAttested — server resolution", () => {
  it("falls back to ~/.stamp/server.yml when --server omitted", () => {
    const h = setupShape2Repo({ multiAdmin: false });
    try {
      // Drop a server.yml so loadServerConfig() resolves it.
      mkdirSync(path.join(h.home, ".stamp"), { recursive: true });
      writeFileSync(
        path.join(h.home, ".stamp", "server.yml"),
        [
          "host: stamp.fallback.invalid",
          "port: 2222",
          "",
        ].join("\n"),
      );
      withCwd(h.repo, () =>
        runMigrateToServerAttested({ selectAdminIndexes: [1] }),
      );
      const cfg = readFileSync(
        path.join(h.repo, ".stamp", "config.yml"),
        "utf8",
      );
      assert.ok(
        cfg.includes("ssh://git@stamp.fallback.invalid:2222"),
        "server.yml fallback must drive review_server URL",
      );
    } finally {
      h.cleanup();
    }
  });

  it("throws an actionable error when no server source is configured", () => {
    const h = setupShape2Repo({ multiAdmin: false });
    try {
      // No --server and no ~/.stamp/server.yml — should throw.
      assert.throws(
        () =>
          withCwd(h.repo, () =>
            runMigrateToServerAttested({ selectAdminIndexes: [1] }),
          ),
        /no stamp server configured.*--server.*server\.yml/s,
      );
    } finally {
      h.cleanup();
    }
  });
});

// ─── 3. dry-run ────────────────────────────────────────────────────

describe("runMigrateToServerAttested — dry-run", () => {
  it("writes nothing and does not invoke the SSH fetch", () => {
    const h = setupShape2Repo({ multiAdmin: false });
    let fetcherCalls = 0;
    const restore = __setFetchForTests(() => {
      fetcherCalls++;
      return h.serverPubkeyPem;
    });
    try {
      const cfgBefore = readFileSync(
        path.join(h.repo, ".stamp", "config.yml"),
        "utf8",
      );
      withCwd(h.repo, () =>
        runMigrateToServerAttested({
          dryRun: true,
          server: SERVER_ARG,
          selectAdminIndexes: [1],
        }),
      );
      // No SSH call.
      assert.equal(fetcherCalls, 0, "dry-run must NOT invoke the fetcher");
      // Config untouched.
      assert.equal(
        readFileSync(path.join(h.repo, ".stamp", "config.yml"), "utf8"),
        cfgBefore,
      );
      // No workflow.
      assert.equal(
        existsSync(
          path.join(h.repo, ".github", "workflows", "stamp-verify.yml"),
        ),
        false,
      );
      // Server pubkey file not created.
      assert.equal(
        existsSync(
          path.join(
            h.repo,
            ".stamp",
            "trusted-keys",
            "review-server-prod.pub",
          ),
        ),
        false,
      );
      // .stamp/reviewers/security.md still present.
      assert.equal(
        existsSync(path.join(h.repo, ".stamp", "reviewers", "security.md")),
        true,
      );
    } finally {
      restore();
      h.cleanup();
    }
  });
});

// ─── 4. end-to-end: passes validateShape4ActivationDiff ─────────────

describe("runMigrateToServerAttested — end-to-end whitelist acceptance", () => {
  it("the produced diff passes validateShape4ActivationDiff cleanly", () => {
    const h = setupShape2Repo({ multiAdmin: false });
    try {
      // Run the scaffold on a feature branch.
      git(h.repo, ["checkout", "-q", "-b", "shape-4-activation"]);
      withCwd(h.repo, () =>
        runMigrateToServerAttested({
          server: SERVER_ARG,
          selectAdminIndexes: [1],
        }),
      );

      // Commit ONLY the .stamp/** subset — that's what stamp attest
      // --migrate-existing signs (the workflow file rides outside).
      git(h.repo, [
        "add",
        ".stamp/config.yml",
        ".stamp/trusted-keys/manifest.yml",
        ".stamp/trusted-keys/review-server-prod.pub",
      ]);
      git(h.repo, ["rm", "-q", ".stamp/reviewers/security.md"]);
      git(h.repo, ["commit", "-q", "-m", "Shape 4 activation"]);

      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "shape-4-activation");
      const result = validateShape4ActivationDiff({
        repoRoot: h.repo,
        baseSha: base,
        headSha: head,
      });
      assert.ok(
        result.ok,
        `expected whitelist acceptance, got: ${(result as { ok: false; reason: string }).reason ?? "(missing)"}`,
      );
      const paths = (result as { ok: true; activatedPaths: string[] }).activatedPaths;
      assert.ok(paths.includes(".stamp/config.yml"), `config in activatedPaths: ${paths.join(", ")}`);
      assert.ok(
        paths.includes(".stamp/trusted-keys/manifest.yml"),
        `manifest in activatedPaths: ${paths.join(", ")}`,
      );
      assert.ok(
        paths.includes(".stamp/trusted-keys/review-server-prod.pub"),
        `new server pubkey in activatedPaths: ${paths.join(", ")}`,
      );
      assert.ok(
        paths.includes(".stamp/reviewers/security.md"),
        `deleted prompt file in activatedPaths: ${paths.join(", ")}`,
      );
    } finally {
      h.cleanup();
    }
  });
});
