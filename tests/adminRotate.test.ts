/**
 * Tests for `stamp admin add-key`, `stamp admin revoke`, and
 * `stamp admin list-keys` (AGT-348).
 *
 * Coverage:
 *   - add-key: happy path (manifest mutated, pub copied, commit made,
 *     stdout points operator at `stamp admin sign --pending <sha>`)
 *   - add-key: rejects duplicate name, duplicate fingerprint,
 *     unknown capability, malformed name, malformed pubkey, missing
 *     pubkey file, missing manifest
 *   - revoke: happy path (manifest mutated, commit made, banner points
 *     at sign-pending)
 *   - revoke: rejects unknown fingerprint, malformed fingerprint,
 *     last-admin-revoke (would brick the gate)
 *   - list-keys: human + JSON output shape; round-trip via JSON
 *
 * Each test sets up a throwaway git repo with a real manifest fixture.
 * No git operations are mocked — same pattern as `tests/adminSign.test.ts`.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
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

import {
  runAdminAddKey,
  runAdminListKeys,
  runAdminRevoke,
} from "../src/commands/adminRotate.ts";
import { fingerprintFromPem } from "../src/lib/keys.ts";
import {
  parseManifest,
  type TrustedKeysManifest,
} from "../src/lib/trustedKeysManifest.ts";

// ─── Harness ────────────────────────────────────────────────────────

interface ExternalKey {
  privatePem: string;
  publicPem: string;
  fingerprint: string;
}

interface Harness {
  repo: string;
  alice: ExternalKey;
  bob: ExternalKey;
  serverKey: ExternalKey;
  cleanup: () => void;
}

function git(repo: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd: repo,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function generateExternalKey(): ExternalKey {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();
  const publicPem = publicKey
    .export({ type: "spki", format: "pem" })
    .toString();
  return { privatePem, publicPem, fingerprint: fingerprintFromPem(publicPem) };
}

function runFromRepo<T>(repo: string, fn: () => T): T {
  const prev = process.cwd();
  process.chdir(repo);
  try {
    return fn();
  } finally {
    process.chdir(prev);
  }
}

function captureStdout(fn: () => void): string {
  const captured: string[] = [];
  const origWrite = process.stdout.write.bind(process.stdout);
  (process.stdout as unknown as { write: (s: string) => boolean }).write = (
    s: string,
  ) => {
    captured.push(typeof s === "string" ? s : (s as Buffer).toString("utf8"));
    return true;
  };
  try {
    fn();
  } finally {
    (process.stdout as unknown as { write: typeof origWrite }).write = origWrite;
  }
  return captured.join("");
}

/**
 * Build a stamp-gated repo with:
 *   - a `.stamp/trusted-keys/manifest.yml` listing alice (admin),
 *     bob (admin), and one server key (server)
 *   - the matching .pub files committed under .stamp/trusted-keys/
 *   - a clean working tree on `main` so the rotation commands can
 *     create commits without conflicts
 *
 * The harness mints a third key (`spare`) that tests can pass to
 * `add-key` to grow the manifest.
 */
function setupHarness(): Harness & { spare: ExternalKey; sparePubPath: string } {
  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-adminrotate-"));
  const repo = path.join(root, "repo");
  mkdirSync(repo, { recursive: true });

  const alice = generateExternalKey();
  const bob = generateExternalKey();
  const serverKey = generateExternalKey();
  const spare = generateExternalKey();

  git(repo, ["init", "-q", "-b", "main"]);
  git(repo, ["config", "user.name", "Test"]);
  git(repo, ["config", "user.email", "test@example.invalid"]);
  git(repo, ["config", "commit.gpgsign", "false"]);

  mkdirSync(path.join(repo, ".stamp", "trusted-keys"), { recursive: true });
  const trustedDir = path.join(repo, ".stamp", "trusted-keys");
  writeFileSync(
    path.join(trustedDir, alice.fingerprint.replace(":", "_") + ".pub"),
    alice.publicPem,
  );
  writeFileSync(
    path.join(trustedDir, bob.fingerprint.replace(":", "_") + ".pub"),
    bob.publicPem,
  );
  writeFileSync(
    path.join(trustedDir, serverKey.fingerprint.replace(":", "_") + ".pub"),
    serverKey.publicPem,
  );

  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", "manifest.yml"),
    [
      "keys:",
      "  alice:",
      `    fingerprint: ${alice.fingerprint}`,
      "    capabilities: [admin]",
      "  bob:",
      `    fingerprint: ${bob.fingerprint}`,
      "    capabilities: [admin]",
      "  review-server:",
      `    fingerprint: ${serverKey.fingerprint}`,
      "    capabilities: [server]",
      "    role_source: server",
      "",
    ].join("\n"),
  );

  writeFileSync(path.join(repo, "README.md"), "initial\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "initial: seed trust-anchor manifest"]);

  // Drop the spare pub on disk for tests to pass to add-key.
  const sparePubPath = path.join(root, "spare.pub");
  writeFileSync(sparePubPath, spare.publicPem);

  return {
    repo,
    alice,
    bob,
    serverKey,
    spare,
    sparePubPath,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

function readManifest(repo: string): TrustedKeysManifest {
  const text = readFileSync(
    path.join(repo, ".stamp", "trusted-keys", "manifest.yml"),
    "utf8",
  );
  const m = parseManifest(text);
  assert.ok(m, "manifest should re-parse cleanly after a rotation command");
  return m!;
}

// ─── add-key ───────────────────────────────────────────────────────

describe("stamp admin add-key", () => {
  it("adds entry, copies pub file, commits, and points operator at sign-pending", () => {
    const h = setupHarness();
    try {
      const headBefore = git(h.repo, ["rev-parse", "HEAD"]).trim();
      const out = captureStdout(() =>
        runFromRepo(h.repo, () =>
          runAdminAddKey({
            pubkeyPath: h.sparePubPath,
            name: "spare-admin",
            capabilities: "admin,operator",
          }),
        ),
      );
      const headAfter = git(h.repo, ["rev-parse", "HEAD"]).trim();
      assert.notEqual(headAfter, headBefore, "add-key must produce a commit");

      // Manifest now lists the new entry with the sorted capabilities.
      const m = readManifest(h.repo);
      const entry = m.entries.find((e) => e.name === "spare-admin");
      assert.ok(entry, "spare-admin should be in the manifest");
      assert.equal(entry!.fingerprint, h.spare.fingerprint);
      assert.deepEqual(entry!.capabilities, ["admin", "operator"]);

      // Pub file copied to trusted-keys under canonical fingerprint name.
      const pubDest = path.join(
        h.repo,
        ".stamp",
        "trusted-keys",
        h.spare.fingerprint.replace(":", "_") + ".pub",
      );
      assert.equal(readFileSync(pubDest, "utf8"), h.spare.publicPem);

      // Commit subject + body match the AGT-348 convention.
      const subject = git(h.repo, ["log", "-1", "--format=%s"]).trim();
      assert.match(subject, /^AGT-348: add admin key spare-admin /);
      const body = git(h.repo, ["log", "-1", "--format=%b"]);
      assert.match(body, /capabilities \[admin, operator\]/);
      assert.match(body, /stamp admin sign --pending/);

      // Stdout points operator at the multi-sig flow.
      assert.match(out, /stamp admin sign --pending/);
      assert.match(out, /bypass_review_cycle/);
    } finally {
      h.cleanup();
    }
  });

  it("rejects an unknown capability string", () => {
    const h = setupHarness();
    try {
      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runAdminAddKey({
              pubkeyPath: h.sparePubPath,
              name: "spare-admin",
              capabilities: "admin,superuser",
            }),
          ),
        /unknown capability/,
      );
      // No commit produced on failure.
      const log = git(h.repo, ["log", "--format=%s"]).trim().split("\n");
      assert.equal(log.length, 1);
    } finally {
      h.cleanup();
    }
  });

  it("rejects a malformed name", () => {
    const h = setupHarness();
    try {
      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runAdminAddKey({
              pubkeyPath: h.sparePubPath,
              name: "name with spaces",
              capabilities: "admin",
            }),
          ),
        /--name .* is invalid/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects an empty capability list", () => {
    const h = setupHarness();
    try {
      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runAdminAddKey({
              pubkeyPath: h.sparePubPath,
              name: "spare-admin",
              capabilities: "",
            }),
          ),
        /--capabilities must list at least one/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects a missing pubkey file", () => {
    const h = setupHarness();
    try {
      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runAdminAddKey({
              pubkeyPath: path.join(h.repo, "does-not-exist.pub"),
              name: "spare-admin",
              capabilities: "admin",
            }),
          ),
        /pubkey file not found/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects a malformed pubkey PEM", () => {
    const h = setupHarness();
    try {
      const badPath = path.join(h.repo, "bad.pub");
      writeFileSync(badPath, "this is not a PEM\n");
      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runAdminAddKey({
              pubkeyPath: badPath,
              name: "spare-admin",
              capabilities: "admin",
            }),
          ),
        /not a valid public key PEM/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects a duplicate name", () => {
    const h = setupHarness();
    try {
      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runAdminAddKey({
              pubkeyPath: h.sparePubPath,
              name: "alice", // already taken
              capabilities: "admin",
            }),
          ),
        /already has an entry named/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects a duplicate fingerprint", () => {
    const h = setupHarness();
    try {
      // Drop alice's pub as a fresh file and try to add it under a new
      // name — same fingerprint, should be rejected.
      const dupPubPath = path.join(h.repo, "alice-dup.pub");
      writeFileSync(dupPubPath, h.alice.publicPem);
      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runAdminAddKey({
              pubkeyPath: dupPubPath,
              name: "alice-clone",
              capabilities: "admin",
            }),
          ),
        /already trusts/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects when the manifest is missing", () => {
    const h = setupHarness();
    try {
      rmSync(path.join(h.repo, ".stamp", "trusted-keys", "manifest.yml"));
      git(h.repo, ["add", "-A"]);
      git(h.repo, ["commit", "-q", "-m", "remove manifest for test"]);
      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runAdminAddKey({
              pubkeyPath: h.sparePubPath,
              name: "spare-admin",
              capabilities: "admin",
            }),
          ),
        /no manifest at/,
      );
    } finally {
      h.cleanup();
    }
  });
});

// ─── revoke ────────────────────────────────────────────────────────

describe("stamp admin revoke", () => {
  it("removes the entry, commits, and points operator at sign-pending", () => {
    const h = setupHarness();
    try {
      const headBefore = git(h.repo, ["rev-parse", "HEAD"]).trim();
      const out = captureStdout(() =>
        runFromRepo(h.repo, () => runAdminRevoke({ fingerprint: h.bob.fingerprint })),
      );
      const headAfter = git(h.repo, ["rev-parse", "HEAD"]).trim();
      assert.notEqual(headAfter, headBefore, "revoke must produce a commit");

      const m = readManifest(h.repo);
      assert.equal(
        m.entries.find((e) => e.fingerprint === h.bob.fingerprint),
        undefined,
        "bob must be removed",
      );
      // alice + server should remain.
      assert.ok(m.entries.find((e) => e.name === "alice"));
      assert.ok(m.entries.find((e) => e.name === "review-server"));

      const subject = git(h.repo, ["log", "-1", "--format=%s"]).trim();
      assert.match(subject, /^AGT-348: revoke admin key bob /);
      assert.match(out, /stamp admin sign --pending/);
    } finally {
      h.cleanup();
    }
  });

  it("rejects an unknown fingerprint", () => {
    const h = setupHarness();
    try {
      const fake = "sha256:" + "f".repeat(64);
      assert.throws(
        () =>
          runFromRepo(h.repo, () => runAdminRevoke({ fingerprint: fake })),
        /no entry in .* with fingerprint/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects a malformed fingerprint", () => {
    const h = setupHarness();
    try {
      assert.throws(
        () =>
          runFromRepo(h.repo, () => runAdminRevoke({ fingerprint: "abc123" })),
        /not in the expected sha256:<64-hex> form/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("refuses to revoke the last admin (would brick the gate)", () => {
    const h = setupHarness();
    try {
      // Revoke bob first (alice remains as sole admin).
      runFromRepo(h.repo, () => runAdminRevoke({ fingerprint: h.bob.fingerprint }));
      // Now revoking alice would leave zero admins.
      assert.throws(
        () =>
          runFromRepo(h.repo, () => runAdminRevoke({ fingerprint: h.alice.fingerprint })),
        /refusing to revoke the last admin key/,
      );
    } finally {
      h.cleanup();
    }
  });
});

// ─── list-keys ─────────────────────────────────────────────────────

describe("stamp admin list-keys", () => {
  it("emits the human table covering every manifest entry", () => {
    const h = setupHarness();
    try {
      const out = captureStdout(() =>
        runFromRepo(h.repo, () => runAdminListKeys()),
      );
      assert.match(out, /trusted-keys manifest — 3 entries/);
      assert.match(out, /alice/);
      assert.match(out, /bob/);
      assert.match(out, /review-server/);
      assert.match(out, new RegExp(h.alice.fingerprint));
      assert.match(out, new RegExp(h.bob.fingerprint));
      assert.match(out, new RegExp(h.serverKey.fingerprint));
      assert.match(out, /\[admin\]/);
      assert.match(out, /\[server\]/);
      assert.match(out, /role_source=server/);
    } finally {
      h.cleanup();
    }
  });

  it("emits parseable JSON when --json is set", () => {
    const h = setupHarness();
    try {
      const out = captureStdout(() =>
        runFromRepo(h.repo, () => runAdminListKeys({ json: true })),
      );
      const parsed = JSON.parse(out);
      assert.ok(Array.isArray(parsed.entries));
      assert.equal(parsed.entries.length, 3);
      const aliceEntry = parsed.entries.find(
        (e: { name: string }) => e.name === "alice",
      );
      assert.ok(aliceEntry);
      assert.equal(aliceEntry.fingerprint, h.alice.fingerprint);
      assert.deepEqual(aliceEntry.capabilities, ["admin"]);
    } finally {
      h.cleanup();
    }
  });

  it("reflects an add-key + revoke round-trip", () => {
    const h = setupHarness();
    try {
      runFromRepo(h.repo, () =>
        runAdminAddKey({
          pubkeyPath: h.sparePubPath,
          name: "spare-admin",
          capabilities: "admin,operator",
        }),
      );
      let listed = JSON.parse(
        captureStdout(() =>
          runFromRepo(h.repo, () => runAdminListKeys({ json: true })),
        ),
      ) as { entries: Array<{ name: string; fingerprint: string }> };
      assert.equal(listed.entries.length, 4);
      assert.ok(listed.entries.find((e) => e.name === "spare-admin"));

      runFromRepo(h.repo, () =>
        runAdminRevoke({ fingerprint: h.spare.fingerprint }),
      );
      listed = JSON.parse(
        captureStdout(() =>
          runFromRepo(h.repo, () => runAdminListKeys({ json: true })),
        ),
      );
      assert.equal(listed.entries.length, 3);
      assert.equal(
        listed.entries.find((e) => e.name === "spare-admin"),
        undefined,
      );
    } finally {
      h.cleanup();
    }
  });

  it("handles a missing manifest gracefully", () => {
    const h = setupHarness();
    try {
      rmSync(path.join(h.repo, ".stamp", "trusted-keys", "manifest.yml"));
      const out = captureStdout(() =>
        runFromRepo(h.repo, () => runAdminListKeys()),
      );
      assert.match(out, /no manifest at/);
    } finally {
      h.cleanup();
    }
  });
});
