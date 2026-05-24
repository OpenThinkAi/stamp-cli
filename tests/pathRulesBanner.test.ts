/**
 * AC#4 (AGT-414): path_rules banner in the merge success report.
 *
 * `collectTrustAnchorSignatures` now returns `CollectTrustAnchorResult`
 * `{ signatures, matchedPathRules }` rather than `TrustAnchorSignatureV4[]`
 * directly. These tests assert:
 *
 *   - When no path_rules are configured → matchedPathRules is []
 *   - When path_rules are configured but the diff doesn't match → [] (silent)
 *   - When a rule matches and sigs satisfy the threshold → matchedPathRules
 *     carries the pattern, minimum_signatures, and the qualifying count
 *   - That the banner format `path_rules: <pattern> (<n>/<min> admin sigs)`
 *     can be constructed from the returned data (merge.ts exercises this
 *     path in the integration test)
 *
 * Uses a real git repo with synthetic Ed25519 admin keys (same pattern as
 * tests/adminSign.test.ts) because `collectTrustAnchorSignatures` reads
 * from git objects. No stamp server is spawned.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync, createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import { fingerprintFromPem } from "../src/lib/keys.ts";
import {
  collectTrustAnchorSignatures,
  type CollectTrustAnchorResult,
} from "../src/lib/trustAnchorCollection.ts";
import { parseManifest, snapshotSha256 } from "../src/lib/trustedKeysManifest.ts";
import { buildPubkeyMap } from "../src/lib/sshReviewClient.ts";
import { showAtRef, listFilesAtRef } from "../src/lib/git.ts";
import { trustAnchorSigningBytes } from "../src/lib/trustAnchorPayload.ts";
import {
  writeNote,
  emptyNote,
  noteWithAppendedSignature,
} from "../src/lib/trustAnchorNotes.ts";
import { signBytes } from "../src/lib/signing.ts";

function git(repo: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd: repo,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function generateAdminKey() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  return { privatePem, publicPem, fingerprint: fingerprintFromPem(publicPem) };
}

interface BannerHarness {
  repo: string;
  baseSha: string;
  headSha: string;
  adminKey: ReturnType<typeof generateAdminKey>;
  diffSha256: string;
  cleanup: () => void;
}

/**
 * Build a minimal stamp repo with:
 *   - path_rules: .stamp/**: require_capability: admin, minimum_signatures: 1
 *   - a feature branch that touches .stamp/reviewers/security.md
 *   - one synthetic admin key committed to trusted-keys
 * Returns the harness; does NOT deposit any notes (tests do that selectively).
 */
function setupBannerHarness(): BannerHarness {
  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-banner-"));
  const repo = path.join(root, "repo");
  mkdirSync(repo, { recursive: true });

  git(repo, ["init", "-q", "-b", "main"]);
  git(repo, ["config", "user.name", "Test"]);
  git(repo, ["config", "user.email", "test@example.invalid"]);
  git(repo, ["config", "commit.gpgsign", "false"]);

  const adminKey = generateAdminKey();
  const pubFile = adminKey.fingerprint.replace(":", "_") + ".pub";

  mkdirSync(path.join(repo, ".stamp", "reviewers"), { recursive: true });
  mkdirSync(path.join(repo, ".stamp", "trusted-keys"), { recursive: true });

  writeFileSync(
    path.join(repo, ".stamp", "config.yml"),
    [
      "branches:",
      "  main:",
      "    required: [security]",
      "    review_server: ssh://git@stamp.test.invalid:22",
      "reviewers:",
      "  security:",
      "    prompt: .stamp/reviewers/security.md",
      "path_rules:",
      "  .stamp/**:",
      "    require_capability: admin",
      "    minimum_signatures: 1",
      "    bypass_review_cycle: true",
      "",
    ].join("\n"),
  );
  writeFileSync(
    path.join(repo, ".stamp", "reviewers", "security.md"),
    "# security\n",
  );
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", pubFile),
    adminKey.publicPem,
  );
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", "manifest.yml"),
    [
      "keys:",
      "  admin-test:",
      `    fingerprint: ${adminKey.fingerprint}`,
      "    capabilities: [admin, operator]",
      "",
    ].join("\n"),
  );

  writeFileSync(path.join(repo, "README.md"), "initial\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "initial"]);
  const baseSha = git(repo, ["rev-parse", "HEAD"]).trim();

  // Feature branch — modifies .stamp/reviewers/security.md (matches .stamp/**)
  git(repo, ["checkout", "-q", "-b", "feature"]);
  writeFileSync(
    path.join(repo, ".stamp", "reviewers", "security.md"),
    "# security (updated)\n",
  );
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "update reviewer"]);
  const headSha = git(repo, ["rev-parse", "HEAD"]).trim();

  // Compute diffSha256 for the collector's signing target.
  const diff = git(repo, ["diff", `${baseSha}..${headSha}`]);
  const diffSha256 = createHash("sha256").update(Buffer.from(diff, "utf8")).digest("hex");

  return {
    repo,
    baseSha,
    headSha,
    adminKey,
    diffSha256,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

/**
 * Sign the trust-anchor payload and deposit it as a git note on headSha.
 * Mirrors what `stamp admin sign` does, using the proper note format.
 */
function depositAdminNote(
  h: BannerHarness,
  operatorFingerprint: string,
): void {
  const { repo, baseSha, headSha, adminKey, diffSha256 } = h;

  const manifestYaml = showAtRef(baseSha, ".stamp/trusted-keys/manifest.yml", repo);
  const manifest = parseManifest(manifestYaml)!;
  const snapshot = snapshotSha256(manifest);

  // Build the signing target the same way `stamp admin sign` does.
  const signingTarget = trustAnchorSigningBytes({
    baseSha,
    headSha,
    targetBranch: "main",
    diffSha256,
    manifestSnapshotSha256: snapshot,
    approvals: [],
    checks: [],
    signerKeyId: operatorFingerprint,
  });

  const sig = signBytes(adminKey.privatePem, signingTarget);

  // Build the note using the proper schema (version, head_sha, base_sha, etc.)
  let note = emptyNote({
    head_sha: headSha,
    base_sha: baseSha,
    diff_sha256: diffSha256,
    target_branch: "main",
  });
  const { note: withSig } = noteWithAppendedSignature(note, {
    signer_key_id: adminKey.fingerprint,
    signature: sig,
  });
  note = withSig;

  writeNote(repo, headSha, note);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function buildInput(h: BannerHarness, operatorFingerprint: string) {
  const manifestYaml = showAtRef(
    h.baseSha,
    ".stamp/trusted-keys/manifest.yml",
    h.repo,
  );
  const manifest = parseManifest(manifestYaml)!;
  const pubFilenames = listFilesAtRef(h.baseSha, ".stamp/trusted-keys", h.repo);
  const pubkeyByFingerprint = buildPubkeyMap(pubFilenames, (relPath) =>
    showAtRef(h.baseSha, relPath, h.repo),
  );
  return {
    repoRoot: h.repo,
    baseSha: h.baseSha,
    headSha: h.headSha,
    targetBranch: "main",
    diffSha256: h.diffSha256,
    manifestSnapshotSha256: snapshotSha256(manifest),
    approvals: [],
    checks: [],
    operatorFingerprint,
    manifest,
    pubkeyByFingerprint,
  };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("collectTrustAnchorSignatures — matchedPathRules banner (AC#4)", () => {
  let h: BannerHarness;

  beforeEach(() => {
    h = setupBannerHarness();
  });

  afterEach(() => {
    h.cleanup();
  });

  it("throws (not silently returns) when a rule matches but no note is deposited", () => {
    // No note deposited → should throw because minimum_signatures: 1 is unmet.
    const input = buildInput(h, h.adminKey.fingerprint);
    assert.throws(
      () => collectTrustAnchorSignatures(input),
      /path_rules.*requires.*admin signature/,
    );
  });

  it("returns matchedPathRules with pattern, minimum_signatures, and qualifying_count when sigs satisfy threshold", () => {
    // Deposit a valid admin note so the threshold is met.
    depositAdminNote(h, h.adminKey.fingerprint);

    const input = buildInput(h, h.adminKey.fingerprint);
    const result: CollectTrustAnchorResult = collectTrustAnchorSignatures(input);

    assert.equal(result.signatures.length, 1, "one verified signature expected");
    assert.equal(result.matchedPathRules.length, 1, "one matched rule expected");

    const rule = result.matchedPathRules[0]!;
    assert.equal(rule.pattern, ".stamp/**");
    assert.equal(rule.minimum_signatures, 1);
    assert.equal(rule.qualifying_count, 1);
  });

  it("matchedPathRules banner string formats as 'path_rules: <pattern> (<n>/<min> admin sigs)'", () => {
    depositAdminNote(h, h.adminKey.fingerprint);

    const input = buildInput(h, h.adminKey.fingerprint);
    const result = collectTrustAnchorSignatures(input);

    for (const pr of result.matchedPathRules) {
      const bannerLine = `  path_rules: ${pr.pattern} (${pr.qualifying_count}/${pr.minimum_signatures} admin sigs)`;
      assert.match(
        bannerLine,
        /path_rules: \.stamp\/\*\* \(1\/1 admin sigs\)/,
        "banner line must match the expected format",
      );
    }
  });

  it("returns empty matchedPathRules (and empty signatures) when diff doesn't touch path_rules pattern", () => {
    // Set up a repo variant where the feature branch only touches README.md,
    // not .stamp/**, so no rule matches.
    const root2 = mkdtempSync(path.join(os.tmpdir(), "stamp-banner-nomatch-"));
    const repo2 = path.join(root2, "repo");
    mkdirSync(repo2, { recursive: true });

    git(repo2, ["init", "-q", "-b", "main"]);
    git(repo2, ["config", "user.name", "Test"]);
    git(repo2, ["config", "user.email", "test@example.invalid"]);
    git(repo2, ["config", "commit.gpgsign", "false"]);

    const adminKey2 = generateAdminKey();
    const pubFile2 = adminKey2.fingerprint.replace(":", "_") + ".pub";

    mkdirSync(path.join(repo2, ".stamp", "reviewers"), { recursive: true });
    mkdirSync(path.join(repo2, ".stamp", "trusted-keys"), { recursive: true });

    writeFileSync(
      path.join(repo2, ".stamp", "config.yml"),
      [
        "branches:",
        "  main:",
        "    required: [security]",
        "    review_server: ssh://git@stamp.test.invalid:22",
        "reviewers:",
        "  security:",
        "    prompt: .stamp/reviewers/security.md",
        "path_rules:",
        "  .stamp/**:",
        "    require_capability: admin",
        "    minimum_signatures: 1",
        "    bypass_review_cycle: true",
        "",
      ].join("\n"),
    );
    writeFileSync(path.join(repo2, ".stamp", "reviewers", "security.md"), "# sec\n");
    writeFileSync(path.join(repo2, ".stamp", "trusted-keys", pubFile2), adminKey2.publicPem);
    writeFileSync(
      path.join(repo2, ".stamp", "trusted-keys", "manifest.yml"),
      [
        "keys:",
        "  admin-test2:",
        `    fingerprint: ${adminKey2.fingerprint}`,
        "    capabilities: [admin, operator]",
        "",
      ].join("\n"),
    );
    writeFileSync(path.join(repo2, "README.md"), "initial\n");
    git(repo2, ["add", "-A"]);
    git(repo2, ["commit", "-q", "-m", "initial"]);
    const baseSha2 = git(repo2, ["rev-parse", "HEAD"]).trim();

    git(repo2, ["checkout", "-q", "-b", "feature"]);
    writeFileSync(path.join(repo2, "README.md"), "updated\n"); // NOT .stamp/**
    git(repo2, ["add", "-A"]);
    git(repo2, ["commit", "-q", "-m", "non-stamp change"]);
    const headSha2 = git(repo2, ["rev-parse", "HEAD"]).trim();

    const diff2 = git(repo2, ["diff", `${baseSha2}..${headSha2}`]);
    const diffSha256_2 = createHash("sha256").update(Buffer.from(diff2, "utf8")).digest("hex");

    const manifestYaml2 = showAtRef(baseSha2, ".stamp/trusted-keys/manifest.yml", repo2);
    const manifest2 = parseManifest(manifestYaml2)!;
    const pubFilenames2 = listFilesAtRef(baseSha2, ".stamp/trusted-keys", repo2);
    const pubkeyByFingerprint2 = buildPubkeyMap(pubFilenames2, (relPath) =>
      showAtRef(baseSha2, relPath, repo2),
    );

    const result = collectTrustAnchorSignatures({
      repoRoot: repo2,
      baseSha: baseSha2,
      headSha: headSha2,
      targetBranch: "main",
      diffSha256: diffSha256_2,
      manifestSnapshotSha256: snapshotSha256(manifest2),
      approvals: [],
      checks: [],
      operatorFingerprint: adminKey2.fingerprint,
      manifest: manifest2,
      pubkeyByFingerprint: pubkeyByFingerprint2,
    });

    assert.deepStrictEqual(result.signatures, [], "no sigs when no rule matches");
    assert.deepStrictEqual(result.matchedPathRules, [], "no matchedPathRules when diff doesn't touch gated paths");

    rmSync(root2, { recursive: true, force: true });
  });

  it("returns empty result (not throw) when no path_rules configured at all", () => {
    // Build a repo without path_rules in config.
    const root3 = mkdtempSync(path.join(os.tmpdir(), "stamp-banner-nopathrules-"));
    const repo3 = path.join(root3, "repo");
    mkdirSync(repo3, { recursive: true });

    git(repo3, ["init", "-q", "-b", "main"]);
    git(repo3, ["config", "user.name", "Test"]);
    git(repo3, ["config", "user.email", "test@example.invalid"]);
    git(repo3, ["config", "commit.gpgsign", "false"]);

    const adminKey3 = generateAdminKey();
    const pubFile3 = adminKey3.fingerprint.replace(":", "_") + ".pub";

    mkdirSync(path.join(repo3, ".stamp", "reviewers"), { recursive: true });
    mkdirSync(path.join(repo3, ".stamp", "trusted-keys"), { recursive: true });

    // No path_rules section
    writeFileSync(
      path.join(repo3, ".stamp", "config.yml"),
      [
        "branches:",
        "  main:",
        "    required: [security]",
        "    review_server: ssh://git@stamp.test.invalid:22",
        "reviewers:",
        "  security:",
        "    prompt: .stamp/reviewers/security.md",
        "",
      ].join("\n"),
    );
    writeFileSync(path.join(repo3, ".stamp", "reviewers", "security.md"), "# sec\n");
    writeFileSync(path.join(repo3, ".stamp", "trusted-keys", pubFile3), adminKey3.publicPem);
    writeFileSync(
      path.join(repo3, ".stamp", "trusted-keys", "manifest.yml"),
      [
        "keys:",
        "  admin-test3:",
        `    fingerprint: ${adminKey3.fingerprint}`,
        "    capabilities: [admin, operator]",
        "",
      ].join("\n"),
    );
    writeFileSync(path.join(repo3, "README.md"), "initial\n");
    git(repo3, ["add", "-A"]);
    git(repo3, ["commit", "-q", "-m", "initial"]);
    const baseSha3 = git(repo3, ["rev-parse", "HEAD"]).trim();

    git(repo3, ["checkout", "-q", "-b", "feature"]);
    writeFileSync(path.join(repo3, ".stamp", "reviewers", "security.md"), "# sec updated\n");
    git(repo3, ["add", "-A"]);
    git(repo3, ["commit", "-q", "-m", "stamp change"]);
    const headSha3 = git(repo3, ["rev-parse", "HEAD"]).trim();

    const diff3 = git(repo3, ["diff", `${baseSha3}..${headSha3}`]);
    const diffSha256_3 = createHash("sha256").update(Buffer.from(diff3, "utf8")).digest("hex");

    const manifestYaml3 = showAtRef(baseSha3, ".stamp/trusted-keys/manifest.yml", repo3);
    const manifest3 = parseManifest(manifestYaml3)!;
    const pubFilenames3 = listFilesAtRef(baseSha3, ".stamp/trusted-keys", repo3);
    const pubkeyByFingerprint3 = buildPubkeyMap(pubFilenames3, (relPath) =>
      showAtRef(baseSha3, relPath, repo3),
    );

    const result = collectTrustAnchorSignatures({
      repoRoot: repo3,
      baseSha: baseSha3,
      headSha: headSha3,
      targetBranch: "main",
      diffSha256: diffSha256_3,
      manifestSnapshotSha256: snapshotSha256(manifest3),
      approvals: [],
      checks: [],
      operatorFingerprint: adminKey3.fingerprint,
      manifest: manifest3,
      pubkeyByFingerprint: pubkeyByFingerprint3,
    });

    assert.deepStrictEqual(result.signatures, [], "no sigs when no path_rules");
    assert.deepStrictEqual(result.matchedPathRules, [], "no matchedPathRules when no path_rules configured");

    rmSync(root3, { recursive: true, force: true });
  });
});
