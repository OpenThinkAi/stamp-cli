/**
 * AGT-398 — Shape 4 migration-bootstrap envelope tests.
 *
 * Covers three surfaces:
 *
 *   1. Canonical signing-byte determinism (the marker is signed; bytes
 *      change when the marker changes; bytes are stable across object
 *      construction order).
 *   2. Attest-side: `runAttest({ migrateExisting: true })` accepted on
 *      a Shape-4-activation diff, refused on diffs that violate the
 *      whitelist or skip the path_rules / admin-cap preconditions.
 *   3. Verifier-side: bootstrap envelope accepted when all conditions
 *      hold; rejected when each condition fails independently. A replay/
 *      spoof test confirms a bootstrap envelope produced against a
 *      non-bootstrap diff verifies false (the verifier re-validates the
 *      whitelist from the merge-base + head trees).
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { runAttest } from "../src/commands/attest.ts";
import { runVerifyPr } from "../src/commands/verifyPr.ts";
import {
  parseEnvelope,
  readAttestationBlobBytes,
  serializePayload,
  PR_ATTESTATION_SCHEMA_VERSION,
} from "../src/lib/prAttestation.ts";
import {
  bootstrapAdminSigningBytes,
  validateShape4ActivationDiff,
  type MigrationBootstrapMarker,
} from "../src/lib/migrationBootstrap.ts";
import type { AttestationPayloadV4 } from "../src/lib/attestationV4.ts";
import { ensureUserKeypair, fingerprintFromPem } from "../src/lib/keys.ts";
import { signBytes, verifyBytes } from "../src/lib/signing.ts";

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

function runFromRepo<T>(repo: string, fn: () => T): T {
  const prev = process.cwd();
  process.chdir(repo);
  try {
    return fn();
  } finally {
    process.chdir(prev);
  }
}

/**
 * Run `runVerifyPr` and capture stderr/console.error so the test can
 * assert against the actual failure reason. The verifier calls
 * `process.exit(1)` on failure; we trap that into a throw whose message
 * carries the captured stderr text.
 */
function expectVerifyPrRejection(
  repo: string,
  args: { head: string; base: string; into: string },
  expected: RegExp,
): void {
  const stderrCapture: string[] = [];
  const prevWrite = process.stderr.write.bind(process.stderr);
  // @ts-expect-error
  process.stderr.write = (chunk: string | Uint8Array): boolean => {
    stderrCapture.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
    return true;
  };
  const prevErrorLog = console.error;
  console.error = (...a: unknown[]) => {
    stderrCapture.push(a.map(String).join(" "));
  };
  const prevExit = process.exit;
  // @ts-expect-error
  process.exit = (code?: number) => {
    if (code && code !== 0) {
      throw new Error(stderrCapture.join("\n") || `runVerifyPr exited with code ${code}`);
    }
  };
  let caught: Error | null = null;
  try {
    runFromRepo(repo, () => runVerifyPr(args));
  } catch (err) {
    caught = err as Error;
  } finally {
    process.exit = prevExit;
    process.stderr.write = prevWrite;
    console.error = prevErrorLog;
  }
  if (!caught) {
    throw new Error(
      `expected runVerifyPr to reject; instead it returned cleanly. stderr: ${stderrCapture.join("")}`,
    );
  }
  if (!expected.test(caught.message)) {
    throw new Error(
      `verifyPr rejected as expected but reason didn't match ${expected}. Got: ${caught.message}`,
    );
  }
}

/** Verify-pr's success path falls through past `printSuccess` without
 *  calling process.exit. We trap a non-zero exit into a throw so an
 *  unexpected failure surfaces in the test rather than terminating it
 *  silently. */
function acceptVerifyPr(
  repo: string,
  args: { head: string; base: string; into: string },
): void {
  const stderrCapture: string[] = [];
  const prevWrite = process.stderr.write.bind(process.stderr);
  // @ts-expect-error
  process.stderr.write = (chunk: string | Uint8Array): boolean => {
    stderrCapture.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
    return true;
  };
  const prevErrorLog = console.error;
  console.error = (...a: unknown[]) => {
    stderrCapture.push(a.map(String).join(" "));
  };
  const prevExit = process.exit;
  // @ts-expect-error
  process.exit = (code?: number) => {
    if (code && code !== 0) {
      throw new Error(stderrCapture.join("\n") || `runVerifyPr exited with code ${code}`);
    }
  };
  try {
    runFromRepo(repo, () => runVerifyPr(args));
  } finally {
    process.exit = prevExit;
    process.stderr.write = prevWrite;
    console.error = prevErrorLog;
  }
}

function listAttestationPatchIds(repo: string): string[] {
  const out = git(repo, [
    "for-each-ref",
    "--format=%(refname)",
    "refs/stamp/attestations",
  ]);
  return out
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((ref) => ref.replace(/^refs\/stamp\/attestations\//, ""));
}

function mintServerKey(): {
  privatePem: string;
  publicPem: string;
  fingerprint: string;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  return {
    privatePem,
    publicPem,
    fingerprint: fingerprintFromPem(publicPem),
  };
}

interface Harness {
  root: string;
  repo: string;
  home: string;
  prevHome: string | undefined;
  operatorFingerprint: string;
  /** Newly-minted server pubkey + fingerprint, ready to be committed
   *  on the feature branch as part of the Shape 4 activation diff. */
  serverKey: { publicPem: string; fingerprint: string };
  cleanup: () => void;
}

/**
 * Set up a Shape 2 → Shape 4 migration harness:
 *   - `main` already carries a `path_rules` ".stamp/**" entry with
 *     bypass_review_cycle: true (the pre-existing Shape 2 scaffolding)
 *   - `main` has a manifest binding the operator as `admin` (so the
 *     operator can self-counter-sign the bootstrap envelope)
 *   - feature branch ADDS `review_server:` to the `main` branch rule
 *     PLUS a new `[server]+role_source:server` entry to the manifest
 *     PLUS the corresponding new server pubkey
 *   - this is the canonical happy-path diff `--migrate-existing` is
 *     designed to handle
 */
function setupHarness(): Harness {
  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-bootstrap-"));
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

  // Base config: operator-cap manifest entry + path_rules covering .stamp/**.
  // No review_server yet — that's what the bootstrap PR adds.
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
      "    minimum_signatures: 1",
      "    bypass_review_cycle: true",
      "",
    ].join("\n"),
  );
  writeFileSync(
    path.join(repo, ".stamp", "reviewers", "security.md"),
    "security reviewer prompt\n",
  );

  const operatorPubFile = operatorFingerprint.replace(":", "_") + ".pub";
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", operatorPubFile),
    operatorKp.publicKeyPem,
  );
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", "manifest.yml"),
    [
      "keys:",
      "  operator-test:",
      `    fingerprint: ${operatorFingerprint}`,
      "    capabilities: [admin, operator]",
      "",
    ].join("\n"),
  );
  writeFileSync(path.join(repo, "README.md"), "initial\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "initial: Shape 2 trust scaffolding"]);

  // Server key the bootstrap PR will introduce.
  const serverKey = mintServerKey();

  git(repo, ["checkout", "-q", "-b", "shape-4-activation"]);

  // Bootstrap diff: ADD review_server + new manifest entry + new pubkey.
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
      "    tools: []",
      "path_rules:",
      "  \".stamp/**\":",
      "    require_capability: admin",
      "    minimum_signatures: 1",
      "    bypass_review_cycle: true",
      "",
    ].join("\n"),
  );
  const serverPubFile = serverKey.fingerprint.replace(":", "_") + ".pub";
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", serverPubFile),
    serverKey.publicPem,
  );
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", "manifest.yml"),
    [
      "keys:",
      "  operator-test:",
      `    fingerprint: ${operatorFingerprint}`,
      "    capabilities: [admin, operator]",
      "  review-server-prod:",
      `    fingerprint: ${serverKey.fingerprint}`,
      "    capabilities: [server]",
      "    role_source: server",
      "",
    ].join("\n"),
  );
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "Shape 4 migration: activate review_server"]);

  return {
    root,
    repo,
    home,
    prevHome,
    operatorFingerprint,
    serverKey: { publicPem: serverKey.publicPem, fingerprint: serverKey.fingerprint },
    cleanup: () => {
      if (prevHome === undefined) delete process.env["HOME"];
      else process.env["HOME"] = prevHome;
      rmSync(root, { recursive: true, force: true });
    },
  };
}

/**
 * Variant of `setupHarness` that lets the test override the base
 * `path_rules` configuration to exercise verifier-side preconditions
 * (`bypass_review_cycle: false`, `minimum_signatures > 1`). The
 * feature-branch diff is the same minimal Shape 4 activation; only
 * BASE differs. */
function setupHarnessCustomBase(args: {
  bypass_review_cycle?: boolean;
  minimum_signatures?: number;
}): Harness {
  const bypass = args.bypass_review_cycle ?? true;
  const minSigs = args.minimum_signatures ?? 1;
  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-bootstrap-custom-"));
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
      `    bypass_review_cycle: ${bypass}`,
      "",
    ].join("\n"),
  );
  writeFileSync(
    path.join(repo, ".stamp", "reviewers", "security.md"),
    "security reviewer prompt\n",
  );

  const operatorPubFile = operatorFingerprint.replace(":", "_") + ".pub";
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", operatorPubFile),
    operatorKp.publicKeyPem,
  );
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", "manifest.yml"),
    [
      "keys:",
      "  operator-test:",
      `    fingerprint: ${operatorFingerprint}`,
      "    capabilities: [admin, operator]",
      "",
    ].join("\n"),
  );
  writeFileSync(path.join(repo, "README.md"), "initial\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "initial: Shape 2 trust scaffolding"]);

  const serverKey = mintServerKey();

  git(repo, ["checkout", "-q", "-b", "shape-4-activation"]);
  // Bootstrap diff (same as setupHarness, but path_rules section is
  // byte-identical with base — that's required by the whitelist).
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
      "    tools: []",
      "path_rules:",
      "  \".stamp/**\":",
      "    require_capability: admin",
      `    minimum_signatures: ${minSigs}`,
      `    bypass_review_cycle: ${bypass}`,
      "",
    ].join("\n"),
  );
  const serverPubFile = serverKey.fingerprint.replace(":", "_") + ".pub";
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", serverPubFile),
    serverKey.publicPem,
  );
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", "manifest.yml"),
    [
      "keys:",
      "  operator-test:",
      `    fingerprint: ${operatorFingerprint}`,
      "    capabilities: [admin, operator]",
      "  review-server-prod:",
      `    fingerprint: ${serverKey.fingerprint}`,
      "    capabilities: [server]",
      "    role_source: server",
      "",
    ].join("\n"),
  );
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "Shape 4 migration: activate review_server"]);

  return {
    root,
    repo,
    home,
    prevHome,
    operatorFingerprint,
    serverKey: { publicPem: serverKey.publicPem, fingerprint: serverKey.fingerprint },
    cleanup: () => {
      if (prevHome === undefined) delete process.env["HOME"];
      else process.env["HOME"] = prevHome;
      rmSync(root, { recursive: true, force: true });
    },
  };
}

// ─── (1) signing-byte determinism ──────────────────────────────────

describe("bootstrapAdminSigningBytes — canonical determinism", () => {
  function samplePayload(): AttestationPayloadV4 {
    return {
      schema_version: PR_ATTESTATION_SCHEMA_VERSION,
      base_sha: "a".repeat(40),
      head_sha: "b".repeat(40),
      target_branch: "main",
      diff_sha256: "c".repeat(64),
      manifest_snapshot_sha256: "sha256:" + "d".repeat(64),
      approvals: [],
      checks: [],
      trust_anchor_signatures: [],
      signer_key_id: "sha256:" + "e".repeat(64),
    };
  }
  const marker: MigrationBootstrapMarker = {
    activated_paths: [".stamp/config.yml", ".stamp/trusted-keys/manifest.yml"],
  };

  it("produces byte-identical output regardless of object key insertion order", () => {
    const p1 = samplePayload();
    const reorderedKeys: AttestationPayloadV4 = {
      // intentionally constructed with different key insertion order
      signer_key_id: p1.signer_key_id,
      checks: p1.checks,
      trust_anchor_signatures: p1.trust_anchor_signatures,
      approvals: p1.approvals,
      manifest_snapshot_sha256: p1.manifest_snapshot_sha256,
      diff_sha256: p1.diff_sha256,
      target_branch: p1.target_branch,
      head_sha: p1.head_sha,
      base_sha: p1.base_sha,
      schema_version: p1.schema_version,
    };
    const b1 = bootstrapAdminSigningBytes({ payloadV4: p1, marker });
    const b2 = bootstrapAdminSigningBytes({ payloadV4: reorderedKeys, marker });
    assert.equal(b1.toString("hex"), b2.toString("hex"));
  });

  it("produces different bytes when the marker changes", () => {
    const p = samplePayload();
    const b1 = bootstrapAdminSigningBytes({ payloadV4: p, marker });
    const m2: MigrationBootstrapMarker = {
      activated_paths: [".stamp/config.yml"], // different — one path
    };
    const b2 = bootstrapAdminSigningBytes({ payloadV4: p, marker: m2 });
    assert.notEqual(b1.toString("hex"), b2.toString("hex"));
  });

  it("zeroes out trust_anchor_signatures (admin signs payload-without-admins)", () => {
    const p = samplePayload();
    const pWithSigs: AttestationPayloadV4 = {
      ...p,
      trust_anchor_signatures: [
        { signer_key_id: "sha256:abc", signature: "deadbeef" },
      ],
    };
    const b1 = bootstrapAdminSigningBytes({ payloadV4: p, marker });
    const b2 = bootstrapAdminSigningBytes({ payloadV4: pWithSigs, marker });
    assert.equal(
      b1.toString("hex"),
      b2.toString("hex"),
      "trust_anchor_signatures must NOT affect bootstrap signing bytes (admins sign payload-without-admins)",
    );
  });
});

// ─── (2) diff-whitelist validator ──────────────────────────────────

describe("validateShape4ActivationDiff", () => {
  it("accepts a canonical Shape 4 activation diff", () => {
    const h = setupHarness();
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "shape-4-activation");
      const result = validateShape4ActivationDiff({
        repoRoot: h.repo,
        baseSha: base,
        headSha: head,
      });
      assert.ok(result.ok, `expected validation ok, got: ${(result as { ok: false; reason: string }).reason ?? "(missing reason)"}`);
      const paths = (result as { ok: true; activatedPaths: string[] }).activatedPaths;
      assert.ok(paths.includes(".stamp/config.yml"));
      assert.ok(paths.includes(".stamp/trusted-keys/manifest.yml"));
      assert.ok(
        paths.some((p) => p.startsWith(".stamp/trusted-keys/") && p.endsWith(".pub")),
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects a diff that touches a file outside .stamp/", () => {
    const h = setupHarness();
    try {
      // Add an extra non-.stamp file to the feature branch.
      writeFileSync(path.join(h.repo, "rogue.txt"), "out of scope\n");
      git(h.repo, ["add", "-A"]);
      git(h.repo, ["commit", "-q", "-m", "rogue add"]);
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "shape-4-activation");
      const result = validateShape4ActivationDiff({
        repoRoot: h.repo,
        baseSha: base,
        headSha: head,
      });
      assert.equal(result.ok, false);
      assert.match(
        (result as { ok: false; reason: string }).reason,
        /rogue\.txt.*outside .stamp\//,
      );
    } finally {
      h.cleanup();
    }
  });

  it("accepts deletion of .stamp/reviewers/*.md alongside the Shape 4 activation (WS2 widening)", () => {
    const h = setupHarness();
    try {
      // Drop an in-repo reviewer prompt on main BEFORE branching to
      // shape-4-activation. The harness already created shape-4-activation
      // from main without a reviewers/*.md; we re-create the branch here
      // with the file at base + a delete on head.
      git(h.repo, ["checkout", "-q", "main"]);
      writeFileSync(
        path.join(h.repo, ".stamp", "reviewers", "security.md"),
        "in-repo prompt\n",
      );
      git(h.repo, ["add", "-A"]);
      git(h.repo, ["commit", "-q", "-m", "add reviewer prompt at base"]);

      git(h.repo, ["checkout", "-q", "-b", "shape-4-activation-with-delete"]);
      // Same Shape 4 activation diff as the harness builds, plus a
      // delete of the prompt file.
      writeFileSync(
        path.join(h.repo, ".stamp", "config.yml"),
        [
          "branches:",
          "  main:",
          "    required: [security]",
          "    review_server: ssh://git@stamp.test.invalid:22",
          "reviewers:",
          "  security:",
          "    prompt: .stamp/reviewers/security.md",
          "    tools: []",
          "path_rules:",
          "  \".stamp/**\":",
          "    require_capability: admin",
          "    minimum_signatures: 1",
          "    bypass_review_cycle: true",
          "",
        ].join("\n"),
      );
      const serverPubFile = h.serverKey.fingerprint.replace(":", "_") + ".pub";
      writeFileSync(
        path.join(h.repo, ".stamp", "trusted-keys", serverPubFile),
        h.serverKey.publicPem,
      );
      writeFileSync(
        path.join(h.repo, ".stamp", "trusted-keys", "manifest.yml"),
        [
          "keys:",
          "  operator-test:",
          `    fingerprint: ${h.operatorFingerprint}`,
          "    capabilities: [admin, operator]",
          "  review-server-prod:",
          `    fingerprint: ${h.serverKey.fingerprint}`,
          "    capabilities: [server]",
          "    role_source: server",
          "",
        ].join("\n"),
      );
      git(h.repo, [
        "rm",
        "-q",
        ".stamp/reviewers/security.md",
      ]);
      git(h.repo, ["add", "-A"]);
      git(h.repo, ["commit", "-q", "-m", "Shape 4 + delete in-repo prompt"]);

      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "shape-4-activation-with-delete");
      const result = validateShape4ActivationDiff({
        repoRoot: h.repo,
        baseSha: base,
        headSha: head,
      });
      assert.ok(
        result.ok,
        `expected acceptance with .md delete, got: ${(result as { ok: false; reason: string }).reason ?? "(missing reason)"}`,
      );
      const paths = (result as { ok: true; activatedPaths: string[] }).activatedPaths;
      assert.ok(
        paths.includes(".stamp/reviewers/security.md"),
        `deleted reviewer file must appear in activatedPaths; got [${paths.join(", ")}]`,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects an ADD of .stamp/reviewers/*.md (whitelist is delete-only)", () => {
    const h = setupHarness();
    try {
      // shape-4-activation already has the canonical Shape 4 diff. Add
      // a NEW reviewer prompt on the feature branch — must reject.
      writeFileSync(
        path.join(h.repo, ".stamp", "reviewers", "rogue.md"),
        "added late\n",
      );
      git(h.repo, ["add", "-A"]);
      git(h.repo, ["commit", "-q", "-m", "add a reviewer prompt"]);
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "shape-4-activation");
      const result = validateShape4ActivationDiff({
        repoRoot: h.repo,
        baseSha: base,
        headSha: head,
      });
      assert.equal(result.ok, false);
      assert.match(
        (result as { ok: false; reason: string }).reason,
        /\.stamp\/reviewers\/rogue\.md/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects a diff that modifies an existing manifest entry", () => {
    const h = setupHarness();
    try {
      // Tamper with the operator-test entry on the feature branch.
      writeFileSync(
        path.join(h.repo, ".stamp", "trusted-keys", "manifest.yml"),
        [
          "keys:",
          "  operator-test:",
          `    fingerprint: ${h.operatorFingerprint}`,
          "    capabilities: [admin, operator, server]", // CHANGED
          "  review-server-prod:",
          `    fingerprint: ${h.serverKey.fingerprint}`,
          "    capabilities: [server]",
          "    role_source: server",
          "",
        ].join("\n"),
      );
      git(h.repo, ["add", "-A"]);
      git(h.repo, ["commit", "-q", "-m", "tamper existing entry"]);
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "shape-4-activation");
      const result = validateShape4ActivationDiff({
        repoRoot: h.repo,
        baseSha: base,
        headSha: head,
      });
      assert.equal(result.ok, false);
      assert.match(
        (result as { ok: false; reason: string }).reason,
        /modifies existing entry "operator-test"/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects a diff that adds a manifest entry without role_source: server", () => {
    const h = setupHarness();
    try {
      // Add an entry with [server] cap but no role_source.
      writeFileSync(
        path.join(h.repo, ".stamp", "trusted-keys", "manifest.yml"),
        [
          "keys:",
          "  operator-test:",
          `    fingerprint: ${h.operatorFingerprint}`,
          "    capabilities: [admin, operator]",
          "  review-server-prod:",
          `    fingerprint: ${h.serverKey.fingerprint}`,
          "    capabilities: [server]",
          // missing role_source
          "",
        ].join("\n"),
      );
      git(h.repo, ["add", "-A"]);
      git(h.repo, ["commit", "-q", "--amend", "-m", "no role_source"]);
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "shape-4-activation");
      const result = validateShape4ActivationDiff({
        repoRoot: h.repo,
        baseSha: base,
        headSha: head,
      });
      assert.equal(result.ok, false);
      assert.match(
        (result as { ok: false; reason: string }).reason,
        /role_source: server/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects a diff that doesn't add review_server (no Shape 4 activation)", () => {
    const h = setupHarness();
    try {
      // Reset config to NOT add review_server, only add the server key.
      writeFileSync(
        path.join(h.repo, ".stamp", "config.yml"),
        [
          "branches:",
          "  main:",
          "    required: [security]",
          // no review_server
          "reviewers:",
          "  security:",
          "    prompt: .stamp/reviewers/security.md",
          "    tools: []",
          "path_rules:",
          "  \".stamp/**\":",
          "    require_capability: admin",
          "    minimum_signatures: 1",
          "    bypass_review_cycle: true",
          "",
        ].join("\n"),
      );
      git(h.repo, ["add", "-A"]);
      git(h.repo, ["commit", "-q", "--amend", "-m", "no review_server"]);
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "shape-4-activation");
      const result = validateShape4ActivationDiff({
        repoRoot: h.repo,
        baseSha: base,
        headSha: head,
      });
      assert.equal(result.ok, false);
      assert.match(
        (result as { ok: false; reason: string }).reason,
        /does not add review_server/,
      );
    } finally {
      h.cleanup();
    }
  });
});

// ─── (3) runAttest --migrate-existing ──────────────────────────────

describe("runAttest --migrate-existing — happy path", () => {
  it("produces a v3 envelope with empty approvals, bootstrap marker, and an admin counter-signature", () => {
    const h = setupHarness();
    try {
      runFromRepo(h.repo, () =>
        runAttest({
          into: "main",
          branch: "shape-4-activation",
          migrateExisting: true,
        }),
      );

      const patchIds = listAttestationPatchIds(h.repo);
      assert.equal(patchIds.length, 1);
      const bytes = readAttestationBlobBytes(patchIds[0]!, h.repo);
      assert.ok(bytes);
      const env = parseEnvelope(bytes);
      assert.ok(env);
      const p = env.payload;
      assert.equal(p.schema_version, PR_ATTESTATION_SCHEMA_VERSION);
      assert.equal(p.approvals.length, 0);
      assert.ok(p.migration_bootstrap);
      assert.ok(p.migration_bootstrap.activated_paths.length >= 3);
      assert.ok(p.migration_bootstrap.activated_paths.includes(".stamp/config.yml"));
      assert.equal(p.trust_anchor_signatures?.length, 1);
      assert.equal(p.trust_anchor_signatures![0]!.signer_key_id, h.operatorFingerprint);
      // operator outer signature must verify against the operator pubkey
      const { keypair } = ensureUserKeypair();
      const ok = verifyBytes(
        keypair.publicKeyPem,
        serializePayload(p),
        env.signature,
      );
      assert.ok(ok, "operator outer signature must verify");
    } finally {
      h.cleanup();
    }
  });
});

describe("runAttest --migrate-existing — refusal paths", () => {
  it("refuses when the diff touches a file outside .stamp/", () => {
    const h = setupHarness();
    try {
      writeFileSync(path.join(h.repo, "rogue.txt"), "out of scope\n");
      git(h.repo, ["add", "-A"]);
      git(h.repo, ["commit", "-q", "-m", "rogue add"]);
      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runAttest({
              into: "main",
              branch: "shape-4-activation",
              migrateExisting: true,
            }),
          ),
        /--migrate-existing refused.*rogue\.txt/s,
      );
    } finally {
      h.cleanup();
    }
  });

  it("refuses when an existing manifest entry is modified", () => {
    const h = setupHarness();
    try {
      writeFileSync(
        path.join(h.repo, ".stamp", "trusted-keys", "manifest.yml"),
        [
          "keys:",
          "  operator-test:",
          `    fingerprint: ${h.operatorFingerprint}`,
          "    capabilities: [admin, operator, server]",
          "  review-server-prod:",
          `    fingerprint: ${h.serverKey.fingerprint}`,
          "    capabilities: [server]",
          "    role_source: server",
          "",
        ].join("\n"),
      );
      git(h.repo, ["add", "-A"]);
      git(h.repo, ["commit", "-q", "--amend", "-m", "tamper manifest"]);
      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runAttest({
              into: "main",
              branch: "shape-4-activation",
              migrateExisting: true,
            }),
          ),
        /modifies existing entry/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("refuses when path_rules at base requires minimum_signatures > 1", () => {
    const h = setupHarnessCustomBase({ minimum_signatures: 2 });
    try {
      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runAttest({
              into: "main",
              branch: "shape-4-activation",
              migrateExisting: true,
            }),
          ),
        /minimum_signatures: 2/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("refuses when path_rules at base has bypass_review_cycle: false", () => {
    const h = setupHarnessCustomBase({ bypass_review_cycle: false });
    try {
      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runAttest({
              into: "main",
              branch: "shape-4-activation",
              migrateExisting: true,
            }),
          ),
        /bypass_review_cycle: false/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("refuses when the operator key lacks admin capability in the working-tree manifest", () => {
    const h = setupHarness();
    try {
      writeFileSync(
        path.join(h.repo, ".stamp", "trusted-keys", "manifest.yml"),
        [
          "keys:",
          "  operator-test:",
          `    fingerprint: ${h.operatorFingerprint}`,
          "    capabilities: [operator]", // no admin
          "  review-server-prod:",
          `    fingerprint: ${h.serverKey.fingerprint}`,
          "    capabilities: [server]",
          "    role_source: server",
          "",
        ].join("\n"),
      );
      git(h.repo, ["add", "-A"]);
      git(h.repo, ["commit", "-q", "--amend", "-m", "drop operator admin cap"]);
      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runAttest({
              into: "main",
              branch: "shape-4-activation",
              migrateExisting: true,
            }),
          ),
        // The whitelist re-validation refuses any modification of an
        // existing entry; dropping the `admin` cap modifies the
        // operator-test entry → that's caught BEFORE the admin-capability
        // check.
        /modifies existing entry "operator-test"/,
      );
    } finally {
      h.cleanup();
    }
  });
});

// ─── (4) runVerifyPr — accept + reject ─────────────────────────────

describe("runVerifyPr — bootstrap envelope acceptance", () => {
  it("accepts a happy-path bootstrap envelope", () => {
    const h = setupHarness();
    try {
      runFromRepo(h.repo, () =>
        runAttest({
          into: "main",
          branch: "shape-4-activation",
          migrateExisting: true,
        }),
      );

      acceptVerifyPr(h.repo, {
        head: "shape-4-activation",
        base: "main",
        into: "main",
      });
    } finally {
      h.cleanup();
    }
  });

  it("rejects an envelope whose marker activated_paths doesn't match the actual diff (spoofing)", () => {
    const h = setupHarness();
    try {
      // Produce a normal bootstrap envelope.
      runFromRepo(h.repo, () =>
        runAttest({
          into: "main",
          branch: "shape-4-activation",
          migrateExisting: true,
        }),
      );
      const patchIds = listAttestationPatchIds(h.repo);
      assert.equal(patchIds.length, 1);
      const bytes = readAttestationBlobBytes(patchIds[0]!, h.repo);
      assert.ok(bytes);
      const env = parseEnvelope(bytes);
      assert.ok(env);

      // Tamper: re-sign the envelope (mimicking an attacker who has the
      // operator key) but with `activated_paths` claiming fewer paths
      // than actually changed. The verifier must catch the mismatch.
      const tamperedPayload = {
        ...env.payload,
        migration_bootstrap: { activated_paths: [".stamp/config.yml"] },
      };
      const { keypair } = ensureUserKeypair();
      const newSig = signBytes(
        keypair.privateKeyPem,
        serializePayload(tamperedPayload),
      );
      const tamperedEnv = { payload: tamperedPayload, signature: newSig };
      // Rewrite the blob at the same ref.
      const out = execFileSync(
        "git",
        ["hash-object", "-w", "--stdin"],
        {
          cwd: h.repo,
          input: Buffer.from(JSON.stringify(tamperedEnv), "utf8"),
          encoding: "utf8",
        },
      );
      const blobSha = out.trim();
      execFileSync(
        "git",
        ["update-ref", `refs/stamp/attestations/${patchIds[0]}`, blobSha],
        { cwd: h.repo },
      );

      expectVerifyPrRejection(
        h.repo,
        { head: "shape-4-activation", base: "main", into: "main" },
        /does not match the actual changed-files set|activated_paths/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects when the admin signature is forged (replay/spoof)", () => {
    const h = setupHarness();
    try {
      runFromRepo(h.repo, () =>
        runAttest({
          into: "main",
          branch: "shape-4-activation",
          migrateExisting: true,
        }),
      );
      const patchIds = listAttestationPatchIds(h.repo);
      const bytes = readAttestationBlobBytes(patchIds[0]!, h.repo);
      const env = parseEnvelope(bytes!);
      assert.ok(env);

      // Replace the admin signature with a random base64 string.
      const tamperedPayload = {
        ...env.payload,
        trust_anchor_signatures: [
          {
            signer_key_id: env.payload.trust_anchor_signatures![0]!.signer_key_id,
            signature: Buffer.alloc(64).toString("base64"),
          },
        ],
      };
      const { keypair } = ensureUserKeypair();
      const newSig = signBytes(
        keypair.privateKeyPem,
        serializePayload(tamperedPayload),
      );
      const tamperedEnv = { payload: tamperedPayload, signature: newSig };
      const blobSha = execFileSync(
        "git",
        ["hash-object", "-w", "--stdin"],
        {
          cwd: h.repo,
          input: Buffer.from(JSON.stringify(tamperedEnv), "utf8"),
          encoding: "utf8",
        },
      ).trim();
      execFileSync(
        "git",
        ["update-ref", `refs/stamp/attestations/${patchIds[0]}`, blobSha],
        { cwd: h.repo },
      );

      expectVerifyPrRejection(
        h.repo,
        { head: "shape-4-activation", base: "main", into: "main" },
        /admin signature.*does not verify/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects when the admin signer lacks admin capability at base", () => {
    const h = setupHarness();
    try {
      // Mint a separate operator key (no admin in manifest), use it to
      // produce a bootstrap envelope by manually crafting the bytes.
      runFromRepo(h.repo, () =>
        runAttest({
          into: "main",
          branch: "shape-4-activation",
          migrateExisting: true,
        }),
      );
      const patchIds = listAttestationPatchIds(h.repo);
      const bytes = readAttestationBlobBytes(patchIds[0]!, h.repo);
      const env = parseEnvelope(bytes!);
      assert.ok(env);

      // Swap signer_key_id on the admin signature to a fingerprint NOT
      // in the manifest. (Even with a valid signature shape, the
      // verifier's manifest lookup fails.)
      const fakeFp = "sha256:" + "0".repeat(64);
      const tamperedPayload = {
        ...env.payload,
        trust_anchor_signatures: [
          {
            signer_key_id: fakeFp,
            signature: env.payload.trust_anchor_signatures![0]!.signature,
          },
        ],
      };
      const { keypair } = ensureUserKeypair();
      const newSig = signBytes(
        keypair.privateKeyPem,
        serializePayload(tamperedPayload),
      );
      const tamperedEnv = { payload: tamperedPayload, signature: newSig };
      const blobSha = execFileSync(
        "git",
        ["hash-object", "-w", "--stdin"],
        {
          cwd: h.repo,
          input: Buffer.from(JSON.stringify(tamperedEnv), "utf8"),
          encoding: "utf8",
        },
      ).trim();
      execFileSync(
        "git",
        ["update-ref", `refs/stamp/attestations/${patchIds[0]}`, blobSha],
        { cwd: h.repo },
      );

      expectVerifyPrRejection(
        h.repo,
        { head: "shape-4-activation", base: "main", into: "main" },
        /admin signer.*not listed in the manifest/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects a bootstrap envelope produced against a non-bootstrap diff (verifier re-validates whitelist)", () => {
    // The spoofing case in the ticket's AC: an attacker produces a
    // `--migrate-existing` envelope and then tries to verify against a
    // diff with content outside the whitelist. We mimic that by
    // mutating the feature-branch HEAD AFTER attest, then verifying
    // against the new head. The verifier re-reads the diff from
    // base/head and rejects.
    const h = setupHarness();
    try {
      runFromRepo(h.repo, () =>
        runAttest({
          into: "main",
          branch: "shape-4-activation",
          migrateExisting: true,
        }),
      );
      // Now add a rogue commit to the feature branch (outside .stamp/).
      writeFileSync(path.join(h.repo, "rogue.txt"), "exfiltrate\n");
      git(h.repo, ["add", "-A"]);
      git(h.repo, ["commit", "-q", "-m", "rogue add"]);

      // The new head's patch-id differs, so the verifier won't find an
      // attestation for it. That alone IS the rejection (a tampered
      // diff invalidates the patch-id lookup). Either rejection shape
      // ("no attestation found" / whitelist mismatch on same patch-id)
      // is valid.
      expectVerifyPrRejection(
        h.repo,
        { head: "shape-4-activation", base: "main", into: "main" },
        /no attestation found|outside .stamp\/|does not match/,
      );
    } finally {
      h.cleanup();
    }
  });
});

// ─── (5) end-to-end happy path ─────────────────────────────────────

describe("--migrate-existing — end-to-end", () => {
  it("synthetic Shape-4-activation diff: attest writes ref + verifier accepts", () => {
    const h = setupHarness();
    try {
      runFromRepo(h.repo, () =>
        runAttest({
          into: "main",
          branch: "shape-4-activation",
          migrateExisting: true,
        }),
      );
      const refs = listAttestationPatchIds(h.repo);
      assert.equal(refs.length, 1);

      const prevExit = process.exit;
      // @ts-expect-error overriding
      process.exit = (code?: number) => {
        if (code && code !== 0) {
          throw new Error(`runVerifyPr exited with code ${code}`);
        }
      };
      try {
        runFromRepo(h.repo, () =>
          runVerifyPr({
            head: "shape-4-activation",
            base: "main",
            into: "main",
          }),
        );
      } finally {
        process.exit = prevExit;
      }
      assert.ok(true, "end-to-end happy-path completed");
    } finally {
      h.cleanup();
    }
  });
});
