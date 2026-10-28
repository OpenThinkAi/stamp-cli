/**
 * AGT-2272: server-signed approvals are bound to the repo they were
 * reviewed for.
 *
 * Unit tests cover the binding rules in `src/lib/repoBinding.ts`. The
 * end-to-end block bundles the real pre-receive hook (the same way the
 * production build does), installs it in a scratch bare repo, and pushes
 * v4 merge commits whose server-signed approval carries various
 * `repo_id`s — so the assertions are about what a stamp server actually
 * accepts, not about one phase function in isolation.
 */

import { strict as assert } from "node:assert";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { buildSync } from "esbuild";

import {
  canonicalSerializeApproval,
  CURRENT_V4_SCHEMA_VERSION,
  formatTrailers,
  canonicalSerializePayload,
  type ApprovalV4,
  type AttestationPayloadV4,
} from "../src/lib/attestationV4.ts";
import { parseConfigFromYaml } from "../src/lib/config.ts";
import { fingerprintFromPem } from "../src/lib/keys.ts";
import {
  checkApprovalRepoId,
  formatRepoId,
  isWellFormedRepoId,
  repoIdRawFromConfigYaml,
  resolveRepoBinding,
  UNBOUND,
} from "../src/lib/repoBinding.ts";
import { signBytes } from "../src/lib/signing.ts";
import { parseManifest, snapshotSha256 } from "../src/lib/trustedKeysManifest.ts";

// ─── Unit: binding rules ────────────────────────────────────────────

describe("repoBinding — resolveRepoBinding / checkApprovalRepoId", () => {
  it("is unbound when no consulted config declares repo_id", () => {
    const b = resolveRepoBinding([
      { where: "tip", raw: undefined },
      { where: "base", raw: null },
    ]);
    assert.deepEqual(b, UNBOUND);
    assert.deepEqual(checkApprovalRepoId(undefined, b), { ok: true });
    assert.deepEqual(checkApprovalRepoId("any/repo", b), { ok: true });
  });

  it("binds to the declared id and prefers the tip's declaration", () => {
    const b = resolveRepoBinding([
      { where: "tip", raw: "acme/widget-v2" },
      { where: "base", raw: "acme/widget" },
    ]);
    assert.equal(b.kind, "bound");
    if (b.kind !== "bound") return;
    assert.equal(b.preferred, "acme/widget-v2");
    assert.deepEqual(b.accepted, ["acme/widget-v2", "acme/widget"]);
    assert.equal(checkApprovalRepoId("acme/widget", b).ok, true);
    assert.equal(checkApprovalRepoId("acme/widget-v2", b).ok, true);
  });

  it("binds when only the tip declares (fork point predates the declaration)", () => {
    const b = resolveRepoBinding([
      { where: "tip", raw: "acme/widget" },
      { where: "base", raw: undefined },
    ]);
    assert.equal(b.kind, "bound");
    assert.equal(checkApprovalRepoId(undefined, b).ok, false);
  });

  it("refuses an approval signed for another repo", () => {
    const b = resolveRepoBinding([{ where: "base", raw: "acme/prod" }]);
    const r = checkApprovalRepoId("acme/sandbox", b);
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /server-signed for repo "acme\/sandbox"/);
  });

  it("refuses an approval with no repo_id when the repo is bound (no downgrade)", () => {
    const b = resolveRepoBinding([{ where: "base", raw: "acme/prod" }]);
    const r = checkApprovalRepoId(undefined, b);
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /carries no server-signed repo_id/);
  });

  it("compares case-sensitively (the server's override lookup is case-sensitive)", () => {
    const b = resolveRepoBinding([{ where: "base", raw: "Acme/Prod" }]);
    assert.equal(checkApprovalRepoId("acme/prod", b).ok, false);
    assert.equal(checkApprovalRepoId("Acme/Prod", b).ok, true);
  });

  it("refuses a non-string repo_id", () => {
    const b = resolveRepoBinding([{ where: "base", raw: "acme/prod" }]);
    assert.equal(checkApprovalRepoId(42, b).ok, false);
  });

  it("fails closed on a malformed declaration", () => {
    for (const raw of ["acme", "acme/prod/extra", "acme/", 7, ["acme/prod"], "../x/y"]) {
      const b = resolveRepoBinding([
        { where: "tip", raw },
        { where: "base", raw: "acme/prod" },
      ]);
      assert.equal(b.kind, "invalid", `expected invalid for ${JSON.stringify(raw)}`);
      assert.equal(checkApprovalRepoId("acme/prod", b).ok, false);
    }
  });

  it("well-formedness mirrors the stamp-review --org/--repo slug shape", () => {
    assert.equal(isWellFormedRepoId("acme/widget-co"), true);
    assert.equal(isWellFormedRepoId("git/stamp-cli"), true);
    assert.equal(isWellFormedRepoId("-x/y"), false);
    assert.equal(formatRepoId("acme", "widget"), "acme/widget");
  });

  it("repoIdRawFromConfigYaml reads the top-level key and tolerates absent/garbage config", () => {
    assert.equal(repoIdRawFromConfigYaml("repo_id: acme/w\nbranches: {}\n"), "acme/w");
    assert.equal(repoIdRawFromConfigYaml("branches: {}\n"), undefined);
    assert.equal(repoIdRawFromConfigYaml(null), undefined);
    assert.equal(repoIdRawFromConfigYaml(": : :\n  - ["), undefined);
  });

  it("config parser accepts a well-formed repo_id and rejects a malformed one", () => {
    const base = "branches:\n  main:\n    required: []\nreviewers: {}\n";
    assert.equal(parseConfigFromYaml(`repo_id: acme/widget\n${base}`).repo_id, "acme/widget");
    assert.equal(parseConfigFromYaml(base).repo_id, undefined);
    assert.throws(() => parseConfigFromYaml(`repo_id: acme\n${base}`), /repo_id must be/);
  });
});

// ─── End to end: the bundled pre-receive hook ───────────────────────

const HERE = path.dirname(fileURLToPath(import.meta.url));
const HOOK_SRC = path.join(HERE, "..", "src", "hooks", "pre-receive.ts");
const PROMPT = "prompt\n";

interface Key {
  privatePem: string;
  publicPem: string;
  fingerprint: string;
}

function genKey(): Key {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  return {
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicPem,
    fingerprint: fingerprintFromPem(publicPem),
  };
}

function git(cwd: string, args: string[]): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

function sha256Hex(s: string): string {
  return createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex");
}

function configYaml(repoId: string | undefined): string {
  return [
    ...(repoId !== undefined ? [`repo_id: ${repoId}`] : []),
    "branches:",
    "  main:",
    "    required: [security]",
    "reviewers:",
    "  security:",
    "    prompt: .stamp/reviewers/security.md",
    "",
  ].join("\n");
}

let hookBundle: string;
const roots: string[] = [];

/**
 * A bare "server" repo with the hook installed, seeded (before the hook
 * goes in) with one commit declaring `baseRepoId`, then optionally a
 * second main commit declaring `tipRepoId`. The feature branch forks
 * from the FIRST commit, so its merge base carries `baseRepoId` and the
 * pre-push tip carries `tipRepoId` (when set).
 */
function setupServer(opts: { baseRepoId?: string; tipRepoId?: string }) {
  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-repo-binding-"));
  roots.push(root);
  const bare = path.join(root, "server.git");
  const work = path.join(root, "work");
  const serverKey = genKey();
  const operatorKey = genKey();

  git(root, ["init", "-q", "--bare", "-b", "main", bare]);
  git(root, ["clone", "-q", bare, work]);
  git(work, ["config", "user.name", "Test"]);
  git(work, ["config", "user.email", "test@example.invalid"]);
  git(work, ["config", "commit.gpgsign", "false"]);
  git(work, ["checkout", "-q", "-b", "main"]);

  mkdirSync(path.join(work, ".stamp", "reviewers"), { recursive: true });
  mkdirSync(path.join(work, ".stamp", "trusted-keys"), { recursive: true });
  writeFileSync(path.join(work, ".stamp", "reviewers", "security.md"), PROMPT);
  writeFileSync(path.join(work, ".stamp", "config.yml"), configYaml(opts.baseRepoId));
  for (const k of [serverKey, operatorKey]) {
    writeFileSync(
      path.join(work, ".stamp", "trusted-keys", k.fingerprint.replace(":", "_") + ".pub"),
      k.publicPem,
    );
  }
  writeFileSync(
    path.join(work, ".stamp", "trusted-keys", "manifest.yml"),
    [
      "keys:",
      "  review-server:",
      `    fingerprint: ${serverKey.fingerprint}`,
      "    capabilities: [server]",
      "  operator:",
      `    fingerprint: ${operatorKey.fingerprint}`,
      "    capabilities: [operator]",
      "",
    ].join("\n"),
  );
  git(work, ["add", "-A"]);
  git(work, ["commit", "-q", "-m", "seed"]);
  const forkPoint = git(work, ["rev-parse", "HEAD"]).trim();

  if (opts.tipRepoId !== undefined) {
    writeFileSync(path.join(work, ".stamp", "config.yml"), configYaml(opts.tipRepoId));
    git(work, ["commit", "-q", "-am", "declare repo_id"]);
  }
  git(work, ["push", "-q", "origin", "main"]);

  const hookPath = path.join(bare, "hooks", "pre-receive");
  writeFileSync(hookPath, hookBundle);
  chmodSync(hookPath, 0o755);

  git(work, ["checkout", "-q", "-b", "feature", forkPoint]);
  writeFileSync(path.join(work, "feature.txt"), "hello\n");
  git(work, ["add", "-A"]);
  git(work, ["commit", "-q", "-m", "add feature"]);
  const headSha = git(work, ["rev-parse", "HEAD"]).trim();
  git(work, ["checkout", "-q", "main"]);
  const baseSha = git(work, ["merge-base", "main", "feature"]).trim();

  /** Merge `feature` with a v4 envelope whose single approval carries
   *  `approvalRepoId` (omitted when undefined), then push main. */
  function pushMerge(approvalRepoId: string | undefined): { status: number | null; stderr: string } {
    const diffText = git(work, ["diff", `${baseSha}...${headSha}`]);
    const diffSha256 = sha256Hex(diffText);
    const manifest = parseManifest(
      git(work, ["show", `${baseSha}:.stamp/trusted-keys/manifest.yml`]),
    );
    assert.ok(manifest);
    const approval: ApprovalV4 = {
      reviewer: "security",
      verdict: "approved",
      prompt_sha256: sha256Hex(PROMPT),
      diff_sha256: diffSha256,
      base_sha: baseSha,
      head_sha: headSha,
      issued_at: "2026-10-28T00:00:00Z",
      server_key_id: serverKey.fingerprint,
      ...(approvalRepoId !== undefined ? { repo_id: approvalRepoId } : {}),
    };
    const payload: AttestationPayloadV4 = {
      schema_version: CURRENT_V4_SCHEMA_VERSION,
      base_sha: baseSha,
      head_sha: headSha,
      target_branch: "main",
      diff_sha256: diffSha256,
      manifest_snapshot_sha256: snapshotSha256(manifest),
      approvals: [
        {
          approval,
          server_attestation: {
            server_key_id: serverKey.fingerprint,
            signature: signBytes(serverKey.privatePem, canonicalSerializeApproval(approval)),
          },
        },
      ],
      checks: [],
      trust_anchor_signatures: [],
      signer_key_id: operatorKey.fingerprint,
    };
    const outer = signBytes(operatorKey.privatePem, canonicalSerializePayload(payload));
    git(work, [
      "merge",
      "-q",
      "--no-ff",
      "feature",
      "-m",
      `Merge feature into main\n\n${formatTrailers(payload, outer)}`,
    ]);
    const r = spawnSync("git", ["push", "origin", "main"], { cwd: work, encoding: "utf8" });
    return { status: r.status, stderr: r.stderr };
  }

  return { pushMerge };
}

describe("pre-receive hook — repo binding end to end (AGT-2272)", () => {
  before(() => {
    const out = buildSync({
      entryPoints: [HOOK_SRC],
      bundle: true,
      platform: "node",
      format: "cjs",
      target: "node22",
      write: false,
      banner: { js: "#!/usr/bin/env node" },
      logLevel: "silent",
    });
    hookBundle = out.outputFiles[0]!.text;
  });

  after(() => {
    for (const r of roots) rmSync(r, { recursive: true, force: true });
  });

  it("accepts an approval signed for this repo's declared id", () => {
    const s = setupServer({ baseRepoId: "acme/prod" });
    const r = s.pushMerge("acme/prod");
    assert.equal(r.status, 0, r.stderr);
  });

  it("rejects an approval minted for another repo (lenient override substitution)", () => {
    const s = setupServer({ baseRepoId: "acme/prod" });
    const r = s.pushMerge("acme/sandbox");
    assert.notEqual(r.status, 0, r.stderr);
    assert.match(r.stderr, /server-signed for repo "acme\/sandbox"/);
    assert.match(r.stderr, /declares repo_id "acme\/prod"/);
  });

  it("rejects an unbound approval once the repo declares its id (no downgrade)", () => {
    const s = setupServer({ baseRepoId: "acme/prod" });
    const r = s.pushMerge(undefined);
    assert.notEqual(r.status, 0, r.stderr);
    assert.match(r.stderr, /carries no server-signed repo_id/);
  });

  it("enforces the tip's declaration even when the branch forked before it", () => {
    const s = setupServer({ tipRepoId: "acme/prod" });
    const r = s.pushMerge("acme/sandbox");
    assert.notEqual(r.status, 0, r.stderr);
    assert.match(r.stderr, /server-signed for repo "acme\/sandbox"/);
  });

  it("keeps verifying unbound approvals in repos that declare no id (old envelopes)", () => {
    const s = setupServer({});
    const r = s.pushMerge(undefined);
    assert.equal(r.status, 0, r.stderr);
  });

  it("accepts a bound approval in a repo that declares no id (server upgraded first)", () => {
    const s = setupServer({});
    const r = s.pushMerge("git/whatever");
    assert.equal(r.status, 0, r.stderr);
  });
});
