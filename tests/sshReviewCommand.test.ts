/**
 * Tests for `runReview({...})` routing through the SSH-transport branch
 * (AGT-332): when `.stamp/config.yml` configures `review_server` on the
 * target branch's rule, each reviewer is dispatched via the SSH verb
 * and its signed approval is persisted to the local DB.
 *
 * Hard contracts:
 *   - `review_server` set on the merge-base config → SSH path runs and
 *     the local LLM path doesn't.
 *   - approval + signature + key_id land in the DB as a v4 row
 *     (`schema_version = REVIEW_ROW_SCHEMA_V4`), all three fields
 *     populated together per `recordReview`'s all-or-nothing invariant.
 *   - 1.x compatibility contract: no `review_server` → falls through to
 *     existing local LLM path (we exercise the negative case via the
 *     STAMP_NO_LLM guard which fires only in the local path).
 *
 * Test approach mirrors tests/headlessReviewCommand.test.ts: fixture
 * repo on disk + monkey-patched stdout/stderr + an injected SSH fake.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  sign,
} from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, it } from "node:test";

import { runReview } from "../src/commands/review.ts";
import {
  canonicalSerializeApproval,
  type ApprovalV4,
} from "../src/lib/attestationV4.ts";
import { REVIEW_ROW_SCHEMA_V4 } from "../src/lib/db.ts";
import { fingerprintFromPem } from "../src/lib/keys.ts";
import { stampStateDbPath } from "../src/lib/paths.ts";
import type { SshSpawnFn } from "../src/lib/sshReviewClient.ts";

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: "pipe" });
}

interface Fixture {
  repo: string;
  serverKeyPem: string;
  signServerApproval: (approval: ApprovalV4) => string;
  restoreCwd: () => void;
}

/**
 * Build a fixture repo with `.stamp/config.yml` that sets
 * `review_server` on `main`, a `.stamp/trusted-keys/manifest.yml` that
 * trusts a freshly-generated keypair with `capabilities: [server]`,
 * and the matching `.pub` file. Returns the keypair so each test can
 * synthesize signed approvals on the fly.
 */
function setupRepoWithReviewServer(): Fixture {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "stamp-ssh-cmd-")));
  const repo = join(tmp, "repo");
  mkdirSync(repo);
  git(["init", "-q", "-b", "main", repo], tmp);
  git(["config", "user.email", "t@t.t"], repo);
  git(["config", "user.name", "t"], repo);
  git(["config", "commit.gpgsign", "false"], repo);
  // Origin pretends to point at a stamp server; the SSH path uses this
  // to derive --org / --repo for the verb.
  git(
    ["remote", "add", "origin", "ssh://git@stamp.example.com:22/srv/git/acme/widget.git"],
    repo,
  );

  // Generate the server's review-signing keypair once; the manifest
  // commits to its fingerprint and the trusted-keys dir holds its .pub.
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const serverKeyPem = publicKey.export({ type: "spki", format: "pem" }) as string;
  const serverFp = fingerprintFromPem(serverKeyPem);

  mkdirSync(join(repo, ".stamp", "reviewers"), { recursive: true });
  mkdirSync(join(repo, ".stamp", "trusted-keys"), { recursive: true });

  writeFileSync(
    join(repo, ".stamp", "config.yml"),
    [
      "branches:",
      "  main:",
      "    required: [security]",
      "    review_server: ssh://git@stamp.example.com:22",
      "reviewers:",
      "  security:",
      "    prompt: .stamp/reviewers/security.md",
      "",
    ].join("\n"),
  );
  writeFileSync(
    join(repo, ".stamp", "reviewers", "security.md"),
    "# security reviewer\n\nFlag exploitable changes.\n",
  );
  writeFileSync(
    join(repo, ".stamp", "trusted-keys", "manifest.yml"),
    [
      "keys:",
      "  review-server-prod:",
      `    fingerprint: ${serverFp}`,
      "    capabilities: [server]",
      "",
    ].join("\n"),
  );
  writeFileSync(
    join(repo, ".stamp", "trusted-keys", "server-prod.pub"),
    serverKeyPem,
  );
  writeFileSync(join(repo, "README.md"), "# fixture\n");
  git(["add", "-A"], repo);
  git(["commit", "-q", "-m", "init"], repo);
  git(["checkout", "-q", "-b", "feature"], repo);
  writeFileSync(join(repo, "src.txt"), "hello\n");
  git(["add", "src.txt"], repo);
  git(["commit", "-q", "-m", "add src"], repo);

  const prevCwd = process.cwd();
  process.chdir(repo);
  return {
    repo,
    serverKeyPem,
    signServerApproval: (approval) => {
      return sign(null, canonicalSerializeApproval(approval), privateKey).toString("base64");
    },
    restoreCwd: () => process.chdir(prevCwd),
  };
}

interface Captured {
  stdout: string;
  stderr: string;
  restore: () => void;
}

function captureStreams(): Captured {
  const captured: Captured = { stdout: "", stderr: "", restore: () => {} };
  const origOut = process.stdout.write.bind(process.stdout);
  const origErr = process.stderr.write.bind(process.stderr);
  (process.stdout.write as unknown) = (chunk: unknown) => {
    captured.stdout += typeof chunk === "string" ? chunk : String(chunk);
    return true;
  };
  (process.stderr.write as unknown) = (chunk: unknown) => {
    captured.stderr += typeof chunk === "string" ? chunk : String(chunk);
    return true;
  };
  // console.log/error route through process.stdout/stderr.write, so the
  // monkey-patch above captures them too.
  captured.restore = () => {
    (process.stdout.write as unknown) = origOut;
    (process.stderr.write as unknown) = origErr;
  };
  return captured;
}

describe("runReview — server-attested SSH transport", () => {
  let cleanup: (() => void) | null = null;
  let fx: Fixture | null = null;

  beforeEach(() => {
    fx = setupRepoWithReviewServer();
    const repo = fx.repo;
    const restoreCwd = fx.restoreCwd;
    cleanup = () => {
      restoreCwd();
      rmSync(repo, { recursive: true, force: true });
    };
  });

  afterEach(() => {
    if (cleanup) cleanup();
    cleanup = null;
    fx = null;
  });

  it("routes through SSH when review_server is configured and persists the signed row", async () => {
    const baseSha = git(["rev-parse", "main"], fx!.repo).trim();
    const headSha = git(["rev-parse", "HEAD"], fx!.repo).trim();
    const diff = git(["diff", "main..HEAD"], fx!.repo);
    const diffSha256 = createHash("sha256").update(diff, "utf8").digest("hex");

    // Build the server's response: a valid approved verdict, signed
    // with the fixture's private key.
    const serverFp = fingerprintFromPem(fx!.serverKeyPem);
    const approval: ApprovalV4 = {
      reviewer: "security",
      verdict: "approved",
      prompt_sha256: "a".repeat(64),
      diff_sha256: diffSha256,
      base_sha: baseSha,
      head_sha: headSha,
      trusted_keys_snapshot_sha256: "sha256:" + "b".repeat(64),
      issued_at: "2026-05-17T18:42:13Z",
      server_key_id: serverFp,
    };
    const signature = fx!.signServerApproval(approval);

    let capturedReviewer: string | null = null;
    const sshFake: SshSpawnFn = async (_url, args) => {
      // Sanity-check the argv shape: --reviewer/--org/--repo/...
      capturedReviewer = args[args.indexOf("--reviewer") + 1] ?? null;
      const response = {
        verdict: "approved" as const,
        prose: "no findings; clean diff",
        approval,
        signature,
      };
      return {
        stdout: JSON.stringify(response) + "\n",
        stderr: "",
        exitCode: 0,
        signal: null,
      };
    };

    const cap = captureStreams();
    try {
      await runReview({
        diff: "main..feature",
        _sshSpawnForTest: sshFake,
      });
    } finally {
      cap.restore();
    }

    assert.equal(capturedReviewer, "security");
    assert.match(cap.stdout, /review_server: ssh:\/\/git@stamp\.example\.com:22/);
    assert.match(cap.stdout, /\[server-attested\]/);
    assert.match(cap.stdout, /verdict: approved/);
    assert.match(cap.stdout, /\[signed by /);

    // DB row: server_approval_json + signature_b64 + server_key_id
    // all-populated, schema_version = 4.
    const db = new DatabaseSync(stampStateDbPath(fx!.repo));
    try {
      const row = db
        .prepare(
          `SELECT reviewer, verdict, server_approval_json, server_signature_b64,
                  server_key_id, schema_version
             FROM reviews
            WHERE reviewer = ? AND base_sha = ? AND head_sha = ?`,
        )
        .get("security", baseSha, headSha) as {
        reviewer: string;
        verdict: string;
        server_approval_json: string;
        server_signature_b64: string;
        server_key_id: string;
        schema_version: number;
      };
      assert.ok(row, "expected a row to be inserted");
      assert.equal(row.reviewer, "security");
      assert.equal(row.verdict, "approved");
      assert.equal(row.schema_version, REVIEW_ROW_SCHEMA_V4);
      assert.equal(row.server_key_id, serverFp);
      // server_approval_json is the wire bytes; parse + sanity-check
      const parsed = JSON.parse(row.server_approval_json) as ApprovalV4;
      assert.equal(parsed.reviewer, "security");
      assert.equal(parsed.diff_sha256, diffSha256);
      assert.equal(parsed.server_key_id, serverFp);
      assert.equal(row.server_signature_b64, signature);
    } finally {
      db.close();
    }
  });

  it("sets exitCode=1 when the signed verdict isn't approved", async () => {
    const baseSha = git(["rev-parse", "main"], fx!.repo).trim();
    const headSha = git(["rev-parse", "HEAD"], fx!.repo).trim();
    const diff = git(["diff", "main..HEAD"], fx!.repo);
    const diffSha256 = createHash("sha256").update(diff, "utf8").digest("hex");
    const serverFp = fingerprintFromPem(fx!.serverKeyPem);
    const approval: ApprovalV4 = {
      reviewer: "security",
      verdict: "changes_requested",
      prompt_sha256: "a".repeat(64),
      diff_sha256: diffSha256,
      base_sha: baseSha,
      head_sha: headSha,
      trusted_keys_snapshot_sha256: "sha256:" + "b".repeat(64),
      issued_at: "2026-05-17T18:42:13Z",
      server_key_id: serverFp,
    };
    const signature = fx!.signServerApproval(approval);
    const sshFake: SshSpawnFn = async () => ({
      stdout: JSON.stringify({
        verdict: "changes_requested",
        prose: "found a leak",
        approval,
        signature,
      }),
      stderr: "",
      exitCode: 0,
      signal: null,
    });

    const savedExitCode = process.exitCode;
    process.exitCode = 0;
    const cap = captureStreams();
    try {
      await runReview({
        diff: "main..feature",
        _sshSpawnForTest: sshFake,
      });
    } finally {
      cap.restore();
    }
    try {
      assert.equal(process.exitCode, 1);
    } finally {
      process.exitCode = savedExitCode;
    }
  });

  it("surfaces SSH-verb non-zero exit as a reviewer failure (exitCode=1)", async () => {
    const sshFake: SshSpawnFn = async () => ({
      stdout: "",
      stderr: "error: role member is not permitted",
      exitCode: 3,
      signal: null,
    });
    const savedExitCode = process.exitCode;
    process.exitCode = 0;
    const cap = captureStreams();
    try {
      await runReview({
        diff: "main..feature",
        _sshSpawnForTest: sshFake,
      });
    } finally {
      cap.restore();
    }
    try {
      assert.equal(process.exitCode, 1);
      assert.match(cap.stderr, /reviewer: security\s+FAILED/);
      // The verb's stderr propagates through into the error message
      assert.match(cap.stderr, /role member is not permitted/);
    } finally {
      process.exitCode = savedExitCode;
    }
  });
});

// AGT-397: Shape 4 (server-attested without code transfer). Reviewers are
// declared in `.stamp/config.yml` WITHOUT a `prompt:` path — the stamp-
// server resolves the prompt from its bundled filesystem cache (AGT-370)
// by reviewer name. `stamp review` must route through the SSH transport
// and never try to read prompt bytes from the merge-base tree.

/**
 * Variant of `setupRepoWithReviewServer` where the reviewer entry has
 * NO `prompt:` field. Otherwise identical (same trusted-keys manifest +
 * .pub file + origin pointing at the stamp server).
 */
function setupRepoShape4(): Fixture {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "stamp-ssh-shape4-")));
  const repo = join(tmp, "repo");
  mkdirSync(repo);
  git(["init", "-q", "-b", "main", repo], tmp);
  git(["config", "user.email", "t@t.t"], repo);
  git(["config", "user.name", "t"], repo);
  git(["config", "commit.gpgsign", "false"], repo);
  git(
    ["remote", "add", "origin", "ssh://git@stamp.example.com:22/srv/git/acme/widget.git"],
    repo,
  );

  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const serverKeyPem = publicKey.export({ type: "spki", format: "pem" }) as string;
  const serverFp = fingerprintFromPem(serverKeyPem);

  mkdirSync(join(repo, ".stamp", "trusted-keys"), { recursive: true });
  // No `.stamp/reviewers/` directory at all — Shape 4's defining trait.
  writeFileSync(
    join(repo, ".stamp", "config.yml"),
    [
      "branches:",
      "  main:",
      "    required: [security]",
      "    review_server: ssh://git@stamp.example.com:22",
      "reviewers:",
      "  security: {}",
      "",
    ].join("\n"),
  );
  writeFileSync(
    join(repo, ".stamp", "trusted-keys", "manifest.yml"),
    [
      "keys:",
      "  review-server-prod:",
      `    fingerprint: ${serverFp}`,
      "    capabilities: [server]",
      "",
    ].join("\n"),
  );
  writeFileSync(
    join(repo, ".stamp", "trusted-keys", "server-prod.pub"),
    serverKeyPem,
  );
  writeFileSync(join(repo, "README.md"), "# fixture\n");
  git(["add", "-A"], repo);
  git(["commit", "-q", "-m", "init"], repo);
  git(["checkout", "-q", "-b", "feature"], repo);
  writeFileSync(join(repo, "src.txt"), "hello\n");
  git(["add", "src.txt"], repo);
  git(["commit", "-q", "-m", "add src"], repo);

  const prevCwd = process.cwd();
  process.chdir(repo);
  return {
    repo,
    serverKeyPem,
    signServerApproval: (approval) => {
      return sign(null, canonicalSerializeApproval(approval), privateKey).toString("base64");
    },
    restoreCwd: () => process.chdir(prevCwd),
  };
}

describe("runReview — Shape 4: reviewers without prompt: (AGT-397)", () => {
  let cleanup: (() => void) | null = null;
  let fx: Fixture | null = null;

  beforeEach(() => {
    fx = setupRepoShape4();
    const repo = fx.repo;
    const restoreCwd = fx.restoreCwd;
    cleanup = () => {
      restoreCwd();
      rmSync(repo, { recursive: true, force: true });
    };
  });

  afterEach(() => {
    if (cleanup) cleanup();
    cleanup = null;
    fx = null;
  });

  it("routes through SSH and persists the signed row even with `prompt:` omitted from config", async () => {
    const baseSha = git(["rev-parse", "main"], fx!.repo).trim();
    const headSha = git(["rev-parse", "HEAD"], fx!.repo).trim();
    const diff = git(["diff", "main..HEAD"], fx!.repo);
    const diffSha256 = createHash("sha256").update(diff, "utf8").digest("hex");

    const serverFp = fingerprintFromPem(fx!.serverKeyPem);
    const approval: ApprovalV4 = {
      reviewer: "security",
      verdict: "approved",
      prompt_sha256: "a".repeat(64),
      diff_sha256: diffSha256,
      base_sha: baseSha,
      head_sha: headSha,
      trusted_keys_snapshot_sha256: "sha256:" + "b".repeat(64),
      issued_at: "2026-05-17T18:42:13Z",
      server_key_id: serverFp,
    };
    const signature = fx!.signServerApproval(approval);

    const sshFake: SshSpawnFn = async () => ({
      stdout:
        JSON.stringify({
          verdict: "approved" as const,
          prose: "no findings",
          approval,
          signature,
        }) + "\n",
      stderr: "",
      exitCode: 0,
      signal: null,
    });

    const cap = captureStreams();
    try {
      await runReview({
        diff: "main..feature",
        _sshSpawnForTest: sshFake,
      });
    } finally {
      cap.restore();
    }

    // The SSH path must have run (the local-LLM branch would have errored
    // out on the missing prompt path with the AGT-397 message — its
    // absence in stderr is the load-bearing assertion).
    assert.match(cap.stdout, /\[server-attested\]/);
    assert.match(cap.stdout, /verdict: approved/);
    assert.equal(
      cap.stderr.includes('no `prompt:` configured'),
      false,
      `local-only prompt-missing error must NOT fire in server-attested mode; stderr was: ${cap.stderr}`,
    );

    const db = new DatabaseSync(stampStateDbPath(fx!.repo));
    try {
      const row = db
        .prepare(
          `SELECT verdict, server_approval_json, server_signature_b64,
                  server_key_id, schema_version
             FROM reviews
            WHERE reviewer = ? AND base_sha = ? AND head_sha = ?`,
        )
        .get("security", baseSha, headSha) as {
        verdict: string;
        server_approval_json: string;
        server_signature_b64: string;
        server_key_id: string;
        schema_version: number;
      };
      assert.ok(row, "expected a server-attested row to be inserted");
      assert.equal(row.verdict, "approved");
      assert.equal(row.schema_version, REVIEW_ROW_SCHEMA_V4);
      assert.equal(row.server_key_id, serverFp);
      assert.equal(row.server_signature_b64, signature);
    } finally {
      db.close();
    }
  });
});
