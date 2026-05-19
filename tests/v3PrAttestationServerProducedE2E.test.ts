/**
 * AGT-355 — v3 PR-attestation server-produced end-to-end round-trip.
 *
 * Closes the Shape 2 (server-attested PR mode) loop with a single
 * hermetic test. Mirrors `tests/v4Roundtrip.test.ts`'s pattern for the
 * v4 commit-trailer flow, adapted to the PR-attestation envelope:
 *
 *   1. REAL `runReviewPipeline` (server side) produces a signed
 *      ApprovalV4 + the new AGT-355 v3 PR-attestation payload fields.
 *   2. REAL `requestServerReview` (client side) parses the response,
 *      verifies the server's signature, surfaces `prAttestationV3`,
 *      persists the row via `recordReview`. SSH is mocked via the
 *      `_sshSpawnForTest` seam — same pattern as
 *      `tests/sshReviewClient.test.ts`.
 *   3. REAL `runAttest` (client side) folds the server-signed approval
 *      into a v3 envelope and operator-signs the outer.
 *   4. REAL `runVerifyPr` (verifier side, AGT-338) accepts the
 *      produced envelope.
 *
 * Any byte drift between the producer (AGT-355) and verifier (AGT-338)
 * surfaces here as a verifier rejection rather than as green unit
 * suites that pass each half in isolation. This is the cross-ticket
 * integration property neither side's isolated tests can observe.
 *
 * Hermetic: temp dirs, ephemeral keypairs, no network, no real
 * stamp-server, mocked SSH spawn. The fixture commits the operator
 * pubkey + manifest entry at base_sha so the verifier can resolve
 * `signer_key_id` to a real key with `[operator]` capability —
 * mirrors `v4Roundtrip.test.ts`'s setup with the same justification.
 */

import { strict as assert } from "node:assert";
import { execFileSync, spawnSync } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  type KeyObject,
} from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { runAttest } from "../src/commands/attest.ts";
import { runVerifyPr } from "../src/commands/verifyPr.ts";
import {
  type ApprovalEntryV4,
  type ApprovalV4,
} from "../src/lib/attestationV4.ts";
import { openDb, recordReview } from "../src/lib/db.ts";
import { ensureUserKeypair, fingerprintFromPem } from "../src/lib/keys.ts";
import { stampStateDbPath } from "../src/lib/paths.ts";
import {
  parseEnvelope,
  readAttestationBlobBytes,
  PR_ATTESTATION_SCHEMA_VERSION,
} from "../src/lib/prAttestation.ts";
import {
  requestServerReview,
  type SshSpawnFn,
} from "../src/lib/sshReviewClient.ts";
import {
  runReviewPipeline,
  type ReviewPipelineInput,
} from "../src/server/reviewPipeline.ts";
import type { AnthropicClientShape } from "../src/lib/headlessReviewer.ts";
import type { UserRow } from "../src/lib/serverDb.ts";

process.env["STAMP_REQUIRE_HUMAN_MERGE"] = "0";

const REVIEWER_PROMPT = "You are the security reviewer. Approve everything.\n";

interface ServerSigningMaterial {
  privateKey: KeyObject;
  privatePem: string;
  publicPem: string;
  fingerprint: string;
}

function mintServerKey(): ServerSigningMaterial {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  return {
    privateKey,
    privatePem,
    publicPem,
    fingerprint: fingerprintFromPem(publicPem),
  };
}

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

function sha256Hex(buf: Buffer | string): string {
  return createHash("sha256")
    .update(typeof buf === "string" ? Buffer.from(buf, "utf8") : buf)
    .digest("hex");
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

const FIXTURE_USER: UserRow = {
  id: 1,
  short_name: "test-caller",
  ssh_pubkey: "ssh-ed25519 AAAA test@host",
  ssh_fp: "SHA256:test-fingerprint",
  role: "member",
  source: "env",
  created_at: "2026-01-01T00:00:00Z",
};

/**
 * Mocked Anthropic client that returns a deterministic approved
 * verdict via the submit_verdict tool_use block. Same shape the
 * real pipeline parses in `extractVerdictFromResponse`.
 */
function approvedMockClient(): AnthropicClientShape {
  return {
    messages: {
      create: async () => ({
        content: [
          {
            type: "tool_use",
            name: "submit_verdict",
            input: { verdict: "approved", prose: "fixture: approve" },
          },
        ],
      }),
    },
  };
}

interface Harness {
  root: string;
  /** Operator's working repo (where `stamp attest` runs). */
  repo: string;
  /** Bare repo the server side reads `.stamp/` artifacts from. Same
   *  base SHA as the operator's repo — we clone working → bare to set
   *  up. */
  bareDir: string;
  home: string;
  prevHome: string | undefined;
  serverKey: ServerSigningMaterial;
  operatorFingerprint: string;
  cleanup: () => void;
}

function setupHarness(): Harness {
  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-prattv3e2e-"));
  const repo = path.join(root, "repo");
  const home = path.join(root, "home");
  mkdirSync(repo, { recursive: true });
  mkdirSync(home, { recursive: true });

  const prevHome = process.env["HOME"];
  process.env["HOME"] = home;

  const serverKey = mintServerKey();

  // Operator keypair via the same code path runAttest uses (HOME
  // redirected so this writes under tmp).
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
      "    review_server: ssh://git@stamp.test.invalid:22",
      "reviewers:",
      "  security:",
      "    prompt: .stamp/reviewers/security.md",
      "    tools: []",
      "",
    ].join("\n"),
  );
  writeFileSync(
    path.join(repo, ".stamp", "reviewers", "security.md"),
    REVIEWER_PROMPT,
  );

  const serverPubFile = serverKey.fingerprint.replace(":", "_") + ".pub";
  const operatorPubFile = operatorFingerprint.replace(":", "_") + ".pub";
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", serverPubFile),
    serverKey.publicPem,
  );
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", operatorPubFile),
    operatorKp.publicKeyPem,
  );
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", "manifest.yml"),
    [
      "keys:",
      "  review-server-test:",
      `    fingerprint: ${serverKey.fingerprint}`,
      "    capabilities: [server]",
      "  operator-test:",
      `    fingerprint: ${operatorFingerprint}`,
      "    capabilities: [operator]",
      "",
    ].join("\n"),
  );

  writeFileSync(path.join(repo, "README.md"), "initial\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "initial: seed .stamp/ config"]);

  // Clone to a bare for the server-side resolver. Done BEFORE the
  // feature branch is created so server-side reads at base_sha hit
  // the seeded .stamp/ artifacts.
  const bareDir = path.join(root, "widget-co.git");
  const cloneResult = spawnSync(
    "git",
    ["clone", "-q", "--bare", repo, bareDir],
    { encoding: "utf8" },
  );
  if (cloneResult.status !== 0) {
    throw new Error(`bare clone failed: ${cloneResult.stderr}`);
  }

  // Now feature branch with a small change.
  git(repo, ["checkout", "-q", "-b", "feature"]);
  writeFileSync(path.join(repo, "feature.txt"), "hello\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "add feature"]);

  return {
    root,
    repo,
    bareDir,
    home,
    prevHome,
    serverKey,
    operatorFingerprint,
    cleanup: () => {
      if (prevHome === undefined) delete process.env["HOME"];
      else process.env["HOME"] = prevHome;
      rmSync(root, { recursive: true, force: true });
    },
  };
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

/**
 * Drive `runReviewPipeline` directly against the harness fixture +
 * mock Anthropic client. Returns the pipeline's `ReviewPipelineResult`
 * with the AGT-355 v3 PR-attestation fields populated.
 */
async function runRealServerPipeline(args: {
  h: Harness;
  baseSha: string;
  headSha: string;
  diff: Buffer;
}): Promise<Awaited<ReturnType<typeof runReviewPipeline>>> {
  const input: ReviewPipelineInput = {
    diff: args.diff,
    params: {
      reviewer: "security",
      org: "acme",
      repo: "widget-co",
      baseSha: args.baseSha,
      headSha: args.headSha,
      diffSha256: sha256Hex(args.diff),
    },
    caller: FIXTURE_USER,
    deps: {
      repoResolver: () => args.h.bareDir,
      anthropic: approvedMockClient(),
      signingKey: {
        privateKey: args.h.serverKey.privateKey,
        fingerprint: args.h.serverKey.fingerprint,
      },
    },
  };
  return runReviewPipeline(input);
}

describe("v3 PR-attestation — server-produced end-to-end (AGT-355)", () => {
  it("server pipeline → SSH client → recordReview → stamp attest → runVerifyPr: full round-trip", async () => {
    const h = setupHarness();
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "feature");
      const diff = Buffer.from(
        git(h.repo, ["diff", `${base}...${head}`]),
        "utf8",
      );

      // ① REAL server-side pipeline produces the signed approval +
      //    the AGT-355 v3 PR-attestation payload fields.
      const pipelineResult = await runRealServerPipeline({
        h,
        baseSha: base,
        headSha: head,
        diff,
      });
      assert.equal(pipelineResult.verdict, "approved");
      assert.ok(
        pipelineResult.pr_attestation_v3_payload_b64.length > 0,
        "pipeline must surface pr_attestation_v3_payload_b64",
      );
      assert.ok(
        pipelineResult.pr_attestation_v3_signature_b64.length > 0,
        "pipeline must surface pr_attestation_v3_signature_b64",
      );

      // ② Wire up a mocked SSH spawn that returns the pipeline's
      //    response as if the server had emitted it on stdout. Same
      //    JSON shape `stamp-review` emits via
      //    `process.stdout.write(JSON.stringify(result) + "\n")`.
      const fakeStdout =
        JSON.stringify(pipelineResult) + "\n";
      const spawnFake: SshSpawnFn = async () => ({
        stdout: fakeStdout,
        stderr: "",
        exitCode: 0,
        signal: null,
      });

      // The SSH client needs the manifest YAML + pubkey map from
      // base_sha — same artifacts the harness already committed.
      const manifestYaml = git(h.repo, [
        "show",
        `${base}:.stamp/trusted-keys/manifest.yml`,
      ]);
      const pubkeyByFingerprint = new Map<string, string>();
      pubkeyByFingerprint.set(h.serverKey.fingerprint, h.serverKey.publicPem);

      // ③ REAL client-side SSH call (mocked spawn). Parses response,
      //    verifies server signature, surfaces prAttestationV3 to
      //    callers.
      const clientResult = await requestServerReview({
        reviewServerUrl: "ssh://git@stamp.test.invalid:22",
        reviewer: "security",
        org: "acme",
        repo: "widget-co",
        baseSha: base,
        headSha: head,
        diff,
        manifestYaml,
        pubkeyByFingerprint,
        _sshSpawnForTest: spawnFake,
      });
      assert.ok(
        clientResult.prAttestationV3,
        "client result must carry prAttestationV3 (server surfaced v3 fields)",
      );
      assert.ok(
        clientResult.prAttestationV3.payloadBytes.length > 0,
        "client's prAttestationV3.payloadBytes must be non-empty",
      );

      // ④ Persist the row the same way `stamp review` would —
      //    recordReview with serverAttestation populated.
      const db = openDb(stampStateDbPath(h.repo));
      try {
        recordReview(db, {
          reviewer: "security",
          base_sha: base,
          head_sha: head,
          verdict: clientResult.verdict,
          issues: clientResult.prose,
          serverAttestation: {
            approval_json: clientResult.approvalJson,
            signature_b64: clientResult.signature,
            server_key_id: clientResult.approval.server_key_id,
          },
        });
      } finally {
        db.close();
      }

      // ⑤ REAL `stamp attest` reads the row, folds it into v3
      //    envelope, operator-signs the outer.
      runFromRepo(h.repo, () =>
        runAttest({ into: "main", branch: "feature" }),
      );

      const patchIds = listAttestationPatchIds(h.repo);
      assert.equal(patchIds.length, 1);
      const blobBytes = readAttestationBlobBytes(patchIds[0]!, h.repo);
      assert.ok(blobBytes);
      const envelope = parseEnvelope(blobBytes);
      assert.ok(envelope, "envelope must pass v3+ shape gate");
      assert.equal(envelope.payload.schema_version, PR_ATTESTATION_SCHEMA_VERSION);

      // Server-signed approval rode through intact.
      const entries = envelope.payload.approvals as ApprovalEntryV4[];
      assert.equal(entries.length, 1);
      const entry = entries[0]!;
      assert.equal(entry.approval.server_key_id, h.serverKey.fingerprint);
      assert.equal(
        entry.server_attestation.server_key_id,
        h.serverKey.fingerprint,
      );
      // The server's signature must equal the bytes the pipeline
      // produced — proof the payload survived: server → SSH JSON →
      // recordReview → serverApprovalsFor → buildV3Envelope without
      // byte drift.
      assert.equal(
        entry.server_attestation.signature,
        pipelineResult.signature,
        "server signature must survive the full round-trip",
      );

      // ⑥ REAL verifier accepts. AGT-338's runVerifyPr will
      //    process.exit(1) on rejection; trap and assert clean exit.
      const prevExit = process.exit;
      let failedWith: number | null = null;
      // @ts-expect-error overriding process.exit for the verifier
      process.exit = (code?: number) => {
        if (code && code !== 0) {
          failedWith = code;
          throw new Error(`runVerifyPr exited with code ${code}`);
        }
      };
      try {
        runFromRepo(h.repo, () =>
          runVerifyPr({ head: "feature", base: "main", into: "main" }),
        );
      } finally {
        process.exit = prevExit;
      }
      assert.equal(
        failedWith,
        null,
        `verifier rejected the server-produced envelope (exit ${failedWith})`,
      );

      // ⑦ Inner approval body matches what the SERVER signed: the
      //    server's approval and the approval folded into the v3
      //    envelope must be the same canonical bytes. This is the
      //    cross-ticket byte-identity contract — without it, the
      //    verifier would reject the inner signature even though both
      //    sides agree on field values.
      const serverApproval: ApprovalV4 = pipelineResult.approval;
      assert.equal(entry.approval.reviewer, serverApproval.reviewer);
      assert.equal(entry.approval.verdict, serverApproval.verdict);
      assert.equal(entry.approval.diff_sha256, serverApproval.diff_sha256);
      assert.equal(entry.approval.base_sha, serverApproval.base_sha);
      assert.equal(entry.approval.head_sha, serverApproval.head_sha);
      assert.equal(
        entry.approval.trusted_keys_snapshot_sha256,
        serverApproval.trusted_keys_snapshot_sha256,
      );
      assert.equal(entry.approval.issued_at, serverApproval.issued_at);
    } finally {
      h.cleanup();
    }
  });
});
