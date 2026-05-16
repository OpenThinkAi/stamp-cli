/**
 * End-to-end test for `stamp verify-pr` — the consumer side of PR-check
 * mode. Shares a harness with the attest tests (real git + real signing
 * keypair + real attestation envelope written via runAttest), then
 * exercises the verifier against the same fixture.
 *
 * Covers:
 *   - happy path: attest then verify → exit 0 + structured success log
 *   - tampered envelope → signature verification rejects
 *   - missing attestation ref → clear "no attestation found" error
 *   - target_branch mismatch → reject (signed-for-X-then-merged-into-Y attack)
 *   - signer key not in trusted-keys at base → reject
 *   - missing required reviewer → gate-closed reject
 *   - strict_base off (default loose): base advancement preserves verification
 *   - strict_base on: base advancement invalidates the attestation
 *   - patch-id stability: squash + re-attest verifies for the squashed head
 *
 * `runVerifyPr` calls `process.exit(1)` on failure (CI consumes the exit
 * code, not the prose), so we trap it via a stubbed exit and assert the
 * thrown sentinel. Trapping `process.exit` at the test boundary keeps
 * the verifier honest about its exit-code contract — a future change
 * that swallows failures into exit 0 would surface immediately.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { runAttest } from "../src/commands/attest.ts";
import { runVerifyPr } from "../src/commands/verifyPr.ts";
import { openDb, recordReview } from "../src/lib/db.ts";
import { ensureUserKeypair } from "../src/lib/keys.ts";
import { stampStateDbPath } from "../src/lib/paths.ts";
import { patchIdForSpan } from "../src/lib/patchId.ts";
import {
  serializePayload,
  writeAttestationRef,
} from "../src/lib/prAttestation.ts";
import { signBytes } from "../src/lib/signing.ts";

interface Harness {
  repo: string;
  home: string;
  prevHome: string | undefined;
  cleanup: () => void;
}

function git(repo: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd: repo,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function setupHarness(opts: { strictBase?: boolean } = {}): Harness {
  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-verifypr-"));
  const repo = path.join(root, "repo");
  const home = path.join(root, "home");
  mkdirSync(repo, { recursive: true });
  mkdirSync(home, { recursive: true });
  const prevHome = process.env["HOME"];
  process.env["HOME"] = home;

  git(repo, ["init", "-q", "-b", "main"]);
  git(repo, ["config", "user.name", "Test"]);
  git(repo, ["config", "user.email", "test@example.invalid"]);
  git(repo, ["config", "commit.gpgsign", "false"]);

  // Drop in .stamp/config.yml + reviewer prompt + the operator's own
  // pubkey under .stamp/trusted-keys/. The pubkey is freshly generated
  // by ensureUserKeypair() against the overridden HOME so it matches
  // what runAttest will sign with.
  mkdirSync(path.join(repo, ".stamp", "reviewers"), { recursive: true });
  mkdirSync(path.join(repo, ".stamp", "trusted-keys"), { recursive: true });
  const cfg = [
    "branches:",
    "  main:",
    "    required: [security]",
    ...(opts.strictBase ? ["    strict_base: true"] : []),
    "reviewers:",
    "  security:",
    "    prompt: .stamp/reviewers/security.md",
    "    tools: []",
    "",
  ].join("\n");
  writeFileSync(path.join(repo, ".stamp", "config.yml"), cfg);
  writeFileSync(
    path.join(repo, ".stamp", "reviewers", "security.md"),
    "You are the security reviewer. Approve.\n",
  );
  // ensureUserKeypair generates the operator's pubkey at $HOME/.stamp/keys/.
  const { keypair } = ensureUserKeypair();
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", "operator.pub"),
    keypair.publicKeyPem,
  );
  writeFileSync(path.join(repo, "README.md"), "initial\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "initial: seed .stamp config + trust"]);

  // Feature branch with one commit.
  git(repo, ["checkout", "-q", "-b", "feature"]);
  writeFileSync(path.join(repo, "feature.txt"), "hello\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "add feature"]);

  return {
    repo,
    home,
    prevHome,
    cleanup: () => {
      process.env["HOME"] = prevHome;
      rmSync(root, { recursive: true, force: true });
    },
  };
}

function shaOf(repo: string, ref: string): string {
  return git(repo, ["rev-parse", ref]).trim();
}

function seedReview(
  repo: string,
  base_sha: string,
  head_sha: string,
  reviewer: string,
  verdict: "approved" | "changes_requested" | "denied",
): void {
  const db = openDb(stampStateDbPath(repo));
  try {
    recordReview(db, {
      reviewer,
      base_sha,
      head_sha,
      verdict,
      issues: `${reviewer} ${verdict}`,
    });
  } finally {
    db.close();
  }
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

const EXIT_SENTINEL = "__exit_called__";

/**
 * Trap process.exit so the verifier's `process.exit(1)` calls surface
 * as throwables we can assert on. Restore in finally so a test that
 * leaks doesn't poison subsequent tests.
 */
function trapExit<T>(fn: () => T): { exitCode: number | null; error: unknown } {
  const original = process.exit;
  let exitCode: number | null = null;
  // Cast through unknown so we can install a never-returning shim.
  process.exit = ((code?: number) => {
    exitCode = code ?? 0;
    throw new Error(EXIT_SENTINEL);
  }) as unknown as typeof process.exit;
  try {
    fn();
    return { exitCode, error: null };
  } catch (e) {
    if (e instanceof Error && e.message === EXIT_SENTINEL) {
      return { exitCode, error: null };
    }
    return { exitCode, error: e };
  } finally {
    process.exit = original;
  }
}

describe("runVerifyPr — happy path", () => {
  it("verifies an attestation produced by runAttest", () => {
    const h = setupHarness();
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "HEAD");
      seedReview(h.repo, base, head, "security", "approved");
      runFromRepo(h.repo, () => runAttest({ into: "main" }));

      const result = trapExit(() =>
        runFromRepo(h.repo, () =>
          runVerifyPr({ head, base, target: "main" }),
        ),
      );
      // Verifier didn't call process.exit (success).
      assert.equal(result.exitCode, null);
      assert.equal(result.error, null);
    } finally {
      h.cleanup();
    }
  });

  it("verifies after a squash that preserves patch-id (loose mode default)", () => {
    const h = setupHarness();
    try {
      // Build three commits on the feature branch, attest, then squash.
      writeFileSync(path.join(h.repo, "feature.txt"), "hello\nworld\n");
      git(h.repo, ["add", "-A"]);
      git(h.repo, ["commit", "-q", "-m", "feature: line 2"]);
      writeFileSync(path.join(h.repo, "feature.txt"), "hello\nworld\n!\n");
      git(h.repo, ["add", "-A"]);
      git(h.repo, ["commit", "-q", "-m", "feature: line 3"]);

      const base = shaOf(h.repo, "main");
      const headBefore = shaOf(h.repo, "HEAD");
      seedReview(h.repo, base, headBefore, "security", "approved");
      runFromRepo(h.repo, () => runAttest({ into: "main" }));

      // Squash three commits into one. Same patch-id; new head SHA.
      git(h.repo, ["reset", "--soft", "main"]);
      git(h.repo, ["commit", "-q", "-m", "feature: squashed"]);
      const headAfter = shaOf(h.repo, "HEAD");
      assert.notEqual(headBefore, headAfter);

      // Verifier checks the SQUASHED head against the existing
      // attestation. Patch-id matches → ref lookup succeeds → loose
      // mode (default) accepts the existing signature.
      const result = trapExit(() =>
        runFromRepo(h.repo, () =>
          runVerifyPr({ head: headAfter, base, target: "main" }),
        ),
      );
      assert.equal(result.error, null);
      assert.equal(result.exitCode, null);
    } finally {
      h.cleanup();
    }
  });
});

describe("runVerifyPr — failure paths", () => {
  it("exits 1 when no attestation exists for the patch-id", () => {
    const h = setupHarness();
    try {
      // Don't attest anything.
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "HEAD");

      const result = trapExit(() =>
        runFromRepo(h.repo, () =>
          runVerifyPr({ head, base, target: "main" }),
        ),
      );
      assert.equal(result.exitCode, 1);
      assert.equal(result.error, null);
    } finally {
      h.cleanup();
    }
  });

  it("exits 1 when the attestation's signature has been tampered with", () => {
    const h = setupHarness();
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "HEAD");
      seedReview(h.repo, base, head, "security", "approved");
      runFromRepo(h.repo, () => runAttest({ into: "main" }));

      // Find the attestation ref, read its blob, swap the signature
      // for a forged-but-syntactically-valid base64, write it back.
      const refsOutput = git(h.repo, [
        "for-each-ref",
        "--format=%(refname)",
        "refs/stamp/attestations",
      ]);
      const ref = refsOutput.split("\n").map((s) => s.trim()).filter(Boolean)[0]!;
      const blob = git(h.repo, ["cat-file", "blob", ref]);
      const env = JSON.parse(blob) as { payload: unknown; signature: string };
      const tampered = JSON.stringify({
        ...env,
        signature: "AAAA" + env.signature.slice(4),
      });
      // hash-object → update-ref to swap.
      const newSha = execFileSync(
        "git",
        ["hash-object", "-w", "--stdin"],
        { cwd: h.repo, input: tampered, encoding: "utf8" },
      ).trim();
      git(h.repo, ["update-ref", ref, newSha]);

      const result = trapExit(() =>
        runFromRepo(h.repo, () =>
          runVerifyPr({ head, base, target: "main" }),
        ),
      );
      assert.equal(result.exitCode, 1);
    } finally {
      h.cleanup();
    }
  });

  it("exits 1 when target argument doesn't match attestation.target_branch", () => {
    const h = setupHarness();
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "HEAD");
      seedReview(h.repo, base, head, "security", "approved");
      runFromRepo(h.repo, () => runAttest({ into: "main" }));

      const result = trapExit(() =>
        runFromRepo(h.repo, () =>
          runVerifyPr({ head, base, target: "release" }),
        ),
      );
      // Note: runVerifyPr's first failure mode here is actually "no
      // branch rule for release" (since the test config only has
      // 'main') — but BEFORE that, target-branch-mismatch fires. Pin
      // exit code only.
      assert.equal(result.exitCode, 1);
    } finally {
      h.cleanup();
    }
  });

  it("exits 1 when the signing key isn't in .stamp/trusted-keys/ at base", () => {
    const h = setupHarness();
    try {
      // Manually craft an attestation signed by a DIFFERENT key (one
      // not in the trust set) and write it under the patch-id ref.
      // Then verify — should fail at the trusted-key lookup step.
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "HEAD");
      seedReview(h.repo, base, head, "security", "approved");

      // Generate a rogue keypair via ensureUserKeypair against a
      // SECOND home dir so we don't collide with the trusted operator.
      const rogueHome = mkdtempSync(path.join(os.tmpdir(), "stamp-verifypr-rogue-"));
      const trueHome = process.env["HOME"];
      process.env["HOME"] = rogueHome;
      const { keypair: rogue } = ensureUserKeypair();
      process.env["HOME"] = trueHome;
      try {
        // Compute the patch-id the verifier will look up.
        const patch_id = patchIdForSpan(base, head, h.repo);
        // Build a payload in the shape verifyPr expects (matches the
        // legitimate attestation but signs with the rogue key and
        // claims the rogue's fingerprint as signer_key_id).
        const payload = {
          schema_version: 1,
          patch_id,
          base_sha: base,
          head_sha: head,
          target_branch: "main",
          target_branch_tip_sha: base, // base IS the tip in this fixture
          approvals: [
            {
              reviewer: "security",
              verdict: "approved",
              review_sha: "0".repeat(64),
            },
          ],
          checks: [],
          signer_key_id: rogue.fingerprint,
        };
        const signature = signBytes(
          rogue.privateKeyPem,
          serializePayload(payload),
        );
        writeAttestationRef({ payload, signature }, h.repo);

        const result = trapExit(() =>
          runFromRepo(h.repo, () =>
            runVerifyPr({ head, base, target: "main" }),
          ),
        );
        assert.equal(result.exitCode, 1);
      } finally {
        rmSync(rogueHome, { recursive: true, force: true });
      }
    } finally {
      h.cleanup();
    }
  });

  it("exits 1 when a required reviewer is missing from the attestation", () => {
    const h = setupHarness();
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "HEAD");
      // Tamper after attest: rewrite the attestation to drop the
      // approvals list. Direct ref edit (the legitimate attest path
      // would refuse to produce this).
      seedReview(h.repo, base, head, "security", "approved");
      runFromRepo(h.repo, () => runAttest({ into: "main" }));

      const refsOutput = git(h.repo, [
        "for-each-ref",
        "--format=%(refname)",
        "refs/stamp/attestations",
      ]);
      const ref = refsOutput.split("\n").map((s) => s.trim()).filter(Boolean)[0]!;
      const blob = git(h.repo, ["cat-file", "blob", ref]);
      const env = JSON.parse(blob) as {
        payload: { approvals: unknown[] };
        signature: string;
      };
      env.payload.approvals = []; // drop all approvals
      const newBlob = JSON.stringify(env);
      const newSha = execFileSync(
        "git",
        ["hash-object", "-w", "--stdin"],
        { cwd: h.repo, input: newBlob, encoding: "utf8" },
      ).trim();
      git(h.repo, ["update-ref", ref, newSha]);

      // Note: signature won't verify after tampering payload, so
      // verifier will fail at signature step before reaching gate.
      // That's still exit 1 — what we're pinning here is "tampering
      // doesn't sneak through."
      const result = trapExit(() =>
        runFromRepo(h.repo, () =>
          runVerifyPr({ head, base, target: "main" }),
        ),
      );
      assert.equal(result.exitCode, 1);
    } finally {
      h.cleanup();
    }
  });
});

describe("runVerifyPr — strict_base", () => {
  it("loose default: base advancement (with same patch-id) still verifies", () => {
    const h = setupHarness({ strictBase: false });
    try {
      const baseAtAttest = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "HEAD");
      seedReview(h.repo, baseAtAttest, head, "security", "approved");
      runFromRepo(h.repo, () => runAttest({ into: "main" }));

      // Advance main with an unrelated commit; the feature branch's
      // HEAD doesn't change. patch-id is keyed on cumulative diff
      // base..head — when base moves forward without conflicting
      // changes, patch-id stays the same.
      git(h.repo, ["checkout", "-q", "main"]);
      writeFileSync(path.join(h.repo, "main-side.txt"), "x\n");
      git(h.repo, ["add", "-A"]);
      git(h.repo, ["commit", "-q", "-m", "main: unrelated change"]);
      const newBase = shaOf(h.repo, "main");
      assert.notEqual(newBase, baseAtAttest);
      git(h.repo, ["checkout", "-q", "feature"]);

      const result = trapExit(() =>
        runFromRepo(h.repo, () =>
          runVerifyPr({ head, base: newBase, target: "main" }),
        ),
      );
      assert.equal(result.error, null);
      assert.equal(result.exitCode, null);
    } finally {
      h.cleanup();
    }
  });

  it("strict_base on: base advancement invalidates the attestation", () => {
    const h = setupHarness({ strictBase: true });
    try {
      const baseAtAttest = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "HEAD");
      seedReview(h.repo, baseAtAttest, head, "security", "approved");
      runFromRepo(h.repo, () => runAttest({ into: "main" }));

      git(h.repo, ["checkout", "-q", "main"]);
      writeFileSync(path.join(h.repo, "main-side.txt"), "x\n");
      git(h.repo, ["add", "-A"]);
      git(h.repo, ["commit", "-q", "-m", "main: unrelated change"]);
      const newBase = shaOf(h.repo, "main");
      git(h.repo, ["checkout", "-q", "feature"]);

      const result = trapExit(() =>
        runFromRepo(h.repo, () =>
          runVerifyPr({ head, base: newBase, target: "main" }),
        ),
      );
      assert.equal(result.exitCode, 1);
    } finally {
      h.cleanup();
    }
  });

  it("strict_base on: same base still verifies", () => {
    // Sanity: strict_base is the no-advancement check; same-base
    // verification must still succeed with strict_base on.
    const h = setupHarness({ strictBase: true });
    try {
      const base = shaOf(h.repo, "main");
      const head = shaOf(h.repo, "HEAD");
      seedReview(h.repo, base, head, "security", "approved");
      runFromRepo(h.repo, () => runAttest({ into: "main" }));

      const result = trapExit(() =>
        runFromRepo(h.repo, () =>
          runVerifyPr({ head, base, target: "main" }),
        ),
      );
      assert.equal(result.error, null);
      assert.equal(result.exitCode, null);
    } finally {
      h.cleanup();
    }
  });
});
