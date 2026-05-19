/**
 * Tests for `stamp admin sign --pending` (AGT-337).
 *
 * Covers:
 *   - Sign mode happy path: validates the commit, signs, persists a
 *     note that round-trips through `readNote` with the expected
 *     fingerprint.
 *   - Sign mode rejects a commit that doesn't touch `.stamp/**`.
 *   - Sign mode rejects when the caller's local key isn't in the
 *     manifest at base.
 *   - Sign mode rejects when the caller's key lacks the `admin`
 *     capability at base.
 *   - Sign mode is idempotent for the same signer.
 *   - List mode surfaces a `.stamp/**`-touching commit with the
 *     correct present/required counts.
 *   - End-to-end: 2 admin counter-signatures collected via the
 *     command land in the v4 envelope's `trust_anchor_signatures[]`
 *     and verify against the merge-time payload.
 *   - Negative end-to-end: 1 signature → `stamp merge` fails actionably.
 *
 * Note on key minting: the tests redirect HOME to a temp dir and call
 * `ensureUserKeypair()` to mint the caller's stamp key — same pattern
 * as `tests/mergeV4.test.ts`. To simulate a SECOND admin, we mint a
 * key manually (generateKeyPairSync), sign with `signBytes` ourselves,
 * and persist the note via `writeNote` — going around the
 * `runAdminSign` command for the second signer because there's only
 * one local HOME (and therefore only one stamp keypair) per process.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
} from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { runAdminSign } from "../src/commands/adminSign.ts";
import { runMerge } from "../src/commands/merge.ts";
import {
  canonicalSerializeApproval,
  trailerValueToPayloadBytes,
  type ApprovalV4,
  type AttestationPayloadV4,
} from "../src/lib/attestationV4.ts";
import { openDb, recordReview, serverApprovalsFor } from "../src/lib/db.ts";
import { ensureUserKeypair, fingerprintFromPem } from "../src/lib/keys.ts";
import { stampStateDbPath } from "../src/lib/paths.ts";
import { signBytes } from "../src/lib/signing.ts";
import {
  readNote,
  writeNote,
  noteWithAppendedSignature,
  emptyNote,
} from "../src/lib/trustAnchorNotes.ts";
import {
  diffSha256Hex,
  trustAnchorSigningBytes,
} from "../src/lib/trustAnchorPayload.ts";

// ─── Harness ────────────────────────────────────────────────────────

interface ExternalKey {
  privatePem: string;
  publicPem: string;
  fingerprint: string;
}

interface Harness {
  repo: string;
  home: string;
  prevHome: string | undefined;
  operatorFingerprint: string;
  /** Pre-minted server key whose pub is committed + manifested. */
  serverKey: ExternalKey;
  /** Pre-minted second admin (Bob) — used in multi-sig scenarios. */
  secondAdmin: ExternalKey;
  cleanup: () => void;
}

const REVIEWER_PROMPT = "You are the security reviewer. Approve everything.\n";

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

function sha256Hex(s: string | Buffer): string {
  return createHash("sha256")
    .update(typeof s === "string" ? Buffer.from(s, "utf8") : s)
    .digest("hex");
}

function shaOf(repo: string, ref: string): string {
  return git(repo, ["rev-parse", ref]).trim();
}

function diffBetween(repo: string, base: string, head: string): string {
  return git(repo, ["diff", `${base}...${head}`]);
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
 * Build a stamp-gated repo with:
 *   - main configured with review_server (v4 dispatch) AND a
 *     path_rules entry gating .stamp/** at minimum_signatures: 2
 *   - committed pubs for: the test server's review key, the operator
 *     (current HOME's stamp key, minted on-demand), and Bob the
 *     second admin
 *   - a manifest binding fingerprints to capabilities:
 *       review-server-test → [server]
 *       operator-test      → [admin, operator]    ← Alice can sign as admin
 *       bob                → [admin]
 *   - a feature branch with one commit modifying .stamp/reviewers/security.md
 *
 * `bypass_review_cycle: true` is set so the reviewer cycle is replaced
 * by the admin gate — required_checks aren't an issue because there
 * are none, matching the M4 caveat documented in trustAnchorPayload.ts.
 */
function setupHarness(opts?: {
  /** When true, the path_rules-touching commit instead modifies a non-
   *  .stamp/** path so sign-mode rejection paths can be exercised. */
  featureTouchesStamp?: boolean;
  /** When true, the operator's key is NOT given the admin capability
   *  in the manifest. Used to test "your key isn't admin" path. */
  operatorIsNotAdmin?: boolean;
}): Harness {
  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-adminsign-"));
  const repo = path.join(root, "repo");
  const home = path.join(root, "home");
  mkdirSync(repo, { recursive: true });
  mkdirSync(home, { recursive: true });

  const prevHome = process.env["HOME"];
  process.env["HOME"] = home;

  const serverKey = generateExternalKey();
  const secondAdmin = generateExternalKey();

  // Mint operator key via the same code path runAdminSign hits.
  const { keypair: operatorKp } = ensureUserKeypair();
  const operatorFingerprint = operatorKp.fingerprint;

  git(repo, ["init", "-q", "-b", "main"]);
  git(repo, ["config", "user.name", "Test"]);
  git(repo, ["config", "user.email", "test@example.invalid"]);
  git(repo, ["config", "commit.gpgsign", "false"]);

  mkdirSync(path.join(repo, ".stamp", "reviewers"), { recursive: true });
  mkdirSync(path.join(repo, ".stamp", "trusted-keys"), { recursive: true });

  // Config: main requires the security reviewer + has review_server +
  // a path_rules entry gating .stamp/** at minimum_signatures: 2.
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
      "  .stamp/**:",
      "    require_capability: admin",
      "    minimum_signatures: 2",
      "    bypass_review_cycle: true",
      "",
    ].join("\n"),
  );
  writeFileSync(
    path.join(repo, ".stamp", "reviewers", "security.md"),
    REVIEWER_PROMPT,
  );

  const serverPubFile = serverKey.fingerprint.replace(":", "_") + ".pub";
  const operatorPubFile = operatorFingerprint.replace(":", "_") + ".pub";
  const bobPubFile = secondAdmin.fingerprint.replace(":", "_") + ".pub";

  writeFileSync(path.join(repo, ".stamp", "trusted-keys", serverPubFile), serverKey.publicPem);
  writeFileSync(path.join(repo, ".stamp", "trusted-keys", operatorPubFile), operatorKp.publicKeyPem);
  writeFileSync(path.join(repo, ".stamp", "trusted-keys", bobPubFile), secondAdmin.publicPem);

  const operatorCaps = opts?.operatorIsNotAdmin
    ? "[operator]"
    : "[admin, operator]";

  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", "manifest.yml"),
    [
      "keys:",
      "  review-server-test:",
      `    fingerprint: ${serverKey.fingerprint}`,
      "    capabilities: [server]",
      "  operator-test:",
      `    fingerprint: ${operatorFingerprint}`,
      `    capabilities: ${operatorCaps}`,
      "  bob:",
      `    fingerprint: ${secondAdmin.fingerprint}`,
      "    capabilities: [admin]",
      "",
    ].join("\n"),
  );

  writeFileSync(path.join(repo, "README.md"), "initial\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "initial: seed .stamp/ config"]);

  // Feature branch: either touches a .stamp/** path (default) or a
  // regular file (for negative-path test).
  git(repo, ["checkout", "-q", "-b", "feature"]);
  if (opts?.featureTouchesStamp === false) {
    writeFileSync(path.join(repo, "feature.txt"), "hello\n");
  } else {
    // Modify the existing reviewer prompt — definitely a .stamp/** touch.
    writeFileSync(
      path.join(repo, ".stamp", "reviewers", "security.md"),
      REVIEWER_PROMPT + "\nApprove with extra enthusiasm.\n",
    );
  }
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "modify .stamp/ reviewer prompt"]);

  git(repo, ["checkout", "-q", "main"]);

  return {
    repo,
    home,
    prevHome,
    operatorFingerprint,
    serverKey,
    secondAdmin,
    cleanup: () => {
      if (prevHome === undefined) delete process.env["HOME"];
      else process.env["HOME"] = prevHome;
      rmSync(root, { recursive: true, force: true });
    },
  };
}

/** Seed a server-signed approval row matching what `stamp review`
 *  would produce against (base, head). */
function seedV4Review(h: Harness, base: string, head: string, diffSha: string): void {
  const approval: ApprovalV4 = {
    reviewer: "security",
    verdict: "approved",
    prompt_sha256: sha256Hex(REVIEWER_PROMPT),
    diff_sha256: diffSha,
    base_sha: base,
    head_sha: head,
    trusted_keys_snapshot_sha256: "sha256:" + "0".repeat(64),
    issued_at: "2026-05-17T18:42:13Z",
    server_key_id: h.serverKey.fingerprint,
  };
  const sig = signBytes(h.serverKey.privatePem, canonicalSerializeApproval(approval));
  const db = openDb(stampStateDbPath(h.repo));
  try {
    recordReview(db, {
      reviewer: "security",
      base_sha: base,
      head_sha: head,
      verdict: "approved",
      issues: "approved",
      serverAttestation: {
        approval_json: JSON.stringify(approval),
        signature_b64: sig,
        server_key_id: h.serverKey.fingerprint,
      },
    });
  } finally {
    db.close();
  }
}

// `requireHumanMerge` is gated by STAMP_REQUIRE_HUMAN_MERGE=0 to keep
// the test non-interactive (matches mergeV4.test.ts convention).
process.env["STAMP_REQUIRE_HUMAN_MERGE"] = "0";

// ─── Sign-mode unit tests ──────────────────────────────────────────

describe("stamp admin sign --pending <sha> — validation", () => {
  it("rejects a commit that doesn't touch any path_rules-matched path", () => {
    const h = setupHarness({ featureTouchesStamp: false });
    try {
      const featureHead = shaOf(h.repo, "feature");
      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runAdminSign({ pending: featureHead }),
          ),
        /doesn't touch any path matched by path_rules/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects when the caller's key isn't in the manifest at base", () => {
    // Set up with a manifest that omits the operator entry entirely.
    const root = mkdtempSync(path.join(os.tmpdir(), "stamp-adminsign-norop-"));
    const repo = path.join(root, "repo");
    const home = path.join(root, "home");
    mkdirSync(repo, { recursive: true });
    mkdirSync(home, { recursive: true });
    const prevHome = process.env["HOME"];
    process.env["HOME"] = home;
    try {
      const serverKey = generateExternalKey();
      const bob = generateExternalKey();
      ensureUserKeypair(); // mint operator into the temp HOME

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
          "path_rules:",
          "  .stamp/**:",
          "    require_capability: admin",
          "    minimum_signatures: 2",
          "    bypass_review_cycle: true",
          "",
        ].join("\n"),
      );
      writeFileSync(path.join(repo, ".stamp", "reviewers", "security.md"), REVIEWER_PROMPT);

      // Manifest omits the operator key entirely.
      writeFileSync(
        path.join(repo, ".stamp", "trusted-keys", "manifest.yml"),
        [
          "keys:",
          "  review-server-test:",
          `    fingerprint: ${serverKey.fingerprint}`,
          "    capabilities: [server]",
          "  bob:",
          `    fingerprint: ${bob.fingerprint}`,
          "    capabilities: [admin]",
          "",
        ].join("\n"),
      );
      const serverPubFile = serverKey.fingerprint.replace(":", "_") + ".pub";
      const bobPubFile = bob.fingerprint.replace(":", "_") + ".pub";
      writeFileSync(path.join(repo, ".stamp", "trusted-keys", serverPubFile), serverKey.publicPem);
      writeFileSync(path.join(repo, ".stamp", "trusted-keys", bobPubFile), bob.publicPem);
      writeFileSync(path.join(repo, "README.md"), "initial\n");
      git(repo, ["add", "-A"]);
      git(repo, ["commit", "-q", "-m", "seed"]);

      git(repo, ["checkout", "-q", "-b", "feature"]);
      writeFileSync(
        path.join(repo, ".stamp", "reviewers", "security.md"),
        REVIEWER_PROMPT + "\nmodified\n",
      );
      git(repo, ["add", "-A"]);
      git(repo, ["commit", "-q", "-m", "modify reviewer"]);

      const featureHead = shaOf(repo, "feature");
      assert.throws(
        () =>
          runFromRepo(repo, () =>
            runAdminSign({ pending: featureHead }),
          ),
        /isn't listed in .stamp\/trusted-keys\/manifest\.yml/,
      );
    } finally {
      if (prevHome === undefined) delete process.env["HOME"];
      else process.env["HOME"] = prevHome;
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("rejects when the caller's key lacks the 'admin' capability at base", () => {
    const h = setupHarness({ operatorIsNotAdmin: true });
    try {
      const featureHead = shaOf(h.repo, "feature");
      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runAdminSign({ pending: featureHead }),
          ),
        /has capabilities \[operator\].*requires the 'admin' capability/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects an unknown commit SHA", () => {
    const h = setupHarness();
    try {
      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runAdminSign({ pending: "0".repeat(40) }),
          ),
        /not found/,
      );
    } finally {
      h.cleanup();
    }
  });

  it("rejects a malformed --signer-key-id override", () => {
    const h = setupHarness();
    try {
      const featureHead = shaOf(h.repo, "feature");
      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runAdminSign({ pending: featureHead, signerKeyId: "not-a-fingerprint" }),
          ),
        /must be a fingerprint of the form/,
      );
    } finally {
      h.cleanup();
    }
  });
});

describe("stamp admin sign --pending <sha> — happy path + idempotency", () => {
  it("signs the pending commit and persists a verifying note", () => {
    const h = setupHarness();
    try {
      const featureHead = shaOf(h.repo, "feature");
      // Seed a server-signed approval so admin-sign's payload prediction
      // matches what stamp merge will compute (otherwise we'd just be
      // testing the empty-approvals branch).
      const base = shaOf(h.repo, "main");
      const diff = diffBetween(h.repo, base, featureHead);
      const diffSha = sha256Hex(diff);
      seedV4Review(h, base, featureHead, diffSha);

      runFromRepo(h.repo, () => runAdminSign({ pending: featureHead }));

      const note = readNote(h.repo, featureHead);
      assert.ok(note, "note must exist after sign");
      assert.equal(note.signatures.length, 1);
      assert.equal(note.signatures[0]!.signer_key_id, h.operatorFingerprint);
      assert.equal(note.head_sha, featureHead);
      assert.equal(note.base_sha, base);
      assert.equal(note.diff_sha256, diffSha);
    } finally {
      h.cleanup();
    }
  });

  it("is a no-op when the same signer runs twice (idempotent)", () => {
    const h = setupHarness();
    try {
      const featureHead = shaOf(h.repo, "feature");
      const base = shaOf(h.repo, "main");
      const diff = diffBetween(h.repo, base, featureHead);
      seedV4Review(h, base, featureHead, sha256Hex(diff));

      runFromRepo(h.repo, () => runAdminSign({ pending: featureHead }));
      runFromRepo(h.repo, () => runAdminSign({ pending: featureHead }));

      const note = readNote(h.repo, featureHead);
      assert.ok(note);
      assert.equal(note.signatures.length, 1);
    } finally {
      h.cleanup();
    }
  });
});

// ─── List-mode tests ───────────────────────────────────────────────

describe("stamp admin sign --pending (no SHA) — list mode", () => {
  it("emits JSON describing the pending commit with present/required counts", () => {
    const h = setupHarness();
    try {
      // Capture stdout while running list mode.
      const captured: string[] = [];
      const origWrite = process.stdout.write.bind(process.stdout);
      // node:test's snapshot of process.stdout.write may be quirky; we
      // mutate the writable's `write` directly which is what every
      // CLI test in this repo does (see runFromRepo's pattern in
      // mergeV4.test.ts). The cast through unknown is necessary because
      // `write` has overloads.
      (process.stdout as unknown as { write: (s: string) => boolean }).write =
        (s: string) => {
          captured.push(typeof s === "string" ? s : (s as Buffer).toString("utf8"));
          return true;
        };
      try {
        runFromRepo(h.repo, () => runAdminSign({ json: true }));
      } finally {
        (process.stdout as unknown as { write: typeof origWrite }).write = origWrite;
      }

      const parsed: unknown = JSON.parse(captured.join(""));
      assert.ok(Array.isArray(parsed));
      // The feature commit isn't on HEAD (we checked out main); since
      // we walk HEAD's first-parent history, our test repo's HEAD won't
      // include the feature commit. Switch to the feature branch and
      // re-run for a more realistic discovery.
      git(h.repo, ["checkout", "-q", "feature"]);
      const captured2: string[] = [];
      (process.stdout as unknown as { write: (s: string) => boolean }).write =
        (s: string) => {
          captured2.push(typeof s === "string" ? s : (s as Buffer).toString("utf8"));
          return true;
        };
      try {
        runFromRepo(h.repo, () => runAdminSign({ json: true }));
      } finally {
        (process.stdout as unknown as { write: typeof origWrite }).write = origWrite;
      }
      const rows = JSON.parse(captured2.join("")) as Array<{
        sha: string;
        signatures_present: number;
        signatures_required: number;
        awaiting: boolean;
      }>;
      const featureHead = shaOf(h.repo, "feature");
      const match = rows.find((r) => r.sha === featureHead);
      assert.ok(match, "feature commit must appear in list mode");
      assert.equal(match.signatures_present, 0);
      assert.equal(match.signatures_required, 2);
      assert.equal(match.awaiting, true);
    } finally {
      h.cleanup();
    }
  });

  it("reflects a partial signature count after one admin signs", () => {
    const h = setupHarness();
    try {
      const featureHead = shaOf(h.repo, "feature");
      const base = shaOf(h.repo, "main");
      seedV4Review(h, base, featureHead, sha256Hex(diffBetween(h.repo, base, featureHead)));
      runFromRepo(h.repo, () => runAdminSign({ pending: featureHead }));

      git(h.repo, ["checkout", "-q", "feature"]);
      const captured: string[] = [];
      const origWrite = process.stdout.write.bind(process.stdout);
      (process.stdout as unknown as { write: (s: string) => boolean }).write =
        (s: string) => {
          captured.push(typeof s === "string" ? s : (s as Buffer).toString("utf8"));
          return true;
        };
      try {
        runFromRepo(h.repo, () => runAdminSign({ json: true }));
      } finally {
        (process.stdout as unknown as { write: typeof origWrite }).write = origWrite;
      }
      const rows = JSON.parse(captured.join("")) as Array<{
        sha: string;
        signatures_present: number;
        signatures_required: number;
        awaiting: boolean;
      }>;
      const match = rows.find((r) => r.sha === featureHead);
      assert.ok(match);
      assert.equal(match.signatures_present, 1);
      assert.equal(match.signatures_required, 2);
      assert.equal(match.awaiting, true);
    } finally {
      h.cleanup();
    }
  });
});

// ─── End-to-end with stamp merge ───────────────────────────────────

/**
 * Externally produce Bob's signature against the same payload bytes
 * `runAdminSign` would produce. Used to simulate the second admin
 * without minting a second HOME. The signing target reconstruction
 * here MIRRORS `runAdminSign`'s logic — by going through
 * `trustAnchorSigningBytes`, we ensure both signers commit to bytes
 * `stamp merge` will independently re-derive.
 */
function bobSigns(h: Harness, baseSha: string, headSha: string, targetBranch: string): void {
  const diff = diffBetween(h.repo, baseSha, headSha);
  const diffSha = diffSha256Hex(diff);

  // Mirror `runAdminSign`'s loadServerApprovals shape using the exported
  // projection helper so this test stays in sync with the production
  // query shape automatically.
  const db = openDb(stampStateDbPath(h.repo));
  let approvals: import("../src/lib/attestationV4.ts").ApprovalEntryV4[];
  try {
    approvals = serverApprovalsFor(db, baseSha, headSha).map((r) => ({
      approval: JSON.parse(r.approval_json) as ApprovalV4,
      server_attestation: {
        server_key_id: r.server_key_id,
        signature: r.signature_b64,
      },
    }));
  } finally {
    db.close();
  }

  const bytes = trustAnchorSigningBytes({
    baseSha,
    headSha,
    targetBranch,
    diffSha256: diffSha,
    approvals,
    checks: [],
    signerKeyId: h.operatorFingerprint, // Bob signs WITH the operator's identity baked in
  });
  const sig = signBytes(h.secondAdmin.privatePem, bytes);

  const existing = readNote(h.repo, headSha);
  const base =
    existing ??
    emptyNote({
      head_sha: headSha,
      base_sha: baseSha,
      diff_sha256: diffSha,
      target_branch: targetBranch,
    });
  const { note } = noteWithAppendedSignature(base, {
    signer_key_id: h.secondAdmin.fingerprint,
    signature: sig,
  });
  writeNote(h.repo, headSha, note);
}

describe("end-to-end: 2 admin signatures → stamp merge produces v4 envelope with trust_anchor_signatures", () => {
  it("populates envelope.trust_anchor_signatures with both verified admin sigs", () => {
    const h = setupHarness();
    try {
      const featureHead = shaOf(h.repo, "feature");
      const base = shaOf(h.repo, "main");
      const diff = diffBetween(h.repo, base, featureHead);
      const diffSha = sha256Hex(diff);

      // Seed the server-signed reviewer row (admin sigs predict approvals=[that row]).
      seedV4Review(h, base, featureHead, diffSha);

      // Alice signs via the command.
      runFromRepo(h.repo, () => runAdminSign({ pending: featureHead }));
      // Bob signs externally (different key, same predicted payload bytes).
      bobSigns(h, base, featureHead, "main");

      const noteBefore = readNote(h.repo, featureHead);
      assert.ok(noteBefore);
      assert.equal(noteBefore.signatures.length, 2);

      // Merge.
      runFromRepo(h.repo, () =>
        runMerge({ branch: "feature", into: "main", yes: true }),
      );

      const mergeMsg = git(h.repo, ["log", "-1", "--pretty=%B"]);
      const payloadMatch = mergeMsg.match(/^Stamp-Payload:\s*(.+)$/m);
      assert.ok(payloadMatch);
      const payload = JSON.parse(
        trailerValueToPayloadBytes(payloadMatch[1]!.trim()).toString("utf8"),
      ) as AttestationPayloadV4;

      assert.equal(payload.trust_anchor_signatures.length, 2);
      const signerIds = payload.trust_anchor_signatures.map((t) => t.signer_key_id).sort();
      const expected = [h.operatorFingerprint, h.secondAdmin.fingerprint].sort();
      assert.deepEqual(signerIds, expected);
    } finally {
      h.cleanup();
    }
  });

  it("with only 1 signature, stamp merge fails actionably and rolls back", () => {
    const h = setupHarness();
    try {
      const featureHead = shaOf(h.repo, "feature");
      const base = shaOf(h.repo, "main");
      const diff = diffBetween(h.repo, base, featureHead);
      seedV4Review(h, base, featureHead, sha256Hex(diff));

      // Only Alice signs.
      runFromRepo(h.repo, () => runAdminSign({ pending: featureHead }));

      const beforeMain = shaOf(h.repo, "main");
      assert.throws(
        () =>
          runFromRepo(h.repo, () =>
            runMerge({ branch: "feature", into: "main", yes: true }),
          ),
        /requires 2 admin signature\(s\) with capability 'admin'/,
      );
      // Rollback: main hasn't moved.
      assert.equal(shaOf(h.repo, "main"), beforeMain);
    } finally {
      h.cleanup();
    }
  });
});
