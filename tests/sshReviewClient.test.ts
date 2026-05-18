/**
 * Tests for `src/lib/sshReviewClient.ts` (AGT-332): the client-side SSH
 * transport that calls stamp-server's `stamp-review` verb and parses
 * the signed response.
 *
 * Hard contracts:
 *   - `parseReviewServerUrl` accepts the happy ssh:// shapes and rejects
 *     anything that could let `ssh` re-interpret the URL as an option
 *     (leading `-`, embedded `=`, wrong scheme).
 *   - `requestServerReview` cross-checks the signed approval body
 *     against the request (reviewer, base, head, diff_sha256) so a
 *     server bug returning a verdict for the wrong payload doesn't
 *     pollute the local DB.
 *   - signature verification refuses on every link of the trust chain:
 *     manifest missing, key not in manifest, key without `server`
 *     capability, no matching .pub file, signature mismatch.
 *   - exit-code mapping surfaces server stderr verbatim with a hint
 *     anchored on AGT-328's documented exit-code contract.
 */

import { strict as assert } from "node:assert";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { describe, it } from "node:test";

import {
  buildPubkeyMap,
  parseReviewServerUrl,
  requestServerReview,
  type SshSpawnFn,
} from "../src/lib/sshReviewClient.ts";
import {
  canonicalSerializeApproval,
  type ApprovalV4,
} from "../src/lib/attestationV4.ts";
import { parseConfigFromYaml } from "../src/lib/config.ts";
import { fingerprintFromPem } from "../src/lib/keys.ts";
import { parseOrgRepoFromUrl } from "../src/lib/remote.ts";

// ─── parseConfigFromYaml — review_server field ──────────────────────

describe("parseConfigFromYaml — review_server field (AGT-332)", () => {
  it("accepts a valid ssh:// URL on a branch rule", () => {
    const yaml = [
      "branches:",
      "  main:",
      "    required: [security]",
      "    review_server: ssh://git@stamp.example.com:22",
      "reviewers:",
      "  security: { prompt: .stamp/reviewers/security.md }",
      "",
    ].join("\n");
    const cfg = parseConfigFromYaml(yaml);
    assert.equal(cfg.branches.main!.review_server, "ssh://git@stamp.example.com:22");
  });

  it("rejects a non-ssh:// URL with operator-readable prose", () => {
    const yaml = [
      "branches:",
      "  main:",
      "    required: [security]",
      "    review_server: https://stamp.example.com",
      "reviewers:",
      "  security: { prompt: .stamp/reviewers/security.md }",
      "",
    ].join("\n");
    assert.throws(() => parseConfigFromYaml(yaml), /must be an ssh:\/\/ URL/);
  });

  it("treats an absent review_server as the 1.x compatibility path (field undefined)", () => {
    const yaml = [
      "branches:",
      "  main: { required: [security] }",
      "reviewers:",
      "  security: { prompt: .stamp/reviewers/security.md }",
      "",
    ].join("\n");
    const cfg = parseConfigFromYaml(yaml);
    assert.equal(cfg.branches.main!.review_server, undefined);
  });

  it("rejects empty-string review_server", () => {
    const yaml = [
      "branches:",
      "  main:",
      "    required: [security]",
      "    review_server: ''",
      "reviewers:",
      "  security: { prompt: .stamp/reviewers/security.md }",
      "",
    ].join("\n");
    assert.throws(() => parseConfigFromYaml(yaml), /must be a non-empty string/);
  });
});

// ─── parseOrgRepoFromUrl ────────────────────────────────────────────

describe("parseOrgRepoFromUrl", () => {
  it("parses github scp-style", () => {
    assert.deepEqual(
      parseOrgRepoFromUrl("git@github.com:acme/widget.git"),
      { org: "acme", repo: "widget" },
    );
  });

  it("parses stamp-server ssh:// with /srv/git nesting", () => {
    assert.deepEqual(
      parseOrgRepoFromUrl("ssh://git@stamp.example.com:22/srv/git/acme/widget.git"),
      { org: "acme", repo: "widget" },
    );
  });

  it("parses github https://", () => {
    assert.deepEqual(
      parseOrgRepoFromUrl("https://github.com/acme/widget.git"),
      { org: "acme", repo: "widget" },
    );
  });

  it("returns null when the path has fewer than 2 segments", () => {
    assert.equal(parseOrgRepoFromUrl("ssh://host/only-one"), null);
  });

  it("returns null on totally bogus input", () => {
    assert.equal(parseOrgRepoFromUrl("not a url"), null);
  });
});

// ─── parseReviewServerUrl ───────────────────────────────────────────

describe("parseReviewServerUrl", () => {
  it("parses the canonical ssh://git@host:port shape", () => {
    const u = parseReviewServerUrl("ssh://git@stamp.example.com:22");
    assert.deepEqual(u, { user: "git", host: "stamp.example.com", port: 22 });
  });

  it("defaults user=git when omitted", () => {
    const u = parseReviewServerUrl("ssh://stamp.example.com:2222");
    assert.equal(u.user, "git");
    assert.equal(u.host, "stamp.example.com");
    assert.equal(u.port, 2222);
  });

  it("defaults port=22 when omitted", () => {
    const u = parseReviewServerUrl("ssh://git@stamp.example.com");
    assert.equal(u.port, 22);
  });

  it("accepts a non-default user", () => {
    const u = parseReviewServerUrl("ssh://stampbot@host:22");
    assert.equal(u.user, "stampbot");
  });

  it("rejects non-ssh scheme", () => {
    assert.throws(
      () => parseReviewServerUrl("https://stamp.example.com:22"),
      /ssh:\/\/ URL/,
    );
  });

  it("rejects empty input", () => {
    assert.throws(() => parseReviewServerUrl(""), /empty/);
  });

  it("rejects empty host", () => {
    assert.throws(() => parseReviewServerUrl("ssh://"), /no host|empty host/);
  });

  it("rejects user starting with -", () => {
    // The defense against `-oProxyCommand=...` smuggling.
    assert.throws(
      () => parseReviewServerUrl("ssh://-oProxyCommand=evil@host:22"),
      /invalid shape/,
    );
  });

  it("rejects host starting with -", () => {
    assert.throws(
      () => parseReviewServerUrl("ssh://-evil-host:22"),
      /invalid shape/,
    );
  });

  it("rejects port out of range", () => {
    assert.throws(() => parseReviewServerUrl("ssh://host:0"), /1\.\.65535/);
    assert.throws(
      () => parseReviewServerUrl("ssh://host:99999"),
      /1\.\.65535/,
    );
  });

  it("rejects URLs with a path component", () => {
    assert.throws(
      () => parseReviewServerUrl("ssh://git@host:22/some/path"),
      /must not include a path/,
    );
  });

  it("rejects host with embedded =", () => {
    assert.throws(
      () => parseReviewServerUrl("ssh://git@h=evil:22"),
      /invalid shape/,
    );
  });
});

// ─── buildPubkeyMap ─────────────────────────────────────────────────

describe("buildPubkeyMap", () => {
  it("indexes .pub files by fingerprint and skips non-pub", () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    const pem = publicKey.export({ type: "spki", format: "pem" }) as string;
    const fp = fingerprintFromPem(pem);
    const files = ["server-prod.pub", "README.md", "alice.pub"];
    const reads: Record<string, string> = {
      ".stamp/trusted-keys/server-prod.pub": pem,
      ".stamp/trusted-keys/alice.pub": pem, // same key for test simplicity
    };
    const map = buildPubkeyMap(files, (p) => {
      if (reads[p] === undefined) throw new Error(`no such file ${p}`);
      return reads[p]!;
    });
    // Two .pub files both happen to encode the same key — last write wins
    // by Map semantics, but the map size depends on fingerprint uniqueness
    // not filename count.
    assert.equal(map.has(fp), true);
  });

  it("silently skips unreadable files", () => {
    const map = buildPubkeyMap(["missing.pub"], () => {
      throw new Error("ENOENT");
    });
    assert.equal(map.size, 0);
  });

  it("silently skips malformed PEM", () => {
    const map = buildPubkeyMap(["junk.pub"], () => "not-a-pem");
    assert.equal(map.size, 0);
  });
});

// ─── requestServerReview ────────────────────────────────────────────

/**
 * Build a fully-signed fixture response for a request — the same shape
 * AGT-330 will eventually emit but synthesized client-side. The fixture
 * is built around a real Ed25519 keypair so signature verification
 * exercises the full code path (no signature stub).
 */
function buildSignedFixture(opts: {
  reviewer: string;
  org: string;
  repo: string;
  baseSha: string;
  headSha: string;
  diff: Buffer;
  verdict: ApprovalV4["verdict"];
  prose: string;
}): {
  responseJson: string;
  manifestYaml: string;
  pubkeyByFingerprint: Map<string, string>;
  fingerprint: string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" }) as string;
  const fp = fingerprintFromPem(pem);
  const diffSha256 = createHash("sha256").update(opts.diff).digest("hex");
  const approval: ApprovalV4 = {
    reviewer: opts.reviewer,
    verdict: opts.verdict,
    prompt_sha256: "a".repeat(64),
    diff_sha256: diffSha256,
    base_sha: opts.baseSha,
    head_sha: opts.headSha,
    trusted_keys_snapshot_sha256: "sha256:" + "b".repeat(64),
    issued_at: "2026-05-17T18:42:13Z",
    server_key_id: fp,
  };
  const sig = sign(null, canonicalSerializeApproval(approval), privateKey);
  const responseJson = JSON.stringify({
    verdict: opts.verdict,
    prose: opts.prose,
    approval,
    signature: sig.toString("base64"),
  });
  const manifestYaml = `
keys:
  review-server-prod:
    fingerprint: ${fp}
    capabilities: [server]
`;
  return {
    responseJson,
    manifestYaml,
    pubkeyByFingerprint: new Map([[fp, pem]]),
    fingerprint: fp,
  };
}

const BASE = "a".repeat(40);
const HEAD = "b".repeat(40);
const DIFF = Buffer.from("diff content\n", "utf8");

describe("requestServerReview — happy path", () => {
  it("parses, verifies, and returns the signed response", async () => {
    const fx = buildSignedFixture({
      reviewer: "security",
      org: "acme",
      repo: "widget",
      baseSha: BASE,
      headSha: HEAD,
      diff: DIFF,
      verdict: "approved",
      prose: "no findings",
    });
    const spawnFake: SshSpawnFn = async () => ({
      stdout: fx.responseJson,
      stderr: "",
      exitCode: 0,
      signal: null,
    });
    const result = await requestServerReview({
      reviewServerUrl: "ssh://git@stamp.example.com:22",
      reviewer: "security",
      org: "acme",
      repo: "widget",
      baseSha: BASE,
      headSha: HEAD,
      diff: DIFF,
      manifestYaml: fx.manifestYaml,
      pubkeyByFingerprint: fx.pubkeyByFingerprint,
      _sshSpawnForTest: spawnFake,
    });
    assert.equal(result.verdict, "approved");
    assert.equal(result.prose, "no findings");
    assert.equal(result.approval.reviewer, "security");
    assert.equal(result.approval.server_key_id, fx.fingerprint);
    assert.ok(result.signature.length > 0);
    // approvalJson is the exact wire bytes (used for DB persistence)
    assert.ok(result.approvalJson.includes(`"reviewer":"security"`));
  });

  it("passes the right argv to the SSH child", async () => {
    const fx = buildSignedFixture({
      reviewer: "security",
      org: "acme",
      repo: "widget",
      baseSha: BASE,
      headSha: HEAD,
      diff: DIFF,
      verdict: "approved",
      prose: "ok",
    });
    let capturedArgs: string[] | null = null;
    let capturedDiff: Buffer | null = null;
    const spawnFake: SshSpawnFn = async (_url, args, diff) => {
      capturedArgs = args;
      capturedDiff = diff;
      return {
        stdout: fx.responseJson,
        stderr: "",
        exitCode: 0,
        signal: null,
      };
    };
    await requestServerReview({
      reviewServerUrl: "ssh://git@stamp.example.com:22",
      reviewer: "security",
      org: "acme",
      repo: "widget",
      baseSha: BASE,
      headSha: HEAD,
      diff: DIFF,
      manifestYaml: fx.manifestYaml,
      pubkeyByFingerprint: fx.pubkeyByFingerprint,
      _sshSpawnForTest: spawnFake,
    });
    assert.deepEqual(capturedArgs, [
      "--reviewer",
      "security",
      "--org",
      "acme",
      "--repo",
      "widget",
      "--base-sha",
      BASE,
      "--head-sha",
      HEAD,
      "--diff-sha256",
      createHash("sha256").update(DIFF).digest("hex"),
    ]);
    assert.deepEqual(capturedDiff, DIFF);
  });
});

describe("requestServerReview — error mapping", () => {
  function emptyFixture() {
    return buildSignedFixture({
      reviewer: "security",
      org: "acme",
      repo: "widget",
      baseSha: BASE,
      headSha: HEAD,
      diff: DIFF,
      verdict: "approved",
      prose: "ok",
    });
  }

  it("surfaces server stderr verbatim with a hint on non-zero exit", async () => {
    const fx = emptyFixture();
    const spawnFake: SshSpawnFn = async () => ({
      stdout: "",
      stderr: "error: role member is not permitted",
      exitCode: 3,
      signal: null,
    });
    await assert.rejects(
      requestServerReview({
        reviewServerUrl: "ssh://git@stamp.example.com:22",
        reviewer: "security",
        org: "acme",
        repo: "widget",
        baseSha: BASE,
        headSha: HEAD,
        diff: DIFF,
        manifestYaml: fx.manifestYaml,
        pubkeyByFingerprint: fx.pubkeyByFingerprint,
        _sshSpawnForTest: spawnFake,
      }),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.match(err.message, /exit 3/);
        assert.match(err.message, /isn't enrolled as a member/);
        assert.match(err.message, /role member is not permitted/);
        return true;
      },
    );
  });

  it("rejects malformed JSON with the first 200 bytes", async () => {
    const fx = emptyFixture();
    const spawnFake: SshSpawnFn = async () => ({
      stdout: "not json {{{",
      stderr: "",
      exitCode: 0,
      signal: null,
    });
    await assert.rejects(
      requestServerReview({
        reviewServerUrl: "ssh://git@stamp.example.com:22",
        reviewer: "security",
        org: "acme",
        repo: "widget",
        baseSha: BASE,
        headSha: HEAD,
        diff: DIFF,
        manifestYaml: fx.manifestYaml,
        pubkeyByFingerprint: fx.pubkeyByFingerprint,
        _sshSpawnForTest: spawnFake,
      }),
      /malformed JSON/,
    );
  });

  it("rejects when verdict is not in the closed set", async () => {
    const spawnFake: SshSpawnFn = async () => ({
      stdout: JSON.stringify({
        verdict: "maybe",
        prose: "",
        approval: {},
        signature: "x",
      }),
      stderr: "",
      exitCode: 0,
      signal: null,
    });
    await assert.rejects(
      requestServerReview({
        reviewServerUrl: "ssh://git@stamp.example.com:22",
        reviewer: "security",
        org: "acme",
        repo: "widget",
        baseSha: BASE,
        headSha: HEAD,
        diff: DIFF,
        manifestYaml: "keys: {}\n",
        pubkeyByFingerprint: new Map(),
        _sshSpawnForTest: spawnFake,
      }),
      /verdict must be approved/,
    );
  });
});

describe("requestServerReview — signature verification", () => {
  it("rejects when manifest is empty/malformed", async () => {
    const fx = buildSignedFixture({
      reviewer: "security",
      org: "acme",
      repo: "widget",
      baseSha: BASE,
      headSha: HEAD,
      diff: DIFF,
      verdict: "approved",
      prose: "ok",
    });
    const spawnFake: SshSpawnFn = async () => ({
      stdout: fx.responseJson,
      stderr: "",
      exitCode: 0,
      signal: null,
    });
    await assert.rejects(
      requestServerReview({
        reviewServerUrl: "ssh://git@stamp.example.com:22",
        reviewer: "security",
        org: "acme",
        repo: "widget",
        baseSha: BASE,
        headSha: HEAD,
        diff: DIFF,
        // Empty top-level — parseManifest returns null
        manifestYaml: "other: 1\n",
        pubkeyByFingerprint: fx.pubkeyByFingerprint,
        _sshSpawnForTest: spawnFake,
      }),
      /missing or malformed/,
    );
  });

  it("rejects when the signing key isn't in the manifest", async () => {
    const fx = buildSignedFixture({
      reviewer: "security",
      org: "acme",
      repo: "widget",
      baseSha: BASE,
      headSha: HEAD,
      diff: DIFF,
      verdict: "approved",
      prose: "ok",
    });
    const spawnFake: SshSpawnFn = async () => ({
      stdout: fx.responseJson,
      stderr: "",
      exitCode: 0,
      signal: null,
    });
    // Manifest with a different (random) fingerprint listed
    const otherManifest = `
keys:
  unrelated:
    fingerprint: sha256:${"f".repeat(64)}
    capabilities: [server]
`;
    await assert.rejects(
      requestServerReview({
        reviewServerUrl: "ssh://git@stamp.example.com:22",
        reviewer: "security",
        org: "acme",
        repo: "widget",
        baseSha: BASE,
        headSha: HEAD,
        diff: DIFF,
        manifestYaml: otherManifest,
        pubkeyByFingerprint: fx.pubkeyByFingerprint,
        _sshSpawnForTest: spawnFake,
      }),
      /isn't in .stamp\/trusted-keys\/manifest/,
    );
  });

  it("rejects when manifest entry lacks `server` capability", async () => {
    const fx = buildSignedFixture({
      reviewer: "security",
      org: "acme",
      repo: "widget",
      baseSha: BASE,
      headSha: HEAD,
      diff: DIFF,
      verdict: "approved",
      prose: "ok",
    });
    const spawnFake: SshSpawnFn = async () => ({
      stdout: fx.responseJson,
      stderr: "",
      exitCode: 0,
      signal: null,
    });
    // Same fingerprint, wrong capability
    const wrongCapManifest = `
keys:
  not-a-server:
    fingerprint: ${fx.fingerprint}
    capabilities: [admin]
`;
    await assert.rejects(
      requestServerReview({
        reviewServerUrl: "ssh://git@stamp.example.com:22",
        reviewer: "security",
        org: "acme",
        repo: "widget",
        baseSha: BASE,
        headSha: HEAD,
        diff: DIFF,
        manifestYaml: wrongCapManifest,
        pubkeyByFingerprint: fx.pubkeyByFingerprint,
        _sshSpawnForTest: spawnFake,
      }),
      /'server' capability/,
    );
  });

  it("rejects when no .pub file matches the signing fingerprint", async () => {
    const fx = buildSignedFixture({
      reviewer: "security",
      org: "acme",
      repo: "widget",
      baseSha: BASE,
      headSha: HEAD,
      diff: DIFF,
      verdict: "approved",
      prose: "ok",
    });
    const spawnFake: SshSpawnFn = async () => ({
      stdout: fx.responseJson,
      stderr: "",
      exitCode: 0,
      signal: null,
    });
    await assert.rejects(
      requestServerReview({
        reviewServerUrl: "ssh://git@stamp.example.com:22",
        reviewer: "security",
        org: "acme",
        repo: "widget",
        baseSha: BASE,
        headSha: HEAD,
        diff: DIFF,
        manifestYaml: fx.manifestYaml,
        // Empty pubkey map — fingerprint resolves nothing
        pubkeyByFingerprint: new Map(),
        _sshSpawnForTest: spawnFake,
      }),
      /no \.pub file/,
    );
  });

  it("rejects when signature was forged (verify fails)", async () => {
    const fx = buildSignedFixture({
      reviewer: "security",
      org: "acme",
      repo: "widget",
      baseSha: BASE,
      headSha: HEAD,
      diff: DIFF,
      verdict: "approved",
      prose: "ok",
    });
    // Tamper with the response: swap the signature for garbage
    const parsed = JSON.parse(fx.responseJson) as {
      verdict: string;
      prose: string;
      approval: ApprovalV4;
      signature: string;
    };
    const garbage = Buffer.alloc(64, 0).toString("base64");
    const tampered = { ...parsed, signature: garbage };
    const spawnFake: SshSpawnFn = async () => ({
      stdout: JSON.stringify(tampered),
      stderr: "",
      exitCode: 0,
      signal: null,
    });
    await assert.rejects(
      requestServerReview({
        reviewServerUrl: "ssh://git@stamp.example.com:22",
        reviewer: "security",
        org: "acme",
        repo: "widget",
        baseSha: BASE,
        headSha: HEAD,
        diff: DIFF,
        manifestYaml: fx.manifestYaml,
        pubkeyByFingerprint: fx.pubkeyByFingerprint,
        _sshSpawnForTest: spawnFake,
      }),
      /signature failed Ed25519 verification/,
    );
  });
});

describe("requestServerReview — cross-check signed approval vs request", () => {
  it("rejects a signed approval for the wrong reviewer", async () => {
    // Server signs for "security" but the client asked for "standards"
    const fx = buildSignedFixture({
      reviewer: "security",
      org: "acme",
      repo: "widget",
      baseSha: BASE,
      headSha: HEAD,
      diff: DIFF,
      verdict: "approved",
      prose: "ok",
    });
    const spawnFake: SshSpawnFn = async () => ({
      stdout: fx.responseJson,
      stderr: "",
      exitCode: 0,
      signal: null,
    });
    await assert.rejects(
      requestServerReview({
        reviewServerUrl: "ssh://git@stamp.example.com:22",
        reviewer: "standards", // ← asked for standards
        org: "acme",
        repo: "widget",
        baseSha: BASE,
        headSha: HEAD,
        diff: DIFF,
        manifestYaml: fx.manifestYaml,
        pubkeyByFingerprint: fx.pubkeyByFingerprint,
        _sshSpawnForTest: spawnFake,
      }),
      /returned a signed approval for reviewer "security"/,
    );
  });

  it("rejects a signed approval for a different head_sha", async () => {
    const fx = buildSignedFixture({
      reviewer: "security",
      org: "acme",
      repo: "widget",
      baseSha: BASE,
      headSha: HEAD,
      diff: DIFF,
      verdict: "approved",
      prose: "ok",
    });
    const spawnFake: SshSpawnFn = async () => ({
      stdout: fx.responseJson,
      stderr: "",
      exitCode: 0,
      signal: null,
    });
    const wrongHead = "c".repeat(40);
    await assert.rejects(
      requestServerReview({
        reviewServerUrl: "ssh://git@stamp.example.com:22",
        reviewer: "security",
        org: "acme",
        repo: "widget",
        baseSha: BASE,
        headSha: wrongHead,
        diff: DIFF,
        manifestYaml: fx.manifestYaml,
        pubkeyByFingerprint: fx.pubkeyByFingerprint,
        _sshSpawnForTest: spawnFake,
      }),
      /head_sha/,
    );
  });
});
