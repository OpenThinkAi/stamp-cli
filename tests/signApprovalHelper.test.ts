/**
 * AGT-2263: the review-signing key is root:root 0600 and the git-user
 * review pipeline signs through the root helper `stamp-sign-approval`.
 *
 * Covers:
 *   - validateApprovalPayload: the helper signs ONLY a well-formed,
 *     canonical ApprovalV4 (incl. repo_id) under its own key id with a
 *     fresh issued_at — never arbitrary bytes;
 *   - runSignApproval: signature round-trip, no-argument rule, refusal
 *     exit codes, key posture (mode / symlink) refusal, audit line;
 *   - key posture: foreign owner refused; legacy git-owned re-own;
 *   - the pipeline's production signer: helper via STAMP_SIGN_APPROVAL_ARGV
 *     end to end, helper failure, and a signature that doesn't verify.
 */

import { strict as assert } from "node:assert";
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  verify,
} from "node:crypto";
import {
  chmodSync,
  linkSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import {
  ApprovalPayloadError,
  MAX_APPROVAL_PAYLOAD_BYTES,
  validateApprovalPayload,
} from "../src/lib/approvalSigning.ts";
import { type ApprovalV4, canonicalSerializeApproval } from "../src/lib/attestationV4.ts";
import { fingerprintFromPem } from "../src/lib/keys.ts";
import {
  assertPrivateKeyPosture,
  lookupGitUid,
  reownLegacyGitOwnedKeyFiles,
  ReviewSigningKeyError,
} from "../src/lib/reviewSigningKey.ts";
import { runSignApproval } from "../src/lib/signApprovalHelper.ts";
import {
  DEFAULT_SIGN_APPROVAL_ARGV,
  helperApprovalSignerFromEnv,
  resolveSignApprovalArgv,
  runReviewPipeline,
  SigningKeyUnavailableError,
} from "../src/server/reviewPipeline.ts";
import type { AnthropicClientShape } from "../src/lib/headlessReviewer.ts";
import type { UserRow } from "../src/lib/serverDb.ts";
import { parseOriginalCommand, VERB_POLICIES } from "../src/lib/sshGate.ts";

const SIGN_APPROVAL_TS = path.resolve(
  import.meta.dirname,
  "..",
  "src",
  "server",
  "sign-approval.ts",
);

interface KeyFixture {
  dir: string;
  keyPath: string;
  pubPath: string;
  publicPem: string;
  fingerprint: string;
  cleanup: () => void;
}

function mintKeyFiles(): KeyFixture {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-sign-approval-"));
  const keyPath = path.join(dir, "review-signing-key.pem");
  const pubPath = path.join(dir, "review-signing-key.pub");
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicPem = publicKey.export({ type: "spki", format: "pem" }) as string;
  writeFileSync(keyPath, privateKey.export({ type: "pkcs8", format: "pem" }) as string, {
    mode: 0o600,
  });
  chmodSync(keyPath, 0o600);
  writeFileSync(pubPath, publicPem, { mode: 0o644 });
  return {
    dir,
    keyPath,
    pubPath,
    publicPem,
    fingerprint: fingerprintFromPem(publicPem),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

const NOW = new Date("2026-10-28T12:00:00Z");

function approval(keyId: string, over: Partial<Record<string, unknown>> = {}): Record<string, unknown> {
  return {
    reviewer: "security",
    verdict: "approved",
    prompt_sha256: "a".repeat(64),
    diff_sha256: "b".repeat(64),
    base_sha: "0123456789abcdef0123456789abcdef01234567",
    head_sha: "fedcba9876543210fedcba9876543210fedcba98",
    issued_at: "2026-10-28T12:00:00Z",
    server_key_id: keyId,
    repo_id: "acme/widget-co",
    ...over,
  };
}

function canonical(obj: Record<string, unknown>): Buffer {
  return canonicalSerializeApproval(obj as unknown as ApprovalV4);
}

const KEY_ID = "sha256:" + "c".repeat(64);

describe("validateApprovalPayload — what the root helper will sign (AGT-2263)", () => {
  it("accepts a canonical, well-formed approval under its own key id", () => {
    const bytes = canonical(approval(KEY_ID));
    const { approval: a, canonical: c } = validateApprovalPayload(bytes, {
      expectedKeyId: KEY_ID,
      now: NOW,
    });
    assert.equal(a.repo_id, "acme/widget-co");
    assert.ok(c.equals(bytes));
  });

  const refusals: Array<[string, Buffer]> = [
    ["arbitrary bytes", Buffer.from("please sign me")],
    ["empty input", Buffer.alloc(0)],
    ["a JSON array", Buffer.from("[1,2]")],
    ["an extra key", canonical(approval(KEY_ID, { extra: "x" }))],
    ["a missing repo_id", canonical((() => { const o = approval(KEY_ID); delete o.repo_id; return o; })())],
    ["another key's server_key_id", canonical(approval("sha256:" + "d".repeat(64)))],
    ["an issued_at 10 minutes in the past", canonical(approval(KEY_ID, { issued_at: "2026-10-28T11:50:00Z" }))],
    ["an issued_at 10 minutes in the future", canonical(approval(KEY_ID, { issued_at: "2026-10-28T12:10:00Z" }))],
    ["an issued_at with milliseconds", canonical(approval(KEY_ID, { issued_at: "2026-10-28T12:00:00.000Z" }))],
    ["an impossible date", canonical(approval(KEY_ID, { issued_at: "2026-13-28T12:00:00Z" }))],
    ["an unknown verdict", canonical(approval(KEY_ID, { verdict: "lgtm" }))],
    ["a short base_sha", canonical(approval(KEY_ID, { base_sha: "abc123" }))],
    ["an uppercase diff_sha256", canonical(approval(KEY_ID, { diff_sha256: "B".repeat(64) }))],
    ["a malformed repo_id", canonical(approval(KEY_ID, { repo_id: "acme/widget/x" }))],
    ["a bad reviewer name", canonical(approval(KEY_ID, { reviewer: "../x" }))],
    ["a non-string field", canonical(approval(KEY_ID, { verdict: 1 }))],
    // Same object, not canonical bytes: unsorted keys / extra whitespace.
    ["non-canonical key order", Buffer.from(JSON.stringify(approval(KEY_ID)))],
    ["non-canonical whitespace", Buffer.from(JSON.stringify(JSON.parse(canonical(approval(KEY_ID)).toString()), null, 1))],
    ["an oversize payload", Buffer.alloc(MAX_APPROVAL_PAYLOAD_BYTES + 1, 0x20)],
  ];
  for (const [what, bytes] of refusals) {
    it(`refuses ${what}`, () => {
      assert.throws(
        () => validateApprovalPayload(bytes, { expectedKeyId: KEY_ID, now: NOW }),
        ApprovalPayloadError,
      );
    });
  }
});

describe("runSignApproval — helper core", () => {
  let fx: KeyFixture;
  beforeEach(() => {
    fx = mintKeyFiles();
  });
  afterEach(() => fx.cleanup());

  function run(stdin: Buffer, argv: string[] = []) {
    let out = "";
    let err = "";
    const audit: string[] = [];
    const code = runSignApproval({
      argv,
      stdin,
      privateKeyPath: fx.keyPath,
      now: NOW,
      out: (s) => (out += s),
      err: (s) => (err += s),
      audit: (l) => audit.push(l),
    });
    return { code, out, err, audit };
  }

  it("signs a valid approval; stdout is only the signature, which verifies", () => {
    const bytes = canonical(approval(fx.fingerprint));
    const r = run(bytes);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /^[A-Za-z0-9+/]{86}==\n$/);
    const ok = verify(
      null,
      bytes,
      createPublicKey(fx.publicPem),
      Buffer.from(r.out.trim(), "base64"),
    );
    assert.ok(ok);
    assert.equal(r.audit.length, 1);
    assert.match(r.audit[0]!, /signed reviewer=security verdict=approved repo_id=acme\/widget-co/);
  });

  it("refuses any argument (exit 2)", () => {
    const r = run(canonical(approval(fx.fingerprint)), ["--anything"]);
    assert.equal(r.code, 2);
    assert.equal(r.out, "");
  });

  it("refuses a non-approval payload (exit 2, nothing on stdout)", () => {
    const r = run(Buffer.from('{"msg":"sign me"}'));
    assert.equal(r.code, 2);
    assert.equal(r.out, "");
    assert.match(r.err, /refusing to sign/);
    assert.equal(r.audit.length, 0);
  });

  it("refuses a group-readable key (exit 1)", () => {
    chmodSync(fx.keyPath, 0o640);
    const r = run(canonical(approval(fx.fingerprint)));
    assert.equal(r.code, 1);
    assert.match(r.err, /mode 0640/);
  });

  it("refuses a key with a second hard link (exit 1)", () => {
    linkSync(fx.keyPath, path.join(fx.dir, "planted-link"));
    const r = run(canonical(approval(fx.fingerprint)));
    assert.equal(r.code, 1);
    assert.match(r.err, /2 hard links/);
    // ...and the legacy re-own never touches it either.
    const calls: string[] = [];
    reownLegacyGitOwnedKeyFiles({
      privateKeyPath: fx.keyPath,
      gitUid: process.getuid!(),
      chown: (p) => void calls.push(p),
    });
    assert.deepEqual(calls, [fx.pubPath]);
  });

  it("refuses a symlinked key (exit 1)", () => {
    const link = path.join(fx.dir, "link.pem");
    symlinkSync(fx.keyPath, link);
    let err = "";
    const code = runSignApproval({
      argv: [],
      stdin: canonical(approval(fx.fingerprint)),
      privateKeyPath: link,
      now: NOW,
      out: () => {},
      err: (s) => (err += s),
    });
    assert.equal(code, 1);
    assert.match(err, /not a regular file/);
  });
});

describe("review-signing key posture (AGT-2263)", () => {
  it("assertPrivateKeyPosture refuses a key owned by another uid", () => {
    const fx = mintKeyFiles();
    try {
      const st = lstatSync(fx.keyPath);
      const foreign = Object.assign(Object.create(Object.getPrototypeOf(st)), st, {
        uid: st.uid + 1,
      });
      assert.throws(
        () => assertPrivateKeyPosture(fx.keyPath, foreign),
        (e: unknown) => e instanceof ReviewSigningKeyError && /owned by uid/.test(e.message),
      );
      assert.doesNotThrow(() => assertPrivateKeyPosture(fx.keyPath, st));
    } finally {
      fx.cleanup();
    }
  });

  it("reownLegacyGitOwnedKeyFiles re-owns a git-owned .pem and .pub to root, nothing else", () => {
    const fx = mintKeyFiles();
    try {
      const myUid = process.getuid!();
      const calls: Array<[string, number, number]> = [];
      const chown = (p: string, u: number, g: number) => void calls.push([p, u, g]);
      // Treat the test user as "git": both files are in the legacy state.
      assert.deepEqual(
        reownLegacyGitOwnedKeyFiles({ privateKeyPath: fx.keyPath, gitUid: myUid, chown }),
        [fx.keyPath, fx.pubPath],
      );
      assert.deepEqual(calls, [
        [fx.keyPath, 0, 0],
        [fx.pubPath, 0, 0],
      ]);
      // A different owner is not the legacy state: left alone.
      calls.length = 0;
      assert.deepEqual(
        reownLegacyGitOwnedKeyFiles({ privateKeyPath: fx.keyPath, gitUid: myUid + 1, chown }),
        [],
      );
      // A symlink is never followed or re-owned.
      const link = path.join(fx.dir, "link.pem");
      symlinkSync(fx.keyPath, link);
      assert.deepEqual(
        reownLegacyGitOwnedKeyFiles({ privateKeyPath: link, gitUid: myUid, chown }),
        [],
      );
      assert.equal(calls.length, 0);
    } finally {
      fx.cleanup();
    }
  });

  it("lookupGitUid reads the git account's uid from a passwd file", () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-passwd-"));
    try {
      const p = path.join(dir, "passwd");
      writeFileSync(p, "root:x:0:0:root:/root:/bin/sh\ngit:x:1000:1000::/home/git:/usr/bin/git-shell\n");
      assert.equal(lookupGitUid(p), 1000);
      writeFileSync(p, "root:x:0:0:root:/root:/bin/sh\n");
      assert.equal(lookupGitUid(p), null);
      assert.equal(lookupGitUid(path.join(dir, "missing")), null);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("pipeline signs via the root helper, never by loading the key", () => {
  let fx: KeyFixture;
  const saved: Record<string, string | undefined> = {};
  const ENV_KEYS = ["REVIEW_SIGNING_KEY_PATH", "STAMP_SIGN_APPROVAL_ARGV"];
  beforeEach(() => {
    fx = mintKeyFiles();
    for (const k of ENV_KEYS) saved[k] = process.env[k];
    process.env["REVIEW_SIGNING_KEY_PATH"] = fx.keyPath;
    process.env["STAMP_SIGN_APPROVAL_ARGV"] = JSON.stringify([
      process.execPath,
      "--import",
      "tsx",
      SIGN_APPROVAL_TS,
    ]);
  });
  afterEach(() => {
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    fx.cleanup();
  });

  it("defaults to `sudo -n /usr/local/sbin/stamp-sign-approval`", () => {
    delete process.env["STAMP_SIGN_APPROVAL_ARGV"];
    assert.deepEqual(resolveSignApprovalArgv(), [...DEFAULT_SIGN_APPROVAL_ARGV]);
    assert.deepEqual(DEFAULT_SIGN_APPROVAL_ARGV, [
      "sudo",
      "-n",
      "/usr/local/sbin/stamp-sign-approval",
    ]);
  });

  it("rejects a malformed STAMP_SIGN_APPROVAL_ARGV", () => {
    process.env["STAMP_SIGN_APPROVAL_ARGV"] = "node helper.js";
    assert.throws(() => resolveSignApprovalArgv(), SigningKeyUnavailableError);
    process.env["STAMP_SIGN_APPROVAL_ARGV"] = "[]";
    assert.throws(() => resolveSignApprovalArgv(), SigningKeyUnavailableError);
  });

  it("runReviewPipeline end to end: fingerprint from .pub, signature from the helper", async () => {
    const cacheRoot = mkdtempSync(path.join(os.tmpdir(), "stamp-pipeline-helper-"));
    try {
      writeFileSync(path.join(cacheRoot, "security.md"), "# security\n");
      const diff = Buffer.from("diff --git a/x b/x\n");
      const anthropic: AnthropicClientShape = {
        messages: {
          create: async () =>
            ({
              content: [
                {
                  type: "tool_use",
                  id: "t1",
                  name: "submit_verdict",
                  input: { verdict: "approved", prose: "fine" },
                },
              ],
              stop_reason: "tool_use",
            }) as never,
        },
      };
      const caller: UserRow = {
        id: 1,
        short_name: "c",
        ssh_pubkey: "ssh-ed25519 AAAA c@h",
        ssh_fp: "SHA256:c",
        role: "member",
        source: "env",
        created_at: "2026-01-01T00:00:00Z",
      };
      const result = await runReviewPipeline({
        diff,
        params: {
          reviewer: "security",
          org: "acme",
          repo: "widget-co",
          baseSha: "0123456789abcdef0123456789abcdef01234567",
          headSha: "fedcba9876543210fedcba9876543210fedcba98",
          diffSha256: createHash("sha256").update(diff).digest("hex"),
        },
        caller,
        deps: {
          promptResolver: (r) => path.join(cacheRoot, `${r}.md`),
          anthropic,
        },
      });
      assert.equal(result.approval.server_key_id, fx.fingerprint);
      assert.equal(result.approval.verdict, "approved");
      assert.ok(
        verify(
          null,
          canonicalSerializeApproval(result.approval),
          createPublicKey(fx.publicPem),
          Buffer.from(result.signature, "base64"),
        ),
      );
    } finally {
      rmSync(cacheRoot, { recursive: true, force: true });
    }
  });

  it("surfaces a helper refusal as SigningKeyUnavailableError", async () => {
    chmodSync(fx.keyPath, 0o644); // helper refuses: wrong mode
    const signer = helperApprovalSignerFromEnv();
    const bytes = canonical(
      approval(fx.fingerprint, {
        issued_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
      }),
    );
    await assert.rejects(signer.signApproval(bytes), (e: unknown) =>
      e instanceof SigningKeyUnavailableError &&
      /exited 1: review-signing key/.test(e.message) &&
      /mode 0644/.test(e.message),
    );
  });

  it("rejects a helper signature that does not verify against the .pub", async () => {
    // A "helper" that prints a well-formed signature by some other key.
    const other = generateKeyPairSync("ed25519");
    const bogus = path.join(fx.dir, "bogus.cjs");
    writeFileSync(
      bogus,
      `const c=require("node:crypto");const k=c.createPrivateKey(${JSON.stringify(
        other.privateKey.export({ type: "pkcs8", format: "pem" }),
      )});let b=[];process.stdin.on("data",d=>b.push(d));process.stdin.on("end",()=>process.stdout.write(c.sign(null,Buffer.concat(b),k).toString("base64")+"\\n"));`,
    );
    process.env["STAMP_SIGN_APPROVAL_ARGV"] = JSON.stringify([process.execPath, bogus]);
    const signer = helperApprovalSignerFromEnv();
    await assert.rejects(
      signer.signApproval(canonical(approval(fx.fingerprint))),
      (e: unknown) => e instanceof SigningKeyUnavailableError && /does not verify/.test(e.message),
    );
  });

  it("fails fast when the .pub is missing", () => {
    rmSync(fx.pubPath);
    assert.throws(() => helperApprovalSignerFromEnv(), (e: unknown) =>
      e instanceof SigningKeyUnavailableError && /public key not found/.test(e.message),
    );
  });
});

describe("stamp-sign-approval is a helper, not an SSH verb", () => {
  it("is absent from stamp-gate's verb allowlist and from git-shell-commands", () => {
    assert.equal(Object.hasOwn(VERB_POLICIES, "stamp-sign-approval"), false);
    for (const cmd of ["stamp-sign-approval", "/usr/local/sbin/stamp-sign-approval"]) {
      assert.equal(parseOriginalCommand(cmd).ok, false, cmd);
    }
    const dockerfile = readFileSync(
      path.resolve(import.meta.dirname, "..", "server", "Dockerfile"),
      "utf8",
    );
    assert.doesNotMatch(dockerfile, /git-shell-commands\/stamp-sign-approval/);
  });

  it("sudoers admits it with no arguments only", () => {
    const sudoers = readFileSync(
      path.resolve(import.meta.dirname, "..", "server", "sudoers.d-stamp"),
      "utf8",
    );
    const rules = sudoers.split("\n").filter((l) => /stamp-sign-approval/.test(l) && !l.startsWith("#"));
    assert.deepEqual(rules, ['git ALL=(root) NOPASSWD: /usr/local/sbin/stamp-sign-approval ""']);
  });
});
