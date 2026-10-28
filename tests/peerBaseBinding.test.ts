/**
 * AGT-2241 — peer-review author check binds base_sha to the protected branch,
 * and the posted review is pinned to head_sha.
 *
 * Covers:
 *   - verifyPeerAuthorLocal against a real git fixture: revoked-at-tip key
 *     citing a pre-revocation base_sha is rejected; a base_sha on a side
 *     branch (where the manifest was edited) is rejected; a missing
 *     origin/HEAD fails closed; honest events pass.
 *   - runPrListen end-to-end with the REAL verifier: the revoked author's
 *     event is skipped before any seat claim; an honest one is reviewed.
 *   - buildPeerReviewPostArgs + the listener post path carry
 *     `commit_id=<head_sha>` via `gh api .../pulls/<n>/reviews`.
 *   - events missing base_sha/head_sha are skipped; re-review-requested
 *     events go through the same author check.
 */

import { strict as assert } from "node:assert";
import { describe, it, before, after } from "node:test";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import os from "node:os";
import { generateKeyPairSync, createHash, createPublicKey } from "node:crypto";
import { spawnSync } from "node:child_process";

import { verifyPeerAuthorLocal } from "../src/lib/peerOperatorVerify.ts";
import {
  buildPeerReviewPostArgs,
  runPrListen,
  type PrListenOptions,
} from "../src/commands/prListen.ts";
import type { PeerReviewEvent } from "../src/lib/peerReviewEvent.ts";
import type { HttpFetchFn } from "../src/lib/seatClient.ts";
import type { Keypair } from "../src/lib/keys.ts";
import { clearListenerRegistry } from "../src/server/peerReviews.ts";

// ─── helpers ──────────────────────────────────────────────────────────

function genKp(): Keypair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }) as string;
  const der = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" }) as Buffer;
  return { privateKeyPem, publicKeyPem, fingerprint: "sha256:" + createHash("sha256").update(der).digest("hex") };
}

function manifestYaml(entries: Array<{ name: string; fp: string }>): string {
  const lines = ["keys:"];
  for (const e of entries) {
    lines.push(`  ${e.name}:`, `    fingerprint: ${e.fp}`, "    capabilities: [operator]");
  }
  return lines.join("\n") + "\n";
}

interface Fixture {
  dir: string;
  /** Commit where `author` and `other` are both operators. */
  preRevoke: string;
  /** Commit on main after `author` was removed (= origin/HEAD tip). */
  tip: string;
  /** Commit on a side branch off preRevoke that adds `outsider`. */
  sideBranch: string;
  author: Keypair;
  other: Keypair;
  outsider: Keypair;
}

function buildFixture(): Fixture {
  const dir = mkdtempSync(join(os.tmpdir(), "peer-base-binding-"));
  const git = (args: string[]): string => {
    const r = spawnSync("git", args, { cwd: dir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
    return r.stdout.trim();
  };
  const author = genKp();
  const other = genKp();
  const outsider = genKp();
  const manifestDir = join(dir, ".stamp", "trusted-keys");
  const writeManifest = (entries: Array<{ name: string; fp: string }>) =>
    writeFileSync(join(manifestDir, "manifest.yml"), manifestYaml(entries), "utf8");

  git(["init", "-q", "-b", "main"]);
  git(["config", "user.email", "t@t"]);
  git(["config", "user.name", "T"]);
  git(["config", "commit.gpgsign", "false"]);
  mkdirSync(manifestDir, { recursive: true });

  writeManifest([{ name: "author", fp: author.fingerprint }, { name: "other", fp: other.fingerprint }]);
  git(["add", "."]);
  git(["commit", "-q", "-m", "both operators"]);
  const preRevoke = git(["rev-parse", "HEAD"]);

  writeManifest([{ name: "other", fp: other.fingerprint }]);
  git(["commit", "-q", "-am", "revoke author"]);
  const tip = git(["rev-parse", "HEAD"]);

  git(["checkout", "-q", "-b", "side", preRevoke]);
  writeManifest([
    { name: "author", fp: author.fingerprint },
    { name: "other", fp: other.fingerprint },
    { name: "outsider", fp: outsider.fingerprint },
  ]);
  git(["commit", "-q", "-am", "self-add outsider"]);
  const sideBranch = git(["rev-parse", "HEAD"]);
  git(["checkout", "-q", "main"]);

  // Simulate a fetched clone: origin/main at the tip, origin/HEAD → origin/main.
  git(["update-ref", "refs/remotes/origin/main", tip]);
  git(["symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main"]);

  return { dir, preRevoke, tip, sideBranch, author, other, outsider };
}

// ─── verifyPeerAuthorLocal ────────────────────────────────────────────

describe("AGT-2241: verifyPeerAuthorLocal binds base_sha to the protected branch", () => {
  let fx: Fixture;
  before(() => { fx = buildFixture(); });
  after(() => rmSync(fx.dir, { recursive: true, force: true }));

  it("accepts an operator at both base_sha and the protected tip", () => {
    assert.deepEqual(verifyPeerAuthorLocal(fx.dir, fx.preRevoke, fx.other.fingerprint), { ok: true });
    assert.deepEqual(verifyPeerAuthorLocal(fx.dir, fx.tip, fx.other.fingerprint), { ok: true });
  });

  it("rejects a revoked key citing a pre-revocation base_sha", () => {
    const r = verifyPeerAuthorLocal(fx.dir, fx.preRevoke, fx.author.fingerprint);
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /revoked at protected tip/);
  });

  it("rejects a revoked key at the current tip too", () => {
    const r = verifyPeerAuthorLocal(fx.dir, fx.tip, fx.author.fingerprint);
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /not in manifest/);
  });

  it("rejects a base_sha that is not on the protected branch (self-edited manifest)", () => {
    const r = verifyPeerAuthorLocal(fx.dir, fx.sideBranch, fx.outsider.fingerprint);
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /base_sha_not_on_protected_branch/);
  });

  it("rejects a base_sha absent from the local clone", () => {
    const r = verifyPeerAuthorLocal(fx.dir, "0".repeat(40), fx.other.fingerprint);
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /base_sha_not_found/);
  });

  it("rejects a non-SHA base_sha (e.g. a ref name) without touching git", () => {
    const r = verifyPeerAuthorLocal(fx.dir, "main", fx.other.fingerprint);
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /not a full 40-char/);
  });

  it("fails closed when origin/HEAD does not resolve", () => {
    const dir = mkdtempSync(join(os.tmpdir(), "peer-base-binding-nohead-"));
    try {
      spawnSync("git", ["init", "-q", "-b", "main"], { cwd: dir });
      const r = verifyPeerAuthorLocal(dir, fx.tip, fx.other.fingerprint);
      assert.equal(r.ok, false);
      if (!r.ok) assert.match(r.reason, /protected_tip_not_found/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ─── listener harness ─────────────────────────────────────────────────

const REPO = "acme/widget";
const PR_URL = "https://github.com/acme/widget/pull/42";
const HEAD_SHA = "9".repeat(40);

interface RunResult {
  stderr: string;
  claims: number;
  ghArgs: string[][];
  verifyCalls: Array<{ baseSha: string; fp: string }>;
}

async function runListener(
  events: PeerReviewEvent[],
  extra: Partial<PrListenOptions> = {},
): Promise<RunResult> {
  const reviewer = genKp();
  const out: RunResult = { stderr: "", claims: 0, ghArgs: [], verifyCalls: [] };
  const fetchFn: HttpFetchFn = async (url) => {
    if (url.endsWith("/peer/claim-seat")) {
      out.claims++;
      return { status: 200, body: JSON.stringify({ ok: true, seat: 1, patch_id: "a".repeat(40) }) };
    }
    return { status: 200, body: JSON.stringify({ ok: true, released: true }) };
  };
  const opts: PrListenOptions = {
    orgs: ["acme"],
    server: "127.0.0.1:2222",
    _keypairForTest: reviewer,
    _eventQueueForTest: events,
    _fetchForTest: fetchFn,
    _peerWatchRulesForTest: null,
    _appendTripletForTest: () => {},
    _sdkRunnerForTest: async () => "Looks fine.",
    _ghDiffForTest: () => ({ status: 0, stdout: "diff --git a/x b/x\n+1\n", stderr: "" }),
    _ghReviewForTest: (_url, _body, _flag, args) => {
      out.ghArgs.push(args);
      return { status: 0, stderr: "" };
    },
    _setIntervalForTest: () => setTimeout(() => {}, 0) as unknown as ReturnType<typeof setInterval>,
    _cwdForTest: "/tmp",
    // AGT-2248: the repo at base_sha consents to the listener's (default
    // Anthropic) endpoint; tests of the data-flow gate override these.
    _dataFlowAtBaseForTest: () => ({ peer_review_endpoints: ["api.anthropic.com"] }),
    _llmEnvForTest: {},
    ...extra,
  };

  const origWrite = process.stderr.write.bind(process.stderr);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (process.stderr as any).write = (chunk: string | Uint8Array) => {
    out.stderr += typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
    return true;
  };
  const origExit = process.exit.bind(process);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (process as any).exit = (code?: number) => { throw new Error(`process.exit(${code})`); };
  try {
    await runPrListen(opts);
  } catch (err) {
    if (!(err instanceof Error) || !err.message.startsWith("process.exit(0)")) throw err;
  } finally {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process.stderr as any).write = origWrite;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process as any).exit = origExit;
    clearListenerRegistry();
  }
  return out;
}

function prOpened(baseSha: string | null, authorFp: string, headSha: string | null = HEAD_SHA): PeerReviewEvent {
  const payload: Record<string, unknown> = {
    patch_id: "a".repeat(40),
    repo: REPO,
    pr_url: PR_URL,
    requested_by_fp: authorFp,
    title: "t",
    paths_changed: ["x"],
  };
  if (baseSha !== null) payload["base_sha"] = baseSha;
  if (headSha !== null) payload["head_sha"] = headSha;
  return { event_type: "pr-opened", patch_id: "a".repeat(40), actor_fp: authorFp, payload };
}

// ─── listener end-to-end with the real verifier ───────────────────────

describe("AGT-2241: listener uses the protected-branch-bound author check", () => {
  let fx: Fixture;
  before(() => { fx = buildFixture(); });
  after(() => rmSync(fx.dir, { recursive: true, force: true }));

  it("skips a revoked author's event that cites a pre-revocation base_sha (no claim, no post)", async () => {
    const r = await runListener([prOpened(fx.preRevoke, fx.author.fingerprint)], {
      _peerReposMapForTest: new Map([[REPO, fx.dir]]),
    });
    assert.equal(r.claims, 0, r.stderr);
    assert.equal(r.ghArgs.length, 0);
    assert.match(r.stderr, /revoked at protected tip/);
  });

  it("skips an event whose base_sha is on a side branch", async () => {
    const r = await runListener([prOpened(fx.sideBranch, fx.outsider.fingerprint)], {
      _peerReposMapForTest: new Map([[REPO, fx.dir]]),
    });
    assert.equal(r.claims, 0, r.stderr);
    assert.match(r.stderr, /base_sha_not_on_protected_branch/);
  });

  it("reviews an honest event and pins the post to head_sha", async () => {
    const r = await runListener([prOpened(fx.preRevoke, fx.other.fingerprint)], {
      _peerReposMapForTest: new Map([[REPO, fx.dir]]),
    });
    assert.equal(r.claims, 1, r.stderr);
    assert.equal(r.ghArgs.length, 1, r.stderr);
    const args = r.ghArgs[0]!;
    assert.deepEqual(args.slice(0, 4), ["api", "--method", "POST", "repos/acme/widget/pulls/42/reviews"]);
    assert.ok(args.includes(`commit_id=${HEAD_SHA}`), `commit_id missing: ${JSON.stringify(args)}`);
    assert.ok(!args.includes("pr") && !args.includes("review"), "must not use `gh pr review`");
  });
});

// ─── payload shape + re-review ────────────────────────────────────────

describe("AGT-2241: base_sha/head_sha are required and re-review is verified", () => {
  const verifyOk = (calls: Array<{ baseSha: string; fp: string }>) =>
    (_p: string, baseSha: string, fp: string) => { calls.push({ baseSha, fp }); return { ok: true as const }; };

  it("skips an event with no head_sha (cannot pin the review)", async () => {
    const calls: Array<{ baseSha: string; fp: string }> = [];
    const r = await runListener([prOpened("b".repeat(40), "sha256:" + "c".repeat(64), null)], {
      _peerReposMapForTest: new Map([[REPO, "/tmp/x"]]),
      _operatorVerifyForTest: verifyOk(calls),
    });
    assert.equal(r.claims, 0);
    assert.equal(calls.length, 0);
    assert.match(r.stderr, /base_sha\/head_sha missing/);
  });

  it("skips an event with no base_sha instead of falling back to a zero SHA", async () => {
    const calls: Array<{ baseSha: string; fp: string }> = [];
    const r = await runListener([prOpened(null, "sha256:" + "c".repeat(64))], {
      _peerReposMapForTest: new Map([[REPO, "/tmp/x"]]),
      _operatorVerifyForTest: verifyOk(calls),
    });
    assert.equal(r.claims, 0);
    assert.equal(calls.length, 0);
  });

  it("runs the author check on re-review-requested and skips when it fails", async () => {
    const calls: Array<{ baseSha: string; fp: string }> = [];
    const authorFp = "sha256:" + "f".repeat(64);
    const ev: PeerReviewEvent = {
      event_type: "re-review-requested",
      patch_id: "d".repeat(40),
      actor_fp: authorFp,
      payload: {
        patch_id: "d".repeat(40),
        requested_by_fp: authorFp,
        pr_url: PR_URL,
        repo: REPO,
        base_sha: "b".repeat(40),
        head_sha: HEAD_SHA,
        seat: 1,
      },
    };
    const r = await runListener([ev], {
      _peerReposMapForTest: new Map([[REPO, "/tmp/x"]]),
      _operatorVerifyForTest: (_p, baseSha, fp) => {
        calls.push({ baseSha, fp });
        return { ok: false, reason: "revoked at protected tip: test" };
      },
    });
    assert.deepEqual(calls, [{ baseSha: "b".repeat(40), fp: authorFp }]);
    assert.equal(r.claims, 0);
    assert.match(r.stderr, /operator verification failed/);
  });
});

// ─── buildPeerReviewPostArgs ──────────────────────────────────────────

describe("AGT-2241: buildPeerReviewPostArgs", () => {
  const pr = { owner: "acme", repo: "widget", number: 42 };

  it("maps each verdict to the REST event and pins commit_id", () => {
    for (const [verdict, event] of [
      ["approve", "APPROVE"],
      ["request-changes", "REQUEST_CHANGES"],
      ["comment", "COMMENT"],
    ] as const) {
      assert.deepEqual(buildPeerReviewPostArgs(pr, HEAD_SHA, verdict, "body"), [
        "api", "--method", "POST", "repos/acme/widget/pulls/42/reviews",
        "-f", `commit_id=${HEAD_SHA}`,
        "-f", `event=${event}`,
        "-f", "body=body",
      ]);
    }
  });

  it("sends the body as a raw field (an @-prefixed body is not a file read)", () => {
    const args = buildPeerReviewPostArgs(pr, HEAD_SHA, "comment", "@/etc/passwd");
    const i = args.indexOf("body=@/etc/passwd");
    assert.ok(i > 0 && args[i - 1] === "-f", JSON.stringify(args));
  });

  it("refuses a non-SHA head", () => {
    assert.throws(() => buildPeerReviewPostArgs(pr, "HEAD", "approve", "b"), /not a full 40-char/);
  });
});
