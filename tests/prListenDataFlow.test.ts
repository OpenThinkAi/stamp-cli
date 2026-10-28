/**
 * AGT-2248 (folds AGT-2244, AGT-2257) — the peer listener honours the target
 * repo's committed `data_flow` consent before ANY LLM call, and reviews the
 * diff at exactly base_sha...head_sha.
 *
 * Covers:
 *   - config: `data_flow.peer_review_endpoints` parse/validation.
 *   - resolvePeerLlmEndpoint: default Anthropic, ANTHROPIC_BASE_URL (hosted
 *     and loopback), cloud routing → unpinnable.
 *   - checkPeerDataFlow: fail-closed matrix (absent list, other host,
 *     require_confirmation unconfirmed, loopback carve-out).
 *   - runPrListen: no consent → skipped before triage (no Haiku call, no
 *     seat claim, no diff fetch, no review); consent → proceeds and prints
 *     the off-host marker; unreadable config → skipped; config read from a
 *     REAL git clone at base_sha (not the working tree).
 *   - diff fetch: compare API at base...head; an unresolvable head_sha
 *     (GitHub 404) refuses the review and releases the seat.
 *
 * No real model, gh, server or network is touched: every boundary is a seam.
 */

import { strict as assert } from "node:assert";
import { describe, it, before, after } from "node:test";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import os from "node:os";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync, createHash, createPublicKey } from "node:crypto";

import {
  buildPeerDiffFetchArgs,
  runPrListen,
  type PrListenOptions,
} from "../src/commands/prListen.ts";
import {
  checkPeerDataFlow,
  formatPeerEgressMarker,
  resolvePeerLlmEndpoint,
} from "../src/lib/dataFlow.ts";
import { parseConfigFromYaml, type DataFlowConfig } from "../src/lib/config.ts";
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

const REPO = "acme/widget";
const PR_URL = "https://github.com/acme/widget/pull/42";
const BASE_SHA = "b".repeat(40);
const HEAD_SHA = "9".repeat(40);
const ANTHROPIC = resolvePeerLlmEndpoint({});

const MIN_CONFIG = `branches:
  main:
    required: [security]
reviewers:
  security:
    prompt: .stamp/reviewers/security.md
`;

interface RunResult {
  stderr: string;
  claims: number;
  releases: number;
  haikuCalls: number;
  sdkDiffs: string[];
  diffArgs: string[][];
  posts: number;
  dataFlowReads: Array<{ path: string; ref: string }>;
}

async function runListener(
  events: PeerReviewEvent[],
  extra: Partial<PrListenOptions> = {},
): Promise<RunResult> {
  const out: RunResult = {
    stderr: "", claims: 0, releases: 0, haikuCalls: 0, sdkDiffs: [], diffArgs: [], posts: 0, dataFlowReads: [],
  };
  const fetchFn: HttpFetchFn = async (url) => {
    if (url.endsWith("/peer/claim-seat")) {
      out.claims++;
      return { status: 200, body: JSON.stringify({ ok: true, seat: 1, patch_id: "a".repeat(40) }) };
    }
    if (url.endsWith("/peer/release-seat")) out.releases++;
    return { status: 200, body: JSON.stringify({ ok: true, released: true }) };
  };
  const opts: PrListenOptions = {
    orgs: ["acme"],
    server: "127.0.0.1:2222",
    _keypairForTest: genKp(),
    _eventQueueForTest: events,
    _fetchForTest: fetchFn,
    _envForTest: { CLAUDECODE: "1", CLAUDE_CODE_SESSION_ID: "deadbeef-cafe-babe-abcd-000000000000" },
    _llmEnvForTest: {},
    // Rules present → the Haiku triage call runs (through the seam), so a
    // test can assert it was NOT reached when the gate refuses.
    _peerWatchRulesForTest: { rules: "claim everything", hash: "h" },
    _haikuRunnerForTest: async () => {
      out.haikuCalls++;
      return JSON.stringify({ claim_seat: "if_available", post_mode: "auto-post", prompt: "default" });
    },
    _appendTripletForTest: () => {},
    _sdkRunnerForTest: async (diff) => { out.sdkDiffs.push(diff); return "Looks fine."; },
    _ghDiffForTest: (_url, args) => {
      out.diffArgs.push(args);
      return { status: 0, stdout: "diff --git a/x b/x\n+1\n", stderr: "" };
    },
    _ghReviewForTest: () => { out.posts++; return { status: 0, stderr: "" }; },
    _setIntervalForTest: () => setTimeout(() => {}, 0) as unknown as ReturnType<typeof setInterval>,
    _cwdForTest: "/tmp",
    _peerReposMapForTest: new Map([[REPO, "/tmp/fake-acme-widget"]]),
    _operatorVerifyForTest: () => ({ ok: true as const }),
    ...extra,
  };
  if (opts._dataFlowAtRefForTest) {
    const inner = opts._dataFlowAtRefForTest;
    opts._dataFlowAtRefForTest = (path, ref) => {
      out.dataFlowReads.push({ path, ref });
      return inner(path, ref);
    };
  }

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

function prOpened(baseSha = BASE_SHA, headSha = HEAD_SHA): PeerReviewEvent {
  return {
    event_type: "pr-opened",
    patch_id: "a".repeat(40),
    actor_fp: "sha256:" + "c".repeat(64),
    payload: {
      patch_id: "a".repeat(40),
      pr_number: 42,
      repo: REPO,
      pr_url: PR_URL,
      requested_by_fp: "sha256:" + "c".repeat(64),
      base_sha: baseSha,
      head_sha: headSha,
      title: "Secret project codename",
      paths_changed: ["src/x.ts"],
    },
  };
}

function assertNothingLeft(r: RunResult): void {
  assert.equal(r.haikuCalls, 0, `triage must not run: ${r.stderr}`);
  assert.equal(r.claims, 0, "no seat claim");
  assert.equal(r.diffArgs.length, 0, "no diff fetch");
  assert.equal(r.sdkDiffs.length, 0, "no review call");
  assert.equal(r.posts, 0, "no post");
}

// ─── config parsing ───────────────────────────────────────────────────

describe("AGT-2248: data_flow.peer_review_endpoints config", () => {
  it("parses and lowercases a host list", () => {
    const cfg = parseConfigFromYaml(
      MIN_CONFIG + `data_flow:\n  peer_review_endpoints: [API.Anthropic.com, "llm.corp.test:8443"]\n`,
    );
    assert.deepEqual(cfg.data_flow?.peer_review_endpoints, ["api.anthropic.com", "llm.corp.test:8443"]);
  });

  it("rejects a URL entry (hosts, not URLs)", () => {
    assert.throws(
      () => parseConfigFromYaml(MIN_CONFIG + `data_flow:\n  peer_review_endpoints: ["https://api.anthropic.com"]\n`),
      /not a host or host:port/,
    );
  });

  it("rejects a non-list value", () => {
    assert.throws(
      () => parseConfigFromYaml(MIN_CONFIG + `data_flow:\n  peer_review_endpoints: api.anthropic.com\n`),
      /must be a list/,
    );
  });
});

// ─── endpoint resolution ──────────────────────────────────────────────

describe("AGT-2248: resolvePeerLlmEndpoint keys on the endpoint", () => {
  it("defaults to api.anthropic.com, off-host", () => {
    assert.deepEqual(ANTHROPIC, { label: "https://api.anthropic.com", host: "api.anthropic.com", offHost: true });
  });

  it("honours a hosted ANTHROPIC_BASE_URL", () => {
    const e = resolvePeerLlmEndpoint({ ANTHROPIC_BASE_URL: "https://Gateway.Corp.test:8443/v1" });
    assert.equal(e.host, "gateway.corp.test:8443");
    assert.equal(e.offHost, true);
  });

  it("treats a loopback ANTHROPIC_BASE_URL as on-host", () => {
    assert.equal(resolvePeerLlmEndpoint({ ANTHROPIC_BASE_URL: "http://127.0.0.1:8000" }).offHost, false);
  });

  it("cannot pin Bedrock/Vertex routing to a host", () => {
    const e = resolvePeerLlmEndpoint({ CLAUDE_CODE_USE_BEDROCK: "1" });
    assert.equal(e.host, null);
    assert.equal(e.offHost, true);
  });
});

// ─── gate decision ────────────────────────────────────────────────────

describe("AGT-2248: checkPeerDataFlow fails closed", () => {
  it("refuses when the repo has no data_flow block", () => {
    const r = checkPeerDataFlow(undefined, ANTHROPIC);
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /add "api\.anthropic\.com" to data_flow\.peer_review_endpoints/);
  });

  it("refuses a disclosure-only block (no endpoint consent)", () => {
    assert.equal(checkPeerDataFlow({ disclosure: "goes to Anthropic" }, ANTHROPIC).ok, false);
  });

  it("refuses when only a different endpoint is listed", () => {
    assert.equal(checkPeerDataFlow({ peer_review_endpoints: ["api.openai.com"] }, ANTHROPIC).ok, false);
  });

  it("allows the listed endpoint", () => {
    assert.deepEqual(checkPeerDataFlow({ peer_review_endpoints: ["api.anthropic.com"] }, ANTHROPIC), { ok: true });
  });

  it("refuses when require_confirmation is armed but not confirmed, even if listed", () => {
    const r = checkPeerDataFlow(
      { require_confirmation: true, peer_review_endpoints: ["api.anthropic.com"] },
      ANTHROPIC,
    );
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /require_confirmation/);
    assert.equal(
      checkPeerDataFlow(
        { require_confirmation: true, confirmed: true, peer_review_endpoints: ["api.anthropic.com"] },
        ANTHROPIC,
      ).ok,
      true,
    );
  });

  it("refuses an unpinnable endpoint whatever is listed", () => {
    const e = resolvePeerLlmEndpoint({ CLAUDE_CODE_USE_VERTEX: "true" });
    assert.equal(checkPeerDataFlow({ peer_review_endpoints: ["api.anthropic.com"] }, e).ok, false);
  });

  it("allows a loopback endpoint with no consent (nothing leaves the host)", () => {
    const e = resolvePeerLlmEndpoint({ ANTHROPIC_BASE_URL: "http://localhost:8000" });
    assert.deepEqual(checkPeerDataFlow({ require_confirmation: true }, e), { ok: true });
  });

  it("marker names what leaves and where", () => {
    const m = formatPeerEgressMarker("PR #42", REPO, ANTHROPIC);
    assert.match(m, /title, changed paths and diff sent off-host to api\.anthropic\.com/);
  });
});

// ─── listener end to end ──────────────────────────────────────────────

describe("AGT-2248: listener refuses without consent for its endpoint", () => {
  it("skips before triage when the repo's data_flow lists no endpoints", async () => {
    const r = await runListener([prOpened()], { _dataFlowAtRefForTest: () => undefined });
    assertNothingLeft(r);
    assert.match(
      r.stderr,
      /skipping event for acme\/widget PR #42 — data-flow gate: at base_sha: the repo has not consented to peer LLM review at api\.anthropic\.com/,
    );
    assert.deepEqual(r.dataFlowReads, [{ path: "/tmp/fake-acme-widget", ref: BASE_SHA }]);
  });

  it("skips when base_sha consents but the protected tip has withdrawn consent", async () => {
    const r = await runListener([prOpened()], {
      _dataFlowAtRefForTest: (_p, ref) =>
        ref === BASE_SHA ? { peer_review_endpoints: ["api.anthropic.com"] } : undefined,
    });
    assertNothingLeft(r);
    assert.match(r.stderr, /data-flow gate: at protected tip: the repo has not consented/);
    assert.deepEqual(
      r.dataFlowReads.map((x) => x.ref),
      [BASE_SHA, "refs/remotes/origin/HEAD"],
    );
  });

  it("skips when the repo consents to a different endpoint than the listener's", async () => {
    const r = await runListener([prOpened()], {
      _dataFlowAtRefForTest: () => ({ peer_review_endpoints: ["api.anthropic.com"] }),
      _llmEnvForTest: { ANTHROPIC_BASE_URL: "https://gateway.corp.test" },
    });
    assertNothingLeft(r);
    assert.match(r.stderr, /not consented to peer LLM review at gateway\.corp\.test/);
  });

  it("skips when require_confirmation is armed without confirmed", async () => {
    const r = await runListener([prOpened()], {
      _dataFlowAtRefForTest: () => ({ require_confirmation: true, peer_review_endpoints: ["api.anthropic.com"] }),
    });
    assertNothingLeft(r);
    assert.match(r.stderr, /require_confirmation is set/);
  });

  it("skips when .stamp/config.yml at base_sha cannot be read", async () => {
    const r = await runListener([prOpened()], {
      _dataFlowAtRefForTest: () => { throw new Error("fatal: path '.stamp/config.yml' does not exist"); },
    });
    assertNothingLeft(r);
    assert.match(r.stderr, /data-flow gate: cannot read or parse \.stamp\/config\.yml at base_sha bbbbbbbbbbbb/);
  });

  it("re-review-requested events are gated too", async () => {
    const ev = { ...prOpened(), event_type: "re-review-requested" } as PeerReviewEvent;
    const r = await runListener([ev], { _dataFlowAtRefForTest: () => undefined });
    assertNothingLeft(r);
  });
});

describe("AGT-2248: listener proceeds with consent", () => {
  // These assert on the marker/disclosure text, which
  // STAMP_SUPPRESS_LLM_NOTICE=1 silences. `stamp merge` runs checks with the
  // caller's env, and agent loops export that flag, so pin it unset here.
  let savedSuppress: string | undefined;
  before(() => {
    savedSuppress = process.env.STAMP_SUPPRESS_LLM_NOTICE;
    delete process.env.STAMP_SUPPRESS_LLM_NOTICE;
  });
  after(() => {
    if (savedSuppress === undefined) delete process.env.STAMP_SUPPRESS_LLM_NOTICE;
    else process.env.STAMP_SUPPRESS_LLM_NOTICE = savedSuppress;
  });

  it("triages, reviews and posts when the endpoint is listed, printing the marker", async () => {
    const r = await runListener([prOpened()], {
      _dataFlowAtRefForTest: () => ({
        disclosure: "Peer reviews go to Anthropic.",
        peer_review_endpoints: ["api.anthropic.com"],
      }),
    });
    assert.equal(r.haikuCalls, 1, r.stderr);
    assert.equal(r.claims, 1, r.stderr);
    assert.equal(r.sdkDiffs.length, 1, r.stderr);
    assert.equal(r.posts, 1, r.stderr);
    assert.match(r.stderr, /acme\/widget PR #42: title, changed paths and diff sent off-host to api\.anthropic\.com/);
    assert.match(r.stderr, /Peer reviews go to Anthropic\./);
  });

  it("proceeds with no consent when the model is on this host", async () => {
    const r = await runListener([prOpened()], {
      _dataFlowAtRefForTest: () => undefined,
      _llmEnvForTest: { ANTHROPIC_BASE_URL: "http://127.0.0.1:8000" },
    });
    assert.equal(r.posts, 1, r.stderr);
    assert.match(r.stderr, /content stays on this host/);
  });
});

// ─── config read from a real clone at base_sha ────────────────────────

function git(cwd: string, ...args: string[]): string {
  const r = spawnSync("git", args, { cwd, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
  return r.stdout.trim();
}

describe("AGT-2248: data_flow is read from the mapped clone at base_sha and the protected tip", () => {
  let dir: string;
  let noConsent: string;
  let consent: string;
  let revoked: string;
  const setTip = (sha: string) => git(dir, "update-ref", "refs/remotes/origin/main", sha);
  before(() => {
    dir = mkdtempSync(join(os.tmpdir(), "peer-data-flow-"));
    git(dir, "init", "-q", "-b", "main");
    git(dir, "config", "user.email", "t@example.test");
    git(dir, "config", "user.name", "t");
    git(dir, "config", "commit.gpgsign", "false");
    mkdirSync(join(dir, ".stamp"));
    writeFileSync(join(dir, ".stamp", "config.yml"), MIN_CONFIG);
    git(dir, "add", ".");
    git(dir, "commit", "-q", "-m", "no consent");
    noConsent = git(dir, "rev-parse", "HEAD");
    writeFileSync(
      join(dir, ".stamp", "config.yml"),
      MIN_CONFIG + "data_flow:\n  peer_review_endpoints: [api.anthropic.com]\n",
    );
    git(dir, "commit", "-q", "-am", "consent");
    consent = git(dir, "rev-parse", "HEAD");
    writeFileSync(join(dir, ".stamp", "config.yml"), MIN_CONFIG);
    git(dir, "commit", "-q", "-am", "withdraw consent");
    revoked = git(dir, "rev-parse", "HEAD");
    // The working tree claims consent; the gate must ignore it.
    writeFileSync(
      join(dir, ".stamp", "config.yml"),
      MIN_CONFIG + "data_flow:\n  peer_review_endpoints: [api.anthropic.com]\n",
    );
    setTip(consent);
    git(dir, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main");
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("refuses an event whose base_sha predates the consent commit", async () => {
    setTip(consent);
    const r = await runListener([prOpened(noConsent)], { _peerReposMapForTest: new Map([[REPO, dir]]) });
    assertNothingLeft(r);
    assert.match(r.stderr, /at base_sha: the repo has not consented to peer LLM review at api\.anthropic\.com/);
  });

  it("proceeds when base_sha and the protected tip both carry the consent", async () => {
    setTip(consent);
    const r = await runListener([prOpened(consent)], { _peerReposMapForTest: new Map([[REPO, dir]]) });
    assert.equal(r.posts, 1, r.stderr);
  });

  it("refuses an old consenting base_sha once the protected tip withdrew consent", async () => {
    setTip(revoked);
    try {
      const r = await runListener([prOpened(consent)], { _peerReposMapForTest: new Map([[REPO, dir]]) });
      assertNothingLeft(r);
      assert.match(r.stderr, /at protected tip: the repo has not consented/);
    } finally {
      setTip(consent);
    }
  });

  it("refuses when origin/HEAD does not resolve", async () => {
    const bare = mkdtempSync(join(os.tmpdir(), "peer-data-flow-nohead-"));
    try {
      git(bare, "init", "-q", "-b", "main");
      const r = await runListener([prOpened(consent)], { _peerReposMapForTest: new Map([[REPO, bare]]) });
      assertNothingLeft(r);
      assert.match(r.stderr, /data-flow gate: refs\/remotes\/origin\/HEAD does not resolve/);
    } finally {
      rmSync(bare, { recursive: true, force: true });
    }
  });
});

// ─── diff at base...head ──────────────────────────────────────────────

describe("AGT-2248: the diff is fetched at base_sha...head_sha", () => {
  const consent = { _dataFlowAtRefForTest: () => ({ peer_review_endpoints: ["api.anthropic.com"] }) };

  it("buildPeerDiffFetchArgs uses the compare API with both SHAs", () => {
    assert.deepEqual(
      buildPeerDiffFetchArgs({ owner: "acme", repo: "widget", number: 42 }, BASE_SHA, HEAD_SHA),
      ["api", "-H", "Accept: application/vnd.github.diff", `repos/acme/widget/compare/${BASE_SHA}...${HEAD_SHA}`],
    );
  });

  it("buildPeerDiffFetchArgs rejects a non-SHA head", () => {
    assert.throws(
      () => buildPeerDiffFetchArgs({ owner: "acme", repo: "widget", number: 42 }, BASE_SHA, "main"),
      /head_sha "main" is not a full/,
    );
  });

  it("the listener fetches via compare (not `gh pr diff`) and reviews that diff", async () => {
    const r = await runListener([prOpened()], consent);
    assert.equal(r.diffArgs.length, 1, r.stderr);
    const args = r.diffArgs[0]!;
    assert.ok(args.includes(`repos/acme/widget/compare/${BASE_SHA}...${HEAD_SHA}`), JSON.stringify(args));
    assert.ok(!args.includes("pr"), "must not use `gh pr diff` (current PR head)");
    assert.deepEqual(r.sdkDiffs, ["diff --git a/x b/x\n+1\n"]);
  });

  it("refuses (and releases the seat) when GitHub cannot resolve head_sha", async () => {
    const r = await runListener([prOpened()], {
      ...consent,
      _ghDiffForTest: () => {
        return { status: 1, stdout: "", stderr: "gh: Not Found (HTTP 404)" };
      },
    });
    assert.equal(r.claims, 1);
    assert.equal(r.sdkDiffs.length, 0, "review must not run");
    assert.equal(r.posts, 0, "nothing posted");
    assert.equal(r.releases, 1, "seat released");
    assert.match(r.stderr, /could not fetch diff at base\.\.\.head \(gh\): gh: Not Found \(HTTP 404\)/);
  });
});

// ─── AGT-2270: refuse partial compare diffs ────────────────────────────

import { classifyPeerDiffFetch, COMPARE_DIFF_FILE_LIMIT } from "../src/commands/prListen.ts";

describe("classifyPeerDiffFetch (AGT-2270)", () => {
  const oneFile = "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n";
  it("accepts a normal diff", () => {
    assert.deepEqual(classifyPeerDiffFetch(0, oneFile, ""), { ok: true, diff: oneFile });
  });
  it("refuses GitHub's too-large / 406 answers with a clear reason", () => {
    for (const err of [
      "gh: Sorry, this diff is taking too long to generate. (HTTP 406)",
      "gh: Server Error: diff too_large",
      "HTTP 406: Sorry, the diff exceeded the maximum number of files (300).",
    ]) {
      const r = classifyPeerDiffFetch(1, "", err);
      assert.equal(r.ok, false, err);
      if (!r.ok) assert.match(r.reason, /too large for GitHub's compare API.*not reviewing a partial diff/);
    }
  });
  it("refuses output cut at the local buffer limit", () => {
    const r = classifyPeerDiffFetch(1, oneFile, "", "ENOBUFS");
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /local output limit/);
  });
  it("refuses a diff at the compare API's file limit as possibly partial", () => {
    const r = classifyPeerDiffFetch(0, oneFile.repeat(COMPARE_DIFF_FILE_LIMIT), "");
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /stops at 300, so it may be partial/);
    assert.equal(classifyPeerDiffFetch(0, oneFile.repeat(COMPARE_DIFF_FILE_LIMIT - 1), "").ok, true);
  });
  it("keeps other failures' gh stderr and the empty-diff case", () => {
    const r = classifyPeerDiffFetch(1, "", "gh: Not Found (HTTP 404)");
    assert.ok(!r.ok && r.reason === "gh: Not Found (HTTP 404)");
    const e = classifyPeerDiffFetch(0, "  \n", "");
    assert.ok(!e.ok && e.reason === "empty diff");
  });
});
