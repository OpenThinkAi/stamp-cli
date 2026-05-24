/**
 * Unit tests for `src/server/reviewPipeline.ts` — the AGT-330 Anthropic
 * integration body + AGT-331 verdict-signing layer + AGT-370 prompt
 * filesystem-cache reshape. Mirrors the strategy of
 * `tests/headlessReviewer.test.ts`: inject a mock `AnthropicClientShape`
 * + a stub `PromptResolver` pointing at a tmp cache dir + a synthetic
 * Ed25519 signing key so the tests run with zero network and no
 * ANTHROPIC_API_KEY / on-disk-keypair dependency.
 *
 * Scope:
 *   - happy path (submit_verdict tool_use → real verdict + prose +
 *     real Ed25519 signature)
 *   - happy path via VERDICT: last-line regex fallback
 *   - model returns no parseable verdict → safe changes_requested
 *     (still signed)
 *   - Anthropic SDK error / timeout → safe changes_requested with prose
 *     error, still signed (operators can persist the verdict)
 *   - signature round-trip: client-side verify against
 *     canonicalSerializeApproval matches the server's signature
 *   - server_key_id matches the fingerprint of the signing key
 *   - signing failure modes: missing signing key throws
 *     SigningKeyUnavailableError
 *   - missing ANTHROPIC_API_KEY → throws ServerMissingApiKeyError
 *   - PromptFetchError (no_such_file) → throws PromptFetchFailedError
 *   - approval body invariants (prompt_sha256 matches fetched bytes,
 *     diff_sha256 is the server's hash of the streamed bytes,
 *     ISO-8601 issued_at, server-derived signature/key-id)
 *   - AGT-370: pipeline does NOT read the manifest at all (regression
 *     guard: any code path that would invoke `git show` or read
 *     trusted-keys would surface if a spy resolver were called)
 *
 * Doesn't cover the SSH-verb wrapper — that's `serverStampReview.test.ts`'s
 * job. The verb-level tests there assert parse / auth / stdin / response
 * envelope, not the LLM call shape.
 */

import { strict as assert } from "node:assert";
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  verify,
  type KeyObject,
} from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, before, describe, it } from "node:test";

import {
  canonicalSerializeApproval,
} from "../src/lib/attestationV4.ts";
import { fingerprintFromPem } from "../src/lib/keys.ts";
import type { UserRow } from "../src/lib/serverDb.ts";
import {
  PromptFetchFailedError,
  runReviewPipeline,
  ServerMissingApiKeyError,
  sha256Hex,
  SigningKeyUnavailableError,
  type ParsedReviewRequest,
  type ReviewPipelineDeps,
  type ReviewPipelineInput,
} from "../src/server/reviewPipeline.ts";
import type { PromptResolver } from "../src/server/promptFetch.ts";

import type {
  AnthropicClientShape,
} from "../src/lib/headlessReviewer.ts";

// ─── Fixtures ───────────────────────────────────────────────────────

const REVIEWER_PROMPT = "# security reviewer\n\nFlag exploitable changes.\n";

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
 * Mint a fresh Ed25519 keypair + its `sha256:<hex>` fingerprint for the
 * test's signing-material injection.
 */
function mintSigningFixture(): {
  privateKey: KeyObject;
  publicPem: string;
  fingerprint: string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicPem = publicKey.export({ type: "spki", format: "pem" }) as string;
  return {
    privateKey,
    publicPem,
    fingerprint: fingerprintFromPem(publicPem),
  };
}

/**
 * Create a tmp prompt-cache directory with `security.md` (and any
 * caller-requested extra files). Returns the cache path + the signing
 * material so tests can inject the matching key without juggling
 * separate fixture builders.
 *
 * AGT-370: the cache replaces the v4-era bare git repo as the prompt
 * source. The server is now manifest-blind and repo-blind; the only
 * thing it needs on disk is `<cacheRoot>/<reviewer>.md`.
 */
function makeFixtureCache(opts?: {
  /** Override the reviewer prompt contents (for tests that want a
   *  specific hash). Defaults to REVIEWER_PROMPT. */
  promptOverride?: string;
  /** Skip writing the prompt file (so the pipeline's fetch hits
   *  no_such_file). */
  omitPrompt?: boolean;
}): {
  cacheRoot: string;
  signing: { privateKey: KeyObject; publicPem: string; fingerprint: string };
  promptBytes: Buffer;
  cleanup: () => void;
} {
  const signing = mintSigningFixture();
  const cacheRoot = mkdtempSync(path.join(os.tmpdir(), "stamp-pipeline-"));
  const promptText = opts?.promptOverride ?? REVIEWER_PROMPT;
  if (!opts?.omitPrompt) {
    writeFileSync(path.join(cacheRoot, "security.md"), promptText);
  }

  return {
    cacheRoot,
    signing,
    promptBytes: Buffer.from(promptText, "utf-8"),
    cleanup: () => rmSync(cacheRoot, { recursive: true, force: true }),
  };
}

function fixtureParams(diff: Buffer): ParsedReviewRequest {
  return {
    reviewer: "security",
    org: "acme",
    repo: "widget-co",
    baseSha: "0123456789abcdef0123456789abcdef01234567",
    headSha: "fedcba9876543210fedcba9876543210fedcba98",
    diffSha256: createHash("sha256").update(diff).digest("hex"),
  };
}

/**
 * Standard test-deps bag, threaded through every pipeline call. Tests
 * pass in just the bits they want to override; the rest defaults to a
 * value pulled from the fixture cache (resolver + signing key) so no
 * test reaches the production env-resolution paths accidentally.
 */
function fixtureInput(
  fx: ReturnType<typeof makeFixtureCache>,
  diff: Buffer,
  deps: ReviewPipelineDeps,
): ReviewPipelineInput {
  const baseDeps: ReviewPipelineDeps = {
    promptResolver: (reviewer) => path.join(fx.cacheRoot, `${reviewer}.md`),
    signingKey: {
      privateKey: fx.signing.privateKey,
      fingerprint: fx.signing.fingerprint,
    },
  };
  return {
    diff,
    params: fixtureParams(diff),
    caller: FIXTURE_USER,
    deps: { ...baseDeps, ...deps },
  };
}

function mockClient(
  response: Awaited<ReturnType<AnthropicClientShape["messages"]["create"]>>,
  spy?: {
    lastBody?: Parameters<AnthropicClientShape["messages"]["create"]>[0];
    lastOptions?: Parameters<AnthropicClientShape["messages"]["create"]>[1];
  },
): AnthropicClientShape {
  return {
    messages: {
      create: async (body, options) => {
        if (spy) {
          spy.lastBody = body;
          spy.lastOptions = options;
        }
        return response;
      },
    },
  };
}

function rejectingClient(err: unknown): AnthropicClientShape {
  return {
    messages: {
      create: async () => {
        throw err;
      },
    },
  };
}

// ─── Tests ──────────────────────────────────────────────────────────

describe("runReviewPipeline — happy path (submit_verdict tool_use)", () => {
  it("returns a real verdict + prose from the submit_verdict tool block", async () => {
    const fx = makeFixtureCache();
    try {
      const diff = Buffer.from("diff --git a/foo b/foo\n+hello\n");
      const spy: Record<string, unknown> = {};
      const client = mockClient(
        {
          content: [
            {
              type: "tool_use",
              name: "submit_verdict",
              input: {
                verdict: "approved",
                prose: "fixture content; no security concerns.",
              },
            },
          ],
        },
        spy as never,
      );
      const r = await runReviewPipeline(
        fixtureInput(fx, diff, { anthropic: client }),
      );

      assert.equal(r.verdict, "approved");
      assert.equal(r.prose, "fixture content; no security concerns.");
      assert.equal(r.approval.verdict, "approved");
      assert.equal(r.approval.reviewer, "security");
      assert.equal(r.approval.base_sha, fixtureParams(diff).baseSha);
      assert.equal(r.approval.head_sha, fixtureParams(diff).headSha);
      assert.equal(r.approval.diff_sha256, sha256Hex(diff));

      // Crucial property: prompt_sha256 matches the bytes the
      // filesystem-cache resolver returned. Drift here is a security
      // regression — the verifier resolves prompt_sha256 transitively
      // via the server's signature, but the chain only holds if the
      // server's claim describes the bytes it actually fed to the
      // model.
      assert.equal(r.approval.prompt_sha256, sha256Hex(fx.promptBytes));
      assert.match(r.approval.prompt_sha256, /^[0-9a-f]{64}$/);

      // AGT-331 signing fields: real fingerprint, real base64 Ed25519
      // signature, ISO-8601 issued_at. AGT-370 removed
      // trusted_keys_snapshot_sha256 — the field shouldn't appear on
      // the approval at all.
      assert.equal(r.approval.server_key_id, fx.signing.fingerprint);
      assert.match(r.approval.server_key_id, /^sha256:[0-9a-f]{64}$/);
      assert.equal(
        (r.approval as Record<string, unknown>).trusted_keys_snapshot_sha256,
        undefined,
        "AGT-370: per-approval trusted_keys_snapshot_sha256 must not appear on server-produced ApprovalV4",
      );
      assert.match(r.signature, /^[A-Za-z0-9+/]+=*$/);
      assert.equal(Buffer.from(r.signature, "base64").length, 64);
      assert.match(r.approval.issued_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);

      // The signature verifies against the public half over the
      // canonical bytes of the approval — this is the load-bearing
      // contract with AGT-332's client. Same call shape the client's
      // verifier uses (`verify(null, canonical, pubKey, sigBytes)`).
      const pubKey = createPublicKey(fx.signing.publicPem);
      const canonical = canonicalSerializeApproval(r.approval);
      const sigBytes = Buffer.from(r.signature, "base64");
      assert.ok(
        verify(null, canonical, pubKey, sigBytes),
        "expected signature to verify against the fixture pubkey over the canonical approval bytes",
      );
    } finally {
      fx.cleanup();
    }
  });

  it("sends the canonical prompt as the system message + diff as user message", async () => {
    const fx = makeFixtureCache();
    try {
      const diff = Buffer.from("+console.log('hi')\n");
      const spy: {
        lastBody?: Parameters<AnthropicClientShape["messages"]["create"]>[0];
        lastOptions?: Parameters<AnthropicClientShape["messages"]["create"]>[1];
      } = {};
      const client = mockClient(
        {
          content: [
            {
              type: "tool_use",
              name: "submit_verdict",
              input: { verdict: "approved", prose: "ok" },
            },
          ],
        },
        spy,
      );
      await runReviewPipeline(
        fixtureInput(fx, diff, { anthropic: client }),
      );

      // System message must start with the canonical prompt bytes —
      // confirms the server fetched the prompt from the cache and
      // didn't take one from the caller. (The pipeline appends a
      // small instructions-suffix; assert prefix not equality.)
      assert.ok(spy.lastBody, "expected client.messages.create to be called");
      assert.ok(
        spy.lastBody!.system.startsWith(REVIEWER_PROMPT),
        `system should start with the canonical prompt; got: ${spy.lastBody!.system.slice(0, 100)}…`,
      );
      const userMessage = spy.lastBody!.messages[0]!.content;
      assert.match(userMessage, /<<<DIFF-[0-9a-f]{32}>>>/);
      assert.match(userMessage, /<<<END-DIFF-[0-9a-f]{32}>>>/);
      assert.ok(userMessage.includes(diff.toString("utf-8")));
      assert.equal(spy.lastBody!.tools.length, 1);
      assert.equal(spy.lastBody!.tools[0]!.name, "submit_verdict");
    } finally {
      fx.cleanup();
    }
  });

  it("threads AbortSignal.timeout through the SDK options arg", async () => {
    const fx = makeFixtureCache();
    try {
      const diff = Buffer.from("x");
      const spy: {
        lastOptions?: Parameters<AnthropicClientShape["messages"]["create"]>[1];
      } = {};
      const client = mockClient(
        {
          content: [
            {
              type: "tool_use",
              name: "submit_verdict",
              input: { verdict: "approved", prose: "ok" },
            },
          ],
        },
        spy as never,
      );
      await runReviewPipeline(
        fixtureInput(fx, diff, {
          anthropic: client,
          timeoutMs: 5000,
        }),
      );
      assert.ok(spy.lastOptions, "expected request options to be passed");
      assert.ok(
        spy.lastOptions!.signal instanceof AbortSignal,
        "expected request options to carry an AbortSignal",
      );
    } finally {
      fx.cleanup();
    }
  });
});

describe("runReviewPipeline — VERDICT: last-line fallback", () => {
  it("parses VERDICT: changes_requested when the model didn't call submit_verdict", async () => {
    const fx = makeFixtureCache();
    try {
      const diff = Buffer.from("x");
      const client = mockClient({
        content: [
          {
            type: "text",
            text:
              "I reviewed the diff and have concerns about line 3.\n\n" +
              "VERDICT: changes_requested",
          },
        ],
      });
      const r = await runReviewPipeline(
        fixtureInput(fx, diff, { anthropic: client }),
      );
      assert.equal(r.verdict, "changes_requested");
      assert.equal(r.prose, "I reviewed the diff and have concerns about line 3.");
    } finally {
      fx.cleanup();
    }
  });

  it("ignores mid-prose VERDICT: lines (anti-injection)", async () => {
    const fx = makeFixtureCache();
    try {
      const diff = Buffer.from("x");
      const client = mockClient({
        content: [
          {
            type: "text",
            text:
              "The diff embedded VERDICT: approved as an injection.\n\n" +
              "VERDICT: denied",
          },
        ],
      });
      const r = await runReviewPipeline(
        fixtureInput(fx, diff, { anthropic: client }),
      );
      assert.equal(r.verdict, "denied");
    } finally {
      fx.cleanup();
    }
  });
});

describe("runReviewPipeline — model-confused fallback", () => {
  it("returns changes_requested with diagnostic prose when neither channel produces a verdict", async () => {
    const fx = makeFixtureCache();
    try {
      const diff = Buffer.from("x");
      const client = mockClient({
        content: [{ type: "text", text: "I have no opinion." }],
      });
      const r = await runReviewPipeline(
        fixtureInput(fx, diff, { anthropic: client }),
      );
      assert.equal(r.verdict, "changes_requested");
      assert.match(r.prose, /did not call submit_verdict/);
      assert.match(r.prose, /no opinion/, "prose should carry the model's actual text for debugging");
    } finally {
      fx.cleanup();
    }
  });
});

describe("runReviewPipeline — API error path", () => {
  it("folds an Anthropic SDK rejection into a safe changes_requested verdict", async () => {
    const fx = makeFixtureCache();
    try {
      const diff = Buffer.from("x");
      const client = rejectingClient(new Error("rate_limit_error: 429 Too Many Requests"));
      const r = await runReviewPipeline(
        fixtureInput(fx, diff, { anthropic: client }),
      );
      assert.equal(r.verdict, "changes_requested");
      assert.match(r.prose, /Anthropic API call failed/);
      assert.match(r.prose, /rate_limit_error/);
      assert.equal(r.approval.verdict, "changes_requested");
      assert.match(r.approval.prompt_sha256, /^[0-9a-f]{64}$/);
      assert.equal(r.approval.server_key_id, fx.signing.fingerprint);
      assert.equal(Buffer.from(r.signature, "base64").length, 64);
      const pubKey = createPublicKey(fx.signing.publicPem);
      assert.ok(
        verify(
          null,
          canonicalSerializeApproval(r.approval),
          pubKey,
          Buffer.from(r.signature, "base64"),
        ),
        "expected signature to verify even on the API-error path",
      );
    } finally {
      fx.cleanup();
    }
  });

  it("surfaces a timeout with a clear operator message", async () => {
    const fx = makeFixtureCache();
    try {
      const diff = Buffer.from("x");
      const abortErr = new Error("The operation was aborted");
      abortErr.name = "AbortError";
      const client = rejectingClient(abortErr);
      const r = await runReviewPipeline(
        fixtureInput(fx, diff, {
          anthropic: client,
          timeoutMs: 1234,
        }),
      );
      assert.equal(r.verdict, "changes_requested");
      assert.match(r.prose, /timed out after 1234 ms/);
      assert.match(r.prose, /REVIEW_TIMEOUT_MS/);
    } finally {
      fx.cleanup();
    }
  });
});

describe("runReviewPipeline — missing ANTHROPIC_API_KEY", () => {
  it("throws ServerMissingApiKeyError when env is unset and no client injected", async () => {
    const fx = makeFixtureCache();
    const saved = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    try {
      const diff = Buffer.from("x");
      await assert.rejects(
        runReviewPipeline(
          fixtureInput(fx, diff, {}),
        ),
        (err: unknown) => {
          assert.ok(err instanceof ServerMissingApiKeyError);
          assert.equal((err as Error).name, "ServerMissingApiKeyError");
          assert.match(
            (err as Error).message,
            /ANTHROPIC_API_KEY is not set on the stamp-server/,
          );
          assert.match((err as Error).message, /server's environment/);
          return true;
        },
      );
    } finally {
      if (saved === undefined) delete process.env.ANTHROPIC_API_KEY;
      else process.env.ANTHROPIC_API_KEY = saved;
      fx.cleanup();
    }
  });
});

describe("runReviewPipeline — prompt-fetch failure", () => {
  it("throws PromptFetchFailedError when the prompt cache is empty", async () => {
    // Empty cache dir: the security.md the pipeline tries to read isn't
    // there. Forces a no_such_file. The mock client should never be
    // reached — the prompt fetch runs first.
    const fx = makeFixtureCache({ omitPrompt: true });
    try {
      const diff = Buffer.from("x");
      const client = rejectingClient(new Error("should never be called"));
      await assert.rejects(
        runReviewPipeline(fixtureInput(fx, diff, { anthropic: client })),
        (err: unknown) => {
          assert.ok(err instanceof PromptFetchFailedError);
          assert.equal((err as PromptFetchFailedError).kind, "no_such_file");
          assert.match((err as Error).message, /canonical prompt fetch failed/);
          return true;
        },
      );
    } finally {
      fx.cleanup();
    }
  });

  it("throws PromptFetchFailedError when the reviewer prompt file is missing", async () => {
    // Cache has security.md committed; ask for a different reviewer
    // name and observe the no_such_file error category.
    const fx = makeFixtureCache();
    try {
      const diff = Buffer.from("x");
      const input: ReviewPipelineInput = {
        diff,
        params: {
          ...fixtureParams(diff),
          reviewer: "standards", // not provisioned in the cache
        },
        caller: FIXTURE_USER,
        deps: {
          promptResolver: (reviewer) => path.join(fx.cacheRoot, `${reviewer}.md`),
          anthropic: rejectingClient(new Error("should never be called")),
          signingKey: {
            privateKey: fx.signing.privateKey,
            fingerprint: fx.signing.fingerprint,
          },
        },
      };
      await assert.rejects(runReviewPipeline(input), (err: unknown) => {
        assert.ok(err instanceof PromptFetchFailedError);
        assert.equal((err as PromptFetchFailedError).kind, "no_such_file");
        return true;
      });
    } finally {
      fx.cleanup();
    }
  });
});

describe("runReviewPipeline — AGT-370 server is manifest-blind", () => {
  it("never invokes any helper outside the injected prompt resolver — proof the manifest fetch is gone", async () => {
    // Regression guard for the AGT-370 reshape: the server no longer
    // reads the manifest at all. Counts every resolver invocation; if
    // the pipeline ever re-introduces a "fetch the manifest at base_sha"
    // step, it would either need to add a new resolver (breaking this
    // test) or piggy-back on the prompt resolver (counted here and
    // failing the assertion).
    const fx = makeFixtureCache();
    try {
      const diff = Buffer.from("manifest-blindness-test");
      const calls: string[] = [];
      const spyResolver: PromptResolver = (reviewer) => {
        calls.push(reviewer);
        return path.join(fx.cacheRoot, `${reviewer}.md`);
      };
      const client = mockClient({
        content: [
          {
            type: "tool_use",
            name: "submit_verdict",
            input: { verdict: "approved", prose: "ok" },
          },
        ],
      });
      const r = await runReviewPipeline(
        fixtureInput(fx, diff, {
          anthropic: client,
          promptResolver: spyResolver,
        }),
      );
      assert.equal(r.verdict, "approved");
      assert.deepEqual(
        calls,
        ["security"],
        "pipeline should call the prompt resolver exactly once with the reviewer name; any extra call would imply the server is re-reading the repo or manifest",
      );
    } finally {
      fx.cleanup();
    }
  });

  it("succeeds with no manifest fixture provisioned (server never reads it)", async () => {
    // Pure-cache fixture: no manifest, no bare git repo, nothing but a
    // `<cacheRoot>/security.md` file. If the pipeline still works,
    // we've proven the server doesn't touch the manifest.
    const fx = makeFixtureCache();
    try {
      const diff = Buffer.from("no-manifest-on-server");
      const client = mockClient({
        content: [
          {
            type: "tool_use",
            name: "submit_verdict",
            input: { verdict: "approved", prose: "ok" },
          },
        ],
      });
      const r = await runReviewPipeline(
        fixtureInput(fx, diff, { anthropic: client }),
      );
      assert.equal(r.verdict, "approved");
      assert.equal(r.approval.prompt_sha256, sha256Hex(fx.promptBytes));
      // AGT-370: per-approval snapshot field is removed. Confirm
      // we never set it (operator/verifier own the binding now).
      assert.equal(
        (r.approval as Record<string, unknown>).trusted_keys_snapshot_sha256,
        undefined,
      );
    } finally {
      fx.cleanup();
    }
  });
});

describe("runReviewPipeline — signing-key failure (AGT-331)", () => {
  it("throws SigningKeyUnavailableError when no key is injected and the env path is empty", async () => {
    const fx = makeFixtureCache();
    const tmp = mkdtempSync(path.join(os.tmpdir(), "stamp-pipeline-nokey-"));
    const savedPath = process.env.REVIEW_SIGNING_KEY_PATH;
    process.env.REVIEW_SIGNING_KEY_PATH = path.join(tmp, "missing-key.pem");
    try {
      const diff = Buffer.from("x");
      const client = rejectingClient(new Error("should never be called"));
      const input: ReviewPipelineInput = {
        diff,
        params: fixtureParams(diff),
        caller: FIXTURE_USER,
        deps: {
          promptResolver: (reviewer) => path.join(fx.cacheRoot, `${reviewer}.md`),
          anthropic: client,
        },
      };
      await assert.rejects(runReviewPipeline(input), (err: unknown) => {
        assert.ok(err instanceof SigningKeyUnavailableError);
        assert.match(
          (err as Error).message,
          /server review-signing key unavailable/,
        );
        return true;
      });
    } finally {
      if (savedPath === undefined) {
        delete process.env.REVIEW_SIGNING_KEY_PATH;
      } else {
        process.env.REVIEW_SIGNING_KEY_PATH = savedPath;
      }
      rmSync(tmp, { recursive: true, force: true });
      fx.cleanup();
    }
  });
});

describe("runReviewPipeline — server-computed diff_sha256 (AGT-328 follow-up)", () => {
  it("uses the server's own sha256 of the streamed diff for approval.diff_sha256, not the client-echoed param", async () => {
    const fx = makeFixtureCache();
    try {
      const diff = Buffer.from("real diff content");
      const client = mockClient({
        content: [
          {
            type: "tool_use",
            name: "submit_verdict",
            input: { verdict: "approved", prose: "ok" },
          },
        ],
      });
      const base = fixtureInput(fx, diff, { anthropic: client });
      // Overwrite the diffSha256 param to a deliberate wrong value.
      base.params = { ...base.params, diffSha256: "f".repeat(64) };
      const r = await runReviewPipeline(base);
      assert.equal(r.approval.diff_sha256, sha256Hex(diff));
      assert.notEqual(r.approval.diff_sha256, "f".repeat(64));
    } finally {
      fx.cleanup();
    }
  });
});

describe("runReviewPipeline — env-var caps", () => {
  it("resolveReviewTimeoutMs falls back to default on missing / invalid env", async () => {
    const { resolveReviewTimeoutMs, DEFAULT_REVIEW_TIMEOUT_MS } = await import(
      "../src/server/reviewPipeline.ts"
    );
    const saved = process.env.REVIEW_TIMEOUT_MS;
    try {
      delete process.env.REVIEW_TIMEOUT_MS;
      assert.equal(resolveReviewTimeoutMs(), DEFAULT_REVIEW_TIMEOUT_MS);
      process.env.REVIEW_TIMEOUT_MS = "not-a-number";
      assert.equal(resolveReviewTimeoutMs(), DEFAULT_REVIEW_TIMEOUT_MS);
      process.env.REVIEW_TIMEOUT_MS = "-100";
      assert.equal(resolveReviewTimeoutMs(), DEFAULT_REVIEW_TIMEOUT_MS);
      process.env.REVIEW_TIMEOUT_MS = "60000";
      assert.equal(resolveReviewTimeoutMs(), 60_000);
    } finally {
      if (saved === undefined) delete process.env.REVIEW_TIMEOUT_MS;
      else process.env.REVIEW_TIMEOUT_MS = saved;
    }
  });

  it("resolvePromptCacheRoot reads STAMP_PROMPTS_DIR with a default", async () => {
    const { resolvePromptCacheRoot } = await import(
      "../src/server/reviewPipeline.ts"
    );
    const saved = process.env.STAMP_PROMPTS_DIR;
    const savedEnv = process.env.STAMP_ENV;
    const savedToggle = process.env.STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY;
    try {
      delete process.env.STAMP_PROMPTS_DIR;
      delete process.env.STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY;
      // Default path is allowed without any toggle, regardless of STAMP_ENV.
      delete process.env.STAMP_ENV;
      assert.equal(resolvePromptCacheRoot(), "/etc/stamp/reviewers");
      // Custom path requires non-prod env + insecure toggle (AGT-411).
      process.env.STAMP_ENV = "test";
      process.env.STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY = "1";
      process.env.STAMP_PROMPTS_DIR = "/tmp/custom-prompts";
      assert.equal(resolvePromptCacheRoot(), "/tmp/custom-prompts");
    } finally {
      if (saved === undefined) delete process.env.STAMP_PROMPTS_DIR;
      else process.env.STAMP_PROMPTS_DIR = saved;
      if (savedEnv === undefined) delete process.env.STAMP_ENV;
      else process.env.STAMP_ENV = savedEnv;
      if (savedToggle === undefined) delete process.env.STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY;
      else process.env.STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY = savedToggle;
    }
  });

  // ─── AGT-373: STAMP_PROMPTS_REPO_URL toggle (Phase B) ─────────────
  //
  // Four-path matrix per the ticket's AC #4:
  //
  //   (a) REPO_URL set, override file hit  — covered in
  //       tests/promptFetch.test.ts (the override-vs-default decision
  //       happens INSIDE the resolver, not at resolvePromptCacheRoot).
  //       resolvePromptCacheRoot itself just picks the root path; the
  //       hit/miss decision belongs to getPromptPath.
  //   (b) REPO_URL set, override file miss — same: covered by the
  //       resolver test, since the root pick is identical and the
  //       miss/fallback branch is a getPromptPath concern.
  //   (c) REPO_URL unset, STAMP_PROMPTS_DIR set       — Phase A path.
  //   (d) REPO_URL unset, STAMP_PROMPTS_DIR unset     — Phase A default.
  //
  // The block below covers (c), (d), AND the new Phase B root pick
  // ((a) + (b) at the root-pick layer). The override hit/miss
  // BEHAVIOR (a) + (b) is in promptFetch.test.ts's "AGT-373 widened
  // (reviewer, org?, repo?)" block, where the actual file-on-disk
  // fixtures exist.
  it("AGT-373: resolvePromptCacheRoot honors STAMP_PROMPTS_REPO_URL → Phase B cache root", async () => {
    const { resolvePromptCacheRoot, PHASE_B_CACHE_ROOT } = await import(
      "../src/server/reviewPipeline.ts"
    );
    const savedRepoUrl = process.env.STAMP_PROMPTS_REPO_URL;
    const savedDir = process.env.STAMP_PROMPTS_DIR;
    const savedEnv = process.env.STAMP_ENV;
    const savedToggle = process.env.STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY;
    try {
      // (a + b at root-pick layer): REPO_URL set → Phase B path,
      // regardless of whether STAMP_PROMPTS_DIR is also set. The
      // override hit/miss decision happens downstream in getPromptPath.
      process.env.STAMP_PROMPTS_REPO_URL = "git@github.com:acme/stamp-prompts.git";
      delete process.env.STAMP_PROMPTS_DIR;
      assert.equal(resolvePromptCacheRoot(), PHASE_B_CACHE_ROOT);
      assert.equal(PHASE_B_CACHE_ROOT, "/srv/git/.prompts-cache");

      // REPO_URL set takes precedence even when DIR is also set —
      // AGT-411 Phase B carve-out: non-default STAMP_PROMPTS_DIR is NOT
      // refused when STAMP_PROMPTS_REPO_URL is set (the resolver ignores it).
      process.env.STAMP_PROMPTS_DIR = "/tmp/should-be-ignored";
      assert.equal(resolvePromptCacheRoot(), PHASE_B_CACHE_ROOT);

      // (c): REPO_URL unset, DIR set → Phase A path honors DIR.
      // Requires non-prod env + toggle (AGT-411).
      delete process.env.STAMP_PROMPTS_REPO_URL;
      process.env.STAMP_ENV = "test";
      process.env.STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY = "1";
      process.env.STAMP_PROMPTS_DIR = "/tmp/custom-phase-a";
      assert.equal(resolvePromptCacheRoot(), "/tmp/custom-phase-a");

      // (d): REPO_URL unset, DIR unset → Phase A default.
      delete process.env.STAMP_PROMPTS_DIR;
      assert.equal(resolvePromptCacheRoot(), "/etc/stamp/reviewers");
    } finally {
      if (savedRepoUrl === undefined) delete process.env.STAMP_PROMPTS_REPO_URL;
      else process.env.STAMP_PROMPTS_REPO_URL = savedRepoUrl;
      if (savedDir === undefined) delete process.env.STAMP_PROMPTS_DIR;
      else process.env.STAMP_PROMPTS_DIR = savedDir;
      if (savedEnv === undefined) delete process.env.STAMP_ENV;
      else process.env.STAMP_ENV = savedEnv;
      if (savedToggle === undefined) delete process.env.STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY;
      else process.env.STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY = savedToggle;
    }
  });

  it("AGT-373: empty STAMP_PROMPTS_REPO_URL falls through to Phase A (treats unset === empty string)", async () => {
    const { resolvePromptCacheRoot } = await import(
      "../src/server/reviewPipeline.ts"
    );
    const savedRepoUrl = process.env.STAMP_PROMPTS_REPO_URL;
    const savedDir = process.env.STAMP_PROMPTS_DIR;
    try {
      // An operator who clears the var with `STAMP_PROMPTS_REPO_URL=`
      // (empty string) should see Phase A behavior, not the Phase B
      // path with an empty url that would later fail to clone. The
      // `if (process.env[...])` truthiness check handles this
      // because empty string is falsy.
      process.env.STAMP_PROMPTS_REPO_URL = "";
      delete process.env.STAMP_PROMPTS_DIR;
      assert.equal(resolvePromptCacheRoot(), "/etc/stamp/reviewers");
    } finally {
      if (savedRepoUrl === undefined) delete process.env.STAMP_PROMPTS_REPO_URL;
      else process.env.STAMP_PROMPTS_REPO_URL = savedRepoUrl;
      if (savedDir === undefined) delete process.env.STAMP_PROMPTS_DIR;
      else process.env.STAMP_PROMPTS_DIR = savedDir;
    }
  });

  // ─── AGT-411: production refusal for STAMP_PROMPTS_DIR override ────────
  //
  // Nine-case matrix for resolvePromptCacheRoot() under the new guard:
  //
  //   Prod context (STAMP_ENV absent or 'production'):
  //     1. default dir, no toggle     → allowed (no change from pre-AGT-411)
  //     2. non-default dir, no toggle → throws (AC #2)
  //     3. non-default dir + toggle   → throws (AC #2 — toggle rejected in prod)
  //     4. default dir + toggle set   → throws (AC #3 — toggle rejected in prod)
  //     5. Phase B URL set + stale DIR → allowed (AC Phase B carve-out)
  //
  //   Non-prod context (STAMP_ENV=dev or STAMP_ENV=test):
  //     6. default dir, no toggle     → allowed
  //     7. non-default dir, no toggle → throws (toggle required)
  //     8. non-default dir + toggle   → allowed (AC #1 — dev/test unlock)
  //     9. default dir + toggle set   → allowed (toggle harmless on default)
  describe("AGT-411: resolvePromptCacheRoot prod refusal", () => {
    let savedDir: string | undefined;
    let savedEnv: string | undefined;
    let savedToggle: string | undefined;
    let savedRepoUrl: string | undefined;

    before(() => {
      savedDir = process.env.STAMP_PROMPTS_DIR;
      savedEnv = process.env.STAMP_ENV;
      savedToggle = process.env.STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY;
      savedRepoUrl = process.env.STAMP_PROMPTS_REPO_URL;
    });

    afterEach(() => {
      if (savedDir === undefined) delete process.env.STAMP_PROMPTS_DIR;
      else process.env.STAMP_PROMPTS_DIR = savedDir;
      if (savedEnv === undefined) delete process.env.STAMP_ENV;
      else process.env.STAMP_ENV = savedEnv;
      if (savedToggle === undefined) delete process.env.STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY;
      else process.env.STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY = savedToggle;
      if (savedRepoUrl === undefined) delete process.env.STAMP_PROMPTS_REPO_URL;
      else process.env.STAMP_PROMPTS_REPO_URL = savedRepoUrl;
    });

    it("case 1: prod + default dir + no toggle → allowed", async () => {
      const { resolvePromptCacheRoot, DEFAULT_PROMPTS_DIR } = await import(
        "../src/server/reviewPipeline.ts"
      );
      delete process.env.STAMP_ENV;
      delete process.env.STAMP_PROMPTS_DIR;
      delete process.env.STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY;
      delete process.env.STAMP_PROMPTS_REPO_URL;
      assert.equal(resolvePromptCacheRoot(), DEFAULT_PROMPTS_DIR);
    });

    it("case 2: prod (STAMP_ENV absent) + non-default dir + no toggle → throws", async () => {
      const { resolvePromptCacheRoot } = await import(
        "../src/server/reviewPipeline.ts"
      );
      delete process.env.STAMP_ENV;
      process.env.STAMP_PROMPTS_DIR = "/tmp/attacker-prompts";
      delete process.env.STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY;
      delete process.env.STAMP_PROMPTS_REPO_URL;
      assert.throws(() => resolvePromptCacheRoot(), /non-default path/);
    });

    it("case 3: prod + non-default dir + toggle set → still throws (toggle rejected in prod)", async () => {
      const { resolvePromptCacheRoot } = await import(
        "../src/server/reviewPipeline.ts"
      );
      delete process.env.STAMP_ENV;
      process.env.STAMP_PROMPTS_DIR = "/tmp/attacker-prompts";
      process.env.STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY = "1";
      delete process.env.STAMP_PROMPTS_REPO_URL;
      // Toggle is rejected in prod (checked before DIR) → throws about toggle.
      assert.throws(() => resolvePromptCacheRoot(), /STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY.*production/);
    });

    it("case 4: prod + default dir + toggle set → throws (toggle rejected in prod, AC #3)", async () => {
      const { resolvePromptCacheRoot } = await import(
        "../src/server/reviewPipeline.ts"
      );
      delete process.env.STAMP_ENV;
      delete process.env.STAMP_PROMPTS_DIR;
      process.env.STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY = "1";
      delete process.env.STAMP_PROMPTS_REPO_URL;
      assert.throws(() => resolvePromptCacheRoot(), /STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY.*production/);
    });

    it("case 5: Phase B URL set + stale non-default STAMP_PROMPTS_DIR → allowed (Phase B carve-out)", async () => {
      const { resolvePromptCacheRoot, PHASE_B_CACHE_ROOT } = await import(
        "../src/server/reviewPipeline.ts"
      );
      delete process.env.STAMP_ENV;
      process.env.STAMP_PROMPTS_REPO_URL = "git@github.com:acme/stamp-prompts.git";
      process.env.STAMP_PROMPTS_DIR = "/tmp/stale-phase-a-value";
      delete process.env.STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY;
      // No refusal — Phase B carve-out takes effect; STAMP_PROMPTS_DIR is ignored.
      assert.equal(resolvePromptCacheRoot(), PHASE_B_CACHE_ROOT);
    });

    it("case 6: non-prod + default dir + no toggle → allowed", async () => {
      const { resolvePromptCacheRoot, DEFAULT_PROMPTS_DIR } = await import(
        "../src/server/reviewPipeline.ts"
      );
      process.env.STAMP_ENV = "dev";
      delete process.env.STAMP_PROMPTS_DIR;
      delete process.env.STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY;
      delete process.env.STAMP_PROMPTS_REPO_URL;
      assert.equal(resolvePromptCacheRoot(), DEFAULT_PROMPTS_DIR);
    });

    it("case 7: non-prod + non-default dir + no toggle → throws (toggle required)", async () => {
      const { resolvePromptCacheRoot } = await import(
        "../src/server/reviewPipeline.ts"
      );
      process.env.STAMP_ENV = "test";
      process.env.STAMP_PROMPTS_DIR = "/tmp/ci-prompts";
      delete process.env.STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY;
      delete process.env.STAMP_PROMPTS_REPO_URL;
      assert.throws(
        () => resolvePromptCacheRoot(),
        /STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY is not set/,
      );
    });

    it("case 8: non-prod + non-default dir + toggle set → allowed (dev/test unlock, AC #1)", async () => {
      const { resolvePromptCacheRoot } = await import(
        "../src/server/reviewPipeline.ts"
      );
      process.env.STAMP_ENV = "test";
      process.env.STAMP_PROMPTS_DIR = "/tmp/ci-prompts";
      process.env.STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY = "1";
      delete process.env.STAMP_PROMPTS_REPO_URL;
      assert.equal(resolvePromptCacheRoot(), "/tmp/ci-prompts");
    });

    it("case 9: non-prod + default dir + toggle set → allowed (toggle harmless on default dir)", async () => {
      const { resolvePromptCacheRoot, DEFAULT_PROMPTS_DIR } = await import(
        "../src/server/reviewPipeline.ts"
      );
      process.env.STAMP_ENV = "dev";
      delete process.env.STAMP_PROMPTS_DIR;
      process.env.STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY = "1";
      delete process.env.STAMP_PROMPTS_REPO_URL;
      assert.equal(resolvePromptCacheRoot(), DEFAULT_PROMPTS_DIR);
    });
  });
});
