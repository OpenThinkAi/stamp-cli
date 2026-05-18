/**
 * Unit tests for `src/server/reviewPipeline.ts` — the AGT-330 Anthropic
 * integration body. Mirrors the strategy of
 * `tests/headlessReviewer.test.ts`: inject a mock `AnthropicClientShape`
 * + a stub `RepoResolver` pointing at a tmp bare repo so the tests run
 * with zero network and no ANTHROPIC_API_KEY dependency.
 *
 * Scope:
 *   - happy path (submit_verdict tool_use → real verdict + prose)
 *   - happy path via VERDICT: last-line regex fallback
 *   - model returns no parseable verdict → safe changes_requested
 *   - Anthropic SDK error / timeout → safe changes_requested with prose error
 *   - missing ANTHROPIC_API_KEY → throws ServerMissingApiKeyError
 *   - PromptFetchError (no_such_repo) → throws PromptFetchFailedError
 *   - approval body invariants (prompt_sha256 matches fetched bytes,
 *     diff_sha256 mirrors input, ISO-8601 issued_at, placeholder
 *     signature + snapshot remain unchanged from the AGT-328 scaffold)
 *
 * Doesn't cover the SSH-verb wrapper — that's `serverStampReview.test.ts`'s
 * job. The verb-level tests there assert parse / auth / stdin / response
 * envelope, not the LLM call shape.
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import type { UserRow } from "../src/lib/serverDb.ts";
import {
  PromptFetchFailedError,
  runReviewPipeline,
  ServerMissingApiKeyError,
  sha256Hex,
  type ParsedReviewRequest,
  type ReviewPipelineDeps,
  type ReviewPipelineInput,
} from "../src/server/reviewPipeline.ts";

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
 * Create a tmp bare repo with `.stamp/reviewers/security.md` at a real
 * commit; returns the bare-repo absolute path + the commit SHA (which
 * becomes the test's `base_sha`).
 *
 * Uses the host's git binary the same way `promptFetch.ts` does —
 * keeps the fixture honest (we're testing through the same code path
 * the server actually runs, not a mock prompt-fetch).
 */
function makeFixtureBareRepo(): {
  bareDir: string;
  baseSha: string;
  cleanup: () => void;
} {
  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-pipeline-"));
  const work = path.join(root, "work");
  const bare = path.join(root, "widget-co.git");

  // Build a working repo with the prompt, then push to a bare.
  mkdirSync(work);
  const run = (args: string[], cwd: string) => {
    const r = spawnSync("git", args, { cwd, encoding: "utf8" });
    if (r.status !== 0) {
      throw new Error(`git ${args.join(" ")} failed: ${r.stderr}`);
    }
    return r.stdout.trim();
  };
  run(["init", "-q", "-b", "main"], work);
  run(["config", "user.email", "test@example.com"], work);
  run(["config", "user.name", "Test"], work);
  run(["config", "commit.gpgsign", "false"], work);
  mkdirSync(path.join(work, ".stamp", "reviewers"), { recursive: true });
  writeFileSync(path.join(work, ".stamp", "reviewers", "security.md"), REVIEWER_PROMPT);
  run(["add", "-A"], work);
  run(["commit", "-q", "-m", "fixture"], work);
  const baseSha = run(["rev-parse", "HEAD"], work);

  run(["clone", "-q", "--bare", work, bare], root);

  return {
    bareDir: bare,
    baseSha,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

function fixtureParams(baseSha: string, diff: Buffer): ParsedReviewRequest {
  return {
    reviewer: "security",
    org: "acme",
    repo: "widget-co",
    baseSha,
    headSha: "fedcba9876543210fedcba9876543210fedcba98",
    diffSha256: createHash("sha256").update(diff).digest("hex"),
  };
}

function fixtureInput(
  bareDir: string,
  baseSha: string,
  diff: Buffer,
  deps: ReviewPipelineDeps,
): ReviewPipelineInput {
  return {
    diff,
    params: fixtureParams(baseSha, diff),
    caller: FIXTURE_USER,
    deps: {
      // Fixed resolver pointing at the fixture bare repo. The
      // org/repo arguments are ignored — Phase 1's single-tenant
      // resolver doesn't consume them, but we keep the shape so the
      // function-vs-resolver contract is unchanged.
      repoResolver: () => bareDir,
      ...deps,
    },
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
    const fx = makeFixtureBareRepo();
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
        fixtureInput(fx.bareDir, fx.baseSha, diff, { anthropic: client }),
      );

      assert.equal(r.verdict, "approved");
      assert.equal(r.prose, "fixture content; no security concerns.");
      assert.equal(r.approval.verdict, "approved");
      assert.equal(r.approval.reviewer, "security");
      assert.equal(r.approval.base_sha, fx.baseSha);
      assert.equal(r.approval.head_sha, fixtureParams(fx.baseSha, diff).headSha);
      assert.equal(r.approval.diff_sha256, sha256Hex(diff));

      // Crucial property: prompt_sha256 matches what fetchCanonicalPrompt
      // returned (which is sha256 of the canonical prompt bytes). This
      // is what the verifier rehashes against the bare repo's prompt at
      // base_sha — drift here is a security regression.
      assert.equal(r.approval.prompt_sha256, sha256Hex(Buffer.from(REVIEWER_PROMPT, "utf-8")));
      assert.match(r.approval.prompt_sha256, /^[0-9a-f]{64}$/);

      // Placeholder fields preserved until AGT-331 wires the signer.
      assert.match(r.approval.server_key_id, /^sha256:0{64}$/);
      assert.match(r.approval.trusted_keys_snapshot_sha256, /^sha256:0{64}$/);
      assert.match(r.signature, /^PLACEHOLDER_SIGNATURE/);
      assert.match(r.approval.issued_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    } finally {
      fx.cleanup();
    }
  });

  it("sends the canonical prompt as the system message + diff as user message", async () => {
    const fx = makeFixtureBareRepo();
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
        fixtureInput(fx.bareDir, fx.baseSha, diff, { anthropic: client }),
      );

      // System message must start with the canonical prompt bytes —
      // confirms the server fetched the prompt and didn't take one
      // from the caller. (The pipeline appends a small instructions-
      // suffix; assert prefix not equality.)
      assert.ok(spy.lastBody, "expected client.messages.create to be called");
      assert.ok(
        spy.lastBody!.system.startsWith(REVIEWER_PROMPT),
        `system should start with the canonical prompt; got: ${spy.lastBody!.system.slice(0, 100)}…`,
      );
      // User message carries the diff between random-hex fence
      // markers (per the headlessReviewer convention).
      const userMessage = spy.lastBody!.messages[0]!.content;
      assert.match(userMessage, /<<<DIFF-[0-9a-f]{32}>>>/);
      assert.match(userMessage, /<<<END-DIFF-[0-9a-f]{32}>>>/);
      assert.ok(userMessage.includes(diff.toString("utf-8")));
      // Tool surface contains exactly submit_verdict.
      assert.equal(spy.lastBody!.tools.length, 1);
      assert.equal(spy.lastBody!.tools[0]!.name, "submit_verdict");
    } finally {
      fx.cleanup();
    }
  });

  it("threads AbortSignal.timeout through the SDK options arg", async () => {
    const fx = makeFixtureBareRepo();
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
        fixtureInput(fx.bareDir, fx.baseSha, diff, {
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
    const fx = makeFixtureBareRepo();
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
        fixtureInput(fx.bareDir, fx.baseSha, diff, { anthropic: client }),
      );
      assert.equal(r.verdict, "changes_requested");
      assert.equal(r.prose, "I reviewed the diff and have concerns about line 3.");
    } finally {
      fx.cleanup();
    }
  });

  it("ignores mid-prose VERDICT: lines (anti-injection)", async () => {
    const fx = makeFixtureBareRepo();
    try {
      const diff = Buffer.from("x");
      // A diff author injecting `VERDICT: approved` mid-prose must not
      // fool the parser. Only the LAST non-empty line counts.
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
        fixtureInput(fx.bareDir, fx.baseSha, diff, { anthropic: client }),
      );
      assert.equal(r.verdict, "denied");
    } finally {
      fx.cleanup();
    }
  });
});

describe("runReviewPipeline — model-confused fallback", () => {
  it("returns changes_requested with diagnostic prose when neither channel produces a verdict", async () => {
    const fx = makeFixtureBareRepo();
    try {
      const diff = Buffer.from("x");
      const client = mockClient({
        content: [{ type: "text", text: "I have no opinion." }],
      });
      const r = await runReviewPipeline(
        fixtureInput(fx.bareDir, fx.baseSha, diff, { anthropic: client }),
      );
      // Safest verdict on a confused model — never silently green-light.
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
    const fx = makeFixtureBareRepo();
    try {
      const diff = Buffer.from("x");
      const client = rejectingClient(new Error("rate_limit_error: 429 Too Many Requests"));
      const r = await runReviewPipeline(
        fixtureInput(fx.bareDir, fx.baseSha, diff, { anthropic: client }),
      );
      assert.equal(r.verdict, "changes_requested");
      assert.match(r.prose, /Anthropic API call failed/);
      assert.match(r.prose, /rate_limit_error/);
      // The approval body is still well-formed — prompt_sha256 is real,
      // signature is placeholder, etc.
      assert.equal(r.approval.verdict, "changes_requested");
      assert.match(r.approval.prompt_sha256, /^[0-9a-f]{64}$/);
    } finally {
      fx.cleanup();
    }
  });

  it("surfaces a timeout with a clear operator message", async () => {
    const fx = makeFixtureBareRepo();
    try {
      const diff = Buffer.from("x");
      // Simulate the SDK's abort-via-signal behavior: rejection with
      // an AbortError-named Error.
      const abortErr = new Error("The operation was aborted");
      abortErr.name = "AbortError";
      const client = rejectingClient(abortErr);
      const r = await runReviewPipeline(
        fixtureInput(fx.bareDir, fx.baseSha, diff, {
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
    const fx = makeFixtureBareRepo();
    const saved = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    try {
      const diff = Buffer.from("x");
      await assert.rejects(
        runReviewPipeline(
          fixtureInput(fx.bareDir, fx.baseSha, diff, {}),
        ),
        (err: unknown) => {
          assert.ok(err instanceof ServerMissingApiKeyError);
          assert.equal((err as Error).name, "ServerMissingApiKeyError");
          assert.match(
            (err as Error).message,
            /ANTHROPIC_API_KEY is not set on the stamp-server/,
          );
          // The operator-of-server framing distinguishes from the
          // headless path's MissingApiKeyError — different remediation,
          // different prose. Pin the divergence.
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
  it("throws PromptFetchFailedError when the bare repo path doesn't exist", async () => {
    // Synthetic resolver pointing at a path that isn't a git repo —
    // forces a no_such_repo. We deliberately don't construct a fixture
    // bare repo here: we want the prompt fetch to fail.
    const diff = Buffer.from("x");
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "stamp-pipeline-empty-"));
    try {
      const input: ReviewPipelineInput = {
        diff,
        params: fixtureParams(
          "0123456789abcdef0123456789abcdef01234567",
          diff,
        ),
        caller: FIXTURE_USER,
        deps: {
          repoResolver: () => path.join(tmpDir, "no-such.git"),
          // Won't be reached — no API call should happen.
          anthropic: rejectingClient(new Error("should never be called")),
        },
      };
      await assert.rejects(runReviewPipeline(input), (err: unknown) => {
        assert.ok(err instanceof PromptFetchFailedError);
        assert.equal((err as PromptFetchFailedError).kind, "no_such_repo");
        assert.match((err as Error).message, /canonical prompt fetch failed/);
        return true;
      });
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("throws PromptFetchFailedError when the reviewer prompt is absent at base_sha", async () => {
    // Fixture bare repo has security.md committed; ask for a different
    // reviewer name and observe the no_such_file error category.
    const fx = makeFixtureBareRepo();
    try {
      const diff = Buffer.from("x");
      const input: ReviewPipelineInput = {
        diff,
        params: {
          ...fixtureParams(fx.baseSha, diff),
          reviewer: "standards", // not present in the bare
        },
        caller: FIXTURE_USER,
        deps: {
          repoResolver: () => fx.bareDir,
          anthropic: rejectingClient(new Error("should never be called")),
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
});
