/**
 * Tests for `runReview({ headless: true })` — the command-layer wiring
 * that calls runHeadlessReview per reviewer in parallel and emits the
 * JSON envelope on stdout + the no-trust banner on stderr (AGT-341).
 *
 * Hard contracts:
 *   - stdout is strictly JSON-parseable (same as --plan; AC #3).
 *   - banner-to-stderr, never to stdout.
 *   - output shape is a superset of --plan: every reviewer has the
 *     plan fields (name, prompt, fence_hex) PLUS the headless additions
 *     (verdict, prose, model, optional error). Downstream tooling that
 *     can read --plan must be able to read --headless without branching.
 *   - missing ANTHROPIC_API_KEY → UsageError-shaped throw with the docs
 *     pointer in the message.
 *   - --plan + --headless together → UsageError-shaped throw.
 *
 * Test approach mirrors tests/reviewPlanCommand.test.ts: monkey-patch
 * process.stdout/stderr.write, run runReview directly (no subprocess),
 * restore. The Anthropic client is replaced via a module-mock that
 * stubs `runHeadlessReview` so no real API call happens.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import { runReview } from "../src/commands/review.ts";
import type { HeadlessReviewerResult } from "../src/lib/headlessReviewer.ts";
import type { ReviewPlanReviewer } from "../src/lib/reviewPlan.ts";

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: "pipe" });
}

const SECURITY_PROMPT = "# security reviewer\n\nFlag exploitable changes.\n";

function setupRepoOnCwd(): { repo: string; restoreCwd: () => void } {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "stamp-headless-cmd-")));
  const repo = join(tmp, "repo");
  mkdirSync(repo);
  git(["init", "-q", "-b", "main", repo], tmp);
  git(["config", "user.email", "t@t.t"], repo);
  git(["config", "user.name", "t"], repo);
  git(["config", "commit.gpgsign", "false"], repo);
  mkdirSync(join(repo, ".stamp", "reviewers"), { recursive: true });
  writeFileSync(
    join(repo, ".stamp", "config.yml"),
    [
      "branches:",
      "  main:",
      "    required: [security]",
      "reviewers:",
      "  security:",
      "    prompt: .stamp/reviewers/security.md",
      "",
    ].join("\n"),
  );
  writeFileSync(
    join(repo, ".stamp", "reviewers", "security.md"),
    SECURITY_PROMPT,
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
  return { repo, restoreCwd: () => process.chdir(prevCwd) };
}

interface Captured {
  stdout: string;
  stderr: string;
  restore: () => void;
}

function captureStreams(): Captured {
  const captured: Captured = {
    stdout: "",
    stderr: "",
    restore: () => {},
  };
  const origStdoutWrite = process.stdout.write.bind(process.stdout);
  const origStderrWrite = process.stderr.write.bind(process.stderr);
  (process.stdout.write as unknown) = (chunk: unknown) => {
    captured.stdout += typeof chunk === "string" ? chunk : String(chunk);
    return true;
  };
  (process.stderr.write as unknown) = (chunk: unknown) => {
    captured.stderr += typeof chunk === "string" ? chunk : String(chunk);
    return true;
  };
  captured.restore = () => {
    (process.stdout.write as unknown) = origStdoutWrite;
    (process.stderr.write as unknown) = origStderrWrite;
  };
  return captured;
}

/**
 * Snapshot env vars touched by the suite, restore in afterEach. Belt-and-
 * suspenders against test-ordering bleed: a stray ANTHROPIC_API_KEY from
 * the operator's shell would otherwise turn the missing-key test into a
 * real API call.
 */
function withCleanApiKeyEnv(): { restore: () => void } {
  const savedKey = process.env.ANTHROPIC_API_KEY;
  const savedExitCode = process.exitCode;
  return {
    restore: () => {
      if (savedKey === undefined) delete process.env.ANTHROPIC_API_KEY;
      else process.env.ANTHROPIC_API_KEY = savedKey;
      process.exitCode = savedExitCode;
    },
  };
}

describe("runReview({ headless: true }) — missing API key contract", () => {
  let cleanup: (() => void) | null = null;
  let envRestore: (() => void) | null = null;

  beforeEach(() => {
    const f = setupRepoOnCwd();
    cleanup = () => {
      f.restoreCwd();
      rmSync(f.repo, { recursive: true, force: true });
    };
    const e = withCleanApiKeyEnv();
    envRestore = e.restore;
    // Force-unset for the duration of the test even if the operator has
    // it exported — the test is about the missing-key path.
    delete process.env.ANTHROPIC_API_KEY;
  });

  afterEach(() => {
    if (cleanup) cleanup();
    cleanup = null;
    if (envRestore) envRestore();
    envRestore = null;
  });

  it("throws UsageError with docs pointer when ANTHROPIC_API_KEY is unset", async () => {
    await assert.rejects(
      runReview({ diff: "main..feature", headless: true }),
      (err: unknown) => {
        // UsageError surfaces by name (not instanceof — see UsageError
        // comment in src/commands/serverRepo.ts and the handleCliError
        // logic in src/index.ts). Exit-code-2 routing keys off .name.
        assert.ok(err instanceof Error);
        assert.equal((err as Error).name, "UsageError");
        assert.match((err as Error).message, /ANTHROPIC_API_KEY is not set/);
        assert.match((err as Error).message, /docs\/local-only-mode\.md/);
        return true;
      },
    );
  });
});

describe("runReview — flag conflict guard", () => {
  let cleanup: (() => void) | null = null;

  beforeEach(() => {
    const f = setupRepoOnCwd();
    cleanup = () => {
      f.restoreCwd();
      rmSync(f.repo, { recursive: true, force: true });
    };
  });

  afterEach(() => {
    if (cleanup) cleanup();
    cleanup = null;
  });

  it("rejects --plan + --headless as mutually exclusive (UsageError)", async () => {
    await assert.rejects(
      runReview({ diff: "main..feature", plan: true, headless: true }),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.equal((err as Error).name, "UsageError");
        assert.match(
          (err as Error).message,
          /mutually exclusive/,
        );
        return true;
      },
    );
  });
});

/**
 * Test fake for the per-reviewer headless impl. Threaded into runReview
 * via the documented `_headlessReviewerForTest` injection seam (see
 * src/commands/review.ts `ReviewOptions`) so the command-layer tests
 * exercise stdout/stderr/exit-code wiring without standing up a real
 * Anthropic client. Production callers (CLI in src/index.ts) leave the
 * seam undefined and the real `runHeadlessReview` runs.
 */
type ReviewerFake = (opts: {
  reviewer: ReviewPlanReviewer;
  diff: string;
  base_sha: string;
  head_sha: string;
  model: string;
}) => Promise<HeadlessReviewerResult>;

describe("runReview({ headless: true }) — stdout/stderr separation + shape", () => {
  let cleanup: (() => void) | null = null;
  let envRestore: (() => void) | null = null;

  beforeEach(() => {
    const f = setupRepoOnCwd();
    cleanup = () => {
      f.restoreCwd();
      rmSync(f.repo, { recursive: true, force: true });
    };
    const e = withCleanApiKeyEnv();
    envRestore = e.restore;
    // Give the API-key guard something to find so the test reaches the
    // fan-out. The injected mock makes the actual value irrelevant.
    process.env.ANTHROPIC_API_KEY = "sk-test-fixture-not-real";
    // Reset exit code; the assertion below relies on it being absent
    // until our happy-path test runs (and asserts it stays absent).
    process.exitCode = 0;
  });

  afterEach(() => {
    if (cleanup) cleanup();
    cleanup = null;
    if (envRestore) envRestore();
    envRestore = null;
  });

  it("emits strictly-JSON-parseable output on stdout (no prose bleed)", async () => {
    const fake: ReviewerFake = async (opts) => ({
      ...opts.reviewer,
      verdict: "approved",
      prose: "no findings",
      model: opts.model,
    });
    const cap = captureStreams();
    try {
      await runReview({
        diff: "main..feature",
        headless: true,
        _headlessReviewerForTest: fake,
      });
    } finally {
      cap.restore();
    }
    const trimmed = cap.stdout.trimEnd();
    assert.doesNotThrow(
      () => JSON.parse(trimmed),
      `stdout not pure JSON: ${cap.stdout}`,
    );
  });

  it("writes the no-trust banner (with metering caveat) to stderr only", async () => {
    const fake: ReviewerFake = async (opts) => ({
      ...opts.reviewer,
      verdict: "approved",
      prose: "ok",
      model: opts.model,
    });
    const cap = captureStreams();
    try {
      await runReview({
        diff: "main..feature",
        headless: true,
        _headlessReviewerForTest: fake,
      });
    } finally {
      cap.restore();
    }
    assert.match(cap.stderr, /iteration feedback only/);
    assert.match(cap.stderr, /No attestation will be created/);
    assert.match(cap.stderr, /ANTHROPIC_API_KEY/);
    assert.match(cap.stderr, /API-billed/);
    // No banner bytes on stdout — would break JSON.parse.
    assert.doesNotMatch(cap.stdout, /iteration feedback only/);
    assert.doesNotMatch(cap.stdout, /API-billed/);
  });

  it("output shape is a superset of --plan (carries reviewer plan fields + adds verdict/prose/model)", async () => {
    const fake: ReviewerFake = async (opts) => ({
      ...opts.reviewer,
      verdict: "approved",
      prose: "no findings",
      model: opts.model,
    });
    const cap = captureStreams();
    try {
      await runReview({
        diff: "main..feature",
        headless: true,
        _headlessReviewerForTest: fake,
      });
    } finally {
      cap.restore();
    }
    const plan = JSON.parse(cap.stdout.trimEnd()) as {
      schema_version: number;
      mode?: string;
      base_sha: string;
      head_sha: string;
      diff: string;
      reviewers: Array<{
        name: string;
        prompt: string;
        fence_hex: string;
        verdict: string;
        prose: string;
        model: string;
      }>;
    };
    assert.equal(plan.schema_version, 1);
    assert.equal(plan.mode, "headless");
    // Top-level plan fields parity with --plan.
    assert.ok(plan.base_sha.length > 0);
    assert.ok(plan.head_sha.length > 0);
    assert.ok(plan.diff.length > 0);
    // Per-reviewer: every field from ReviewPlanReviewer carries through;
    // headless additions are populated.
    assert.equal(plan.reviewers.length, 1);
    const r = plan.reviewers[0]!;
    assert.equal(r.name, "security");
    assert.match(r.prompt, /security reviewer/);
    assert.match(r.fence_hex, /^[0-9a-f]{32}$/);
    assert.equal(r.verdict, "approved");
    assert.equal(r.prose, "no findings");
    assert.ok(typeof r.model === "string" && r.model.length > 0);
  });

  it("happy path: all approvals → process.exitCode is not set", async () => {
    process.exitCode = 0;
    const fake: ReviewerFake = async (opts) => ({
      ...opts.reviewer,
      verdict: "approved",
      prose: "ok",
      model: opts.model,
    });
    const cap = captureStreams();
    try {
      await runReview({
        diff: "main..feature",
        headless: true,
        _headlessReviewerForTest: fake,
      });
    } finally {
      cap.restore();
    }
    // exitCode stays whatever it was (0 here); the headless branch only
    // sets it to 1 when a reviewer failed or returned null verdict.
    assert.notEqual(process.exitCode, 1);
  });

  it("any reviewer failure → process.exitCode = 1 (cron / hook signal)", async () => {
    process.exitCode = 0;
    const fake: ReviewerFake = async (opts) => ({
      ...opts.reviewer,
      verdict: null,
      prose: "",
      model: opts.model,
      error: "Anthropic API call failed: rate_limit_error",
    });
    const cap = captureStreams();
    try {
      await runReview({
        diff: "main..feature",
        headless: true,
        _headlessReviewerForTest: fake,
      });
    } finally {
      cap.restore();
    }
    assert.equal(process.exitCode, 1);
    const plan = JSON.parse(cap.stdout.trimEnd()) as {
      reviewers: Array<{ error?: string; verdict: string | null }>;
    };
    // The failed reviewer's error is preserved in the JSON — the caller
    // gets a parseable explanation, not just a non-zero exit code.
    assert.equal(plan.reviewers[0]!.verdict, null);
    assert.match(plan.reviewers[0]!.error ?? "", /rate_limit_error/);
  });

  it("changes_requested verdict → process.exitCode = 1 (non-approved is a failure for cron callers)", async () => {
    // Regression pin: an earlier iteration's `anyFailed` predicate only
    // checked `verdict === null`, so a successful `changes_requested`
    // from every reviewer silently exited 0 — directly contradicting
    // the documented contract (docs/local-only-mode.md: "exit 1 if any
    // reviewer ... returned a non-null non-approved verdict"). The
    // primary --headless audience is cron / git hooks gating off the
    // exit code; this case must surface as a failure.
    process.exitCode = 0;
    const fake: ReviewerFake = async (opts) => ({
      ...opts.reviewer,
      verdict: "changes_requested",
      prose: "fix the foo before merging",
      model: opts.model,
    });
    const cap = captureStreams();
    try {
      await runReview({
        diff: "main..feature",
        headless: true,
        _headlessReviewerForTest: fake,
      });
    } finally {
      cap.restore();
    }
    assert.equal(process.exitCode, 1);
    const plan = JSON.parse(cap.stdout.trimEnd()) as {
      reviewers: Array<{ verdict: string | null; error?: string }>;
    };
    assert.equal(plan.reviewers[0]!.verdict, "changes_requested");
    assert.equal(plan.reviewers[0]!.error, undefined);
  });

  it("denied verdict → process.exitCode = 1 (paired regression for the changes_requested case)", async () => {
    process.exitCode = 0;
    const fake: ReviewerFake = async (opts) => ({
      ...opts.reviewer,
      verdict: "denied",
      prose: "blocking security finding",
      model: opts.model,
    });
    const cap = captureStreams();
    try {
      await runReview({
        diff: "main..feature",
        headless: true,
        _headlessReviewerForTest: fake,
      });
    } finally {
      cap.restore();
    }
    assert.equal(process.exitCode, 1);
  });
});
