/**
 * Tests for `runReview({ plan: true })` — the command-layer wiring that
 * emits the plan as JSON on stdout and the no-trust banner on stderr.
 *
 * Hard contract (AGT-339): stdout is strictly the JSON plan, parseable as
 * a single JSON document with nothing else mixed in. The banner — and any
 * other human-facing prose — goes to stderr. AGT-340's Claude Code skill
 * pipes stdout into `JSON.parse`; any incidental text would break it.
 *
 * Test approach: monkey-patch `process.stdout.write` / `process.stderr.write`
 * for the duration of one call, capture both streams, then restore. This
 * avoids spawning a subprocess (slow + flaky in CI) while still exercising
 * the real `runReview` path including the commander → runReview boundary.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import { runReview } from "../src/commands/review.ts";

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: "pipe" });
}

const SECURITY_PROMPT = "# security reviewer\n\nFlag exploitable changes.\n";

function setupRepoOnCwd(): { repo: string; restoreCwd: () => void } {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "stamp-plan-cmd-")));
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
  writeFileSync(join(repo, ".stamp", "reviewers", "security.md"), SECURITY_PROMPT);
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
  (process.stdout.write as unknown) = ((chunk: unknown) => {
    captured.stdout += typeof chunk === "string" ? chunk : String(chunk);
    return true;
  });
  (process.stderr.write as unknown) = ((chunk: unknown) => {
    captured.stderr += typeof chunk === "string" ? chunk : String(chunk);
    return true;
  });
  captured.restore = () => {
    (process.stdout.write as unknown) = origStdoutWrite;
    (process.stderr.write as unknown) = origStderrWrite;
  };
  return captured;
}

describe("runReview({ plan: true }) — stdout/stderr separation", () => {
  let cleanup: (() => void) | null = null;
  let repo: string;

  beforeEach(() => {
    const f = setupRepoOnCwd();
    repo = f.repo;
    cleanup = () => {
      f.restoreCwd();
      rmSync(repo, { recursive: true, force: true });
    };
  });

  afterEach(() => {
    if (cleanup) cleanup();
    cleanup = null;
  });

  it("emits strictly-JSON-parseable output on stdout", async () => {
    const cap = captureStreams();
    try {
      await runReview({ diff: "main..feature", plan: true });
    } finally {
      cap.restore();
    }
    // Stdout is just the JSON plan + trailing newline. `JSON.parse` will
    // throw if anything extra (a progress bar, a banner, a "running 1
    // reviewer..." line) leaked through.
    const trimmed = cap.stdout.trimEnd();
    assert.doesNotThrow(() => JSON.parse(trimmed), `stdout not pure JSON: ${cap.stdout!}`);
    const plan = JSON.parse(trimmed) as { schema_version: number; reviewers: { name: string }[] };
    assert.equal(plan.schema_version, 1);
    assert.deepEqual(plan.reviewers.map((r) => r.name), ["security"]);
  });

  it("writes the no-trust banner to stderr only (not stdout)", async () => {
    const cap = captureStreams();
    try {
      await runReview({ diff: "main..feature", plan: true });
    } finally {
      cap.restore();
    }
    assert.match(cap.stderr, /iteration feedback only/);
    assert.match(cap.stderr, /No attestation will be created/);
    assert.match(cap.stderr, /review_server/);
    // The banner phrases MUST NOT appear on stdout (would break JSON parse
    // and is the specific anti-pattern AGT-339 calls out).
    assert.doesNotMatch(cap.stdout, /iteration feedback only/);
    assert.doesNotMatch(cap.stdout, /No attestation/);
  });

  it("does NOT touch the LLM (no STAMP_NO_LLM throw, no network call)", async () => {
    // Belt-and-suspenders: with STAMP_NO_LLM=1 the trusted-mode path
    // throws immediately. --plan must short-circuit BEFORE that guard so
    // setting STAMP_NO_LLM=1 doesn't break local-only iteration.
    const saved = process.env.STAMP_NO_LLM;
    process.env.STAMP_NO_LLM = "1";
    const cap = captureStreams();
    try {
      await runReview({ diff: "main..feature", plan: true });
    } finally {
      cap.restore();
      if (saved === undefined) delete process.env.STAMP_NO_LLM;
      else process.env.STAMP_NO_LLM = saved;
    }
    const trimmed = cap.stdout.trimEnd();
    const plan = JSON.parse(trimmed) as { reviewers: unknown[] };
    assert.equal(plan.reviewers.length, 1);
  });
});
