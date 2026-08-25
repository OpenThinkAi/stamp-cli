/**
 * AGT-1139: `stamp review --backend/--model/--endpoint` and the matching
 * `stamp config reviewers set-endpoint/clear-endpoint/set-tools/clear-tools`
 * setters.
 *
 * This is a SURFACE ticket over the resolver AGT-1137/AGT-1138 already
 * shipped — no second selection mechanism, no new transport. The tests
 * below are organized around that constraint:
 *
 *   1. **Precedence (AC1/AC2).** The flag is threaded into
 *      `resolveReviewerBackendFrom` as a FOURTH tier above the existing
 *      env-var one, not a parallel path. Pinned from both directions: flag
 *      beats env/config, and — the actual regression risk per the ticket —
 *      omitting every flag must be byte-identical to code that predates this
 *      parameter entirely.
 *   2. **Parse-time validation (AC5).** An invalid `--backend` value, or
 *      `--endpoint` combined with `--backend anthropic`, must throw a
 *      `UsageError` before any repo/config/network access — same contract
 *      `--plan`+`--headless` already has.
 *   3. **The AGT-415 disclosure gate moves with `--endpoint` (the ticket's
 *      named hazard).** A flag-selected hosted endpoint must disclose
 *      exactly like an env-var-selected one; a flag-selected loopback
 *      endpoint must not. Exercised through `runReview` itself (not just the
 *      predicate it composes), using the fact that the disclosure decision
 *      happens before any network call — so a missing-credential / refused
 *      connection failure downstream doesn't invalidate the assertion.
 *   4. **Provenance (AC6).** A flag-selected backend feeds
 *      `backendProvenance` exactly like a config-selected one — the same
 *      composition `runReview` performs when building `provenanceByReviewer`.
 *   5. **The new `stamp config reviewers` setters.** Round-trip through
 *      `~/.stamp/config.yml`, and never mutate it from a `stamp review` flag
 *      (AC2's other half).
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import { runReview } from "../src/commands/review.ts";
import {
  runConfigReviewersClearEndpoint,
  runConfigReviewersClearTools,
  runConfigReviewersSetEndpoint,
  runConfigReviewersSetTools,
} from "../src/commands/config.ts";
import { backendProvenance, formatProvenance } from "../src/lib/provenance.ts";
import { isLoopbackEndpoint } from "../src/lib/providerCredentials.ts";
import {
  loadUserConfig,
  REVIEWER_BACKEND_FLAG_VALUES,
  resolveReviewerBackendFrom,
  writeUserConfig,
  type ReviewerBackendOverride,
  type UserConfig,
} from "../src/lib/userConfig.ts";
import { userConfigPath } from "../src/lib/paths.ts";

const OPENAI_URL = "https://api.openai.com/v1";
const LOCALHOST_URL = "http://localhost:8000/v1";

const MANAGED_ENV_KEYS = [
  "STAMP_REVIEWER_BACKEND",
  "STAMP_LOCAL_MODEL",
  "STAMP_LOCAL_ENDPOINT",
  "STAMP_OPENAI_COMPATIBLE_MODEL",
  "STAMP_OPENAI_COMPATIBLE_ENDPOINT",
  "STAMP_OPENAI_API_KEY",
  "STAMP_DEEPSEEK_API_KEY",
  "OPENAI_API_KEY",
  "DEEPSEEK_API_KEY",
  // Ambient-shell hazards for the runReview() integration tests below
  // (section 3): none of these gate CREDENTIAL resolution, but several gate
  // whether disclosure/notice TEXT is printed at all, which is exactly what
  // those tests assert on. A shell that happens to export one of these
  // (e.g. from an earlier manual `STAMP_SUPPRESS_LLM_NOTICE=1 stamp review`)
  // must not change whether these tests pass — that was the actual AGT-1139
  // hermeticity bug: STAMP_SUPPRESS_LLM_NOTICE ambient in the merge
  // environment silenced the disclosure this suite asserts on, which had
  // nothing to do with credential resolution.
  "STAMP_SUPPRESS_LLM_NOTICE",
  "STAMP_NO_LLM",
  "STAMP_ANTHROPIC_NO_RETAIN",
] as const;

/** Run `fn` with exactly the given env keys set; everything else in the
 *  managed namespace cleared, then restored. */
function withEnv(vars: Record<string, string>, fn: () => void): void {
  const saved: Record<string, string | undefined> = {};
  for (const k of MANAGED_ENV_KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  try {
    for (const [k, v] of Object.entries(vars)) process.env[k] = v;
    fn();
  } finally {
    for (const k of MANAGED_ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

// ---------------------------------------------------------------------------
// 1. AC1/AC2 — precedence: flag > env > config > default
// ---------------------------------------------------------------------------

describe("AGT-1139 AC1: --backend/--model/--endpoint beat env and config", () => {
  it("--backend beats STAMP_REVIEWER_BACKEND", () => {
    withEnv({ STAMP_REVIEWER_BACKEND: "openai-compatible" }, () => {
      const override: ReviewerBackendOverride = { backend: "anthropic" };
      const b = resolveReviewerBackendFrom(null, "security", override);
      assert.deepEqual(b, { kind: "anthropic", model: null });
    });
  });

  it("--model beats STAMP_OPENAI_COMPATIBLE_MODEL", () => {
    withEnv(
      { STAMP_REVIEWER_BACKEND: "openai-compatible", STAMP_OPENAI_COMPATIBLE_MODEL: "env-model" },
      () => {
        const override: ReviewerBackendOverride = { model: "flag-model" };
        const b = resolveReviewerBackendFrom(null, "security", override);
        assert.equal((b as { model: string }).model, "flag-model");
      },
    );
  });

  it("--model beats the reviewer's configured scheme value (no --backend flag)", () => {
    const cfg: UserConfig = {
      reviewers: { security: "openai-compatible:cfg-model" },
    };
    withEnv({}, () => {
      const b = resolveReviewerBackendFrom(cfg, "security", { model: "flag-model" });
      assert.deepEqual(b, {
        kind: "openai-compatible",
        model: "flag-model",
        endpoint: undefined,
        enableTools: false,
      });
    });
  });

  it("--endpoint beats STAMP_OPENAI_COMPATIBLE_ENDPOINT", () => {
    withEnv(
      {
        STAMP_REVIEWER_BACKEND: "openai-compatible",
        STAMP_OPENAI_COMPATIBLE_ENDPOINT: "http://localhost:1111/v1",
      },
      () => {
        const override: ReviewerBackendOverride = {
          model: "m",
          endpoint: "http://localhost:2222/v1",
        };
        const b = resolveReviewerBackendFrom(null, "security", override);
        assert.equal((b as { endpoint: string }).endpoint, "http://localhost:2222/v1");
      },
    );
  });

  it("--endpoint beats the configured openai_compatible_endpoint (no --backend flag)", () => {
    const cfg: UserConfig = {
      reviewers: { security: "openai-compatible:cfg-model" },
      openai_compatible_endpoint: "http://localhost:3333/v1",
    };
    withEnv({}, () => {
      const b = resolveReviewerBackendFrom(cfg, "security", {
        endpoint: "http://localhost:4444/v1",
      });
      assert.equal((b as { endpoint: string }).endpoint, "http://localhost:4444/v1");
    });
  });

  it("--backend local is honored as the legacy alias for openai-compatible", () => {
    withEnv({}, () => {
      const b = resolveReviewerBackendFrom(null, "security", {
        backend: "local",
        model: "m",
        endpoint: LOCALHOST_URL,
      });
      assert.deepEqual(b, {
        kind: "openai-compatible",
        model: "m",
        endpoint: LOCALHOST_URL,
        enableTools: false,
      });
    });
  });

  it("REVIEWER_BACKEND_FLAG_VALUES is exactly {anthropic, openai-compatible, local}", () => {
    assert.deepEqual(
      [...REVIEWER_BACKEND_FLAG_VALUES].sort(),
      ["anthropic", "local", "openai-compatible"].sort(),
    );
  });
});

describe("AGT-1139 AC1: no flag passed => behaviour is UNCHANGED (the regression risk)", () => {
  it("omitting the third argument entirely matches passing an empty override", () => {
    const cfg: UserConfig = {
      reviewers: { security: "openai-compatible:cfg-model" },
      openai_compatible_endpoint: LOCALHOST_URL,
    };
    withEnv({}, () => {
      const withoutArg = resolveReviewerBackendFrom(cfg, "security");
      const withEmptyOverride = resolveReviewerBackendFrom(cfg, "security", {});
      assert.deepEqual(withoutArg, withEmptyOverride);
      assert.deepEqual(withoutArg, {
        kind: "openai-compatible",
        model: "cfg-model",
        endpoint: LOCALHOST_URL,
        enableTools: false,
      });
    });
  });

  it("STAMP_REVIEWER_BACKEND=local still resolves identically with no override arg", () => {
    // Same fixture AGT-1138's own alias-compatibility test pins — repeated
    // here with an explicit `undefined` override to nail down that adding
    // the parameter did not perturb the pre-existing env-var path.
    withEnv(
      {
        STAMP_REVIEWER_BACKEND: "local",
        STAMP_LOCAL_MODEL: "qwen3-coder-30b",
        STAMP_LOCAL_ENDPOINT: LOCALHOST_URL,
      },
      () => {
        assert.deepEqual(resolveReviewerBackendFrom(null, "security", undefined), {
          kind: "openai-compatible",
          model: "qwen3-coder-30b",
          endpoint: LOCALHOST_URL,
          enableTools: false,
        });
      },
    );
  });

  it("a plain Anthropic config value with no override resolves as before", () => {
    const cfg: UserConfig = { reviewers: { security: "claude-opus-4-7" } };
    withEnv({}, () => {
      assert.deepEqual(resolveReviewerBackendFrom(cfg, "security"), {
        kind: "anthropic",
        model: "claude-opus-4-7",
      });
    });
  });

  it("no config, no env, no override resolves to the SDK default", () => {
    withEnv({}, () => {
      assert.deepEqual(resolveReviewerBackendFrom(null, "security"), {
        kind: "anthropic",
        model: null,
      });
    });
  });
});

// ---------------------------------------------------------------------------
// 2. AC5 — invalid combinations rejected at PARSE TIME
// ---------------------------------------------------------------------------

describe("AGT-1139 AC5: invalid --backend/--endpoint combinations are rejected at parse time", () => {
  it("rejects an unrecognised --backend value before any repo access", async () => {
    await assert.rejects(
      runReview({ diff: "main..feature", backend: "gpt5-direct" }),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.equal((err as Error).name, "UsageError");
        assert.match((err as Error).message, /--backend 'gpt5-direct' is invalid/);
        assert.match((err as Error).message, /anthropic/);
        assert.match((err as Error).message, /openai-compatible/);
        return true;
      },
    );
  });

  it("rejects --endpoint combined with --backend anthropic, naming the conflict", async () => {
    await assert.rejects(
      runReview({
        diff: "main..feature",
        backend: "anthropic",
        endpoint: "https://api.openai.com/v1",
      }),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.equal((err as Error).name, "UsageError");
        assert.match((err as Error).message, /--endpoint is not applicable/);
        assert.match((err as Error).message, /anthropic/);
        return true;
      },
    );
  });

  it("--backend is case-insensitive and accepts the legacy 'local' alias", async () => {
    // Neither of these should hit the invalid-value branch; they'll fail
    // later for the unrelated reason that there's no repo in cwd, which
    // proves parse-time validation let them through.
    await assert.rejects(
      runReview({ diff: "main..feature", backend: "LOCAL" }),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.notEqual((err as Error).name, "UsageError");
        return true;
      },
    );
  });
});

// ---------------------------------------------------------------------------
// 3. The AGT-415 disclosure gate moves with --endpoint
// ---------------------------------------------------------------------------

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: "pipe" });
}

const SECURITY_PROMPT = "# security reviewer\n\nFlag exploitable changes.\n";

function setupRepoOnCwd(): { repo: string; restoreCwd: () => void } {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "stamp-backend-flags-")));
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
  const captured: Captured = { stdout: "", stderr: "", restore: () => {} };
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

describe("AGT-1139: --endpoint moves the AGT-415 data-flow disclosure", () => {
  let cleanup: (() => void) | null = null;
  let tmpHome: string;
  let savedHome: string | undefined;
  let savedExitCode: number | undefined;

  beforeEach(() => {
    const f = setupRepoOnCwd();
    tmpHome = mkdtempSync(join(tmpdir(), "stamp-backend-flags-home-"));
    savedHome = process.env.HOME;
    process.env.HOME = tmpHome;
    savedExitCode = process.exitCode;
    cleanup = () => {
      f.restoreCwd();
      rmSync(f.repo, { recursive: true, force: true });
      rmSync(tmpHome, { recursive: true, force: true });
      if (savedHome === undefined) delete process.env.HOME;
      else process.env.HOME = savedHome;
      process.exitCode = savedExitCode;
    };
  });

  afterEach(() => {
    if (cleanup) cleanup();
    cleanup = null;
  });

  it("a flag-selected HOSTED endpoint discloses that the diff leaves the host", async () => {
    await withEnvAsync({}, async () => {
      const cap = captureStreams();
      try {
        // The disclosure block (review.ts: `if (offHostCount > 0) { ... }`)
        // runs and prints BEFORE any reviewer is invoked — it does not
        // depend on, wait on, or get gated by credential resolution, which
        // only happens later, inside invokeLocalReviewer's buildClient(),
        // at actual invocation time. So this assertion is unconditionally
        // true for ANY outcome of the reviewer call that follows.
        //
        // What the reviewer call itself does here is a SEPARATE, also-
        // deterministic concern with no relevance to the assertions below:
        // with every credential env var cleared by withEnvAsync (see
        // MANAGED_ENV_KEYS) and no provider_keys in the fresh tmpHome
        // config, credential resolution for api.openai.com finds nothing
        // and buildClient() throws its missing-credential error BEFORE any
        // fetch — so this test makes no network call and needs none.
        //
        // The ONE thing that genuinely gates whether the disclosure TEXT
        // below gets printed at all is STAMP_SUPPRESS_LLM_NOTICE
        // (dataFlow.ts: `noticesSuppressed()`), which is why it — along
        // with every credential var — is in MANAGED_ENV_KEYS and cleared by
        // withEnvAsync. A prior version of this test omitted it, which
        // passed only in a shell with that var unset and failed identically
        // to a real defect (missing disclosure) wherever it happened to be
        // exported (e.g. a `stamp merge` environment inheriting it from an
        // earlier `STAMP_SUPPRESS_LLM_NOTICE=1 stamp review` invocation).
        await runReview({
          diff: "main..feature",
          backend: "openai-compatible",
          model: "gpt-5",
          endpoint: OPENAI_URL,
        });
      } finally {
        cap.restore();
      }
      const out = cap.stdout + cap.stderr;
      assert.doesNotMatch(
        out,
        /the diff stays on this host/,
        "a hosted endpoint must NOT be reported as staying on this host",
      );
      assert.match(
        out,
        /diff sent off-host for review/,
        "the AGT-415 off-host marker must fire for a hosted --endpoint",
      );
    });
  });

  it("a flag-selected LOOPBACK endpoint does NOT disclose", async () => {
    await withEnvAsync({}, async () => {
      const cap = captureStreams();
      try {
        // Port 1 has no listener; the fetch fails fast with ECONNREFUSED
        // (no real server needed) — again, after the disclosure decision.
        await runReview({
          diff: "main..feature",
          backend: "openai-compatible",
          model: "m",
          endpoint: "http://127.0.0.1:1/v1",
        });
      } finally {
        cap.restore();
      }
      const out = cap.stdout + cap.stderr;
      assert.match(
        out,
        /the diff stays on this host/,
        "a loopback endpoint must be reported as staying on this host",
      );
      assert.doesNotMatch(
        out,
        /diff sent off-host for review/,
        "the AGT-415 off-host marker must NOT fire for a loopback --endpoint",
      );
    });
  });

  it("verifies the same predicate `backendSendsOffHost` composes: isLoopbackEndpoint", () => {
    // Direct pin on the primitive the command layer's off-host check is
    // built from, independent of the full runReview integration above.
    const hosted = resolveReviewerBackendFrom(null, "security", {
      backend: "openai-compatible",
      model: "gpt-5",
      endpoint: OPENAI_URL,
    });
    const loopback = resolveReviewerBackendFrom(null, "security", {
      backend: "openai-compatible",
      model: "m",
      endpoint: LOCALHOST_URL,
    });
    assert.equal(isLoopbackEndpoint((hosted as { endpoint: string }).endpoint), false);
    assert.equal(isLoopbackEndpoint((loopback as { endpoint: string }).endpoint), true);
  });
});

/** async sibling of `withEnv` for tests that await inside the callback. */
async function withEnvAsync(
  vars: Record<string, string>,
  fn: () => Promise<void>,
): Promise<void> {
  const saved: Record<string, string | undefined> = {};
  for (const k of MANAGED_ENV_KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  try {
    for (const [k, v] of Object.entries(vars)) process.env[k] = v;
    await fn();
  } finally {
    for (const k of MANAGED_ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

// ---------------------------------------------------------------------------
// 4. AC6 — a flag-selected backend feeds provenance exactly like config does
// ---------------------------------------------------------------------------

describe("AGT-1139 AC6: a flag-selected backend produces normal provenance", () => {
  it("backendProvenance(resolved-via-flag) records the flag's kind/model/endpoint", () => {
    const backend = resolveReviewerBackendFrom(null, "security", {
      backend: "openai-compatible",
      model: "deepseek-chat",
      endpoint: "https://api.deepseek.com/v1",
    });
    const prov = backendProvenance(backend);
    assert.equal(prov.backend_kind, "local"); // stored literal, per AGT-1137/1138
    assert.equal(prov.backend_model, "deepseek-chat");
    assert.equal(prov.backend_endpoint, "https://api.deepseek.com/v1");
    assert.equal(
      formatProvenance(prov),
      "openai-compatible / deepseek-chat @ https://api.deepseek.com/v1",
    );
  });

  it("a flag-forced anthropic backend records anthropic provenance with the pinned model", () => {
    const cfg: UserConfig = { reviewers: { security: "openai-compatible:qwen" } };
    const backend = resolveReviewerBackendFrom(cfg, "security", {
      backend: "anthropic",
      model: "claude-opus-4-7",
    });
    const prov = backendProvenance(backend);
    assert.deepEqual(prov, {
      backend_kind: "anthropic",
      backend_model: "claude-opus-4-7",
      backend_endpoint: null,
    });
  });
});

// ---------------------------------------------------------------------------
// 5. AC3 — `stamp config reviewers set-endpoint/clear-endpoint/set-tools/clear-tools`
// ---------------------------------------------------------------------------

describe("AGT-1139 AC3: config setters for the endpoint and the tools opt-in", () => {
  let tmpHome: string;
  let savedHome: string | undefined;

  beforeEach(() => {
    tmpHome = mkdtempSync(join(tmpdir(), "stamp-backend-flags-cfg-"));
    savedHome = process.env.HOME;
    process.env.HOME = tmpHome;
  });

  afterEach(() => {
    if (savedHome === undefined) delete process.env.HOME;
    else process.env.HOME = savedHome;
    rmSync(tmpHome, { recursive: true, force: true });
  });

  it("set-endpoint writes the canonical openai_compatible_endpoint", () => {
    runConfigReviewersSetEndpoint("https://api.openai.com/v1");
    const cfg = loadUserConfig();
    assert.equal(cfg?.openai_compatible_endpoint, "https://api.openai.com/v1");
  });

  it("set-endpoint rejects a non-http(s) value", () => {
    assert.throws(
      () => runConfigReviewersSetEndpoint("not-a-url"),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.equal((err as Error).name, "UsageError");
        return true;
      },
    );
  });

  it("clear-endpoint removes both the canonical and legacy keys", () => {
    writeUserConfig({
      reviewers: {},
      openai_compatible_endpoint: "https://api.openai.com/v1",
      local_endpoint: "http://localhost:1234/v1",
    });
    runConfigReviewersClearEndpoint();
    const cfg = loadUserConfig();
    assert.equal(cfg?.openai_compatible_endpoint, undefined);
    assert.equal(cfg?.local_endpoint, undefined);
  });

  it("clear-endpoint is a no-op note when nothing is configured", () => {
    // Must not throw, must not create a file with an empty reviewers map
    // where none existed.
    runConfigReviewersClearEndpoint();
    const cfg = loadUserConfig();
    assert.equal(cfg, null);
  });

  it("set-tools accepts true/false/on/off/1/0 and writes a strict boolean", () => {
    runConfigReviewersSetTools("on");
    assert.equal(loadUserConfig()?.openai_compatible_tools, true);
    runConfigReviewersSetTools("0");
    assert.equal(loadUserConfig()?.openai_compatible_tools, false);
  });

  it("set-tools rejects an unrecognised value rather than guessing", () => {
    assert.throws(
      () => runConfigReviewersSetTools("enabled"),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.equal((err as Error).name, "UsageError");
        assert.match((err as Error).message, /true, false, on, off, 1, 0/);
        return true;
      },
    );
  });

  it("clear-tools removes both the canonical and legacy keys", () => {
    writeUserConfig({
      reviewers: {},
      openai_compatible_tools: true,
      local_tools: true,
    });
    runConfigReviewersClearTools();
    const cfg = loadUserConfig();
    assert.equal(cfg?.openai_compatible_tools, undefined);
    assert.equal(cfg?.local_tools, undefined);
  });

  it("set-endpoint round-trips through the YAML file on disk", () => {
    runConfigReviewersSetEndpoint("http://localhost:9999/v1");
    const raw = readFileSync(userConfigPath(), "utf8");
    assert.match(raw, /openai_compatible_endpoint: http:\/\/localhost:9999\/v1/);
  });
});

// ---------------------------------------------------------------------------
// AC2 — a `stamp review` flag never mutates ~/.stamp/config.yml
// ---------------------------------------------------------------------------

describe("AGT-1139 AC2: a --backend/--model/--endpoint flag never writes config.yml", () => {
  let cleanup: (() => void) | null = null;
  let tmpHome: string;
  let savedHome: string | undefined;
  let savedExitCode: number | undefined;

  beforeEach(() => {
    const f = setupRepoOnCwd();
    tmpHome = mkdtempSync(join(tmpdir(), "stamp-backend-flags-nowrite-"));
    savedHome = process.env.HOME;
    process.env.HOME = tmpHome;
    savedExitCode = process.exitCode;
    cleanup = () => {
      f.restoreCwd();
      rmSync(f.repo, { recursive: true, force: true });
      rmSync(tmpHome, { recursive: true, force: true });
      if (savedHome === undefined) delete process.env.HOME;
      else process.env.HOME = savedHome;
      process.exitCode = savedExitCode;
    };
  });

  afterEach(() => {
    if (cleanup) cleanup();
    cleanup = null;
  });

  it("config.yml is byte-identical before and after a flag-driven run", async () => {
    // Seed a config file directly (skip a flagless runReview call — a
    // default-backend run would resolve to `anthropic` and actually invoke
    // the Claude Agent SDK, which this test must not do).
    writeUserConfig({ reviewers: { security: "claude-opus-4-7" } });
    const before = readFileSync(userConfigPath(), "utf8");

    await withEnvAsync({}, async () => {
      const cap = captureStreams();
      try {
        // Loopback + no listener: the flag-forced backend fails fast with
        // no network dependency and no cost, but the resolution + provenance
        // + credential-lookup machinery around it all still runs for real.
        await runReview({
          diff: "main..feature",
          backend: "openai-compatible",
          model: "m",
          endpoint: "http://127.0.0.1:1/v1",
        });
      } finally {
        cap.restore();
      }
    });
    const after = readFileSync(userConfigPath(), "utf8");
    assert.equal(after, before, "a review flag must never mutate ~/.stamp/config.yml");
  });
});
