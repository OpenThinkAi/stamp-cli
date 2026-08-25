/**
 * AGT-1138: OpenAI and DeepSeek reachable through the one OpenAI-compatible
 * adapter, plus the `local` → `openai-compatible` rename.
 *
 * Four concerns, in order of how badly getting them wrong would hurt:
 *
 *   1. **Credential leakage (AC1).** The highest-risk AC by a distance: a key
 *      that reaches `state.db`, a log line, or a spooled trace is a leak that
 *      outlives the process. Pinned by asserting the key's absence from the
 *      resolved backend, the persisted row, the rendered `stamp log` output,
 *      and every error string the adapter can produce — including the case
 *      where the SERVER echoes the bearer token back in a 401 body, which
 *      real gateways do.
 *
 *   2. **Alias compatibility (AC3).** A rename is only safe if the old names
 *      keep resolving identically. Every pre-AGT-1138 spelling gets its own
 *      pinning test — the open-team and schnap-it flows are running these
 *      env vars right now, and a break here breaks live automation, not a
 *      test.
 *
 *   3. **Per-provider resolution (AC2).** Pointing at DeepSeek must not send
 *      an OpenAI key. Asserted as an absence, from both directions, plus the
 *      "localhost with nothing configured still works" case that is the
 *      whole existing user base.
 *
 *   4. **Actionable failure + separability (AC4, AC6).** A missing key and a
 *      401 must name the endpoint and the fix; an OpenAI verdict and a
 *      DeepSeek verdict must be distinguishable in the record.
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import { openDb, recordReview, reviewHistory } from "../src/lib/db.ts";
import {
  createLocalReviewClient,
  LOCAL_DEFAULT_BASE_URL,
  type FetchLike,
} from "../src/lib/localReviewClient.ts";
import { invokeLocalReviewer } from "../src/lib/localReviewer.ts";
import {
  backendProvenance,
  formatProvenance,
  PROVENANCE_KIND_OPENAI_COMPATIBLE,
} from "../src/lib/provenance.ts";
import {
  isLoopbackEndpoint,
  providerEnvVar,
  providerIdForEndpoint,
  providerRequiresCredential,
  redactSecrets,
  resolveProviderCredentialFrom,
  REDACTED_MARKER,
} from "../src/lib/providerCredentials.ts";
import {
  LOCAL_MODEL_PREFIX,
  OPENAI_COMPATIBLE_MODEL_PREFIX,
  parseUserConfig,
  resolveReviewerBackendFrom,
  stringifyUserConfig,
  type ReviewerBackend,
  type UserConfig,
} from "../src/lib/userConfig.ts";

const OPENAI_URL = "https://api.openai.com/v1";
const DEEPSEEK_URL = "https://api.deepseek.com/v1";
const LOCALHOST_URL = "http://localhost:8000/v1";

/** A value distinctive enough that finding it anywhere is unambiguous. */
const SECRET = "sk-AGT1138-do-not-leak-me-0123456789";

/**
 * Run `fn` with exactly the given env keys set (everything else in the
 * credential/backend namespace cleared), then restore. Clearing rather than
 * merely overriding matters here: the developer running these tests very
 * plausibly has a real `OPENAI_API_KEY` exported, and a test that passed only
 * because of it would be worse than no test.
 */
const MANAGED_ENV_KEYS = [
  "STAMP_REVIEWER_BACKEND",
  "STAMP_LOCAL_MODEL",
  "STAMP_LOCAL_ENDPOINT",
  "STAMP_LOCAL_TOOLS",
  "STAMP_OPENAI_COMPATIBLE_MODEL",
  "STAMP_OPENAI_COMPATIBLE_ENDPOINT",
  "STAMP_OPENAI_COMPATIBLE_TOOLS",
  "STAMP_OPENAI_API_KEY",
  "STAMP_DEEPSEEK_API_KEY",
  "OPENAI_API_KEY",
  "DEEPSEEK_API_KEY",
] as const;

function withEnv(vars: Record<string, string>, fn: () => void): void {
  const saved: Record<string, string | undefined> = {};
  for (const k of MANAGED_ENV_KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  const extra = Object.keys(vars).filter(
    (k) => !(MANAGED_ENV_KEYS as readonly string[]).includes(k),
  );
  for (const k of extra) saved[k] = process.env[k];
  try {
    for (const [k, v] of Object.entries(vars)) process.env[k] = v;
    fn();
  } finally {
    for (const k of [...MANAGED_ENV_KEYS, ...extra]) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

/** A fetch that records what it was called with and replies with a verdict. */
function verdictFetch(): {
  fetchImpl: FetchLike;
  calls: Array<{ url: string; headers: Record<string, string> }>;
} {
  const calls: Array<{ url: string; headers: Record<string, string> }> = [];
  const fetchImpl: FetchLike = async (url, init) => {
    calls.push({ url, headers: init.headers });
    return {
      ok: true,
      status: 200,
      text: async () =>
        JSON.stringify({
          choices: [
            { message: { content: "Fine.\n\nVERDICT: approved" }, finish_reason: "stop" },
          ],
        }),
    };
  };
  return { fetchImpl, calls };
}

/** A fetch that fails with `status` and a body of the caller's choosing. */
function failingFetch(status: number, body: string): FetchLike {
  return async () => ({ ok: false, status, text: async () => body });
}

function baseReviewerParams(overrides: Record<string, unknown> = {}) {
  return {
    reviewer: "security",
    systemPrompt: "# security\n",
    diff: "diff --git a/a b/a\n+x\n",
    base_sha: "1".repeat(40),
    head_sha: "2".repeat(40),
    model: "gpt-5",
    endpoint: OPENAI_URL,
    enableTools: false,
    repoRoot: "/tmp/not-used",
    enforceReadsOnDotstamp: false,
    userConfig: null as UserConfig | null,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// AC2 — per-provider credential resolution
// ---------------------------------------------------------------------------

describe("AGT-1138 AC2: provider derivation from the endpoint", () => {
  it("maps the vendor hosts to their provider ids", () => {
    assert.equal(providerIdForEndpoint(OPENAI_URL), "openai");
    assert.equal(providerIdForEndpoint(DEEPSEEK_URL), "deepseek");
  });

  it("maps every loopback spelling to `local`, and only those", () => {
    for (const url of [
      "http://localhost:1234/v1",
      "http://127.0.0.1:8000/v1",
      "http://0.0.0.0:8080/v1",
      "http://[::1]:8000/v1",
    ]) {
      assert.equal(providerIdForEndpoint(url), "local", url);
      assert.equal(isLoopbackEndpoint(url), true, url);
    }
    // A LAN box is NOT loopback: its diff genuinely leaves this machine, and
    // the data-flow disclosure in `stamp review` keys on this answer.
    assert.equal(isLoopbackEndpoint("http://192.168.1.50:8000/v1"), false);
    assert.equal(isLoopbackEndpoint(OPENAI_URL), false);
  });

  it("matches vendor hosts EXACTLY — no suffix matching", () => {
    // `api.openai.com.evil.test` must never be handed an OpenAI key.
    const id = providerIdForEndpoint("https://api.openai.com.evil.test/v1");
    assert.notEqual(id, "openai");
    assert.equal(id, "api.openai.com.evil.test");
  });

  it("derives a deterministic env var name from any provider id", () => {
    assert.equal(providerEnvVar("openai"), "STAMP_OPENAI_API_KEY");
    assert.equal(providerEnvVar("deepseek"), "STAMP_DEEPSEEK_API_KEY");
    assert.equal(
      providerEnvVar("my-llm.corp.test"),
      "STAMP_MY_LLM_CORP_TEST_API_KEY",
    );
  });

  it("requires a credential only for providers known to reject anonymous calls", () => {
    assert.equal(providerRequiresCredential("openai"), true);
    assert.equal(providerRequiresCredential("deepseek"), true);
    // Back-compat: the whole existing user base points at one of these and
    // has no credential configured at all.
    assert.equal(providerRequiresCredential("local"), false);
    assert.equal(providerRequiresCredential("192.168.1.50"), false);
  });
});

describe("AGT-1138 AC2: credentials are per-provider, never shared", () => {
  it("localhost with NO credential configured still resolves cleanly", () => {
    const c = resolveProviderCredentialFrom(null, LOCALHOST_URL, {});
    assert.equal(c.apiKey, null);
    assert.equal(c.required, false);
    assert.equal(c.source, null);
    assert.equal(c.providerId, "local");
  });

  it("does NOT send an OpenAI key to DeepSeek", () => {
    const c = resolveProviderCredentialFrom(null, DEEPSEEK_URL, {
      OPENAI_API_KEY: SECRET,
      STAMP_OPENAI_API_KEY: SECRET,
    });
    assert.equal(
      c.apiKey,
      null,
      "an OpenAI credential must not be resolved for a DeepSeek endpoint",
    );
    assert.equal(c.required, true, "and the absence must be a hard failure");
  });

  it("does NOT send a DeepSeek key to OpenAI", () => {
    const c = resolveProviderCredentialFrom(null, OPENAI_URL, {
      DEEPSEEK_API_KEY: SECRET,
      STAMP_DEEPSEEK_API_KEY: SECRET,
    });
    assert.equal(c.apiKey, null);
  });

  it("does NOT forward an ambient vendor key to an unrecognised endpoint", () => {
    // The operator has OPENAI_API_KEY exported for unrelated tooling and
    // points a reviewer at their own gateway. Nothing of OpenAI's goes there.
    const c = resolveProviderCredentialFrom(null, "https://llm.corp.test/v1", {
      OPENAI_API_KEY: SECRET,
      DEEPSEEK_API_KEY: SECRET,
    });
    assert.equal(c.apiKey, null);
    assert.equal(c.providerId, "llm.corp.test");
    assert.equal(c.required, false, "an unknown host keeps the old behaviour");
  });

  it("resolves each provider from its own stamp-namespaced variable", () => {
    const env = {
      STAMP_OPENAI_API_KEY: "openai-key",
      STAMP_DEEPSEEK_API_KEY: "deepseek-key",
    };
    assert.equal(
      resolveProviderCredentialFrom(null, OPENAI_URL, env).apiKey,
      "openai-key",
    );
    assert.equal(
      resolveProviderCredentialFrom(null, DEEPSEEK_URL, env).apiKey,
      "deepseek-key",
    );
  });

  it("falls back to the conventional vendor variable for that vendor's host", () => {
    const c = resolveProviderCredentialFrom(null, OPENAI_URL, {
      OPENAI_API_KEY: "vendor-key",
    });
    assert.equal(c.apiKey, "vendor-key");
    assert.equal(c.source, "OPENAI_API_KEY");
  });

  it("prefers the stamp-namespaced variable over the vendor one", () => {
    const c = resolveProviderCredentialFrom(null, OPENAI_URL, {
      STAMP_OPENAI_API_KEY: "stamp-key",
      OPENAI_API_KEY: "vendor-key",
    });
    assert.equal(c.apiKey, "stamp-key");
    assert.equal(c.source, "STAMP_OPENAI_API_KEY");
  });

  it("falls back to provider_keys in ~/.stamp/config.yml, per provider", () => {
    const cfg: UserConfig = {
      reviewers: {},
      provider_keys: { openai: "cfg-openai", deepseek: "cfg-deepseek" },
    };
    assert.equal(
      resolveProviderCredentialFrom(cfg, OPENAI_URL, {}).apiKey,
      "cfg-openai",
    );
    assert.equal(
      resolveProviderCredentialFrom(cfg, DEEPSEEK_URL, {}).apiKey,
      "cfg-deepseek",
    );
    assert.match(
      resolveProviderCredentialFrom(cfg, OPENAI_URL, {}).source!,
      /provider_keys\.openai/,
    );
  });

  it("env outranks config, matching the rest of the resolver's precedence", () => {
    const cfg: UserConfig = {
      reviewers: {},
      provider_keys: { openai: "cfg-openai" },
    };
    assert.equal(
      resolveProviderCredentialFrom(cfg, OPENAI_URL, {
        STAMP_OPENAI_API_KEY: "env-openai",
      }).apiKey,
      "env-openai",
    );
  });

  it("supplies a credential to an unrecognised endpoint when one is set for it", () => {
    const c = resolveProviderCredentialFrom(null, "https://llm.corp.test/v1", {
      STAMP_LLM_CORP_TEST_API_KEY: "gateway-key",
    });
    assert.equal(c.apiKey, "gateway-key");
  });

  it("plumbs the resolved key onto the wire as a bearer token", async () => {
    const { fetchImpl, calls } = verdictFetch();
    const r = await invokeLocalReviewer({
      ...baseReviewerParams(),
      fetchImpl,
      env: { STAMP_OPENAI_API_KEY: SECRET },
    } as Parameters<typeof invokeLocalReviewer>[0]);
    assert.equal(r.verdict, "approved");
    // The bug this ticket exists to fix: before AGT-1138 this header said
    // `Bearer lm-studio` no matter what the operator configured.
    assert.equal(calls[0]!.headers.authorization, `Bearer ${SECRET}`);
    assert.equal(calls[0]!.url, `${OPENAI_URL}/chat/completions`);
  });

  it("still sends the placeholder for localhost with nothing configured", async () => {
    const { fetchImpl, calls } = verdictFetch();
    await invokeLocalReviewer({
      ...baseReviewerParams({ endpoint: LOCALHOST_URL, model: "qwen3-coder-30b" }),
      fetchImpl,
      env: {},
    } as Parameters<typeof invokeLocalReviewer>[0]);
    assert.equal(
      calls[0]!.headers.authorization,
      "Bearer lm-studio",
      "the pre-AGT-1138 localhost path must be byte-for-byte unchanged",
    );
  });
});

// ---------------------------------------------------------------------------
// AC3 — the rename keeps every existing alias working
// ---------------------------------------------------------------------------

describe("AGT-1138 AC3: `local` aliases keep resolving identically", () => {
  const CFG_LOCAL: UserConfig = {
    reviewers: { security: `${LOCAL_MODEL_PREFIX}qwen3-coder-30b` },
    local_endpoint: LOCALHOST_URL,
  };
  const CFG_NEW: UserConfig = {
    reviewers: { security: `${OPENAI_COMPATIBLE_MODEL_PREFIX}qwen3-coder-30b` },
    openai_compatible_endpoint: LOCALHOST_URL,
  };

  it("alias: the `local:` reviewers prefix", () => {
    withEnv({}, () => {
      const b = resolveReviewerBackendFrom(CFG_LOCAL, "security");
      assert.deepEqual(b, {
        kind: "openai-compatible",
        model: "qwen3-coder-30b",
        endpoint: LOCALHOST_URL,
        enableTools: false,
      });
    });
  });

  it("canonical: the `openai-compatible:` reviewers prefix resolves the same", () => {
    withEnv({}, () => {
      assert.deepEqual(
        resolveReviewerBackendFrom(CFG_NEW, "security"),
        resolveReviewerBackendFrom(CFG_LOCAL, "security"),
      );
    });
  });

  it("alias: top-level `local_endpoint:`; canonical wins when both are present", () => {
    withEnv({}, () => {
      const both: UserConfig = {
        reviewers: { security: "local:m" },
        local_endpoint: "http://localhost:1111/v1",
        openai_compatible_endpoint: "http://localhost:2222/v1",
      };
      const b = resolveReviewerBackendFrom(both, "security");
      assert.equal(
        (b as { endpoint: string }).endpoint,
        "http://localhost:2222/v1",
      );
    });
  });

  it("alias: STAMP_REVIEWER_BACKEND=local", () => {
    withEnv(
      {
        STAMP_REVIEWER_BACKEND: "local",
        STAMP_LOCAL_MODEL: "qwen3-coder-30b",
        STAMP_LOCAL_ENDPOINT: LOCALHOST_URL,
      },
      () => {
        assert.deepEqual(resolveReviewerBackendFrom(null, "security"), {
          kind: "openai-compatible",
          model: "qwen3-coder-30b",
          endpoint: LOCALHOST_URL,
          enableTools: false,
        });
      },
    );
  });

  it("canonical: STAMP_REVIEWER_BACKEND=openai-compatible + STAMP_OPENAI_COMPATIBLE_*", () => {
    withEnv(
      {
        STAMP_REVIEWER_BACKEND: "openai-compatible",
        STAMP_OPENAI_COMPATIBLE_MODEL: "qwen3-coder-30b",
        STAMP_OPENAI_COMPATIBLE_ENDPOINT: LOCALHOST_URL,
      },
      () => {
        assert.deepEqual(resolveReviewerBackendFrom(null, "security"), {
          kind: "openai-compatible",
          model: "qwen3-coder-30b",
          endpoint: LOCALHOST_URL,
          enableTools: false,
        });
      },
    );
  });

  it("alias env vars lose to their canonical counterparts when both are set", () => {
    withEnv(
      {
        STAMP_REVIEWER_BACKEND: "openai-compatible",
        STAMP_LOCAL_MODEL: "legacy-model",
        STAMP_OPENAI_COMPATIBLE_MODEL: "new-model",
        STAMP_LOCAL_ENDPOINT: "http://localhost:1111/v1",
        STAMP_OPENAI_COMPATIBLE_ENDPOINT: "http://localhost:2222/v1",
      },
      () => {
        const b = resolveReviewerBackendFrom(null, "security");
        assert.equal((b as { model: string }).model, "new-model");
        assert.equal(
          (b as { endpoint: string }).endpoint,
          "http://localhost:2222/v1",
        );
      },
    );
  });

  it("alias: STAMP_LOCAL_TOOLS and `local_tools:`; canonical spellings too", () => {
    const cfgLegacy: UserConfig = {
      reviewers: { security: "local:m" },
      local_tools: true,
    };
    const cfgNew: UserConfig = {
      reviewers: { security: "openai-compatible:m" },
      openai_compatible_tools: true,
    };
    withEnv({}, () => {
      assert.equal(
        (resolveReviewerBackendFrom(cfgLegacy, "security") as { enableTools: boolean })
          .enableTools,
        true,
      );
      assert.equal(
        (resolveReviewerBackendFrom(cfgNew, "security") as { enableTools: boolean })
          .enableTools,
        true,
      );
    });
    for (const varName of ["STAMP_LOCAL_TOOLS", "STAMP_OPENAI_COMPATIBLE_TOOLS"]) {
      withEnv({ [varName]: "1" }, () => {
        const b = resolveReviewerBackendFrom(
          { reviewers: { security: "local:m" } },
          "security",
        );
        assert.equal(
          (b as { enableTools: boolean }).enableTools,
          true,
          `${varName}=1 must enable tools`,
        );
      });
    }
  });

  it("alias: STAMP_REVIEWER_BACKEND=anthropic still de-schemes BOTH prefixes", () => {
    withEnv({ STAMP_REVIEWER_BACKEND: "anthropic" }, () => {
      for (const prefix of [LOCAL_MODEL_PREFIX, OPENAI_COMPATIBLE_MODEL_PREFIX]) {
        const b = resolveReviewerBackendFrom(
          { reviewers: { security: `${prefix}qwen` } },
          "security",
        );
        assert.deepEqual(
          b,
          { kind: "anthropic", model: null },
          `${prefix} must not be handed to the Anthropic SDK as a model id`,
        );
      }
    });
  });

  it("parse + stringify round-trips both spellings and provider_keys verbatim", () => {
    const yaml =
      "reviewers:\n  security: local:qwen\n" +
      "local_endpoint: http://localhost:8000/v1\n" +
      "local_tools: true\n" +
      "openai_compatible_endpoint: https://api.openai.com/v1\n" +
      "openai_compatible_tools: false\n" +
      "provider_keys:\n  openai: sk-abc\n";
    const cfg = parseUserConfig(yaml);
    assert.equal(cfg.local_endpoint, "http://localhost:8000/v1");
    assert.equal(cfg.openai_compatible_endpoint, "https://api.openai.com/v1");
    assert.equal(cfg.local_tools, true);
    assert.equal(cfg.openai_compatible_tools, false);
    assert.deepEqual(cfg.provider_keys, { openai: "sk-abc" });
    // A rewrite by `stamp config reviewers set` must not normalise the legacy
    // spelling away, and must not drop the operator's credentials.
    assert.deepEqual(parseUserConfig(stringifyUserConfig(cfg)), cfg);
  });

  it("a validation error for provider_keys never quotes the value back", () => {
    // Every other field in this parser echoes the bad value. Doing it here
    // would print an API key to stderr the first time someone fat-fingers
    // the YAML.
    assert.throws(
      () => parseUserConfig(`reviewers: {}\nprovider_keys:\n  openai: 12345\n`),
      (err: unknown) => {
        const msg = (err as Error).message;
        assert.match(msg, /provider_keys\.openai must be a non-empty string/);
        assert.ok(!msg.includes("12345"), "the value must not be echoed");
        return true;
      },
    );
  });
});

// ---------------------------------------------------------------------------
// AC1 — no credential reaches state.db, logs, traces, or a failed-runs dump
// ---------------------------------------------------------------------------

describe("AGT-1138 AC1: the credential never leaves the request", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "stamp-agt1138-"));
  });
  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("is absent from the resolved ReviewerBackend (the object that gets stored)", () => {
    withEnv(
      {
        STAMP_REVIEWER_BACKEND: "openai-compatible",
        STAMP_OPENAI_COMPATIBLE_MODEL: "gpt-5",
        STAMP_OPENAI_COMPATIBLE_ENDPOINT: OPENAI_URL,
        STAMP_OPENAI_API_KEY: SECRET,
      },
      () => {
        const backend: ReviewerBackend = resolveReviewerBackendFrom(
          { reviewers: {}, provider_keys: { openai: SECRET } },
          "security",
        );
        assert.ok(
          !JSON.stringify(backend).includes(SECRET),
          "ReviewerBackend is displayed, stored and signed — it must carry no key",
        );
        assert.ok(
          !JSON.stringify(backendProvenance(backend)).includes(SECRET),
          "provenance is written to state.db and into the attestation",
        );
      },
    );
  });

  it("is absent from the persisted review row and from `stamp log --reviews`", async () => {
    const dbPath = join(tmp, "state.db");
    const db = openDb(dbPath);
    try {
      recordReview(db, {
        reviewer: "security",
        base_sha: "1".repeat(40),
        head_sha: "2".repeat(40),
        verdict: "approved",
        issues: "no concerns",
        provenance: backendProvenance({
          kind: "openai-compatible",
          model: "gpt-5",
          endpoint: OPENAI_URL,
          enableTools: false,
        }),
      });
      const rows = reviewHistory(db);
      assert.equal(rows.length, 1);
      assert.ok(!JSON.stringify(rows).includes(SECRET));
      // The endpoint IS recorded — that is AC6 — but the key is not, and the
      // row is what an operator, a backup, and a future reader all see.
      assert.equal(rows[0]!.backend_endpoint, OPENAI_URL);
    } finally {
      db.close();
    }
    // Belt and braces: scan the raw SQLite bytes, not just the parsed rows.
    // A leak into a column we forgot to read back would still be on disk.
    assert.ok(
      !readFileSync(dbPath, "latin1").includes(SECRET),
      "the key must not appear anywhere in the state.db file",
    );
  });

  it("is redacted when the endpoint echoes the bearer token back in a 401 body", async () => {
    // Not hypothetical: several OpenAI-compatible gateways include the
    // presented Authorization value in their rejection body, and that body is
    // exactly what the adapter truncates into its error message.
    const client = createLocalReviewClient({
      baseURL: OPENAI_URL,
      apiKey: SECRET,
      providerId: "openai",
      credentialSource: "STAMP_OPENAI_API_KEY",
      fetchImpl: failingFetch(
        401,
        `{"error":"invalid key: Bearer ${SECRET}"}`,
      ),
    });
    await assert.rejects(
      client.messages.create(
        { model: "gpt-5", max_tokens: 16, system: "s", messages: [], tools: [] },
        undefined,
      ),
      (err: unknown) => {
        const msg = (err as Error).message;
        assert.ok(!msg.includes(SECRET), `key leaked into: ${msg}`);
        assert.match(msg, new RegExp(REDACTED_MARKER.replace(/[[\]]/g, "\\$&")));
        return true;
      },
    );
  });

  it("is redacted on the non-401 and transport-failure error paths too", async () => {
    const bad = createLocalReviewClient({
      baseURL: OPENAI_URL,
      apiKey: SECRET,
      fetchImpl: failingFetch(500, `upstream said ${SECRET}`),
    });
    await assert.rejects(
      bad.messages.create(
        { model: "m", max_tokens: 16, system: "s", messages: [], tools: [] },
        undefined,
      ),
      (err: unknown) => {
        assert.ok(!(err as Error).message.includes(SECRET));
        return true;
      },
    );

    const unreachable = createLocalReviewClient({
      baseURL: OPENAI_URL,
      apiKey: SECRET,
      fetchImpl: async () => {
        throw new Error(`socket hang up while sending ${SECRET}`);
      },
    });
    await assert.rejects(
      unreachable.messages.create(
        { model: "m", max_tokens: 16, system: "s", messages: [], tools: [] },
        undefined,
      ),
      (err: unknown) => {
        const msg = (err as Error).message;
        assert.ok(!msg.includes(SECRET));
        assert.match(msg, /unreachable/);
        return true;
      },
    );
  });

  it("is absent from the reviewer failure thrown up to `stamp review`", async () => {
    // This is the string that reaches stderr and, for the agent-SDK path, a
    // spooled trace under .git/stamp/failed-runs/. Nothing derived from the
    // key may be in it.
    await assert.rejects(
      invokeLocalReviewer({
        ...baseReviewerParams(),
        fetchImpl: failingFetch(401, `denied for ${SECRET}`),
        env: { STAMP_OPENAI_API_KEY: SECRET },
      } as Parameters<typeof invokeLocalReviewer>[0]),
      (err: unknown) => {
        assert.ok(!(err as Error).message.includes(SECRET));
        return true;
      },
    );
  });

  it("redactSecrets leaves the surrounding diagnostic intact", () => {
    // Blanking the whole snippet would trade a real diagnostic for a
    // hypothetical one; the upstream's own explanation is why it is shown.
    const out = redactSecrets(`model not loaded (key ${SECRET})`, [SECRET]);
    assert.match(out, /model not loaded/);
    assert.ok(!out.includes(SECRET));
    // Values too short to be a real secret are skipped — otherwise they would
    // blank unrelated text wholesale.
    assert.equal(redactSecrets("abc def", ["ab"]), "abc def");
  });
});

// ---------------------------------------------------------------------------
// AC4 — actionable failures
// ---------------------------------------------------------------------------

describe("AGT-1138 AC4: a misconfigured provider fails actionably", () => {
  it("refuses to send anything when a required credential is missing", async () => {
    let called = false;
    const fetchImpl: FetchLike = async () => {
      called = true;
      throw new Error("must not be reached");
    };
    await assert.rejects(
      invokeLocalReviewer({
        ...baseReviewerParams(),
        fetchImpl,
        env: {},
      } as Parameters<typeof invokeLocalReviewer>[0]),
      (err: unknown) => {
        const msg = (err as Error).message;
        assert.match(msg, /no API credential/);
        assert.ok(msg.includes(OPENAI_URL), "names the endpoint");
        assert.match(msg, /provider "openai"/, "names the provider");
        assert.match(msg, /STAMP_OPENAI_API_KEY/, "names the env var to set");
        assert.match(msg, /OPENAI_API_KEY/, "names the vendor variable too");
        assert.match(msg, /provider_keys/, "names the config route");
        return true;
      },
    );
    assert.equal(called, false, "nothing may go on the wire without a key");
  });

  it("turns a 401 into a message naming the endpoint, provider and key source", async () => {
    await assert.rejects(
      invokeLocalReviewer({
        ...baseReviewerParams({ endpoint: DEEPSEEK_URL, model: "deepseek-chat" }),
        fetchImpl: failingFetch(401, "Authentication Fails"),
        env: { STAMP_DEEPSEEK_API_KEY: "wrong-key" },
      } as Parameters<typeof invokeLocalReviewer>[0]),
      (err: unknown) => {
        const msg = (err as Error).message;
        assert.match(msg, /HTTP 401 \(unauthorized\)/);
        assert.ok(msg.includes(DEEPSEEK_URL));
        assert.match(msg, /[Pp]rovider "deepseek"/);
        assert.match(
          msg,
          /STAMP_DEEPSEEK_API_KEY/,
          "must say WHICH source supplied the rejected key",
        );
        assert.match(msg, /Authentication Fails/, "keeps the upstream reason");
        assert.ok(
          !/may not support tool-calling/.test(msg),
          "a 401 must not be blamed on the prompt or the model's tool support",
        );
        return true;
      },
    );
  });

  it("a 403 from an unauthenticated endpoint says no credential was sent", async () => {
    const client = createLocalReviewClient({
      baseURL: "https://llm.corp.test/v1",
      providerId: "llm.corp.test",
      credentialSource: null,
      fetchImpl: failingFetch(403, "forbidden"),
    });
    await assert.rejects(
      client.messages.create(
        { model: "m", max_tokens: 16, system: "s", messages: [], tools: [] },
        undefined,
      ),
      (err: unknown) => {
        const msg = (err as Error).message;
        assert.match(msg, /no credential was sent/);
        assert.match(msg, /STAMP_LLM_CORP_TEST_API_KEY/);
        return true;
      },
    );
  });

  it("never returns a null verdict on a credential failure — it throws", async () => {
    // A null verdict would be recorded and silently fail the gate with no
    // explanation; throwing is what makes `Promise.allSettled` mark the
    // reviewer failed and print the reason.
    await assert.rejects(
      invokeLocalReviewer({
        ...baseReviewerParams(),
        fetchImpl: failingFetch(401, "nope"),
        env: { STAMP_OPENAI_API_KEY: "bad" },
      } as Parameters<typeof invokeLocalReviewer>[0]),
    );
  });
});

// ---------------------------------------------------------------------------
// AC6 — OpenAI and DeepSeek are separable in the record
// ---------------------------------------------------------------------------

describe("AGT-1138 AC6: providers are separable in `stamp log --reviews`", () => {
  it("records the same kind but different endpoints, rendered distinctly", () => {
    const openai = backendProvenance({
      kind: "openai-compatible",
      model: "gpt-5",
      endpoint: OPENAI_URL,
      enableTools: false,
    });
    const deepseek = backendProvenance({
      kind: "openai-compatible",
      model: "deepseek-chat",
      endpoint: DEEPSEEK_URL,
      enableTools: false,
    });
    // Kind alone cannot distinguish them — both ride the one adapter — and
    // the stored value is deliberately still the AGT-1137 literal.
    assert.equal(openai.backend_kind, PROVENANCE_KIND_OPENAI_COMPATIBLE);
    assert.equal(deepseek.backend_kind, PROVENANCE_KIND_OPENAI_COMPATIBLE);
    // The endpoint is what separates them.
    assert.notEqual(openai.backend_endpoint, deepseek.backend_endpoint);
    assert.notEqual(formatProvenance(openai), formatProvenance(deepseek));
    assert.equal(
      formatProvenance(openai),
      `openai-compatible / gpt-5 @ ${OPENAI_URL}`,
    );
    assert.equal(
      formatProvenance(deepseek),
      `openai-compatible / deepseek-chat @ ${DEEPSEEK_URL}`,
    );
  });

  it("neither is labelled `local` on the display surface", () => {
    const p = backendProvenance({
      kind: "openai-compatible",
      model: "gpt-5",
      endpoint: OPENAI_URL,
      enableTools: false,
    });
    assert.ok(!formatProvenance(p).startsWith("local "));
  });

  it("an unset endpoint still records the URL that will actually be hit", () => {
    const p = backendProvenance({
      kind: "openai-compatible",
      model: "qwen",
      endpoint: undefined,
      enableTools: false,
    });
    assert.equal(p.backend_endpoint, LOCAL_DEFAULT_BASE_URL);
  });
});
