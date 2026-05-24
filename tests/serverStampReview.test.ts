/**
 * End-to-end tests for the SSH-invoked stamp-review wrapper.
 *
 * Identical harness pattern to `tests/serverMintInvite.test.ts`: spawn
 * the unbundled TS via tsx, point STAMP_SERVER_DB_PATH + SSH_USER_AUTH
 * at a tmp fixture, exercise the wrapper as a black box.
 *
 * Scope (AGT-328 + AGT-330):
 *   - parse, auth, size cap, diff-sha256 cross-check (verb-shaped)
 *   - the verb reaches the pipeline and surfaces pipeline errors
 *     correctly (e.g. ServerMissingApiKeyError, PromptFetchFailedError)
 *
 * Out of scope: the actual LLM call / verdict path. That's
 * `tests/serverReviewPipeline.test.ts`, which exercises the pipeline
 * directly with an injected `AnthropicClientShape` mock. The verb's
 * subprocess shape doesn't admit an in-process mock; running the
 * happy path here would require a real HTTP stub which would be more
 * brittle than load-bearing.
 *
 * AGT-331 adds tests for the real signature once the signer wires in.
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { fingerprintFromPem } from "../src/lib/keys.ts";
import { insertUser, openServerDb } from "../src/lib/serverDb.ts";

const STAMP_REVIEW_TS = path.resolve(
  import.meta.dirname,
  "..",
  "src",
  "server",
  "stamp-review.ts",
);

// Re-uses tests/sshKeys.test.ts fixture so the fingerprint is known.
const MEMBER_SSH_LINE =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO0fHPCBttt9fiLYtDixe2+eGATWUa+BiRi7V5B7Bc7b member@host";
const MEMBER_SSH_FP = "SHA256:ULy/G0aXU8CnDHhJe9uePIDwgzzNp16KH4b5LxLR/+k";

// Full-shape SHAs the parser will accept.
const BASE_SHA = "0123456789abcdef0123456789abcdef01234567";
const HEAD_SHA = "fedcba9876543210fedcba9876543210fedcba98";

interface Harness {
  dbPath: string;
  authPath: string;
  /** AGT-370: server's filesystem prompt cache root
   *  (`STAMP_PROMPTS_DIR`). Replaces the v4-era bare-repo root
   *  (`STAMP_REPO_ROOT`, removed). Populated only by setups that need
   *  the pipeline's prompt fetch to succeed. */
  promptCacheRoot?: string;
  /** Absolute path to a fixture review-signing key minted for the test
   *  (mode 0600, sibling .pub written). Wired into the verb's env as
   *  `REVIEW_SIGNING_KEY_PATH` so the pipeline's signing-key loader
   *  resolves to this file instead of `/srv/git/.stamp-state/...`. Only
   *  populated by `setupWithFixturePromptCache`. */
  signingKeyPath?: string;
  /** Fingerprint (sha256:<hex>) of the fixture review-signing key.
   *  Used by tests to assert that the signed approval names this key. */
  signingKeyFingerprint?: string;
  cleanup: () => void;
}

function setup(callerRole: "owner" | "admin" | "member" | "none"): Harness {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-review-"));
  const dbPath = path.join(dir, "users.db");
  const authPath = path.join(dir, "ssh_user_auth");

  if (callerRole !== "none") {
    const db = openServerDb({ path: dbPath, skipChmod: true });
    try {
      insertUser(db, {
        short_name: "caller",
        ssh_pubkey: MEMBER_SSH_LINE,
        ssh_fp: MEMBER_SSH_FP,
        role: callerRole,
        source: "env",
      });
    } finally {
      db.close();
    }
  }

  writeFileSync(authPath, `publickey ${MEMBER_SSH_LINE}\n`, { mode: 0o600 });

  return {
    dbPath,
    authPath,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

/**
 * Provision a fixture filesystem prompt cache (AGT-370 — replaces the
 * bare-repo fixture) plus a fixture Ed25519 review-signing key.
 *
 * The cache holds `<promptCacheRoot>/security.md` so the pipeline's
 * prompt fetch resolves. The signing-key file is minted at mode 0600
 * (required by `loadReviewSigningKey`) and the path is exported as
 * `REVIEW_SIGNING_KEY_PATH` for the verb subprocess.
 *
 * After AGT-370 the pipeline's structural-error order is just:
 * prompt → signing-key → anthropic. The manifest fetch is gone
 * (the server no longer reads it).
 */
function setupWithFixturePromptCache(
  callerRole: "owner" | "admin" | "member",
): Harness {
  const h = setup(callerRole);
  const promptCacheRoot = path.join(path.dirname(h.dbPath), "prompts");
  mkdirSync(promptCacheRoot, { recursive: true });
  writeFileSync(
    path.join(promptCacheRoot, "security.md"),
    "# security reviewer\n",
  );

  // Mint a fixture review-signing key in the harness state dir. The
  // pipeline's loader will read this from REVIEW_SIGNING_KEY_PATH at
  // request time; 0600 perms are required for `loadReviewSigningKey`
  // to accept the file.
  const stateDir = path.join(path.dirname(h.dbPath), "state");
  mkdirSync(stateDir, { recursive: true });
  const signingKeyPath = path.join(stateDir, "review-signing-key.pem");
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({
    type: "pkcs8",
    format: "pem",
  }) as string;
  const publicPem = publicKey.export({ type: "spki", format: "pem" }) as string;
  writeFileSync(signingKeyPath, privatePem, { mode: 0o600 });
  const signingKeyFingerprint = fingerprintFromPem(publicPem);

  return {
    ...h,
    promptCacheRoot,
    signingKeyPath,
    signingKeyFingerprint,
  };
}

interface RunResult {
  stdout: string;
  stderr: string;
  status: number | null;
}

function runStampReview(
  harness: Harness,
  args: string[],
  opts: { stdin?: Buffer; envOverrides?: Record<string, string | undefined> } = {},
): RunResult {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    STAMP_SERVER_DB_PATH: harness.dbPath,
    SSH_USER_AUTH: harness.authPath,
  };
  if (harness.promptCacheRoot) {
    env.STAMP_PROMPTS_DIR = harness.promptCacheRoot;
    // AGT-411: custom promptCacheRoot is a non-default STAMP_PROMPTS_DIR.
    // The resolver's prod guard rejects non-default dirs unless STAMP_ENV
    // is non-prod AND STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY is set.
    // Callers can override via envOverrides if they want to assert the
    // refusal path itself.
    env.STAMP_ENV = env.STAMP_ENV ?? "test";
    env.STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY =
      env.STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY ?? "1";
  }
  if (harness.signingKeyPath) {
    env.REVIEW_SIGNING_KEY_PATH = harness.signingKeyPath;
  }
  if (opts.envOverrides) {
    for (const [k, v] of Object.entries(opts.envOverrides)) {
      if (v === undefined) {
        delete env[k];
      } else {
        env[k] = v;
      }
    }
  }
  const result = spawnSync(
    process.execPath,
    ["--import", "tsx", STAMP_REVIEW_TS, ...args],
    {
      env,
      input: opts.stdin ?? Buffer.alloc(0),
      encoding: "utf8",
    },
  );
  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    status: result.status,
  };
}

/** Build the full happy-path argv for a given diff. */
function argvFor(diff: Buffer, overrides: Partial<Record<string, string>> = {}): string[] {
  const diffSha = createHash("sha256").update(diff).digest("hex");
  const merged: Record<string, string> = {
    "--reviewer": "security",
    "--org": "acme",
    "--repo": "widget-co",
    "--base-sha": BASE_SHA,
    "--head-sha": HEAD_SHA,
    "--diff-sha256": diffSha,
    ...overrides,
  };
  const out: string[] = [];
  for (const [k, v] of Object.entries(merged)) out.push(k, v);
  return out;
}

describe("stamp-review — verb reaches pipeline (AGT-330 wiring)", () => {
  it("surfaces ServerMissingApiKeyError when fixture bare resolves but ANTHROPIC_API_KEY is unset", () => {
    // With a real fixture bare repo (so the prompt fetch succeeds) and
    // no ANTHROPIC_API_KEY, the verb should reach the pipeline, hit the
    // missing-key throw, and exit 1 (server-side config error) with a
    // clear stderr message. This pins the verb-to-pipeline wiring AND
    // confirms the pipeline's typed-error path crosses the SSH boundary
    // cleanly.
    const h = setupWithFixturePromptCache("member");
    try {
      const diff = Buffer.from("diff --git a/foo b/foo\n");
      // base_sha is opaque to the pipeline after AGT-370 (it's just
      // baked into the signed approval body; the server never resolves
      // it back to a real commit). The verb still validates it as a
      // 40-hex SHA per the wire protocol.
      const r = runStampReview(h, argvFor(diff, { "--base-sha": BASE_SHA }), {
        stdin: diff,
        envOverrides: { ANTHROPIC_API_KEY: undefined },
      });
      assert.equal(r.status, 1, `stderr=${r.stderr}\nstdout=${r.stdout}`);
      // The verb's top-level .catch surfaces the error message verbatim
      // — pin the ServerMissingApiKeyError prose so a future agent
      // tweaking the wording doesn't break operator-visible behavior.
      assert.match(r.stderr, /ANTHROPIC_API_KEY is not set on the stamp-server/);
    } finally {
      h.cleanup();
    }
  });

  it("surfaces PromptFetchFailedError when the prompt isn't reachable at base_sha", () => {
    // No fixture bare repo, so the prompt fetch hits no_such_repo
    // immediately. Verb should exit 1 with a clear category-flavored
    // stderr message; the typed kind reaches the operator.
    const h = setup("member");
    try {
      const diff = Buffer.from("x");
      const r = runStampReview(h, argvFor(diff), { stdin: diff });
      assert.equal(r.status, 1, `stderr=${r.stderr}\nstdout=${r.stdout}`);
      assert.match(r.stderr, /canonical prompt fetch failed/);
    } finally {
      h.cleanup();
    }
  });

  it("accepts owner / admin / member callers as authorized to request reviews", () => {
    // Authorization-only assertion — every role MAY reach the pipeline
    // (i.e. NOT rejected at the auth gate with exit 3). The pipeline
    // itself fails downstream (no fixture, no API key) and surfaces
    // exit 1; that's fine for this test, which is about the role gate
    // not the LLM path.
    for (const role of ["owner", "admin", "member"] as const) {
      const h = setup(role);
      try {
        const diff = Buffer.from(`role=${role}\n`);
        const r = runStampReview(h, argvFor(diff), { stdin: diff });
        // Exit must NOT be 3 (role-rejected). Pipeline-flavored errors
        // (exit 1) are expected here without a fixture bare repo.
        assert.notEqual(r.status, 3, `role=${role} stderr=${r.stderr}`);
      } finally {
        h.cleanup();
      }
    }
  });
});

describe("stamp-review — authorization", () => {
  it("refuses when SSH_USER_AUTH is unset (no ExposeAuthInfo)", () => {
    const h = setup("member");
    try {
      const diff = Buffer.from("x");
      const r = runStampReview(h, argvFor(diff), {
        stdin: diff,
        envOverrides: { SSH_USER_AUTH: undefined },
      });
      assert.equal(r.status, 1);
      assert.match(r.stderr, /authenticated identity/);
    } finally {
      h.cleanup();
    }
  });

  it("refuses when the caller's SSH key isn't in the DB", () => {
    const h = setup("none");
    try {
      const diff = Buffer.from("x");
      const r = runStampReview(h, argvFor(diff), { stdin: diff });
      assert.equal(r.status, 1);
      assert.match(r.stderr, /not in the membership DB/);
    } finally {
      h.cleanup();
    }
  });

  // The Role union (and the DB's CHECK constraint) currently covers
  // {owner, admin, member} — every legal value is also an allowed
  // value. We therefore can't write a "role below member is rejected"
  // E2E test today without bypassing the DB schema. The structural
  // gate is the `ALLOWED_ROLES` Set in stamp-review.ts; a future Role
  // expansion that adds e.g. `viewer` will trip the existing test
  // surface immediately (an inserted viewer would not match the Set
  // and the verb would exit 3). Documented here so a future agent
  // adding a new Role variant remembers to add the regression test.
});

describe("stamp-review — help", () => {
  it("prints usage to stdout and exits 0 on --help", () => {
    const h = setup("member");
    try {
      const r = runStampReview(h, ["--help"]);
      assert.equal(r.status, 0, `stderr=${r.stderr}`);
      assert.match(r.stdout, /^usage: stamp-review --reviewer/);
      // stderr may carry Node's "experimental SQLite" warning, but
      // must not carry an `error:` line from the verb itself.
      assert.doesNotMatch(r.stderr, /^error:/m);
    } finally {
      h.cleanup();
    }
  });

  it("prints usage to stdout and exits 0 on -h", () => {
    const h = setup("member");
    try {
      const r = runStampReview(h, ["-h"]);
      assert.equal(r.status, 0, `stderr=${r.stderr}`);
      assert.match(r.stdout, /^usage: stamp-review --reviewer/);
    } finally {
      h.cleanup();
    }
  });
});

describe("stamp-review — request validation", () => {
  it("rejects missing required flags with a usage error", () => {
    const h = setup("member");
    try {
      const r = runStampReview(h, ["--reviewer", "security"], {
        stdin: Buffer.alloc(0),
      });
      assert.equal(r.status, 2);
      assert.match(r.stderr, /missing required flag/);
      assert.match(r.stderr, /--org/);
    } finally {
      h.cleanup();
    }
  });

  it("rejects an unknown flag", () => {
    const h = setup("member");
    try {
      const r = runStampReview(h, [...argvFor(Buffer.from("x")), "--nope", "1"], {
        stdin: Buffer.from("x"),
      });
      assert.equal(r.status, 2);
      assert.match(r.stderr, /unknown flag/);
    } finally {
      h.cleanup();
    }
  });

  it("rejects a malformed --base-sha (short hex)", () => {
    const h = setup("member");
    try {
      const diff = Buffer.from("x");
      const r = runStampReview(h, argvFor(diff, { "--base-sha": "deadbeef" }), {
        stdin: diff,
      });
      assert.equal(r.status, 2);
      assert.match(r.stderr, /--base-sha/);
    } finally {
      h.cleanup();
    }
  });

  it("rejects a malformed --reviewer shape", () => {
    const h = setup("member");
    try {
      const diff = Buffer.from("x");
      const r = runStampReview(h, argvFor(diff, { "--reviewer": "has spaces" }), {
        stdin: diff,
      });
      assert.equal(r.status, 2);
      assert.match(r.stderr, /--reviewer/);
    } finally {
      h.cleanup();
    }
  });

  it("rejects a --diff-sha256 that doesn't match the streamed bytes", () => {
    const h = setup("member");
    try {
      const diff = Buffer.from("actual content");
      const wrongSha = "f".repeat(64);
      const r = runStampReview(h, argvFor(diff, { "--diff-sha256": wrongSha }), {
        stdin: diff,
      });
      assert.equal(r.status, 4);
      assert.match(r.stderr, /diff content sha256 mismatch/);
    } finally {
      h.cleanup();
    }
  });

  it("rejects diff content larger than MAX_DIFF_BYTES (env override)", () => {
    const h = setup("member");
    try {
      // Cap = 16 bytes; stdin = 100 bytes. The streaming reader should
      // abort as soon as cumulative bytes exceed 16, well before
      // reaching the diff-sha cross-check.
      const diff = Buffer.alloc(100, 0x61); // 'a' x 100
      const r = runStampReview(h, argvFor(diff), {
        stdin: diff,
        envOverrides: { MAX_DIFF_BYTES: "16" },
      });
      assert.equal(r.status, 4);
      assert.match(r.stderr, /exceeds MAX_DIFF_BYTES/);
    } finally {
      h.cleanup();
    }
  });
});

describe("stamp-review — rate limit (AGT-420)", () => {
  it("rejects the over-cap call with exit 5 (back off)", () => {
    // The token-bucket check runs after auth and BEFORE stdin/pipeline,
    // and persists in the shared STAMP_SERVER_DB_PATH across the two
    // subprocess calls. With MAX_REVIEWS_PER_HOUR=1 the first call
    // consumes the only token (it then fails downstream on missing
    // ANTHROPIC_API_KEY — irrelevant here), and the second is throttled.
    const h = setup("member");
    try {
      const diff = Buffer.from("diff --git a/x b/x\n+y\n");
      const argv = argvFor(diff);
      const env = {
        MAX_REVIEWS_PER_HOUR: "1",
        ANTHROPIC_API_KEY: undefined,
      };
      runStampReview(h, argv, { stdin: diff, envOverrides: env }); // consumes the token
      const second = runStampReview(h, argv, { stdin: diff, envOverrides: env });
      assert.equal(second.status, 5, `stderr=${second.stderr}`);
      assert.match(second.stderr, /rate limit exceeded/);
      assert.match(second.stderr, /MAX_REVIEWS_PER_HOUR/);
    } finally {
      h.cleanup();
    }
  });
});
