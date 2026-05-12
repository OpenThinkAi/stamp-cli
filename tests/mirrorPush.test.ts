/**
 * Tests for buildMirrorPushInvocation.
 *
 * Audit finding L1: the GitHub bot token must not appear in the argv git
 * is spawned with — that's the surface visible to local users via
 * `ps` / `/proc/<pid>/cmdline`. The helper supplies the credential via
 * `GIT_CONFIG_*` env vars carrying an `Authorization: Basic` header
 * instead, so the token never reaches the process command line.
 *
 * These tests are the regression guard. They live in their own file
 * rather than `post-receive.test.ts` because the post-receive hook module
 * auto-runs `main()` on import (and calls `process.exit(0)` from a
 * `.finally`), which tears down the test process before in-file
 * assertions execute.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  buildMirrorPushInvocation,
  buildMirrorPushInvocationSsh,
} from "../src/lib/mirrorPush.ts";

describe("buildMirrorPushInvocation", () => {
  const TOKEN = "ghp_FAKE_TEST_TOKEN_abcdef0123456789";
  const REPO = "OpenThinkAi/example";
  const SHA = "1234567890abcdef1234567890abcdef12345678";
  const REFNAME = "refs/heads/main";

  it("emits a plain https URL with no embedded credentials", () => {
    const { args } = buildMirrorPushInvocation(REPO, SHA, REFNAME, TOKEN);
    assert.deepEqual(args, [
      "push",
      `https://github.com/${REPO}.git`,
      `${SHA}:${REFNAME}`,
    ]);
  });

  it("never includes the token in any argv element", () => {
    const { args } = buildMirrorPushInvocation(REPO, SHA, REFNAME, TOKEN);
    for (const a of args) {
      assert.ok(!a.includes(TOKEN), `argv element leaked token: ${a}`);
      // Also catch the historical x-access-token:<...>@ URL form.
      assert.ok(
        !/x-access-token:/i.test(a),
        `argv element retained x-access-token credential form: ${a}`,
      );
    }
  });

  it("supplies the token via GIT_CONFIG_* env vars as Basic auth", () => {
    const parentEnv = { PATH: "/usr/bin", HOME: "/home/git" };
    const { env } = buildMirrorPushInvocation(
      REPO,
      SHA,
      REFNAME,
      TOKEN,
      parentEnv,
    );
    assert.equal(env.GIT_CONFIG_COUNT, "1");
    assert.equal(env.GIT_CONFIG_KEY_0, "http.extraHeader");
    const expectedB64 = Buffer.from(`x-access-token:${TOKEN}`).toString(
      "base64",
    );
    assert.equal(
      env.GIT_CONFIG_VALUE_0,
      `Authorization: Basic ${expectedB64}`,
    );
    // Parent env preserved (PATH/HOME etc. that git needs).
    assert.equal(env.PATH, "/usr/bin");
    assert.equal(env.HOME, "/home/git");
  });

  it("does not lose the token across the env round-trip", () => {
    // Decode the Basic auth value back out and confirm it carries the token
    // — the credential must actually be conveyed, not just absent from argv.
    const { env } = buildMirrorPushInvocation(REPO, SHA, REFNAME, TOKEN);
    const value = env.GIT_CONFIG_VALUE_0 ?? "";
    const m = value.match(/^Authorization: Basic (.+)$/);
    assert.ok(m, `unexpected GIT_CONFIG_VALUE_0 shape: ${value}`);
    const decoded = Buffer.from(m[1]!, "base64").toString("utf8");
    assert.equal(decoded, `x-access-token:${TOKEN}`);
  });
});

// SSH variant — used by post-receive when a deploy key is installed at
// the well-known path. No bot token is involved; auth is the SSH key.
// The interesting invariants are (1) the URL must be the SSH form so
// git's transport selects ssh and consults ~/.ssh/config (which points
// at the deploy key) rather than https, and (2) no http.extraHeader is
// emitted — leaking an Authorization header here would be dead weight
// but worth pinning against accidental re-introduction.
describe("buildMirrorPushInvocationSsh", () => {
  const REPO = "OpenThinkAi/example";
  const SHA = "1234567890abcdef1234567890abcdef12345678";
  const REFNAME = "refs/heads/main";

  it("uses the git@github.com:owner/repo.git SSH URL form", () => {
    const { args } = buildMirrorPushInvocationSsh(REPO, SHA, REFNAME);
    assert.deepEqual(args, [
      "push",
      `git@github.com:${REPO}.git`,
      `${SHA}:${REFNAME}`,
    ]);
  });

  it("does not emit any GIT_CONFIG_* / http.extraHeader env vars", () => {
    const parentEnv = { PATH: "/usr/bin", HOME: "/home/git" };
    const { env } = buildMirrorPushInvocationSsh(
      REPO,
      SHA,
      REFNAME,
      parentEnv,
    );
    assert.equal(env.GIT_CONFIG_COUNT, undefined);
    assert.equal(env.GIT_CONFIG_KEY_0, undefined);
    assert.equal(env.GIT_CONFIG_VALUE_0, undefined);
    // Parent env preserved (PATH/HOME etc. that git/ssh need).
    assert.equal(env.PATH, "/usr/bin");
    assert.equal(env.HOME, "/home/git");
  });

  it("does not embed any token shape (defense against accidental drift)", () => {
    // SSH path must never carry a credential on argv or in extraHeader —
    // re-pins audit finding L1 for the SSH branch.
    const { args, env } = buildMirrorPushInvocationSsh(REPO, SHA, REFNAME);
    for (const a of args) {
      assert.ok(
        !/x-access-token:/i.test(a),
        `argv element retained x-access-token form: ${a}`,
      );
      assert.ok(
        !/Authorization:/i.test(a),
        `argv element retained Authorization header: ${a}`,
      );
    }
    for (const v of Object.values(env)) {
      if (typeof v !== "string") continue;
      assert.ok(
        !/x-access-token:/i.test(v),
        `env value retained x-access-token form: ${v}`,
      );
    }
  });
});
