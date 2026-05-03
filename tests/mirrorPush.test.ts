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

import { buildMirrorPushInvocation } from "../src/lib/mirrorPush.ts";

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
