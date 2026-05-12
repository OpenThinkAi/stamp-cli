/**
 * Tests for computePerRepoKeyPath.
 *
 * The path returned by this function flows directly into:
 *   - existsSync() in post-receive's transport selector
 *   - `ssh -i <path>` in mirrorPush's GIT_SSH_COMMAND when the per-repo
 *     branch is taken
 *
 * The function therefore has two jobs: (a) match the server-side
 * stamp-ensure-repo-key naming convention exactly, and (b) reject any
 * input shape that the server wouldn't accept. Drift between these two
 * sides silently breaks the per-repo path (the file the client expects
 * is never the file the server created), so the explicit shape contract
 * is what these tests pin.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  SSH_CLIENT_KEY_DIR,
  computePerRepoKeyPath,
} from "../src/lib/perRepoKey.ts";

describe("computePerRepoKeyPath — path shape", () => {
  it("flattens <owner>/<repo> to <owner>_<repo>_ed25519 under the keys dir", () => {
    const path = computePerRepoKeyPath("OpenThinkAi/stamp-cli");
    assert.equal(
      path,
      `${SSH_CLIENT_KEY_DIR}/OpenThinkAi_stamp-cli_ed25519`,
    );
  });

  it("permits dots and hyphens in both halves (real repo names use them)", () => {
    const path = computePerRepoKeyPath("some.org/repo.with-dots");
    assert.equal(
      path,
      `${SSH_CLIENT_KEY_DIR}/some.org_repo.with-dots_ed25519`,
    );
  });

  it("permits underscores in repo names", () => {
    // GitHub allows underscores in repo names; the path separator stays
    // unambiguous because the owner half cannot contain '/'.
    const path = computePerRepoKeyPath("foo/under_score");
    assert.equal(path, `${SSH_CLIENT_KEY_DIR}/foo_under_score_ed25519`);
  });
});

describe("computePerRepoKeyPath — input rejection", () => {
  // Mirrors the server-side stamp-ensure-repo-key shape checks; drift
  // either direction silently produces a path the server won't honor.
  it("rejects empty input", () => {
    assert.throws(() => computePerRepoKeyPath(""), /non-empty/);
  });

  it("rejects input with a leading '-' (would parse as a flag downstream)", () => {
    assert.throws(
      () => computePerRepoKeyPath("-flag/repo"),
      /must not start with '-'/,
    );
  });

  it("rejects '..' anywhere (path-traversal defense in depth)", () => {
    assert.throws(
      () => computePerRepoKeyPath("foo/..bar"),
      /must not contain '\.\.'/,
    );
    assert.throws(
      () => computePerRepoKeyPath("../etc"),
      /must not contain '\.\.'/,
    );
  });

  it("rejects missing or doubled slash", () => {
    assert.throws(
      () => computePerRepoKeyPath("noseparator"),
      /exactly <owner>\/<repo>/,
    );
    assert.throws(
      () => computePerRepoKeyPath("owner/repo/extra"),
      /exactly <owner>\/<repo>/,
    );
  });

  it("rejects empty halves (leading or trailing slash)", () => {
    assert.throws(
      () => computePerRepoKeyPath("/repo"),
      /both be non-empty/,
    );
    assert.throws(
      () => computePerRepoKeyPath("owner/"),
      /both be non-empty/,
    );
  });

  it("rejects whitespace anywhere", () => {
    assert.throws(
      () => computePerRepoKeyPath("owner/has space"),
      /invalid characters/,
    );
    assert.throws(
      () => computePerRepoKeyPath("owner /repo"),
      /invalid characters/,
    );
  });

  it("rejects shell metacharacters", () => {
    for (const bad of [
      "owner/$repo",
      "owner/repo;rm",
      "owner/repo|cat",
      "owner/repo`cat`",
      "owner/repo&background",
      "owner/repo*glob",
    ]) {
      assert.throws(
        () => computePerRepoKeyPath(bad),
        /invalid characters/,
        `expected rejection for ${bad}`,
      );
    }
  });

  it("rejects non-string input at the type-bypass boundary", () => {
    // The TS signature says `string`, but a runtime caller could
    // pass `null`/`undefined` from a parsed yaml or similar.
    // @ts-expect-error — intentional runtime-shape test.
    assert.throws(() => computePerRepoKeyPath(null), /non-empty string/);
    // @ts-expect-error — intentional runtime-shape test.
    assert.throws(() => computePerRepoKeyPath(undefined), /non-empty string/);
  });
});
