/**
 * AGT-372 — tests for the prompts-cache module (Phase B foundation).
 *
 * Coverage matrix per the ticket's AC bullet 7:
 *
 *   a. Clone-then-fetch idempotency — first call clones, second call
 *      fast-paths to fetch + reset, both return a valid sha + timestamp.
 *   b. Per-repo override lookup with fallback — `getPromptPath` returns
 *      the `<org>/<repo>/<reviewer>.md` path when it exists, else falls
 *      back to `<cacheRoot>/<reviewer>.md`. Default path is returned
 *      EVEN IF IT DOESN'T EXIST (the read is `fetchCanonicalPrompt`'s
 *      job to validate, not the resolver's).
 *   c. Atomic swap survives mid-fetch failure — point at a bogus URL,
 *      assert the existing cacheRoot is unchanged after the throw.
 *   d. Lock prevents concurrent fetches — fire two `cloneOrFetchPromptsCache`
 *      calls in the same process simultaneously; both resolve to the same
 *      result without `git clone` running twice.
 *
 * Fixture model: a local bare repo (file:// URL) seeded with three reviewer
 * prompt files. No network. Each test gets its own tmpdir so they can run
 * in parallel without trampling each other.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import {
  existsSync,
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

import {
  buildCloneArgs,
  buildRemoteSetUrlArgs,
  cloneOrFetchPromptsCache,
  getPromptPath,
  scrubGitUrlCredentials,
} from "../src/server/prompts-cache.ts";

// ─── fixture helpers ─────────────────────────────────────────────────

function git(repo: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd: repo,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      // Deterministic identity so commits don't depend on the dev's
      // global git config.
      GIT_AUTHOR_NAME: "stamp-test",
      GIT_AUTHOR_EMAIL: "stamp-test@example.com",
      GIT_COMMITTER_NAME: "stamp-test",
      GIT_COMMITTER_EMAIL: "stamp-test@example.com",
    },
  });
}

/**
 * Build a bare upstream repo + a seed working copy that gets pushed into
 * it. Returns the file:// URL of the bare repo (usable as `opts.url` for
 * the cache module) plus the seed-repo path (so the test can push more
 * commits later).
 */
function makeBareUpstream(root: string): { url: string; seedRepo: string } {
  const bare = join(root, "upstream.git");
  mkdirSync(bare, { recursive: true });
  git(bare, ["init", "--bare", "--initial-branch=main"]);

  const seed = join(root, "seed");
  mkdirSync(seed, { recursive: true });
  git(seed, ["init", "--initial-branch=main"]);
  writeFileSync(join(seed, "security.md"), "default security reviewer\n");
  writeFileSync(join(seed, "standards.md"), "default standards reviewer\n");
  writeFileSync(join(seed, "product.md"), "default product reviewer\n");
  // A per-repo override that one of the tests will assert on.
  mkdirSync(join(seed, "acme", "widgets"), { recursive: true });
  writeFileSync(
    join(seed, "acme", "widgets", "security.md"),
    "ACME-specific security reviewer\n",
  );
  git(seed, ["add", "."]);
  git(seed, ["commit", "-q", "-m", "initial prompts"]);
  git(seed, ["remote", "add", "origin", bare]);
  git(seed, ["push", "-q", "origin", "main"]);

  return { url: `file://${bare}`, seedRepo: seed };
}

/**
 * Push a new commit on `main` in the seed repo, so the next
 * `cloneOrFetchPromptsCache` call has fresh refs to fetch.
 */
function commitNewPrompt(seed: string, filename: string, body: string): string {
  writeFileSync(join(seed, filename), body);
  git(seed, ["add", filename]);
  git(seed, ["commit", "-q", "-m", `add ${filename}`]);
  git(seed, ["push", "-q", "origin", "main"]);
  return git(seed, ["rev-parse", "HEAD"]).trim();
}

// ─── lifecycle ────────────────────────────────────────────────────────

let workRoot: string;

beforeEach(() => {
  workRoot = realpathSync(mkdtempSync(join(tmpdir(), "stamp-promptscache-")));
});

afterEach(() => {
  rmSync(workRoot, { recursive: true, force: true });
});

// ─── (a) clone-then-fetch idempotency ────────────────────────────────

describe("cloneOrFetchPromptsCache — clone + fetch idempotency", () => {
  it("first call clones; second call fast-paths to in-place fetch", async () => {
    const { url, seedRepo } = makeBareUpstream(workRoot);
    const cacheRoot = join(workRoot, "cache");

    const first = await cloneOrFetchPromptsCache({ url, ref: "main", cacheRoot });
    assert.ok(existsSync(join(cacheRoot, "security.md")));
    assert.match(first.commitSha, /^[0-9a-f]{40}$/);
    assert.match(first.refreshedAt, /^\d{4}-\d{2}-\d{2}T/);

    // No new upstream commits: second call should return the same sha.
    const second = await cloneOrFetchPromptsCache({ url, ref: "main", cacheRoot });
    assert.equal(second.commitSha, first.commitSha);

    // Push a new commit and confirm the third call picks it up.
    const newSha = commitNewPrompt(seedRepo, "extra.md", "extra reviewer\n");
    const third = await cloneOrFetchPromptsCache({ url, ref: "main", cacheRoot });
    assert.equal(third.commitSha, newSha);
    assert.ok(existsSync(join(cacheRoot, "extra.md")));
    assert.equal(readFileSync(join(cacheRoot, "extra.md"), "utf8"), "extra reviewer\n");
  });

  it("second call does not re-clone — cache root is reused (in-place fetch path)", async () => {
    const { url } = makeBareUpstream(workRoot);
    const cacheRoot = join(workRoot, "cache");

    await cloneOrFetchPromptsCache({ url, ref: "main", cacheRoot });
    // Marker file inside .git/ — preserved iff we did NOT delete + re-clone.
    // (`git clone` would wipe the .git dir; in-place fetch leaves it alone.)
    const marker = join(cacheRoot, ".git", "stamp-marker");
    writeFileSync(marker, "i was here\n");

    await cloneOrFetchPromptsCache({ url, ref: "main", cacheRoot });
    assert.ok(existsSync(marker), "in-place fetch should not delete .git contents");
  });
});

// ─── (b) per-repo override + fallback ────────────────────────────────

describe("getPromptPath — per-repo override lookup with fallback", () => {
  it("returns <cacheRoot>/<org>/<repo>/<reviewer>.md when that override file exists", async () => {
    const { url } = makeBareUpstream(workRoot);
    const cacheRoot = join(workRoot, "cache");
    await cloneOrFetchPromptsCache({ url, ref: "main", cacheRoot });

    const overridePath = getPromptPath(cacheRoot, "security", "acme", "widgets");
    assert.equal(overridePath, join(cacheRoot, "acme", "widgets", "security.md"));
    // Sanity: the override file actually exists on disk.
    assert.ok(existsSync(overridePath));
  });

  it("falls back to <cacheRoot>/<reviewer>.md when no per-repo override exists", async () => {
    const { url } = makeBareUpstream(workRoot);
    const cacheRoot = join(workRoot, "cache");
    await cloneOrFetchPromptsCache({ url, ref: "main", cacheRoot });

    // The fixture has acme/widgets/security.md but NOT
    // acme/widgets/standards.md — so standards falls back.
    const fallback = getPromptPath(cacheRoot, "standards", "acme", "widgets");
    assert.equal(fallback, join(cacheRoot, "standards.md"));
  });

  it("falls back when org/repo are omitted entirely", async () => {
    const { url } = makeBareUpstream(workRoot);
    const cacheRoot = join(workRoot, "cache");
    await cloneOrFetchPromptsCache({ url, ref: "main", cacheRoot });

    const path = getPromptPath(cacheRoot, "security");
    assert.equal(path, join(cacheRoot, "security.md"));
  });

  it("returns the fallback path EVEN IF that file doesn't exist on disk", async () => {
    // The reader (fetchCanonicalPrompt) handles missing-file as
    // `no_such_file`. The resolver's job ends at "which path should I try."
    const { url } = makeBareUpstream(workRoot);
    const cacheRoot = join(workRoot, "cache");
    await cloneOrFetchPromptsCache({ url, ref: "main", cacheRoot });

    const path = getPromptPath(cacheRoot, "unknown-reviewer");
    assert.equal(path, join(cacheRoot, "unknown-reviewer.md"));
    assert.equal(existsSync(path), false);
  });

  it("rejects reviewer names with path-traversal characters", () => {
    assert.throws(
      () => getPromptPath("/tmp/cache", "../escape"),
      /invalid reviewer name/,
    );
    assert.throws(
      () => getPromptPath("/tmp/cache", "sub/path"),
      /invalid reviewer name/,
    );
  });

  it("falls back to default path when org/repo are malformed (does not throw)", () => {
    // A verb call without repo context, or with a slug that fails our
    // stricter shape check, must NOT take down the request — just
    // fall through to the default path. The read decides what's actually
    // available.
    const out = getPromptPath("/tmp/cache", "security", "../bad", "repo");
    assert.equal(out, "/tmp/cache/security.md");
  });
});

// ─── (c) atomic swap survives mid-fetch failure ──────────────────────

describe("cloneOrFetchPromptsCache — atomic swap survives mid-fetch failure", () => {
  it("a failed refresh against a bogus URL leaves the existing cacheRoot intact", async () => {
    const { url } = makeBareUpstream(workRoot);
    const cacheRoot = join(workRoot, "cache");

    // First, populate the cache with a known-good state.
    const good = await cloneOrFetchPromptsCache({ url, ref: "main", cacheRoot });
    const beforeSecurity = readFileSync(join(cacheRoot, "security.md"), "utf8");

    // Drop a sentinel inside the cache that the bogus-URL refresh
    // attempt must NOT delete.
    writeFileSync(join(cacheRoot, "sentinel.txt"), "do not delete me\n");

    // Now point the next refresh at a URL that doesn't resolve. We
    // also nuke the .git/config remote so the in-place fetch path
    // fails AND the atomic rebuild path also fails (the rebuild tries
    // to clone the bogus URL into .tmp).
    const bogusUrl = `file://${workRoot}/does-not-exist.git`;
    let threw = false;
    try {
      await cloneOrFetchPromptsCache({ url: bogusUrl, ref: "main", cacheRoot });
    } catch {
      threw = true;
    }
    assert.equal(threw, true, "bogus-URL refresh must throw");

    // The original cacheRoot is still here, with its original content.
    assert.ok(existsSync(join(cacheRoot, "security.md")));
    assert.equal(
      readFileSync(join(cacheRoot, "security.md"), "utf8"),
      beforeSecurity,
    );
    assert.ok(existsSync(join(cacheRoot, "sentinel.txt")));
    assert.equal(
      readFileSync(join(cacheRoot, "sentinel.txt"), "utf8"),
      "do not delete me\n",
    );

    // A subsequent good refresh recovers cleanly (proves the failed
    // attempt didn't leave the cache in a corrupted state).
    const recover = await cloneOrFetchPromptsCache({ url, ref: "main", cacheRoot });
    assert.equal(recover.commitSha, good.commitSha);
  });

  it("a clone failure on first-run leaves no half-built cacheRoot", async () => {
    const cacheRoot = join(workRoot, "cache");
    const bogusUrl = `file://${workRoot}/never-existed.git`;

    let threw = false;
    try {
      await cloneOrFetchPromptsCache({ url: bogusUrl, ref: "main", cacheRoot });
    } catch {
      threw = true;
    }
    assert.equal(threw, true);
    // cacheRoot was never populated (the swap only happens after
    // rev-parse succeeds inside .tmp). The .tmp dir may or may not be
    // present depending on where the failure happened; the invariant
    // we care about is that the LIVE path is absent.
    assert.equal(existsSync(cacheRoot), false);
  });
});

// ─── (d) in-process lock prevents concurrent fetches ─────────────────

describe("cloneOrFetchPromptsCache — concurrent-fetch coalescing", () => {
  it("two simultaneous calls for the same cacheRoot share one in-flight fetch", async () => {
    const { url } = makeBareUpstream(workRoot);
    const cacheRoot = join(workRoot, "cache");

    // Fire two calls without awaiting the first.
    const p1 = cloneOrFetchPromptsCache({ url, ref: "main", cacheRoot });
    const p2 = cloneOrFetchPromptsCache({ url, ref: "main", cacheRoot });
    const [r1, r2] = await Promise.all([p1, p2]);

    // Both resolve to the same result — the coalescing map handed both
    // callers the SAME promise object, so they MUST have the same sha
    // and the same refreshedAt timestamp.
    assert.equal(r1.commitSha, r2.commitSha);
    assert.equal(r1.refreshedAt, r2.refreshedAt);

    // And the cache landed correctly.
    assert.ok(existsSync(join(cacheRoot, "security.md")));
  });

  it("after a refresh completes, a new call is allowed (lock + map cleared)", async () => {
    const { url } = makeBareUpstream(workRoot);
    const cacheRoot = join(workRoot, "cache");

    const r1 = await cloneOrFetchPromptsCache({ url, ref: "main", cacheRoot });
    const r2 = await cloneOrFetchPromptsCache({ url, ref: "main", cacheRoot });
    // Same sha (no new upstream commits), but DIFFERENT refreshedAt
    // proves it actually ran a second time rather than returning the
    // cached promise.
    assert.equal(r1.commitSha, r2.commitSha);
    assert.notEqual(r1.refreshedAt, r2.refreshedAt);
  });

  it("a failed refresh clears the in-flight map so retries are not blocked", async () => {
    const { url } = makeBareUpstream(workRoot);
    const cacheRoot = join(workRoot, "cache");

    // First, prime the cache so the cleanup path doesn't take "fresh
    // clone" → "lockfile-only" mode (which is also fine, but this test
    // is specifically about post-failure recovery).
    await cloneOrFetchPromptsCache({ url, ref: "main", cacheRoot });

    let threw = false;
    try {
      await cloneOrFetchPromptsCache({
        url: `file://${workRoot}/bogus.git`,
        ref: "main",
        cacheRoot,
      });
    } catch {
      threw = true;
    }
    assert.equal(threw, true);

    // Retry with the good URL — must succeed (proves the in-flight
    // map and the lock both got cleared).
    const retry = await cloneOrFetchPromptsCache({ url, ref: "main", cacheRoot });
    assert.match(retry.commitSha, /^[0-9a-f]{40}$/);
  });
});

// ─── input validation ─────────────────────────────────────────────────

describe("cloneOrFetchPromptsCache — input validation", () => {
  it("rejects a ref containing shell metacharacters", async () => {
    await assert.rejects(
      cloneOrFetchPromptsCache({
        url: "file:///tmp/anything.git",
        ref: "main; rm -rf /",
        cacheRoot: join(workRoot, "cache"),
      }),
      /not allowed in a git refspec/,
    );
  });

  it("rejects a missing url", async () => {
    await assert.rejects(
      // @ts-expect-error — deliberately bad input
      cloneOrFetchPromptsCache({ ref: "main", cacheRoot: workRoot }),
      /url is required/,
    );
  });

  it("rejects a missing cacheRoot", async () => {
    await assert.rejects(
      // @ts-expect-error — deliberately bad input
      cloneOrFetchPromptsCache({ url: "file:///x.git", ref: "main" }),
      /cacheRoot is required/,
    );
  });

  // AGT-417: URL shape validation (option-injection / whitespace / controls)
  it("rejects a `-`-leading url (git option-injection class)", async () => {
    await assert.rejects(
      cloneOrFetchPromptsCache({
        url: "--upload-pack=touch /tmp/pwned",
        ref: "main",
        cacheRoot: join(workRoot, "cache"),
      }),
      /not an accepted git URL shape/,
    );
  });

  it("rejects a url containing whitespace", async () => {
    await assert.rejects(
      cloneOrFetchPromptsCache({
        url: "https://example.com/a b.git",
        ref: "main",
        cacheRoot: join(workRoot, "cache"),
      }),
      /not an accepted git URL shape/,
    );
  });

  it("rejects a url containing a control character", async () => {
    await assert.rejects(
      cloneOrFetchPromptsCache({
        url: "https://example.com/a" + String.fromCharCode(1) + "b.git",
        ref: "main",
        cacheRoot: join(workRoot, "cache"),
      }),
      /not an accepted git URL shape/,
    );
  });

  it("masks embedded credentials in the thrown error (no network)", async () => {
    // Well-shaped file:// URL with userinfo → passes the shape check, then
    // git clone fails fast locally (no such repo). The thrown error must
    // mask the token. Pins AC4's credential-masking on the error path.
    let err: Error | null = null;
    try {
      await cloneOrFetchPromptsCache({
        url: "file://x-access-token:SUPERSECRET@/nonexistent/repo.git",
        ref: "main",
        cacheRoot: join(workRoot, "fresh-cache"),
      });
    } catch (e) {
      err = e as Error;
    }
    assert.ok(err, "expected the clone to fail");
    assert.ok(
      !err!.message.includes("SUPERSECRET"),
      `token leaked in error: ${err!.message}`,
    );
    assert.match(err!.message, /\*\*\*@/);
  });
});

describe("scrubGitUrlCredentials (AGT-417)", () => {
  it("masks userinfo for any scheme", () => {
    assert.equal(
      scrubGitUrlCredentials("https://x-access-token:TOK@github.com/o/r.git"),
      "https://***@github.com/o/r.git",
    );
    assert.equal(
      scrubGitUrlCredentials("ssh://user:pw@host/path"),
      "ssh://***@host/path",
    );
  });

  it("leaves the scp-short git@host: form alone (no inline secret)", () => {
    assert.equal(
      scrubGitUrlCredentials("git@github.com:o/r.git"),
      "git@github.com:o/r.git",
    );
  });

  it("leaves a credential-free URL unchanged", () => {
    assert.equal(
      scrubGitUrlCredentials("https://github.com/o/r.git"),
      "https://github.com/o/r.git",
    );
  });
});

describe("git argv builders carry the -- terminator (AGT-417)", () => {
  it("buildCloneArgs puts -- before the url positional", () => {
    const args = buildCloneArgs("main", "https://h/r.git", "/tmp/x");
    assert.deepEqual(args, [
      "clone", "--quiet", "--branch", "main", "--", "https://h/r.git", "/tmp/x",
    ]);
    // the url must come AFTER the -- terminator
    assert.ok(args.indexOf("--") < args.indexOf("https://h/r.git"));
  });

  it("buildRemoteSetUrlArgs puts -- before the url positional", () => {
    const args = buildRemoteSetUrlArgs("https://h/r.git");
    assert.deepEqual(args, ["remote", "set-url", "origin", "--", "https://h/r.git"]);
    assert.ok(args.indexOf("--") < args.indexOf("https://h/r.git"));
  });
});
