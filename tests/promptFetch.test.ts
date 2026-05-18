/**
 * Tests for the server-side canonical-prompt fetch (src/server/promptFetch.ts).
 *
 * Coverage walks the security-critical contract spelled out in AGT-329:
 *   - happy path returns bytes + correct sha256 (bare hex, matching the
 *     ApprovalV4.prompt_sha256 convention)
 *   - every documented failure mode maps to its typed PromptFetchError.kind
 *     (no_such_repo, no_such_ref, no_such_file, ambiguous_sha,
 *      invalid_input, git_error)
 *   - the discriminated-union return shape — no thrown errors for runtime
 *     conditions, only for caller bugs (invalid resolver input)
 *   - hash determinism: identical bytes hash identically across calls and
 *     match a hand-computed sha256 via Node `crypto.createHash`
 *   - resolver injection: a custom resolver routes the fetch to a
 *     different bare repo, and the default resolver maps single-tenant
 *     `(org, repo)` to `<baseDir>/<repo>.git` while ignoring org
 *   - no fallback: a missing file or missing ref ALWAYS errors, never
 *     returns content from HEAD or any other ref
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
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

import {
  defaultRepoResolver,
  fetchCanonicalPrompt,
  type FetchedPrompt,
  type PromptFetchError,
  type RepoResolver,
} from "../src/server/promptFetch.ts";

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: "pipe" });
}

/**
 * Build a bare repo at `<baseDir>/<name>.git` whose initial commit
 * contains `.stamp/reviewers/<reviewer>.md` with the given content.
 * Returns the bare path + the initial commit SHA so tests can pass it
 * as `baseSha`. Uses a temp working clone for the seed commit, then
 * mirror-pushes into the bare — same pattern as `server/new-stamp-repo`
 * but compressed for tests.
 */
function buildSeededBareRepo(
  baseDir: string,
  name: string,
  reviewer: string,
  promptBody: string,
): { barePath: string; baseSha: string } {
  const barePath = join(baseDir, `${name}.git`);
  execFileSync("git", ["init", "-q", "--bare", "-b", "main", barePath], {
    stdio: "pipe",
  });

  const workDir = mkdtempSync(join(tmpdir(), "stamp-promptfetch-seed-"));
  try {
    git(["init", "-q", "-b", "main"], workDir);
    git(["config", "user.email", "t@example.com"], workDir);
    git(["config", "user.name", "Test"], workDir);
    git(["config", "commit.gpgsign", "false"], workDir);

    mkdirSync(join(workDir, ".stamp", "reviewers"), { recursive: true });
    writeFileSync(join(workDir, ".stamp", "reviewers", `${reviewer}.md`), promptBody);
    git(["add", "."], workDir);
    git(["commit", "-q", "-m", "seed"], workDir);

    git(["remote", "add", "origin", barePath], workDir);
    git(["push", "-q", "origin", "main"], workDir);

    const baseSha = git(["rev-parse", "HEAD"], workDir).trim();
    return { barePath, baseSha };
  } finally {
    rmSync(workDir, { recursive: true, force: true });
  }
}

/**
 * Assertion narrowing helper: fail the test loudly if the result isn't
 * the expected discriminant, so the rest of the test body type-checks
 * against `FetchedPrompt`. Easier to read than `if (result.kind !== "ok")`
 * scattered across every test.
 */
function assertOk(
  result: FetchedPrompt | PromptFetchError,
): asserts result is FetchedPrompt {
  if (result.kind !== "ok") {
    assert.fail(
      `expected fetch ok, got error kind=${result.kind} detail=${result.detail}`,
    );
  }
}

function assertError(
  result: FetchedPrompt | PromptFetchError,
  expectedKind: PromptFetchError["kind"],
): asserts result is PromptFetchError {
  if (result.kind === "ok") {
    assert.fail(`expected fetch error kind=${expectedKind}, got ok`);
  }
  if (result.kind !== expectedKind) {
    assert.fail(
      `expected fetch error kind=${expectedKind}, got ${result.kind} (detail=${result.detail})`,
    );
  }
}

describe("defaultRepoResolver", () => {
  it("maps (org, repo) to <baseDir>/<repo>.git, ignoring org in Phase 1", () => {
    const r = defaultRepoResolver("/srv/git");
    assert.equal(r("acme", "widget-co"), "/srv/git/widget-co.git");
    // Different org, same repo → same path (Phase 1 is single-tenant).
    assert.equal(r("other-org", "widget-co"), "/srv/git/widget-co.git");
  });

  it("strips exactly one trailing slash from baseDir", () => {
    const r = defaultRepoResolver("/srv/git/");
    assert.equal(r("acme", "widget-co"), "/srv/git/widget-co.git");
  });

  it("throws on missing baseDir", () => {
    assert.throws(() => defaultRepoResolver(""), /baseDir/);
  });

  it("throws on a repo name containing a path separator", () => {
    const r = defaultRepoResolver("/srv/git");
    assert.throws(() => r("acme", "../escape"), /invalid repo name/);
    assert.throws(() => r("acme", "sub/path"), /invalid repo name/);
  });

  it("throws on a repo name with a leading dot or dash", () => {
    const r = defaultRepoResolver("/srv/git");
    assert.throws(() => r("acme", ".hidden"), /invalid repo name/);
    assert.throws(() => r("acme", "-flag"), /invalid repo name/);
  });

  it("throws on an org name with path metacharacters", () => {
    const r = defaultRepoResolver("/srv/git");
    assert.throws(() => r("../escape", "widget"), /invalid org name/);
  });

  it("accepts the Phase-1 single-tenant convention shape repo names", () => {
    const r = defaultRepoResolver("/srv/git");
    assert.equal(r("acme", "widget_co.v2-beta"), "/srv/git/widget_co.v2-beta.git");
  });
});

describe("fetchCanonicalPrompt — happy path", () => {
  let tmpRoot: string;
  let baseSha: string;
  const promptBody = "You are a security reviewer.\n\nReject all hardcoded secrets.\n";

  beforeEach(() => {
    tmpRoot = realpathSync(mkdtempSync(join(tmpdir(), "stamp-promptfetch-")));
    ({ baseSha } = buildSeededBareRepo(
      tmpRoot,
      "widget-co",
      "security",
      promptBody,
    ));
  });

  afterEach(() => {
    rmSync(tmpRoot, { recursive: true, force: true });
  });

  it("returns bytes + bare-hex sha256 of the prompt at base_sha", async () => {
    const resolver = defaultRepoResolver(tmpRoot);
    const result = await fetchCanonicalPrompt(
      resolver,
      "acme",
      "widget-co",
      baseSha,
      "security",
    );
    assertOk(result);

    // Bytes are exactly what's in the tree.
    assert.equal(result.bytes.toString("utf8"), promptBody);

    // sha256 is bare hex (no `sha256:` prefix), matches the
    // ApprovalV4.prompt_sha256 convention in src/lib/attestationV4.ts,
    // and matches a hand-computed Node hash over the same bytes.
    assert.match(result.sha256, /^[0-9a-f]{64}$/);
    assert.equal(
      result.sha256,
      createHash("sha256").update(Buffer.from(promptBody)).digest("hex"),
    );
    assert.equal(result.sha256.startsWith("sha256:"), false);
  });

  it("returns the SAME hash for identical bytes across repeated calls", async () => {
    const resolver = defaultRepoResolver(tmpRoot);
    const a = await fetchCanonicalPrompt(resolver, "acme", "widget-co", baseSha, "security");
    const b = await fetchCanonicalPrompt(resolver, "acme", "widget-co", baseSha, "security");
    assertOk(a);
    assertOk(b);
    assert.equal(a.sha256, b.sha256);
    assert.deepEqual(a.bytes, b.bytes);
  });

  it("preserves byte-exact content (no whitespace normalization)", async () => {
    // Seed a prompt with CRLF + trailing whitespace + a final-no-newline
    // edge case to confirm git show returns bytes verbatim.
    const oddBody = "line one\r\nline two   \nfinal-no-newline";
    const { baseSha: oddSha } = buildSeededBareRepo(
      tmpRoot,
      "odd-repo",
      "standards",
      oddBody,
    );

    const resolver = defaultRepoResolver(tmpRoot);
    const result = await fetchCanonicalPrompt(
      resolver,
      "acme",
      "odd-repo",
      oddSha,
      "standards",
    );
    assertOk(result);
    assert.equal(result.bytes.toString("utf8"), oddBody);
    assert.equal(
      result.sha256,
      createHash("sha256").update(Buffer.from(oddBody)).digest("hex"),
    );
  });
});

describe("fetchCanonicalPrompt — error paths", () => {
  let tmpRoot: string;
  let barePath: string;
  let baseSha: string;

  beforeEach(() => {
    tmpRoot = realpathSync(mkdtempSync(join(tmpdir(), "stamp-promptfetch-err-")));
    ({ barePath, baseSha } = buildSeededBareRepo(
      tmpRoot,
      "widget-co",
      "security",
      "prompt body\n",
    ));
  });

  afterEach(() => {
    rmSync(tmpRoot, { recursive: true, force: true });
  });

  it("no_such_repo: resolver points at a path with no bare repo", async () => {
    const resolver: RepoResolver = () => join(tmpRoot, "does-not-exist.git");
    const result = await fetchCanonicalPrompt(
      resolver,
      "acme",
      "anything",
      baseSha,
      "security",
    );
    assertError(result, "no_such_repo");
    // Detail surfaces server-side context (path) — log-only, do not
    // reflect this back to the SSH caller verbatim.
    assert.match(result.detail, /does-not-exist\.git/);
  });

  it("no_such_repo: resolver points at a directory that isn't a git repo", async () => {
    const notARepo = join(tmpRoot, "plain-dir");
    mkdirSync(notARepo);
    const resolver: RepoResolver = () => notARepo;
    const result = await fetchCanonicalPrompt(
      resolver,
      "acme",
      "anything",
      baseSha,
      "security",
    );
    assertError(result, "no_such_repo");
  });

  it("no_such_ref: base_sha doesn't exist in the bare repo", async () => {
    const resolver = defaultRepoResolver(tmpRoot);
    // Valid-shape SHA that won't resolve in this repo (all-zeros except
    // last char to avoid any zero-object special-case).
    const fakeSha = "0".repeat(39) + "1";
    const result = await fetchCanonicalPrompt(
      resolver,
      "acme",
      "widget-co",
      fakeSha,
      "security",
    );
    assertError(result, "no_such_ref");
  });

  it("no_such_file: base_sha resolves but reviewer file is absent at that ref", async () => {
    const resolver = defaultRepoResolver(tmpRoot);
    // The seeded repo has security.md but not standards.md.
    const result = await fetchCanonicalPrompt(
      resolver,
      "acme",
      "widget-co",
      baseSha,
      "standards",
    );
    assertError(result, "no_such_file");
  });

  it("invalid_input: baseSha is not a full 40-char hex SHA (rejects abbreviations)", async () => {
    const resolver = defaultRepoResolver(tmpRoot);
    // Abbreviated SHAs would otherwise trigger git's own ambiguity check.
    // We reject upstream so the verb handler gets a clean signal.
    const result = await fetchCanonicalPrompt(
      resolver,
      "acme",
      "widget-co",
      baseSha.slice(0, 12),
      "security",
    );
    assertError(result, "invalid_input");
    assert.match(result.detail, /40-char/);
  });

  it("invalid_input: baseSha contains non-hex characters", async () => {
    const resolver = defaultRepoResolver(tmpRoot);
    const result = await fetchCanonicalPrompt(
      resolver,
      "acme",
      "widget-co",
      "Z".repeat(40),
      "security",
    );
    assertError(result, "invalid_input");
  });

  it("invalid_input: reviewer name with path separator (security check)", async () => {
    const resolver = defaultRepoResolver(tmpRoot);
    // The exact attempted traversal a hostile caller would try if the
    // verb handler forgot to validate reviewerName. Must NOT escape to
    // an arbitrary file under .stamp/.
    const result = await fetchCanonicalPrompt(
      resolver,
      "acme",
      "widget-co",
      baseSha,
      "../../etc/passwd",
    );
    assertError(result, "invalid_input");
  });

  it("invalid_input: reviewer name starting with a dash (would be confused with a flag)", async () => {
    const resolver = defaultRepoResolver(tmpRoot);
    const result = await fetchCanonicalPrompt(
      resolver,
      "acme",
      "widget-co",
      baseSha,
      "-flag",
    );
    assertError(result, "invalid_input");
  });

  it("invalid_input: resolver throws on bad repo name → surfaces as invalid_input (not crash)", async () => {
    const resolver = defaultRepoResolver(tmpRoot);
    // defaultRepoResolver throws on a bad repo name; fetchCanonicalPrompt
    // must catch the throw and convert it to a typed error so the verb
    // handler doesn't have to wrap the call in try/catch.
    const result = await fetchCanonicalPrompt(
      resolver,
      "acme",
      "../escape",
      baseSha,
      "security",
    );
    assertError(result, "invalid_input");
    assert.match(result.detail, /resolver rejected/);
  });

  it("NO FALLBACK: missing file at base_sha never returns the file at HEAD", async () => {
    // Security property: if a later commit added the standards.md file
    // but the caller asks at the original baseSha, the fetch MUST error.
    // Regressing this would let an attacker claim a permissive prompt
    // existed at their base when it didn't.
    const workDir = mkdtempSync(join(tmpdir(), "stamp-promptfetch-second-"));
    try {
      git(["clone", "-q", barePath, workDir], "/");
      git(["config", "user.email", "t@example.com"], workDir);
      git(["config", "user.name", "Test"], workDir);
      git(["config", "commit.gpgsign", "false"], workDir);
      writeFileSync(
        join(workDir, ".stamp", "reviewers", "standards.md"),
        "added in second commit\n",
      );
      git(["add", "."], workDir);
      git(["commit", "-q", "-m", "add standards reviewer"], workDir);
      git(["push", "-q", "origin", "main"], workDir);

      const resolver = defaultRepoResolver(tmpRoot);
      // Ask for `standards` at the ORIGINAL baseSha — must fail with
      // no_such_file, NOT silently return the second-commit version.
      const result = await fetchCanonicalPrompt(
        resolver,
        "acme",
        "widget-co",
        baseSha,
        "standards",
      );
      assertError(result, "no_such_file");
    } finally {
      rmSync(workDir, { recursive: true, force: true });
    }
  });
});

describe("fetchCanonicalPrompt — resolver injection", () => {
  let tmpRoot: string;

  beforeEach(() => {
    tmpRoot = realpathSync(mkdtempSync(join(tmpdir(), "stamp-promptfetch-inj-")));
  });

  afterEach(() => {
    rmSync(tmpRoot, { recursive: true, force: true });
  });

  it("uses the path the injected resolver returns (multi-tenant Phase 2 shape)", async () => {
    // Phase 2 SaaS resolver shape: `<root>/<org>/<repo>.git`. Build a
    // bare at the non-default path and confirm fetchCanonicalPrompt
    // hits it.
    const orgDir = join(tmpRoot, "acme");
    mkdirSync(orgDir);
    const { baseSha } = buildSeededBareRepo(orgDir, "widget-co", "security", "tenant prompt\n");

    const saasResolver: RepoResolver = (org, repo) =>
      join(tmpRoot, org, `${repo}.git`);

    const result = await fetchCanonicalPrompt(
      saasResolver,
      "acme",
      "widget-co",
      baseSha,
      "security",
    );
    assertOk(result);
    assert.equal(result.bytes.toString("utf8"), "tenant prompt\n");
  });

  it("different orgs route to different bare repos under a multi-tenant resolver", async () => {
    mkdirSync(join(tmpRoot, "acme"));
    mkdirSync(join(tmpRoot, "globex"));
    const a = buildSeededBareRepo(
      join(tmpRoot, "acme"),
      "shared-name",
      "security",
      "acme prompt\n",
    );
    const g = buildSeededBareRepo(
      join(tmpRoot, "globex"),
      "shared-name",
      "security",
      "globex prompt\n",
    );

    const saasResolver: RepoResolver = (org, repo) =>
      join(tmpRoot, org, `${repo}.git`);

    const acmeResult = await fetchCanonicalPrompt(
      saasResolver,
      "acme",
      "shared-name",
      a.baseSha,
      "security",
    );
    const globexResult = await fetchCanonicalPrompt(
      saasResolver,
      "globex",
      "shared-name",
      g.baseSha,
      "security",
    );
    assertOk(acmeResult);
    assertOk(globexResult);
    assert.equal(acmeResult.bytes.toString("utf8"), "acme prompt\n");
    assert.equal(globexResult.bytes.toString("utf8"), "globex prompt\n");
    assert.notEqual(acmeResult.sha256, globexResult.sha256);
  });
});
