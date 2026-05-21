/**
 * Tests for the server-side canonical-prompt fetch (src/server/promptFetch.ts).
 *
 * AGT-370 reshape: the prompt source moved from a bare git repo + `git
 * show` at `base_sha` to a filesystem cache. Coverage walks the new
 * security-critical contract:
 *   - happy path returns bytes + correct sha256 (bare hex, matching the
 *     ApprovalV4.prompt_sha256 convention)
 *   - every documented failure mode maps to its typed PromptFetchError.kind
 *     (no_such_file, io_error, invalid_input)
 *   - the discriminated-union return shape — no thrown errors for
 *     runtime conditions, only for caller bugs (invalid resolver input)
 *   - hash determinism: identical bytes hash identically across calls
 *     and match a hand-computed sha256 via Node `crypto.createHash`
 *   - resolver injection: a custom resolver routes the fetch to a
 *     different cache path, and the default resolver maps `reviewer`
 *     to `<cacheRoot>/<reviewer>.md`
 *   - no fallback: a missing file ALWAYS errors, never returns content
 *     from some other path
 */

import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import {
  chmodSync,
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
  defaultPromptCacheResolver,
  fetchCanonicalPrompt,
  type FetchedPrompt,
  type PromptFetchError,
  type PromptResolver,
} from "../src/server/promptFetch.ts";

/**
 * Assertion narrowing helper: fail the test loudly if the result isn't
 * the expected discriminant, so the rest of the test body type-checks
 * against `FetchedPrompt`. Easier to read than scattering `if
 * (result.kind !== "ok")` across every test.
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

describe("defaultPromptCacheResolver", () => {
  it("maps reviewer to <cacheRoot>/<reviewer>.md", () => {
    const r = defaultPromptCacheResolver("/etc/stamp/reviewers");
    assert.equal(r("security"), "/etc/stamp/reviewers/security.md");
    assert.equal(r("standards"), "/etc/stamp/reviewers/standards.md");
  });

  it("strips exactly one trailing slash from cacheRoot", () => {
    const r = defaultPromptCacheResolver("/etc/stamp/reviewers/");
    assert.equal(r("security"), "/etc/stamp/reviewers/security.md");
  });

  it("throws on missing cacheRoot", () => {
    assert.throws(() => defaultPromptCacheResolver(""), /cacheRoot/);
  });

  it("throws on a reviewer name containing a path separator", () => {
    const r = defaultPromptCacheResolver("/etc/stamp/reviewers");
    assert.throws(() => r("../escape"), /invalid reviewer name/);
    assert.throws(() => r("sub/path"), /invalid reviewer name/);
  });

  it("throws on a reviewer name with a leading dash", () => {
    const r = defaultPromptCacheResolver("/etc/stamp/reviewers");
    assert.throws(() => r("-flag"), /invalid reviewer name/);
  });

  it("throws on a reviewer name that's too long", () => {
    const r = defaultPromptCacheResolver("/etc/stamp/reviewers");
    // REVIEWER_NAME_RE cap is 64 chars (1 leading + 63 follow). 65 must reject.
    assert.throws(() => r("a".repeat(65)), /invalid reviewer name/);
  });

  it("accepts the documented reviewer-name shapes", () => {
    const r = defaultPromptCacheResolver("/etc/stamp/reviewers");
    assert.equal(r("security"), "/etc/stamp/reviewers/security.md");
    assert.equal(r("product_review"), "/etc/stamp/reviewers/product_review.md");
    assert.equal(r("v2-beta"), "/etc/stamp/reviewers/v2-beta.md");
  });
});

// ─── AGT-373: widened (reviewer, org?, repo?) resolver ─────────────
//
// Phase A tests above exercise the single-arg call shape — they
// continue to pass unmodified because `org` / `repo` are optional
// (AC #5). The block below covers the Phase B widening:
// per-repo override file present → resolver returns the override
// path; absent or missing slug → resolver falls back to the
// `<cacheRoot>/<reviewer>.md` default. The path-construction logic
// itself lives in `getPromptPath` (AGT-372) and has its own coverage
// in tests/promptsCache.test.ts; these tests exist to prove the
// resolver wiring forwards correctly.

describe("defaultPromptCacheResolver — AGT-373 widened (reviewer, org?, repo?)", () => {
  let cacheRoot: string;

  beforeEach(() => {
    cacheRoot = realpathSync(mkdtempSync(join(tmpdir(), "stamp-promptfetch-373-")));
    // Default reviewer prompts at the cache-root level.
    writeFileSync(join(cacheRoot, "security.md"), "default security prompt\n");
    writeFileSync(join(cacheRoot, "standards.md"), "default standards prompt\n");
    // Per-repo override for security — but NOT for standards.
    mkdirSync(join(cacheRoot, "acme", "widgets"), { recursive: true });
    writeFileSync(
      join(cacheRoot, "acme", "widgets", "security.md"),
      "ACME-widgets security prompt\n",
    );
  });

  afterEach(() => {
    rmSync(cacheRoot, { recursive: true, force: true });
  });

  it("returns the override path when <cacheRoot>/<org>/<repo>/<reviewer>.md exists", () => {
    const r = defaultPromptCacheResolver(cacheRoot);
    const overridePath = r("security", "acme", "widgets");
    assert.equal(overridePath, join(cacheRoot, "acme", "widgets", "security.md"));
  });

  it("falls back to the default when org+repo are passed but the override file is absent", () => {
    const r = defaultPromptCacheResolver(cacheRoot);
    // standards.md exists at root but NOT under acme/widgets/.
    const fallback = r("standards", "acme", "widgets");
    assert.equal(fallback, join(cacheRoot, "standards.md"));
  });

  it("falls back to the default when org/repo are omitted entirely (Phase A shape)", () => {
    const r = defaultPromptCacheResolver(cacheRoot);
    assert.equal(r("security"), join(cacheRoot, "security.md"));
  });

  it("ignores org/repo when only one of the two is supplied (resolver expects a complete tuple)", () => {
    const r = defaultPromptCacheResolver(cacheRoot);
    // Just org, no repo → fallback (the override path needs both).
    assert.equal(
      r("security", "acme"),
      join(cacheRoot, "security.md"),
      "single-org without repo should not consult the override",
    );
    assert.equal(
      r("security", undefined, "widgets"),
      join(cacheRoot, "security.md"),
      "single-repo without org should not consult the override",
    );
  });

  it("falls back to the default when org/repo are malformed (does not throw)", () => {
    const r = defaultPromptCacheResolver(cacheRoot);
    // A malformed slug from upstream is much more likely to be
    // "verb didn't carry repo context" than "attacker forged a slug".
    // getPromptPath silently falls through; the read decides what's
    // actually available.
    assert.equal(r("security", "../bad", "widgets"), join(cacheRoot, "security.md"));
  });
});

describe("fetchCanonicalPrompt — AGT-373 org/repo threading", () => {
  let cacheRoot: string;

  beforeEach(() => {
    cacheRoot = realpathSync(mkdtempSync(join(tmpdir(), "stamp-promptfetch-373fc-")));
    writeFileSync(join(cacheRoot, "security.md"), "default-bytes\n");
    mkdirSync(join(cacheRoot, "acme", "widgets"), { recursive: true });
    writeFileSync(
      join(cacheRoot, "acme", "widgets", "security.md"),
      "override-bytes\n",
    );
  });

  afterEach(() => {
    rmSync(cacheRoot, { recursive: true, force: true });
  });

  it("returns the override bytes when (reviewer, org, repo) maps to an existing override file", async () => {
    const r = defaultPromptCacheResolver(cacheRoot);
    const result = await fetchCanonicalPrompt(r, "security", "acme", "widgets");
    assertOk(result);
    assert.equal(result.bytes.toString("utf8"), "override-bytes\n");
  });

  it("returns the default bytes when the override file is absent for this (org, repo)", async () => {
    const r = defaultPromptCacheResolver(cacheRoot);
    // globex/anvils has no override → fall through to <cacheRoot>/security.md.
    const result = await fetchCanonicalPrompt(r, "security", "globex", "anvils");
    assertOk(result);
    assert.equal(result.bytes.toString("utf8"), "default-bytes\n");
  });

  it("forwards (reviewer, org, repo) verbatim to a custom resolver", async () => {
    const calls: Array<{ reviewer: string; org?: string; repo?: string }> = [];
    // Custom resolver records the args and returns the default path.
    const spyResolver: PromptResolver = (reviewer, org, repo) => {
      calls.push({ reviewer, org, repo });
      return join(cacheRoot, `${reviewer}.md`);
    };
    const result = await fetchCanonicalPrompt(
      spyResolver,
      "security",
      "acme",
      "widgets",
    );
    assertOk(result);
    assert.deepEqual(calls, [{ reviewer: "security", org: "acme", repo: "widgets" }]);
  });

  it("an older one-arg resolver remains assignable and is called with the wider signature (variance check)", async () => {
    // Phase A resolvers that ignore org/repo MUST keep working.
    // Variance: `(r: string) => string` is assignable to
    // `(r: string, org?: string, repo?: string) => string` — the
    // narrower resolver discards extra args.
    const narrowResolver: PromptResolver = (reviewer: string): string =>
      join(cacheRoot, `${reviewer}.md`);
    const result = await fetchCanonicalPrompt(
      narrowResolver,
      "security",
      "acme",
      "widgets",
    );
    assertOk(result);
    // No override consulted (the narrow resolver ignores org/repo).
    assert.equal(result.bytes.toString("utf8"), "default-bytes\n");
  });
});

describe("fetchCanonicalPrompt — happy path", () => {
  let cacheRoot: string;
  const promptBody = "You are a security reviewer.\n\nReject all hardcoded secrets.\n";

  beforeEach(() => {
    cacheRoot = realpathSync(mkdtempSync(join(tmpdir(), "stamp-promptfetch-")));
    writeFileSync(join(cacheRoot, "security.md"), promptBody);
  });

  afterEach(() => {
    rmSync(cacheRoot, { recursive: true, force: true });
  });

  it("returns bytes + bare-hex sha256 of the prompt at the cache path", async () => {
    const resolver = defaultPromptCacheResolver(cacheRoot);
    const result = await fetchCanonicalPrompt(resolver, "security");
    assertOk(result);

    assert.equal(result.bytes.toString("utf8"), promptBody);

    // sha256 is bare hex (no `sha256:` prefix), matches the
    // ApprovalV4.prompt_sha256 convention, and matches a hand-computed
    // Node hash over the same bytes.
    assert.match(result.sha256, /^[0-9a-f]{64}$/);
    assert.equal(
      result.sha256,
      createHash("sha256").update(Buffer.from(promptBody)).digest("hex"),
    );
    assert.equal(result.sha256.startsWith("sha256:"), false);
  });

  it("returns the SAME hash for identical bytes across repeated calls", async () => {
    const resolver = defaultPromptCacheResolver(cacheRoot);
    const a = await fetchCanonicalPrompt(resolver, "security");
    const b = await fetchCanonicalPrompt(resolver, "security");
    assertOk(a);
    assertOk(b);
    assert.equal(a.sha256, b.sha256);
    assert.deepEqual(a.bytes, b.bytes);
  });

  it("preserves byte-exact content (no whitespace normalization)", async () => {
    // Seed a prompt with CRLF + trailing whitespace + a final-no-newline
    // edge case to confirm fs.readFileSync returns bytes verbatim.
    const oddBody = "line one\r\nline two   \nfinal-no-newline";
    writeFileSync(join(cacheRoot, "standards.md"), oddBody);

    const resolver = defaultPromptCacheResolver(cacheRoot);
    const result = await fetchCanonicalPrompt(resolver, "standards");
    assertOk(result);
    assert.equal(result.bytes.toString("utf8"), oddBody);
    assert.equal(
      result.sha256,
      createHash("sha256").update(Buffer.from(oddBody)).digest("hex"),
    );
  });
});

describe("fetchCanonicalPrompt — error paths", () => {
  let cacheRoot: string;

  beforeEach(() => {
    cacheRoot = realpathSync(mkdtempSync(join(tmpdir(), "stamp-promptfetch-err-")));
    writeFileSync(join(cacheRoot, "security.md"), "prompt body\n");
  });

  afterEach(() => {
    // Restore mode if we chmod'd anything before deleting.
    try {
      chmodSync(cacheRoot, 0o755);
    } catch {
      // best-effort
    }
    rmSync(cacheRoot, { recursive: true, force: true });
  });

  it("no_such_file: prompt file is absent from the cache", async () => {
    const resolver = defaultPromptCacheResolver(cacheRoot);
    // The seeded cache has security.md but not standards.md.
    const result = await fetchCanonicalPrompt(resolver, "standards");
    assertError(result, "no_such_file");
    assert.match(result.detail, /standards\.md/);
  });

  it("no_such_file: cacheRoot itself doesn't exist", async () => {
    const missingRoot = join(cacheRoot, "does-not-exist");
    const resolver = defaultPromptCacheResolver(missingRoot);
    const result = await fetchCanonicalPrompt(resolver, "security");
    assertError(result, "no_such_file");
  });

  it("invalid_input: reviewer name with path separator (security check)", async () => {
    const resolver = defaultPromptCacheResolver(cacheRoot);
    // The exact attempted traversal a hostile caller would try if the
    // verb handler forgot to validate reviewerName. Must NOT escape to
    // an arbitrary file under the cache root.
    const result = await fetchCanonicalPrompt(resolver, "../../etc/passwd");
    assertError(result, "invalid_input");
  });

  it("invalid_input: reviewer name starting with a dash (would be confused with a flag)", async () => {
    const resolver = defaultPromptCacheResolver(cacheRoot);
    const result = await fetchCanonicalPrompt(resolver, "-flag");
    assertError(result, "invalid_input");
  });

  it("invalid_input: empty reviewer name", async () => {
    const resolver = defaultPromptCacheResolver(cacheRoot);
    const result = await fetchCanonicalPrompt(resolver, "");
    assertError(result, "invalid_input");
  });

  it("invalid_input: resolver throws on bad reviewer name → surfaces as invalid_input (not crash)", async () => {
    // The default resolver throws when its inner validation fails;
    // fetchCanonicalPrompt's own outer validation catches it first,
    // but a custom resolver that throws after a non-default validation
    // path must still surface as invalid_input rather than crashing.
    const throwingResolver: PromptResolver = (reviewer) => {
      if (reviewer === "tenant-security") {
        throw new Error("multi-tenant resolver rejected: tenant not provisioned");
      }
      return join(cacheRoot, `${reviewer}.md`);
    };
    const result = await fetchCanonicalPrompt(throwingResolver, "tenant-security");
    assertError(result, "invalid_input");
    assert.match(result.detail, /resolver rejected/);
    assert.match(result.detail, /tenant not provisioned/);
  });

  it("io_error: prompt file is unreadable (permission denied)", async () => {
    // chmod a file 000 so readFileSync hits EACCES. Skip on Windows
    // where unix-mode semantics don't apply, but on darwin/linux this
    // exercises the io_error branch deterministically.
    if (process.platform === "win32") return;
    if (process.getuid?.() === 0) return; // root bypasses mode bits
    const path = join(cacheRoot, "noaccess.md");
    writeFileSync(path, "secret\n");
    chmodSync(path, 0o000);
    const resolver = defaultPromptCacheResolver(cacheRoot);
    try {
      const result = await fetchCanonicalPrompt(resolver, "noaccess");
      assertError(result, "io_error");
    } finally {
      chmodSync(path, 0o644); // restore so afterEach cleanup can rm
    }
  });

  it("NO FALLBACK: missing file at the cache path never returns content from anywhere else", async () => {
    // Security property: if the cache has security.md but the caller
    // asks for standards, the fetch MUST error. Regressing this would
    // let an attacker claim a permissive prompt existed for a reviewer
    // it didn't.
    const resolver = defaultPromptCacheResolver(cacheRoot);
    const result = await fetchCanonicalPrompt(resolver, "standards");
    assertError(result, "no_such_file");
  });
});

describe("fetchCanonicalPrompt — resolver injection", () => {
  let cacheRoot: string;

  beforeEach(() => {
    cacheRoot = realpathSync(mkdtempSync(join(tmpdir(), "stamp-promptfetch-inj-")));
  });

  afterEach(() => {
    rmSync(cacheRoot, { recursive: true, force: true });
  });

  it("uses the path the injected resolver returns (multi-tenant Phase 2 shape)", async () => {
    // Phase 2 SaaS resolver shape: `<root>/<tenant>/<reviewer>.md`.
    // Build the file at the non-default path and confirm
    // fetchCanonicalPrompt hits it.
    const tenantDir = join(cacheRoot, "acme");
    mkdirSync(tenantDir);
    writeFileSync(join(tenantDir, "security.md"), "tenant prompt\n");

    const saasResolver: PromptResolver = (reviewer) =>
      join(cacheRoot, "acme", `${reviewer}.md`);

    const result = await fetchCanonicalPrompt(saasResolver, "security");
    assertOk(result);
    assert.equal(result.bytes.toString("utf8"), "tenant prompt\n");
  });

  it("different tenants route to different paths under a multi-tenant resolver", async () => {
    mkdirSync(join(cacheRoot, "acme"));
    mkdirSync(join(cacheRoot, "globex"));
    writeFileSync(join(cacheRoot, "acme", "security.md"), "acme prompt\n");
    writeFileSync(join(cacheRoot, "globex", "security.md"), "globex prompt\n");

    const acmeResolver: PromptResolver = (reviewer) =>
      join(cacheRoot, "acme", `${reviewer}.md`);
    const globexResolver: PromptResolver = (reviewer) =>
      join(cacheRoot, "globex", `${reviewer}.md`);

    const acmeResult = await fetchCanonicalPrompt(acmeResolver, "security");
    const globexResult = await fetchCanonicalPrompt(globexResolver, "security");
    assertOk(acmeResult);
    assertOk(globexResult);
    assert.equal(acmeResult.bytes.toString("utf8"), "acme prompt\n");
    assert.equal(globexResult.bytes.toString("utf8"), "globex prompt\n");
    assert.notEqual(acmeResult.sha256, globexResult.sha256);
  });
});
