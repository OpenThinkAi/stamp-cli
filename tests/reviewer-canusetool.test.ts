/**
 * Unit tests for the reviewer tool-gating helpers shipped in
 * `src/lib/reviewer.ts` to close audit M3 (AGT-035).
 *
 * Pinning notes:
 * - Filename retains `canusetool` for git-history continuity, but the gate
 *   is now `hooks.PreToolUse`, not `canUseTool` — the SDK bypasses
 *   canUseTool for tools listed in `allowedTools`, so the prior gate was
 *   structurally inert in production. See AGT-035 QA bounce.
 * - These tests call the exported `checkReviewerTool` directly, which is
 *   the same function the production PreToolUse hook delegates to. No
 *   parallel reimplementation means the tests cannot drift from
 *   production behaviour.
 * - The integration concern — does the SDK actually invoke the
 *   PreToolUse hook for Read/Grep/Glob? — is covered by the gated
 *   integration test in `reviewer-canusetool.integration.test.ts`.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { checkReviewerTool, denyIfOutsideRepo } from "../src/lib/reviewer.ts";

describe("denyIfOutsideRepo (path-scope helper)", () => {
  const repoRoot = "/tmp/repo";

  it("allows a relative path inside the repo", () => {
    assert.equal(denyIfOutsideRepo("src/foo.ts", repoRoot, "Read"), null);
    assert.equal(denyIfOutsideRepo("README.md", repoRoot, "Read"), null);
    assert.equal(denyIfOutsideRepo("./README.md", repoRoot, "Read"), null);
  });

  it("allows an absolute path inside the repo", () => {
    assert.equal(
      denyIfOutsideRepo("/tmp/repo/src/foo.ts", repoRoot, "Read"),
      null,
    );
    // The repoRoot itself resolves to repoRoot — odd but legal.
    assert.equal(denyIfOutsideRepo("/tmp/repo", repoRoot, "Read"), null);
  });

  it("denies an absolute path outside the repo", () => {
    const msg = denyIfOutsideRepo("/etc/hosts", repoRoot, "Read");
    assert.match(msg ?? "", /resolves outside repoRoot/);
    assert.match(msg ?? "", /\/etc\/hosts/);
  });

  it("denies a relative .. traversal escape", () => {
    // <repoRoot>/../sibling/secret resolves to /tmp/sibling/secret —
    // outside the repo even though the literal string starts inside it.
    const msg = denyIfOutsideRepo("../sibling/secret", repoRoot, "Read");
    assert.match(msg ?? "", /resolves outside repoRoot/);
  });

  it("denies a deeper relative .. traversal escape", () => {
    const msg = denyIfOutsideRepo("src/../../escape", repoRoot, "Grep");
    assert.match(msg ?? "", /Grep path/);
    assert.match(msg ?? "", /resolves outside repoRoot/);
  });

  it("denies a sibling directory whose name has the repo's name as a prefix", () => {
    // The classic '+ path.sep' bug: <repoRoot>-evil/x must not match
    // <repoRoot> as a literal string prefix.
    const msg = denyIfOutsideRepo("/tmp/repo-evil/x", repoRoot, "Read");
    assert.match(msg ?? "", /resolves outside repoRoot/);
  });

  it("returns a typed deny message that names the tool", () => {
    assert.match(
      denyIfOutsideRepo("/etc/passwd", repoRoot, "Read") ?? "",
      /^Read /,
    );
    assert.match(
      denyIfOutsideRepo("/etc/passwd", repoRoot, "Grep") ?? "",
      /^Grep /,
    );
    assert.match(
      denyIfOutsideRepo("/etc/passwd", repoRoot, "Glob") ?? "",
      /^Glob /,
    );
  });

  it("rejects non-string and empty inputs without crashing", () => {
    assert.match(denyIfOutsideRepo(undefined, repoRoot, "Read") ?? "", /string/);
    assert.match(denyIfOutsideRepo(null, repoRoot, "Read") ?? "", /string/);
    assert.match(denyIfOutsideRepo(123, repoRoot, "Read") ?? "", /string/);
    assert.match(denyIfOutsideRepo("", repoRoot, "Read") ?? "", /string/);
  });

  it("normalises a non-canonical repoRoot (trailing slash, .. segment)", () => {
    // path.resolve collapses these on both sides — a `repoRoot` value of
    // "/tmp/repo/" or "/tmp/foo/../repo" must behave identically to
    // "/tmp/repo". Pin so a future "optimisation" can't quietly assume
    // the caller gave us a canonical path.
    assert.equal(denyIfOutsideRepo("README.md", "/tmp/repo/", "Read"), null);
    assert.equal(
      denyIfOutsideRepo("README.md", "/tmp/foo/../repo", "Read"),
      null,
    );
    assert.match(
      denyIfOutsideRepo("/etc/hosts", "/tmp/repo/", "Read") ?? "",
      /resolves outside repoRoot/,
    );
  });
});

const repoRoot = "/tmp/repo";
const noWebHosts = new Set<string>();

describe("checkReviewerTool — Read", () => {
  // AC #5 named target — `Read('/etc/hosts')` must be denied. The unit
  // pins the deny logic; the integration test pins that the SDK actually
  // runs the hook (see reviewer-canusetool.integration.test.ts).
  it("denies Read('/etc/hosts')", () => {
    const r = checkReviewerTool({
      toolName: "Read",
      toolInput: { file_path: "/etc/hosts" },
      repoRoot,
      webFetchHosts: noWebHosts,
    });
    assert.equal(r.allow, false);
    if (!r.allow) assert.match(r.reason, /resolves outside repoRoot/);
  });

  // AC #6: traversal that *starts inside* repoRoot but escapes via ..
  it("denies Read('<repoRoot>/../sibling/secret') as a traversal", () => {
    const r = checkReviewerTool({
      toolName: "Read",
      toolInput: { file_path: `${repoRoot}/../sibling/secret` },
      repoRoot,
      webFetchHosts: noWebHosts,
    });
    assert.equal(r.allow, false);
  });

  // AC #7: regression — the legitimate happy-path is still allowed.
  it("allows Read('<repoRoot>/README.md') (regression check)", () => {
    const r = checkReviewerTool({
      toolName: "Read",
      toolInput: { file_path: `${repoRoot}/README.md` },
      repoRoot,
      webFetchHosts: noWebHosts,
    });
    assert.equal(r.allow, true);
  });

  // AC #4: reviewer-internal denylist (attestation DB).
  it("denies Read('.git/stamp/state.db') even inside repoRoot", () => {
    const r = checkReviewerTool({
      toolName: "Read",
      toolInput: { file_path: ".git/stamp/state.db" },
      repoRoot,
      webFetchHosts: noWebHosts,
    });
    assert.equal(r.allow, false);
    if (!r.allow) assert.match(r.reason, /reviewer-internal|denied/);
  });

  // AC #4: reviewer-internal denylist (trusted-keys directory).
  it("denies Read('.stamp/trusted-keys/anyone.pub') even inside repoRoot", () => {
    const r = checkReviewerTool({
      toolName: "Read",
      toolInput: { file_path: ".stamp/trusted-keys/alice.pub" },
      repoRoot,
      webFetchHosts: noWebHosts,
    });
    assert.equal(r.allow, false);
    if (!r.allow) assert.match(r.reason, /trust anchors|exfil-attractive|denied/);
  });

  it("allows Read of files in unrelated subdirs that contain 'stamp' in the name", () => {
    // Make sure the denylist is path-equality / prefix-anchored, not a
    // substring match. A repo that contains a `docs/stamp-overview.md`
    // or `lib/stamp-helper.ts` must not be caught by the trusted-keys
    // prefix test.
    for (const p of [
      "docs/stamp-overview.md",
      ".stamp/config.yml",
      ".stamp/reviewers/security.md",
    ]) {
      const r = checkReviewerTool({
        toolName: "Read",
        toolInput: { file_path: p },
        repoRoot,
        webFetchHosts: noWebHosts,
      });
      assert.equal(r.allow, true, `Read('${p}') should be allowed`);
    }
  });
});

describe("checkReviewerTool — Grep", () => {
  it("allows Grep with no path (defaults to cwd which is repoRoot)", () => {
    const r = checkReviewerTool({
      toolName: "Grep",
      toolInput: { pattern: "TODO" },
      repoRoot,
      webFetchHosts: noWebHosts,
    });
    assert.equal(r.allow, true);
  });

  it("allows Grep with a path inside the repo", () => {
    const r = checkReviewerTool({
      toolName: "Grep",
      toolInput: { pattern: "TODO", path: "src/" },
      repoRoot,
      webFetchHosts: noWebHosts,
    });
    assert.equal(r.allow, true);
  });

  it("denies Grep with a path outside the repo", () => {
    const r = checkReviewerTool({
      toolName: "Grep",
      toolInput: { pattern: "secret", path: "/etc" },
      repoRoot,
      webFetchHosts: noWebHosts,
    });
    assert.equal(r.allow, false);
    if (!r.allow) assert.match(r.reason, /Grep path/);
  });
});

describe("checkReviewerTool — Glob", () => {
  it("allows Glob with no path", () => {
    const r = checkReviewerTool({
      toolName: "Glob",
      toolInput: { pattern: "**/*.ts" },
      repoRoot,
      webFetchHosts: noWebHosts,
    });
    assert.equal(r.allow, true);
  });

  it("allows Glob with an in-repo path", () => {
    const r = checkReviewerTool({
      toolName: "Glob",
      toolInput: { pattern: "**/*.ts", path: "src/" },
      repoRoot,
      webFetchHosts: noWebHosts,
    });
    assert.equal(r.allow, true);
  });

  it("denies Glob with an out-of-repo path", () => {
    const r = checkReviewerTool({
      toolName: "Glob",
      toolInput: { pattern: "*", path: "/etc" },
      repoRoot,
      webFetchHosts: noWebHosts,
    });
    assert.equal(r.allow, false);
  });

  it("denies an absolute glob pattern (belt-and-suspenders)", () => {
    const r = checkReviewerTool({
      toolName: "Glob",
      toolInput: { pattern: "/etc/**/*" },
      repoRoot,
      webFetchHosts: noWebHosts,
    });
    assert.equal(r.allow, false);
    if (!r.allow) assert.match(r.reason, /absolute/);
  });

  it("denies a glob pattern containing a '..' segment", () => {
    const r = checkReviewerTool({
      toolName: "Glob",
      toolInput: { pattern: "../**/*" },
      repoRoot,
      webFetchHosts: noWebHosts,
    });
    assert.equal(r.allow, false);
    if (!r.allow) assert.match(r.reason, /'\.\.' segment/);
  });

  it("allows ordinary recursive globs", () => {
    for (const p of ["**/*.ts", "src/**/*.test.ts", "*.md"]) {
      const r = checkReviewerTool({
        toolName: "Glob",
        toolInput: { pattern: p },
        repoRoot,
        webFetchHosts: noWebHosts,
      });
      assert.equal(r.allow, true, `pattern ${p} should be allowed`);
    }
  });
});

describe("checkReviewerTool — WebFetch", () => {
  // The WebFetch host allowlist used to live in the canUseTool branch
  // and was structurally inert for the same reason Read/Grep/Glob were
  // (canUseTool bypassed when the tool is in allowedTools). It now
  // routes through the same checkReviewerTool function and the same
  // PreToolUse hook — pin the contract here.
  const hosts = new Set(["api.example.com", "docs.example.com"]);

  it("allows a WebFetch to an allow-listed host", () => {
    const r = checkReviewerTool({
      toolName: "WebFetch",
      toolInput: { url: "https://api.example.com/v1/issues/42" },
      repoRoot,
      webFetchHosts: hosts,
    });
    assert.equal(r.allow, true);
  });

  it("denies a WebFetch to a non-allowlisted host", () => {
    const r = checkReviewerTool({
      toolName: "WebFetch",
      toolInput: { url: "https://evil.example.org/exfil" },
      repoRoot,
      webFetchHosts: hosts,
    });
    assert.equal(r.allow, false);
    if (!r.allow) assert.match(r.reason, /not in allowed_hosts/);
  });

  it("denies a WebFetch when the URL is not a string", () => {
    const r = checkReviewerTool({
      toolName: "WebFetch",
      toolInput: { url: 42 },
      repoRoot,
      webFetchHosts: hosts,
    });
    assert.equal(r.allow, false);
  });

  it("denies a WebFetch when the URL is unparseable", () => {
    const r = checkReviewerTool({
      toolName: "WebFetch",
      toolInput: { url: "not-a-url" },
      repoRoot,
      webFetchHosts: hosts,
    });
    assert.equal(r.allow, false);
    if (!r.allow) assert.match(r.reason, /not parseable/);
  });

  it("matches hostname case-insensitively", () => {
    const r = checkReviewerTool({
      toolName: "WebFetch",
      toolInput: { url: "https://API.Example.com/x" },
      repoRoot,
      webFetchHosts: hosts,
    });
    assert.equal(r.allow, true);
  });
});

describe("checkReviewerTool — pass-through", () => {
  // Tools not specifically gated (the verdict-submission MCP tool, MCP
  // tools the operator wired in) pass through. SAFE_TOOLS at config-load
  // time already gatekeeps which tool names can reach this function.
  it("allows the verdict-submission MCP tool", () => {
    const r = checkReviewerTool({
      toolName: "mcp__stamp-verdict__submit_verdict",
      toolInput: { verdict: "approved", prose: "looks good" },
      repoRoot,
      webFetchHosts: noWebHosts,
    });
    assert.equal(r.allow, true);
  });
});
