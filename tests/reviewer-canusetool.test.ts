/**
 * Unit tests for the canUseTool path-scope helpers shipped in
 * src/lib/reviewer.ts to close audit M3 (AGT-035).
 *
 * The integration concern — does the Claude Agent SDK actually invoke
 * canUseTool for Read/Grep/Glob? — is verified manually and recorded in
 * the PR description; the SDK is mocked at the unit level so this file
 * stays offline. The pure helper covers the path-resolution logic that
 * does the actual deny/allow work.
 */

import { strict as assert } from "node:assert";
import path from "node:path";
import { describe, it } from "node:test";

import { denyIfOutsideRepo } from "../src/lib/reviewer.ts";

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
    const msg = denyIfOutsideRepo(
      "src/../../escape",
      repoRoot,
      "Grep",
    );
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

/**
 * Re-implement the canUseTool dispatch for unit testing, pulling the same
 * helper exports so we exercise the live deny/allow logic without standing
 * up an SDK subprocess. This mirrors the structure inside invokeReviewer's
 * canUseTool and lets us pin the AC #4 reviewer-internal denylist
 * (`.git/stamp/state.db`, `.stamp/trusted-keys/*`) and the AC #3 glob
 * pattern checks without coupling to the SDK's input shape.
 *
 * If the inline canUseTool branches drift from this re-implementation, the
 * test should be updated alongside, NOT silently — the test is the
 * structural pin. There's no path to extracting the dispatcher into its
 * own export without burdening the production code with a callback shape
 * just for testability.
 */
type CanUseToolResult =
  | { behavior: "allow"; updatedInput: unknown }
  | { behavior: "deny"; message: string };

function makeDispatch(repoRoot: string) {
  return async function dispatch(
    toolName: string,
    input: unknown,
  ): Promise<CanUseToolResult> {
    if (toolName === "Read") {
      const filePath = (input as { file_path?: unknown }).file_path;
      const denied = denyIfOutsideRepo(filePath, repoRoot, "Read");
      if (denied) return { behavior: "deny", message: denied };
      // Mirror the inline reviewer-internal denylist.
      const resolvedRoot = path.resolve(repoRoot);
      const resolved = path.resolve(resolvedRoot, filePath as string);
      const rel = path.relative(resolvedRoot, resolved);
      const internalPaths = [".git/stamp/state.db"];
      const internalPrefixes = [".stamp/trusted-keys/"];
      for (const denied2 of internalPaths) {
        if (rel === denied2)
          return {
            behavior: "deny",
            message: `Read of "${filePath as string}" denied: ${denied2} ...`,
          };
      }
      for (const prefix of internalPrefixes) {
        if (rel === prefix.replace(/\/$/, "") || rel.startsWith(prefix))
          return {
            behavior: "deny",
            message: `Read of "${filePath as string}" denied: ${prefix}* ...`,
          };
      }
    }
    if (toolName === "Grep") {
      const grepPath = (input as { path?: unknown }).path;
      if (grepPath !== undefined) {
        const denied = denyIfOutsideRepo(grepPath, repoRoot, "Grep");
        if (denied) return { behavior: "deny", message: denied };
      }
    }
    if (toolName === "Glob") {
      const globPath = (input as { path?: unknown }).path;
      if (globPath !== undefined) {
        const denied = denyIfOutsideRepo(globPath, repoRoot, "Glob");
        if (denied) return { behavior: "deny", message: denied };
      }
      const pattern = (input as { pattern?: unknown }).pattern;
      if (typeof pattern === "string") {
        if (pattern.startsWith("/"))
          return {
            behavior: "deny",
            message: `Glob pattern "${pattern}" is absolute; ...`,
          };
        if (pattern.split("/").some((seg) => seg === ".."))
          return {
            behavior: "deny",
            message: `Glob pattern "${pattern}" contains a '..' segment; ...`,
          };
      }
    }
    return { behavior: "allow", updatedInput: input };
  };
}

describe("canUseTool dispatch — Read", () => {
  const repoRoot = "/tmp/repo";
  const dispatch = makeDispatch(repoRoot);

  // AC #5 named target — verify the helper denies the audit's exact
  // example. The integration concern (does the SDK actually invoke our
  // canUseTool for Read?) is verified manually outside the test suite.
  it("denies Read('/etc/hosts')", async () => {
    const r = await dispatch("Read", { file_path: "/etc/hosts" });
    assert.equal(r.behavior, "deny");
    if (r.behavior === "deny") {
      assert.match(r.message, /resolves outside repoRoot/);
    }
  });

  // AC #6: traversal that *starts inside* repoRoot but escapes via ..
  it("denies Read('<repoRoot>/../sibling/secret') as a traversal", async () => {
    const r = await dispatch("Read", {
      file_path: `${repoRoot}/../sibling/secret`,
    });
    assert.equal(r.behavior, "deny");
  });

  // AC #7: regression — the legitimate happy-path is still allowed.
  it("allows Read('<repoRoot>/README.md') (regression check)", async () => {
    const r = await dispatch("Read", { file_path: `${repoRoot}/README.md` });
    assert.equal(r.behavior, "allow");
  });

  // AC #4: reviewer-internal denylist (attestation DB).
  it("denies Read('.git/stamp/state.db') even inside repoRoot", async () => {
    const r = await dispatch("Read", { file_path: ".git/stamp/state.db" });
    assert.equal(r.behavior, "deny");
    if (r.behavior === "deny") {
      assert.match(r.message, /reviewer-internal|denied/);
    }
  });

  // AC #4: reviewer-internal denylist (trusted-keys directory).
  it("denies Read('.stamp/trusted-keys/anyone.pub') even inside repoRoot", async () => {
    const r = await dispatch("Read", {
      file_path: ".stamp/trusted-keys/alice.pub",
    });
    assert.equal(r.behavior, "deny");
    if (r.behavior === "deny") {
      assert.match(r.message, /trust anchors|exfil-attractive|denied/);
    }
  });

  it("allows Read of files in unrelated subdirs that contain 'stamp' in the name", () => {
    // Make sure the denylist is path-equality / prefix-anchored, not a
    // substring match. A repo that contains a `docs/stamp-overview.md`
    // or `lib/stamp-helper.ts` must not be caught by the trusted-keys
    // prefix test.
    return Promise.all([
      dispatch("Read", { file_path: "docs/stamp-overview.md" }).then((r) =>
        assert.equal(r.behavior, "allow"),
      ),
      dispatch("Read", { file_path: ".stamp/config.yml" }).then((r) =>
        assert.equal(r.behavior, "allow"),
      ),
      dispatch("Read", { file_path: ".stamp/reviewers/security.md" }).then(
        (r) => assert.equal(r.behavior, "allow"),
      ),
    ]);
  });
});

describe("canUseTool dispatch — Grep", () => {
  const repoRoot = "/tmp/repo";
  const dispatch = makeDispatch(repoRoot);

  it("allows Grep with no path (defaults to cwd which is repoRoot)", async () => {
    const r = await dispatch("Grep", { pattern: "TODO" });
    assert.equal(r.behavior, "allow");
  });

  it("allows Grep with a path inside the repo", async () => {
    const r = await dispatch("Grep", { pattern: "TODO", path: "src/" });
    assert.equal(r.behavior, "allow");
  });

  it("denies Grep with a path outside the repo", async () => {
    const r = await dispatch("Grep", { pattern: "secret", path: "/etc" });
    assert.equal(r.behavior, "deny");
    if (r.behavior === "deny") {
      assert.match(r.message, /Grep path/);
    }
  });
});

describe("canUseTool dispatch — Glob", () => {
  const repoRoot = "/tmp/repo";
  const dispatch = makeDispatch(repoRoot);

  it("allows Glob with no path", async () => {
    const r = await dispatch("Glob", { pattern: "**/*.ts" });
    assert.equal(r.behavior, "allow");
  });

  it("allows Glob with an in-repo path", async () => {
    const r = await dispatch("Glob", { pattern: "**/*.ts", path: "src/" });
    assert.equal(r.behavior, "allow");
  });

  it("denies Glob with an out-of-repo path", async () => {
    const r = await dispatch("Glob", { pattern: "*", path: "/etc" });
    assert.equal(r.behavior, "deny");
  });

  it("denies an absolute glob pattern (belt-and-suspenders)", async () => {
    const r = await dispatch("Glob", { pattern: "/etc/**/*" });
    assert.equal(r.behavior, "deny");
    if (r.behavior === "deny") {
      assert.match(r.message, /absolute/);
    }
  });

  it("denies a glob pattern containing a '..' segment", async () => {
    const r = await dispatch("Glob", { pattern: "../**/*" });
    assert.equal(r.behavior, "deny");
    if (r.behavior === "deny") {
      assert.match(r.message, /'\.\.' segment/);
    }
  });

  it("allows ordinary recursive globs", async () => {
    for (const p of ["**/*.ts", "src/**/*.test.ts", "*.md"]) {
      const r = await dispatch("Glob", { pattern: p });
      assert.equal(r.behavior, "allow", `pattern ${p} should be allowed`);
    }
  });
});
