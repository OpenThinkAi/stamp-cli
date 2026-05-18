/**
 * Phase-2 PR-mode (Shape 2) auto-mirror workflow scaffold tests.
 *
 * Pins:
 *   - opt-in (no --pr-mode means no file)
 *   - placeholder rendering when review_server / origin aren't configured
 *   - substituted rendering when they are
 *   - idempotent re-run (don't clobber operator edits)
 *   - --pr-mode-force overwrites
 *   - load-bearing fields of the rendered template (trigger, permissions,
 *     STAMP_MIRROR_KEY env var, `git push --mirror` invocation)
 */

import { strict as assert } from "node:assert";
import { execSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import {
  derivePrModeSubstitution,
  maybeWritePrModeMirrorWorkflow,
  PR_MODE_WORKFLOW_PATH,
  renderMirrorWorkflow,
} from "../src/commands/init.ts";

function tmpRepo(): { path: string; cleanup: () => void } {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-init-prmode-"));
  // The substitution helper shells out to `git remote get-url origin`, so
  // the fixture has to look like a git repo. Init quietly + set an
  // origin URL the parser can recognize.
  execSync("git init -q -b main", { cwd: dir });
  return { path: dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function setOrigin(repo: string, url: string): void {
  // Use `git remote add` first run, fall back to `set-url`. Tests may
  // call this twice on the same fixture.
  try {
    execSync(`git remote add origin ${JSON.stringify(url)}`, { cwd: repo });
  } catch {
    execSync(`git remote set-url origin ${JSON.stringify(url)}`, { cwd: repo });
  }
}

function writeStampConfig(repo: string, body: string): void {
  mkdirSync(path.join(repo, ".stamp"), { recursive: true });
  writeFileSync(path.join(repo, ".stamp", "config.yml"), body);
}

const MIN_CONFIG_WITH_SERVER = `branches:
  main:
    required: [example]
    review_server: ssh://git@stamp.example.com:2222
reviewers:
  example:
    prompt: example.md
`;

const MIN_CONFIG_WITHOUT_SERVER = `branches:
  main:
    required: [example]
reviewers:
  example:
    prompt: example.md
`;

describe("derivePrModeSubstitution — happy path", () => {
  it("returns host/port/org/repo when both .stamp/config.yml and origin are configured", () => {
    const r = tmpRepo();
    try {
      writeStampConfig(r.path, MIN_CONFIG_WITH_SERVER);
      setOrigin(r.path, "git@github.com:acme/widgets.git");
      const sub = derivePrModeSubstitution(r.path);
      assert.deepEqual(sub, {
        host: "stamp.example.com",
        port: 2222,
        org: "acme",
        repo: "widgets",
      });
    } finally {
      r.cleanup();
    }
  });

  it("parses https-style origin URLs too", () => {
    const r = tmpRepo();
    try {
      writeStampConfig(r.path, MIN_CONFIG_WITH_SERVER);
      setOrigin(r.path, "https://github.com/acme/widgets.git");
      const sub = derivePrModeSubstitution(r.path);
      assert.ok(sub);
      assert.equal(sub!.org, "acme");
      assert.equal(sub!.repo, "widgets");
    } finally {
      r.cleanup();
    }
  });
});

describe("derivePrModeSubstitution — fallback to null", () => {
  it("returns null when .stamp/config.yml has no review_server", () => {
    const r = tmpRepo();
    try {
      writeStampConfig(r.path, MIN_CONFIG_WITHOUT_SERVER);
      setOrigin(r.path, "git@github.com:acme/widgets.git");
      assert.equal(derivePrModeSubstitution(r.path), null);
    } finally {
      r.cleanup();
    }
  });

  it("returns null when origin is not configured", () => {
    const r = tmpRepo();
    try {
      writeStampConfig(r.path, MIN_CONFIG_WITH_SERVER);
      assert.equal(derivePrModeSubstitution(r.path), null);
    } finally {
      r.cleanup();
    }
  });

  it("returns null when .stamp/config.yml is absent entirely", () => {
    const r = tmpRepo();
    try {
      setOrigin(r.path, "git@github.com:acme/widgets.git");
      assert.equal(derivePrModeSubstitution(r.path), null);
    } finally {
      r.cleanup();
    }
  });

  it("returns null when origin URL has no parseable org/repo shape", () => {
    const r = tmpRepo();
    try {
      writeStampConfig(r.path, MIN_CONFIG_WITH_SERVER);
      // Single path segment — parser requires at least two.
      setOrigin(r.path, "https://example.com/single-segment");
      assert.equal(derivePrModeSubstitution(r.path), null);
    } finally {
      r.cleanup();
    }
  });
});

describe("maybeWritePrModeMirrorWorkflow — file output", () => {
  it("writes the workflow on a fresh run", () => {
    const r = tmpRepo();
    try {
      writeStampConfig(r.path, MIN_CONFIG_WITH_SERVER);
      setOrigin(r.path, "git@github.com:acme/widgets.git");
      const result = maybeWritePrModeMirrorWorkflow(r.path);
      assert.equal(result.action, "wrote");
      assert.equal(result.path, PR_MODE_WORKFLOW_PATH);
      assert.ok(existsSync(path.join(r.path, PR_MODE_WORKFLOW_PATH)));
      assert.deepEqual(result.substitution, {
        host: "stamp.example.com",
        port: 2222,
        org: "acme",
        repo: "widgets",
      });
    } finally {
      r.cleanup();
    }
  });

  it("creates the .github/workflows/ tree on first write", () => {
    const r = tmpRepo();
    try {
      writeStampConfig(r.path, MIN_CONFIG_WITH_SERVER);
      setOrigin(r.path, "git@github.com:acme/widgets.git");
      assert.equal(existsSync(path.join(r.path, ".github")), false);
      maybeWritePrModeMirrorWorkflow(r.path);
      assert.ok(existsSync(path.join(r.path, ".github", "workflows")));
      assert.ok(existsSync(path.join(r.path, PR_MODE_WORKFLOW_PATH)));
    } finally {
      r.cleanup();
    }
  });

  it("writes a placeholder template when review_server / origin can't be derived", () => {
    const r = tmpRepo();
    try {
      // No .stamp/config.yml, no origin — both substitution sources empty.
      const result = maybeWritePrModeMirrorWorkflow(r.path);
      assert.equal(result.action, "wrote");
      assert.equal(result.substitution, null);
      const body = readFileSync(
        path.join(r.path, PR_MODE_WORKFLOW_PATH),
        "utf8",
      );
      // Placeholder markers are exactly the strings the design doc names.
      assert.ok(body.includes("<STAMP_SERVER_HOST>"));
      assert.ok(body.includes("<STAMP_SERVER_PORT>"));
      assert.ok(body.includes("<REPO_ORG>"));
      assert.ok(body.includes("<REPO_NAME>"));
    } finally {
      r.cleanup();
    }
  });

  it("substitutes host/port/org/repo when both sources are configured", () => {
    const r = tmpRepo();
    try {
      writeStampConfig(r.path, MIN_CONFIG_WITH_SERVER);
      setOrigin(r.path, "git@github.com:acme/widgets.git");
      maybeWritePrModeMirrorWorkflow(r.path);
      const body = readFileSync(
        path.join(r.path, PR_MODE_WORKFLOW_PATH),
        "utf8",
      );
      // No literal placeholder markers leak through into the rendered body.
      assert.equal(body.includes("<STAMP_SERVER_HOST>"), false);
      assert.equal(body.includes("<STAMP_SERVER_PORT>"), false);
      assert.equal(body.includes("<REPO_ORG>"), false);
      assert.equal(body.includes("<REPO_NAME>"), false);
      // Values appear as quoted YAML env entries (not as bare shell
      // command tokens — security feedback round 1 motivated the
      // env-var indirection).
      assert.match(body, /STAMP_SERVER_HOST:\s*"stamp\.example\.com"/);
      assert.match(body, /STAMP_SERVER_PORT:\s*"2222"/);
      assert.match(body, /STAMP_REPO_ORG:\s*"acme"/);
      assert.match(body, /STAMP_REPO_NAME:\s*"widgets"/);
    } finally {
      r.cleanup();
    }
  });
});

describe("maybeWritePrModeMirrorWorkflow — idempotency", () => {
  it("returns 'exists' on re-run without clobbering operator edits", () => {
    const r = tmpRepo();
    try {
      writeStampConfig(r.path, MIN_CONFIG_WITH_SERVER);
      setOrigin(r.path, "git@github.com:acme/widgets.git");

      maybeWritePrModeMirrorWorkflow(r.path);
      const fullPath = path.join(r.path, PR_MODE_WORKFLOW_PATH);

      // Operator customizes (adds concurrency block, fork-PR conditions, etc.)
      const customized =
        readFileSync(fullPath, "utf8") + "\n# operator addition: concurrency\n";
      writeFileSync(fullPath, customized);

      const result = maybeWritePrModeMirrorWorkflow(r.path);
      assert.equal(result.action, "exists");
      assert.equal(readFileSync(fullPath, "utf8"), customized);
    } finally {
      r.cleanup();
    }
  });

  it("force: true overwrites an existing file", () => {
    const r = tmpRepo();
    try {
      writeStampConfig(r.path, MIN_CONFIG_WITH_SERVER);
      setOrigin(r.path, "git@github.com:acme/widgets.git");

      // First run with no config yet — substitution null, placeholders in file.
      writeStampConfig(r.path, MIN_CONFIG_WITHOUT_SERVER);
      maybeWritePrModeMirrorWorkflow(r.path);
      const fullPath = path.join(r.path, PR_MODE_WORKFLOW_PATH);
      const beforeBody = readFileSync(fullPath, "utf8");
      assert.ok(beforeBody.includes("<STAMP_SERVER_HOST>"));

      // Now add review_server + re-run with --force to fill in placeholders.
      writeStampConfig(r.path, MIN_CONFIG_WITH_SERVER);
      const result = maybeWritePrModeMirrorWorkflow(r.path, { force: true });
      assert.equal(result.action, "wrote");
      assert.deepEqual(result.substitution, {
        host: "stamp.example.com",
        port: 2222,
        org: "acme",
        repo: "widgets",
      });
      const afterBody = readFileSync(fullPath, "utf8");
      assert.equal(afterBody.includes("<STAMP_SERVER_HOST>"), false);
      assert.match(afterBody, /stamp\.example\.com/);
    } finally {
      r.cleanup();
    }
  });

  it("respects pre-existing .github/workflows/ tree (no clobber of siblings)", () => {
    const r = tmpRepo();
    try {
      writeStampConfig(r.path, MIN_CONFIG_WITH_SERVER);
      setOrigin(r.path, "git@github.com:acme/widgets.git");
      mkdirSync(path.join(r.path, ".github", "workflows"), { recursive: true });
      writeFileSync(
        path.join(r.path, ".github", "workflows", "ci.yml"),
        "name: ci\non: push\n",
      );
      maybeWritePrModeMirrorWorkflow(r.path);
      assert.ok(existsSync(path.join(r.path, ".github", "workflows", "ci.yml")));
      assert.ok(existsSync(path.join(r.path, PR_MODE_WORKFLOW_PATH)));
    } finally {
      r.cleanup();
    }
  });
});

describe("renderMirrorWorkflow — pinned content", () => {
  it("triggers on push to all branches + tags (mirror needs full ref set)", () => {
    const body = renderMirrorWorkflow(null);
    assert.match(body, /^on:\n\s+push:\n\s+branches:\s*\[\s*'\*\*'\s*\]/m);
    assert.match(body, /tags:\s*\[\s*'\*\*'\s*\]/);
  });

  it("declares minimum permissions (contents: read only)", () => {
    const body = renderMirrorWorkflow(null);
    assert.match(body, /permissions:/);
    assert.match(body, /contents:\s*read/);
    // No write scopes — the mirror pushes over SSH using STAMP_MIRROR_KEY,
    // not back to github via GITHUB_TOKEN.
    assert.equal(body.includes("contents: write"), false);
    assert.equal(body.includes("pull-requests:"), false);
    assert.equal(body.includes("checks:"), false);
  });

  it("injects STAMP_MIRROR_KEY from secrets, not a hard-coded value", () => {
    const body = renderMirrorWorkflow(null);
    assert.match(body, /STAMP_MIRROR_KEY:\s*\$\{\{\s*secrets\.STAMP_MIRROR_KEY\s*\}\}/);
  });

  it("guards against an empty STAMP_MIRROR_KEY with a clear error", () => {
    const body = renderMirrorWorkflow(null);
    // The guard prevents the mirror from silently no-op'ing when the org
    // secret wasn't registered. Pin both the existence check AND the
    // pointer to the setup URL.
    assert.match(body, /if \[ -z "\$\{STAMP_MIRROR_KEY:-\}" \]/);
    assert.match(body, /organizations\/<your-org>\/settings\/secrets\/actions\/new/);
  });

  it("uses `git push --mirror` so every ref the server needs ships in one call", () => {
    const body = renderMirrorWorkflow(null);
    assert.match(body, /git push --mirror stamp-server/);
  });

  it("uses fetch-depth: 0 so the server can resolve base..head diffs", () => {
    const body = renderMirrorWorkflow(null);
    assert.match(body, /fetch-depth:\s*0/);
  });

  it("uses IdentitiesOnly=yes to pin the injected SSH key", () => {
    const body = renderMirrorWorkflow(null);
    // Defends against the action-runner's environment containing an
    // unrelated agent-forwarded key that would silently take precedence.
    assert.match(body, /IdentitiesOnly=yes/);
  });

  it("pins host key via ssh-keyscan referencing env vars (defense-in-depth)", () => {
    const body = renderMirrorWorkflow({
      host: "stamp.example.com",
      port: 2222,
      org: "acme",
      repo: "widgets",
    });
    // The shell should reference $STAMP_SERVER_PORT / $STAMP_SERVER_HOST
    // rather than embedding the values as command tokens — that way a
    // future parser-regression that lets a metacharacter through still
    // can't reach the shell as a syntactically-active token.
    assert.match(
      body,
      /ssh-keyscan -p "\$STAMP_SERVER_PORT" "\$STAMP_SERVER_HOST"/,
    );
    // And the values themselves still appear in the file, as YAML env: entries.
    assert.match(body, /STAMP_SERVER_HOST:\s*"stamp\.example\.com"/);
    assert.match(body, /STAMP_SERVER_PORT:\s*"2222"/);
    assert.match(body, /STAMP_REPO_ORG:\s*"acme"/);
    assert.match(body, /STAMP_REPO_NAME:\s*"widgets"/);
  });

  it("constructs the stamp-server SSH URL through env-var expansion, not direct interpolation", () => {
    const body = renderMirrorWorkflow({
      host: "stamp.example.com",
      port: 2222,
      org: "acme",
      repo: "widgets",
    });
    // The `git remote add stamp-server ...` line must use $VAR
    // expansions inside a double-quoted argument so the values stay
    // quoted at shell-token level. Embedding the literal host as a
    // bare token would be the regression security flagged in round 1.
    assert.match(
      body,
      /git remote add stamp-server\s*\\\n\s*"ssh:\/\/git@\$\{STAMP_SERVER_HOST\}:\$\{STAMP_SERVER_PORT\}\/srv\/git\/\$\{STAMP_REPO_ORG\}\/\$\{STAMP_REPO_NAME\}\.git"/,
    );
    // Defense-in-depth: bare-token interpolation of the four values
    // must NOT appear anywhere in the rendered shell. (Match without
    // quoting; a substring miss here would be the regression.)
    assert.equal(body.includes(" stamp.example.com "), false);
    assert.equal(body.includes("/srv/git/acme/widgets.git"), false);
  });

  it("does not interpolate raw `${sub}` placeholders into rendered text (regression)", () => {
    // Mirror of the renderVerifyWorkflow regression check: catch a draft
    // that used a string literal where a template literal was needed.
    // Use a sentinel that no test value contains so a match means the
    // template literal was malformed, not that the value coincidentally
    // contained the placeholder name.
    const body = renderMirrorWorkflow({
      host: "stamp.example.com",
      port: 2222,
      org: "acme",
      repo: "widgets",
    });
    // Variables named literally `host` / `port` / `org` / `repo` only
    // appear as TypeScript-source identifiers in this file, never in
    // the rendered output. The rendered output uses the namespaced
    // shell vars (`STAMP_SERVER_HOST`, ...) instead. A `${host}` leak
    // would indicate a string-literal-vs-template-literal regression.
    assert.equal(body.includes("${host}"), false);
    assert.equal(body.includes("${port}"), false);
    // `${org}` and `${repo}` are too generic to test in isolation
    // because legitimate substrings of the namespaced vars
    // (`STAMP_REPO_ORG`, `STAMP_REPO_NAME`) include "ORG" / "REPO".
    // The two assertions above carry the regression-coverage load.
  });
});
