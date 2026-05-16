/**
 * Phase-4 PR-check workflow drop tests. Pins the mode-aware default
 * (forge-direct + local-only get the workflow, server-gated doesn't),
 * the explicit-opt-out path (`prCheck: false`), the
 * explicit-force-write path (`prCheck: true` even for server-gated),
 * the idempotent re-init behavior (don't clobber existing files), and
 * the rendered template's load-bearing fields (action ref, job name,
 * permissions shape).
 */

import { strict as assert } from "node:assert";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
  mkdirSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import {
  maybeWriteVerifyWorkflow,
  renderVerifyWorkflow,
  VERIFY_ACTION_REF,
} from "../src/commands/init.ts";

function tmpRepo(): { path: string; cleanup: () => void } {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-init-pr-"));
  return { path: dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

const WORKFLOW_PATH = ".github/workflows/stamp-verify.yml";

describe("maybeWriteVerifyWorkflow — mode-aware default (prCheckOpt undefined)", () => {
  it("writes the workflow for forge-direct mode", () => {
    const r = tmpRepo();
    try {
      const result = maybeWriteVerifyWorkflow(r.path, undefined, "forge-direct");
      assert.equal(result.action, "wrote");
      assert.equal(result.path, WORKFLOW_PATH);
      assert.ok(existsSync(path.join(r.path, WORKFLOW_PATH)));
    } finally {
      r.cleanup();
    }
  });

  it("writes the workflow for local-only mode", () => {
    const r = tmpRepo();
    try {
      const result = maybeWriteVerifyWorkflow(r.path, undefined, "local-only");
      assert.equal(result.action, "wrote");
      assert.ok(existsSync(path.join(r.path, WORKFLOW_PATH)));
    } finally {
      r.cleanup();
    }
  });

  it("SKIPS for server-gated mode (server enforces at receive hook)", () => {
    const r = tmpRepo();
    try {
      const result = maybeWriteVerifyWorkflow(r.path, undefined, "server-gated");
      assert.equal(result.action, "skipped");
      assert.equal(existsSync(path.join(r.path, WORKFLOW_PATH)), false);
    } finally {
      r.cleanup();
    }
  });
});

describe("maybeWriteVerifyWorkflow — explicit prCheckOpt overrides", () => {
  it("prCheck: false skips even in forge-direct (operator opted out)", () => {
    const r = tmpRepo();
    try {
      const result = maybeWriteVerifyWorkflow(r.path, false, "forge-direct");
      assert.equal(result.action, "skipped");
      assert.equal(existsSync(path.join(r.path, WORKFLOW_PATH)), false);
    } finally {
      r.cleanup();
    }
  });

  it("prCheck: true writes even in server-gated (belt-and-suspenders)", () => {
    const r = tmpRepo();
    try {
      const result = maybeWriteVerifyWorkflow(r.path, true, "server-gated");
      assert.equal(result.action, "wrote");
      assert.ok(existsSync(path.join(r.path, WORKFLOW_PATH)));
    } finally {
      r.cleanup();
    }
  });
});

describe("maybeWriteVerifyWorkflow — idempotency", () => {
  it("returns 'exists' on a re-run without clobbering operator edits", () => {
    const r = tmpRepo();
    try {
      // First run writes.
      maybeWriteVerifyWorkflow(r.path, true, "forge-direct");
      const fullPath = path.join(r.path, WORKFLOW_PATH);

      // Operator customizes the file (adds a concurrency block, etc.).
      const customized =
        readFileSync(fullPath, "utf8") + "\n# operator added: concurrency\n";
      writeFileSync(fullPath, customized);

      // Second run.
      const result = maybeWriteVerifyWorkflow(r.path, true, "forge-direct");
      assert.equal(result.action, "exists");
      // File body unchanged.
      assert.equal(readFileSync(fullPath, "utf8"), customized);
    } finally {
      r.cleanup();
    }
  });

  it("creates the .github/workflows/ directory tree on first write", () => {
    const r = tmpRepo();
    try {
      // No .github/ exists yet.
      assert.equal(existsSync(path.join(r.path, ".github")), false);
      maybeWriteVerifyWorkflow(r.path, undefined, "forge-direct");
      // Both intermediate dirs and the file are created.
      assert.ok(existsSync(path.join(r.path, ".github", "workflows")));
      assert.ok(existsSync(path.join(r.path, WORKFLOW_PATH)));
    } finally {
      r.cleanup();
    }
  });

  it("respects pre-existing .github/workflows/ tree (no clobber)", () => {
    const r = tmpRepo();
    try {
      // Pre-create a sibling workflow + the dir tree.
      mkdirSync(path.join(r.path, ".github", "workflows"), { recursive: true });
      writeFileSync(
        path.join(r.path, ".github", "workflows", "ci.yml"),
        "name: ci\non: push\n",
      );
      maybeWriteVerifyWorkflow(r.path, undefined, "forge-direct");
      // Sibling workflow still there.
      assert.ok(existsSync(path.join(r.path, ".github", "workflows", "ci.yml")));
      // New stamp workflow added alongside.
      assert.ok(existsSync(path.join(r.path, WORKFLOW_PATH)));
    } finally {
      r.cleanup();
    }
  });
});

describe("renderVerifyWorkflow — pinned content", () => {
  const body = renderVerifyWorkflow();

  it("references the OpenThinkAi/stamp-cli action at the pinned VERIFY_ACTION_REF", () => {
    assert.match(
      body,
      new RegExp(
        `uses:\\s*OpenThinkAi/stamp-cli/\\.github/actions/verify-attestation@${VERIFY_ACTION_REF.replace(/\./g, "\\.")}`,
      ),
      `expected workflow to reference @${VERIFY_ACTION_REF}; body:\n${body}`,
    );
  });

  it("triggers on pull_request to main", () => {
    assert.match(body, /^on:\n\s+pull_request:\n\s+branches:\s*\[\s*main\s*\]/m);
  });

  it("declares minimum permissions (read contents, write checks only)", () => {
    assert.match(body, /permissions:/);
    assert.match(body, /contents:\s*read/);
    assert.match(body, /checks:\s*write/);
    // No `pull-requests`, no `actions`, no implicit org-default writes.
    assert.equal(body.includes("pull-requests:"), false);
  });

  it("names the job `stamp verify` so branch protection wires by that string", () => {
    assert.match(body, /name:\s*stamp verify/);
    // Critical for the operator's branch-protection setup hint that
    // says "add `stamp verify` (the workflow's job name) as required."
    // If this name drifts, the hint becomes a wild-goose chase.
  });

  it("uses fetch-depth: 0 so the action can resolve attestation refs", () => {
    assert.match(body, /fetch-depth:\s*0/);
  });

  it("does not interpolate VERIFY_ACTION_REF as literal `${...}` text (regression)", () => {
    // An earlier draft used a regular string literal where a template
    // literal was needed — `${VERIFY_ACTION_REF}` ended up in the
    // rendered output verbatim. Pin against re-introducing that.
    assert.equal(
      body.includes("${VERIFY_ACTION_REF}"),
      false,
      `rendered workflow has a literal \${VERIFY_ACTION_REF} placeholder — template-literal regression`,
    );
  });
});
