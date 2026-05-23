/**
 * Characterization tests for the filesystem-touching wrappers
 * `ensureAgentsMd()` and `ensureClaudeMd()` in src/lib/agentsMd.ts.
 *
 * Gap-fill for AGT-406 (coverage baseline before Shape 2/3 cleanup).
 * Existing tests in tests/validators.test.ts cover the pure-string
 * `injectStampSection()` / `injectClaudeSection()` helpers, but NOT
 * the wrappers that branch on `AgentsMdMode = "server-gated" | "local-only"`
 * and actually write to disk.
 *
 * The goal here is NOT to test "the right behavior" — it's to PIN DOWN
 * CURRENT BEHAVIOR. AGT-407 will collapse the `AgentsMdMode` enum during
 * Shape 3 deprecation; these tests will go red on the cases that need
 * a decision then, surfacing the per-mode differences to the removal
 * author rather than leaving them silently fungible.
 *
 * Convention: each test creates its own tmpdir via mkdtempSync and
 * cleans up in a finally — same shape as initVerifyWorkflow.test.ts.
 */

import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import {
  ensureAgentsMd,
  ensureClaudeMd,
  STAMP_BEGIN,
  STAMP_BEGIN_LEGACY,
  STAMP_CLAUDE_BEGIN_LEGACY,
  STAMP_CLAUDE_END_LEGACY,
  STAMP_END,
} from "../src/lib/agentsMd.ts";

function tmpRepo(): { path: string; cleanup: () => void } {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-agents-md-"));
  return { path: dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

// ---------- ensureAgentsMd ----------

describe("ensureAgentsMd — server-gated mode on empty repo", () => {
  it("returns 'created' and writes a fresh AGENTS.md with server-gated content", () => {
    const r = tmpRepo();
    try {
      const result = ensureAgentsMd(r.path, "server-gated");
      assert.equal(result, "created");

      const filePath = path.join(r.path, "AGENTS.md");
      assert.ok(existsSync(filePath), "AGENTS.md should exist after ensureAgentsMd");

      const body = readFileSync(filePath, "utf8");
      // Stamp markers are present.
      assert.ok(body.includes(STAMP_BEGIN), "STAMP_BEGIN marker present");
      assert.ok(body.includes(STAMP_END), "STAMP_END marker present");
      // Server-gated specific framing: the section talks about the
      // server-side pre-receive hook rejecting direct pushes.
      assert.match(
        body,
        /pre-receive hook/,
        "server-gated body references the pre-receive hook",
      );
      assert.match(
        body,
        /stamp push/,
        "server-gated body references `stamp push` (the server-aware push command)",
      );
      // Local-only-specific framing is absent.
      assert.equal(
        /The agent following these instructions is the gate/.test(body),
        false,
        "server-gated body should NOT contain the local-only 'agent is the gate' framing",
      );
    } finally {
      r.cleanup();
    }
  });
});

describe("ensureAgentsMd — local-only mode on empty repo", () => {
  it("returns 'created' and writes a fresh AGENTS.md with local-only content", () => {
    const r = tmpRepo();
    try {
      const result = ensureAgentsMd(r.path, "local-only");
      assert.equal(result, "created");

      const filePath = path.join(r.path, "AGENTS.md");
      assert.ok(existsSync(filePath), "AGENTS.md should exist after ensureAgentsMd");

      const body = readFileSync(filePath, "utf8");
      // Stamp markers are present.
      assert.ok(body.includes(STAMP_BEGIN), "STAMP_BEGIN marker present");
      assert.ok(body.includes(STAMP_END), "STAMP_END marker present");
      // Local-only specific framing: the agent is the gate; the remote
      // will accept any push.
      assert.match(
        body,
        /The agent following these instructions is the gate/,
        "local-only body identifies the agent as the gate",
      );
      assert.match(
        body,
        /advisory mode/,
        "local-only body labels itself as advisory mode",
      );
      // Server-gated-specific framing is absent. The literal phrase
      // "pre-receive hook" only appears in the server-gated body.
      assert.equal(
        /will be rejected by\s+the server-side pre-receive hook/.test(body),
        false,
        "local-only body should NOT promise server-side rejection",
      );
    } finally {
      r.cleanup();
    }
  });
});

describe("ensureAgentsMd — idempotency", () => {
  it("called twice on the same repo with the same mode is a no-op on the second call", () => {
    const r = tmpRepo();
    try {
      const first = ensureAgentsMd(r.path, "server-gated");
      assert.equal(first, "created");
      const afterFirst = readFileSync(path.join(r.path, "AGENTS.md"), "utf8");

      const second = ensureAgentsMd(r.path, "server-gated");
      assert.equal(second, "unchanged", "second call should report 'unchanged'");
      const afterSecond = readFileSync(path.join(r.path, "AGENTS.md"), "utf8");
      assert.equal(afterFirst, afterSecond, "file bytes are unchanged on second call");

      // Exactly one stamp:begin marker in the file.
      const beginCount = (afterSecond.match(/<!-- stamp:begin /g) ?? []).length;
      assert.equal(beginCount, 1, "exactly one stamp:begin marker (no duplicate)");
    } finally {
      r.cleanup();
    }
  });

  it("idempotent for local-only mode as well", () => {
    const r = tmpRepo();
    try {
      ensureAgentsMd(r.path, "local-only");
      const second = ensureAgentsMd(r.path, "local-only");
      assert.equal(second, "unchanged");
    } finally {
      r.cleanup();
    }
  });
});

describe("ensureAgentsMd — re-injection over a legacy stamp block", () => {
  it("returns 'replaced' and replaces the legacy block in place (no append)", () => {
    const r = tmpRepo();
    try {
      const filePath = path.join(r.path, "AGENTS.md");
      // Pre-seed AGENTS.md with the legacy "stamp-cli" wording inside the
      // begin marker. ensureAgentsMd should detect via prefix match and
      // replace in place.
      const legacy =
        "# AGENTS.md\n\n" +
        `${STAMP_BEGIN_LEGACY}\n\n## old stamp content\n\n${STAMP_END}\n`;
      writeFileSync(filePath, legacy);

      const result = ensureAgentsMd(r.path, "server-gated");
      assert.equal(result, "replaced");

      const out = readFileSync(filePath, "utf8");
      // New wording present, legacy gone.
      assert.ok(out.includes(STAMP_BEGIN), "new stamp:begin wording present");
      assert.equal(
        out.includes(STAMP_BEGIN_LEGACY),
        false,
        "legacy stamp:begin wording gone after migration",
      );
      // Exactly one stamp:begin marker — no duplicate block.
      const beginCount = (out.match(/<!-- stamp:begin /g) ?? []).length;
      assert.equal(beginCount, 1, "exactly one begin marker (no duplicate block)");
    } finally {
      r.cleanup();
    }
  });

  it("returns 'appended' when AGENTS.md exists without any stamp markers", () => {
    const r = tmpRepo();
    try {
      const filePath = path.join(r.path, "AGENTS.md");
      writeFileSync(filePath, "# my project\n\nSome content.\n");

      const result = ensureAgentsMd(r.path, "server-gated");
      assert.equal(result, "appended");

      const out = readFileSync(filePath, "utf8");
      assert.match(out, /Some content/, "pre-existing content preserved");
      assert.ok(out.includes(STAMP_BEGIN), "stamp block appended");
    } finally {
      r.cleanup();
    }
  });
});

describe("ensureAgentsMd — preserves user content outside the markers", () => {
  it("user content above and below the stamp block survives a re-inject verbatim", () => {
    const r = tmpRepo();
    try {
      const filePath = path.join(r.path, "AGENTS.md");
      const userAbove = "# user-managed content\nthis is mine\n";
      const userBelow = "trailing user content\n";
      const existing =
        `${userAbove}\n` +
        `${STAMP_BEGIN}\n\n## old stamp content\n\n${STAMP_END}\n` +
        userBelow;
      writeFileSync(filePath, existing);

      const result = ensureAgentsMd(r.path, "server-gated");
      assert.equal(result, "replaced");

      const out = readFileSync(filePath, "utf8");
      assert.match(out, /this is mine/, "pre-stamp user content preserved");
      assert.match(out, /trailing user content/, "post-stamp user content preserved");
    } finally {
      r.cleanup();
    }
  });
});

// ---------- ensureClaudeMd (parallel coverage) ----------
//
// ensureClaudeMd mirrors ensureAgentsMd's shape closely enough to warrant
// a parallel describe block: same create/replace/append/unchanged return
// shape, same idempotency contract, same legacy-marker migration path. The
// notable differences are that there is no mode parameter (CLAUDE.md
// guidance is mode-agnostic) and CLAUDE.md uses a distinct legacy marker
// pair (STAMP_CLAUDE_BEGIN_LEGACY / STAMP_CLAUDE_END_LEGACY) on top of the
// unified one.

describe("ensureClaudeMd — empty repo", () => {
  it("returns 'created' and writes a fresh CLAUDE.md with unified markers", () => {
    const r = tmpRepo();
    try {
      const result = ensureClaudeMd(r.path);
      assert.equal(result, "created");

      const filePath = path.join(r.path, "CLAUDE.md");
      assert.ok(existsSync(filePath), "CLAUDE.md should exist after ensureClaudeMd");

      const body = readFileSync(filePath, "utf8");
      assert.ok(body.includes(STAMP_BEGIN), "unified STAMP_BEGIN marker present");
      assert.ok(body.includes(STAMP_END), "unified STAMP_END marker present");
      // Fresh-write must not contain the CLAUDE.md-specific legacy marker.
      assert.equal(
        body.includes(STAMP_CLAUDE_BEGIN_LEGACY),
        false,
        "fresh CLAUDE.md should not contain the legacy stamp:claude:begin marker",
      );
      // CLAUDE.md content references AGENTS.md as the full reference.
      assert.match(
        body,
        /AGENTS\.md/,
        "CLAUDE.md body should point readers at AGENTS.md",
      );
    } finally {
      r.cleanup();
    }
  });
});

describe("ensureClaudeMd — idempotency", () => {
  it("called twice in a row is a no-op on the second call", () => {
    const r = tmpRepo();
    try {
      const first = ensureClaudeMd(r.path);
      assert.equal(first, "created");
      const afterFirst = readFileSync(path.join(r.path, "CLAUDE.md"), "utf8");

      const second = ensureClaudeMd(r.path);
      assert.equal(second, "unchanged");
      const afterSecond = readFileSync(path.join(r.path, "CLAUDE.md"), "utf8");
      assert.equal(afterFirst, afterSecond);
    } finally {
      r.cleanup();
    }
  });
});

describe("ensureClaudeMd — legacy-marker migration", () => {
  it("returns 'replaced' and migrates a legacy stamp:claude:begin block to unified markers", () => {
    const r = tmpRepo();
    try {
      const filePath = path.join(r.path, "CLAUDE.md");
      const legacy =
        "# CLAUDE.md\n\n" +
        `${STAMP_CLAUDE_BEGIN_LEGACY}\n\n## old stamp content\n\n${STAMP_CLAUDE_END_LEGACY}\n`;
      writeFileSync(filePath, legacy);

      const result = ensureClaudeMd(r.path);
      assert.equal(result, "replaced");

      const out = readFileSync(filePath, "utf8");
      assert.ok(out.includes(STAMP_BEGIN), "unified begin marker present after migration");
      assert.equal(
        out.includes(STAMP_CLAUDE_BEGIN_LEGACY),
        false,
        "legacy stamp:claude:begin marker gone after migration",
      );
    } finally {
      r.cleanup();
    }
  });

  it("returns 'appended' when CLAUDE.md exists without any stamp markers", () => {
    const r = tmpRepo();
    try {
      const filePath = path.join(r.path, "CLAUDE.md");
      writeFileSync(filePath, "# project claude notes\n\npre-existing.\n");

      const result = ensureClaudeMd(r.path);
      assert.equal(result, "appended");

      const out = readFileSync(filePath, "utf8");
      assert.match(out, /pre-existing/, "pre-existing content preserved");
      assert.ok(out.includes(STAMP_BEGIN), "stamp block appended");
    } finally {
      r.cleanup();
    }
  });
});

describe("ensureClaudeMd — preserves user content outside the markers", () => {
  it("user content above and below the stamp block survives a re-inject verbatim", () => {
    const r = tmpRepo();
    try {
      const filePath = path.join(r.path, "CLAUDE.md");
      const userAbove = "# user-managed CLAUDE.md\nmy own notes\n";
      const userBelow = "trailing claude content\n";
      const existing =
        `${userAbove}\n` +
        `${STAMP_BEGIN}\n\n## old stamp content\n\n${STAMP_END}\n` +
        userBelow;
      writeFileSync(filePath, existing);

      const result = ensureClaudeMd(r.path);
      assert.equal(result, "replaced");

      const out = readFileSync(filePath, "utf8");
      assert.match(out, /my own notes/, "pre-stamp user content preserved");
      assert.match(out, /trailing claude content/, "post-stamp user content preserved");
    } finally {
      r.cleanup();
    }
  });
});
