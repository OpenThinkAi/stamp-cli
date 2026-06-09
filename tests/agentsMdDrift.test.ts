/**
 * Regression tests for AGT-473 — AGENTS.md drift detection + attested-pr mode.
 *
 * The sniffer + drift checker live in src/lib/agentsMd.ts (`sniffAgentsMdMode`,
 * `maybeWarnAgentsMdDrift`, `expectedAgentsMdModeFromShape`). These tests
 * pin the four state transitions called out in the ticket's AC #5 plus:
 *
 *   - opt-out env var suppresses the warning
 *   - the attested-pr body is what `--migrate-to-server-attested` writes
 *     (sniffable, distinct from server-gated and local-only)
 *   - the three sniff phrases are mutually exclusive (an invariant the
 *     sniffer's first-match-wins logic depends on)
 *
 * Convention: each test creates its own tmpdir via mkdtempSync and
 * cleans up in a finally — same shape as agentsMdEnsure.test.ts.
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import {
  DRIFT_WARNING_SUPPRESS_ENV,
  STAMP_AGENTS_SECTION_ATTESTED_PR,
  STAMP_AGENTS_SECTION_LOCAL_ONLY,
  STAMP_AGENTS_SECTION_SERVER_GATED,
  SNIFF_PHRASE_ATTESTED_PR,
  SNIFF_PHRASE_LOCAL_ONLY,
  SNIFF_PHRASE_SERVER_GATED,
  ensureAgentsMd,
  expectedAgentsMdModeFromShape,
  maybeWarnAgentsMdDrift,
  sniffAgentsMdMode,
} from "../src/lib/agentsMd.ts";

function tmpRepo(): { path: string; cleanup: () => void } {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-agents-md-drift-"));
  return { path: dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

/** Capture buffer stand-in for process.stderr; lets tests inspect warning
 *  text without polluting the real test runner output. */
function captureStderr(): { write: (s: string) => boolean; out: () => string } {
  const chunks: string[] = [];
  return {
    write: (s: string) => {
      chunks.push(s);
      return true;
    },
    out: () => chunks.join(""),
  };
}

// ---------- sniff phrase invariants ----------

describe("sniff phrase invariants", () => {
  it("the server-gated phrase appears ONLY in the server-gated body", () => {
    assert.ok(
      STAMP_AGENTS_SECTION_SERVER_GATED.includes(SNIFF_PHRASE_SERVER_GATED),
      "server-gated body contains its sniff phrase",
    );
    assert.equal(
      STAMP_AGENTS_SECTION_LOCAL_ONLY.includes(SNIFF_PHRASE_SERVER_GATED),
      false,
      "local-only body must NOT contain the server-gated sniff phrase",
    );
    assert.equal(
      STAMP_AGENTS_SECTION_ATTESTED_PR.includes(SNIFF_PHRASE_SERVER_GATED),
      false,
      "attested-pr body must NOT contain the server-gated sniff phrase",
    );
  });

  it("the local-only phrase appears ONLY in the local-only body", () => {
    assert.ok(
      STAMP_AGENTS_SECTION_LOCAL_ONLY.includes(SNIFF_PHRASE_LOCAL_ONLY),
      "local-only body contains its sniff phrase",
    );
    assert.equal(
      STAMP_AGENTS_SECTION_SERVER_GATED.includes(SNIFF_PHRASE_LOCAL_ONLY),
      false,
      "server-gated body must NOT contain the local-only sniff phrase",
    );
    assert.equal(
      STAMP_AGENTS_SECTION_ATTESTED_PR.includes(SNIFF_PHRASE_LOCAL_ONLY),
      false,
      "attested-pr body must NOT contain the local-only sniff phrase",
    );
  });

  it("the attested-pr phrase appears ONLY in the attested-pr body", () => {
    assert.ok(
      STAMP_AGENTS_SECTION_ATTESTED_PR.includes(SNIFF_PHRASE_ATTESTED_PR),
      "attested-pr body contains its sniff phrase",
    );
    assert.equal(
      STAMP_AGENTS_SECTION_SERVER_GATED.includes(SNIFF_PHRASE_ATTESTED_PR),
      false,
      "server-gated body must NOT contain the attested-pr sniff phrase",
    );
    assert.equal(
      STAMP_AGENTS_SECTION_LOCAL_ONLY.includes(SNIFF_PHRASE_ATTESTED_PR),
      false,
      "local-only body must NOT contain the attested-pr sniff phrase",
    );
  });
});

// ---------- sniffAgentsMdMode ----------

describe("sniffAgentsMdMode — reads the live mode from AGENTS.md", () => {
  it("returns 'server-gated' when AGENTS.md was written with server-gated body", () => {
    const r = tmpRepo();
    try {
      ensureAgentsMd(r.path, "server-gated");
      assert.equal(sniffAgentsMdMode(r.path), "server-gated");
    } finally {
      r.cleanup();
    }
  });

  it("returns 'local-only' when AGENTS.md was written with local-only body", () => {
    const r = tmpRepo();
    try {
      ensureAgentsMd(r.path, "local-only");
      assert.equal(sniffAgentsMdMode(r.path), "local-only");
    } finally {
      r.cleanup();
    }
  });

  it("returns 'attested-pr' when AGENTS.md was written with attested-pr body", () => {
    const r = tmpRepo();
    try {
      ensureAgentsMd(r.path, "attested-pr");
      assert.equal(sniffAgentsMdMode(r.path), "attested-pr");
    } finally {
      r.cleanup();
    }
  });

  it("returns 'absent' when AGENTS.md does not exist", () => {
    const r = tmpRepo();
    try {
      assert.equal(sniffAgentsMdMode(r.path), "absent");
    } finally {
      r.cleanup();
    }
  });

  it("returns 'absent' when AGENTS.md exists but has no managed block", () => {
    const r = tmpRepo();
    try {
      writeFileSync(
        path.join(r.path, "AGENTS.md"),
        "# AGENTS.md\n\nNo stamp block here — just user content.\n",
      );
      assert.equal(sniffAgentsMdMode(r.path), "absent");
    } finally {
      r.cleanup();
    }
  });

  it("returns 'unknown' when a managed block exists but no sniff phrase matches", () => {
    const r = tmpRepo();
    try {
      const customised =
        "# AGENTS.md\n\n" +
        "<!-- stamp:begin (managed by `stamp init` — do not edit between markers) -->\n\n" +
        "## fully custom body with no recognisable phrase\n\n" +
        "<!-- stamp:end -->\n";
      writeFileSync(path.join(r.path, "AGENTS.md"), customised);
      assert.equal(sniffAgentsMdMode(r.path), "unknown");
    } finally {
      r.cleanup();
    }
  });
});

// ---------- expectedAgentsMdModeFromShape ----------

describe("expectedAgentsMdModeFromShape — remote shape → expected mode", () => {
  it("stamp-server shape → server-gated expectation", () => {
    assert.equal(
      expectedAgentsMdModeFromShape("stamp-server", "server-gated"),
      "server-gated",
    );
  });

  it("forge-direct shape → local-only expectation by default", () => {
    assert.equal(
      expectedAgentsMdModeFromShape("forge-direct", "local-only"),
      "local-only",
    );
  });

  it("forge-direct shape + sniffed attested-pr → attested-pr expectation (no drift)", () => {
    // Shape 4 looks like forge-direct on the wire (GitHub mirror) but the
    // operator has migrated; we should NOT warn.
    assert.equal(
      expectedAgentsMdModeFromShape("forge-direct", "attested-pr"),
      "attested-pr",
    );
  });

  it("unknown shape → null (no opinion)", () => {
    assert.equal(
      expectedAgentsMdModeFromShape("unknown", "local-only"),
      null,
    );
  });

  it("unset shape → null (no opinion)", () => {
    assert.equal(
      expectedAgentsMdModeFromShape("unset", "local-only"),
      null,
    );
  });
});

// ---------- maybeWarnAgentsMdDrift — AC #5 state transitions ----------

describe("maybeWarnAgentsMdDrift — AC #5 (a) local-only AGENTS.md, stamp-server remote", () => {
  it("emits a warning when AGENTS.md says local-only but origin is a stamp server", () => {
    const r = tmpRepo();
    try {
      ensureAgentsMd(r.path, "local-only");
      const stderr = captureStderr();
      const warned = maybeWarnAgentsMdDrift({
        repoRoot: r.path,
        remoteShape: "stamp-server",
        command: "push",
        stderr,
        env: {},
      });
      assert.equal(warned, true, "drift detected → warned");
      const out = stderr.out();
      assert.match(out, /warning: AGENTS\.md says `local-only`/);
      assert.match(out, /expected `server-gated`/);
      assert.match(out, /stamp init --mode server-gated/);
      assert.match(out, /STAMP_SUPPRESS_AGENTS_MD_DRIFT_WARNING=1/);
    } finally {
      r.cleanup();
    }
  });
});

describe("maybeWarnAgentsMdDrift — AC #5 (b) local-only AGENTS.md, attested-pr drift", () => {
  it("does NOT emit a warning when AGENTS.md says local-only and origin is forge-direct (the matched case)", () => {
    // This is the default-matched case: the drift checker doesn't try to
    // upgrade a forge-direct repo to attested-pr unilaterally — Shape 4
    // is opt-in. So local-only + forge-direct is the no-warning happy path.
    const r = tmpRepo();
    try {
      ensureAgentsMd(r.path, "local-only");
      const stderr = captureStderr();
      const warned = maybeWarnAgentsMdDrift({
        repoRoot: r.path,
        remoteShape: "forge-direct",
        command: "push",
        stderr,
        env: {},
      });
      assert.equal(warned, false, "matched mode → silent");
      assert.equal(stderr.out(), "");
    } finally {
      r.cleanup();
    }
  });

  it("emits a warning when AGENTS.md says attested-pr but origin is a stamp server", () => {
    // The asymmetry case: an operator wrote --mode attested-pr but origin
    // is still pointed at a stamp server (server-gated would be honest).
    const r = tmpRepo();
    try {
      ensureAgentsMd(r.path, "attested-pr");
      const stderr = captureStderr();
      const warned = maybeWarnAgentsMdDrift({
        repoRoot: r.path,
        remoteShape: "stamp-server",
        command: "merge",
        stderr,
        env: {},
      });
      assert.equal(warned, true, "drift detected → warned");
      const out = stderr.out();
      assert.match(out, /AGENTS\.md says `attested-pr`/);
      assert.match(out, /expected `server-gated`/);
    } finally {
      r.cleanup();
    }
  });
});

describe("maybeWarnAgentsMdDrift — AC #5 (c) matched mode (no warning)", () => {
  it("server-gated AGENTS.md + stamp-server remote → no warning", () => {
    const r = tmpRepo();
    try {
      ensureAgentsMd(r.path, "server-gated");
      const stderr = captureStderr();
      const warned = maybeWarnAgentsMdDrift({
        repoRoot: r.path,
        remoteShape: "stamp-server",
        command: "push",
        stderr,
        env: {},
      });
      assert.equal(warned, false, "matched mode → silent");
      assert.equal(stderr.out(), "");
    } finally {
      r.cleanup();
    }
  });

  it("attested-pr AGENTS.md + forge-direct remote → no warning (Shape 4 looks like forge-direct on the wire)", () => {
    const r = tmpRepo();
    try {
      ensureAgentsMd(r.path, "attested-pr");
      const stderr = captureStderr();
      const warned = maybeWarnAgentsMdDrift({
        repoRoot: r.path,
        remoteShape: "forge-direct",
        command: "push",
        stderr,
        env: {},
      });
      assert.equal(warned, false, "matched mode → silent");
      assert.equal(stderr.out(), "");
    } finally {
      r.cleanup();
    }
  });
});

describe("maybeWarnAgentsMdDrift — AC #5 (d) AGENTS.md absent (no warning, not an error)", () => {
  it("returns false and emits nothing when AGENTS.md does not exist", () => {
    const r = tmpRepo();
    try {
      const stderr = captureStderr();
      const warned = maybeWarnAgentsMdDrift({
        repoRoot: r.path,
        remoteShape: "stamp-server",
        command: "push",
        stderr,
        env: {},
      });
      assert.equal(warned, false, "absent AGENTS.md → silent (not an error)");
      assert.equal(stderr.out(), "");
    } finally {
      r.cleanup();
    }
  });

  it("returns false and emits nothing when the AGENTS.md body is customised (unknown sniff)", () => {
    const r = tmpRepo();
    try {
      writeFileSync(
        path.join(r.path, "AGENTS.md"),
        "# AGENTS.md\n\n" +
          "<!-- stamp:begin (managed by `stamp init` — do not edit between markers) -->\n\n" +
          "## customised content; no recognisable phrase\n\n" +
          "<!-- stamp:end -->\n",
      );
      const stderr = captureStderr();
      const warned = maybeWarnAgentsMdDrift({
        repoRoot: r.path,
        remoteShape: "stamp-server",
        command: "push",
        stderr,
        env: {},
      });
      assert.equal(warned, false, "unknown sniff → silent (don't punish customised bodies)");
      assert.equal(stderr.out(), "");
    } finally {
      r.cleanup();
    }
  });

  it("returns false and emits nothing when the remote shape is unknown/unset", () => {
    const r = tmpRepo();
    try {
      ensureAgentsMd(r.path, "local-only");
      const stderr = captureStderr();
      const warned = maybeWarnAgentsMdDrift({
        repoRoot: r.path,
        remoteShape: "unknown",
        command: "push",
        stderr,
        env: {},
      });
      assert.equal(warned, false, "unknown shape → silent");
      assert.equal(stderr.out(), "");
    } finally {
      r.cleanup();
    }
  });
});

describe("maybeWarnAgentsMdDrift — AC #5 (e) opt-out env var", () => {
  it(`${DRIFT_WARNING_SUPPRESS_ENV}=1 suppresses the warning even when drift is real`, () => {
    const r = tmpRepo();
    try {
      ensureAgentsMd(r.path, "local-only");
      const stderr = captureStderr();
      const warned = maybeWarnAgentsMdDrift({
        repoRoot: r.path,
        remoteShape: "stamp-server",
        command: "push",
        stderr,
        env: { [DRIFT_WARNING_SUPPRESS_ENV]: "1" },
      });
      assert.equal(warned, false, "suppress env → silent");
      assert.equal(stderr.out(), "");
    } finally {
      r.cleanup();
    }
  });

  it(`${DRIFT_WARNING_SUPPRESS_ENV} set to something other than "1" does NOT suppress`, () => {
    const r = tmpRepo();
    try {
      ensureAgentsMd(r.path, "local-only");
      const stderr = captureStderr();
      const warned = maybeWarnAgentsMdDrift({
        repoRoot: r.path,
        remoteShape: "stamp-server",
        command: "push",
        stderr,
        env: { [DRIFT_WARNING_SUPPRESS_ENV]: "0" },
      });
      assert.equal(warned, true, "non-'1' value → warning still emitted");
      assert.match(stderr.out(), /warning: AGENTS\.md says `local-only`/);
    } finally {
      r.cleanup();
    }
  });
});

// ---------- AC #5 (f) attested-pr body is what --migrate-to-server-attested writes ----------

describe("attested-pr body is what `--migrate-to-server-attested` writes", () => {
  it("ensureAgentsMd with mode 'attested-pr' writes the Shape 4 body", () => {
    const r = tmpRepo();
    try {
      const action = ensureAgentsMd(r.path, "attested-pr");
      assert.equal(action, "created");
      const body = readFileSync(path.join(r.path, "AGENTS.md"), "utf8");

      assert.ok(
        body.includes(SNIFF_PHRASE_ATTESTED_PR),
        "Shape 4 sniff phrase present in the written body",
      );
      assert.match(
        body,
        /stamp-verify/,
        "attested-pr body references the stamp-verify PR check",
      );
      assert.match(
        body,
        /GitHub branch protection/,
        "attested-pr body names the branch-protection prerequisite",
      );
      // Negative invariants: the server-gated body's `stamp push` workflow
      // and the local-only body's "agent is the gate" framing must not
      // leak into the attested-pr body.
      assert.equal(
        body.includes(SNIFF_PHRASE_LOCAL_ONLY),
        false,
        "attested-pr body must not contain local-only framing",
      );
      assert.equal(
        body.includes(SNIFF_PHRASE_SERVER_GATED),
        false,
        "attested-pr body must not contain server-gated framing",
      );
    } finally {
      r.cleanup();
    }
  });

  it("ensureAgentsMd with mode 'attested-pr' refreshes a prior local-only body in place", () => {
    const r = tmpRepo();
    try {
      ensureAgentsMd(r.path, "local-only");
      assert.equal(sniffAgentsMdMode(r.path), "local-only");

      const action = ensureAgentsMd(r.path, "attested-pr");
      assert.equal(action, "replaced", "second call replaces the existing block in place");
      assert.equal(sniffAgentsMdMode(r.path), "attested-pr");
    } finally {
      r.cleanup();
    }
  });

  it("ensureAgentsMd with mode 'attested-pr' is idempotent on the second call", () => {
    const r = tmpRepo();
    try {
      const first = ensureAgentsMd(r.path, "attested-pr");
      assert.equal(first, "created");
      const second = ensureAgentsMd(r.path, "attested-pr");
      assert.equal(second, "unchanged");
    } finally {
      r.cleanup();
    }
  });
});
