/**
 * Tests for the per-user reviewer-model config (~/.stamp/config.yml).
 *
 * Covers the full surface that downstream code relies on:
 *   - parseUserConfig accept/reject shapes (this is the trust boundary
 *     between operator hand-edits and the resolver)
 *   - stringifyUserConfig round-trip pin (the on-disk YAML body shouldn't
 *     drift between releases — operators copy this around for sharing)
 *   - loadOrCreateUserConfig writes defaults exactly once (idempotence is
 *     load-bearing for the upgrade-notice flow in runReview)
 *   - resolveReviewerModel returns the configured model OR null (null is
 *     the "fall back to SDK default" sentinel)
 *   - the CLI handlers (set/clear/show) round-trip correctly
 *
 * Each test redirects HOME into a tmpdir so writes never touch the real
 * ~/.stamp/. The redirect is per-test (beforeEach/afterEach) so a
 * crashing test can't poison the next one.
 */

import { strict as assert } from "node:assert";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import {
  DEFAULT_REVIEWER_MODELS,
  deleteUserConfig,
  isValidModelId,
  isValidReviewerName,
  loadOrCreateUserConfig,
  loadUserConfig,
  parseUserConfig,
  resolveReviewerModel,
  stringifyUserConfig,
  writeUserConfig,
} from "../src/lib/userConfig.ts";
import {
  runConfigReviewersClear,
  runConfigReviewersSet,
  runConfigReviewersShow,
} from "../src/commands/config.ts";
import { userConfigPath } from "../src/lib/paths.ts";

let tmpHome: string;
let savedHome: string | undefined;

beforeEach(() => {
  tmpHome = mkdtempSync(join(tmpdir(), "stamp-userconfig-"));
  savedHome = process.env.HOME;
  process.env.HOME = tmpHome;
});

afterEach(() => {
  if (savedHome === undefined) delete process.env.HOME;
  else process.env.HOME = savedHome;
  rmSync(tmpHome, { recursive: true, force: true });
});

describe("parseUserConfig", () => {
  it("accepts an empty file as zero overrides", () => {
    const cfg = parseUserConfig("");
    assert.deepEqual(cfg.reviewers, {});
  });

  it("accepts an explicit reviewers mapping", () => {
    const cfg = parseUserConfig(
      "reviewers:\n  security: claude-opus-4-7\n  standards: claude-sonnet-4-6\n",
    );
    assert.equal(cfg.reviewers.security, "claude-opus-4-7");
    assert.equal(cfg.reviewers.standards, "claude-sonnet-4-6");
  });

  it("trims whitespace around model ids", () => {
    const cfg = parseUserConfig(
      "reviewers:\n  security: '  claude-opus-4-7  '\n",
    );
    assert.equal(cfg.reviewers.security, "claude-opus-4-7");
  });

  it("treats `reviewers: {}` as zero overrides", () => {
    const cfg = parseUserConfig("reviewers: {}\n");
    assert.deepEqual(cfg.reviewers, {});
  });

  it("rejects a non-mapping top-level YAML", () => {
    assert.throws(() => parseUserConfig("- a\n- b\n"), /mapping/);
  });

  it("rejects 'reviewers' as a list", () => {
    assert.throws(
      () => parseUserConfig("reviewers:\n  - security\n"),
      /reviewers.*mapping/,
    );
  });

  it("rejects an invalid reviewer name", () => {
    assert.throws(
      () => parseUserConfig("reviewers:\n  -bad: claude-sonnet-4-6\n"),
      /reviewer name/,
    );
  });

  it("rejects an empty model id", () => {
    assert.throws(
      () => parseUserConfig("reviewers:\n  security: ''\n"),
      /non-empty/,
    );
  });

  it("rejects a model id with embedded whitespace", () => {
    assert.throws(
      () =>
        parseUserConfig(
          "reviewers:\n  security: 'claude sonnet 4 6'\n",
        ),
      /not a valid model id/,
    );
  });

  it("rejects a non-string model id", () => {
    assert.throws(
      () => parseUserConfig("reviewers:\n  security: 42\n"),
      /non-empty string/,
    );
  });
});

describe("stringifyUserConfig + parseUserConfig round-trip", () => {
  it("preserves the operator's reviewers map", () => {
    const original = {
      reviewers: {
        security: "claude-opus-4-7",
        standards: "claude-sonnet-4-6",
        product: "claude-haiku-4-5",
      },
    };
    const yaml = stringifyUserConfig(original);
    const reparsed = parseUserConfig(yaml);
    assert.deepEqual(reparsed.reviewers, original.reviewers);
  });

  it("renders an empty config as `reviewers: {}` (still parseable)", () => {
    const yaml = stringifyUserConfig({ reviewers: {} });
    const reparsed = parseUserConfig(yaml);
    assert.deepEqual(reparsed.reviewers, {});
  });
});

describe("writeUserConfig file mode + perms", () => {
  it("writes the file at 0o600 under a ~/.stamp dir", () => {
    const path = writeUserConfig({ reviewers: { security: "claude-sonnet-4-6" } });
    assert.equal(path, userConfigPath());
    assert.equal(existsSync(path), true);
    // mode masking: stat returns the full mode bits including file-type;
    // mask to the perm bits we set.
    const mode = statSync(path).mode & 0o777;
    assert.equal(mode, 0o600, `expected 0o600, got 0o${mode.toString(8)}`);
  });
});

describe("loadOrCreateUserConfig", () => {
  it("creates the file with defaults on first call", () => {
    const result = loadOrCreateUserConfig();
    assert.equal(result.created, true);
    assert.equal(existsSync(result.path), true);
    // Defaults match what the project README documents.
    assert.equal(result.config.reviewers.security, "claude-sonnet-4-6");
    assert.equal(result.config.reviewers.standards, "claude-sonnet-4-6");
    assert.equal(result.config.reviewers.product, "claude-sonnet-4-6");
  });

  it("is idempotent on second call (no overwrite, created=false)", () => {
    const first = loadOrCreateUserConfig();
    const firstBytes = readFileSync(first.path, "utf8");
    // Tamper with the file to prove second call doesn't overwrite — operator
    // customisation must survive any subsequent load.
    writeUserConfig({ reviewers: { security: "claude-opus-4-7" } });
    const second = loadOrCreateUserConfig();
    assert.equal(second.created, false);
    assert.equal(second.config.reviewers.security, "claude-opus-4-7");
    assert.notEqual(readFileSync(second.path, "utf8"), firstBytes);
  });

  it("treats an empty existing file as 'no overrides' (created=false)", () => {
    // Pre-create the file empty — operator may have started a config and
    // not yet added any reviewers. Should NOT re-fill with defaults; that
    // would silently undo their delete.
    mkdirSync(dirname(userConfigPath()), { recursive: true, mode: 0o700 });
    writeFileSync(userConfigPath(), "");
    const result = loadOrCreateUserConfig();
    assert.equal(result.created, false);
    assert.deepEqual(result.config.reviewers, {});
  });
});

describe("resolveReviewerModel", () => {
  it("returns null when no per-user config exists", () => {
    assert.equal(resolveReviewerModel("security"), null);
  });

  it("returns the configured model when set", () => {
    writeUserConfig({ reviewers: { security: "claude-opus-4-7" } });
    assert.equal(resolveReviewerModel("security"), "claude-opus-4-7");
  });

  it("returns null for a reviewer that isn't pinned", () => {
    writeUserConfig({ reviewers: { security: "claude-opus-4-7" } });
    // standards not pinned → SDK default applies
    assert.equal(resolveReviewerModel("standards"), null);
  });

  it("returns null on a malformed file (resolver is on the hot path)", () => {
    // Write a file the parser would throw on. The resolver must NOT throw —
    // it's called per-reviewer per-review and a parse error mid-review is a
    // worse UX than a silent fall-back to the SDK default.
    mkdirSync(dirname(userConfigPath()), { recursive: true, mode: 0o700 });
    writeFileSync(userConfigPath(), "reviewers:\n  -bad-name: claude-sonnet-4-6\n");
    assert.equal(resolveReviewerModel("security"), null);
  });

  it("each reviewer resolves independently", () => {
    writeUserConfig({
      reviewers: {
        security: "claude-opus-4-7",
        standards: "claude-sonnet-4-6",
      },
    });
    assert.equal(resolveReviewerModel("security"), "claude-opus-4-7");
    assert.equal(resolveReviewerModel("standards"), "claude-sonnet-4-6");
    assert.equal(resolveReviewerModel("product"), null);
  });
});

describe("deleteUserConfig", () => {
  it("returns false when the file doesn't exist", () => {
    assert.equal(deleteUserConfig(), false);
  });

  it("removes the file and returns true when present", () => {
    writeUserConfig({ reviewers: { security: "claude-sonnet-4-6" } });
    assert.equal(existsSync(userConfigPath()), true);
    assert.equal(deleteUserConfig(), true);
    assert.equal(existsSync(userConfigPath()), false);
  });
});

describe("name + model-id validators", () => {
  it("isValidReviewerName accepts the documented shape", () => {
    for (const name of ["security", "Standards", "team-1", "a", "abc_123"]) {
      assert.equal(isValidReviewerName(name), true, name);
    }
  });

  it("isValidReviewerName rejects path-traversal and leading-non-alnum shapes", () => {
    // Includes leading underscore — the regex requires the first char to be
    // [A-Za-z0-9], so `_hidden` is not a legal reviewer name. Pinned here so
    // a future regex relaxation is a deliberate test update.
    for (const name of [
      "",
      "-leading",
      "_hidden_x",
      "../../evil",
      "name.with.dots",
      "name with space",
    ]) {
      assert.equal(isValidReviewerName(name), false, name);
    }
  });

  it("isValidModelId accepts known shapes (claude-* and friends)", () => {
    for (const id of [
      "claude-sonnet-4-6",
      "claude-opus-4-7",
      "claude-haiku-4-5-20251001",
      "anthropic/claude-sonnet-4-6",
      "claude.experimental",
    ]) {
      assert.equal(isValidModelId(id), true, id);
    }
  });

  it("isValidModelId rejects whitespace, empty, and over-long shapes", () => {
    assert.equal(isValidModelId(""), false);
    assert.equal(isValidModelId(" claude"), false);
    assert.equal(isValidModelId("claude sonnet"), false);
    assert.equal(isValidModelId("a".repeat(129)), false);
  });
});

describe("DEFAULT_REVIEWER_MODELS contract", () => {
  it("ships Sonnet across the three starter personas", () => {
    // Pin the exact defaults that the project README and AC#3 promise.
    // If these change, the upgrade-notice text in runReview also wants
    // updating, so a deliberate test update is the right gate.
    assert.deepEqual(
      { ...DEFAULT_REVIEWER_MODELS },
      {
        security: "claude-sonnet-4-6",
        standards: "claude-sonnet-4-6",
        product: "claude-sonnet-4-6",
      },
    );
  });
});

// ---------- CLI handler round-trip ----------

describe("stamp config reviewers — CLI handlers", () => {
  it("set writes a new reviewer entry, show prints it back", () => {
    const logs = captureLogs();
    try {
      runConfigReviewersSet({ reviewer: "security", modelId: "claude-opus-4-7" });
      runConfigReviewersShow();
    } finally {
      logs.restore();
    }
    const out = logs.text();
    assert.match(out, /reviewers\.security = claude-opus-4-7/);
    assert.match(out, /security/);
    assert.match(out, /claude-opus-4-7/);
    // resolver agrees
    assert.equal(resolveReviewerModel("security"), "claude-opus-4-7");
  });

  it("set then re-set updates the value (prior -> new)", () => {
    const logs = captureLogs();
    try {
      runConfigReviewersSet({ reviewer: "security", modelId: "claude-sonnet-4-6" });
      logs.clear();
      runConfigReviewersSet({ reviewer: "security", modelId: "claude-opus-4-7" });
    } finally {
      logs.restore();
    }
    assert.match(logs.text(), /security: claude-sonnet-4-6 -> claude-opus-4-7/);
  });

  it("set with the SAME value reports unchanged", () => {
    const logs = captureLogs();
    try {
      runConfigReviewersSet({ reviewer: "security", modelId: "claude-opus-4-7" });
      logs.clear();
      runConfigReviewersSet({ reviewer: "security", modelId: "claude-opus-4-7" });
    } finally {
      logs.restore();
    }
    assert.match(logs.text(), /unchanged/);
  });

  it("clear <reviewer> removes a single entry, leaves the file in place", () => {
    runConfigReviewersSet({ reviewer: "security", modelId: "claude-opus-4-7" });
    runConfigReviewersSet({ reviewer: "standards", modelId: "claude-sonnet-4-6" });
    const logs = captureLogs();
    try {
      runConfigReviewersClear({ reviewer: "security" });
    } finally {
      logs.restore();
    }
    assert.match(logs.text(), /cleared reviewers\.security/);
    assert.equal(resolveReviewerModel("security"), null);
    // standards entry survives — clear is per-reviewer.
    assert.equal(resolveReviewerModel("standards"), "claude-sonnet-4-6");
    assert.equal(existsSync(userConfigPath()), true);
  });

  it("clear --all removes the whole file", () => {
    runConfigReviewersSet({ reviewer: "security", modelId: "claude-opus-4-7" });
    runConfigReviewersClear({ all: true });
    assert.equal(existsSync(userConfigPath()), false);
    assert.equal(resolveReviewerModel("security"), null);
  });

  it("clear --all on an absent file is a no-op (no throw)", () => {
    // operator running clear before any set ever happened
    runConfigReviewersClear({ all: true });
  });

  it("clear of an unset reviewer is a no-op (no throw)", () => {
    runConfigReviewersClear({ reviewer: "never-set" });
  });

  it("clear with neither reviewer nor --all throws UsageError", () => {
    assert.throws(
      () => runConfigReviewersClear({}),
      /pass <reviewer>.*--all/,
    );
  });

  it("clear with both reviewer AND --all throws UsageError", () => {
    assert.throws(
      () => runConfigReviewersClear({ reviewer: "security", all: true }),
      /not both/,
    );
  });

  it("set rejects an invalid reviewer name", () => {
    assert.throws(
      () => runConfigReviewersSet({ reviewer: "../../etc", modelId: "claude-sonnet-4-6" }),
      /invalid reviewer name/,
    );
  });

  it("set rejects an invalid model id shape", () => {
    assert.throws(
      () => runConfigReviewersSet({ reviewer: "security", modelId: "claude sonnet 4" }),
      /invalid shape/,
    );
  });

  it("show with no config explains defaults", () => {
    const logs = captureLogs();
    try {
      runConfigReviewersShow();
    } finally {
      logs.restore();
    }
    const out = logs.text();
    assert.match(out, /no per-user stamp config/);
    assert.match(out, /security: claude-sonnet-4-6/);
    assert.match(out, /standards: claude-sonnet-4-6/);
    assert.match(out, /product: claude-sonnet-4-6/);
  });

  it("show distinguishes pinned overrides from unpinned defaults", () => {
    // Pin only `security` (matching default) — `standards` + `product`
    // should appear in the unpinned section.
    runConfigReviewersSet({
      reviewer: "security",
      modelId: "claude-opus-4-7",
    });
    const logs = captureLogs();
    try {
      runConfigReviewersShow();
    } finally {
      logs.restore();
    }
    const out = logs.text();
    assert.match(out, /reviewers:/);
    assert.match(out, /security.*claude-opus-4-7/);
    assert.match(out, /unpinned/);
    assert.match(out, /standards.*claude-sonnet-4-6.*default/);
  });
});

// ---------- helpers ----------

function captureLogs(): {
  text: () => string;
  clear: () => void;
  restore: () => void;
} {
  const lines: string[] = [];
  const origLog = console.log;
  const origErr = console.error;
  console.log = (...args: unknown[]) => {
    lines.push(args.map((a) => String(a)).join(" "));
  };
  console.error = (...args: unknown[]) => {
    lines.push(args.map((a) => String(a)).join(" "));
  };
  return {
    text: () => lines.join("\n"),
    clear: () => {
      lines.length = 0;
    },
    restore: () => {
      console.log = origLog;
      console.error = origErr;
    },
  };
}

// Silence the TS unused-import warnings for helpers Node's test runner imports
// transitively. The shape pins live below; loadUserConfig is exercised
// indirectly via loadOrCreateUserConfig + resolveReviewerModel.
void loadUserConfig;
