/**
 * Unit tests for the pure validators and helpers we ship. These are the
 * functions whose bugs cost the most review-cycle time recently:
 *
 *   - parseGithubOriginUrl rejected repo names with dots (regex too strict)
 *   - the actor_type "User" silently no-op'd on org repos (the BypassActor
 *     type encodes the right answer; this test pins the User-vs-OrgAdmin
 *     selection to the rule)
 *   - injectStampSection's three-case logic (no markers / with markers /
 *     empty input) needed clear test cases to confirm idempotence
 *
 * Note: client-side validateRepoName / validateTrashEntryName /
 * validateGithubRepoSpec live in src/commands/serverRepo.ts and are
 * currently un-exported. Adding tests for those means exporting them
 * through serverRepo.ts (or moving them into a lib module). Skipped
 * for this pass — the load-bearing fix is the conventions check + the
 * helpers below, which catch the patterns those validators were added
 * to defend.
 *
 * Each test is a single assertion of accept-or-reject on input shapes
 * we've actually seen go wrong. New regressions add cases here, not
 * another reviewer round.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  buildRulesetPayload,
  parseGithubOriginUrl,
  type BypassActor,
} from "../src/lib/ghRuleset.ts";
import {
  bareRepoSshUrl,
  parseServerConfig,
  parseServerFlag,
} from "../src/lib/serverConfig.ts";
import {
  injectClaudeSection,
  injectStampSection,
  STAMP_BEGIN,
  STAMP_CLAUDE_BEGIN,
  STAMP_CLAUDE_END,
  STAMP_END,
} from "../src/lib/agentsMd.ts";
import {
  formatServerConfigYaml,
  runServerConfig,
} from "../src/commands/server.ts";
import {
  filterLiveBareRepoNames,
  normalizeRepoName,
} from "../src/commands/serverRepo.ts";
import {
  globToRegex,
  isGlobPattern,
  matchesAnyPattern,
  matchesAnyTagPattern,
  resolveTagPatterns,
} from "../src/lib/refPatterns.ts";
import { findBranchRule, type BranchRule } from "../src/lib/config.ts";
import { parseServerConfig as parseServerYaml } from "../src/lib/serverConfig.ts";

// ---------- parseGithubOriginUrl ----------

describe("parseGithubOriginUrl", () => {
  const cases: Array<{
    name: string;
    url: string;
    expect: { owner: string; repo: string } | null;
  }> = [
    {
      name: "scp-style git@",
      url: "git@github.com:owner/repo.git",
      expect: { owner: "owner", repo: "repo" },
    },
    {
      name: "https without .git",
      url: "https://github.com/owner/repo",
      expect: { owner: "owner", repo: "repo" },
    },
    {
      name: "ssh:// with explicit port returns null (existing limitation)",
      url: "ssh://git@github.com:22/owner/repo.git",
      // The current regex doesn't account for ssh-port forms like
      // github.com:22/owner/repo.git — it expects the owner to come
      // directly after github.com[:/]. Documenting the limitation; if
      // this becomes a real problem the regex needs an optional port
      // group. Pinning the current behavior so a future fix is a
      // deliberate test update, not a silent change.
      expect: null,
    },
    {
      name: "repo name with dots (the regex bug from 0.7.1)",
      url: "git@github.com:owner/has.dots.git",
      expect: { owner: "owner", repo: "has.dots" },
    },
    {
      name: "repo name with dashes",
      url: "git@github.com:owner/foo-bar.git",
      expect: { owner: "owner", repo: "foo-bar" },
    },
    {
      name: "non-github url returns null",
      url: "git@gitlab.com:owner/repo.git",
      expect: null,
    },
    {
      name: "stamp-server-style ssh url returns null",
      url: "ssh://git@stamp.example.com:2222/srv/git/myproject.git",
      expect: null,
    },
  ];
  for (const c of cases) {
    it(c.name, () => {
      assert.deepEqual(parseGithubOriginUrl(c.url), c.expect);
    });
  }
});

// ---------- BypassActor / buildRulesetPayload ----------

describe("buildRulesetPayload", () => {
  it("encodes a User actor verbatim", () => {
    const actor: BypassActor = { type: "User", id: 12345 };
    const payload = buildRulesetPayload(actor) as {
      bypass_actors: Array<{ actor_id: number; actor_type: string }>;
    };
    assert.equal(payload.bypass_actors.length, 1);
    assert.equal(payload.bypass_actors[0]!.actor_type, "User");
    assert.equal(payload.bypass_actors[0]!.actor_id, 12345);
  });

  it("encodes an OrganizationAdmin actor with id=1", () => {
    // Pin the magic constant: actor_id=1 is GitHub's "any org admin"
    // sentinel. The 0.7.2 fix depends on this being the value sent.
    const actor: BypassActor = { type: "OrganizationAdmin", id: 1 };
    const payload = buildRulesetPayload(actor) as {
      bypass_actors: Array<{ actor_id: number; actor_type: string }>;
    };
    assert.equal(payload.bypass_actors[0]!.actor_type, "OrganizationAdmin");
    assert.equal(payload.bypass_actors[0]!.actor_id, 1);
  });

  it("does NOT include required_linear_history rule (incompatible with --no-ff merges)", () => {
    const payload = buildRulesetPayload({ type: "User", id: 1 }) as {
      rules: Array<{ type: string }>;
    };
    const types = payload.rules.map((r) => r.type);
    assert.equal(
      types.includes("required_linear_history"),
      false,
      "stamp produces --no-ff merges; required_linear_history would reject every merge",
    );
  });
});

// ---------- parseServerConfig ----------

describe("parseServerConfig", () => {
  it("accepts host + port + defaults", () => {
    const cfg = parseServerConfig("host: stamp.example.com\nport: 2222\n");
    assert.equal(cfg.host, "stamp.example.com");
    assert.equal(cfg.port, 2222);
    assert.equal(cfg.user, "git");
    assert.equal(cfg.repoRootPrefix, "/srv/git");
  });

  it("honors user + repo_root_prefix overrides", () => {
    const cfg = parseServerConfig(
      "host: x\nport: 22\nuser: alice\nrepo_root_prefix: /var/repos\n",
    );
    assert.equal(cfg.user, "alice");
    assert.equal(cfg.repoRootPrefix, "/var/repos");
  });

  it("rejects missing host", () => {
    assert.throws(() => parseServerConfig("port: 2222\n"), /host/);
  });

  it("rejects out-of-range port", () => {
    assert.throws(() => parseServerConfig("host: x\nport: 0\n"), /port/);
    assert.throws(() => parseServerConfig("host: x\nport: 70000\n"), /port/);
  });

  it("rejects non-yaml input", () => {
    assert.throws(() => parseServerConfig("not a mapping"), /mapping/);
  });
});

describe("parseServerFlag", () => {
  it("accepts <host>:<port>", () => {
    const cfg = parseServerFlag("stamp.example.com:2222");
    assert.equal(cfg.host, "stamp.example.com");
    assert.equal(cfg.port, 2222);
  });

  it("rejects missing port", () => {
    assert.throws(() => parseServerFlag("stamp.example.com"), /<host>:<port>/);
  });

  it("rejects non-integer port", () => {
    assert.throws(() => parseServerFlag("x:abc"), /<host>:<port>/);
  });
});

describe("bareRepoSshUrl", () => {
  it("composes the stamp-server SSH URL deterministically", () => {
    const cfg = parseServerFlag("stamp.example.com:2222");
    assert.equal(
      bareRepoSshUrl(cfg, "myproject"),
      "ssh://git@stamp.example.com:2222/srv/git/myproject.git",
    );
  });
});

// ---------- injectStampSection (AGENTS.md) ----------

describe("injectStampSection (AGENTS.md)", () => {
  it("creates a fresh AGENTS.md when input is empty", () => {
    const out = injectStampSection(undefined, "server-gated");
    assert.match(out, /^# AGENTS\.md/);
    assert.ok(out.includes(STAMP_BEGIN), "output should contain STAMP_BEGIN marker");
    assert.ok(out.includes(STAMP_END), "output should contain STAMP_END marker");
  });

  it("appends to existing content without markers (only once — second pass replaces in place)", () => {
    const existing = "# my project\n\nSome content.\n";
    const first = injectStampSection(existing, "local-only");
    assert.match(first, /Some content/);
    assert.ok(first.includes(STAMP_BEGIN), "first pass should add STAMP_BEGIN");
    // Second pass: now the markers exist, so the section gets replaced
    // in place rather than re-appended. Idempotent from here on.
    const second = injectStampSection(first, "local-only");
    assert.equal(
      first,
      second,
      "calling injectStampSection twice with the same mode is a no-op",
    );
  });

  it("replaces the stamp section in place when markers are present", () => {
    const existing = injectStampSection(undefined, "server-gated");
    // Re-inject with a different mode — stamp section content should
    // change (different body for local-only) but the rest of the file
    // (preamble, markers location) stays intact.
    const switched = injectStampSection(existing, "local-only");
    assert.match(switched, /^# AGENTS\.md/);
    assert.match(switched, /advisory mode|NOT enforced/i);
  });

  it("preserves user content outside the markers across re-inject", () => {
    const existing =
      "# user-managed content\n" +
      "this is mine\n\n" +
      `${STAMP_BEGIN}\n\n## old stamp content\n\n${STAMP_END}\n` +
      "trailing user content\n";
    const out = injectStampSection(existing, "server-gated");
    assert.match(out, /this is mine/);
    assert.match(out, /trailing user content/);
  });
});

// ---------- formatServerConfigYaml ----------

describe("formatServerConfigYaml", () => {
  it("emits only host + port when user / repo_root_prefix are absent", () => {
    const yaml = formatServerConfigYaml({ host: "stamp.example.com", port: 2222 });
    const round = parseServerYaml(yaml);
    assert.equal(round.host, "stamp.example.com");
    assert.equal(round.port, 2222);
    assert.equal(round.user, "git");
    assert.equal(round.repoRootPrefix, "/srv/git");
    assert.equal(yaml.includes("user:"), false, "should omit user when default");
    assert.equal(
      yaml.includes("repo_root_prefix:"),
      false,
      "should omit repo_root_prefix when default",
    );
  });

  it("includes user + repo_root_prefix overrides when provided", () => {
    const yaml = formatServerConfigYaml({
      host: "x",
      port: 22,
      user: "alice",
      repoRootPrefix: "/var/repos",
    });
    const round = parseServerYaml(yaml);
    assert.equal(round.user, "alice");
    assert.equal(round.repoRootPrefix, "/var/repos");
  });

  it("trims whitespace on overrides (defensive)", () => {
    const yaml = formatServerConfigYaml({
      host: "x",
      port: 22,
      user: "  alice  ",
      repoRootPrefix: "  /var/repos  ",
    });
    const round = parseServerYaml(yaml);
    assert.equal(round.user, "alice");
    assert.equal(round.repoRootPrefix, "/var/repos");
  });

  it("treats empty-string overrides as 'use default' (no key emitted)", () => {
    const yaml = formatServerConfigYaml({
      host: "x",
      port: 22,
      user: "",
      repoRootPrefix: "   ",
    });
    assert.equal(yaml.includes("user:"), false);
    assert.equal(yaml.includes("repo_root_prefix:"), false);
  });
});

// ---------- runServerConfig: argument validation ----------

describe("runServerConfig validation", () => {
  it("rejects no args (no mode chosen)", () => {
    assert.throws(() => runServerConfig({}), /exactly one/);
  });

  it("rejects host:port + --show together (multiple modes)", () => {
    assert.throws(
      () => runServerConfig({ hostPort: "x:22", show: true }),
      /exactly one/,
    );
  });

  it("rejects --show + --unset together (multiple modes)", () => {
    assert.throws(
      () => runServerConfig({ show: true, unset: true }),
      /exactly one/,
    );
  });

  it("rejects --user with --show (only applies on write)", () => {
    assert.throws(
      () => runServerConfig({ show: true, user: "alice" }),
      /only apply when writing/,
    );
  });

  it("rejects --repo-root-prefix with --unset (only applies on write)", () => {
    assert.throws(
      () => runServerConfig({ unset: true, repoRootPrefix: "/v" }),
      /only apply when writing/,
    );
  });

  it("rejects malformed host:port (format error)", () => {
    assert.throws(
      () => runServerConfig({ hostPort: "not-a-spec" }),
      /must be in the form <host>:<port>/,
    );
  });

  it("rejects out-of-range port with the port-specific message (not the format one)", () => {
    // Pinning the bug standards caught: a fixed wrap message would
    // misleadingly tell the user the format is wrong when the format
    // is fine and the port is out of range.
    assert.throws(
      () => runServerConfig({ hostPort: "x:99999" }),
      /port must be an integer 1\.\.65535/,
    );
  });

  it("error messages use 'stamp server config' context (not '--server')", () => {
    assert.throws(
      () => runServerConfig({ hostPort: "not-a-spec" }),
      /stamp server config:/,
    );
  });
});

// ---------- normalizeRepoName ----------

describe("normalizeRepoName", () => {
  it("returns canonical name unchanged", () => {
    assert.equal(normalizeRepoName("spotfxTEST5"), "spotfxTEST5");
  });

  it("strips a trailing .git (the bug from the 'list' display form)", () => {
    // Pre-0.7.7 the validator threw on `spotfxTEST5.git`; post-0.7.7 it's
    // accepted as the operator-natural form (matches what `list` printed).
    assert.equal(normalizeRepoName("spotfxTEST5.git"), "spotfxTEST5");
  });

  it("strips only one .git suffix (a name like foo.git.git becomes foo.git, then validates)", () => {
    // Defensive: if someone really has `foo.git` as the canonical name, this
    // still works after the strip — the resulting `foo.git` is a valid
    // canonical name. The double-extension that plagued 0.7.6 was a
    // server-side artifact, not an input we want to support directly.
    assert.equal(normalizeRepoName("foo.git.git"), "foo.git");
  });

  it("rejects names that are invalid even after stripping", () => {
    assert.throws(() => normalizeRepoName("lost+found"), /must start with/);
    assert.throws(() => normalizeRepoName("foo..bar"), /'\.\.'/);
    assert.throws(() => normalizeRepoName("-leading-dash"), /must start with/);
  });

  it("strips .git then re-validates (e.g. '+invalid.git' is still rejected)", () => {
    assert.throws(() => normalizeRepoName("foo+bar.git"), /must start with/);
  });
});

// ---------- filterLiveBareRepoNames ----------

describe("filterLiveBareRepoNames", () => {
  it("strips .git suffix from bare-repo dirs and drops on-volume metadata", () => {
    const raw = [
      "budget.git",
      "keeb-cooker.git",
      "lost+found",
      "open-audit.git",
      ".trash",
      ".ssh-host-keys",
      "scrub.git",
      "",
    ].join("\n");
    assert.deepEqual(filterLiveBareRepoNames(raw), [
      "budget",
      "keeb-cooker",
      "open-audit",
      "scrub",
    ]);
  });

  it("returns empty array on empty input", () => {
    assert.deepEqual(filterLiveBareRepoNames(""), []);
  });

  it("ignores entries that don't end in .git (positive filter, not a denylist)", () => {
    // Anything that isn't a bare repo directory is dropped — this keeps
    // future filesystem artifacts (e.g. an admin SSH'ing in and creating
    // a `notes.txt`) from showing up as confusing list entries.
    const raw = ["notes.txt", "scratch", "real.git"].join("\n");
    assert.deepEqual(filterLiveBareRepoNames(raw), ["real"]);
  });
});

// ---------- refPatterns (mirror.yml tags:) ----------

describe("globToRegex", () => {
  it("matches a literal tag name verbatim", () => {
    assert.equal(globToRegex("v1.0.0").test("v1.0.0"), true);
  });

  it("does NOT treat regex meta in literals as wildcards (the . bug)", () => {
    // Pre-fix: a naive `*`→`.*`  pass would also let `.` match anything,
    // so `v1.0.0` would match `v1x0x0`. Pin that we escape regex meta.
    assert.equal(globToRegex("v1.0.0").test("v1x0x0"), false);
  });

  it("treats * as 'zero or more characters'", () => {
    assert.equal(globToRegex("v*").test("v1.0.0"), true);
    assert.equal(globToRegex("v*").test("v"), true);
    assert.equal(globToRegex("v*").test("u1.0.0"), false);
  });

  it("treats ? as 'exactly one character'", () => {
    assert.equal(globToRegex("v?.0").test("v1.0"), true);
    assert.equal(globToRegex("v?.0").test("v.0"), false);
    assert.equal(globToRegex("v?.0").test("v10.0"), false);
  });

  it("anchors the pattern (substring matches don't slip through)", () => {
    assert.equal(globToRegex("v*").test("xv1.0.0"), false);
    assert.equal(globToRegex("v1").test("v1.0.0"), false);
  });

  it("escapes other regex metacharacters that operators don't expect to mean anything", () => {
    // +, ^, $, (, ), |, [, ], {, } in a glob should be literals.
    assert.equal(globToRegex("v(1)").test("v(1)"), true);
    assert.equal(globToRegex("v+1").test("v+1"), true);
    assert.equal(globToRegex("v+1").test("v1"), false);
  });
});

describe("resolveTagPatterns", () => {
  it("undefined → [] (no tag mirroring; default behavior)", () => {
    assert.deepEqual(resolveTagPatterns(undefined), []);
  });

  it("null → [] (operator wrote 'tags:' with no value)", () => {
    assert.deepEqual(resolveTagPatterns(null), []);
  });

  it("false → [] (explicit opt-out)", () => {
    assert.deepEqual(resolveTagPatterns(false), []);
  });

  it("true → ['*'] (mirror all tags)", () => {
    assert.deepEqual(resolveTagPatterns(true), ["*"]);
  });

  it("array of strings is returned as-is", () => {
    assert.deepEqual(resolveTagPatterns(["v*", "rc-*"]), ["v*", "rc-*"]);
  });

  it("empty array stays empty (operator opted out via empty list)", () => {
    assert.deepEqual(resolveTagPatterns([]), []);
  });

  it("non-string element → null (config error)", () => {
    assert.equal(resolveTagPatterns(["v*", 123]), null);
  });

  it("empty string element → null (config error)", () => {
    assert.equal(resolveTagPatterns(["v*", ""]), null);
  });

  it("string at top level → null (operator probably forgot the dash)", () => {
    assert.equal(resolveTagPatterns("v*"), null);
  });

  it("number at top level → null", () => {
    assert.equal(resolveTagPatterns(42), null);
  });
});

describe("matchesAnyTagPattern", () => {
  it("returns true when any pattern matches", () => {
    assert.equal(matchesAnyTagPattern("v1.0.0", ["v*", "rc-*"]), true);
    assert.equal(matchesAnyTagPattern("rc-2", ["v*", "rc-*"]), true);
  });

  it("returns false when no pattern matches", () => {
    assert.equal(matchesAnyTagPattern("hotfix", ["v*", "rc-*"]), false);
  });

  it("empty pattern list never matches (= no tag mirroring)", () => {
    assert.equal(matchesAnyTagPattern("v1.0.0", []), false);
  });

  it("the all-tags shortcut ['*'] matches everything", () => {
    assert.equal(matchesAnyTagPattern("v1.0.0", ["*"]), true);
    assert.equal(matchesAnyTagPattern("hotfix-2026", ["*"]), true);
    assert.equal(matchesAnyTagPattern("", ["*"]), true);
  });
});

// ---------- glob matching for branch refs (issue #9) ----------

describe("matchesAnyPattern (branch / generic ref names)", () => {
  it("matches a literal branch name without metachars", () => {
    assert.equal(matchesAnyPattern("main", ["main"]), true);
    assert.equal(matchesAnyPattern("develop", ["main"]), false);
  });

  it("matches a glob with slashes — release/v3.2 against release/*", () => {
    // The * metachar must cross /, otherwise common branch families like
    // `release/*` or `team-foo/feature` wouldn't be expressible.
    assert.equal(matchesAnyPattern("release/v3.2", ["release/*"]), true);
    assert.equal(matchesAnyPattern("release/v3.2/hotfix", ["release/*"]), true);
  });

  it("returns true if any of multiple patterns match", () => {
    assert.equal(matchesAnyPattern("staging", ["main", "staging", "release/*"]), true);
    assert.equal(matchesAnyPattern("release/v1", ["main", "release/*"]), true);
  });

  it("empty pattern list never matches", () => {
    assert.equal(matchesAnyPattern("main", []), false);
  });

  it("matchesAnyTagPattern is the same function under the back-compat name", () => {
    // Pin the alias so a future rename doesn't silently change behavior.
    assert.equal(matchesAnyTagPattern, matchesAnyPattern);
  });
});

describe("isGlobPattern", () => {
  it("returns true for strings with * or ?", () => {
    assert.equal(isGlobPattern("release/*"), true);
    assert.equal(isGlobPattern("v?.0"), true);
    assert.equal(isGlobPattern("*"), true);
  });

  it("returns false for plain literal names", () => {
    assert.equal(isGlobPattern("main"), false);
    assert.equal(isGlobPattern("release/v1"), false);
    assert.equal(isGlobPattern(""), false);
  });
});

describe("findBranchRule (config.yml branches: glob support, issue #9)", () => {
  const ruleMain: BranchRule = { required: ["security"] };
  const ruleRelease: BranchRule = { required: ["security", "standards"] };
  const ruleTeam: BranchRule = { required: ["product"] };

  it("returns undefined when no key matches (unprotected branch)", () => {
    const branches = { main: ruleMain };
    assert.equal(findBranchRule(branches, "feature/x"), undefined);
  });

  it("returns the rule on exact key match", () => {
    const branches = { main: ruleMain };
    assert.equal(findBranchRule(branches, "main"), ruleMain);
  });

  it("falls back to glob match when no exact key", () => {
    const branches = { "release/*": ruleRelease };
    assert.equal(findBranchRule(branches, "release/v3.2"), ruleRelease);
  });

  it("exact key wins over glob (more specific intent)", () => {
    // An operator who wrote both `release/v3.2: ...` and `release/*: ...`
    // expects the exact key to govern that one branch and the glob to
    // catch the rest. Pin the precedence so a future refactor can't
    // accidentally flip it.
    const branches = {
      "release/*": ruleRelease,
      "release/v3.2": ruleMain,
    };
    assert.equal(findBranchRule(branches, "release/v3.2"), ruleMain);
    assert.equal(findBranchRule(branches, "release/v4.0"), ruleRelease);
  });

  it("throws with both keys named when multiple globs match the same branch", () => {
    // Ambiguous configs are surfaced as errors rather than silently
    // resolved by insertion order — the operator almost certainly meant
    // to write a more specific exact key for the overlap case.
    const branches = {
      "release/*": ruleRelease,
      "*/v3.2": ruleTeam,
    };
    assert.throws(
      () => findBranchRule(branches, "release/v3.2"),
      (err: Error) => {
        assert.match(err.message, /matches multiple glob patterns/);
        assert.match(err.message, /"release\/\*"/);
        assert.match(err.message, /"\*\/v3\.2"/);
        return true;
      },
    );
  });

  it("literal keys never participate in glob matching", () => {
    // Without this, a literal key like `main` would pass globToRegex too
    // (no metachars → exact-string regex), which is fine for `main` but
    // would change semantics for keys that happen to contain `.` or
    // `+` — those would gain regex-meta meaning if treated as patterns.
    // Guard with isGlobPattern at the call site so literals stay literal.
    const branches = { "main.staging": ruleMain };
    assert.equal(findBranchRule(branches, "mainXstaging"), undefined);
    assert.equal(findBranchRule(branches, "main.staging"), ruleMain);
  });
});

describe("injectClaudeSection (CLAUDE.md)", () => {
  it("uses the CLAUDE-specific markers, not AGENTS markers", () => {
    const out = injectClaudeSection(undefined);
    assert.ok(out.includes(STAMP_CLAUDE_BEGIN), "output should contain CLAUDE begin marker");
    assert.ok(out.includes(STAMP_CLAUDE_END), "output should contain CLAUDE end marker");
    // CRITICAL: must NOT include the AGENTS.md begin marker, otherwise
    // a future ensureAgentsMd run on this file would treat the CLAUDE
    // section as the AGENTS section and clobber it.
    assert.equal(
      out.includes(STAMP_BEGIN),
      false,
      "CLAUDE.md must not contain the AGENTS.md begin marker",
    );
  });
});
