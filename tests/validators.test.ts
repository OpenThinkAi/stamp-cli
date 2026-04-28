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
