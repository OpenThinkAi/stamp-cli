/**
 * Tests for skills/stamp-review.md (AGT-340).
 *
 * The Claude Code skill is the local-only-mode consumer of the JSON plan
 * emitted by stamp review --plan (AGT-339). It is a markdown file with
 * YAML frontmatter loaded by the Claude Code harness; this test pins the
 * frontmatter shape + a small handful of load-bearing phrases so a casual
 * edit can't silently drift the contract.
 *
 * Why these specific assertions:
 *   - name: skill is loaded by name via the harness Skill tool.
 *   - description: the harness uses this to decide whether to invoke; it
 *     must lead with the local-only / no-attestation framing so a parent
 *     agent doesn't reach for it when trusted-mode review is what's needed.
 *   - body must reference the banner concept + the plan schema file so a
 *     future agent maintaining the skill knows where the contract lives.
 */

import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";

const SKILL_PATH = join(process.cwd(), "skills", "stamp-review.md");

function loadSkill(): { frontmatter: string; body: string; raw: string } {
  const raw = readFileSync(SKILL_PATH, "utf8");
  // Frontmatter is the first ---...--- block at the top of the file.
  // Match Claude Code's documented skill format (YAML between fences).
  const m = raw.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
  if (!m) {
    throw new Error(
      'skills/stamp-review.md must open with a "---" YAML frontmatter block followed by a "---" terminator and a body',
    );
  }
  return { frontmatter: m[1]!, body: m[2]!, raw };
}

describe("skills/stamp-review.md — file presence and frontmatter", () => {
  it("exists at skills/stamp-review.md", () => {
    // readFileSync throws on missing file; the existence check is the load.
    const { raw } = loadSkill();
    assert.ok(raw.length > 0, "skill file must not be empty");
  });

  it("has a YAML frontmatter block with name + description + allowed-tools", () => {
    const { frontmatter } = loadSkill();
    // Plain regex parse — keeps the test free of a yaml dep. The skill
    // format is small enough that this is more robust than a parser pin.
    assert.match(frontmatter, /^name:\s*stamp-review\s*$/m, "name field must be exactly 'stamp-review'");
    assert.match(frontmatter, /^description:\s*\S+/m, "description field must be present and non-empty");
    assert.match(frontmatter, /^allowed-tools:\s*\S+/m, "allowed-tools field must be present and non-empty");
  });

  it("description leads with the local-only / no-attestation framing", () => {
    const { frontmatter } = loadSkill();
    const desc = frontmatter.match(/^description:\s*(.+)$/m)?.[1] ?? "";
    // Two load-bearing phrases — drift on either breaks the contract.
    // 'local-only mode' is how design.md frames the transport.
    // 'attestation' (NOT) keeps the no-trust framing salient so the
    // harness/operator doesn't mistake the skill for trusted-mode review.
    assert.match(desc, /local-only mode/i, "description must name 'local-only mode'");
    assert.match(desc, /not? a verifiable attestation/i, "description must call out that no verifiable attestation is produced");
  });

  it("allowed-tools declares Bash + Task at minimum", () => {
    const { frontmatter } = loadSkill();
    const tools = frontmatter.match(/^allowed-tools:\s*(.+)$/m)?.[1] ?? "";
    // Bash to run `stamp review --plan`; Task to dispatch one subagent
    // per reviewer. If either is missing, the skill can't function.
    assert.match(tools, /\bBash\b/, "allowed-tools must include Bash (to run stamp review --plan)");
    assert.match(tools, /\bTask\b/, "allowed-tools must include Task (to dispatch reviewer subagents)");
  });
});

describe("skills/stamp-review.md — body content", () => {
  it("references the plan schema source-of-truth so maintainers know where the contract lives", () => {
    const { body } = loadSkill();
    // The skill consumes ReviewPlan from src/lib/reviewPlan.ts (AGT-339).
    // A skill body that doesn't name this file leaves the next maintainer
    // guessing where the schema is defined.
    assert.match(body, /src\/lib\/reviewPlan\.ts/, "body must reference src/lib/reviewPlan.ts (plan schema source)");
    assert.match(body, /schema_version/, "body must reference the schema_version field");
  });

  it("names the no-trust banner concept and where it comes from", () => {
    const { body } = loadSkill();
    // The banner is the most load-bearing piece of UX — surfaces no-trust
    // framing before and after the verdicts. Body must instruct the parent
    // agent to print it, and must reference PLAN_NO_TRUST_BANNER so the
    // canonical source is discoverable.
    assert.match(body, /no-trust banner/i, "body must instruct the parent to print the no-trust banner");
    assert.match(body, /PLAN_NO_TRUST_BANNER/, "body must reference PLAN_NO_TRUST_BANNER (the canonical source)");
  });

  it("explicitly forbids inventing a stamp record-feedback verb", () => {
    const { body } = loadSkill();
    // Design decision (design.md Option E): the parent agent already has
    // each subagent's response and does not need to round-trip through
    // stamp to format or persist it. A future contributor who tries to
    // add a record-feedback verb is reverting that decision.
    assert.match(body, /record-feedback/, "body must explicitly mention the (rejected) record-feedback verb so the design boundary is enforced");
  });

  it("instructs parallel subagent dispatch (single message, multiple tool_use)", () => {
    const { body } = loadSkill();
    // The whole point of the skill is parallel review. Sequential dispatch
    // defeats local-only mode's iteration latency benefit.
    assert.match(body, /parallel/i, "body must instruct parallel dispatch");
    assert.match(body, /single message/i, "body must call out single-message multi-tool-use dispatch pattern");
  });

  it("points at docs/local-only-mode.md for mode background", () => {
    const { body } = loadSkill();
    // The skill is the orchestration recipe; the long-form mode docs live
    // in docs/local-only-mode.md. Cross-link must survive doc reshuffles.
    assert.match(body, /docs\/local-only-mode\.md/, "body must link to docs/local-only-mode.md");
  });
});

describe("skills/stamp-review.md — cross-file links resolve", () => {
  it("every relative file path referenced from the skill body exists in the repo", () => {
    const { body } = loadSkill();
    // Skill body uses ../<path> from skills/ to reach repo root, so resolve
    // any (../...) path it mentions and require it to exist. Catches typos
    // like ../docs/local-only.md (singular) when the doc is local-only-mode.md.
    const matches = [...body.matchAll(/\(\.\.\/([\w./-]+)\)/g)];
    assert.ok(matches.length > 0, "sanity: skill body should link to at least one repo file");
    for (const m of matches) {
      const rel = m[1]!;
      // Skip purely conceptual references; require ones with a file extension.
      if (!/\.[a-z]+$/.test(rel)) continue;
      const abs = join(process.cwd(), rel);
      assert.doesNotThrow(
        () => readFileSync(abs),
        `skill body references ../${rel} but that file does not exist at ${abs}`,
      );
    }
  });
});
