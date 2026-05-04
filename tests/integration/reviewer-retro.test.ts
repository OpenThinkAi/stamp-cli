/**
 * Live-LLM integration test for AGT-052 — AC #5: an orchestrator can run
 * `stamp review` against a fixture diff, parse the retro section from
 * stdout, and produce the list of reviewer-emitted candidates.
 *
 * The unit suite (`tests/retro.test.ts`) pins the formatter ↔ parser
 * round-trip directly. This file pins the orthogonal contract: that a real
 * reviewer agent, given a real prompt asking for a retro, actually calls
 * the `submit_retro` MCP tool we wired into `invokeReviewer`, and that the
 * resulting `printReview` stdout deserialises through `parseRetroBlocks`
 * the way an orchestrator would consume it.
 *
 * Skipped unless one of these env vars is set:
 *   - `ANTHROPIC_API_KEY` — direct API auth (CI typical).
 *   - `STAMP_TEST_INTEGRATION_LIVE=1` — opt-in for devs with Claude Code
 *     login already configured (the SDK auto-discovers OAuth creds; no
 *     env-var copy needed).
 *
 * One live LLM call per case (single reviewer, capped at maxTurns=8 per
 * invokeReviewer's default, ~5–15s wall-clock for a tiny fixture diff).
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import {
  parseConfigFromYaml,
  type StampConfig,
} from "../../src/lib/config.ts";
import { invokeReviewer } from "../../src/lib/reviewer.ts";
import {
  formatRetroBlock,
  parseRetroBlocks,
  RETRO_KIND_VALUES,
} from "../../src/lib/retro.ts";

const hasCreds =
  !!process.env.ANTHROPIC_API_KEY ||
  process.env.STAMP_TEST_INTEGRATION_LIVE === "1";
const skipReason = hasCreds
  ? undefined
  : "requires ANTHROPIC_API_KEY or STAMP_TEST_INTEGRATION_LIVE=1 (Claude Code login auto-detected)";

const FIXTURE_REVIEWER_PROMPT = `# fixture reviewer (AGT-052 e2e)

You are reviewing a tiny test diff. The diff is intentionally trivial —
your verdict is not the focus of this test.

When you review:

1. Call \`submit_retro\` exactly once with a short codebase observation
   about the file being changed. Use kind \`convention\` and a one-sentence
   observation. Optional evidence is fine but not required.
2. Then call \`submit_verdict\` with verdict "approved" and one sentence
   of prose acknowledging the change.

Keep your overall response brief. Do not call submit_retro more than once.

VERDICT: approved
`;

function buildConfig(reviewerPromptPath: string): StampConfig {
  const yaml = `
branches:
  main:
    required: [fixture]
reviewers:
  fixture:
    prompt: ${reviewerPromptPath}
`;
  return parseConfigFromYaml(yaml);
}

describe("submit_retro lands on stdout in a parseable fence (AGT-052 AC #5)", () => {
  it(
    "invokeReviewer captures a retro candidate, printReview emits it, parseRetroBlocks recovers it",
    { skip: skipReason, timeout: 120_000 },
    async () => {
      const repoRoot = realpathSync(
        mkdtempSync(path.join(tmpdir(), "stamp-agt052-")),
      );
      const reviewerPromptRel = "fixture-reviewer.md";
      writeFileSync(
        path.join(repoRoot, reviewerPromptRel),
        FIXTURE_REVIEWER_PROMPT,
      );
      // The fixture diff is intentionally trivial — we care about the retro
      // channel, not the model's verdict reasoning.
      const diff = [
        "diff --git a/example.txt b/example.txt",
        "new file mode 100644",
        "--- /dev/null",
        "+++ b/example.txt",
        "@@ -0,0 +1,1 @@",
        "+hello",
      ].join("\n");

      const config = buildConfig(reviewerPromptRel);
      const result = await invokeReviewer({
        reviewer: "fixture",
        config,
        repoRoot,
        diff,
        base_sha: "0000000000000000000000000000000000000000",
        head_sha: "1111111111111111111111111111111111111111",
        systemPrompt: FIXTURE_REVIEWER_PROMPT,
      });

      // Producer side: invokeReviewer surfaced the retro through the structured channel.
      assert.ok(
        result.retros.length >= 1,
        `expected at least one retro candidate via submit_retro; got ${result.retros.length}. ` +
          `If 0, the model didn't call the tool — the system-prompt appendix or the reviewer prompt ` +
          `instruction may need to be more directive. Verdict: ${result.verdict}, prose: ${result.prose.slice(0, 200)}`,
      );
      const first = result.retros[0]!;
      assert.ok(
        (RETRO_KIND_VALUES as readonly string[]).includes(first.kind),
        `retro kind "${first.kind}" should be one of the documented enum values`,
      );
      assert.ok(
        first.observation.length > 0,
        "retro observation must be a non-empty string per the Zod schema",
      );

      // Wire-format side: the formatter that printReview uses produces a
      // fence parseRetroBlocks can recover. We exercise the formatter
      // directly (rather than capturing printReview's stdout) so the test
      // doesn't depend on stdout interception — the printReview wiring is
      // covered by the unit test for printReview's call to formatRetroBlock.
      const fence = formatRetroBlock(result.reviewer, result.retros);
      const parsed = parseRetroBlocks(`${fence}\n`);
      assert.equal(parsed.length, 1);
      assert.equal(parsed[0]!.reviewer, "fixture");
      assert.deepEqual(parsed[0]!.candidates, result.retros);
    },
  );
});
