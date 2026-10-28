/**
 * AGT-2247 / decision D-5: `stamp init` keeps reviewer prose by default
 * (no TTL) and scaffolds a commented-out `retention:` block in
 * .stamp/config.yml showing how to opt in. Pins that the block is present,
 * that as-written it parses to NO retention (behaviour unchanged), and that
 * uncommenting it yields a valid RetentionConfig using the real keys.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  DEFAULT_CONFIG,
  MINIMAL_CONFIG,
  parseConfigFromYaml,
  RETENTION_CONFIG_SCAFFOLD,
  renderInitialConfig,
} from "../src/lib/config.ts";

/** Strip the leading `# ` from the commented `retention:` block lines only. */
function uncommentRetention(text: string): string {
  const lines = text.split("\n");
  const start = lines.findIndex((l) => l === "# retention:");
  assert.ok(start >= 0, "scaffold must contain a `# retention:` line");
  for (let i = start; i < lines.length && lines[i]!.startsWith("# "); i++) {
    // Keep pure comment-continuation lines (only whitespace before `#`) as comments.
    const body = lines[i]!.slice(2);
    if (/^\s*#/.test(body)) continue;
    lines[i] = body;
  }
  return lines.join("\n");
}

describe("stamp init retention scaffold (AGT-2247)", () => {
  for (const [name, cfg] of [
    ["default", DEFAULT_CONFIG],
    ["minimal", MINIMAL_CONFIG],
  ] as const) {
    it(`${name} config text contains the commented retention block`, () => {
      const text = renderInitialConfig(cfg);
      assert.ok(text.includes(RETENTION_CONFIG_SCAFFOLD));
      assert.match(text, /^# retention:$/m);
      assert.match(text, /^#\s+reviews: \d+d/m);
      assert.match(text, /^#\s+spools: \d+d/m);
      assert.match(text, /^#\s+auto_prune: true/m);
      assert.match(text, /stamp prune/);
      // No live (uncommented) retention key.
      assert.doesNotMatch(text, /^retention:/m);
    });

    it(`${name} config parses with retention undefined (prose kept by default)`, () => {
      const parsed = parseConfigFromYaml(renderInitialConfig(cfg));
      assert.equal(parsed.retention, undefined);
      assert.deepEqual(parsed.branches, cfg.branches);
      assert.deepEqual(Object.keys(parsed.reviewers), Object.keys(cfg.reviewers));
    });
  }

  it("uncommenting the block yields a valid opt-in retention config", () => {
    const parsed = parseConfigFromYaml(
      uncommentRetention(renderInitialConfig(DEFAULT_CONFIG)),
    );
    assert.deepEqual(parsed.retention, {
      reviews: "60d",
      spools: "60d",
      auto_prune: true,
    });
  });
});
