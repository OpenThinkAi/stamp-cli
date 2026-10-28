/**
 * AGT-2270: `stamp reviewers add/remove` and `stamp bootstrap` rewrite
 * .stamp/config.yml without dropping comments (incl. the init retention
 * scaffold) or top-level keys they don't own.
 */
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  parseConfigFromYaml,
  patchConfigYaml,
  RETENTION_CONFIG_SCAFFOLD,
  renderInitialConfig,
} from "../src/lib/config.ts";

const RAW = `# team policy: keep security required
branches:
  main:
    required: [security] # gate
reviewers:
  security:
    prompt: .stamp/reviewers/security.md # calibrated 2026-10
data_flow:
  review_endpoints: [api.anthropic.com]
`;

describe("patchConfigYaml (AGT-2270)", () => {
  it("adds a reviewer and keeps every comment and unrelated key", () => {
    const cfg = parseConfigFromYaml(RAW);
    const out = patchConfigYaml(RAW, {
      reviewers: { ...cfg.reviewers, product: { prompt: ".stamp/reviewers/product.md" } },
    });
    for (const c of ["# team policy", "# gate", "# calibrated 2026-10"]) assert.ok(out.includes(c), c);
    const re = parseConfigFromYaml(out);
    assert.deepEqual(Object.keys(re.reviewers).sort(), ["product", "security"]);
    assert.deepEqual(re.data_flow?.review_endpoints, ["api.anthropic.com"]);
  });

  it("removes a reviewer without touching the rest", () => {
    const two = patchConfigYaml(RAW, {
      reviewers: { security: { prompt: ".stamp/reviewers/security.md" }, x: { prompt: ".stamp/reviewers/x.md" } },
    });
    const out = patchConfigYaml(two, { reviewers: { security: { prompt: ".stamp/reviewers/security.md" } } });
    assert.ok(out.includes("# calibrated 2026-10"));
    assert.deepEqual(Object.keys(parseConfigFromYaml(out).reviewers), ["security"]);
  });

  it("keeps the init retention scaffold through a bootstrap-shaped patch", () => {
    const init = renderInitialConfig(parseConfigFromYaml(RAW));
    const out = patchConfigYaml(init, {
      branches: { main: { required: ["security", "standards"] } },
      reviewers: {
        security: { prompt: ".stamp/reviewers/security.md" },
        standards: { prompt: ".stamp/reviewers/standards.md" },
      },
    });
    assert.ok(out.includes(RETENTION_CONFIG_SCAFFOLD.trim().split("\n")[0]!), out);
    assert.ok(out.includes("# retention:"), out);
    assert.deepEqual(parseConfigFromYaml(out).branches.main?.required, ["security", "standards"]);
  });
});
