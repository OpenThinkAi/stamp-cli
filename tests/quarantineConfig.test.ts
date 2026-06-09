/**
 * Tests for the AGT-476 flake-quarantine config field on
 * `required_checks[].quarantine` in `.stamp/config.yml`.
 *
 * Covers `parseConfigFromYaml` accept/reject shapes for the new field
 * and confirms the absence of the field round-trips with no `quarantine`
 * key on the parsed CheckDef (the byte-identity property the
 * attestation envelopes depend on).
 *
 * The runtime behavior of the quarantine list — env-var pass-through
 * to the check command and folding into the merge attestation — is
 * covered separately in `tests/quarantineRunner.test.ts` and
 * `tests/quarantineAttestation.test.ts`.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { parseConfigFromYaml } from "../src/lib/config.ts";

const BASE_REVIEWERS = `
reviewers:
  security:
    prompt: .stamp/reviewers/security.md
`;

function configWithCheck(checkYaml: string): string {
  return `
branches:
  main:
    required: [security]
    required_checks:
${checkYaml}
${BASE_REVIEWERS}
`;
}

describe("AGT-476 quarantine config field", () => {
  it("accepts a check with no quarantine field (preserves byte-identity)", () => {
    const yaml = configWithCheck(`      - name: test
        run: npm test`);
    const cfg = parseConfigFromYaml(yaml);
    const checks = cfg.branches.main?.required_checks;
    assert.ok(checks);
    assert.equal(checks.length, 1);
    assert.equal(checks[0]?.name, "test");
    assert.equal(checks[0]?.run, "npm test");
    // CRITICAL byte-identity property: no quarantine key in the parsed
    // object when none was declared in config. Attestation envelopes
    // depend on this — repos that don't use quarantine produce
    // envelopes byte-identical to pre-AGT-476.
    assert.equal("quarantine" in checks[0]!, false);
  });

  it("accepts a check with a non-empty quarantine list", () => {
    const yaml = configWithCheck(`      - name: test
        run: npm test
        quarantine:
          - test: tests/daemon/status.test.ts
            reason: vitest fork-pool worker-startup timeout flake on host-pressure (GH#49)
          - test: tests/integration/slow.test.ts
            reason: timing-sensitive; quarantined while we rewrite as event-driven`);
    const cfg = parseConfigFromYaml(yaml);
    const q = cfg.branches.main?.required_checks?.[0]?.quarantine;
    assert.ok(q);
    assert.equal(q.length, 2);
    assert.equal(q[0]?.test, "tests/daemon/status.test.ts");
    assert.match(q[0]?.reason ?? "", /vitest fork-pool/);
    assert.equal(q[1]?.test, "tests/integration/slow.test.ts");
  });

  it("treats an empty quarantine list as 'no quarantine' (omits the field)", () => {
    const yaml = configWithCheck(`      - name: test
        run: npm test
        quarantine: []`);
    const cfg = parseConfigFromYaml(yaml);
    const check = cfg.branches.main?.required_checks?.[0];
    assert.ok(check);
    // Empty array collapses to "undefined" so the byte-identity
    // property holds — scaffolding the field without entries must not
    // perturb attestation envelopes.
    assert.equal("quarantine" in check, false);
  });

  it("rejects a non-array quarantine field", () => {
    const yaml = configWithCheck(`      - name: test
        run: npm test
        quarantine: "tests/daemon/status.test.ts"`);
    assert.throws(
      () => parseConfigFromYaml(yaml),
      /quarantine must be an array/,
    );
  });

  it("rejects a quarantine entry missing 'test'", () => {
    const yaml = configWithCheck(`      - name: test
        run: npm test
        quarantine:
          - reason: flaky`);
    assert.throws(
      () => parseConfigFromYaml(yaml),
      /quarantine\[0\]\.test must be a non-empty string/,
    );
  });

  it("rejects a quarantine entry missing 'reason'", () => {
    const yaml = configWithCheck(`      - name: test
        run: npm test
        quarantine:
          - test: tests/foo.test.ts`);
    assert.throws(
      () => parseConfigFromYaml(yaml),
      /quarantine\[0\]\.reason must be a non-empty string/,
    );
  });

  it("rejects a quarantine entry with an empty test ID", () => {
    const yaml = configWithCheck(`      - name: test
        run: npm test
        quarantine:
          - test: ""
            reason: flaky`);
    assert.throws(
      () => parseConfigFromYaml(yaml),
      /quarantine\[0\]\.test must be a non-empty string/,
    );
  });

  it("rejects a quarantine entry with an empty reason", () => {
    const yaml = configWithCheck(`      - name: test
        run: npm test
        quarantine:
          - test: tests/foo.test.ts
            reason: ""`);
    assert.throws(
      () => parseConfigFromYaml(yaml),
      /quarantine\[0\]\.reason must be a non-empty string/,
    );
  });

  it("rejects a non-object quarantine entry", () => {
    const yaml = configWithCheck(`      - name: test
        run: npm test
        quarantine:
          - "tests/foo.test.ts"`);
    assert.throws(
      () => parseConfigFromYaml(yaml),
      /quarantine\[0\] must be an object/,
    );
  });
});
