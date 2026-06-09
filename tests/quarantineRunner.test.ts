/**
 * Tests for the AGT-476 flake-quarantine runtime in `runChecks`:
 *
 *   - when a check has a non-empty `quarantine` list, the shell command
 *     receives `STAMP_QUARANTINE_TESTS` (comma-joined `test` IDs) in
 *     its env.
 *   - when a check has no quarantine (or an empty list), the env var
 *     is NOT set — preserving zero behavior change for repos that
 *     don't use the feature.
 *   - the resulting `CheckResult.quarantine` carries the entries
 *     verbatim so the merge code can fold them into the signed
 *     attestation envelope.
 *
 * Quarantine doesn't change exit-code semantics — stamp never strips
 * the check itself, it only surfaces the list to the operator's
 * command. These tests use trivial shell commands to inspect the env
 * variable; the operator's real test runner would consume the same
 * env var in its own filter logic.
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import { runChecks, QUARANTINE_ENV_VAR } from "../src/lib/checks.ts";
import type { CheckDef } from "../src/lib/config.ts";

let cwd: string;

beforeEach(() => {
  cwd = mkdtempSync(join(tmpdir(), "stamp-quarantine-runner-"));
});

afterEach(() => {
  rmSync(cwd, { recursive: true, force: true });
});

describe("AGT-476 runChecks quarantine env-var pass-through", () => {
  it("does not set STAMP_QUARANTINE_TESTS when no quarantine is configured", () => {
    // The command echoes the env var (or the literal token if unset).
    // We can't read the var directly from runChecks; we read it via
    // the command's stdout, which is hashed into output_sha. So we
    // instead assert exit_code: the command `[ -z "$STAMP_QUARANTINE_TESTS" ]`
    // succeeds (exit 0) when unset.
    const checks: CheckDef[] = [
      { name: "no-q", run: `[ -z "$${QUARANTINE_ENV_VAR}" ]` },
    ];
    const results = runChecks(checks, cwd);
    assert.equal(results.length, 1);
    assert.equal(results[0]?.exit_code, 0, "env var should be unset");
    assert.equal("quarantine" in results[0]!, false);
  });

  it("sets STAMP_QUARANTINE_TESTS to comma-joined test IDs when quarantine is configured", () => {
    const checks: CheckDef[] = [
      {
        name: "with-q",
        run: `[ "$${QUARANTINE_ENV_VAR}" = "tests/a.test.ts,tests/b.test.ts" ]`,
        quarantine: [
          { test: "tests/a.test.ts", reason: "flaky a" },
          { test: "tests/b.test.ts", reason: "flaky b" },
        ],
      },
    ];
    const results = runChecks(checks, cwd);
    assert.equal(results.length, 1);
    assert.equal(
      results[0]?.exit_code,
      0,
      "env var should equal the comma-joined test IDs",
    );
  });

  it("forwards the quarantine list onto CheckResult verbatim", () => {
    const checks: CheckDef[] = [
      {
        name: "with-q",
        run: "true",
        quarantine: [
          { test: "tests/a.test.ts", reason: "flaky a" },
          { test: "tests/b.test.ts", reason: "flaky b" },
        ],
      },
    ];
    const results = runChecks(checks, cwd);
    assert.deepEqual(results[0]?.quarantine, [
      { test: "tests/a.test.ts", reason: "flaky a" },
      { test: "tests/b.test.ts", reason: "flaky b" },
    ]);
  });

  it("does not set the env var for a check with an empty quarantine list", () => {
    // An empty list shouldn't trigger the env-var path (preserves
    // byte-identity for envelopes from scaffolded-but-empty configs).
    const checks: CheckDef[] = [
      {
        name: "empty-q",
        run: `[ -z "$${QUARANTINE_ENV_VAR}" ]`,
        quarantine: [],
      },
    ];
    const results = runChecks(checks, cwd);
    assert.equal(results[0]?.exit_code, 0);
    assert.equal("quarantine" in results[0]!, false);
  });

  it("does not perturb PATH/HOME/etc when injecting STAMP_QUARANTINE_TESTS", () => {
    // Defense-in-depth: the operator's check command depends on PATH
    // (to find `npm`, `npx`, etc.) and HOME (for tool caches). The
    // env-var pass-through must MERGE the new var, not replace
    // process.env wholesale.
    const checks: CheckDef[] = [
      {
        name: "path-preserved",
        run: 'test -n "$PATH" && test -n "$HOME"',
        quarantine: [{ test: "x", reason: "y" }],
      },
    ];
    const results = runChecks(checks, cwd);
    assert.equal(results[0]?.exit_code, 0, "PATH and HOME must still be set");
  });
});
