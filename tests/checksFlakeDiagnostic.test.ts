/**
 * Tests for the vitest fork-pool worker-startup-timeout diagnostic
 * detector in src/lib/checks.ts (AGT-470).
 *
 * Pins the contract that `detectVitestForkPoolFlake`:
 *   1. Fires on the canonical vitest signature (`Failed to start forks worker`).
 *   2. Does NOT fire on real test-assertion failures, dependency-resolution
 *      errors, generic "worker" / "forks" output, or empty input.
 *
 * Also asserts that the diagnostic constant names the suspected root cause
 * (macOS syspolicyd ExecPolicy DB bloat) so AC#1's "clearly-labelled" and
 * "naming the suspected root cause" requirements stay enforced if someone
 * later edits the prose.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  VITEST_FORK_POOL_FLAKE_DIAGNOSTIC,
  detectVitestForkPoolFlake,
} from "../src/lib/checks.ts";

describe("detectVitestForkPoolFlake", () => {
  it("matches the canonical vitest fork-pool startup-timeout line", () => {
    const fixture = [
      " RUN  v3.0.0 /repo",
      "",
      "Error: Failed to start forks worker after 60000ms timeout",
      "    at Timeout._onTimeout (/repo/node_modules/vitest/dist/chunks/forks.js:42:13)",
      "",
      "FAIL  tests/daemon/status.test.ts",
    ].join("\n");
    assert.equal(detectVitestForkPoolFlake(fixture), true);
  });

  it("matches when the signature appears embedded in a longer stderr tail", () => {
    const fixture =
      "noise noise noise\n" +
      "stack frame stack frame\n" +
      "Failed to start forks worker\n" +
      "more noise after\n";
    assert.equal(detectVitestForkPoolFlake(fixture), true);
  });

  it("does NOT match a real test-assertion failure", () => {
    const fixture = [
      " FAIL  tests/foo.test.ts > foo > bar",
      "AssertionError: expected 1 to equal 2",
      "  Expected: 2",
      "  Received: 1",
      "    at /repo/tests/foo.test.ts:10:5",
    ].join("\n");
    assert.equal(detectVitestForkPoolFlake(fixture), false);
  });

  it("does NOT match a dependency-resolution error", () => {
    const fixture = [
      "npm error code E404",
      "npm error 404 Not Found - GET https://registry.npmjs.org/missing-pkg",
      "npm error 404 'missing-pkg@*' is not in this registry.",
    ].join("\n");
    assert.equal(detectVitestForkPoolFlake(fixture), false);
  });

  it("does NOT match output that merely mentions 'worker' or 'forks'", () => {
    const fixture = [
      "Worker initialized OK",
      "Using forks pool with maxForks=4",
      "All tests passed",
    ].join("\n");
    assert.equal(detectVitestForkPoolFlake(fixture), false);
  });

  it("does NOT match empty or whitespace-only output", () => {
    assert.equal(detectVitestForkPoolFlake(""), false);
    assert.equal(detectVitestForkPoolFlake("   \n  \n"), false);
  });
});

describe("VITEST_FORK_POOL_FLAKE_DIAGNOSTIC", () => {
  it("names the suspected root cause (syspolicyd ExecPolicy DB bloat)", () => {
    // AC#1 requires the diagnostic to NAME the suspected cause — if someone
    // later edits the prose and drops the cause-naming, this test catches it.
    assert.match(VITEST_FORK_POOL_FLAKE_DIAGNOSTIC, /syspolicyd/i);
    assert.match(VITEST_FORK_POOL_FLAKE_DIAGNOSTIC, /ExecPolicy/);
  });

  it("points at the documented recovery path (reboot)", () => {
    // AC#1 requires the diagnostic to point at the recovery path.
    assert.match(VITEST_FORK_POOL_FLAKE_DIAGNOSTIC, /reboot/i);
  });

  it("distinguishes the flake from a real test failure in its prose", () => {
    // AC#1's "clearly-labelled diagnostic line distinguishing it from a real
    // test failure" — assert the prose actually says so.
    assert.match(VITEST_FORK_POOL_FLAKE_DIAGNOSTIC, /NOT a real\s+test failure/i);
  });
});
