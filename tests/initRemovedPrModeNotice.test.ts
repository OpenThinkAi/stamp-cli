// Characterizes the removal tombstone for the Shape 2 `--pr-mode` /
// `--pr-mode-force` flags (removed in the Shape 2/3 cleanup, AGT-407 C5).
// The shim turns commander's bare "unknown option" into an actionable
// removal notice; the caller exits 2 (invalid-usage convention).

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { removedPrModeNotice } from "../src/commands/init.ts";

describe("removedPrModeNotice", () => {
  it("returns null when no removed flag is present", () => {
    assert.equal(removedPrModeNotice(["node", "stamp", "init"]), null);
    assert.equal(
      removedPrModeNotice(["node", "stamp", "init", "--mode", "local-only"]),
      null,
    );
  });

  it("detects --pr-mode and names it in an actionable notice", () => {
    const lines = removedPrModeNotice(["node", "stamp", "init", "--pr-mode"]);
    assert.ok(lines, "expected a notice for --pr-mode");
    assert.equal(lines.length, 2);
    assert.match(lines[0], /^error: '--pr-mode' was removed in stamp 2\.x/);
    assert.match(lines[0], /Shape 4/);
    assert.match(lines[1], /^note: /);
    assert.match(lines[1], /migration-1\.x-to-2\.x\.md/);
  });

  it("detects --pr-mode-force and names that exact flag", () => {
    const lines = removedPrModeNotice([
      "node",
      "stamp",
      "init",
      "--pr-mode-force",
    ]);
    assert.ok(lines, "expected a notice for --pr-mode-force");
    assert.match(lines[0], /'--pr-mode-force'/);
  });

  it("does not match unrelated flags that share a prefix", () => {
    // --pr-mode-ish or --mode must not trip the exact-match guard.
    assert.equal(
      removedPrModeNotice(["node", "stamp", "init", "--pr-mode-ish"]),
      null,
    );
    assert.equal(removedPrModeNotice(["node", "stamp", "review"]), null);
  });
});
