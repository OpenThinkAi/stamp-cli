/**
 * Unit tests for `src/lib/renderCheck.ts` — the ANSI/box-drawing
 * primitives behind `stamp verify-pr`'s CI check output.
 *
 * The renderer is pure string-in/string-out (color passed explicitly),
 * so these tests assert on structure: table frames, column sizing,
 * flex-column wrapping, ANSI stripping in width math, NO_COLOR/CI
 * detection, and markdown cell escaping. The verify-pr composition on
 * top of these primitives is covered by tests/verifyPr.test.ts's
 * exit-code + stderr-reason contracts (deliberately format-agnostic).
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { colorEnabled, mdCell, paint, table, wrap } from "../src/lib/renderCheck.js";

describe("paint", () => {
  it("wraps text in SGR codes when color is on", () => {
    const p = paint(true);
    assert.equal(p("hi", "1", "32"), "\x1b[1;32mhi\x1b[0m");
  });

  it("is the identity when color is off or no codes given", () => {
    const p = paint(false);
    assert.equal(p("hi", "1"), "hi");
    assert.equal(paint(true)("hi"), "hi");
  });
});

describe("colorEnabled", () => {
  it("NO_COLOR disables even inside GitHub Actions", () => {
    assert.equal(colorEnabled({ NO_COLOR: "", GITHUB_ACTIONS: "true" }), false);
  });

  it("GITHUB_ACTIONS=true enables without a TTY", () => {
    assert.equal(colorEnabled({ GITHUB_ACTIONS: "true" }), true);
  });
});

describe("wrap", () => {
  it("wraps at word boundaries within the width", () => {
    assert.deepEqual(wrap("one two three", 7), ["one two", "three"]);
  });

  it("hard-breaks words longer than the column", () => {
    assert.deepEqual(wrap("abcdefgh", 4), ["abcd", "efgh"]);
  });
});

describe("table", () => {
  it("renders a framed table sized to content", () => {
    const t = table(
      [{ header: "check" }, { header: "result" }],
      [["integrity", "valid"]],
      { color: false, maxWidth: 80 },
    );
    const lines = t.split("\n");
    assert.equal(lines.length, 5); // top, header, divider, row, bottom
    assert.ok(lines[0]!.startsWith("┌") && lines[0]!.endsWith("┐"));
    assert.ok(lines[1]!.includes("check") && lines[1]!.includes("result"));
    assert.ok(lines[3]!.includes("integrity"));
    // All frame lines are the same visible width.
    const widths = new Set(lines.map((l) => l.length));
    assert.equal(widths.size, 1);
  });

  it("wraps the flex column to the width budget", () => {
    const long = "a finding sentence that is far too long to fit the budget";
    const t = table(
      [{ header: "k" }, { header: "v", flex: true }],
      [["x", long]],
      { color: false, maxWidth: 40 },
    );
    // Row spills across multiple physical lines, none wider than budget.
    const lines = t.split("\n");
    assert.ok(lines.length > 5);
    for (const l of lines) assert.ok(l.length <= 40, `line too wide: ${l}`);
  });

  it("measures cell width ignoring ANSI escapes", () => {
    const p = paint(true);
    const plain = table([{ header: "k" }], [["value"]], { color: false, maxWidth: 80 });
    const painted = table([{ header: "k" }], [[p("value", "32")]], {
      color: false,
      maxWidth: 80,
    });
    // Same frame geometry whether or not the cell carries color.
    assert.equal(
      plain.split("\n")[0]!.length,
      painted.split("\n")[0]!.length,
    );
  });
});

describe("mdCell", () => {
  it("escapes pipes and flattens newlines", () => {
    assert.equal(mdCell("a|b\nc"), "a\\|b c");
  });
});
