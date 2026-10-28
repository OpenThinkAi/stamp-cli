import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { escapeLogControls, stripTerminalControls } from "../src/lib/terminalText.ts";
import { verbCrashLine } from "../src/server/verbCrash.ts";
import { PromptFetchFailedError } from "../src/server/reviewPipeline.ts";

describe("stripTerminalControls (AGT-2270)", () => {
  it("removes CSI/OSC sequences and stray controls, keeps newline and tab", () => {
    const hostile = "a\u001b[2J\u001b[1;1Hb\u001b]0;pwned\u0007c\u001b]8;;http://x\u001b\\d\r\u0007e\u009bf\tg\nh";
    assert.equal(stripTerminalControls(hostile), "abcdef\tg\nh");
  });
  it("leaves ordinary unicode alone", () => {
    assert.equal(stripTerminalControls("⟳ claimed seat 1 — ok"), "⟳ claimed seat 1 — ok");
  });
});

describe("escapeLogControls (AGT-2270)", () => {
  it("renders line breaks and controls visibly so a value cannot forge a log line", () => {
    const v = 'x\nstamp-http-server 2026 info fake\r\u001b\u2028';
    const out = escapeLogControls(`reviewer_filter name "${v}" not found`);
    assert.doesNotMatch(out, /[\n\r\u001b\u2028]/);
    assert.ok(out.includes("x\\nstamp-http-server 2026 info fake\\r\\x1b\\u2028"), out);
  });
});

describe("verbCrashLine (AGT-2270)", () => {
  it("prints the error class and first message line, never the stack", () => {
    const err = new TypeError("boom\nsecond line");
    const line = verbCrashLine("stamp-review", err);
    assert.equal(line, "error: stamp-review failed: TypeError: boom\n");
    assert.doesNotMatch(line, / at /);
  });
  it("keeps PromptFetchFailedError's server-side detail out of the message", () => {
    const err = new PromptFetchFailedError("no_such_file", "prompt cache miss: /srv/git/.prompts-cache/x.md", "security");
    const line = verbCrashLine("stamp-review", err);
    assert.doesNotMatch(line, /\/srv\/git/);
    assert.match(line, /canonical prompt fetch failed \(no_such_file\) for reviewer "security"/);
    assert.match(err.detail, /\/srv\/git/);
  });
});
