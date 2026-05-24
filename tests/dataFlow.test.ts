/**
 * AGT-415 — data-flow disclosure + consent for `stamp review`.
 *
 * Covers the four behaviours and the config parsing they hang off:
 *   - per-invocation marker (AC #1): fires every run, silenced by suppress env
 *   - disclosure echo (AC #2): present when committed, absent otherwise
 *   - confirmed gate (AC #3): refuses armed-but-unconfirmed, proceeds when
 *     confirmed, no-ops for disclosure-only / absent blocks
 *   - no-retain warning (AC #4): loud no-op notice when the flag is set
 *   - config parse: data_flow round-trips, stays optional + additive, types validated
 */

import { strict as assert } from "node:assert";
import { afterEach, beforeEach, describe, it } from "node:test";

import { parseConfigFromYaml } from "../src/lib/config.ts";
import type { DataFlowConfig } from "../src/lib/config.ts";
import {
  assertDataFlowConfirmed,
  formatDataFlowDisclosure,
  formatDiffSentMarker,
  formatNoRetainWarning,
  printDataFlowDisclosure,
  printDiffSentMarker,
} from "../src/lib/dataFlow.ts";

// Capture everything written to process.stderr during `fn`.
function captureStderr(fn: () => void): string {
  const orig = process.stderr.write.bind(process.stderr);
  let out = "";
  // @ts-expect-error narrow override of the write signature for the test
  process.stderr.write = (chunk: string | Uint8Array): boolean => {
    out += typeof chunk === "string" ? chunk : Buffer.from(chunk).toString();
    return true;
  };
  try {
    fn();
  } finally {
    process.stderr.write = orig;
  }
  return out;
}

const BASE_CONFIG = `
branches:
  main:
    required: [security]
reviewers:
  security:
    prompt: .stamp/reviewers/security.md
`;

describe("data_flow config parsing", () => {
  it("absence leaves data_flow undefined (additive / back-compat)", () => {
    const cfg = parseConfigFromYaml(BASE_CONFIG);
    assert.equal(cfg.data_flow, undefined);
  });

  it("parses disclosure + require_confirmation + confirmed", () => {
    const cfg = parseConfigFromYaml(
      BASE_CONFIG +
        `
data_flow:
  disclosure: "Diffs go to Anthropic (sub-processor)."
  require_confirmation: true
  confirmed: true
`,
    );
    assert.deepEqual(cfg.data_flow, {
      disclosure: "Diffs go to Anthropic (sub-processor).",
      require_confirmation: true,
      confirmed: true,
    });
  });

  it("rejects non-object data_flow", () => {
    assert.throws(
      () => parseConfigFromYaml(BASE_CONFIG + `\ndata_flow: "nope"\n`),
      /config\.data_flow must be an object/,
    );
  });

  it("rejects non-boolean require_confirmation / confirmed", () => {
    assert.throws(
      () =>
        parseConfigFromYaml(
          BASE_CONFIG + `\ndata_flow:\n  require_confirmation: "yes"\n`,
        ),
      /require_confirmation must be a boolean/,
    );
    assert.throws(
      () => parseConfigFromYaml(BASE_CONFIG + `\ndata_flow:\n  confirmed: 1\n`),
      /confirmed must be a boolean/,
    );
  });

  it("rejects non-string disclosure", () => {
    assert.throws(
      () => parseConfigFromYaml(BASE_CONFIG + `\ndata_flow:\n  disclosure: 42\n`),
      /disclosure must be a string/,
    );
  });
});

describe("assertDataFlowConfirmed (AC #3 gate)", () => {
  it("no-ops when there is no data_flow block", () => {
    assert.doesNotThrow(() => assertDataFlowConfirmed(undefined));
  });

  it("no-ops for a disclosure-only block (gate not armed)", () => {
    const df: DataFlowConfig = { disclosure: "hi" };
    assert.doesNotThrow(() => assertDataFlowConfirmed(df));
  });

  it("no-ops when require_confirmation is false", () => {
    assert.doesNotThrow(() =>
      assertDataFlowConfirmed({ require_confirmation: false }),
    );
  });

  it("refuses when armed but unconfirmed", () => {
    assert.throws(
      () => assertDataFlowConfirmed({ require_confirmation: true }),
      /data_flow\.require_confirmation is set.*refusing to run/s,
    );
  });

  it("refuses when armed and confirmed is explicitly false", () => {
    assert.throws(
      () =>
        assertDataFlowConfirmed({
          require_confirmation: true,
          confirmed: false,
        }),
      /refusing to run/,
    );
  });

  it("proceeds when armed and confirmed: true", () => {
    assert.doesNotThrow(() =>
      assertDataFlowConfirmed({
        require_confirmation: true,
        confirmed: true,
      }),
    );
  });
});

describe("per-invocation marker (AC #1)", () => {
  let savedSuppress: string | undefined;
  beforeEach(() => {
    savedSuppress = process.env.STAMP_SUPPRESS_LLM_NOTICE;
    delete process.env.STAMP_SUPPRESS_LLM_NOTICE;
  });
  afterEach(() => {
    if (savedSuppress === undefined)
      delete process.env.STAMP_SUPPRESS_LLM_NOTICE;
    else process.env.STAMP_SUPPRESS_LLM_NOTICE = savedSuppress;
  });

  it("names off-host transport + reviewer count, pluralized", () => {
    assert.match(formatDiffSentMarker(3), /diff sent off-host/);
    assert.match(formatDiffSentMarker(3), /3 reviewers/);
    assert.match(formatDiffSentMarker(1), /1 reviewer\b/);
  });

  it("fires on every invocation", () => {
    const out = captureStderr(() => {
      printDiffSentMarker(2);
      printDiffSentMarker(2);
    });
    const lines = out.trim().split("\n");
    assert.equal(lines.length, 2);
  });

  it("is silenced by STAMP_SUPPRESS_LLM_NOTICE=1", () => {
    process.env.STAMP_SUPPRESS_LLM_NOTICE = "1";
    const out = captureStderr(() => printDiffSentMarker(2));
    assert.equal(out, "");
  });
});

describe("disclosure echo (AC #2)", () => {
  let savedSuppress: string | undefined;
  beforeEach(() => {
    savedSuppress = process.env.STAMP_SUPPRESS_LLM_NOTICE;
    delete process.env.STAMP_SUPPRESS_LLM_NOTICE;
  });
  afterEach(() => {
    if (savedSuppress === undefined)
      delete process.env.STAMP_SUPPRESS_LLM_NOTICE;
    else process.env.STAMP_SUPPRESS_LLM_NOTICE = savedSuppress;
  });

  it("returns null when no disclosure present", () => {
    assert.equal(formatDataFlowDisclosure(undefined), null);
    assert.equal(formatDataFlowDisclosure({ require_confirmation: true }), null);
    assert.equal(formatDataFlowDisclosure({ disclosure: "  " }), null);
  });

  it("renders the committed disclosure text", () => {
    const block = formatDataFlowDisclosure({ disclosure: "PHI under review." });
    assert.ok(block);
    assert.match(block!, /PHI under review\./);
  });

  it("echoes to stderr when present, nothing when absent", () => {
    const withText = captureStderr(() =>
      printDataFlowDisclosure({ disclosure: "send-to-anthropic" }),
    );
    assert.match(withText, /send-to-anthropic/);
    const without = captureStderr(() => printDataFlowDisclosure(undefined));
    assert.equal(without, "");
  });

  it("is silenced by STAMP_SUPPRESS_LLM_NOTICE=1", () => {
    process.env.STAMP_SUPPRESS_LLM_NOTICE = "1";
    const out = captureStderr(() =>
      printDataFlowDisclosure({ disclosure: "secret" }),
    );
    assert.equal(out, "");
  });
});

describe("no-retain warning (AC #4)", () => {
  let saved: string | undefined;
  beforeEach(() => {
    saved = process.env.STAMP_ANTHROPIC_NO_RETAIN;
  });
  afterEach(() => {
    if (saved === undefined) delete process.env.STAMP_ANTHROPIC_NO_RETAIN;
    else process.env.STAMP_ANTHROPIC_NO_RETAIN = saved;
  });

  it("returns null when the flag is unset", () => {
    delete process.env.STAMP_ANTHROPIC_NO_RETAIN;
    assert.equal(formatNoRetainWarning(), null);
  });

  it("only fires on the literal '1'", () => {
    for (const v of ["0", "true", "yes", ""]) {
      process.env.STAMP_ANTHROPIC_NO_RETAIN = v;
      assert.equal(formatNoRetainWarning(), null, `value ${JSON.stringify(v)}`);
    }
  });

  it("warns it is a NO-OP and points at the real options when set", () => {
    process.env.STAMP_ANTHROPIC_NO_RETAIN = "1";
    const warning = formatNoRetainWarning();
    assert.ok(warning);
    assert.match(warning!, /NO-OP/);
    assert.match(warning!, /account-level|ZDR/);
    assert.match(warning!, /STAMP_NO_LLM/);
  });
});
