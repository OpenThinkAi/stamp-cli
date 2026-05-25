/**
 * Unit tests for AGT-246: MCP server launch/connection failure detection.
 *
 * Tests the exported `classifyMcpServers` function directly — same approach
 * as `reviewer-canusetool.test.ts` tests `checkReviewerTool` directly and
 * `dotstampReads.test.ts` tests `findMissingDotstampReads` directly. No SDK
 * loop needed; the classification logic is pure.
 *
 * Four scenarios from the spike:
 *   (a) All declared servers connected → proceed, entries recorded.
 *   (b) Non-optional failed server → appears in nonOptionalFailures.
 *   (c) Optional failed server → appears in optionalFailures, NOT nonOptionalFailures.
 *   (d) `pending` past init treated as failure for non-optional.
 *
 * Hash-stability:
 *   Asserts that `hashMcpServers` on a config without `optional` is byte-
 *   identical to one parsed with `optional` unset (omit-on-unset back-compat).
 *   And that explicitly setting `optional: true` DOES change the hash.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { classifyMcpServers } from "../src/lib/reviewer.ts";
import { hashMcpServers } from "../src/lib/reviewerHash.ts";
import { parseConfigFromYaml } from "../src/lib/config.ts";

// ---------------------------------------------------------------------------
// classifyMcpServers: happy path — all servers connected
// ---------------------------------------------------------------------------
describe("classifyMcpServers — all connected", () => {
  it("returns empty failure lists and one entry per init server", () => {
    const initServers = [
      { name: "linear", status: "connected" },
      { name: "stamp-verdict", status: "connected" },
    ];
    const declaredServers = {
      linear: { command: "npx", args: ["-y", "@tacticlabs/linear-mcp-server"] },
    };
    const richStatuses: Array<{ name: string; status: string; error?: string }> = [];

    const { entries, nonOptionalFailures, optionalFailures } =
      classifyMcpServers(initServers, declaredServers, richStatuses);

    assert.equal(entries.length, 2, "one entry per init server");
    assert.equal(nonOptionalFailures.length, 0);
    assert.equal(optionalFailures.length, 0);

    const linearEntry = entries.find((e) => e.name === "linear")!;
    assert.ok(linearEntry);
    assert.equal(linearEntry.status, "connected");
    assert.equal(linearEntry.declared, true);
    assert.equal(linearEntry.optional, false);

    // stamp-verdict is not in declaredServers — it should be declared=false
    const verdictEntry = entries.find((e) => e.name === "stamp-verdict")!;
    assert.ok(verdictEntry);
    assert.equal(verdictEntry.declared, false);
  });

  it("returns the init server status when richStatuses is empty (happy-path no traffic)", () => {
    const initServers = [{ name: "linear", status: "connected" }];
    const declaredServers = {
      linear: { command: "npx" },
    };

    const { entries } = classifyMcpServers(initServers, declaredServers, []);
    assert.equal(entries[0]!.status, "connected");
  });
});

// ---------------------------------------------------------------------------
// classifyMcpServers: non-optional failure → nonOptionalFailures
// ---------------------------------------------------------------------------
describe("classifyMcpServers — non-optional failed server", () => {
  it("puts a non-optional failed server into nonOptionalFailures with name and status", () => {
    const initServers = [{ name: "linear", status: "failed" }];
    const declaredServers = {
      linear: { command: "npx" },
      // optional is absent → defaults to false
    };
    const richStatuses = [
      { name: "linear", status: "failed", error: "spawn ENOENT" },
    ];

    const { entries, nonOptionalFailures, optionalFailures } =
      classifyMcpServers(initServers, declaredServers, richStatuses);

    assert.equal(nonOptionalFailures.length, 1);
    assert.equal(optionalFailures.length, 0);
    assert.equal(entries.length, 1);

    const entry = nonOptionalFailures[0]!;
    assert.equal(entry.name, "linear");
    assert.equal(entry.status, "failed");
    assert.equal(entry.optional, false);
    assert.equal(entry.declared, true);
    assert.equal(entry.error, "spawn ENOENT");
  });

  it("uses richStatuses error string rather than absent error from init message", () => {
    const initServers = [{ name: "linear", status: "failed" }];
    const declaredServers = { linear: { command: "npx" } };
    const richStatuses = [{ name: "linear", status: "failed", error: "connection refused" }];

    const { nonOptionalFailures } = classifyMcpServers(
      initServers,
      declaredServers,
      richStatuses,
    );

    assert.equal(nonOptionalFailures[0]!.error, "connection refused");
  });

  it("does NOT fail on stamp-verdict even if it appears failed (stamp-internal)", () => {
    const initServers = [
      { name: "stamp-verdict", status: "failed" },
      { name: "linear", status: "connected" },
    ];
    // stamp-verdict is NOT in declaredServers (it's stamp-internal)
    const declaredServers = { linear: { command: "npx" } };

    const { nonOptionalFailures, optionalFailures } = classifyMcpServers(
      initServers,
      declaredServers,
      [],
    );

    assert.equal(nonOptionalFailures.length, 0, "stamp-verdict must not trigger failure");
    assert.equal(optionalFailures.length, 0);
  });
});

// ---------------------------------------------------------------------------
// classifyMcpServers: optional failure → optionalFailures, not nonOptionalFailures
// ---------------------------------------------------------------------------
describe("classifyMcpServers — optional failed server", () => {
  it("puts an optional failed server into optionalFailures, not nonOptionalFailures", () => {
    const initServers = [{ name: "linear", status: "failed" }];
    const declaredServers = {
      linear: { command: "npx", optional: true },
    };
    const richStatuses = [{ name: "linear", status: "failed", error: "timed out" }];

    const { entries, nonOptionalFailures, optionalFailures } =
      classifyMcpServers(initServers, declaredServers, richStatuses);

    assert.equal(nonOptionalFailures.length, 0);
    assert.equal(optionalFailures.length, 1);
    assert.equal(entries.length, 1);

    const entry = optionalFailures[0]!;
    assert.equal(entry.name, "linear");
    assert.equal(entry.optional, true);
    assert.equal(entry.error, "timed out");
  });

  it("correctly separates optional and non-optional failures in the same call", () => {
    const initServers = [
      { name: "linear", status: "failed" },
      { name: "github", status: "failed" },
    ];
    const declaredServers = {
      linear: { command: "npx", optional: true },
      github: { command: "npx" }, // non-optional
    };
    const richStatuses: Array<{ name: string; status: string; error?: string }> = [];

    const { nonOptionalFailures, optionalFailures } =
      classifyMcpServers(initServers, declaredServers, richStatuses);

    assert.equal(nonOptionalFailures.length, 1);
    assert.equal(nonOptionalFailures[0]!.name, "github");
    assert.equal(optionalFailures.length, 1);
    assert.equal(optionalFailures[0]!.name, "linear");
  });
});

// ---------------------------------------------------------------------------
// classifyMcpServers: `pending` past init treated as failure
// ---------------------------------------------------------------------------
describe("classifyMcpServers — pending status treated as failure", () => {
  it("treats pending as a non-optional failure for a non-optional server", () => {
    const initServers = [{ name: "linear", status: "pending" }];
    const declaredServers = { linear: { command: "npx" } };

    const { nonOptionalFailures, optionalFailures } = classifyMcpServers(
      initServers,
      declaredServers,
      [],
    );

    assert.equal(nonOptionalFailures.length, 1, "pending must be treated as failure");
    assert.equal(nonOptionalFailures[0]!.status, "pending");
    assert.equal(optionalFailures.length, 0);
  });

  it("treats pending as an optional failure for an optional server", () => {
    const initServers = [{ name: "linear", status: "pending" }];
    const declaredServers = { linear: { command: "npx", optional: true } };

    const { nonOptionalFailures, optionalFailures } = classifyMcpServers(
      initServers,
      declaredServers,
      [],
    );

    assert.equal(nonOptionalFailures.length, 0);
    assert.equal(optionalFailures.length, 1, "pending optional must be in optionalFailures");
  });

  it("treats needs-auth as a non-optional failure", () => {
    const { nonOptionalFailures } = classifyMcpServers(
      [{ name: "github", status: "needs-auth" }],
      { github: { command: "npx" } },
      [],
    );
    assert.equal(nonOptionalFailures.length, 1);
    assert.equal(nonOptionalFailures[0]!.status, "needs-auth");
  });

  it("treats disabled as a non-optional failure", () => {
    const { nonOptionalFailures } = classifyMcpServers(
      [{ name: "github", status: "disabled" }],
      { github: { command: "npx" } },
      [],
    );
    assert.equal(nonOptionalFailures.length, 1);
  });
});

// ---------------------------------------------------------------------------
// Hash-stability: optional field omit-on-unset
// ---------------------------------------------------------------------------
describe("hashMcpServers — optional field hash stability (AGT-246)", () => {
  it("hashMcpServers is byte-identical when `optional` is absent vs. explicitly false via config parse", () => {
    // Without optional at all (existing configs before AGT-246)
    const before = hashMcpServers({
      linear: {
        command: "npx",
        args: ["-y", "@tacticlabs/linear-mcp-server"],
        env: { LINEAR_API_KEY: "$LINEAR_API_KEY" },
      },
    });

    // Parsed config that has no `optional` field (omit-on-unset)
    const cfgYaml = `
branches:
  main: { required: [r] }
reviewers:
  r:
    prompt: ./r.md
    mcp_servers:
      linear:
        command: npx
        args: ["-y", "@tacticlabs/linear-mcp-server"]
        env:
          LINEAR_API_KEY: $LINEAR_API_KEY
`;
    const parsed = parseConfigFromYaml(cfgYaml);
    const afterParse = hashMcpServers(parsed.reviewers.r!.mcp_servers!);

    assert.equal(
      before,
      afterParse,
      "parsing a config without optional must not drift hashMcpServers",
    );
  });

  it("setting optional: true produces a DIFFERENT hash (config change is intentional drift)", () => {
    const withoutOptional = hashMcpServers({
      linear: { command: "npx", args: ["-y", "@tacticlabs/linear-mcp-server"] },
    });

    const cfgYaml = `
branches:
  main: { required: [r] }
reviewers:
  r:
    prompt: ./r.md
    mcp_servers:
      linear:
        command: npx
        args: ["-y", "@tacticlabs/linear-mcp-server"]
        optional: true
`;
    const parsed = parseConfigFromYaml(cfgYaml);
    const withOptionalTrue = hashMcpServers(parsed.reviewers.r!.mcp_servers!);

    assert.notEqual(
      withoutOptional,
      withOptionalTrue,
      "setting optional: true must change the mcp_sha256 hash",
    );
  });

  it("setting optional: false also produces a different hash (explicit false != absent)", () => {
    // Rationale: explicit `optional: false` in YAML is a meaningful config
    // assertion; it should enter the hash so operators can see when it was
    // added or removed. This is consistent with how `allowed_env: []` works.
    const withoutOptional = hashMcpServers({
      linear: { command: "npx" },
    });

    const cfgYaml = `
branches:
  main: { required: [r] }
reviewers:
  r:
    prompt: ./r.md
    mcp_servers:
      linear:
        command: npx
        optional: false
`;
    const parsed = parseConfigFromYaml(cfgYaml);
    const withOptionalFalse = hashMcpServers(parsed.reviewers.r!.mcp_servers!);

    assert.notEqual(
      withoutOptional,
      withOptionalFalse,
      "explicit optional: false must change the hash relative to absent optional",
    );
  });
});

// ---------------------------------------------------------------------------
// Config parsing: optional field validation
// ---------------------------------------------------------------------------
describe("parseMcpServers — optional field", () => {
  const cfg = (optionalVal: unknown) => `
branches:
  main: { required: [r] }
reviewers:
  r:
    prompt: ./r.md
    mcp_servers:
      linear:
        command: npx
        args: ["-y", "@tacticlabs/linear-mcp-server"]
        optional: ${JSON.stringify(optionalVal)}
`;

  it("accepts optional: true and reflects it on the parsed McpServerDef", () => {
    const c = parseConfigFromYaml(cfg(true));
    const srv = c.reviewers.r!.mcp_servers!.linear!;
    assert.equal(srv.optional, true);
  });

  it("accepts optional: false and reflects it on the parsed McpServerDef", () => {
    const c = parseConfigFromYaml(cfg(false));
    const srv = c.reviewers.r!.mcp_servers!.linear!;
    assert.equal(srv.optional, false);
  });

  it("rejects optional when it is a string", () => {
    assert.throws(
      () => parseConfigFromYaml(cfg("true")),
      /optional must be a boolean/,
    );
  });

  it("rejects optional when it is a number", () => {
    assert.throws(
      () => parseConfigFromYaml(cfg(1)),
      /optional must be a boolean/,
    );
  });

  it("omits optional from the parsed McpServerDef when not set in YAML", () => {
    const cfgYaml = `
branches:
  main: { required: [r] }
reviewers:
  r:
    prompt: ./r.md
    mcp_servers:
      linear:
        command: npx
`;
    const c = parseConfigFromYaml(cfgYaml);
    const srv = c.reviewers.r!.mcp_servers!.linear!;
    // Must be undefined (not false) when absent — omit-on-unset
    assert.equal(srv.optional, undefined);
    assert.ok(!Object.prototype.hasOwnProperty.call(srv, "optional"));
  });
});
