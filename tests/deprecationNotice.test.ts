/**
 * Tests for the bridge-release deprecation banner (AGT-346).
 *
 * Hard contracts:
 *   - banner goes to stderr (not stdout) so it never contaminates
 *     command output parsers
 *   - banner names the migration guide (`docs/migration-1.x-to-2.x.md`)
 *     so an operator who sees the line can find the upgrade path
 *     without further hunting
 *   - banner names the suppression env var by its exact spelling so
 *     ops can grep their CLI output for the suppression hint and
 *     copy-paste it into their CI config
 *   - STAMP_SUPPRESS_DEPRECATION=1 suppresses entirely (no write to
 *     stderr at all — important so CI logs aren't padded by the
 *     banner repeated per invocation)
 *   - any value other than the exact string "1" does NOT suppress
 *     (defends against `STAMP_SUPPRESS_DEPRECATION=""` silently
 *     disabling, mirroring the STAMP_REQUIRE_HUMAN_MERGE convention)
 *   - **banner is silent on stamp 2.x+** — only fires for the
 *     installed-1.x audience the bridge banner was designed for.
 *     The version is read from the installed package.json; tests
 *     pass `versionOverride` to avoid touching disk.
 *
 * Approach mirrors tests/humanMerge.test.ts: monkey-patch
 * process.stderr.write, capture, restore.
 */

import { strict as assert } from "node:assert";
import { afterEach, beforeEach, describe, it } from "node:test";

import { maybePrintDeprecationNotice } from "../src/lib/deprecationNotice.ts";

describe("maybePrintDeprecationNotice", () => {
  let savedEnv: string | undefined;
  let savedWrite: typeof process.stderr.write;
  let captured: string[];

  beforeEach(() => {
    savedEnv = process.env.STAMP_SUPPRESS_DEPRECATION;
    delete process.env.STAMP_SUPPRESS_DEPRECATION;
    captured = [];
    savedWrite = process.stderr.write.bind(process.stderr);
    // Replace stderr.write with a capturing stub. We cast through
    // `{ write: unknown }` because node's `process.stderr.write` has
    // several overloads (Buffer / string / encoding / callback) and the
    // runtime only cares that the function exists and returns truthy.
    (process.stderr as { write: unknown }).write = ((
      chunk: string | Uint8Array,
    ) => {
      captured.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
      return true;
    }) as typeof process.stderr.write;
  });

  afterEach(() => {
    process.stderr.write = savedWrite;
    if (savedEnv === undefined) delete process.env.STAMP_SUPPRESS_DEPRECATION;
    else process.env.STAMP_SUPPRESS_DEPRECATION = savedEnv;
  });

  it("emits a one-line banner to stderr by default", () => {
    maybePrintDeprecationNotice("1.10.0");
    const out = captured.join("");
    assert.ok(out.length > 0, "expected banner output");
    // Single trailing newline; no embedded newlines mid-banner.
    assert.equal(
      out.match(/\n/g)?.length,
      1,
      "banner should be exactly one line (one terminating newline)",
    );
  });

  it("uses the lowercase `warning:` prefix (stamp stderr convention)", () => {
    // stamp's stderr convention is lowercase prefixes — `error:`,
    // `warning:`, `note:` — so agent / operator stderr classifiers
    // don't have to special-case this banner. The literal-string match
    // locks the prefix in: changing it requires updating this test,
    // which is the right friction.
    maybePrintDeprecationNotice("1.10.0");
    assert.ok(
      captured.join("").startsWith("warning: "),
      `banner must start with 'warning: '; got: ${JSON.stringify(captured.join("").slice(0, 40))}`,
    );
  });

  it("names the migration guide so operators can find the upgrade path", () => {
    maybePrintDeprecationNotice("1.10.0");
    assert.match(captured.join(""), /docs\/migration-1\.x-to-2\.x\.md/);
  });

  it("names the suppression env var by its exact spelling", () => {
    maybePrintDeprecationNotice("1.10.0");
    assert.match(captured.join(""), /STAMP_SUPPRESS_DEPRECATION=1/);
  });

  it("suppresses entirely when STAMP_SUPPRESS_DEPRECATION=1", () => {
    process.env.STAMP_SUPPRESS_DEPRECATION = "1";
    maybePrintDeprecationNotice("1.10.0");
    assert.equal(
      captured.join(""),
      "",
      "expected no stderr writes when suppression env var is set to '1'",
    );
  });

  it("does NOT suppress on STAMP_SUPPRESS_DEPRECATION='' (defends against accidental disabling)", () => {
    process.env.STAMP_SUPPRESS_DEPRECATION = "";
    maybePrintDeprecationNotice("1.10.0");
    assert.ok(captured.join("").length > 0);
  });

  it("does NOT suppress on STAMP_SUPPRESS_DEPRECATION='true' (only the literal '1' opts out)", () => {
    process.env.STAMP_SUPPRESS_DEPRECATION = "true";
    maybePrintDeprecationNotice("1.10.0");
    assert.ok(captured.join("").length > 0);
  });

  // Version-gate tests: the bridge-release banner is meant for 1.x
  // operators. On 2.x+ it's silent (the operator is already on the
  // active line and the banner would only confuse).

  it("stays silent on stamp 2.x+ (the active line)", () => {
    maybePrintDeprecationNotice("2.0.1");
    assert.equal(
      captured.join(""),
      "",
      "banner must be silent on stamp 2.x — operator is already on the active line",
    );
  });

  it("stays silent on stamp 3.x and beyond (forward-compat)", () => {
    maybePrintDeprecationNotice("3.0.0");
    assert.equal(captured.join(""), "");
  });

  it("fires on stamp 1.x prereleases (e.g. 1.0.0-alpha.7)", () => {
    // Prerelease semver still starts with the major; the regex
    // `^(\d+)\.` matches "1.0.0-alpha.7" → 1, so the banner fires.
    maybePrintDeprecationNotice("1.0.0-alpha.7");
    assert.ok(captured.join("").length > 0);
  });

  it("stays silent when the version string is unparseable", () => {
    // Defensive: if a future build embeds a malformed version string,
    // we prefer silence over a banner with no version context. Better
    // to miss the 1.x notice than emit a confusing one.
    maybePrintDeprecationNotice("not-a-version");
    assert.equal(captured.join(""), "");
  });
});
