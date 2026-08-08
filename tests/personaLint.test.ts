/**
 * Tests for the persona/config consistency lint (issue #53, AGT-878).
 *
 * The contradiction being linted: a reviewer with
 * `enforce_reads_on_dotstamp: true` whose persona prompt tells it to ignore
 * `.stamp/`. The harness voids any approval whose tool trace lacks a Read of
 * every modified `.stamp/*` path, so a persona that puts `.stamp/` out of
 * scope steers the reviewer straight into an overridden verdict.
 *
 * Two halves here:
 *   1. `findDotstampExclusions` — the text heuristic itself, including the
 *      negation guard that keeps "do NOT ignore .stamp/" from being flagged.
 *   2. `stamp reviewers verify` end-to-end over a real repo fixture, asserting
 *      the LOCK_DRIFT_EXIT convention, the `--no-persona-lint` escape hatch,
 *      and that the lint fires with no lock files present (an unpinned
 *      reviewer holds the contradiction just as easily as a pinned one).
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { stringify as yamlStringify } from "yaml";
import {
  findDotstampExclusions,
  formatDotstampExclusionReport,
} from "../src/lib/personaLint.ts";
import { LOCK_DRIFT_EXIT } from "../src/lib/reviewerLock.ts";
import { DEFAULT_CONFIG } from "../src/lib/config.ts";

const REPO_ROOT = fileURLToPath(new URL("..", import.meta.url));
const CLI_ENTRY = join(REPO_ROOT, "src", "index.ts");
// The child runs with cwd inside a temp fixture repo, so a bare `--import tsx`
// would resolve against the fixture (no node_modules) and die with
// ERR_MODULE_NOT_FOUND. Resolve the loader to an absolute URL from here.
const TSX_LOADER = import.meta.resolve("tsx");

describe("findDotstampExclusions — flags persona wording that excludes .stamp/", () => {
  // The exact wording from the starter security persona that caused the
  // original fx-tracker incident (2026-07-04).
  it("flags the historical 'tool meta, separate concern' exclusion", () => {
    const hits = findDotstampExclusions(
      [
        "## What you do NOT check",
        "",
        "- Anything in `.stamp/` — tool meta, separate concern.",
      ].join("\n"),
    );
    assert.equal(hits.length, 1);
    assert.equal(hits[0]!.line, 3);
    assert.match(hits[0]!.cue, /separate concern/i);
    assert.match(hits[0]!.text, /tool meta/);
  });

  for (const [label, line] of [
    ["ignore", "Ignore `.stamp/` files entirely."],
    ["skip", "Skip anything under .stamp/ when reviewing."],
    ["exclude", "Exclude `.stamp/**` from your analysis."],
    ["out of scope", "Changes to `.stamp/config.yml` are out of scope for you."],
    ["not your concern", "`.stamp/` is not your concern."],
    ["do not review", "Do not review files in .stamp/."],
    ["no need to read", "There is no need to read `.stamp/` files."],
    ["disregard", "Disregard `.stamp/trusted-keys/*` changes."],
  ] as const) {
    it(`flags the "${label}" phrasing`, () => {
      const hits = findDotstampExclusions(line);
      assert.equal(hits.length, 1, `expected a hit for: ${line}`);
    });
  }

  it("reports every offending line, in document order", () => {
    const hits = findDotstampExclusions(
      ["Ignore .stamp/config.yml.", "Some prose.", "`.stamp/` is out of scope."].join(
        "\n",
      ),
    );
    assert.deepEqual(
      hits.map((h) => h.line),
      [1, 3],
    );
  });

  it("caps the echoed line so a long persona line can't wreck the report", () => {
    const hits = findDotstampExclusions(`Ignore .stamp/ ${"x".repeat(400)}`);
    assert.equal(hits.length, 1);
    assert.ok(
      hits[0]!.text.length <= 140,
      `echoed text was ${hits[0]!.text.length} chars`,
    );
    assert.ok(hits[0]!.text.endsWith("…"), "long lines should be ellipsized");
  });
});

describe("findDotstampExclusions — does not flag compliant or negated wording", () => {
  it("does not flag the current scaffolded security persona", () => {
    // DEFAULT_CONFIG's security reviewer ships enforce_reads_on_dotstamp: true,
    // so the persona stamp scaffolds must be lint-clean or every fresh repo
    // starts out failing its own `stamp reviewers verify`.
    assert.equal(
      DEFAULT_CONFIG.reviewers.security?.enforce_reads_on_dotstamp,
      true,
      "guard: this test is only meaningful while the scaffold sets the flag",
    );
    const hits = findDotstampExclusions(SECURITY_PERSONA_INCLUSIVE);
    assert.deepEqual(hits, [], `unexpected hits: ${JSON.stringify(hits)}`);
  });

  for (const [label, line] of [
    ["do not ignore", "Do NOT ignore `.stamp/` changes — they are trust anchors."],
    ["never skip", "Never skip `.stamp/` files."],
    ["don't exclude", "Don't exclude .stamp/ from your review."],
    ["explicitly in scope", "`.stamp/` changes ARE in scope: Read each modified file."],
    ["must read", "You must Read every modified `.stamp/*` path before approving."],
  ] as const) {
    it(`does not flag "${label}"`, () => {
      assert.deepEqual(
        findDotstampExclusions(line),
        [],
        `false positive on: ${line}`,
      );
    });
  }

  it("does not flag exclusion wording on lines that never mention .stamp", () => {
    assert.deepEqual(
      findDotstampExclusions(
        ["Ignore whitespace-only changes.", "Formatting is out of scope."].join("\n"),
      ),
      [],
    );
  });

  it("is stable across repeated calls (no leaked regex lastIndex)", () => {
    // The cue regexes are module-level and /g-flagged; a stale lastIndex
    // would make the second call miss the match.
    const prompt = "Ignore `.stamp/` entirely.";
    assert.deepEqual(findDotstampExclusions(prompt), findDotstampExclusions(prompt));
    assert.equal(findDotstampExclusions(prompt).length, 1);
  });
});

describe("formatDotstampExclusionReport", () => {
  it("names the reviewer, the prompt location, and both fixes", () => {
    const report = formatDotstampExclusionReport("security", ".stamp/reviewers/security.md", [
      { line: 12, text: "- Anything in `.stamp/` — separate concern.", cue: "separate concern" },
    ]);
    assert.match(report, /^error: reviewer 'security'/);
    assert.match(report, /\.stamp\/reviewers\/security\.md:12/);
    assert.match(report, /enforce_reads_on_dotstamp: false/);
    assert.match(report, /--no-persona-lint/);
  });
});

// --------------------------------------------------------------------------
// end-to-end: stamp reviewers verify
// --------------------------------------------------------------------------

describe("stamp reviewers verify — persona lint (AC#1)", () => {
  let dir: string;

  beforeEach(() => {
    dir = realpathSync(mkdtempSync(join(tmpdir(), "stamp-persona-lint-")));
    execFileSync("git", ["init", "-q"], { cwd: dir });
    mkdirSync(join(dir, ".stamp", "reviewers"), { recursive: true });
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function writeRepo(promptText: string, enforce: boolean): void {
    writeFileSync(join(dir, ".stamp", "reviewers", "security.md"), promptText);
    writeFileSync(
      join(dir, ".stamp", "config.yml"),
      yamlStringify({
        version: 1,
        reviewers: {
          security: {
            prompt: ".stamp/reviewers/security.md",
            ...(enforce ? { enforce_reads_on_dotstamp: true } : {}),
          },
        },
        branches: { main: { required: ["security"] } },
      }),
    );
  }

  function runVerify(args: string[] = []): {
    status: number;
    stdout: string;
    stderr: string;
  } {
    const res = execFileSync(
      process.execPath,
      ["--import", TSX_LOADER, CLI_ENTRY, "reviewers", "verify", ...args],
      { cwd: dir, encoding: "utf8", env: process.env, stdio: "pipe" },
      // execFileSync throws on non-zero; caught below.
    );
    return { status: 0, stdout: res, stderr: "" };
  }

  function runVerifyAllowFail(args: string[] = []): {
    status: number;
    stdout: string;
    stderr: string;
  } {
    try {
      return runVerify(args);
    } catch (err) {
      const e = err as { status?: number; stdout?: string; stderr?: string };
      return {
        status: e.status ?? -1,
        stdout: e.stdout ?? "",
        stderr: e.stderr ?? "",
      };
    }
  }

  it("exits LOCK_DRIFT_EXIT and explains, with no lock files present (AC#1)", () => {
    writeRepo(CONTRADICTORY_PERSONA, true);
    const { status, stdout, stderr } = runVerifyAllowFail();
    assert.equal(status, LOCK_DRIFT_EXIT, `stdout: ${stdout}\nstderr: ${stderr}`);
    assert.match(stderr, /enforce_reads_on_dotstamp: true but its persona excludes/);
    assert.match(stderr, /\.stamp\/reviewers\/security\.md:\d+/);
    // The "no lock files present" happy-path message must not be the last
    // word when the lint has something to say.
    assert.doesNotMatch(stdout, /No lock files present/);
  });

  it("--no-persona-lint suppresses the finding and exits 0", () => {
    writeRepo(CONTRADICTORY_PERSONA, true);
    const { status, stdout } = runVerifyAllowFail(["--no-persona-lint"]);
    assert.equal(status, 0);
    assert.doesNotMatch(stdout, /persona excludes/);
  });

  it("stays silent when the reviewer does not enforce reads on .stamp", () => {
    // Same persona text, flag off — no contradiction, nothing to report.
    writeRepo(CONTRADICTORY_PERSONA, false);
    const { status, stdout } = runVerifyAllowFail();
    assert.equal(status, 0);
    assert.doesNotMatch(stdout, /persona excludes/);
  });

  it("stays silent on a compliant persona with the flag on", () => {
    writeRepo(SECURITY_PERSONA_INCLUSIVE, true);
    const { status, stdout } = runVerifyAllowFail();
    assert.equal(status, 0);
    assert.doesNotMatch(stdout, /persona excludes/);
  });
});

const CONTRADICTORY_PERSONA = [
  "# security reviewer",
  "",
  "## What you do NOT check",
  "",
  "- Anything in `.stamp/` — tool meta, separate concern.",
  "",
].join("\n");

const SECURITY_PERSONA_INCLUSIVE = [
  "# security reviewer",
  "",
  "## What you do NOT check",
  "",
  "- Code style, idiom, abstraction choices → **standards** reviewer.",
  "",
  "`.stamp/` changes ARE in scope: Read each modified `.stamp/*` file",
  "before your verdict — you are reviewing stamp's own trust anchors",
  "(reviewer prompts, config, trusted keys), not tool meta.",
  "",
].join("\n");
