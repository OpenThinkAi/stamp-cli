/**
 * Tests for the prview document emitter (AGT-1426): diff indexing, prose
 * parsing, target selection, and schema validation of the emitted document
 * against a vendored copy of prview's `prview-review/1` JSON Schema.
 */

import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { runReview } from "../src/commands/review.ts";
import {
  anchorFor,
  buildPrviewDocument,
  indexDiff,
  parseReviewerFindings,
  pickRemoteTarget,
  splitBlocks,
} from "../src/lib/prviewDocument.ts";

const SCHEMA = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), "fixtures", "prview-review-1.schema.json"), "utf8"),
) as Schema;

// --- minimal JSON Schema validator (the subset prview-review/1 uses) -------

type Schema = {
  $ref?: string;
  const?: unknown;
  enum?: unknown[];
  type?: string | string[];
  required?: string[];
  properties?: Record<string, Schema>;
  items?: Schema;
  oneOf?: Schema[];
  pattern?: string;
  minLength?: number;
  maxLength?: number;
  minItems?: number;
  minimum?: number;
  maximum?: number;
  $defs?: Record<string, Schema>;
};

function typeOf(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (Number.isInteger(v)) return "integer";
  return typeof v;
}

function validate(v: unknown, s: Schema, path: string, errs: string[]): void {
  if (s.$ref) {
    const target = SCHEMA.$defs?.[s.$ref.replace("#/$defs/", "")];
    if (!target) return void errs.push(`${path}: unresolved ${s.$ref}`);
    validate(v, target, path, errs);
  }
  if (s.const !== undefined && v !== s.const) errs.push(`${path}: expected const ${String(s.const)}`);
  if (s.enum && !s.enum.includes(v)) errs.push(`${path}: ${String(v)} not in enum`);
  if (s.type) {
    const types = Array.isArray(s.type) ? s.type : [s.type];
    const t = typeOf(v);
    const ok = types.some((x) => x === t || (x === "number" && t === "integer"));
    if (!ok) return void errs.push(`${path}: expected ${types.join("|")}, got ${t}`);
  }
  if (typeof v === "string") {
    if (s.pattern && !new RegExp(s.pattern).test(v)) errs.push(`${path}: does not match ${s.pattern}`);
    if (s.minLength !== undefined && v.length < s.minLength) errs.push(`${path}: shorter than ${s.minLength}`);
    if (s.maxLength !== undefined && v.length > s.maxLength) errs.push(`${path}: longer than ${s.maxLength}`);
  }
  if (typeof v === "number") {
    if (s.minimum !== undefined && v < s.minimum) errs.push(`${path}: below ${s.minimum}`);
    if (s.maximum !== undefined && v > s.maximum) errs.push(`${path}: above ${s.maximum}`);
  }
  if (Array.isArray(v)) {
    if (s.minItems !== undefined && v.length < s.minItems) errs.push(`${path}: fewer than ${s.minItems} items`);
    if (s.items) v.forEach((x, i) => validate(x, s.items!, `${path}[${i}]`, errs));
  }
  if (v && typeof v === "object" && !Array.isArray(v)) {
    const o = v as Record<string, unknown>;
    for (const r of s.required ?? []) if (!(r in o)) errs.push(`${path}: missing ${r}`);
    for (const [k, sub] of Object.entries(s.properties ?? {})) if (k in o) validate(o[k], sub, `${path}.${k}`, errs);
  }
}

function assertValid(doc: unknown): void {
  const errs: string[] = [];
  validate(doc, SCHEMA, "$", errs);
  assert.deepEqual(errs, []);
}

// --- fixtures -------------------------------------------------------------

const BASE = "a".repeat(40);
const HEAD = "b".repeat(40);

const DIFF = [
  "diff --git a/src/auth.ts b/src/auth.ts",
  "index 111..222 100644",
  "--- a/src/auth.ts",
  "+++ b/src/auth.ts",
  "@@ -40,6 +42,8 @@ export function login() {",
  " ctx",
  "+added",
  "@@ -100,3 +120,4 @@ export function logout() {",
  " ctx",
  "diff --git a/old/name.ts b/new/name.ts",
  "similarity index 100%",
  "rename from old/name.ts",
  "rename to new/name.ts",
  "diff --git a/src/gone.ts b/src/gone.ts",
  "deleted file mode 100644",
  "--- a/src/gone.ts",
  "+++ /dev/null",
  "@@ -1,2 +0,0 @@",
  "-x",
  "-y",
  "diff --git a/lib/util.ts b/lib/util.ts",
  "--- a/lib/util.ts",
  "+++ b/lib/util.ts",
  "@@ -5 +5 @@",
  "-a",
  "+b",
  "diff --git a/other/util.ts b/other/util.ts",
  "--- a/other/util.ts",
  "+++ b/other/util.ts",
  "@@ -1 +1 @@",
  "-a",
  "+b",
  "",
].join("\n");

const target = { repo: "o/r", base: BASE, head: HEAD, label: "main..f" };

describe("indexDiff / anchorFor", () => {
  const idx = indexDiff(DIFF);

  it("indexes hunks by new path with old:new starts", () => {
    assert.deepEqual(
      idx.hunks.get("src/auth.ts")!.map((h) => [h.oldStart, h.newStart, h.newLen]),
      [
        [40, 42, 8],
        [100, 120, 4],
      ],
    );
  });

  it("uses the new path for a rename and marks hunkless files file-only", () => {
    assert.ok(idx.files.includes("new/name.ts"));
    assert.ok(!idx.files.includes("old/name.ts"));
    assert.deepEqual(idx.fileOnly, ["new/name.ts"]);
    assert.deepEqual(anchorFor(idx, "new/name.ts", 3), { hunk: "new/name.ts@file", line: 0 });
  });

  it("keeps a deleted file under its old path", () => {
    assert.ok(idx.hunks.has("src/gone.ts"));
  });

  it("places a line inside a hunk, else on the nearest hunk's first line", () => {
    assert.deepEqual(anchorFor(idx, "src/auth.ts", 45), { hunk: "src/auth.ts@40:42", line: 45 });
    assert.deepEqual(anchorFor(idx, "src/auth.ts", 118), { hunk: "src/auth.ts@100:120", line: 120 });
    assert.deepEqual(anchorFor(idx, "src/auth.ts", null), { hunk: "src/auth.ts@40:42", line: 42 });
    assert.equal(anchorFor(idx, "nope.ts", 1), null);
  });
});

describe("splitBlocks", () => {
  it("splits list items and paragraphs and tracks headings", () => {
    const blocks = splitBlocks("## Blocking\n- first item\n  continued\n- second\n\nPara text");
    assert.deepEqual(
      blocks.map((b) => [b.heading.trim(), b.text]),
      [
        ["## Blocking", "- first item\n  continued"],
        ["## Blocking", "- second"],
        ["## Blocking", "Para text"],
      ],
    );
  });
});

describe("parseReviewerFindings", () => {
  const idx = indexDiff(DIFF);
  const parse = (prose: string, verdict = "changes_requested", reviewer = "standards") =>
    parseReviewerFindings({ reviewer, verdict, prose }, idx);

  it("anchors a finding on the file:line it names", () => {
    const [f] = parse("- **Blocking**: `src/auth.ts:45` logs the token on failure. The whole request is passed.");
    assert.equal(f!.hunk, "src/auth.ts@40:42");
    assert.equal(f!.line, 45);
    assert.equal(f!.side, "new");
    assert.equal(f!.severity, "blocking");
    assert.equal(f!.source, "stamp:standards");
    assert.equal(f!.claim, "Blocking: src/auth.ts:45 logs the token on failure.");
    assert.equal(f!.evidence, "The whole request is passed.");
  });

  it("folds following reference-free paragraphs into the finding's evidence", () => {
    const [f, g] = parse(
      "**Critical** — `src/auth.ts:45`\n\n```js\nlog(req)\n```\n\nThe token is logged.\n\n- src/auth.ts:121 second.",
    );
    assert.equal(f!.claim, "Critical — src/auth.ts:45");
    assert.equal(f!.evidence, "log(req) The token is logged.");
    assert.equal(g!.line, 121);
  });

  it("keeps underscores inside identifiers", () => {
    assert.match(parse("- src/auth.ts:45 use node:child_process, _not_ this.")[0]!.claim, /node:child_process, not this/);
  });

  it("understands ranges, #L, and 'line N' reference forms", () => {
    assert.equal(parse("- src/auth.ts:121-130 is wrong.")[0]!.line, 121);
    assert.equal(parse("- src/auth.ts#L122 is wrong.")[0]!.line, 122);
    assert.equal(parse("- src/auth.ts, line 43 is wrong.")[0]!.line, 43);
    assert.equal(parse("- src/auth.ts (line 44) is wrong.")[0]!.line, 44);
  });

  it("anchors a file-only reference on its first hunk with no line claim", () => {
    const [f] = parse("- src/auth.ts needs a test.");
    assert.equal(f!.hunk, "src/auth.ts@40:42");
    assert.equal(f!.line, 42);
  });

  it("matches a bare basename only when unique in the diff", () => {
    assert.equal(parse("- auth.ts:45 is off.")[0]!.hunk, "src/auth.ts@40:42");
    // util.ts exists twice: ambiguous, so no anchor -> summary fallback.
    assert.equal(parse("- util.ts:5 is off.")[0]!.kind, "summary");
  });

  it("ignores paths that are not in the diff", () => {
    const [f] = parse("- src/elsewhere.ts:10 is odd.");
    assert.equal(f!.kind, "summary");
  });

  it("reads severity from markers and headings; negation does not block", () => {
    assert.equal(parse("- nit: src/auth.ts:45 naming.")[0]!.severity, "nit");
    assert.equal(parse("## Blocking\n- src/auth.ts:45 broke.")[0]!.severity, "blocking");
    assert.equal(parse("- src/auth.ts:45 is non-blocking.")[0]!.severity, "nit");
    assert.equal(parse("## No blocking issues\n- src/auth.ts:45 fine.")[0]!.severity, "warn");
    assert.equal(parse("- src/auth.ts:45 broke.")[0]!.severity, "warn");
  });

  it("derives kind from the reviewer and keywords", () => {
    assert.equal(parse("- src/auth.ts:45 x.", "approved", "security")[0]!.kind, "security");
    assert.equal(parse("- src/auth.ts:45 crashes on null.")[0]!.kind, "bug");
    assert.equal(parse("- src/auth.ts:45 x.", "approved", "product")[0]!.kind, "design");
  });

  it("falls back to one summary finding on the first hunk, severity by verdict", () => {
    const [bad] = parse("Overall this breaks the exit code contract. More detail.");
    assert.equal(bad!.kind, "summary");
    assert.equal(bad!.hunk, "src/auth.ts@40:42");
    assert.equal(bad!.severity, "blocking");
    const [ok] = parse("Looks good to me.", "approved");
    assert.equal(ok!.severity, "nit");
  });

  it("emits nothing for empty prose or an empty diff", () => {
    assert.deepEqual(parse("   \n"), []);
    assert.deepEqual(parseReviewerFindings({ reviewer: "x", verdict: "approved", prose: "hi" }, indexDiff("")), []);
  });

  it("respects the schema length limits", () => {
    const long = "word ".repeat(400);
    const [f] = parse(`- src/auth.ts:45 ${long}`);
    assert.ok(f!.claim.length <= 300);
    assert.ok((f!.evidence ?? "").length <= 500);
  });
});

describe("pickRemoteTarget", () => {
  it("prefers a github remote over a stamp-server origin", () => {
    assert.deepEqual(
      pickRemoteTarget(
        [
          { name: "origin", url: "ssh://git@host:1/srv/git/stamp-cli.git" },
          { name: "github", url: "git@github.com:OpenThinkAi/stamp-cli.git" },
        ],
        "dir",
      ),
      { repo: "OpenThinkAi/stamp-cli", platform: "github" },
    );
  });

  it("omits platform for an unknown host and falls back to the dir name", () => {
    assert.deepEqual(pickRemoteTarget([{ name: "origin", url: "ssh://git@h.example/srv/git/o/r.git" }], "dir"), {
      repo: "o/r",
    });
    assert.deepEqual(pickRemoteTarget([], "dir"), { repo: "dir" });
  });
});

describe("buildPrviewDocument", () => {
  const doc = buildPrviewDocument({
    target,
    diff: DIFF,
    reviewers: [
      { reviewer: "security", verdict: "changes_requested", prose: "- **Blocking** src/auth.ts:45 leaks a token." },
      { reviewer: "standards", verdict: "approved", prose: "Clean change." },
      { reviewer: "product", verdict: "approved", prose: "- nit: lib/util.ts:5 naming." },
    ],
  });

  it("validates against the prview-review/1 schema", () => {
    assertValid(doc);
    assertValid(JSON.parse(JSON.stringify(doc)));
  });

  it("carries per-reviewer sources, unique ids, and the submit declaration", () => {
    assert.deepEqual(doc.findings.map((f) => f.source), ["stamp:security", "stamp:standards", "stamp:product"]);
    assert.equal(new Set(doc.findings.map((f) => f.id)).size, 3);
    assert.deepEqual(doc.on_submit, { run: ["stamp", "attest", "--from", "{file}"] });
    assert.equal(doc.schema, "prview-review/1");
  });

  it("the validator itself rejects a bad document", () => {
    const errs: string[] = [];
    validate({ schema: "prview-review/1", target: { base: "x", head: HEAD }, findings: [{ source: "s", hunk: "nope", line: null, claim: "c" }] }, SCHEMA, "$", errs);
    assert.ok(errs.length >= 3, errs.join("\n"));
  });
});

describe("runReview --prview usage", () => {
  it("is rejected with --plan and --headless before touching the repo", async () => {
    await assert.rejects(runReview({ diff: "main..x", prview: "/tmp/x.json", plan: true }), /--prview/);
    await assert.rejects(runReview({ diff: "main..x", prview: "/tmp/x.json", headless: true }), /--prview/);
  });
});
