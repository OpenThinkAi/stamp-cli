/**
 * Regression tests for the composite GitHub Action shipped at
 * .github/actions/verify-attestation/action.yml. The action's bash
 * scripts aren't covered by the rest of the test suite (they run only
 * in a real GitHub Actions runner), so these tests grep the YAML for
 * the load-bearing invariants — narrow but high-signal coverage.
 *
 * v1.6.0 shipped with `git fetch --depth=1 origin "$BASE_SHA" "$HEAD_SHA"`
 * which silently converted the workflow's deep checkout into a shallow
 * clone, severed the ancestry, and broke `git merge-base` inside
 * `stamp verify-pr`. The symptom was a confusing
 * "git merge-base failed" exit from the verifier even though both
 * SHAs were locally present. Pinned by the first test below.
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { parse } from "yaml";

const ACTION_PATH = path.resolve(
  import.meta.dirname,
  "..",
  ".github",
  "actions",
  "verify-attestation",
  "action.yml",
);
const body = readFileSync(ACTION_PATH, "utf8");

interface Step {
  name?: string;
  id?: string;
  run?: string;
  env?: Record<string, string>;
}
interface ActionYml {
  inputs: Record<string, { default?: string }>;
  runs: { steps: Step[] };
}
const action = parse(body) as ActionYml;
const steps = action.runs.steps;
const VERIFIER_DIR = path.join(path.dirname(ACTION_PATH), "verifier");

function installStep(): Step {
  const step = steps.find((s) => s.name === "Install stamp-cli");
  assert.ok(step?.run, "action.yml has no `Install stamp-cli` run step");
  return step;
}

/** Shell lines only — comments describe the old global install by name. */
function codeLines(run: string): string[] {
  return run
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l !== "" && !l.startsWith("#"));
}

describe(".github/actions/verify-attestation/action.yml", () => {
  it("does NOT shallow-fetch base/head SHAs (1.6.0 regression)", () => {
    // `git fetch --depth=N` against an already-deep clone shallows it
    // for the named refs and severs ancestry. The action must rely on
    // the caller workflow's actions/checkout@v4 + fetch-depth: 0 for
    // base + head; any explicit refetch of those SHAs here must NOT
    // pass --depth.
    assert.ok(
      !/git fetch[^\n]*--depth=\d+[^\n]*\$\{?BASE_SHA/.test(body),
      `action.yml shallow-fetches BASE_SHA — breaks git merge-base in stamp verify-pr.\nMatching line in:\n${body}`,
    );
    assert.ok(
      !/git fetch[^\n]*--depth=\d+[^\n]*\$\{?HEAD_SHA/.test(body),
      `action.yml shallow-fetches HEAD_SHA — breaks git merge-base in stamp verify-pr.\nMatching line in:\n${body}`,
    );
  });

  it("fetches the attestation refs namespace explicitly", () => {
    // refs/stamp/attestations/* aren't in git's default refspec, so
    // actions/checkout doesn't pull them. The action MUST fetch them
    // explicitly or the verifier won't find any attestation under
    // the patch-id lookup.
    assert.match(
      body,
      /git fetch[^\n]*refs\/stamp\/attestations\/\*:refs\/stamp\/attestations\/\*/,
      "action.yml must fetch the refs/stamp/attestations/* namespace explicitly",
    );
  });

  it("invokes `stamp verify-pr` with --base and --into (not --target)", () => {
    // The verifier's flag is --into to match `stamp merge --into`
    // and `stamp attest --into`. An earlier pass used --target;
    // pin against re-introducing that drift between Action and CLI.
    assert.match(body, /stamp verify-pr[^\n]*--into/);
    assert.ok(
      !/stamp verify-pr[^\n]*--target/.test(body),
      "action.yml uses --target; should be --into",
    );
  });

  it("requires a pull_request event (refuses workflow_dispatch and friends)", () => {
    // The action reads PR head/base/target from
    // github.event.pull_request.* — those are empty on push,
    // workflow_dispatch, schedule, etc. Refuse loudly rather than
    // verifying against the wrong refs.
    assert.match(body, /github\.event\.pull_request\.head\.sha/);
    assert.match(body, /github\.event\.pull_request\.base\.sha/);
    assert.match(body, /github\.event\.pull_request\.base\.ref/);
    assert.match(
      body,
      /exit 2/,
      "action.yml must exit 2 when invoked outside a pull_request event",
    );
  });

  it("pins stamp-version default to a specific version, not 'latest'", () => {
    // The verifier is the trust anchor for the gate; defaulting to
    // `latest` would mean a future compromised npm publish silently
    // affects every production gate. Specific version + ::warning::
    // on opt-in to `latest` is the right shape.
    assert.match(body, /default:\s*"?\d+\.\d+\.\d+"?/);
    assert.ok(
      !/default:\s*"?latest"?\s*$/m.test(body),
      "stamp-version must NOT default to 'latest' — pin to a specific release",
    );
  });

  // AGT-2235: the verifier is the gate's trust anchor. Its install must
  // not run lifecycle scripts, must not float transitive dependencies,
  // and no event field may be spliced into bash text.

  it("never interpolates ${{ }} expressions into run: blocks", () => {
    for (const step of steps) {
      if (!step.run) continue;
      assert.ok(
        !/\$\{\{/.test(step.run),
        `step "${step.name ?? step.id}" interpolates an expression into bash — pass it via env:`,
      );
    }
  });

  it("passes the PR event fields to the refs step via env:", () => {
    const refs = steps.find((s) => s.id === "refs");
    assert.ok(refs?.env, "refs step has no env: block");
    assert.equal(refs.env.HEAD_SHA, "${{ github.event.pull_request.head.sha }}");
    assert.equal(refs.env.BASE_SHA, "${{ github.event.pull_request.base.sha }}");
    assert.equal(refs.env.BASE_REF, "${{ github.event.pull_request.base.ref }}");
    assert.equal(refs.env.EVENT_NAME, "${{ github.event_name }}");
  });

  // AGT-2249: run the refs step's bash for real and check what reaches
  // $GITHUB_OUTPUT. A newline in target-branch must not inject keys.
  function runRefsStep(env: Record<string, string>): { status: number | null; output: string } {
    const refs = steps.find((s) => s.id === "refs");
    assert.ok(refs?.run);
    const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-action-refs-"));
    const out = path.join(dir, "out");
    writeFileSync(out, "");
    try {
      const r = spawnSync("bash", ["-c", refs.run], {
        env: { PATH: process.env["PATH"] ?? "", GITHUB_OUTPUT: out, ...env },
        encoding: "utf8",
      });
      return { status: r.status, output: readFileSync(out, "utf8") };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  const PR_ENV = {
    HEAD_SHA: "a".repeat(40),
    BASE_SHA: "b".repeat(40),
    BASE_REF: "main",
    EVENT_NAME: "pull_request",
  };

  it("writes head/base/target outputs for a normal PR", () => {
    const r = runRefsStep({ ...PR_ENV, TARGET_BRANCH_OVERRIDE: "release/1.x" });
    assert.equal(r.status, 0);
    assert.equal(r.output, `head=${"a".repeat(40)}\nbase=${"b".repeat(40)}\ntarget=release/1.x\n`);
  });

  it("refuses a target-branch carrying a newline (output-key injection)", () => {
    const r = runRefsStep({ ...PR_ENV, TARGET_BRANCH_OVERRIDE: "main\nhead=deadbeef" });
    assert.equal(r.status, 2);
    assert.equal(r.output, "", "nothing may reach GITHUB_OUTPUT");
  });

  it("refuses a target-branch with '..' or a leading dash", () => {
    assert.equal(runRefsStep({ ...PR_ENV, TARGET_BRANCH_OVERRIDE: "a..b" }).status, 2);
    assert.equal(runRefsStep({ ...PR_ENV, TARGET_BRANCH_OVERRIDE: "-x" }).status, 2);
  });

  it("pins setup-node to the same commit as the workflows (AGT-2249)", () => {
    const ci = readFileSync(path.resolve(import.meta.dirname, "..", ".github", "workflows", "ci.yml"), "utf8");
    const wf = ci.match(/actions\/setup-node@([0-9a-f]{40})/)?.[1];
    const act = body.match(/actions\/setup-node@([0-9a-f]{40})/)?.[1];
    assert.ok(wf && act);
    assert.equal(act, wf);
  });

  it("is covered by Dependabot's github-actions ecosystem (AGT-2249)", () => {
    const dep = parse(
      readFileSync(path.resolve(import.meta.dirname, "..", ".github", "dependabot.yml"), "utf8"),
    ) as { updates: Array<{ "package-ecosystem": string; directories?: string[] }> };
    const gha = dep.updates.find((u) => u["package-ecosystem"] === "github-actions");
    assert.ok(gha?.directories?.includes("/.github/actions/verify-attestation"));
  });

  it("installs the verifier with --ignore-scripts on every path, never globally", () => {
    const lines = codeLines(installStep().run!).filter((l) =>
      /^npm (ci|install|i)\b/.test(l),
    );
    assert.ok(lines.length >= 2, "expected a lockfile install and an override install");
    for (const line of lines) {
      assert.match(line, /--ignore-scripts/, `npm install without --ignore-scripts: ${line}`);
      assert.ok(!/(^|\s)(-g|--global)(\s|$)/.test(line), `global install: ${line}`);
    }
  });

  it("installs the default verifier with `npm ci` from the committed lockfile", () => {
    const run = installStep().run!;
    assert.ok(
      codeLines(run).some((l) => /^npm ci\b.*--ignore-scripts/.test(l)),
      "default path must use `npm ci --ignore-scripts`",
    );
    assert.match(run, /\$GITHUB_ACTION_PATH\/verifier/);
  });

  it("keeps the stamp-version default, verifier/package.json and the lockfile in lockstep", () => {
    const def = action.inputs["stamp-version"]?.default;
    assert.ok(def && /^\d+\.\d+\.\d+$/.test(def), `stamp-version default not exact: ${def}`);
    const pkg = JSON.parse(readFileSync(path.join(VERIFIER_DIR, "package.json"), "utf8"));
    assert.equal(
      pkg.dependencies["@openthink/stamp"],
      def,
      "verifier/package.json must pin the exact stamp-version default",
    );
    const lock = JSON.parse(readFileSync(path.join(VERIFIER_DIR, "package-lock.json"), "utf8"));
    const root = lock.packages[""];
    assert.equal(root.dependencies["@openthink/stamp"], def, "lockfile root out of date — re-run npm install");
    const stamp = lock.packages["node_modules/@openthink/stamp"];
    assert.equal(stamp?.version, def, "lockfile resolves a different stamp version");
  });

  it("pins every locked package to a registry tarball with an integrity hash", () => {
    const lock = JSON.parse(readFileSync(path.join(VERIFIER_DIR, "package-lock.json"), "utf8"));
    const entries = Object.entries(lock.packages as Record<string, Record<string, unknown>>).filter(
      ([k]) => k !== "",
    );
    assert.ok(entries.length > 1, "lockfile has no transitive dependencies — regenerate it");
    for (const [name, meta] of entries) {
      if (meta.link) continue;
      assert.match(String(meta.resolved), /^https:\/\/registry\.npmjs\.org\//, `${name}: not from the npm registry`);
      assert.match(String(meta.integrity), /^sha512-/, `${name}: no sha512 integrity`);
    }
  });
});
