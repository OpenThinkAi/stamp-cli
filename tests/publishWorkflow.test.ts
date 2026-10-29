/**
 * Regression tests for .github/workflows/publish.yml (oaudit AGT-2234 /
 * AGT-2237). The workflow only runs on a real GitHub runner, so these
 * tests parse the YAML and pin the least-privilege job layout:
 *
 *   - no dependency code (npm ci / install scripts / build) runs in a job
 *     that holds `id-token: write` (npm Trusted Publishing OIDC);
 *   - only the publish job holds `id-token: write`, only the tag job holds
 *     `contents: write`, and the build job is read-only;
 *   - the build checkout does not persist the GITHUB_TOKEN;
 *   - every install uses --ignore-scripts;
 *   - only main publishes to `latest`: a `release/<N>.x` maintenance line
 *     publishes to `legacy-<N>` and any other ref fails closed (AGT-2236).
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { parse } from "yaml";

const WORKFLOW_PATH = path.resolve(
  import.meta.dirname,
  "..",
  ".github",
  "workflows",
  "publish.yml",
);

interface Step {
  name?: string;
  id?: string;
  uses?: string;
  run?: string;
  with?: Record<string, unknown>;
}
interface Job {
  environment?: string | { name: string };
  needs?: string | string[];
  if?: string;
  permissions?: Record<string, string>;
  steps: Step[];
}
interface Workflow {
  permissions?: Record<string, string>;
  jobs: Record<string, Job>;
}

const wf = parse(readFileSync(WORKFLOW_PATH, "utf8")) as Workflow;
const jobs = wf.jobs;

function runText(job: Job): string {
  return job.steps.map((s) => s.run ?? "").join("\n");
}

function needsList(job: Job): string[] {
  if (job.needs === undefined) return [];
  return Array.isArray(job.needs) ? job.needs : [job.needs];
}

describe(".github/workflows/publish.yml", () => {
  it("defaults the workflow token to no permissions", () => {
    assert.deepEqual(wf.permissions, {});
  });

  it("has exactly the build, publish and tag jobs", () => {
    assert.deepEqual(Object.keys(jobs).sort(), ["build", "publish", "tag"]);
  });

  it("grants each job only what it needs", () => {
    assert.deepEqual(jobs.build.permissions, { contents: "read" });
    assert.deepEqual(jobs.publish.permissions, { "id-token": "write" });
    assert.deepEqual(jobs.tag.permissions, { contents: "write" });
  });

  it("binds the OIDC-holding publish job to the npm-publish environment (AGT-2249)", () => {
    assert.equal(jobs.publish.environment, "npm-publish");
  });

  it("holds id-token: write in the publish job only", () => {
    for (const [name, job] of Object.entries(jobs)) {
      if (name === "publish") continue;
      assert.ok(
        !job.permissions || !("id-token" in job.permissions),
        `job ${name} must not hold id-token`,
      );
    }
  });

  it("runs no install, build or checkout in the OIDC-holding publish job", () => {
    const run = runText(jobs.publish);
    assert.ok(!/\bnpm (ci|install|i|rebuild)\b/.test(run), "publish job installs deps");
    assert.ok(!/\bnpm run\b/.test(run), "publish job runs package scripts");
    for (const step of jobs.publish.steps) {
      assert.ok(
        !step.uses?.startsWith("actions/checkout@"),
        "publish job must not check out the repo",
      );
      if (step.uses?.startsWith("actions/setup-node@")) {
        assert.ok(!step.with?.cache, "publish job setup-node must not use a dependency cache");
      }
    }
  });

  it("publishes the prebuilt tarball with --ignore-scripts and --provenance", () => {
    const run = runText(jobs.publish);
    const publish = run.split("\n").find((l) => /npm@[\d.]+ publish/.test(l));
    assert.ok(publish, "no pinned `npx npm@X publish` line in the publish job");
    assert.match(publish, /npx -y npm@\d+\.\d+\.\d+ publish /, "npm must be pinned to an exact version");
    assert.match(publish, /\.tgz|TARBALL/, "publish must target the downloaded tarball");
    assert.match(publish, /--ignore-scripts/);
    assert.match(publish, /--provenance/);
    assert.ok(
      jobs.publish.steps.some((s) => s.uses?.startsWith("actions/download-artifact@")),
      "publish job must download the build artifact",
    );
    assert.deepEqual(needsList(jobs.publish), ["build"]);
  });

  it("annotates the tarball-count failure as a workflow error (AGT-2270)", () => {
    assert.match(runText(jobs.publish), /echo "::error::expected exactly one tarball/);
  });

  it("installs with --ignore-scripts in every job", () => {
    for (const [name, job] of Object.entries(jobs)) {
      for (const line of runText(job).split("\n")) {
        if (/\bnpm ci\b/.test(line)) {
          assert.match(line, /--ignore-scripts/, `job ${name}: ${line.trim()}`);
        }
      }
    }
  });

  it("does not persist the GITHUB_TOKEN in the build checkout", () => {
    const checkout = jobs.build.steps.find((s) => s.uses?.startsWith("actions/checkout@"));
    assert.ok(checkout, "build job has no checkout");
    assert.equal(checkout.with?.["persist-credentials"], false);
  });

  it("runs only git in the contents:write tag job, after publish", () => {
    assert.deepEqual(needsList(jobs.tag).sort(), ["build", "publish"]);
    const run = runText(jobs.tag);
    assert.ok(!/\b(npm|npx|node)\b/.test(run), "tag job must not run npm/node");
    for (const step of jobs.tag.steps) {
      if (step.uses) {
        assert.ok(step.uses.startsWith("actions/checkout@"), `unexpected action in tag job: ${step.uses}`);
      }
    }
  });

  it("pins every action by full commit SHA", () => {
    for (const [name, job] of Object.entries(jobs)) {
      for (const step of job.steps) {
        if (!step.uses) continue;
        assert.match(step.uses, /@[0-9a-f]{40}$/, `job ${name}: ${step.uses} is not SHA-pinned`);
      }
    }
  });

  it("never interpolates ${{ }} expressions into run: blocks", () => {
    for (const [name, job] of Object.entries(jobs)) {
      assert.ok(!/\$\{\{/.test(runText(job)), `job ${name} interpolates an expression into bash`);
    }
  });
});

/**
 * Runs the build job's `read target version` step as a real bash script
 * against a scratch package.json, with GITHUB_REF set the way the runner
 * sets it on a push. Returns the exit status and the parsed dist_tag output.
 */
function runVersionStep(ref: string, version: string): { status: number | null; distTag?: string; stderr: string } {
  const step = jobs.build.steps.find((s) => s.id === "version");
  assert.ok(step?.run, "build job has no `version` step");
  const dir = mkdtempSync(path.join(tmpdir(), "stamp-publish-wf-"));
  try {
    writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "@openthink/stamp", version }));
    const out = path.join(dir, "github_output");
    writeFileSync(out, "");
    const res = spawnSync("bash", ["-e", "-c", step.run], {
      cwd: dir,
      env: { PATH: process.env.PATH, GITHUB_REF: ref, GITHUB_OUTPUT: out },
      encoding: "utf8",
    });
    const m = /^dist_tag<<(\S+)\n([\s\S]*?)\n\1$/m.exec(readFileSync(out, "utf8"));
    return { status: res.status, distTag: m?.[2], stderr: res.stderr };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("publish.yml dist-tag selection (AGT-2236)", () => {
  it("keeps main's behaviour: bare versions go to latest, prereleases to their label", () => {
    for (const [version, tag] of [["3.7.0", "latest"], ["4.0.0-rc.1", "rc"], ["4.0.0-alpha.3", "alpha"]]) {
      const r = runVersionStep("refs/heads/main", version);
      assert.equal(r.status, 0, r.stderr);
      assert.equal(r.distTag, tag, version);
    }
  });

  it("never tags a release/1.x publish latest: it goes to legacy-1", () => {
    const r = runVersionStep("refs/heads/release/1.x", "1.11.1");
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.distTag, "legacy-1");
  });

  it("keeps release-line prereleases off the shared prerelease tags", () => {
    const r = runVersionStep("refs/heads/release/1.x", "1.12.0-rc.1");
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.distTag, "legacy-1");
  });

  it("refuses a release line publishing another major's version", () => {
    const r = runVersionStep("refs/heads/release/1.x", "3.7.0");
    assert.notEqual(r.status, 0);
    assert.equal(r.distTag, undefined);
  });

  it("fails closed on any other ref", () => {
    for (const ref of ["refs/heads/release/1.y", "refs/heads/feature", "refs/tags/v1.0.0", ""]) {
      const r = runVersionStep(ref, "1.11.1");
      assert.notEqual(r.status, 0, `ref ${JSON.stringify(ref)} should not publish`);
      assert.equal(r.distTag, undefined);
    }
  });

  it("publishes only from main and the release/1.x line", () => {
    const raw = parse(readFileSync(WORKFLOW_PATH, "utf8")) as { on: { push: { branches: string[] } } };
    assert.deepEqual(raw.on.push.branches, ["main", "release/1.x"]);
  });
});
