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
 *   - every install uses --ignore-scripts.
 */

import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
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
  uses?: string;
  run?: string;
  with?: Record<string, unknown>;
}
interface Job {
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
