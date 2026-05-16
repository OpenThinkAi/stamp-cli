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
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, it } from "node:test";

const ACTION_PATH = path.resolve(
  import.meta.dirname,
  "..",
  ".github",
  "actions",
  "verify-attestation",
  "action.yml",
);
const body = readFileSync(ACTION_PATH, "utf8");

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
});
