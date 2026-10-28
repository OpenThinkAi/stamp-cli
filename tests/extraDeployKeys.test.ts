/**
 * AGT-2249: GitHub's DeployKey ruleset bypass is repo-scoped, so every
 * write-enabled deploy key on a mirror bypasses stamp-mirror-only.
 * `stamp provision` (incl. --migrate-bypass) warns about any write key
 * other than the canonical stamp-mirror key.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  formatExtraDeployKeyWarning,
  otherWriteDeployKeys,
  warnOnExtraWriteDeployKeys,
  type DeployKeyInfo,
} from "../src/lib/ghRuleset.ts";

const KEYS: DeployKeyInfo[] = [
  { id: 1, title: "stamp-mirror", read_only: false },
  { id: 2, title: "ci-deploy", read_only: false },
  { id: 3, title: "docs-reader", read_only: true },
];

function captureLog(fn: () => void): string {
  const lines: string[] = [];
  const orig = console.log;
  console.log = (...a: unknown[]) => void lines.push(a.join(" "));
  try {
    fn();
  } finally {
    console.log = orig;
  }
  return lines.join("\n");
}

describe("otherWriteDeployKeys", () => {
  it("flags write keys other than the canonical one; ignores read-only keys", () => {
    assert.deepEqual(otherWriteDeployKeys(KEYS, 1).map((k) => k.id), [2]);
  });

  it("returns nothing when the canonical key is the only write key", () => {
    assert.deepEqual(otherWriteDeployKeys([KEYS[0]!, KEYS[2]!], 1), []);
  });
});

describe("formatExtraDeployKeyWarning", () => {
  it("names each extra key and the remediation", () => {
    const w = formatExtraDeployKeyWarning("acme", "widget", [KEYS[1]!]);
    assert.ok(w);
    assert.match(w, /"ci-deploy" \(id 2\)/);
    assert.match(w, /EVERY write deploy key/);
    assert.match(w, /\/repos\/acme\/widget\/keys/);
  });

  it("is null when there are none", () => {
    assert.equal(formatExtraDeployKeyWarning("acme", "widget", []), null);
  });
});

describe("warnOnExtraWriteDeployKeys", () => {
  it("prints the warning from the listing", () => {
    const out = captureLog(() => warnOnExtraWriteDeployKeys("acme", "widget", 1, () => KEYS));
    assert.match(out, /other write-enabled deploy key/);
  });

  it("prints nothing for a clean repo", () => {
    const out = captureLog(() =>
      warnOnExtraWriteDeployKeys("acme", "widget", 1, () => [KEYS[0]!]),
    );
    assert.equal(out, "");
  });

  it("says the check could not run when the listing fails", () => {
    const out = captureLog(() => warnOnExtraWriteDeployKeys("acme", "widget", 1, () => null));
    assert.match(out, /could not list deploy keys/);
  });
});
