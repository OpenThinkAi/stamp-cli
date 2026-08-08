/**
 * Tests for gh-api failure reporting on deploy-key registration (issue #54).
 *
 * `gh api` puts the terse headline on stderr and the *response body* — the
 * only part naming the actual cause — on stdout. Preferring stderr dropped
 * "Deploy keys are disabled for this repository" on the floor and cost a
 * real debugging session. These cover the formatter and the end-to-end
 * shape a caller sees, including the actionable hint.
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";

import {
  formatGhApiFailure,
  registerDeployKey,
} from "../src/lib/ghRuleset.ts";

/** The exact body GitHub returns when an org has deploy keys switched off. */
const DEPLOY_KEYS_DISABLED_BODY = JSON.stringify({
  message: "Validation Failed",
  errors: [
    {
      resource: "PublicKey",
      code: "custom",
      message: "Deploy keys are disabled for this repository",
    },
  ],
});

describe("formatGhApiFailure", () => {
  it("surfaces errors[].message from a 422 body instead of dropping it", () => {
    const detail = formatGhApiFailure(
      DEPLOY_KEYS_DISABLED_BODY,
      "gh: Validation Failed (HTTP 422)",
      1,
    );
    assert.match(detail, /Deploy keys are disabled for this repository/);
    // The stderr headline is kept alongside, not replaced by, the body.
    assert.match(detail, /HTTP 422/);
  });

  it("keeps the top-level summary as a prefix to the specific errors", () => {
    const detail = formatGhApiFailure(DEPLOY_KEYS_DISABLED_BODY, "", 1);
    assert.equal(
      detail,
      "Validation Failed: Deploy keys are disabled for this repository",
    );
  });

  it("joins multiple errors[] messages", () => {
    const body = JSON.stringify({
      message: "Validation Failed",
      errors: [
        { message: "key is already in use" },
        { message: "key is invalid" },
      ],
    });
    const detail = formatGhApiFailure(body, "", 1);
    assert.match(detail, /key is already in use/);
    assert.match(detail, /key is invalid/);
  });

  it("falls back to the top-level message when errors[] is absent", () => {
    const detail = formatGhApiFailure(
      JSON.stringify({ message: "Not Found" }),
      "",
      1,
    );
    assert.equal(detail, "Not Found");
  });

  it("passes non-JSON stdout through verbatim", () => {
    const detail = formatGhApiFailure("some plain text failure", "", 1);
    assert.equal(detail, "some plain text failure");
  });

  it("de-dupes text echoed on both streams", () => {
    const detail = formatGhApiFailure("same thing", "same thing", 1);
    assert.equal(detail, "same thing");
  });

  it("falls back to the exit status when both streams are empty", () => {
    assert.equal(formatGhApiFailure("", "", 7), "gh api exited 7");
  });
});

/**
 * Drive the real `registerDeployKey` against a fake `gh` on PATH, so the
 * assertion covers the whole surface a provision run would print.
 */
describe("registerDeployKey error reporting", () => {
  const dirs: string[] = [];
  const origPath = process.env.PATH;

  after(() => {
    process.env.PATH = origPath;
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  /**
   * Install a `gh` stub that reports no existing key (so registration
   * proceeds to POST) and then fails the POST with `body` on stdout and
   * `headline` on stderr.
   */
  function stubGh(body: string, headline: string): void {
    const dir = mkdtempSync(join(tmpdir(), "stamp-gh-stub-"));
    dirs.push(dir);
    const gh = join(dir, "gh");
    writeFileSync(
      gh,
      // The --jq lookup (findDeployKey) must succeed with empty output;
      // anything else is the POST and must fail carrying the body.
      `#!/bin/sh
for a in "$@"; do
  if [ "$a" = "--jq" ]; then exit 0; fi
done
cat >/dev/null 2>&1
printf '%s' ${JSON.stringify(body)}
printf '%s' ${JSON.stringify(headline)} >&2
exit 1
`,
    );
    chmodSync(gh, 0o755);
    process.env.PATH = `${dir}:${origPath}`;
  }

  it("reports the deploy-keys-disabled cause and an actionable hint", () => {
    stubGh(DEPLOY_KEYS_DISABLED_BODY, "gh: Validation Failed (HTTP 422)");

    const res = registerDeployKey(
      "MicroMediaSites",
      "fx-tracker",
      "stamp-mirror",
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI stamp@server",
    );

    assert.equal(res.status, "failed");
    assert.equal(res.status === "failed" && typeof res.error, "string");
    const error = res.status === "failed" ? res.error : "";
    // The cause, not just "Validation Failed".
    assert.match(error, /Deploy keys are disabled for this repository/);
    // Context: which repo and which key title.
    assert.match(error, /MicroMediaSites\/fx-tracker/);
    assert.match(error, /stamp-mirror/);
    // The hint points at the setting that actually fixes it.
    assert.match(error, /hint: deploy keys are turned off/);
    assert.match(
      error,
      /github\.com\/MicroMediaSites\/fx-tracker\/settings\/keys/,
    );
  });

  it("does not attach the deploy-keys hint to unrelated failures", () => {
    stubGh(
      JSON.stringify({
        message: "Validation Failed",
        errors: [{ message: "key is already in use" }],
      }),
      "gh: Validation Failed (HTTP 422)",
    );

    const res = registerDeployKey(
      "MicroMediaSites",
      "fx-tracker",
      "stamp-mirror",
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI stamp@server",
    );

    assert.equal(res.status, "failed");
    const error = res.status === "failed" ? res.error : "";
    assert.match(error, /key is already in use/);
    assert.doesNotMatch(error, /hint: deploy keys are turned off/);
  });

  it("keeps the stub self-consistent: gh is the one we installed", () => {
    stubGh("{}", "");
    const which = spawnSync("sh", ["-c", "command -v gh"], {
      encoding: "utf8",
    });
    assert.match(which.stdout.trim(), /stamp-gh-stub-/);
  });
});
