/**
 * `stamp provision --yes` and the `github` mirror remote (issue #86).
 *
 * Provision's last step is `stamp bootstrap`, whose protected-branch merge
 * hits the audit-H1 confirmation gate. Before --yes existed on provision, a
 * headless run (agent session, CI) created the server repo, clone, GitHub
 * mirror, deploy key and Ruleset, and only then died on "no TTY". Two fixes
 * are asserted here:
 *
 *   1. `--yes` exists on provision and is forwarded to bootstrap (only).
 *      Without it and with no TTY, provision refuses BEFORE any remote work.
 *      "Before any remote work" is checked by putting a fake `ssh` first on
 *      PATH that records every invocation: provision's first remote action is
 *      `ssh … new-stamp-repo`, so an empty record means nothing was touched.
 *   2. A provision that creates a mirror adds it to the clone as `github`.
 *
 * The provision → runBootstrap → runMerge half of the --yes wiring is a
 * compile-time guarantee (excess-property checks on the object literals),
 * the same way tests/bootstrapYes.test.ts treats bootstrap → runMerge.
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

import { mergeConfirmationWouldFail } from "../src/lib/humanMerge.ts";
import { parseGithubOriginUrl } from "../src/lib/ghRuleset.ts";
import {
  addGithubMirrorRemote,
  githubMirrorRemoteUrl,
} from "../src/commands/provision.ts";

const here = dirname(fileURLToPath(import.meta.url));
const cliEntry = join(here, "..", "src", "index.ts");
// Absolute, not the bare "tsx" specifier: these runs use a temp-dir cwd, and
// a bare `--import tsx` resolves against the cwd (see bootstrapYes.test.ts).
const tsxLoader = import.meta.resolve("tsx");

/**
 * Run the real CLI from source with piped stdio (so neither stdin nor stdout
 * is a TTY) and a fake `ssh` first on PATH that appends its argv to a log and
 * exits 1. Returns the result plus what the fake ssh recorded.
 */
function runProvisionCli(args: string[], extraEnv: Record<string, string> = {}) {
  const work = mkdtempSync(join(tmpdir(), "stamp-provision-yes-"));
  const bin = join(work, "bin");
  const sshLog = join(work, "ssh.log");
  spawnSync("mkdir", ["-p", bin]);
  const fakeSsh = join(bin, "ssh");
  writeFileSync(
    fakeSsh,
    `#!/bin/sh\necho "$@" >> "${sshLog}"\necho "fake ssh: refusing" >&2\nexit 1\n`,
  );
  chmodSync(fakeSsh, 0o755);

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    PATH: `${bin}:${process.env.PATH ?? ""}`,
    STAMP_SUPPRESS_LLM_NOTICE: "1",
    NO_COLOR: "1",
    ...extraEnv,
  };
  // The opt-out under test must come only from the flag or extraEnv.
  if (!("STAMP_REQUIRE_HUMAN_MERGE" in extraEnv)) {
    delete env.STAMP_REQUIRE_HUMAN_MERGE;
  }

  const result = spawnSync(
    process.execPath,
    ["--import", tsxLoader, cliEntry, "provision", ...args],
    { cwd: work, encoding: "utf8", env, stdio: ["pipe", "pipe", "pipe"] },
  );
  const sshCalls = existsSync(sshLog)
    ? readFileSync(sshLog, "utf8").trim().split("\n").filter(Boolean)
    : [];
  return { ...result, output: `${result.stdout}${result.stderr}`, sshCalls, work };
}

describe("mergeConfirmationWouldFail", () => {
  const noTty = { stdin: false, stdout: false };
  const tty = { stdin: true, stdout: true };

  it("fails with no TTY and no opt-out", () => {
    assert.equal(mergeConfirmationWouldFail({ env: {}, isTTY: noTty }), true);
  });

  it("fails when only one of stdin/stdout is a TTY (matches requireHumanMerge)", () => {
    assert.equal(
      mergeConfirmationWouldFail({ env: {}, isTTY: { stdin: true, stdout: false } }),
      true,
    );
    assert.equal(
      mergeConfirmationWouldFail({ env: {}, isTTY: { stdin: false, stdout: true } }),
      true,
    );
  });

  it("passes with --yes even without a TTY", () => {
    assert.equal(mergeConfirmationWouldFail({ yes: true, env: {}, isTTY: noTty }), false);
  });

  it("passes with STAMP_REQUIRE_HUMAN_MERGE=0 even without a TTY", () => {
    assert.equal(
      mergeConfirmationWouldFail({ env: { STAMP_REQUIRE_HUMAN_MERGE: "0" }, isTTY: noTty }),
      false,
    );
  });

  it("does not treat other env values as an opt-out", () => {
    assert.equal(
      mergeConfirmationWouldFail({ env: { STAMP_REQUIRE_HUMAN_MERGE: "1" }, isTTY: noTty }),
      true,
    );
  });

  it("passes at an interactive terminal (the prompt will be shown)", () => {
    assert.equal(mergeConfirmationWouldFail({ env: {}, isTTY: tty }), false);
  });
});

describe("stamp provision --yes", () => {
  it("is listed in --help as an opt-in flag that enables unattended runs", () => {
    const { stdout, status } = runProvisionCli(["--help"]);
    assert.equal(status, 0, "provision --help should exit 0");
    assert.match(stdout, /-y, --yes/);
    assert.match(stdout, /unattended/i);
    assert.match(stdout, /audit H1/i);
    assert.doesNotMatch(stdout, /--no-yes/, "--yes must never default on");
  });

  it("without --yes and with no TTY, refuses before any remote work", () => {
    const { status, stderr, sshCalls } = runProvisionCli([
      "demo",
      "--server",
      "stamp.invalid:2222",
      "--org",
      "acme",
    ]);
    assert.notEqual(status, 0, "provision must fail");
    assert.match(stderr, /confirmation required/);
    assert.match(stderr, /no TTY/);
    assert.match(stderr, /stamp provision demo --org acme --yes/, "hint must name the fix");
    assert.match(stderr, /Nothing has been created yet/);
    assert.deepEqual(sshCalls, [], "no ssh (= no remote work) may happen before the refusal");
  });

  it("with --yes, gets past the pre-check to the first remote step", () => {
    const { status, output, sshCalls } = runProvisionCli([
      "demo",
      "--server",
      "stamp.invalid:2222",
      "--yes",
    ]);
    // The fake ssh refuses, so provision still fails — but at the server
    // step, which proves the pre-check let it through.
    assert.notEqual(status, 0);
    assert.doesNotMatch(output, /confirmation required/);
    assert.equal(sshCalls.length, 1, `expected one ssh call, got: ${sshCalls.join(" | ")}`);
    assert.match(sshCalls[0]!, /new-stamp-repo demo/);
  });

  it("STAMP_REQUIRE_HUMAN_MERGE=0 also satisfies the pre-check", () => {
    const { output, sshCalls } = runProvisionCli(
      ["demo", "--server", "stamp.invalid:2222"],
      { STAMP_REQUIRE_HUMAN_MERGE: "0" },
    );
    assert.doesNotMatch(output, /confirmation required/);
    assert.equal(sshCalls.length, 1);
  });

  it("--dry-run still previews the plan with no TTY, and says how the merge will be confirmed", () => {
    const { status, stdout, sshCalls } = runProvisionCli([
      "demo",
      "--server",
      "stamp.invalid:2222",
      "--org",
      "acme",
      "--dry-run",
    ]);
    assert.equal(status, 0);
    assert.match(stdout, /merge confirm:\s+interactive prompt/);
    assert.match(stdout, /github remote:\s+git@github\.com:acme\/demo\.git/);
    assert.deepEqual(sshCalls, []);

    const withYes = runProvisionCli([
      "demo",
      "--server",
      "stamp.invalid:2222",
      "--dry-run",
      "--yes",
    ]);
    assert.equal(withYes.status, 0);
    assert.match(withYes.stdout, /merge confirm:\s+skipped for the bootstrap merge \(--yes\)/);
  });
});

describe("github mirror remote", () => {
  const mirror = { owner: "MicroMediaSites", repo: "dask" };

  it("uses an SSH URL that parses back to the same mirror", () => {
    const url = githubMirrorRemoteUrl(mirror);
    assert.equal(url, "git@github.com:MicroMediaSites/dask.git");
    assert.deepEqual(parseGithubOriginUrl(url), mirror);
  });

  it("adds a `github` remote to the clone alongside origin", () => {
    const clone = mkdtempSync(join(tmpdir(), "stamp-provision-remote-"));
    spawnSync("git", ["init", "-q", clone]);
    spawnSync("git", ["-C", clone, "remote", "add", "origin", "ssh://git@stamp.invalid:2222/srv/git/dask.git"]);

    addGithubMirrorRemote(clone, mirror);

    const get = spawnSync("git", ["-C", clone, "remote", "get-url", "github"], { encoding: "utf8" });
    assert.equal(get.status, 0, get.stderr);
    assert.equal(get.stdout.trim(), "git@github.com:MicroMediaSites/dask.git");
    const origin = spawnSync("git", ["-C", clone, "remote", "get-url", "origin"], { encoding: "utf8" });
    assert.equal(origin.stdout.trim(), "ssh://git@stamp.invalid:2222/srv/git/dask.git");
  });

  it("warns instead of throwing when the remote cannot be added", () => {
    const clone = mkdtempSync(join(tmpdir(), "stamp-provision-remote-"));
    spawnSync("git", ["init", "-q", clone]);
    spawnSync("git", ["-C", clone, "remote", "add", "github", "git@github.com:someone/else.git"]);

    const errors: string[] = [];
    const original = console.error;
    console.error = (...a: unknown[]) => {
      errors.push(a.join(" "));
    };
    try {
      assert.doesNotThrow(() => addGithubMirrorRemote(clone, mirror));
    } finally {
      console.error = original;
    }
    assert.match(errors.join("\n"), /warning: could not add the `github` remote/);
    assert.match(errors.join("\n"), /remote add github git@github\.com:MicroMediaSites\/dask\.git/);
  });
});
