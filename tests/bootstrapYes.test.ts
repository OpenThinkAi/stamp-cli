/**
 * `stamp bootstrap --yes` — the automated-merge-intent passthrough.
 *
 * Bootstrap performs its own protected-branch merge (step 8), so it hits the
 * audit-H1 gate in `lib/humanMerge.ts` like any other merge. Before this flag
 * existed there was no way to declare intent for it, which made bootstrap
 * impossible to run unattended: a CI shell or a build worker with no stdin TTY
 * hard-fails at the confirmation prompt. That is the correct H1 behaviour, but
 * it left such callers with only the process-wide `STAMP_REQUIRE_HUMAN_MERGE=0`
 * escape hatch, which un-gates every *other* merge in the same process.
 *
 * `requireHumanMerge`'s own opt-out semantics are covered by humanMerge.test.ts.
 * What is untested there — and what actually broke — is the WIRING: the flag
 * has to exist on the command, and it has to survive the trip into
 * `BootstrapOptions`. Both are asserted here against the real commander program,
 * driven through tsx so no build step is required.
 *
 * The bootstrap → `runMerge` half of the wiring is a compile-time guarantee:
 * `runMerge` takes `MergeOptions`, and TypeScript's excess-property check on the
 * object literal rejects a misspelled key, so `npm run typecheck` fails if the
 * passthrough is renamed on one side only.
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { describe, it } from "node:test";

const here = dirname(fileURLToPath(import.meta.url));
const cliEntry = join(here, "..", "src", "index.ts");

/**
 * Resolved absolutely, not as the bare specifier "tsx". One of these runs uses a
 * temp dir as its cwd, and a bare `--import tsx` is resolved relative to the
 * cwd — from outside the project it fails to load, so the child dies before
 * commander ever parses and every assertion about parsing passes vacuously.
 */
const tsxLoader = import.meta.resolve("tsx");

/** Run the real CLI from source. `cwd` matters: bootstrap resolves a repo root. */
const runCli = (args: string[], cwd: string) =>
  spawnSync(
    process.execPath,
    ["--import", tsxLoader, cliEntry, ...args],
    {
      cwd,
      encoding: "utf8",
      // Commander writes help to stdout and errors to stderr; capture both.
      env: { ...process.env, STAMP_SUPPRESS_LLM_NOTICE: "1", NO_COLOR: "1" },
    },
  );

describe("stamp bootstrap --yes", () => {
  it("is listed in the command's help output", () => {
    const { stdout, status } = runCli(["bootstrap", "--help"], here);

    assert.equal(status, 0, "bootstrap --help should exit 0");
    assert.match(
      stdout,
      /-y, --yes/,
      "bootstrap --help must advertise the -y/--yes flag",
    );
  });

  it("documents that it is what makes an unattended run possible", () => {
    const { stdout } = runCli(["bootstrap", "--help"], here);

    // The whole reason the flag exists. If this wording drifts to something
    // that no longer tells an operator WHEN to reach for it, the flag becomes
    // undiscoverable to exactly the caller it was added for.
    assert.match(
      stdout,
      /unattended/i,
      "the --yes help text must say it enables unattended runs",
    );
    assert.match(
      stdout,
      /audit H1/i,
      "the --yes help text must point at the control it opts out of",
    );
  });

  it("is accepted by the command rather than rejected as unknown", () => {
    // Run somewhere that is definitively not a stamp repo, so bootstrap fails
    // on the repo lookup. That failure is expected and is not what is under
    // test — what matters is that commander parsed `--yes` first. Before the
    // flag was wired up, commander rejected the invocation outright with
    // "unknown option", which is the regression this guards.
    const notARepo = mkdtempSync(join(tmpdir(), "stamp-bootstrap-yes-"));
    const { stderr, stdout } = runCli(
      ["bootstrap", "--yes", "--dry-run"],
      notARepo,
    );

    const output = `${stdout}${stderr}`;
    assert.doesNotMatch(
      output,
      /unknown option/i,
      `--yes must be a recognised bootstrap option; got: ${output}`,
    );
  });

  it("still defaults to the interactive prompt without the flag", () => {
    const { stdout } = runCli(["bootstrap", "--help"], here);

    // Commander renders `--no-*` negations distinctly; `--yes` must NOT be one
    // of those, or the default would invert and every bootstrap would merge
    // unattended — the exact opposite of what H1 wants.
    assert.doesNotMatch(
      stdout,
      /--no-yes/,
      "--yes must be an opt-in flag, never a default-on negatable one",
    );
  });
});
