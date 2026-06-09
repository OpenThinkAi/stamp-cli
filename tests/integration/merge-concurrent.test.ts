/**
 * Concurrent-invocation regression test for `stamp merge` (AGT-474, GH#31).
 *
 * The race this guards against: two `stamp merge` invocations running in
 * the same checkout against different feature branches can interleave
 * their `git merge --no-ff` and `git commit --amend` windows, producing a
 * commit whose `Stamp-Payload.head_sha` doesn't match its actual second
 * parent. Server pre-receive correctly rejects but the bad commit blocks
 * subsequent pushes.
 *
 * Fix (this ticket): `runMerge` acquires an exclusive file lock per repo
 * (per gitCommonDir) around the merge → amend window. Concurrent same-
 * checkout invocations either block-then-run or exit non-zero with the
 * "another stamp merge is in progress" diagnostic.
 *
 * Test shape:
 *  - Sets up one v3-mode stamp-gated repo with TWO feature branches
 *    (`feature-a`, `feature-b`).
 *  - Seeds approved verdicts for both.
 *  - Forks two child processes via `tsx` that each call `runMerge` against
 *    the same checkout but different `branch`. Starts them as close to
 *    simultaneously as possible.
 *  - Asserts:
 *      * at least ONE child exited 0
 *      * any failed child's stderr mentions "another stamp merge is in
 *        progress" — the lock-acquire path, not a mysterious crash
 *      * every NEW merge commit on main between baseMain and final main has
 *        a Stamp-Payload trailer AND its head_sha equals its actual second
 *        parent — the bug condition (head_sha != second parent) MUST NOT
 *        appear on any commit.
 *
 * Run as part of integration suite (~5s; the seed/spawn cost dominates).
 */

import { strict as assert } from "node:assert";
import { execFileSync, spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

import { parseCommitAttestation } from "../../src/lib/attestation.ts";
import { openDb, recordReview } from "../../src/lib/db.ts";
import { ensureUserKeypair } from "../../src/lib/keys.ts";
import { stampStateDbPath } from "../../src/lib/paths.ts";

// Bypass H1 human-confirmation gate (same as the sibling merge.test.ts).
process.env["STAMP_REQUIRE_HUMAN_MERGE"] = "0";

const REVIEWER_PROMPT = "You are the security reviewer. Approve everything.\n";

function git(repo: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd: repo,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

interface Harness {
  repo: string;
  home: string;
  prevHome: string | undefined;
  cleanup: () => void;
}

/**
 * v3-mode harness with two feature branches. Mirrors the v3 setup in
 * `merge.test.ts` but cuts TWO feature branches before checking back out
 * to main so the concurrent runners have distinct merge targets.
 */
function setupHarness(): Harness {
  const root = mkdtempSync(path.join(os.tmpdir(), "stamp-merge-concurrent-"));
  const repo = path.join(root, "repo");
  const home = path.join(root, "home");
  mkdirSync(repo, { recursive: true });
  mkdirSync(home, { recursive: true });

  const prevHome = process.env["HOME"];
  process.env["HOME"] = home;

  git(repo, ["init", "-q", "-b", "main"]);
  git(repo, ["config", "user.name", "Test"]);
  git(repo, ["config", "user.email", "test@example.invalid"]);
  git(repo, ["config", "commit.gpgsign", "false"]);

  mkdirSync(path.join(repo, ".stamp", "reviewers"), { recursive: true });
  mkdirSync(path.join(repo, ".stamp", "trusted-keys"), { recursive: true });

  writeFileSync(
    path.join(repo, ".stamp", "config.yml"),
    [
      "branches:",
      "  main:",
      "    required: [security]",
      "reviewers:",
      "  security:",
      "    prompt: .stamp/reviewers/security.md",
      "    tools: []",
      "",
    ].join("\n"),
  );
  writeFileSync(
    path.join(repo, ".stamp", "reviewers", "security.md"),
    REVIEWER_PROMPT,
  );

  const { keypair } = ensureUserKeypair();
  const pubFileName = keypair.fingerprint.replace(/:/g, "_") + ".pub";
  writeFileSync(
    path.join(repo, ".stamp", "trusted-keys", pubFileName),
    keypair.publicKeyPem,
  );

  writeFileSync(path.join(repo, "README.md"), "initial\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "initial: seed .stamp/ config"]);

  // Cut feature-a from main.
  git(repo, ["checkout", "-q", "-b", "feature-a"]);
  writeFileSync(path.join(repo, "a.txt"), "a\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "add a"]);

  // Cut feature-b from main (sibling, not stacked).
  git(repo, ["checkout", "-q", "main"]);
  git(repo, ["checkout", "-q", "-b", "feature-b"]);
  writeFileSync(path.join(repo, "b.txt"), "b\n");
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "add b"]);

  git(repo, ["checkout", "-q", "main"]);

  return {
    repo,
    home,
    prevHome,
    cleanup: () => {
      process.env["HOME"] = prevHome;
      rmSync(root, { recursive: true, force: true });
    },
  };
}

function seedApproval(
  repo: string,
  baseSha: string,
  headSha: string,
  reviewer: string,
): void {
  const db = openDb(stampStateDbPath(repo));
  try {
    recordReview(db, {
      reviewer,
      base_sha: baseSha,
      head_sha: headSha,
      verdict: "approved",
      issues: `${reviewer} approved`,
    });
  } finally {
    db.close();
  }
}

/**
 * Locate the stamp-cli repo root by walking up from this test file until we
 * see a package.json named `@openthink/stamp`. Used to anchor absolute paths
 * for the child-process driver (which can't trust process.cwd or relative
 * imports once it chdirs into the scratch repo).
 */
function findStampRepoRoot(startFrom: string): string {
  let dir = startFrom;
  for (let i = 0; i < 12; i++) {
    const pkg = path.join(dir, "package.json");
    try {
      const parsed = JSON.parse(readFileSync(pkg, "utf8")) as {
        name?: string;
      };
      if (parsed.name === "@openthink/stamp") return dir;
    } catch {
      // not here
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error(
    `could not locate stamp-cli repo root starting from ${startFrom}`,
  );
}

describe("stamp merge concurrent-invocation lock (AGT-474)", () => {
  it("two concurrent merges in the same checkout do not produce a head_sha/second-parent mismatch", () => {
    const thisFileDir = path.dirname(fileURLToPath(import.meta.url));
    const stampRepoRoot = findStampRepoRoot(thisFileDir);
    const mergeTsAbs = path.join(stampRepoRoot, "src", "commands", "merge.ts");

    const h = setupHarness();
    try {
      // Seed approvals for BOTH feature branches against the current main.
      const baseMain = git(h.repo, ["rev-parse", "main"]).trim();
      const headA = git(h.repo, ["rev-parse", "feature-a"]).trim();
      const headB = git(h.repo, ["rev-parse", "feature-b"]).trim();
      seedApproval(h.repo, baseMain, headA, "security");
      seedApproval(h.repo, baseMain, headB, "security");

      // Write a tiny driver into a scratch dir. The driver is invoked by
      // each child process via `node --import tsx`. It imports the absolute
      // path of `merge.ts` from the stamp-cli source tree, chdirs into the
      // scratch repo, and calls runMerge with the branch supplied on argv.
      //
      // tsx loader handles the .ts extension on import.
      const driverDir = mkdtempSync(
        path.join(os.tmpdir(), "stamp-merge-driver-"),
      );
      const driverPath = path.join(driverDir, "driver.mts");
      const driverSrc = [
        `const mergeMod = await import(${JSON.stringify(
          pathToFileURLString(mergeTsAbs),
        )});`,
        `process.chdir(${JSON.stringify(h.repo)});`,
        `process.env.STAMP_REQUIRE_HUMAN_MERGE = '0';`,
        `process.env.HOME = ${JSON.stringify(h.home)};`,
        `try {`,
        `  mergeMod.runMerge({ branch: process.argv[2], into: 'main', yes: true });`,
        `  process.exit(0);`,
        `} catch (err) {`,
        `  process.stderr.write((err && err.message) || String(err));`,
        `  process.exit(1);`,
        `}`,
      ].join("\n");
      writeFileSync(driverPath, driverSrc);

      const results = runTwoConcurrent({
        nodeBin: process.execPath,
        driverPath,
        branches: ["feature-a", "feature-b"],
        env: {
          ...process.env,
          STAMP_REQUIRE_HUMAN_MERGE: "0",
          HOME: h.home,
        },
      });
      rmSync(driverDir, { recursive: true, force: true });

      const summary = results
        .map(
          (r, i) =>
            `  child ${i} (${r.branch}): exit=${r.exitCode} stderr=${truncate(r.stderr, 300)}`,
        )
        .join("\n");

      // AC#3a: at least one success.
      const successes = results.filter((r) => r.exitCode === 0);
      assert.ok(
        successes.length >= 1,
        `expected at least one merge to succeed, got 0:\n${summary}`,
      );

      // AC#3a (continued): any failed child must have failed because of the
      // lock specifically — not a corrupt repo, missing dep, ENV issue, etc.
      for (const r of results) {
        if (r.exitCode !== 0) {
          assert.match(
            r.stderr,
            /another stamp merge is in progress/i,
            `child for ${r.branch} failed but not due to the lock — possible regression:\n${summary}`,
          );
        }
      }

      // AC#3b: every NEW merge commit on main between baseMain..main has
      // Stamp-Payload.head_sha == its actual second parent. The bug
      // condition (the trailer head_sha doesn't match the real second
      // parent) MUST NOT appear on any commit.
      const newCommits = git(h.repo, [
        "log",
        `${baseMain}..main`,
        "--pretty=%H",
      ])
        .trim()
        .split("\n")
        .filter(Boolean);

      assert.ok(
        newCommits.length >= 1,
        `expected at least one new commit on main; got none:\n${summary}`,
      );

      let signedMergeCount = 0;
      for (const sha of newCommits) {
        const parents = git(h.repo, ["rev-list", "--parents", "-n", "1", sha])
          .trim()
          .split(/\s+/)
          .slice(1);
        if (parents.length < 2) continue; // non-merge commit — skip

        signedMergeCount++;
        const message = git(h.repo, ["log", "-1", "--format=%B", sha]);
        const parsed = parseCommitAttestation(message);
        assert.ok(
          parsed,
          `merge commit ${sha.slice(0, 8)} has no Stamp-Payload trailer — ` +
            `an unsigned merge landed on main:\n${summary}`,
        );

        const secondParent = parents[1];
        assert.equal(
          parsed.payload.head_sha,
          secondParent,
          `merge commit ${sha.slice(0, 8)}: Stamp-Payload.head_sha=${parsed.payload.head_sha.slice(0, 8)} ` +
            `does not match second parent ${secondParent.slice(0, 8)} — the exact AGT-474/GH#31 corruption pattern.\n${summary}`,
        );
      }
      assert.ok(
        signedMergeCount >= 1,
        `expected at least one signed merge on main; got ${signedMergeCount}:\n${summary}`,
      );
    } finally {
      h.cleanup();
    }
  });
});

interface ChildResult {
  branch: string;
  exitCode: number;
  stdout: string;
  stderr: string;
}

/**
 * Spawn two driver processes in parallel via bash `&` + `wait`. spawnSync
 * blocks per call; bash gives us true parallelism without pulling in extra
 * async machinery. Captured streams are read after both children exit.
 */
function runTwoConcurrent(args: {
  nodeBin: string;
  driverPath: string;
  branches: [string, string];
  env: NodeJS.ProcessEnv;
}): ChildResult[] {
  const tmp = mkdtempSync(path.join(os.tmpdir(), "stamp-concurrent-out-"));
  const out0 = path.join(tmp, "out0");
  const err0 = path.join(tmp, "err0");
  const out1 = path.join(tmp, "out1");
  const err1 = path.join(tmp, "err1");
  const rc0 = path.join(tmp, "rc0");
  const rc1 = path.join(tmp, "rc1");

  const cmd = (branch: string, out: string, err: string, rc: string) =>
    `'${args.nodeBin}' --import tsx '${args.driverPath}' '${branch}' >'${out}' 2>'${err}'; echo $? >'${rc}'`;

  const script = [
    "set +e",
    `( ${cmd(args.branches[0], out0, err0, rc0)} ) &`,
    "P0=$!",
    `( ${cmd(args.branches[1], out1, err1, rc1)} ) &`,
    "P1=$!",
    "wait $P0",
    "wait $P1",
  ].join("\n");

  spawnSync("bash", ["-c", script], {
    stdio: ["ignore", "inherit", "inherit"],
    env: args.env,
  });

  const read = (p: string) => {
    try {
      return readFileSync(p, "utf8");
    } catch {
      return "";
    }
  };
  const readRc = (p: string) => Number(read(p).trim() || "1");

  const results: ChildResult[] = [
    {
      branch: args.branches[0],
      exitCode: readRc(rc0),
      stdout: read(out0),
      stderr: read(err0),
    },
    {
      branch: args.branches[1],
      exitCode: readRc(rc1),
      stdout: read(out1),
      stderr: read(err1),
    },
  ];

  rmSync(tmp, { recursive: true, force: true });
  return results;
}

function pathToFileURLString(p: string): string {
  return `file://${p}`;
}

function truncate(s: string, n: number): string {
  if (s.length <= n) return s;
  return `${s.slice(0, n)}…(truncated, ${s.length} total)`;
}
