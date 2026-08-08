/**
 * Tests for the `stamp server-repos` client→server invocation shape
 * (issue #67).
 *
 * The stamp server runs the `git` account under `git-shell`, which only
 * executes verbs present in `/home/git/git-shell-commands/`. A raw shell
 * string is not a verb: `server-repos list` used to send
 * `ls -1 /srv/git/` and died with `fatal: unrecognized command`.
 *
 * The fixture here is a fake `ssh` that emulates exactly that constraint,
 * and — importantly — derives its whitelist from the *real* Dockerfile
 * symlink lines. So a verb the client sends but nobody wired into the
 * image fails the test, which is the specific four-touchpoint mistake
 * this repo keeps making.
 *
 * The destructive `delete` path is exercised against this fixture only.
 * Nothing here talks to a real server.
 *
 * Everything lives in ONE suite on purpose: the fixture works by
 * prepending a stub dir to `process.env.PATH`, which is process-global.
 * Sibling top-level suites run concurrently and would clobber each
 * other's stub between an `await` and the `spawnSync` that follows.
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import {
  filterLiveBareRepoNames,
  runServerRepoDelete,
  runServerRepoList,
} from "../src/commands/serverRepo.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");
const DOCKERFILE = resolve(repoRoot, "server", "Dockerfile");

const SERVER_FLAG = "stamp.example.test:2222";

/**
 * The verbs git-shell will actually accept, read out of the Dockerfile's
 * `ln -s ... /home/git/git-shell-commands/<verb>` lines. This is the
 * source of truth the running image is built from.
 */
function dockerfileGitShellVerbs(): Set<string> {
  const contents = readFileSync(DOCKERFILE, "utf-8");
  const verbs = new Set<string>();
  const re = /ln\s+-s\s+\S+\s+\/home\/git\/git-shell-commands\/([A-Za-z0-9._-]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(contents)) !== null) verbs.add(m[1]!);
  // git-shell's built-ins are always available without a symlink.
  for (const b of ["git-receive-pack", "git-upload-pack", "git-upload-archive"]) {
    verbs.add(b);
  }
  return verbs;
}

const dirs: string[] = [];
const origPath = process.env.PATH;
let argvLog = "";

/**
 * Install a fake `ssh` that behaves like git-shell: it accepts only the
 * whitelisted verbs and rejects anything else the way git-shell does
 * (`fatal: unrecognized command '<cmd>'`, exit 128). Records the remote
 * command argv so tests can assert the wire shape.
 */
function stubSsh(stdoutForVerb: Record<string, string> = {}): void {
  const dir = mkdtempSync(join(tmpdir(), "stamp-ssh-stub-"));
  dirs.push(dir);
  argvLog = join(dir, "argv.log");

  const allowed = [...dockerfileGitShellVerbs()].join(" ");
  const cases = Object.entries(stdoutForVerb)
    // %b (not %s) so the \n escapes JSON.stringify emits become real
    // newlines — the client filters on line shape, so a literal "\n"
    // collapses every fixture to a single unparseable line.
    .map(([verb, out]) => `    ${verb}) printf '%b' ${JSON.stringify(out)} ;;`)
    .join("\n");

  const ssh = join(dir, "ssh");
  writeFileSync(
    ssh,
    `#!/bin/sh
# Skip ssh's own options to find the destination, then treat everything
# after it as the remote command — same split the real ssh does.
while [ $# -gt 0 ]; do
  case "$1" in
    -p) shift 2 ;;
    --) shift; break ;;
    *) break ;;
  esac
done
dest="$1"; shift
printf '%s\\n' "$*" >> ${JSON.stringify(argvLog)}

# git-shell semantics: the FIRST argument is the verb and it must be
# whitelisted. A raw shell string arrives as one unrecognized blob.
verb="$1"
for a in ${allowed}; do
  if [ "$a" = "$verb" ]; then
    case "$verb" in
${cases}
    esac
    exit 0
  fi
done
echo "fatal: unrecognized command '$*'" >&2
exit 128
`,
  );
  chmodSync(ssh, 0o755);
  process.env.PATH = `${dir}:${origPath}`;
}

function recordedCommands(): string[] {
  return readFileSync(argvLog, "utf-8").split("\n").filter(Boolean);
}

/** Capture console.log while running `fn`. */
function captureStdout(fn: () => void): string[] {
  const lines: string[] = [];
  const orig = console.log;
  console.log = (...args: unknown[]) => {
    lines.push(args.map(String).join(" "));
  };
  try {
    fn();
  } finally {
    console.log = orig;
  }
  return lines;
}

const LIST_FIXTURE = {
  "list-stamp-repos": "stamp-cli.git\nbloom-cms.git\n",
  "list-trash": "20260427T193412Z-old.git  size: 1.2M  deleted-at: 2026-04-27\n",
  "delete-stamp-repo": "",
};

describe("server-repos git-shell transport (issue #67)", () => {
  after(() => {
    process.env.PATH = origPath;
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  // ── the verb is wired into the image (all four touchpoints) ──────────

  it("Dockerfile whitelists list-stamp-repos for git-shell", () => {
    assert.ok(
      dockerfileGitShellVerbs().has("list-stamp-repos"),
      "list-stamp-repos must be symlinked into /home/git/git-shell-commands",
    );
  });

  it("the server script exists and is a shell script", () => {
    const script = readFileSync(
      resolve(repoRoot, "server", "list-stamp-repos"),
      "utf-8",
    );
    assert.match(script, /^#!\/bin\/sh/);
  });

  it("Dockerfile COPYs the script and marks it executable", () => {
    const contents = readFileSync(DOCKERFILE, "utf-8");
    assert.match(
      contents,
      /COPY server\/list-stamp-repos \/usr\/local\/bin\/list-stamp-repos/,
    );
    assert.match(contents, /chmod \+x[\s\S]*\/usr\/local\/bin\/list-stamp-repos/);
  });

  // ── the fixture genuinely models git-shell ───────────────────────────

  it("rejects a raw shell string the way git-shell does", () => {
    stubSsh();
    const r = spawnSync(
      "ssh",
      ["-p", "2222", "--", "git@stamp.example.test", "ls", "-1", "/srv/git/"],
      { encoding: "utf8" },
    );
    assert.equal(r.status, 128);
    assert.match(r.stderr, /unrecognized command 'ls -1 \/srv\/git\/'/);
  });

  // ── list ─────────────────────────────────────────────────────────────

  it("list succeeds against a git-shell server and lists the repos", () => {
    stubSsh(LIST_FIXTURE);
    const out = captureStdout(() => runServerRepoList({ server: SERVER_FLAG }));
    assert.deepEqual(out, ["stamp-cli", "bloom-cms"]);
  });

  it("list sends a bare permitted verb, not a shell string", () => {
    stubSsh(LIST_FIXTURE);
    runServerRepoList({ server: SERVER_FLAG });
    const cmds = recordedCommands();
    assert.deepEqual(cmds, ["list-stamp-repos"]);
    // The regression being guarded: no `ls`, no path, no shell string.
    assert.doesNotMatch(cmds[0]!, /ls|\/srv\/git/);
  });

  it("list --trash keeps using its own permitted verb", () => {
    stubSsh(LIST_FIXTURE);
    runServerRepoList({ server: SERVER_FLAG, trash: true });
    assert.deepEqual(recordedCommands(), ["list-trash"]);
  });

  it("list reports an empty server without inventing entries", () => {
    stubSsh({ "list-stamp-repos": "(no live bare repos)\n" });
    const out = captureStdout(() => runServerRepoList({ server: SERVER_FLAG }));
    assert.deepEqual(out, ["(no live bare repos)"]);
  });

  // ── delete (fixture only — never a real server) ───────────────────────

  it("delete sends delete-stamp-repo as a permitted verb with the name as argv", async () => {
    stubSsh(LIST_FIXTURE);
    await runServerRepoDelete({
      server: SERVER_FLAG,
      name: "fixture-repo",
      yes: true,
    });
    assert.deepEqual(recordedCommands(), ["delete-stamp-repo fixture-repo"]);
  });

  it("delete passes --purge through as a separate argv element", async () => {
    stubSsh(LIST_FIXTURE);
    await runServerRepoDelete({
      server: SERVER_FLAG,
      name: "fixture-repo",
      purge: true,
      yes: true,
    });
    assert.deepEqual(recordedCommands(), [
      "delete-stamp-repo fixture-repo --purge",
    ]);
  });

  it("delete normalizes a .git suffix before it reaches the server", async () => {
    stubSsh(LIST_FIXTURE);
    await runServerRepoDelete({
      server: SERVER_FLAG,
      name: "fixture-repo.git",
      yes: true,
    });
    assert.deepEqual(recordedCommands(), ["delete-stamp-repo fixture-repo"]);
  });

  it("delete uses a verb the Dockerfile actually whitelists", () => {
    assert.ok(dockerfileGitShellVerbs().has("delete-stamp-repo"));
  });

  // ── output filtering ─────────────────────────────────────────────────

  it("filterLiveBareRepoNames strips .git and drops non-repo entries", () => {
    const names = filterLiveBareRepoNames(
      ["stamp-cli.git", ".trash", ".ssh-host-keys", "lost+found", "bloom.git", ""].join(
        "\n",
      ),
    );
    assert.deepEqual(names, ["stamp-cli", "bloom"]);
  });

  it("filterLiveBareRepoNames drops the server's empty-state sentinel", () => {
    assert.deepEqual(filterLiveBareRepoNames("(no live bare repos)\n"), []);
  });
});
