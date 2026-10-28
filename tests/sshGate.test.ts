/**
 * AGT-2265 — the SSH session gate.
 *
 *   1. Command parsing (src/lib/sshGate.ts): git-shell's quoting rules,
 *      the path rule (only live /srv/git/<name>.git; dot-dirs, nesting,
 *      `..`, absolute paths elsewhere, relative and ~ paths refused) and
 *      the verb allowlist (kept in lockstep with server/Dockerfile).
 *   2. The access rule: operators and unscoped members everywhere, scoped
 *      members only where a repo's mirror mapping matches a grant.
 *   3. The authorized_keys lines the resolver and entrypoint emit.
 *   4. stamp-gate-check end to end (tsx, temp users.db, faked
 *      SSH_USER_AUTH) for the identity and refusal paths.
 *
 * Over-real-SSH coverage (member refused .trash / .prompts-cache / a
 * non-granted repo, admin unaffected, push/pull through the gate) lives in
 * scripts/docker-boot-smoke.sh.
 */

import { strict as assert } from "node:assert";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { addRepoGrant } from "../src/lib/repoAccess.ts";
import { insertUser, openServerDb, type Role } from "../src/lib/serverDb.ts";
import { gatedAuthorizedKeysLine } from "../src/lib/sshForcedCommand.ts";
import {
  canonicalCommand,
  decideRepoAccess,
  decideVerbAccess,
  isLiveBareRepo,
  parseOriginalCommand,
  readServerRepoMapping,
  repoNameFromPath,
  splitCmdline,
  sqQuote,
  VERB_POLICIES,
  type GateCaller,
} from "../src/lib/sshGate.ts";

const ROOT = path.resolve(import.meta.dirname, "..");

function parseOk(cmd: string) {
  const r = parseOriginalCommand(cmd);
  assert.ok(r.ok, `expected ${JSON.stringify(cmd)} to parse; got ${!r.ok ? r.message : ""}`);
  return r.cmd;
}

function parseErr(cmd: string | undefined): string {
  const r = parseOriginalCommand(cmd);
  assert.ok(!r.ok, `expected ${JSON.stringify(cmd)} to be refused`);
  return r.message;
}

describe("splitCmdline matches git-shell's split_cmdline", () => {
  it("splits on whitespace and honours both quote styles", () => {
    assert.deepEqual(splitCmdline(`a  b\t'c d' "e f"`), ["a", "b", "c d", "e f"]);
  });
  it("concatenates adjacent quoted and bare segments into one word", () => {
    assert.deepEqual(splitCmdline(`'ab'\\''cd'`), ["ab'cd"]);
    assert.deepEqual(splitCmdline(`x"y z"w`), ["xy zw"]);
  });
  it("backslash escapes outside single quotes only", () => {
    assert.deepEqual(splitCmdline(`a\\ b "c\\"d" 'e\\f'`), ["a b", 'c"d', "e\\f"]);
  });
  it("refuses an unclosed quote or trailing backslash", () => {
    assert.equal(splitCmdline(`'abc`), null);
    assert.equal(splitCmdline(`"abc`), null);
    assert.equal(splitCmdline(`abc\\`), null);
  });
  it("sqQuote round-trips through the splitter", () => {
    for (const w of ["plain", "with space", "it's", "''", "a\\b", '"q"', "--flag"]) {
      assert.deepEqual(splitCmdline(sqQuote(w)), [w]);
    }
  });
});

describe("path rule", () => {
  it("accepts only live repos under /srv/git", () => {
    assert.equal(repoNameFromPath("/srv/git/foo.git"), "foo");
    assert.equal(repoNameFromPath("/srv/git/foo"), "foo");
    assert.equal(repoNameFromPath("/srv/git/foo.git/"), "foo");
    assert.equal(repoNameFromPath("/srv/git/my.repo_1-x.git"), "my.repo_1-x");
  });
  it("refuses dot-dirs, nesting, traversal and paths outside /srv/git", () => {
    for (const p of [
      "/srv/git/.trash/20200101T000000Z-x.git",
      "/srv/git/.trash",
      "/srv/git/.prompts-cache",
      "/srv/git/.stamp-state",
      "/srv/git/.ssh-client-keys",
      "/srv/git/..",
      "/srv/git/../etc",
      "/srv/git/a..b.git",
      "/srv/git/foo/../.trash/x.git",
      "/srv/git/org/repo.git",
      "/srv/git/",
      "/srv/git",
      "/srv/git//foo.git",
      "/srv/gitx/foo.git",
      "/etc/passwd",
      "/home/git/.ssh",
      "foo.git",
      "srv/git/foo.git",
      "~/foo.git",
      "~git/../../srv/git/.trash/x.git",
      "/srv/git/-foo.git",
      "/srv/git/foo bar.git",
      "/srv/git/foo.git//",
    ]) {
      assert.equal(repoNameFromPath(p), null, p);
    }
  });
});

describe("parseOriginalCommand", () => {
  it("parses each git transport verb and canonicalises the path", () => {
    for (const svc of ["git-upload-pack", "git-receive-pack", "git-upload-archive"]) {
      const c = parseOk(`${svc} '/srv/git/foo'`);
      assert.deepEqual(c, { kind: "git", service: svc, name: "foo", repoPath: "/srv/git/foo.git" });
      assert.equal(canonicalCommand(c), `${svc} '/srv/git/foo.git'`);
    }
  });
  it("accepts the `git upload-pack` spelling git-shell also accepts", () => {
    const c = parseOk(`git upload-pack '/srv/git/foo.git'`);
    assert.equal(canonicalCommand(c), `git-upload-pack '/srv/git/foo.git'`);
  });
  it("accepts unquoted and double-quoted paths", () => {
    assert.equal(canonicalCommand(parseOk(`git-upload-pack /srv/git/foo.git`)), `git-upload-pack '/srv/git/foo.git'`);
    assert.equal(canonicalCommand(parseOk(`git-upload-pack "/srv/git/foo.git"`)), `git-upload-pack '/srv/git/foo.git'`);
  });
  it("refuses dot-dir and traversal paths for git verbs", () => {
    assert.match(parseErr(`git-upload-pack '/srv/git/.trash/20200101T000000Z-x.git'`), /not allowed/);
    assert.match(parseErr(`git-upload-pack '/srv/git/.prompts-cache'`), /not allowed/);
    assert.match(parseErr(`git-upload-pack '/srv/git/../../etc'`), /not allowed/);
    assert.match(parseErr(`git-upload-pack '/srv/git/foo'\\''/../.trash'`), /not allowed/);
    assert.match(parseErr(`git-receive-pack 'foo.git'`), /not allowed/);
    assert.match(parseErr(`git-upload-archive '~/x'`), /not allowed/);
  });
  it("refuses git verbs with zero or several paths", () => {
    assert.match(parseErr(`git-upload-pack`), /exactly one/);
    assert.match(parseErr(`git-upload-pack '/srv/git/a.git' '/srv/git/b.git'`), /exactly one/);
  });
  it("parses allowlisted verbs and re-quotes their arguments", () => {
    const c = parseOk(`delete-stamp-repo foo --purge`);
    assert.deepEqual(c, { kind: "verb", verb: "delete-stamp-repo", args: ["foo", "--purge"] });
    assert.equal(canonicalCommand(c), `delete-stamp-repo 'foo' '--purge'`);
    const q = parseOk(`stamp-review --org "a b" --repo 'it'\\''s'`);
    assert.deepEqual(splitCmdline(canonicalCommand(q)), ["stamp-review", "--org", "a b", "--repo", "it's"]);
  });
  it("refuses unknown commands, the gate itself, and shell-ish input", () => {
    assert.match(parseErr(`sh -c id`), /unrecognized command 'sh'/);
    assert.match(parseErr(`stamp-gate 1`), /unrecognized command 'stamp-gate'/);
    assert.match(parseErr(`stamp-gate-check 1`), /unrecognized/);
    assert.match(parseErr(`/usr/bin/git-upload-pack '/srv/git/foo.git'`), /unrecognized/);
    assert.match(parseErr(`internal-sftp`), /unrecognized/);
    assert.match(parseErr(`git`), /unrecognized/);
    assert.match(parseErr(`list-stamp-repos\nsh`), /control characters/);
    assert.match(parseErr(`list-stamp-repos 'unclosed`), /could not parse/);
  });
  it("refuses an empty / interactive session", () => {
    assert.match(parseErr(undefined), /interactive sessions are not available/);
    assert.match(parseErr("   "), /interactive sessions are not available/);
  });
  it("bounds the echoed verb", () => {
    assert.ok(parseErr("x".repeat(500)).length < 120);
  });
});

describe("verb allowlist", () => {
  it("matches the git-shell-commands symlinks in server/Dockerfile (minus stamp-gate)", () => {
    const dockerfile = readFileSync(path.join(ROOT, "server", "Dockerfile"), "utf8");
    const linked = [...dockerfile.matchAll(/\/home\/git\/git-shell-commands\/([A-Za-z0-9-]+)/g)]
      .map((m) => m[1]!)
      .filter((v) => v !== "stamp-gate");
    assert.deepEqual([...new Set(linked)].sort(), Object.keys(VERB_POLICIES).sort());
    assert.match(dockerfile, /ln -s \/usr\/local\/bin\/stamp-gate \/home\/git\/git-shell-commands\/stamp-gate/);
    assert.match(dockerfile, /gate-check\.cjs \/usr\/local\/sbin\/stamp-gate-check/);
    assert.doesNotMatch(dockerfile, /git-shell-commands\/stamp-gate-check/);
  });
});

describe("access rule", () => {
  const admin: GateCaller = { role: "admin", grants: [] };
  const owner: GateCaller = { role: "owner", grants: [{ org: "acme", repo: "a" }] };
  const unscoped: GateCaller = { role: "member", grants: [] };
  const scoped: GateCaller = { role: "member", grants: [{ org: "acme", repo: "a" }] };
  const orgWide: GateCaller = { role: "member", grants: [{ org: "acme", repo: "*" }] };
  const never = () => {
    throw new Error("mapping must not be read for an unscoped caller");
  };

  it("operators and unscoped members reach every live repo without reading the mapping", () => {
    for (const c of [admin, owner, unscoped]) assert.deepEqual(decideRepoAccess(c, "x", never), { ok: true });
  });
  it("scoped members need a matching mapping", () => {
    assert.ok(decideRepoAccess(scoped, "x", () => ({ org: "acme", repo: "a" })).ok);
    assert.ok(!decideRepoAccess(scoped, "x", () => ({ org: "acme", repo: "b" })).ok);
    assert.ok(!decideRepoAccess(scoped, "x", () => ({ org: "other", repo: "a" })).ok);
    assert.ok(!decideRepoAccess(scoped, "x", () => null).ok, "no mapping fails closed");
    assert.ok(decideRepoAccess(orgWide, "x", () => ({ org: "acme", repo: "zzz" })).ok);
  });
  it("list-stamp-repos is refused only to scoped members; self-gating verbs pass", () => {
    assert.ok(decideVerbAccess(unscoped, "list-stamp-repos").ok);
    assert.ok(decideVerbAccess(admin, "list-stamp-repos").ok);
    assert.ok(!decideVerbAccess(scoped, "list-stamp-repos").ok);
    assert.ok(decideVerbAccess(scoped, "stamp-review").ok);
    assert.ok(!decideVerbAccess(admin, "not-a-verb").ok);
  });
});

describe("repo checks on disk", () => {
  function bare(dir: string, name: string, mirrorYml?: string): string {
    const repo = path.join(dir, `${name}.git`);
    execFileSync("git", ["init", "-q", "--bare", "-b", "main", repo]);
    if (mirrorYml !== undefined) {
      const work = path.join(dir, `${name}-work`);
      execFileSync("git", ["init", "-q", "-b", "main", work]);
      mkdirSync(path.join(work, ".stamp"));
      writeFileSync(path.join(work, ".stamp", "mirror.yml"), mirrorYml);
      execFileSync("git", ["-C", work, "add", "-A"]);
      execFileSync("git", ["-C", work, "-c", "user.email=t@e", "-c", "user.name=t", "commit", "-qm", "m"]);
      execFileSync("git", ["-C", work, "push", "-q", repo, "main"]);
    }
    return repo;
  }

  it("reads github.repo from HEAD's .stamp/mirror.yml", () => {
    const dir = realpathSync(mkdtempSync(path.join(os.tmpdir(), "stamp-gate-map-")));
    try {
      assert.deepEqual(readServerRepoMapping(bare(dir, "m", "github:\n  repo: Acme/Widgets\n")), {
        org: "acme",
        repo: "widgets",
      });
      assert.equal(readServerRepoMapping(bare(dir, "empty")), null);
      assert.equal(readServerRepoMapping(bare(dir, "bad", "github:\n  repo: a/b/c\n")), null);
      assert.equal(readServerRepoMapping(bare(dir, "wild", "github:\n  repo: acme/*\n")), null);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("isLiveBareRepo refuses symlinks and missing paths", () => {
    const dir = realpathSync(mkdtempSync(path.join(os.tmpdir(), "stamp-gate-live-")));
    try {
      const real = bare(dir, "real");
      symlinkSync(real, path.join(dir, "link.git"));
      assert.equal(isLiveBareRepo(real), true);
      assert.equal(isLiveBareRepo(path.join(dir, "link.git")), false);
      assert.equal(isLiveBareRepo(path.join(dir, "missing.git")), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("authorized_keys lines", () => {
  const KEY =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO0fHPCBttt9fiLYtDixe2+eGATWUa+BiRi7V5B7Bc7b tester@example";

  it("the resolver line forces the gate with the user id", () => {
    assert.equal(gatedAuthorizedKeysLine(7, KEY), `command="stamp-gate 7",restrict ${KEY}`);
  });
  it("refuses stored lines that carry their own options or odd shapes", () => {
    assert.equal(gatedAuthorizedKeysLine(7, `command="sh" ${KEY}`), null);
    assert.equal(gatedAuthorizedKeysLine(7, `${KEY}\nssh-ed25519 AAAA x`), null);
    assert.equal(gatedAuthorizedKeysLine(0, KEY), null);
  });
  it("entrypoint's helper gates every AuthorizedKeysFile line", () => {
    const lib = path.join(ROOT, "server", "lib", "gate-authorized-keys.sh");
    const input = `\n# comment\n  ${KEY}  \nfrom="10.0.0.1" ${KEY}\n`;
    const out = execFileSync("sh", ["-c", `. "${lib}"; _gate_authorized_keys`], { input, encoding: "utf8" });
    assert.equal(
      out,
      `command="stamp-gate legacy",restrict ${KEY}\n` +
        `command="stamp-gate legacy",restrict,from="10.0.0.1" ${KEY}\n`,
    );
  });
});

// ---------------------------------------------------------------------------
// stamp-gate-check end to end
// ---------------------------------------------------------------------------

const GATE_TS = path.join(ROOT, "src", "server", "gate-check.ts");

interface Harness {
  run: (bound: string, who: "admin" | "member" | "stranger", original?: string) => {
    status: number | null;
    stdout: string;
    stderr: string;
  };
  ids: Record<"admin" | "member", number>;
  dbPath: string;
  cleanup: () => void;
}

function harness(): Harness {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-gate-check-"));
  const dbPath = path.join(dir, "users.db");
  const keys: Record<string, { line: string; fp: string }> = {};
  for (const who of ["admin", "member", "stranger"]) {
    const kp = path.join(dir, who);
    execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", who, "-f", kp]);
    const line = readFileSync(`${kp}.pub`, "utf8").trim();
    const fp = execFileSync("ssh-keygen", ["-lf", `${kp}.pub`], { encoding: "utf8" }).split(" ")[1]!;
    keys[who] = { line, fp };
    writeFileSync(path.join(dir, `${who}.auth`), `publickey ${line}\n`);
  }
  const db = openServerDb({ path: dbPath, skipChmod: true });
  const ids = {} as Record<"admin" | "member", number>;
  try {
    for (const [who, role] of [["admin", "admin"], ["member", "member"]] as Array<["admin" | "member", Role]>) {
      ids[who] = insertUser(db, {
        short_name: who,
        ssh_pubkey: keys[who]!.line,
        ssh_fp: keys[who]!.fp,
        role,
        source: "manual",
      });
    }
  } finally {
    db.close();
  }
  return {
    ids,
    dbPath,
    run: (bound, who, original) => {
      const env: NodeJS.ProcessEnv = {
        ...process.env,
        STAMP_SERVER_DB_PATH: dbPath,
        SSH_USER_AUTH: path.join(dir, `${who}.auth`),
      };
      if (original === undefined) delete env["SSH_ORIGINAL_COMMAND"];
      else env["SSH_ORIGINAL_COMMAND"] = original;
      const r = spawnSync(process.execPath, ["--import", "tsx", GATE_TS, bound], { env, encoding: "utf8" });
      return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
    },
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

describe("stamp-gate-check", () => {
  it("prints the canonical command for an allowed verb", () => {
    const h = harness();
    try {
      const r = h.run(String(h.ids.member), "member", `list-stamp-repos`);
      assert.equal(r.status, 0, r.stderr);
      assert.equal(r.stdout, "list-stamp-repos");
      const a = h.run("legacy", "admin", `delete-stamp-repo foo --purge`);
      assert.equal(a.status, 0, a.stderr);
      assert.equal(a.stdout, `delete-stamp-repo 'foo' '--purge'`);
    } finally {
      h.cleanup();
    }
  });

  it("refuses an unenrolled key, a missing identity, and a mismatched user id (exit 1)", () => {
    const h = harness();
    try {
      assert.equal(h.run("legacy", "stranger", "list-stamp-repos").status, 1);
      const mismatch = h.run(String(h.ids.admin), "member", "list-stamp-repos");
      assert.equal(mismatch.status, 1);
      assert.match(mismatch.stderr, /does not match/);
      assert.equal(h.run("abc", "admin", "list-stamp-repos").status, 1);
    } finally {
      h.cleanup();
    }
  });

  it("refuses dot-dir paths and unknown commands for an admin too (exit 2)", () => {
    const h = harness();
    try {
      for (const cmd of [
        `git-upload-pack '/srv/git/.trash/20200101T000000Z-x.git'`,
        `git-upload-pack '/srv/git/.prompts-cache'`,
        `sh -c id`,
      ]) {
        const r = h.run(String(h.ids.admin), "admin", cmd);
        assert.equal(r.status, 2, `${cmd}: ${r.stderr}`);
        assert.equal(r.stdout, "");
      }
      assert.equal(h.run(String(h.ids.admin), "admin").status, 2);
    } finally {
      h.cleanup();
    }
  });

  it("refuses a scoped member list-stamp-repos (exit 3) and a missing repo", () => {
    const h = harness();
    try {
      const db = openServerDb({ path: h.dbPath, skipChmod: true });
      try {
        addRepoGrant(db, h.ids.member, "acme", "a", h.ids.admin);
      } finally {
        db.close();
      }
      const r = h.run(String(h.ids.member), "member", "list-stamp-repos");
      assert.equal(r.status, 3, r.stderr);
      // /srv/git/<name>.git doesn't exist on the test host: a scoped member
      // gets the same refusal as for a repo they can't use.
      const g = h.run(String(h.ids.member), "member", `git-upload-pack '/srv/git/stamp-gate-test-nope.git'`);
      assert.equal(g.status, 3, g.stderr);
      assert.match(g.stderr, /not found or not permitted/);
    } finally {
      h.cleanup();
    }
  });
});
