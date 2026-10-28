/**
 * AGT-2276: `repo_id:` is declared by default when (and only when) the
 * stamp server reports it signs `repo_id` into approvals.
 *
 * Covers the capability probe (parser, the real ssh path against a fake
 * `ssh` on PATH that runs the shipped `server/stamp-server-pubkey`, an
 * old server that refuses the flag), the decision (probe true → write;
 * false / failed / no server → skip with a note; malformed derived id →
 * refused without probing; an existing declaration is never touched),
 * and bootstrap's probe-target resolution + in-place config patch.
 * No test reaches a real server: the probe is stubbed or ssh is faked.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { parse as parseYaml } from "yaml";

import {
  resolveBootstrapProbeTarget,
  writeBootstrapFiles,
  type BootstrapPlan,
} from "../src/commands/bootstrap.ts";
import { parseConfigFromYaml, type StampConfig } from "../src/lib/config.ts";
import { candidateRepoId, decideRepoIdDefault } from "../src/lib/repoIdDefault.ts";
import {
  __setCapabilityProbeForTests,
  parseCapabilitiesOutput,
  probeServerCapabilities,
  type CapabilityProbeResult,
  type CapabilityProbeTarget,
} from "../src/lib/serverCapabilities.ts";

const PUBKEY_SCRIPT = path.resolve(import.meta.dirname, "..", "server", "stamp-server-pubkey");
const TARGET: CapabilityProbeTarget = { user: "git", host: "stamp.invalid", port: 2222 };

function tmp(): { dir: string; cleanup: () => void } {
  const dir = mkdtempSync(path.join(os.tmpdir(), "stamp-repoid-default-"));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function gitRepo(dir: string, origin: string | null): string {
  const repo = path.join(dir, "repo");
  mkdirSync(repo, { recursive: true });
  execFileSync("git", ["init", "-q", "-b", "main"], { cwd: repo });
  if (origin !== null) execFileSync("git", ["remote", "add", "origin", origin], { cwd: repo });
  return repo;
}

/** Stub the probe; records every call. */
function stubProbe(result: CapabilityProbeResult): { calls: CapabilityProbeTarget[]; restore: () => void } {
  const calls: CapabilityProbeTarget[] = [];
  const restore = __setCapabilityProbeForTests((t) => {
    calls.push(t);
    return result;
  });
  return { calls, restore };
}

const YES: CapabilityProbeResult = { ok: true, capabilities: { approvalRepoId: true } };
const NO: CapabilityProbeResult = { ok: true, capabilities: { approvalRepoId: false } };
const FAILED: CapabilityProbeResult = { ok: false, reason: "stamp-server-pubkey --capabilities exited 2" };

/** Put a fake `ssh` first on PATH for the duration of `fn`. */
function withFakeSsh<T>(dir: string, body: string, fn: () => T): T {
  const bin = path.join(dir, "bin");
  mkdirSync(bin, { recursive: true });
  writeFileSync(path.join(bin, "ssh"), `#!/bin/sh\n${body}\n`);
  chmodSync(path.join(bin, "ssh"), 0o755);
  const prev = process.env["PATH"];
  process.env["PATH"] = `${bin}${path.delimiter}${prev ?? ""}`;
  try {
    return fn();
  } finally {
    process.env["PATH"] = prev;
  }
}

describe("server capability probe", () => {
  it("parses the capability line; only a literal true counts", () => {
    assert.deepEqual(parseCapabilitiesOutput('{"approval_repo_id":true}\n'), { approvalRepoId: true });
    assert.deepEqual(parseCapabilitiesOutput('{"approval_repo_id":"true"}'), { approvalRepoId: false });
    assert.deepEqual(parseCapabilitiesOutput('{"something_else":true}'), { approvalRepoId: false });
    assert.equal(parseCapabilitiesOutput(""), null);
    assert.equal(parseCapabilitiesOutput("[true]"), null);
    assert.equal(parseCapabilitiesOutput("ssh-ed25519 AAAA..."), null);
  });

  it("the shipped verb answers approval_repo_id: true over the real ssh path", () => {
    const t = tmp();
    try {
      // Fake ssh: drop `-p N -- user@host`, run the verb script with the rest.
      const body = `shift 4\nverb="$1"; shift\n[ "$verb" = stamp-server-pubkey ] || exit 127\nexec /bin/sh '${PUBKEY_SCRIPT}' "$@"`;
      const r = withFakeSsh(t.dir, body, () => probeServerCapabilities(TARGET));
      assert.deepEqual(r, { ok: true, capabilities: { approvalRepoId: true } });
    } finally {
      t.cleanup();
    }
  });

  it("an old server that refuses the flag reads as no capability, never throws", () => {
    const t = tmp();
    try {
      const body = `echo "stamp-server-pubkey: spec must not start with '-': --capabilities" >&2\nexit 2`;
      const r = withFakeSsh(t.dir, body, () => probeServerCapabilities(TARGET));
      assert.equal(r.ok, false);
      assert.match((r as { reason: string }).reason, /exited 2/);
    } finally {
      t.cleanup();
    }
  });

  it("a server that prints something else reads as no capability", () => {
    const t = tmp();
    try {
      const r = withFakeSsh(t.dir, "echo ssh-ed25519 AAAAC3Nz legacy", () => probeServerCapabilities(TARGET));
      assert.equal(r.ok, false);
    } finally {
      t.cleanup();
    }
  });
});

describe("decideRepoIdDefault", () => {
  const ORIGIN = "ssh://git@stamp.invalid:2222/srv/git/dask.git";

  it("probe true → write the pair stamp review sends (last two origin segments)", () => {
    const t = tmp();
    const p = stubProbe(YES);
    try {
      const repo = gitRepo(t.dir, ORIGIN);
      const d = decideRepoIdDefault({ repoRoot: repo, existingRaw: undefined, target: TARGET });
      assert.deepEqual(d, { kind: "write", repoId: "git/dask" });
      assert.deepEqual(p.calls, [TARGET]);
    } finally {
      p.restore();
      t.cleanup();
    }
  });

  for (const [label, result, want] of [
    ["probe false", NO, /does not report signing repo_id/],
    ["probe failed (old server)", FAILED, /did not answer the capability probe/],
  ] as const) {
    it(`${label} → not written, note names the line to add`, () => {
      const t = tmp();
      const p = stubProbe(result);
      try {
        const repo = gitRepo(t.dir, ORIGIN);
        const d = decideRepoIdDefault({ repoRoot: repo, existingRaw: undefined, target: TARGET });
        assert.equal(d.kind, "skip");
        const note = (d as { note: string }).note;
        assert.match(note, want);
        assert.match(note, /`repo_id: git\/dask`/);
      } finally {
        p.restore();
        t.cleanup();
      }
    });
  }

  it("no server to ask → not written, no probe", () => {
    const t = tmp();
    const p = stubProbe(YES);
    try {
      const repo = gitRepo(t.dir, ORIGIN);
      const d = decideRepoIdDefault({ repoRoot: repo, existingRaw: undefined, target: null });
      assert.equal(d.kind, "skip");
      assert.equal(p.calls.length, 0);
    } finally {
      p.restore();
      t.cleanup();
    }
  });

  it("malformed derived org/repo is refused before probing", () => {
    const t = tmp();
    const p = stubProbe(YES);
    try {
      const repo = gitRepo(t.dir, "git@github.com:-acme/widget.git");
      const d = decideRepoIdDefault({ repoRoot: repo, existingRaw: undefined, target: TARGET });
      assert.equal(d.kind, "skip");
      assert.match((d as { note: string }).note, /"-acme\/widget", is not a well-formed repo id/);
      assert.equal(p.calls.length, 0, "never probe for an id we would refuse");
    } finally {
      p.restore();
      t.cleanup();
    }
  });

  it("no origin → refused (nothing to derive)", () => {
    const t = tmp();
    const p = stubProbe(YES);
    try {
      const repo = gitRepo(t.dir, null);
      const d = decideRepoIdDefault({ repoRoot: repo, existingRaw: undefined, target: TARGET });
      assert.equal(d.kind, "skip");
      assert.equal(p.calls.length, 0);
    } finally {
      p.restore();
      t.cleanup();
    }
  });

  it("an existing declaration is kept and the server is not asked", () => {
    const t = tmp();
    const p = stubProbe(YES);
    try {
      const repo = gitRepo(t.dir, ORIGIN);
      const d = decideRepoIdDefault({ repoRoot: repo, existingRaw: "Acme/widget", target: TARGET });
      assert.deepEqual(d, { kind: "declared", repoId: "Acme/widget" });
      assert.equal(p.calls.length, 0);
    } finally {
      p.restore();
      t.cleanup();
    }
  });

  it("candidateRepoId refuses shapes the server's slug check would", () => {
    assert.equal(candidateRepoId({ org: "acme", repo: "widget" }).ok, true);
    assert.equal(candidateRepoId({ org: "ac me", repo: "widget" }).ok, false);
    assert.equal(candidateRepoId({ org: "acme", repo: "-widget" }).ok, false);
    assert.equal(candidateRepoId(null).ok, false);
  });
});

describe("stamp bootstrap: repo_id probe target + config patch", () => {
  const rule = (extra: Record<string, unknown> = {}) =>
    ({ required: ["example"], ...extra }) as StampConfig["branches"][string];

  it("prefers the branch's review_server, then provision's server, then a stamp-server origin", () => {
    const t = tmp();
    try {
      const repo = gitRepo(t.dir, "ssh://git@origin.invalid:2200/srv/git/dask.git");
      assert.deepEqual(
        resolveBootstrapProbeTarget(rule({ review_server: "ssh://git@review.invalid:2222" }), { server: TARGET }, repo),
        { user: "git", host: "review.invalid", port: 2222 },
      );
      assert.deepEqual(resolveBootstrapProbeTarget(rule(), { server: TARGET }, repo), TARGET);
      assert.deepEqual(resolveBootstrapProbeTarget(rule(), {}, repo), {
        user: "git",
        host: "origin.invalid",
        port: 2200,
      });
    } finally {
      t.cleanup();
    }
  });

  it("a forge origin with no review_server or server gives no target", () => {
    const t = tmp();
    try {
      const repo = gitRepo(t.dir, "git@github.com:acme/widget.git");
      assert.equal(resolveBootstrapProbeTarget(rule(), {}, repo), null);
    } finally {
      t.cleanup();
    }
  });

  function plan(): BootstrapPlan {
    return {
      targetBranch: "main",
      newReviewers: ["security"],
      reviewerFiles: new Map([["security", { path: ".stamp/reviewers/security.md", content: "x\n" }]]),
      newConfig: {
        branches: { main: { required: ["security"] } },
        reviewers: { security: { prompt: ".stamp/reviewers/security.md" }, example: { prompt: ".stamp/reviewers/example.md" } },
      },
    };
  }

  const SEED = [
    "# placeholder seed",
    "branches:",
    "  main:",
    "    required: [example]",
    "reviewers:",
    "  example:",
    "    prompt: .stamp/reviewers/example.md",
    "# trailing comment survives",
    "",
  ].join("\n");

  it("writes repo_id in place, keeping comments", () => {
    const t = tmp();
    try {
      const repo = gitRepo(t.dir, null);
      mkdirSync(path.join(repo, ".stamp"), { recursive: true });
      writeFileSync(path.join(repo, ".stamp", "config.yml"), SEED);
      writeBootstrapFiles(repo, plan(), "git/dask");
      const text = readFileSync(path.join(repo, ".stamp", "config.yml"), "utf8");
      assert.match(text, /# placeholder seed/);
      assert.match(text, /# trailing comment survives/);
      assert.equal((parseYaml(text) as Record<string, unknown>)["repo_id"], "git/dask");
      assert.equal(parseConfigFromYaml(text).repo_id, "git/dask");
    } finally {
      t.cleanup();
    }
  });

  it("leaves repo_id out when the probe said no", () => {
    const t = tmp();
    try {
      const repo = gitRepo(t.dir, null);
      mkdirSync(path.join(repo, ".stamp"), { recursive: true });
      writeFileSync(path.join(repo, ".stamp", "config.yml"), SEED);
      writeBootstrapFiles(repo, plan(), undefined);
      const text = readFileSync(path.join(repo, ".stamp", "config.yml"), "utf8");
      assert.equal("repo_id" in (parseYaml(text) as Record<string, unknown>), false);
    } finally {
      t.cleanup();
    }
  });
});
