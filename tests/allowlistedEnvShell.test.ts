/**
 * AGT-2264: tests for server/lib/allowlisted-env.sh — the explicit env
 * allowlists the entrypoint uses to start the internet-facing HTTP listener
 * (and the git-user workers) from `env -i` instead of `su -p`.
 *
 * Covers:
 *   - only listed, set vars reach the child; PATH is fixed, HOME is the
 *     given dir; everything else (the secrets) is dropped
 *   - set-but-empty passes through as empty; unset stays unset
 *   - values with spaces / quotes / $ / newlines survive verbatim
 *   - a non-identifier name is refused, never eval'd
 *   - the listener allowlist holds no credential except the webhook HMAC
 *     secret, and never the prompts repo URL / deploy key path
 *   - every env var the listener + worker source reads is in one of the two
 *     allowlists (so a new knob can't silently stop working in the image)
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, it } from "node:test";

const ROOT = path.resolve(import.meta.dirname, "..");
const LIB = path.join(ROOT, "server", "lib", "allowlisted-env.sh");

function runWith(
  env: Record<string, string>,
  names: string,
): { status: number | null; stdout: string; stderr: string } {
  const snippet = `. "${LIB}" && _exec_allowlisted_env /var/empty "${names}" /usr/bin/env`;
  const r = spawnSync("sh", ["-c", snippet], {
    env: { PATH: process.env["PATH"] ?? "/usr/bin:/bin", ...env },
    encoding: "utf8",
  });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

function allowlist(name: "STAMP_HTTP_SERVER_ENV" | "STAMP_WORKERS_ENV"): string[] {
  const r = spawnSync("sh", ["-c", `. "${LIB}" && printf '%s' "$${name}"`], {
    encoding: "utf8",
  });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.split(/\s+/).filter(Boolean);
}

// Run /usr/bin/env under the allowlist and parse what the child saw.
function childEnv(env: Record<string, string>, names: string): Record<string, string> {
  const r = runWith(env, names);
  assert.equal(r.status, 0, r.stderr);
  // Values may contain newlines; parse by known names instead of splitting.
  const out: Record<string, string> = {};
  const keys = ["PATH", "HOME", ...names.split(/\s+/).filter(Boolean), ...Object.keys(env)];
  const lines = r.stdout.split("\n");
  let cur: string | null = null;
  for (const line of lines) {
    const eq = line.indexOf("=");
    const k = eq > 0 ? line.slice(0, eq) : null;
    if (k !== null && keys.includes(k) && !(k in out)) {
      cur = k;
      out[k] = line.slice(eq + 1);
    } else if (cur !== null) {
      out[cur] += `\n${line}`;
    }
  }
  if (cur !== null && out[cur]!.endsWith("\n")) out[cur] = out[cur]!.slice(0, -1);
  return out;
}

describe("_exec_allowlisted_env (AGT-2264)", () => {
  it("passes only listed, set vars plus fixed PATH and HOME", () => {
    const env = childEnv(
      {
        STAMP_HTTP_PORT: "8080",
        STAMP_PROMPTS_WEBHOOK_SECRET: "hmac-secret",
        GITHUB_BOT_TOKEN: "ghp_should_not_leak",
        ANTHROPIC_API_KEY: "sk-ant-should-not-leak",
        AUTHORIZED_KEYS: "ssh-ed25519 AAAA leak",
      },
      "STAMP_HTTP_PORT STAMP_PROMPTS_WEBHOOK_SECRET STAMP_PEER_REVIEWS_ENABLED",
    );
    assert.deepEqual(Object.keys(env).sort(), [
      "HOME",
      "PATH",
      "STAMP_HTTP_PORT",
      "STAMP_PROMPTS_WEBHOOK_SECRET",
    ]);
    assert.equal(env["PATH"], "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    assert.equal(env["HOME"], "/var/empty");
    assert.equal(env["STAMP_HTTP_PORT"], "8080");
    assert.equal(env["STAMP_PROMPTS_WEBHOOK_SECRET"], "hmac-secret");
  });

  it("passes set-but-empty through as empty", () => {
    const env = childEnv({ STAMP_TRASH_SWEEP_INTERVAL_SEC: "" }, "STAMP_TRASH_SWEEP_INTERVAL_SEC");
    assert.equal(env["STAMP_TRASH_SWEEP_INTERVAL_SEC"], "");
  });

  it("never lets a listed PATH/HOME override the fixed values", () => {
    const env = childEnv({ HOME: "/root" }, "PATH HOME");
    assert.equal(env["HOME"], "/var/empty");
    assert.equal(env["PATH"], "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
  });

  it("preserves awkward values verbatim", () => {
    const v = `a b 'q' "d" $HOME \`x\` ;|&`;
    const env = childEnv({ STAMP_PROMPTS_WEBHOOK_SECRET: v }, "STAMP_PROMPTS_WEBHOOK_SECRET");
    assert.equal(env["STAMP_PROMPTS_WEBHOOK_SECRET"], v);
  });

  it("refuses a name that is not a plain identifier", () => {
    for (const bad of ["A;id", "1ABC", "A-B", "$(id)"]) {
      const r = runWith({}, bad);
      assert.equal(r.status, 2, `${bad}: ${r.stderr}`);
      assert.match(r.stderr, /bad variable name/);
    }
  });

  it("forwards the command's own arguments intact", () => {
    const snippet = `. "${LIB}" && _exec_allowlisted_env /var/empty "" /bin/sh -c 'printf "%s|%s" "$0" "$1"' "a b" "c=d"`;
    const r = spawnSync("sh", ["-c", snippet], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout, "a b|c=d");
  });
});

describe("listener / worker allowlists (AGT-2264)", () => {
  const http = allowlist("STAMP_HTTP_SERVER_ENV");
  const workers = allowlist("STAMP_WORKERS_ENV");

  it("hands the listener no credential but the webhook HMAC secret", () => {
    for (const forbidden of [
      "GITHUB_BOT_TOKEN",
      "ANTHROPIC_API_KEY",
      "AUTHORIZED_KEYS",
      "OPERATOR_PUB_KEY",
      "REVIEW_SIGNING_KEY_PATH",
      "STAMP_PROMPTS_REPO_URL",
      "STAMP_PROMPTS_DEPLOY_KEY_PATH",
    ]) {
      assert.ok(!http.includes(forbidden), `listener allowlist must not include ${forbidden}`);
    }
    const secretish = http.filter((n) => /SECRET|TOKEN|KEY|PASS/.test(n));
    assert.deepEqual(secretish, ["STAMP_PROMPTS_WEBHOOK_SECRET"]);
  });

  it("hands the workers no bot token or API key", () => {
    for (const forbidden of ["GITHUB_BOT_TOKEN", "ANTHROPIC_API_KEY", "STAMP_PROMPTS_WEBHOOK_SECRET"]) {
      assert.ok(!workers.includes(forbidden), `workers allowlist must not include ${forbidden}`);
    }
  });

  it("covers every env var the listener and worker code reads", () => {
    const files = [
      "src/server/start-http-server.ts",
      "src/server/start-workers.ts",
      "src/server/http-server.ts",
      "src/server/peerReviews.ts",
      "src/server/prompts-cache.ts",
      "src/server/trashPurge.ts",
      "src/lib/serverDb.ts",
      "src/lib/invites.ts",
      "src/lib/repoAccess.ts",
    ];
    // Read only by SSH verbs (serverDb rate caps), never by these processes.
    const sshVerbOnly = new Set(["MAX_REVIEWS_PER_HOUR", "MAX_INVITES_PER_HOUR"]);
    const read = new Set<string>();
    for (const f of files) {
      const src = readFileSync(path.join(ROOT, f), "utf8");
      for (const m of src.matchAll(/process\.env\[\s*"([A-Z0-9_]+)"\s*\]/g)) read.add(m[1]!);
      for (const m of src.matchAll(/process\.env\.([A-Z0-9_]+)/g)) read.add(m[1]!);
      for (const m of src.matchAll(/(?:resolvePeerReviewLimit|positiveIntEnv)\(\s*"([A-Z0-9_]+)"/g)) {
        read.add(m[1]!);
      }
    }
    const covered = new Set([...http, ...workers]);
    const missing = [...read].filter((n) => !covered.has(n) && !sshVerbOnly.has(n));
    assert.deepEqual(missing, [], `env vars read but not allowlisted: ${missing.join(", ")}`);
  });
});
