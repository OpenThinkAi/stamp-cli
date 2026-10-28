/**
 * AGT-2277: every env var the `stamp-review` SSH verb reads must reach it.
 *
 * sshd strips the container env from SSH sessions, so a verb only sees what
 * server/entrypoint.sh persists to /etc/stamp/env with `write_env_var` (and
 * loadServerEnvFile() merges back). Before this test, STAMP_REVIEWER_MODEL,
 * STAMP_REVIEWER_THINKING, MAX_DIFF_BYTES, REVIEW_TIMEOUT_MS and
 * STAMP_PROMPTS_CACHE_ROOT were documented server settings that silently did
 * nothing on the image.
 *
 * Walks the relative-import closure of stamp-review.ts and of the helper it
 * runs through sudo (sign-approval.ts, which reloads the same file), collects
 * every env-var-shaped string literal plus `process.env.NAME` reads, and
 * requires each to be either written by the entrypoint or listed below as
 * intentionally not passed, with the reason. Modelled on the stamp-workers
 * allowlist coverage test in allowlistedEnvShell.test.ts.
 *
 * Also covers write_env_var's refusal of multi-line values.
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

const ROOT = path.resolve(import.meta.dirname, "..");
const ENTRYPOINT = path.join(ROOT, "server", "entrypoint.sh");

/** Read by code in the closure but deliberately NOT persisted for SSH verbs. */
const NOT_PASSED: Record<string, string> = {
  SSH_USER_AUTH: "set by sshd for each session (ExposeAuthInfo)",
  STAMP_STATE_DIR: "pinned by the image (entrypoint); the code default is the same path",
  STAMP_SERVER_DB_PATH:
    "test / relief-valve override; the SSH key resolver and every verb use the default, so persisting it for stamp-review alone would split the DB",
  STAMP_SIGN_APPROVAL_ARGV: "test-only hook for the signing-helper argv",
  STAMP_REPO_ROOT: "removed in 2.1; only its presence is warned about",
  STAMP_PROMPTS_DEPLOY_KEY_PATH: "prompts refresh only (bootstrap / stamp-workers); the verb never fetches",
  GIT_SSH_KNOWN_HOSTS: "prompts refresh only (bootstrap / stamp-workers)",
  GIT_SSH_COMMAND: "built by the prompts refresh for its own git child",
  STAMP_PEER_EVENT_RETENTION_DAYS: "stamp-workers retention sweep only",
  STAMP_SERVER_VERDICT_RETENTION_DAYS: "stamp-workers retention sweep only",
  CLAUDE_CODE_EXTRA_BODY: "client-side Agent SDK child env; the server makes one Messages call",
  STAMP_REVIEWER_BACKEND: "client-side backend choice; the server always calls Anthropic",
  STAMP_LOCAL_ENDPOINT: "client-side backend choice",
  STAMP_LOCAL_MODEL: "client-side backend choice",
  STAMP_LOCAL_TOOLS: "client-side backend choice",
  STAMP_OPENAI_COMPATIBLE_ENDPOINT: "client-side backend choice",
  STAMP_OPENAI_COMPATIBLE_MODEL: "client-side backend choice",
  STAMP_OPENAI_COMPATIBLE_TOOLS: "client-side backend choice",
  STAMP_PEER_WATCH_LOG: "client-side peer watcher log path",
};

function importClosure(entries: string[]): string[] {
  const seen = new Set<string>();
  const queue = entries.map((e) => path.join(ROOT, e));
  while (queue.length > 0) {
    const f = queue.pop()!;
    if (seen.has(f)) continue;
    seen.add(f);
    const src = readFileSync(f, "utf8");
    for (const m of src.matchAll(/(?:from|import)\s*\(?\s*"(\.{1,2}\/[^"]+)\.js"/g)) {
      const p = path.resolve(path.dirname(f), `${m[1]}.ts`);
      if (existsSync(p)) queue.push(p);
    }
  }
  return [...seen];
}

function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
}

/** Env var names the closure can read. Deliberately over-inclusive: any
 *  NAME_LIKE_THIS string literal counts, which also catches reads through
 *  a constant (`process.env[REVIEWER_THINKING_ENV]`) or a helper taking the
 *  name (`positiveIntEnv("MAX_REVIEWS_PER_HOUR", …)`). */
function namesRead(files: string[]): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  const add = (n: string, f: string) => {
    if (!out.has(n)) out.set(n, new Set());
    out.get(n)!.add(path.relative(ROOT, f));
  };
  for (const f of files) {
    const src = stripComments(readFileSync(f, "utf8"));
    for (const m of src.matchAll(/["'`]([A-Z][A-Z0-9]*_[A-Z0-9_]+)["'`]/g)) add(m[1]!, f);
    for (const m of src.matchAll(/process\.env\.([A-Z][A-Z0-9_]*)/g)) add(m[1]!, f);
  }
  return out;
}

function writtenByEntrypoint(): Set<string> {
  const src = readFileSync(ENTRYPOINT, "utf8");
  return new Set([...src.matchAll(/^write_env_var ([A-Z][A-Z0-9_]*)\b/gm)].map((m) => m[1]!));
}

describe("stamp-review env coverage (AGT-2277)", () => {
  const files = importClosure(["src/server/stamp-review.ts", "src/server/sign-approval.ts"]);
  const read = namesRead(files);
  const written = writtenByEntrypoint();

  it("walks the real closure", () => {
    const rel = files.map((f) => path.relative(ROOT, f));
    for (const f of ["src/server/reviewPipeline.ts", "src/server/promptsCachePaths.ts", "src/lib/reviewerThinking.ts"]) {
      assert.ok(rel.includes(f), `closure is missing ${f}`);
    }
  });

  it("every variable stamp-review reads is written to /etc/stamp/env or listed as not passed", () => {
    const missing = [...read.keys()]
      .filter((n) => !written.has(n) && !(n in NOT_PASSED))
      .map((n) => `${n} (${[...read.get(n)!].join(", ")})`);
    assert.deepEqual(missing, [], `env vars stamp-review reads that never reach it: ${missing.join("; ")}`);
  });

  it("passes the reviewer tuning knobs and the cache root", () => {
    for (const n of [
      "STAMP_REVIEWER_MODEL",
      "STAMP_REVIEWER_THINKING",
      "MAX_DIFF_BYTES",
      "REVIEW_TIMEOUT_MS",
      "STAMP_PROMPTS_CACHE_ROOT",
      "STAMP_ENV",
      "STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY",
    ]) {
      assert.ok(written.has(n), `entrypoint does not write_env_var ${n}`);
    }
  });

  it("has no stale or contradictory not-passed entries", () => {
    for (const n of Object.keys(NOT_PASSED)) {
      assert.ok(read.has(n), `${n} is listed as not passed but nothing in the closure reads it`);
      assert.ok(!written.has(n), `${n} is both written and listed as not passed`);
    }
  });
});

describe("write_env_var (AGT-2277)", () => {
  // Run the entrypoint's own function definition against a temp file.
  const src = readFileSync(ENTRYPOINT, "utf8");
  const start = src.indexOf("write_env_var() {");
  const endMarker = "_wev_cr=$(printf '\\r')";
  const end = src.indexOf(endMarker);
  assert.ok(start > 0 && end > start, "could not find write_env_var in entrypoint.sh");
  const fn = src.slice(start, end + endMarker.length);

  function run(env: Record<string, string>, names: string[]): { out: string; stderr: string } {
    const dir = mkdtempSync(path.join(tmpdir(), "stamp-wev-"));
    try {
      const file = path.join(dir, "env");
      const body = fn.replaceAll("/etc/stamp/env", file);
      const script = `set -e\n: > "${file}"\n${body}\n${names.map((n) => `write_env_var ${n}`).join("\n")}\n`;
      const r = spawnSync("sh", ["-c", script], { env: { PATH: process.env["PATH"] ?? "/usr/bin:/bin", ...env }, encoding: "utf8" });
      assert.equal(r.status, 0, r.stderr);
      return { out: readFileSync(file, "utf8"), stderr: r.stderr };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  it("writes set values one per line and skips unset/empty ones", () => {
    const { out } = run(
      { STAMP_REVIEWER_MODEL: "claude-opus-5", MAX_DIFF_BYTES: "", REVIEW_TIMEOUT_MS: "60000" },
      ["STAMP_REVIEWER_MODEL", "MAX_DIFF_BYTES", "REVIEW_TIMEOUT_MS", "STAMP_REVIEWER_THINKING"],
    );
    assert.equal(out, "STAMP_REVIEWER_MODEL=claude-opus-5\nREVIEW_TIMEOUT_MS=60000\n");
  });

  it("keeps awkward single-line values verbatim", () => {
    const v = `a b 'q' "d" $HOME \`x\` ;|&=`;
    const { out } = run({ STAMP_REVIEWER_MODEL: v }, ["STAMP_REVIEWER_MODEL"]);
    assert.equal(out, `STAMP_REVIEWER_MODEL=${v}\n`);
  });

  it("refuses a value with an embedded newline or CR instead of writing a second line", () => {
    const { out, stderr } = run(
      {
        STAMP_REVIEWER_MODEL: "claude-opus-5\nSTAMP_PROMPTS_DIR=/tmp/evil",
        REVIEW_TIMEOUT_MS: "1000\rX=1",
        MAX_DIFF_BYTES: "64",
      },
      ["STAMP_REVIEWER_MODEL", "REVIEW_TIMEOUT_MS", "MAX_DIFF_BYTES"],
    );
    assert.equal(out, "MAX_DIFF_BYTES=64\n");
    assert.match(stderr, /warning: STAMP_REVIEWER_MODEL contains a newline/);
    assert.match(stderr, /warning: REVIEW_TIMEOUT_MS contains a newline/);
  });
});
