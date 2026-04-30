/**
 * stamp mirror post-receive hook.
 *
 * Runs after pre-receive accepts a push (so the ref has already been updated
 * on the server). For each ref that matches the mirror config, pushes to a
 * configured GitHub repo using a bot's personal access token.
 *
 * Intent: stamp remote remains source of truth; GitHub is a read-only public
 * mirror that deploy pipelines (Actions/Vercel/Netlify/etc.) can hook into
 * natively. A bot account is the only authorized pusher to the mirror's
 * main branch (enforce via GitHub branch protection).
 *
 * Degrades gracefully:
 *   - No .stamp/mirror.yml → no-op
 *   - Ref not in mirror config → no-op
 *   - GITHUB_BOT_TOKEN missing → warn to stderr, skip (don't fail the push)
 *   - Mirror push fails → warn to stderr, log for operator (don't fail;
 *     the main push already succeeded)
 */

import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import {
  decideMirrorStatus,
  postCommitStatus,
  type MirrorStatusDecision,
} from "../lib/mirrorStatus.js";
import {
  matchesAnyPattern,
  matchesAnyTagPattern,
  resolveTagPatterns,
} from "../lib/refPatterns.js";

interface MirrorConfig {
  github?: {
    repo: string; // "owner/repo"
    /**
     * Branches to mirror. Each entry is a glob pattern (literal names like
     * `main` are valid no-metachar globs and still match exactly). Same
     * `*` / `?` grammar as the `tags:` field; see refPatterns.ts.
     */
    branches: string[];
    /**
     * Glob patterns of tags to mirror, normalized by resolveTagPatterns.
     * Empty array = no tag mirroring (also the default when the operator
     * doesn't include a `tags:` key at all). Tag pushes still need to land
     * on the stamp server first; this just controls the GitHub mirror leg.
     */
    tags: string[];
  };
}

/**
 * sshd strips most env vars from sessions. The server entrypoint writes
 * secrets like GITHUB_BOT_TOKEN to /etc/stamp/env (0600, owned by git);
 * this loader merges them into process.env before the hook runs.
 */
function loadServerEnvFile(path = "/etc/stamp/env"): void {
  if (!existsSync(path)) return;
  let content: string;
  try {
    content = readFileSync(path, "utf8");
  } catch {
    return;
  }
  for (const line of content.split("\n")) {
    const m = line.match(/^\s*([A-Z_][A-Z0-9_]*)=(.*)$/);
    if (!m) continue;
    const key = m[1]!;
    if (process.env[key] === undefined) {
      process.env[key] = (m[2] ?? "").trim();
    }
  }
}

// Strips `x-access-token:<token>@` credentials out of any string before it's
// forwarded to the pushing client. Git's push errors (e.g. "fatal: unable to
// access 'https://...'") can echo the URL back, and the URL embeds the bot
// token. Call this on every stderr/message that leaves the server.
function scrubTokenUrls(s: string): string {
  return s.replace(/x-access-token:[^@\s]*@/g, "x-access-token:***@");
}

const GITHUB_REPO_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*\/[A-Za-z0-9][A-Za-z0-9._-]*$/;

// Single deterministic context so operators can mark `stamp/verified` as a
// required check in their GitHub branch ruleset. Don't add a suffix per
// reviewer or per branch — that would multiply required-check rows on
// every PR for no operator benefit.
const STATUS_CONTEXT = "stamp/verified";

// Cap how many per-commit status POSTs a single push can issue. A normal
// pardini-style flow is single-digit commits; the cap exists so a one-time
// big mirror (e.g. first push of a long-lived stamped branch) can't exhaust
// the bot's status-creates quota in a single hook invocation.
const STATUS_POST_LIMIT = 100;

async function main(): Promise<void> {
  loadServerEnvFile();

  const stdin = readAllStdin();
  const lines = stdin.split("\n").filter((l) => l.trim().length > 0);
  if (lines.length === 0) return;

  for (const line of lines) {
    const parts = line.split(/\s+/);
    if (parts.length < 3) continue;
    const [oldSha, newSha, refname] = parts as [string, string, string];
    if (newSha === ZERO_SHA) continue; // deletion — never mirror deletions

    if (refname.startsWith("refs/heads/")) {
      const branch = refname.slice("refs/heads/".length);
      const cfg = readMirrorConfig(newSha);
      if (!cfg?.github) continue;
      if (!matchesAnyPattern(branch, cfg.github.branches)) continue;
      await mirrorRef(`branch ${branch}`, refname, oldSha, newSha, cfg.github.repo);
      continue;
    }

    if (refname.startsWith("refs/tags/")) {
      const tag = refname.slice("refs/tags/".length);
      // Tag mirror config has to be read from the tip of a branch (since
      // .stamp/mirror.yml lives on a branch tree, not on the tag). The tag
      // commit itself usually IS reachable via main, so we read mirror.yml
      // from `main` if it exists. If main can't be read, skip — without a
      // mirror config there's nothing to do.
      const cfg = readMirrorConfigFromMainBranch();
      if (!cfg?.github) continue;
      if (cfg.github.tags.length === 0) continue;
      if (!matchesAnyTagPattern(tag, cfg.github.tags)) continue;
      await mirrorRef(`tag ${tag}`, refname, oldSha, newSha, cfg.github.repo);
      continue;
    }

    // Ignore other refs (refs/notes/, refs/replace/, etc.).
  }
}

/**
 * Read mirror.yml from the `main` branch (mirror config doesn't ride along
 * on tags themselves — tags point at commits, not at trees with their own
 * mirror.yml semantics, and we want one source of truth per repo). Returns
 * null if main doesn't exist or doesn't contain mirror.yml.
 */
function readMirrorConfigFromMainBranch(): MirrorConfig | null {
  let mainSha: string;
  try {
    mainSha = run(["rev-parse", "refs/heads/main"]).trim();
  } catch {
    return null;
  }
  if (!mainSha) return null;
  return readMirrorConfig(mainSha);
}

const ZERO_SHA = "0000000000000000000000000000000000000000";

/**
 * Push a single ref (branch or tag) to the configured GitHub mirror, then
 * publish a `stamp/verified` commit status to GitHub for each commit in
 * the pushed range. `label` is operator-friendly text for log lines
 * ("branch main", "tag v1.0.0").
 */
async function mirrorRef(
  label: string,
  refname: string,
  oldSha: string,
  newSha: string,
  githubRepo: string,
): Promise<void> {
  const token = process.env["GITHUB_BOT_TOKEN"];
  if (!token) {
    warn(
      `mirror: GITHUB_BOT_TOKEN not set in environment; skipping mirror of ${label} → ${githubRepo}`,
    );
    return;
  }

  const remoteUrl = `https://x-access-token:${token}@github.com/${githubRepo}.git`;

  // git push — use --force-with-lease where possible. A first push to a
  // fresh github repo needs a plain force; subsequent pushes should be
  // fast-forward since stamp is source of truth. Start with FF-only and
  // fall back to documented force-push on the operator's request.
  const result = spawnSync(
    "git",
    ["push", remoteUrl, `${newSha}:${refname}`],
    {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  if (result.status === 0) {
    info(
      `mirror: pushed ${label} (${newSha.slice(0, 8)}) → github.com/${githubRepo}`,
    );
    await postStatuses(label, refname, oldSha, newSha, githubRepo, token);
  } else {
    const errOut = scrubTokenUrls((result.stderr ?? "").trim());
    warn(
      `mirror: push of ${label} to github.com/${githubRepo} failed (exit ${result.status})`,
    );
    if (errOut) warn(`mirror: ${errOut.replace(/\n/g, "\nmirror: ")}`);
    warn(
      `mirror: stamp-server push already accepted; mirror out-of-sync. Retry manually with: ` +
        `git push https://...@github.com/${githubRepo}.git ${refname}`,
    );
  }
}

/**
 * For each commit in the just-pushed range, post a `stamp/verified` commit
 * status to GitHub. Trusted keys are read from the tip of the pushed ref —
 * pre-receive already accepted the push, so the tip's trusted-keys set is
 * the authoritative one for this push (and the `signer_key_id` recorded in
 * each attestation is invariant once signed, so reading at the tip rather
 * than per-commit doesn't change correctness).
 *
 * Failures of any individual status POST warn and continue: the mirror
 * push has already succeeded, and a missing status is recoverable by the
 * operator (re-trigger the hook or post manually).
 */
async function postStatuses(
  label: string,
  refname: string,
  oldSha: string,
  newSha: string,
  githubRepo: string,
  token: string,
): Promise<void> {
  const trustedKeys = readTrustedKeyPemsAt(newSha);
  if (trustedKeys.length === 0) {
    warn(
      `mirror: no trusted keys readable at ${newSha.slice(0, 8)}; ${STATUS_CONTEXT} statuses for ${label} would all fail-mark — skipping status post.`,
    );
    return;
  }

  const shas = listShasInPushRange(oldSha, newSha, refname);
  if (shas.length === 0) return;

  let posted = 0;
  let truncated = false;
  for (const sha of shas) {
    if (posted >= STATUS_POST_LIMIT) {
      truncated = true;
      break;
    }
    let decision: MirrorStatusDecision;
    try {
      const message = readCommitMessage(sha);
      decision = decideMirrorStatus(message, trustedKeys);
    } catch (err) {
      warn(
        `mirror: status decision for ${sha.slice(0, 8)} failed (${err instanceof Error ? err.message : String(err)}); skipping.`,
      );
      continue;
    }
    try {
      await postCommitStatus(githubRepo, sha, decision, token, STATUS_CONTEXT);
      posted++;
      info(
        `mirror: ${STATUS_CONTEXT} ${decision.state} for ${sha.slice(0, 8)} on github.com/${githubRepo}`,
      );
    } catch (err) {
      warn(
        `mirror: status post for ${sha.slice(0, 8)} on github.com/${githubRepo} failed — ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }
  if (truncated) {
    warn(
      `mirror: status posts capped at ${STATUS_POST_LIMIT} for ${label}; ${shas.length - STATUS_POST_LIMIT} commit(s) without ${STATUS_CONTEXT} status. Re-run the hook or post manually for the older shas.`,
    );
  }
}

/**
 * Enumerate the commits a status should be posted for. Branches use
 * `--first-parent oldSha..newSha` so we report on the merges/commits that
 * landed on the protected ref itself, not every commit they brought in
 * via a feature-branch second parent. Branch creations (oldSha all zeros)
 * and tag pushes both fall back to the single tip commit — there's no
 * meaningful range to walk.
 */
function listShasInPushRange(
  oldSha: string,
  newSha: string,
  refname: string,
): string[] {
  if (oldSha === ZERO_SHA || refname.startsWith("refs/tags/")) {
    return [newSha];
  }
  let out: string;
  try {
    out = run(["rev-list", "--first-parent", `${oldSha}..${newSha}`]).trim();
  } catch {
    return [newSha];
  }
  if (!out) return [];
  return out.split("\n");
}

function readCommitMessage(sha: string): string {
  // %B is the raw body of the commit message, including all trailers,
  // without the headers `git cat-file -p` would prepend.
  return run(["log", "-1", "--format=%B", sha]);
}

/**
 * Read every `.pub` under `.stamp/trusted-keys/` at the given commit and
 * return the PEM contents. Mirrors the lookup pre-receive does, but
 * returns an opaque PEM list — the consumer (decideMirrorStatus) hashes
 * each PEM into a fingerprint itself.
 */
function readTrustedKeyPemsAt(sha: string): string[] {
  let lsOut: string;
  try {
    lsOut = run(["ls-tree", "-r", "--name-only", sha, ".stamp/trusted-keys/"]);
  } catch {
    return [];
  }
  const files = lsOut.split("\n").filter((f) => f.endsWith(".pub"));
  const pems: string[] = [];
  for (const path of files) {
    try {
      pems.push(run(["show", `${sha}:${path}`]));
    } catch {
      // skip unreadable
    }
  }
  return pems;
}

// Canonical schema shape used in warning messages. Matches the YAML
// example in DESIGN.md and server/README.md so the operator sees
// consistent text at every touchpoint. Branch and tag entries both accept
// glob patterns (`*`, `?`); literal names like `main` are no-metachar
// globs and still match exactly.
const SCHEMA_HINT =
  "expected schema: github: { repo: owner/repo, branches: [main, \"release/*\"], tags?: [\"v*\"] | true }";

function readMirrorConfig(sha: string): MirrorConfig | null {
  // Absence of the file is normal — repos without mirror configured just
  // don't have .stamp/mirror.yml. Silent no-op in that case.
  let raw: string;
  try {
    raw = run(["show", `${sha}:.stamp/mirror.yml`]);
  } catch {
    return null;
  }

  // File exists. From here on, misconfigurations warn explicitly rather
  // than silently disabling the mirror — that silent-no-op pattern was the
  // bug reported in issue #2.
  let parsed: unknown;
  try {
    parsed = parseYaml(raw);
  } catch (err) {
    warn(
      `mirror: .stamp/mirror.yml failed to parse as YAML (${err instanceof Error ? err.message : String(err)}) — skipping mirror.`,
    );
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    warn(
      `mirror: .stamp/mirror.yml is empty or not a map — skipping mirror. ${SCHEMA_HINT}.`,
    );
    return null;
  }
  const obj = parsed as Record<string, unknown>;
  if (obj.github === undefined) {
    const topKeys = Object.keys(obj).join(", ") || "(none)";
    warn(
      `mirror: .stamp/mirror.yml has no top-level 'github' key (found: ${topKeys}) — skipping mirror. ${SCHEMA_HINT}.`,
    );
    return null;
  }
  if (obj.github === null) {
    warn(
      `mirror: .stamp/mirror.yml's 'github' key is null (likely 'github:' with no value) — skipping mirror. ${SCHEMA_HINT}.`,
    );
    return null;
  }
  if (typeof obj.github !== "object" || Array.isArray(obj.github)) {
    warn(
      `mirror: .stamp/mirror.yml's 'github' value must be a map, not ${Array.isArray(obj.github) ? "an array" : typeof obj.github} — skipping mirror. ${SCHEMA_HINT}.`,
    );
    return null;
  }
  const gh = obj.github as Record<string, unknown>;
  if (typeof gh.repo !== "string") {
    warn(
      `mirror: .stamp/mirror.yml missing 'github.repo' (expected string of form owner/repo) — skipping mirror. ${SCHEMA_HINT}.`,
    );
    return null;
  }
  if (!GITHUB_REPO_RE.test(gh.repo)) {
    // Refuse to interpolate an unexpected-shape repo into a URL. Git's parser
    // keeps github.com as the host (first @ wins) so this isn't host-hijack
    // territory — it's defense in depth against a malformed mirror.yml
    // slipping through review and producing surprising push behavior.
    warn(
      `mirror: invalid github.repo '${gh.repo}' in .stamp/mirror.yml — skipping mirror. ${SCHEMA_HINT}.`,
    );
    return null;
  }
  if (!Array.isArray(gh.branches)) {
    warn(
      `mirror: .stamp/mirror.yml missing or non-array 'github.branches' (expected list of branch names or glob patterns) — skipping mirror. ${SCHEMA_HINT}.`,
    );
    return null;
  }
  const tags = resolveTagPatterns(gh.tags);
  if (tags === null) {
    warn(
      `mirror: .stamp/mirror.yml has invalid 'github.tags' (expected list of glob strings, or 'true' for all tags) — tags will not be mirrored. ${SCHEMA_HINT}.`,
    );
    // Fall through with tags=[] so branch mirroring still works; tag pushes
    // just won't be mirrored. Same posture as a missing tags field.
  }
  return {
    github: {
      repo: gh.repo,
      branches: gh.branches.map(String),
      tags: tags ?? [],
    },
  };
}

function run(args: string[]): string {
  return execFileSync("git", args, {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function readAllStdin(): string {
  const { readFileSync } = require("node:fs") as typeof import("node:fs");
  try {
    return readFileSync(0).toString("utf8");
  } catch {
    return "";
  }
}

// Mirror status output goes to stderr so it surfaces to the pushing client via
// git's "remote:" prefix without being mistaken for an error that blocks
// anything (nothing can block; post-receive is informational).
function info(msg: string): void {
  process.stderr.write(`${msg}\n`);
}
function warn(msg: string): void {
  process.stderr.write(`${msg}\n`);
}

// Run as async so per-commit GitHub status posts can await fetch responses
// before the hook exits and Node would otherwise tear down in-flight
// sockets. Exit 0 regardless — post-receive failures shouldn't affect the
// push result.
void main()
  .catch((err: unknown) => {
    warn(
      `mirror: internal error — ${err instanceof Error ? err.message : String(err)}`,
    );
  })
  .finally(() => process.exit(0));
