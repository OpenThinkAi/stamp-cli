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

function main(): void {
  loadServerEnvFile();

  const stdin = readAllStdin();
  const lines = stdin.split("\n").filter((l) => l.trim().length > 0);
  if (lines.length === 0) return;

  for (const line of lines) {
    const parts = line.split(/\s+/);
    if (parts.length < 3) continue;
    const [_oldSha, newSha, refname] = parts as [string, string, string];
    if (newSha === ZERO_SHA) continue; // deletion — never mirror deletions

    if (refname.startsWith("refs/heads/")) {
      const branch = refname.slice("refs/heads/".length);
      const cfg = readMirrorConfig(newSha);
      if (!cfg?.github) continue;
      if (!matchesAnyPattern(branch, cfg.github.branches)) continue;
      mirrorRef(`branch ${branch}`, refname, newSha, cfg.github.repo);
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
      mirrorRef(`tag ${tag}`, refname, newSha, cfg.github.repo);
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
 * Push a single ref (branch or tag) to the configured GitHub mirror.
 * `label` is operator-friendly text for log lines ("branch main", "tag v1.0.0").
 */
function mirrorRef(
  label: string,
  refname: string,
  newSha: string,
  githubRepo: string,
): void {
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

try {
  main();
} catch (err) {
  warn(
    `mirror: internal error — ${err instanceof Error ? err.message : String(err)}`,
  );
  // Exit 0 regardless — post-receive failures shouldn't affect the push result.
}
process.exit(0);
