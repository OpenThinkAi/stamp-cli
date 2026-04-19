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

interface MirrorConfig {
  github?: {
    repo: string; // "owner/repo"
    branches: string[];
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
      process.env[key] = m[2];
    }
  }
}

function main(): void {
  loadServerEnvFile();

  const stdin = readAllStdin();
  const lines = stdin.split("\n").filter((l) => l.trim().length > 0);
  if (lines.length === 0) return;

  for (const line of lines) {
    const parts = line.split(/\s+/);
    if (parts.length < 3) continue;
    const [_oldSha, newSha, refname] = parts as [string, string, string];
    if (newSha === ZERO_SHA) continue; // deletion
    if (!refname.startsWith("refs/heads/")) continue;
    const branch = refname.slice("refs/heads/".length);

    const cfg = readMirrorConfig(newSha);
    if (!cfg?.github) continue;
    if (!cfg.github.branches.includes(branch)) continue;

    mirrorBranch(branch, refname, newSha, cfg.github.repo);
  }
}

const ZERO_SHA = "0000000000000000000000000000000000000000";

function mirrorBranch(
  branch: string,
  refname: string,
  newSha: string,
  githubRepo: string,
): void {
  const token = process.env["GITHUB_BOT_TOKEN"];
  if (!token) {
    warn(
      `mirror: GITHUB_BOT_TOKEN not set in environment; skipping mirror of ${branch} → ${githubRepo}`,
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
      `mirror: pushed ${branch} (${newSha.slice(0, 8)}) → github.com/${githubRepo}`,
    );
  } else {
    const errOut = (result.stderr ?? "").trim();
    warn(
      `mirror: push to github.com/${githubRepo} failed (exit ${result.status})`,
    );
    if (errOut) warn(`mirror: ${errOut.replace(/\n/g, "\nmirror: ")}`);
    warn(
      `mirror: main push already accepted; mirror out-of-sync. Retry manually with: ` +
        `git push https://...@github.com/${githubRepo}.git ${refname}`,
    );
  }
}

function readMirrorConfig(sha: string): MirrorConfig | null {
  // Try repo-root .stamp/mirror.yml at the pushed ref.
  try {
    const raw = run(["show", `${sha}:.stamp/mirror.yml`]);
    const parsed = parseYaml(raw) as unknown;
    if (!parsed || typeof parsed !== "object") return null;
    const obj = parsed as Record<string, unknown>;

    const out: MirrorConfig = {};
    if (obj.github && typeof obj.github === "object") {
      const gh = obj.github as Record<string, unknown>;
      if (typeof gh.repo === "string" && Array.isArray(gh.branches)) {
        out.github = {
          repo: gh.repo,
          branches: gh.branches.map(String),
        };
      }
    }
    return out;
  } catch {
    return null;
  }
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
