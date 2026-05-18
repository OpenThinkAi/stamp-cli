/**
 * Classify what `git remote get-url <remote>` looks like, so init/bootstrap
 * can warn or refuse based on whether the user actually has server-side
 * enforcement set up.
 *
 * The classification is deliberately heuristic — there's no reliable way to
 * tell a self-hosted stamp server apart from any other custom git remote,
 * and forge URLs vary in shape. The goal is to catch the common foot-gun:
 * an agent runs `stamp init` and `gh repo create --push`, ending up with
 * `origin = github.com:org/repo.git` and a stamp config that's enforced by
 * absolutely nothing.
 */

import { runGit } from "./git.js";

export type DeploymentShape =
  | "stamp-server" // Looks like a stamp server (SSH host with /srv/git/, or local bare repo path)
  | "forge-direct" // Direct push to a known public forge (GitHub, GitLab, Bitbucket, ...)
  | "unknown" // Some other remote (self-hosted gitea, gerrit, custom domain) — could be a stamp server or not
  | "unset"; // No remote configured

export interface DeploymentClassification {
  shape: DeploymentShape;
  /** Name of the remote we queried (carried so describeShape can name it accurately even for non-default --remote values). */
  remoteName: string;
  /** The raw remote URL we examined, or null if no remote was configured. */
  url: string | null;
  /** Short human-readable label for the detected forge ("github.com" etc.) when shape === "forge-direct". */
  forge?: string;
}

/**
 * Hosts that are unambiguously public code-hosting forges, not stamp servers.
 * Direct pushes to these mean no server-side stamp enforcement.
 */
const KNOWN_FORGE_HOSTS = [
  "github.com",
  "gitlab.com",
  "bitbucket.org",
  "codeberg.org",
  "git.sr.ht",
  "dev.azure.com",
];

/**
 * Inspect the configured remote and classify the deployment shape. Returns
 * `unset` if the remote doesn't exist (typical for `git init`-only repos
 * that haven't run `git remote add` yet).
 */
export function classifyRemote(
  remote: string,
  cwd: string,
): DeploymentClassification {
  let url: string;
  try {
    url = runGit(["remote", "get-url", remote], cwd).trim();
  } catch {
    return { shape: "unset", remoteName: remote, url: null };
  }

  if (!url) {
    return { shape: "unset", remoteName: remote, url: null };
  }

  // Forge detection — match against any known public forge host appearing
  // anywhere in the URL. Catches ssh://, git@, https://, and the SCP-style
  // `git@github.com:org/repo.git` form.
  for (const host of KNOWN_FORGE_HOSTS) {
    if (url.includes(host)) {
      return { shape: "forge-direct", remoteName: remote, url, forge: host };
    }
  }

  // Stamp-server heuristic: the canonical path layout (/srv/git/<name>.git)
  // shows up in both the SSH form (ssh://git@host/srv/git/x.git) and the
  // local bare-repo form used by the README's local-test quickstart
  // (/tmp/myproject.git etc.). This isn't proof — anyone can name a path
  // /srv/git — but it's a strong-enough signal to skip the warning.
  if (/(^|[/:])srv\/git\//.test(url)) {
    return { shape: "stamp-server", remoteName: remote, url };
  }

  // Anything else (custom domain, IP address, self-hosted gitea, etc.) we
  // don't try to classify. Could be a stamp server, could be anything.
  return { shape: "unknown", remoteName: remote, url };
}

/**
 * Derive `{ org, repo }` from `git remote get-url <remote>` so AGT-332's
 * SSH transport has something to pass to the server's `--org` / `--repo`
 * flags. Returns null when the URL doesn't have a recognizable
 * `<org>/<repo>` shape — the caller (`stamp review`) then surfaces a
 * usage error asking the operator to set the remote.
 *
 * Recognized shapes:
 *   - `git@host:org/repo.git` (scp-style)
 *   - `ssh://[user@]host[:port]/.../org/repo.git` (where org/repo are
 *     the last two path segments)
 *   - `https://host/.../org/repo.git`
 *
 * The pattern intentionally matches the *last two* path segments rather
 * than insisting on a top-of-path layout, so both the GitHub Shape 2
 * (`github.com/<owner>/<repo>.git`) and the stamp-server Shape 1
 * (`/srv/git/<owner>/<repo>.git`) hit the same code path. The server-
 * side `parseRequest` re-validates `org` / `repo` against its own
 * regexes, so anything that gets past this returns the same "invalid
 * shape" prose either way.
 */
export function deriveOrgRepoFromRemote(
  remote: string,
  cwd: string,
): { org: string; repo: string } | null {
  let url: string;
  try {
    url = runGit(["remote", "get-url", remote], cwd).trim();
  } catch {
    return null;
  }
  if (!url) return null;
  return parseOrgRepoFromUrl(url);
}

/**
 * Pure URL → `{ org, repo }` parser; exposed separately so tests can
 * hit every URL shape without standing up a git repo. Same logic as
 * `deriveOrgRepoFromRemote` but skips the `git remote get-url` shell
 * out. Returns null on any shape we can't confidently classify.
 */
export function parseOrgRepoFromUrl(
  url: string,
): { org: string; repo: string } | null {
  // SCP shape: `<user>@<host>:<path>`. Anchored on `<user>@<host>:` so
  // a URL whose path happens to contain `@` and `:` doesn't accidentally
  // match. Repo segment is non-greedy with optional `.git` suffix.
  const scp = url.match(/^[A-Za-z0-9._-]+@[^:]+:(.+)$/);
  let pathPart: string | null = null;
  if (scp && scp[1]) {
    pathPart = scp[1];
  } else {
    try {
      const parsed = new URL(url);
      pathPart = parsed.pathname;
    } catch {
      return null;
    }
  }
  if (!pathPart) return null;
  // Strip any leading slashes + optional `.git` suffix, then split.
  const cleaned = pathPart.replace(/^\/+/, "").replace(/\.git$/, "");
  const parts = cleaned.split("/").filter((p) => p.length > 0);
  if (parts.length < 2) return null;
  // Use the LAST two segments — handles `/srv/git/owner/repo.git` and
  // `/owner/repo` alike. A future per-tenant scheme that nests deeper
  // (`/srv/git/tenants/foo/owner/repo.git`) still picks out the right
  // pair because tenants don't appear in the server's `--org`/`--repo`
  // contract in Phase 1.
  const repo = parts[parts.length - 1]!;
  const org = parts[parts.length - 2]!;
  if (!org || !repo) return null;
  return { org, repo };
}

/**
 * Pretty one-line summary of the classification, suitable for inclusion in
 * warning/error messages. The caller decides what action to take on the
 * shape — this is just the prose.
 */
export function describeShape(c: DeploymentClassification): string {
  switch (c.shape) {
    case "stamp-server":
      return `${c.remoteName} appears to be a stamp server (${c.url})`;
    case "forge-direct":
      return `${c.remoteName} pushes directly to ${c.forge} (${c.url}) — no stamp server in this picture`;
    case "unknown":
      return `${c.remoteName} is an unrecognized remote (${c.url}) — may or may not be a stamp server`;
    case "unset":
      return `no remote named "${c.remoteName}" is configured`;
  }
}
