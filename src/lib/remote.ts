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
