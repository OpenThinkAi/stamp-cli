/**
 * Compute the absolute filesystem path on the stamp server where a
 * per-repo deploy-key private file is expected to live.
 *
 * Mirrors the path convention defined by `server/stamp-ensure-repo-key`:
 *
 *   /srv/git/.ssh-client-keys/<owner>_<repo>_ed25519
 *
 * The single '/' in the GitHub `<owner>/<repo>` form becomes '_' in the
 * filename — flat directory, one-glance `ls -l` view of registered repos.
 *
 * Used by the post-receive mirror-push selector to decide whether to use
 * the per-repo SSH transport (file exists) or fall back to the legacy
 * shared key / HTTPS+token path. Exported as a pure function so unit
 * tests can verify the path-and-shape contract without touching the
 * filesystem or shelling out to the server-side helper.
 *
 * Shape contract enforced here (mirrors stamp-ensure-repo-key's checks):
 *   - exactly one '/' separator
 *   - owner and repo halves both non-empty
 *   - charset [A-Za-z0-9._-] only (no '..', no whitespace, no leading '-')
 *
 * Throws on invalid input rather than returning a string that might still
 * shape-look plausible — the caller would then check existsSync() on a
 * path that could never legitimately exist, masking a programming error.
 */
const VALID_SEGMENT = /^[A-Za-z0-9._-]+$/;

/**
 * Root directory of the per-repo deploy-key files on the stamp server.
 * Kept in sync with `SSH_CLIENT_KEY_DIR` in server/entrypoint.sh — both
 * sides change together if the location ever moves.
 */
export const SSH_CLIENT_KEY_DIR = "/srv/git/.ssh-client-keys";

export function computePerRepoKeyPath(githubRepo: string): string {
  if (typeof githubRepo !== "string" || githubRepo.length === 0) {
    throw new Error("computePerRepoKeyPath: githubRepo must be a non-empty string");
  }
  if (githubRepo.startsWith("-")) {
    throw new Error(
      `computePerRepoKeyPath: githubRepo must not start with '-': ${githubRepo}`,
    );
  }
  if (githubRepo.includes("..")) {
    throw new Error(
      `computePerRepoKeyPath: githubRepo must not contain '..': ${githubRepo}`,
    );
  }
  const slashCount = (githubRepo.match(/\//g) ?? []).length;
  if (slashCount !== 1) {
    throw new Error(
      `computePerRepoKeyPath: githubRepo must be exactly <owner>/<repo>: ${githubRepo}`,
    );
  }
  const [owner, repo] = githubRepo.split("/");
  if (!owner || !repo) {
    throw new Error(
      `computePerRepoKeyPath: owner and repo halves must both be non-empty: ${githubRepo}`,
    );
  }
  if (!VALID_SEGMENT.test(owner) || !VALID_SEGMENT.test(repo)) {
    throw new Error(
      `computePerRepoKeyPath: githubRepo contains invalid characters: ${githubRepo}`,
    );
  }
  return `${SSH_CLIENT_KEY_DIR}/${owner}_${repo}_ed25519`;
}
