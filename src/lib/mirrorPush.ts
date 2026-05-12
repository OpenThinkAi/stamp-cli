/**
 * Build the `spawnSync(git, args, { env })` pieces for the post-receive
 * mirror push.
 *
 * The bot token is supplied to git via env-side config injection rather
 * than the historical `https://x-access-token:<token>@github.com/...` URL
 * form: that form put the token in the process command line, where any
 * local user with `ps` / `/proc/<pid>/cmdline` access could read it during
 * the push window (audit finding L1).
 *
 * Mechanism: `GIT_CONFIG_COUNT=N` plus `GIT_CONFIG_KEY_<i>` /
 * `GIT_CONFIG_VALUE_<i>` pairs are interpreted by git as additional
 * runtime config (equivalent to `-c key=value` flags) but kept in the
 * environment, not on argv. We use it to set `http.extraHeader` to a
 * Basic-auth header carrying the token. GitHub accepts
 * `Authorization: Basic base64("x-access-token:" + <PAT>)` for HTTPS git
 * operations — the same pattern GitHub Actions and gh CLI use internally.
 *
 * Lives in `lib/` rather than inline in `hooks/post-receive.ts` so unit
 * tests can import it without triggering the hook's auto-running `main()`
 * entry point (which calls `process.exit(0)` and would otherwise tear down
 * the test process before any assertions execute).
 */
export function buildMirrorPushInvocation(
  githubRepo: string,
  newSha: string,
  refname: string,
  token: string,
  parentEnv: NodeJS.ProcessEnv = process.env,
): { args: string[]; env: NodeJS.ProcessEnv } {
  const remoteUrl = `https://github.com/${githubRepo}.git`;
  const args = ["push", remoteUrl, `${newSha}:${refname}`];
  const basicAuth = Buffer.from(`x-access-token:${token}`).toString("base64");
  const env: NodeJS.ProcessEnv = {
    ...parentEnv,
    GIT_CONFIG_COUNT: "1",
    GIT_CONFIG_KEY_0: "http.extraHeader",
    GIT_CONFIG_VALUE_0: `Authorization: Basic ${basicAuth}`,
  };
  return { args, env };
}

/**
 * Build the `spawnSync(git, args, { env })` pieces for an SSH-transport
 * mirror push, using a deploy key registered on the GitHub repo as the
 * push identity.
 *
 * This path is selected by post-receive when the server-side deploy-key
 * private file exists at the well-known path
 * (`/srv/git/.ssh-client-keys/github_ed25519`); the SSH client config
 * written by `server/entrypoint.sh` points github.com at that key with
 * `IdentitiesOnly yes` + `UserKnownHostsFile /etc/ssh/ssh_known_hosts`,
 * so no per-push GIT_SSH_COMMAND override is needed — the standard
 * `git@github.com:owner/repo.git` URL is sufficient.
 *
 * Why SSH at all when HTTPS+PAT also works: a Ruleset bypass-actor of
 * `DeployKey` survives the "no machine-user account, no GitHub App
 * approval" constraint common at locked-down work orgs. The PAT path
 * needs a user (or App) identity in the bypass list; the SSH path uses
 * the deploy key, which is a per-repo resource and doesn't touch org-
 * level third-party-application policy.
 *
 * No token is needed for the push itself — SSH auth is via the deploy
 * key. The caller still threads `GITHUB_BOT_TOKEN` separately for the
 * `postStatuses` REST calls (those are unaffected by transport choice).
 */
export function buildMirrorPushInvocationSsh(
  githubRepo: string,
  newSha: string,
  refname: string,
  parentEnv: NodeJS.ProcessEnv = process.env,
): { args: string[]; env: NodeJS.ProcessEnv } {
  const remoteUrl = `git@github.com:${githubRepo}.git`;
  const args = ["push", remoteUrl, `${newSha}:${refname}`];
  return { args, env: { ...parentEnv } };
}
