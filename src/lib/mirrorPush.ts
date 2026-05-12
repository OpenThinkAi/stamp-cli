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
 * Two modes, selected by post-receive based on which key file exists on
 * the server:
 *
 *   - `sshKeyPath` omitted (LEGACY shared key): no per-push override.
 *     The SSH client config written by `server/entrypoint.sh` points
 *     github.com at the shared `/srv/git/.ssh-client-keys/github_ed25519`
 *     with `IdentitiesOnly yes` + `UserKnownHostsFile
 *     /etc/ssh/ssh_known_hosts`. Kept for back-compat with repos
 *     provisioned before the per-repo key feature shipped.
 *
 *   - `sshKeyPath` provided (PER-REPO key): overrides the SSH command
 *     so the push authenticates ONLY as the specific deploy key
 *     registered on this repo.
 *
 *     The override has to bypass `~/.ssh/config` with `-F /dev/null`,
 *     not merely set `IdentitiesOnly=yes`. The static client config
 *     installed by `server/entrypoint.sh` carries an `IdentityFile`
 *     line pointing at the legacy shared key. `IdentitiesOnly=yes`
 *     only suppresses ssh-agent / PKCS11 / SecurityKey sources — it
 *     does NOT suppress static-config `IdentityFile` entries (see
 *     `ssh_config(5)`). With the static config in scope, ssh would
 *     offer BOTH the legacy IdentityFile and the per-repo `-i` key;
 *     github auths the first one accepted (the legacy key) and the
 *     push then fails at the deploy-key→repo authorization layer
 *     because the legacy key is registered on stamp-cli, not the
 *     target. `-F /dev/null` makes ssh ignore both system and user
 *     config; we then re-specify the host-verification directives
 *     (`UserKnownHostsFile=/etc/ssh/ssh_known_hosts`,
 *     `StrictHostKeyChecking=yes`) on the command line so the strict
 *     verification posture of the static config is preserved.
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
  sshKeyPath?: string,
): { args: string[]; env: NodeJS.ProcessEnv } {
  const remoteUrl = `git@github.com:${githubRepo}.git`;
  const args = ["push", remoteUrl, `${newSha}:${refname}`];
  const env: NodeJS.ProcessEnv = { ...parentEnv };
  if (sshKeyPath) {
    // sshKeyPath is constructed by computePerRepoKeyPath from a
    // validated <owner>/<repo> spec, so it cannot contain whitespace,
    // shell metacharacters, or anything outside [A-Za-z0-9./_-]. git's
    // GIT_SSH_COMMAND parser splits on whitespace and interprets the
    // result as ssh's argv; embedding the path bare is safe under those
    // rules. The four options form a complete replacement for the
    // static client config's directives.
    env["GIT_SSH_COMMAND"] =
      `ssh -F /dev/null` +
      ` -i ${sshKeyPath}` +
      ` -o IdentitiesOnly=yes` +
      ` -o UserKnownHostsFile=/etc/ssh/ssh_known_hosts` +
      ` -o StrictHostKeyChecking=yes`;
  }
  return { args, env };
}
