/**
 * `stamp provision <name>` — single-command server-gated repo setup.
 *
 * What previously took the agent five guesses and a known_hosts crisis:
 *   1. SSH to the stamp server (which host? which port?) and run
 *      `new-stamp-repo <name>` to create the bare repo.
 *   2. Clone the result locally.
 *   3. Run `stamp bootstrap` on the clone to swap the placeholder reviewer
 *      for the real ones.
 *   4. Optionally create a GitHub mirror repo and write .stamp/mirror.yml.
 *   5. Optionally apply the GitHub Ruleset that locks the mirror down.
 *
 * Now: `stamp provision spotfx --org MicroMediaSites`. Reads
 * ~/.stamp/server.yml for connection details, does all five steps, exits
 * with a clean working directory the operator can `cd` into.
 *
 * Designed for agents: deterministic, single-command, no SSH/host-key
 * decisions delegated to the caller. Server-gated mode gets the same
 * "agent never has to bypass anything" property local-only got in 0.6.1.
 */

import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve as resolvePath } from "node:path";
import { parse as parseYaml } from "yaml";
import { runGit } from "../lib/git.js";
import {
  applyStampRuleset,
  checkGhAvailable,
  computeDesiredBypassActors,
  deleteDeployKey,
  fetchDeployKeyPublic,
  findDeployKey,
  findExistingStampRuleset,
  getRulesetBypassActors,
  lookupAuthenticatedUserId,
  lookupRepoOwnerType,
  parseGithubOriginUrl,
  registerDeployKey,
  replaceBypassActors,
  STAMP_MIRROR_DEPLOY_KEY_TITLE,
  type BypassActor,
} from "../lib/ghRuleset.js";
import {
  bareRepoSshUrl,
  loadServerConfig,
  parseServerFlag,
  type ServerConfig,
} from "../lib/serverConfig.js";
import { runBootstrap } from "./bootstrap.js";
import { fetchServerPubkey } from "./server.js";

export interface ProvisionOptions {
  /**
   * Repo name. Required for greenfield (`stamp provision <name>`) and
   * for `--migrate-existing` (used as the new server-side bare repo
   * name). Ignored under `--migrate-bypass` — that mode operates on
   * cwd's existing setup and identifies the GitHub mirror via
   * .stamp/mirror.yml, not a name argument. The CLI passes `""` for
   * migrate-bypass invocations that omit the positional arg; the
   * type stays `string` so the rest of the file's downstream readers
   * don't have to narrow.
   */
  name: string;
  /** Override ~/.stamp/server with `<host>:<port>`. */
  server?: string;
  /** GitHub org or user to host the mirror repo under. Skips mirror setup if omitted. */
  org?: string;
  /** Where to clone the new repo locally. Default: <cwd>/<name>. */
  into?: string;
  /** Skip writing .stamp/mirror.yml and creating the GitHub mirror repo. */
  noMirror?: boolean;
  /** Skip applying the GitHub Ruleset on the mirror repo. */
  noRuleset?: boolean;
  /** Print the plan and exit without changing anything. */
  dryRun?: boolean;
  /** Mark the GitHub mirror repo as private (default true). Ignored in --migrate-existing. */
  privateRepo?: boolean;
  /**
   * Brownfield migration mode: take the existing repo at cwd (already
   * stamp-init'd, with a GitHub remote and history) and migrate it to
   * server-gated topology. Provisions a bare repo on the stamp server
   * seeded from the existing local repo's full state via tarball,
   * renames the existing origin to `github`, points origin at the stamp
   * server, writes mirror.yml from the existing GitHub URL. Does NOT
   * create a new GitHub repo — the existing remote IS the mirror.
   */
  migrateExisting?: boolean;
  /**
   * Bypass-actor migration mode: take an existing server-gated repo
   * (cwd has .stamp/mirror.yml + a github remote) and migrate its
   * `stamp-mirror-only` Ruleset bypass list from `OrganizationAdmin`
   * to `DeployKey`. Fetches a per-repo deploy key from the stamp
   * server, registers it on the GitHub mirror under the canonical
   * `stamp-mirror` title (deleting any prior key under that title
   * that doesn't match — e.g. the legacy shared key), then adds
   * `DeployKey` to the ruleset's bypass actors alongside any
   * existing entries.
   *
   * By default this is purely additive (Phase B in the migration plan).
   * Pair with `--remove-orgadmin` to also strip `OrganizationAdmin`
   * from the bypass list in the same invocation (Phase C); operators
   * are warned to verify the DeployKey path works before doing so,
   * since there's no automated push-verification step.
   */
  migrateBypass?: boolean;
  /**
   * Under `--migrate-bypass`, also remove `OrganizationAdmin` from the
   * ruleset bypass list, leaving only `DeployKey` (and any pre-existing
   * `User` actors). No-op without `--migrate-bypass`.
   */
  removeOrgadmin?: boolean;
}

export async function runProvision(opts: ProvisionOptions): Promise<void> {
  if (opts.migrateExisting && opts.migrateBypass) {
    throw new Error(
      `--migrate-existing and --migrate-bypass are mutually exclusive: the ` +
        `first moves a forge-direct repo to server-gated topology, the ` +
        `second changes the bypass-actor shape on an already-server-gated repo.`,
    );
  }
  if (opts.removeOrgadmin && !opts.migrateBypass) {
    throw new Error(
      `--remove-orgadmin is only meaningful with --migrate-bypass`,
    );
  }
  // Name is required for greenfield + migrate-existing, ignored for
  // migrate-bypass (which identifies the target via .stamp/mirror.yml).
  // The CLI defaults name to "" for migrate-bypass invocations that
  // omit the positional arg — see ProvisionOptions.name's JSDoc.
  if (!opts.migrateBypass) {
    if (!opts.name) {
      throw new Error(
        `stamp provision requires a <name> argument (the bare repo name on the stamp server). ` +
          `If you meant to migrate an already-server-gated repo's Ruleset bypass instead, ` +
          `pass --migrate-bypass (identifies the target via cwd's .stamp/mirror.yml; no <name> needed).`,
      );
    }
    validateRepoName(opts.name);
  } else if (opts.name) {
    console.log(
      `note: <name> argument ignored under --migrate-bypass; the target is identified by .stamp/mirror.yml in the cwd.`,
    );
    console.log();
  }
  if (opts.org !== undefined) validateOrgName(opts.org);

  // 1. Resolve server connection. --server flag wins over the file.
  const server = opts.server
    ? parseServerFlag(opts.server)
    : loadServerConfig();
  if (!server) {
    throw new Error(
      `no stamp server configured. Either:\n` +
        `  - create ~/.stamp/server.yml with at least:\n` +
        `      host: <ssh-host>\n` +
        `      port: <ssh-port>\n` +
        `  - or pass --server <host>:<port> on the command line.\n` +
        `\nSee docs/quickstart-server.md for how to deploy a stamp server first.`,
    );
  }

  // Bypass-actor migration is a separate flow — different inputs
  // (existing .stamp/mirror.yml in cwd, not a name argument), different
  // ops (deploy-key swap + ruleset patch, no bare-repo touches), and
  // doesn't run bootstrap. Branch early so the greenfield code stays
  // clean and so an operator pass that's just changing the bypass shape
  // doesn't accidentally re-trigger any of the other provisioning steps.
  if (opts.migrateBypass) {
    await runMigrateBypass(opts, server);
    return;
  }

  // Brownfield migration is a separate flow — different inputs (existing
  // local repo, not a fresh clone target), different ops (rename remotes,
  // tarball-seed), and different mirror handling (existing GitHub remote,
  // not gh repo create). Branch early so the greenfield code stays clean.
  if (opts.migrateExisting) {
    await runMigrateExisting(opts, server);
    return;
  }

  // 2. Resolve clone destination.
  const cloneTarget = resolvePath(opts.into ?? opts.name);
  if (existsSync(cloneTarget)) {
    throw new Error(
      `clone destination already exists: ${cloneTarget}. ` +
        `Move or remove it, or pass --into <other-path>.`,
    );
  }

  // 3. Print the plan. Always — provision is meant to be transparent.
  printPlan({ opts, server, cloneTarget });

  if (opts.dryRun) {
    console.log("\n(dry run — no changes made)");
    return;
  }

  // 4. Provision the bare repo on the server.
  console.log(`\nProvisioning bare repo on ${server.host}:${server.port}`);
  provisionBareRepoOnServer(server, opts.name);

  // 5. Clone it locally.
  console.log(`Cloning to ${cloneTarget}`);
  const sshUrl = bareRepoSshUrl(server, opts.name);
  runGit(["clone", sshUrl, cloneTarget], process.cwd());

  // 6. Optional: create the GitHub mirror repo.
  let mirrorRepo: { owner: string; repo: string } | null = null;
  if (opts.org && !opts.noMirror) {
    console.log(`Creating GitHub mirror repo ${opts.org}/${opts.name}`);
    mirrorRepo = createGithubMirrorRepo(opts.org, opts.name, opts.privateRepo ?? true);
  }

  // 7. Optional: write .stamp/mirror.yml so the post-receive hook knows where to mirror.
  if (mirrorRepo) {
    writeMirrorYml(cloneTarget, mirrorRepo);
  }

  // 8. Run the existing bootstrap flow (in the clone) to land real reviewers.
  //    Bootstrap commits + pushes to origin (= the stamp server), so this
  //    is the merge that activates real reviewers on main going forward.
  //
  //    chdir is intentional: runBootstrap (and runReview / runMerge inside
  //    it) all use findRepoRoot() from the cwd. The chdir affects only
  //    this in-flight CLI process, which is about to exit — it does NOT
  //    follow the operator into their shell. The "Next: cd <path>" line
  //    in printSuccess is correct advice for the operator's shell.
  console.log(`Bootstrapping reviewers on the clone`);
  process.chdir(cloneTarget);
  await runBootstrap({});

  // 9. Optional: apply the GitHub Ruleset on the mirror repo.
  if (mirrorRepo && !opts.noRuleset) {
    applyMirrorRuleset(mirrorRepo, server);
  }

  // 10. Final summary.
  printSuccess({ cloneTarget, server, repoName: opts.name, mirrorRepo });
}

function validateRepoName(name: string): void {
  // The name is interpolated into ssh args + filesystem paths on the
  // server. Allow alphanumeric, dash, dot, underscore — but require the
  // FIRST character to be alphanumeric or `_`, so a value like `-foo` or
  // `.foo` can't be parsed as a flag or hidden file. The regex enforces
  // both rules in one pass so the error message matches what was rejected.
  if (!/^[A-Za-z0-9_][A-Za-z0-9._-]*$/.test(name)) {
    throw new Error(
      `repo name must start with [A-Za-z0-9_] and match [A-Za-z0-9._-]+ (got "${name}")`,
    );
  }
}

function validateOrgName(org: string): void {
  // Same shape as repo name, applied to --org. GitHub itself constrains
  // org/user names to a narrower set, but adding our own rejection of
  // leading `-` keeps a typo like `--org=-foo` from getting parsed as a
  // flag by `gh repo create` further down the chain.
  if (!/^[A-Za-z0-9_][A-Za-z0-9-]*$/.test(org)) {
    throw new Error(
      `--org must start with [A-Za-z0-9_] and match [A-Za-z0-9-]+ (got "${org}")`,
    );
  }
}

// Shared label width across printPlan and printSuccess so the value column
// lines up identically in both blocks. Convention from .stamp/reviewers/product.md.
const LABEL_PAD = 18;
const fmt = (label: string, value: string): string =>
  `  ${(label + ":").padEnd(LABEL_PAD)} ${value}`;

function printPlan(args: {
  opts: ProvisionOptions;
  server: ServerConfig;
  cloneTarget: string;
}): void {
  const bar = "─".repeat(72);
  console.log(bar);
  console.log("stamp provision — plan");
  console.log(bar);
  console.log(fmt("repo name", args.opts.name));
  console.log(fmt("stamp server", `${args.server.user}@${args.server.host}:${args.server.port}`));
  console.log(fmt("bare repo path", `${args.server.repoRootPrefix}/${args.opts.name}.git`));
  console.log(fmt("local clone", args.cloneTarget));
  if (args.opts.org && !args.opts.noMirror) {
    console.log(fmt("GitHub mirror", `${args.opts.org}/${args.opts.name} (${args.opts.privateRepo === false ? "public" : "private"})`));
    console.log(fmt("mirror.yml", "written to .stamp/mirror.yml in the clone"));
  } else {
    console.log(fmt("GitHub mirror", `skipped (${args.opts.noMirror ? "--no-mirror" : "no --org given"})`));
  }
  if (args.opts.org && !args.opts.noMirror && !args.opts.noRuleset) {
    console.log(fmt("GitHub Ruleset", "apply stamp-mirror-only on the mirror repo"));
    // The bypass-actor shape is determined by gh-side owner-type lookup at
    // apply time, so we can't be certain here. Spell out both possibilities
    // so the operator sees what's actually going to happen in either case.
    console.log(
      fmt(
        "bypass actor",
        `org repo → stamp-server deploy key "${STAMP_MIRROR_DEPLOY_KEY_TITLE}" (auto-registered or reused); ` +
          `personal repo → your gh-authed user`,
      ),
    );
  } else {
    console.log(fmt("GitHub Ruleset", "skipped"));
  }
  console.log(bar);
}

function provisionBareRepoOnServer(
  server: ServerConfig,
  name: string,
): void {
  // ssh git@<host> -p <port> new-stamp-repo <name>
  // new-stamp-repo lives at /usr/local/bin on the server image (see
  // server/Dockerfile). It refuses if the repo already exists, which is
  // the right behavior — provisioning twice is almost always a mistake.
  // The `--` before the destination terminates ssh's option processing —
  // belt-and-suspenders against any future code path that would let a
  // `-`-leading user/host slip past the shape regex in serverConfig.ts.
  const result = spawnSync(
    "ssh",
    [
      "-p",
      String(server.port),
      "--",
      `${server.user}@${server.host}`,
      "new-stamp-repo",
      name,
    ],
    { stdio: ["ignore", "inherit", "inherit"] },
  );
  if (result.status !== 0) {
    throw new Error(
      `ssh ${server.user}@${server.host}:${server.port} new-stamp-repo ${name} failed (exit ${result.status}). ` +
        `Common causes: server unreachable, your SSH key isn't in AUTHORIZED_KEYS, the repo already exists, ` +
        `or the host key changed (check the warning above and verify the new fingerprint matches).`,
    );
  }
}

function createGithubMirrorRepo(
  owner: string,
  repo: string,
  privateRepo: boolean,
): { owner: string; repo: string } {
  const ghCheck = checkGhAvailable();
  if (!ghCheck.available) {
    throw new Error(
      `GitHub mirror requested but ${ghCheck.reason}. ` +
        `Install/authenticate gh, or re-run with --no-mirror.`,
    );
  }
  const visibility = privateRepo ? "--private" : "--public";
  const result = spawnSync(
    "gh",
    ["repo", "create", `${owner}/${repo}`, visibility],
    { stdio: ["ignore", "inherit", "inherit"] },
  );
  if (result.status !== 0) {
    throw new Error(
      `gh repo create ${owner}/${repo} failed. Common causes: repo already exists, ` +
        `you don't have permission in that org, or your token is missing the required scopes.`,
    );
  }
  return { owner, repo };
}

function writeMirrorYml(
  cloneTarget: string,
  mirror: { owner: string; repo: string },
): void {
  // The post-receive hook on the stamp server reads .stamp/mirror.yml at
  // each push to determine where to mirror. Layout matches what the
  // existing budget-app / think-cli repos use; format documented in
  // server/README.md.
  const yml =
    `github:\n` +
    `  repo: ${mirror.owner}/${mirror.repo}\n` +
    `  branches:\n` +
    `    - main\n` +
    `  # Mirror tags to GitHub too — uncomment if you publish on tag push\n` +
    `  # (npm/Cargo/PyPI release workflows). Glob patterns or 'true' for all.\n` +
    `  # tags:\n` +
    `  #   - "v*"\n`;
  const path = `${cloneTarget}/.stamp/mirror.yml`;
  // .stamp/ exists already on the clone (created by the placeholder seed
  // when new-stamp-repo ran on the server side). If it doesn't, the bootstrap
  // step coming next will fail loudly anyway.
  writeFileSync(path, yml);
  console.log(`Wrote mirror.yml → .stamp/mirror.yml (${mirror.owner}/${mirror.repo})`);
}

function applyMirrorRuleset(
  mirror: { owner: string; repo: string },
  server: ServerConfig,
): void {
  // Short-circuit on re-runs: if a stamp-mirror-only ruleset is already
  // present we don't touch it (operator may have customized the actor;
  // we never clobber). Doing this BEFORE deploy-key registration avoids
  // depositing a stray key on a repo whose ruleset we won't end up
  // wiring up to it anyway.
  const existing = findExistingStampRuleset(mirror.owner, mirror.repo);
  if (existing !== null) {
    console.log(
      `GitHub Ruleset: stamp-mirror-only already present on ${mirror.owner}/${mirror.repo}. Not modified.`,
    );
    return;
  }

  const ownerType = lookupRepoOwnerType(mirror.owner, mirror.repo);
  if (ownerType === null) {
    // All "auto-apply skipped" lines in this function use the `warning:`
    // prefix — operator-actionable follow-up signals stay one shape so
    // agents grepping for failure conditions don't have to match `note:`
    // AND `warning:` AND no-prefix variants.
    console.log(
      `warning: GitHub Ruleset auto-apply skipped — couldn't determine whether ${mirror.owner}/${mirror.repo} is a personal or org repo.`,
    );
    console.log(`         For manual setup, see docs/github-ruleset-setup.md.`);
    return;
  }

  let actor: BypassActor;
  let actorDescription: string;
  if (ownerType === "Organization") {
    // Org repos: register the stamp server's mirror-push public key as
    // a per-repo deploy key, then point the Ruleset bypass at it. This
    // path survives locked-down orgs that don't permit machine-user
    // accounts or GitHub App installs — deploy keys are repo-scoped and
    // bypass org third-party-application policy entirely. Replaces the
    // earlier OrganizationAdmin (actor_id=1) magic constant.
    let pubkey: string;
    try {
      // Per-repo deploy key — the server lazily generates one keyed by
      // <owner>/<repo> and returns its public half. Each migrated mirror
      // ends up with its own key, working around GitHub's "deploy key
      // already in use" uniqueness constraint that blocked rolling the
      // legacy shared key across more than one repo.
      pubkey = fetchServerPubkey(server, mirror);
    } catch (err) {
      console.log(
        `warning: GitHub Ruleset auto-apply skipped — couldn't fetch stamp server pubkey: ` +
          `${err instanceof Error ? err.message : String(err)}`,
      );
      console.log(`         For manual setup, see docs/github-ruleset-setup.md.`);
      return;
    }
    const reg = registerDeployKey(
      mirror.owner,
      mirror.repo,
      STAMP_MIRROR_DEPLOY_KEY_TITLE,
      pubkey,
    );
    if (reg.status === "failed") {
      console.log(`warning: GitHub Ruleset auto-apply skipped — deploy-key registration failed: ${reg.error}`);
      console.log(`         For manual setup, see docs/github-ruleset-setup.md.`);
      return;
    }
    const verb = reg.status === "created" ? "registered" : "reused";
    console.log(
      `Deploy key: ${verb} "${STAMP_MIRROR_DEPLOY_KEY_TITLE}" on ${mirror.owner}/${mirror.repo} (id ${reg.keyId}).`,
    );
    actor = { type: "DeployKey", id: reg.keyId };
    actorDescription = `stamp-server deploy key "${STAMP_MIRROR_DEPLOY_KEY_TITLE}", id ${reg.keyId}`;
  } else {
    // Personal repos: User actor on the gh-authed user, same as before
    // the deploy-key migration. Personal repos don't face the org
    // third-party-application policy that drove the migration.
    const user = lookupAuthenticatedUserId();
    if (!user) {
      console.log(
        `warning: GitHub Ruleset auto-apply skipped — couldn't look up the gh-authenticated user.`,
      );
      console.log(`         Try \`gh auth status\` and re-apply manually via docs/github-ruleset-setup.md.`);
      return;
    }
    actor = { type: "User", id: user.id };
    actorDescription = `${user.login}, id ${user.id}`;
  }

  const result = applyStampRuleset(mirror.owner, mirror.repo, actor);
  switch (result.status) {
    case "created":
      console.log(
        `GitHub Ruleset: created stamp-mirror-only on ${mirror.owner}/${mirror.repo} (bypass actor: ${actorDescription}).`,
      );
      break;
    case "exists":
      // The findExistingStampRuleset short-circuit above should make
      // this branch unreachable in practice, but applyStampRuleset's
      // own idempotency check is the source of truth so keep handling
      // it rather than drop into the failed branch.
      console.log(
        `GitHub Ruleset: stamp-mirror-only already present on ${mirror.owner}/${mirror.repo}. Not modified.`,
      );
      break;
    case "failed":
      console.log(
        `warning: GitHub Ruleset auto-apply failed: ${result.error}`,
      );
      console.log(`         For manual setup, see docs/github-ruleset-setup.md.`);
      break;
  }
}

function printSuccess(args: {
  cloneTarget: string;
  server: ServerConfig;
  repoName: string;
  mirrorRepo: { owner: string; repo: string } | null;
}): void {
  const bar = "─".repeat(72);
  console.log(`\n${bar}`);
  console.log(`✓ provisioned`);
  console.log(bar);
  console.log(fmt("clone", args.cloneTarget));
  console.log(fmt("origin", bareRepoSshUrl(args.server, args.repoName)));
  if (args.mirrorRepo) {
    console.log(fmt("mirror", `https://github.com/${args.mirrorRepo.owner}/${args.mirrorRepo.repo}`));
  }
  console.log(bar);
  console.log(`\nNext: cd ${args.cloneTarget}, then work on a feature branch and go through stamp review/merge/push.`);
}

// ---------- brownfield migration ----------

/**
 * Migrate an existing local repo to server-gated topology. Inputs:
 *   - cwd is a git repo with .stamp/ committed and an `origin` remote
 *     pointing at github.com (the future mirror destination).
 *   - opts.name names the bare repo to create on the stamp server.
 *
 * Steps:
 *   1. Sanity-check cwd: is a git repo, has .stamp/, has origin → github.
 *   2. tar | scp the existing repo as a bare-clone to the server.
 *   3. ssh new-stamp-repo --from-tarball: extracts the tarball as the
 *      bare repo (preserves operator's full history, .stamp/, trusted-keys).
 *   4. Locally: rename origin → github, add new origin → stamp server.
 *   5. Write .stamp/mirror.yml from the now-`github` remote URL.
 *   6. Apply the GitHub Ruleset on the existing GitHub repo.
 *
 * Net effect: same local SHAs, same GitHub repo, server is now origin and
 * GitHub is the downstream mirror. No bootstrap merge needed (operator's
 * existing .stamp/config.yml IS the gate config; no placeholder swap dance).
 */
async function runMigrateExisting(
  opts: ProvisionOptions,
  server: ServerConfig,
): Promise<void> {
  const repoRoot = process.cwd();

  // Surface flag-conflict early. --org, --into, and --public/--no-public
  // (privateRepo) only apply to the greenfield path; in migrate mode the
  // mirror destination comes from the existing origin URL and there's no
  // separate clone target. Silent-ignore is the worst option for an agent
  // that passed these expecting them to do something.
  const ignoredFlags: string[] = [];
  if (opts.org !== undefined) ignoredFlags.push("--org");
  if (opts.into !== undefined) ignoredFlags.push("--into");
  if (opts.privateRepo === false) ignoredFlags.push("--public");
  if (ignoredFlags.length > 0) {
    console.log(
      `warning: ${ignoredFlags.join(", ")} ignored under --migrate-existing — ` +
        `the mirror destination comes from the existing \`origin\` remote, ` +
        `and there's no separate clone (cwd is the source).`,
    );
    console.log();
  }

  // 1. Pre-flight checks. The migrate path makes destructive changes to
  // the local repo's remotes and to the stamp server, so refuse loudly
  // when the inputs aren't shaped like we expect — BEFORE any external
  // call. Order matters: checks that don't mutate anything come first,
  // and we re-validate "is github remote already taken" / "is origin
  // already a stamp server URL" so a half-completed prior run doesn't
  // strand the operator with a duplicate remote.
  ensureCwdIsGitRepo(repoRoot);
  ensureStampInitDone(repoRoot);
  const githubOriginUrl = readOriginUrl(repoRoot);
  const mirrorParse = parseGithubOriginUrl(githubOriginUrl);
  if (!mirrorParse) {
    throw new Error(
      `existing origin (${githubOriginUrl}) doesn't look like a github.com URL. ` +
        `--migrate-existing assumes the current origin is the GitHub repo that will become ` +
        `the downstream mirror. If your existing remote isn't GitHub, this command isn't for you yet.`,
    );
  }
  ensureNoConflictingRemotes(repoRoot);
  ensureWorkingTreeClean(repoRoot);

  // 2. Print the plan.
  printMigratePlan({ opts, server, repoRoot, mirror: mirrorParse });

  if (opts.dryRun) {
    console.log("\n(dry run — no changes made)");
    return;
  }

  // 3. Build the bare-clone tarball locally and scp to the server.
  const stagingDir = mkdtempSync(join(tmpdir(), "stamp-migrate-"));
  const bareCloneDir = join(stagingDir, `${opts.name}.git`);
  const tarballPath = join(stagingDir, `${opts.name}.tar.gz`);
  try {
    console.log(`\nBuilding bare-clone tarball of existing repo`);
    runGit(["clone", "--bare", repoRoot, bareCloneDir], stagingDir);
    runTarGz(stagingDir, `${opts.name}.git`, tarballPath);

    console.log(`Uploading tarball to ${server.host}:${server.port}`);
    const remoteTarballPath = `/tmp/stamp-migrate-${opts.name}-${process.pid}.tar.gz`;
    scpToServer(server, tarballPath, remoteTarballPath);

    // 4. Provision the bare repo on the server from the tarball.
    // The server-side `new-stamp-repo --from-tarball` wrapper takes
    // ownership of the uploaded tarball and removes it on exit (success
    // or failure), so no client-side cleanup step is required.
    console.log(`Provisioning bare repo on ${server.host}:${server.port} from tarball`);
    sshRunNewStampRepoFromTarball(server, opts.name, remoteTarballPath);
  } finally {
    rmSync(stagingDir, { recursive: true, force: true });
  }

  // 6. Rewire local remotes. Existing origin → github (preserved as the
  // mirror destination); new origin → stamp server (the new source of truth).
  console.log(`Rewiring local remotes: origin → github, new origin → stamp server`);
  runGit(["remote", "rename", "origin", "github"], repoRoot);
  const stampSshUrl = bareRepoSshUrl(server, opts.name);
  runGit(["remote", "add", "origin", stampSshUrl], repoRoot);

  // 7. Write .stamp/mirror.yml so the post-receive hook on the server
  // knows where to mirror. Skipped under --no-mirror.
  if (!opts.noMirror) {
    writeMirrorYml(repoRoot, mirrorParse);
  }

  // 8. Apply the GitHub Ruleset on the existing GitHub repo. Skipped
  // under --no-ruleset.
  if (!opts.noMirror && !opts.noRuleset) {
    applyMirrorRuleset(mirrorParse, server);
  }

  // 9. Success.
  printMigrateSuccess({ repoRoot, server, repoName: opts.name, mirror: mirrorParse, opts });
}

function ensureCwdIsGitRepo(cwd: string): void {
  try {
    runGit(["rev-parse", "--is-inside-work-tree"], cwd);
  } catch {
    throw new Error(
      `--migrate-existing must run inside an existing git repository. ` +
        `cwd (${cwd}) is not a git working tree. ` +
        `cd into your existing repo first, then re-run.`,
    );
  }
}

function ensureStampInitDone(cwd: string): void {
  if (!existsSync(join(cwd, ".stamp", "config.yml"))) {
    throw new Error(
      `--migrate-existing expects this repo to already be stamp-init'd ` +
        `(${join(cwd, ".stamp/config.yml")} not found). Run \`stamp init --mode local-only\` ` +
        `first, calibrate your reviewers, then re-run with --migrate-existing.`,
    );
  }
}

function readOriginUrl(cwd: string): string {
  try {
    return runGit(["remote", "get-url", "origin"], cwd).trim();
  } catch {
    throw new Error(
      `--migrate-existing expects the existing repo to have an \`origin\` remote ` +
        `pointing at the GitHub repo that will become the mirror. No origin found. ` +
        `Add it first: \`git remote add origin git@github.com:<owner>/<repo>.git\``,
    );
  }
}

/**
 * Refuse to proceed if a `github` remote already exists. Catches the
 * "user re-ran --migrate-existing on an already-migrated repo" case before
 * we provision a duplicate bare on the server. Without this check, the
 * remote rename later in the flow would fail AFTER the server-side
 * provisioning, leaving the operator with a stranded bare repo and no
 * mirror.yml.
 *
 * Other defensive checks (e.g. "origin already points at the stamp
 * server") are unreachable here — the caller validated origin parses as
 * a github.com URL before this runs, so origin can't be a stamp ssh URL
 * by construction. Keep this function focused on the one real concern.
 */
function ensureNoConflictingRemotes(cwd: string): void {
  const remotes = runGit(["remote"], cwd)
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
  if (remotes.includes("github")) {
    throw new Error(
      `a \`github\` remote already exists in this repo. --migrate-existing renames ` +
        `the existing \`origin\` (your GitHub URL) to \`github\`, so the slot must be free. ` +
        `If you've already run --migrate-existing here, the migration is already done — ` +
        `nothing to do. Otherwise: rename or remove the existing \`github\` remote first.`,
    );
  }
}

function ensureWorkingTreeClean(cwd: string): void {
  const dirty = runGit(["status", "--porcelain", "--untracked-files=no"], cwd).trim();
  if (dirty) {
    throw new Error(
      `working tree has uncommitted changes. --migrate-existing rewires remotes; ` +
        `commit or stash your work first.`,
    );
  }
}

function runTarGz(parentDir: string, dirName: string, outputPath: string): void {
  // Pack the bare-clone dir as a gzipped tarball. `-C parentDir dirName`
  // preserves the top-level directory name inside the archive so the
  // server-side --strip-components=1 + extraction lands cleanly.
  const result = spawnSync("tar", ["-czf", outputPath, "-C", parentDir, dirName], {
    stdio: ["ignore", "inherit", "inherit"],
  });
  if (result.status !== 0) {
    throw new Error(
      `tar -czf failed (exit ${result.status}). Cannot package the existing repo for upload.`,
    );
  }
}

function scpToServer(
  server: ServerConfig,
  localPath: string,
  remotePath: string,
): void {
  // scp -P <port> -- <local> <user>@<host>:<remote>
  // `--` before the positional args terminates scp's option processing.
  const result = spawnSync(
    "scp",
    [
      "-P",
      String(server.port),
      "--",
      localPath,
      `${server.user}@${server.host}:${remotePath}`,
    ],
    { stdio: ["ignore", "inherit", "inherit"] },
  );
  if (result.status !== 0) {
    throw new Error(
      `scp to ${server.user}@${server.host}:${server.port} failed (exit ${result.status}). ` +
        `Common causes: SSH key isn't authorized, host-key mismatch, or the server doesn't allow scp.`,
    );
  }
}

function sshRunNewStampRepoFromTarball(
  server: ServerConfig,
  name: string,
  remoteTarballPath: string,
): void {
  const result = spawnSync(
    "ssh",
    [
      "-p",
      String(server.port),
      "--",
      `${server.user}@${server.host}`,
      "new-stamp-repo",
      name,
      "--from-tarball",
      remoteTarballPath,
    ],
    { stdio: ["ignore", "inherit", "inherit"] },
  );
  if (result.status !== 0) {
    throw new Error(
      `ssh new-stamp-repo ${name} --from-tarball failed (exit ${result.status}). ` +
        `Common causes: server doesn't have the new-stamp-repo --from-tarball mode yet (server image is older than 0.7.1), ` +
        `the bare repo path already exists, or the tarball is malformed.`,
    );
  }
}

function printMigratePlan(args: {
  opts: ProvisionOptions;
  server: ServerConfig;
  repoRoot: string;
  mirror: { owner: string; repo: string };
}): void {
  const bar = "─".repeat(72);
  console.log(bar);
  console.log("stamp provision --migrate-existing — plan");
  console.log(bar);
  console.log(fmt("source repo", args.repoRoot));
  console.log(fmt("repo name", args.opts.name));
  console.log(fmt("stamp server", `${args.server.user}@${args.server.host}:${args.server.port}`));
  console.log(fmt("bare repo path", `${args.server.repoRootPrefix}/${args.opts.name}.git`));
  console.log(
    fmt("seed", "tarball of existing repo (full history + .stamp/ + trusted-keys preserved)"),
  );
  console.log(fmt("origin", "stamp server (was: github)"));
  console.log(fmt("github", `mirror destination (${args.mirror.owner}/${args.mirror.repo})`));
  if (!args.opts.noMirror) {
    console.log(fmt("mirror.yml", "written to .stamp/mirror.yml"));
  } else {
    console.log(fmt("mirror.yml", "skipped (--no-mirror)"));
  }
  if (!args.opts.noMirror && !args.opts.noRuleset) {
    console.log(fmt("GitHub Ruleset", `apply stamp-mirror-only on ${args.mirror.owner}/${args.mirror.repo}`));
  } else {
    console.log(fmt("GitHub Ruleset", "skipped"));
  }
  console.log(bar);
}

function printMigrateSuccess(args: {
  repoRoot: string;
  server: ServerConfig;
  repoName: string;
  mirror: { owner: string; repo: string };
  opts: ProvisionOptions;
}): void {
  const bar = "─".repeat(72);
  console.log(`\n${bar}`);
  console.log(`✓ migrated to server-gated`);
  console.log(bar);
  console.log(fmt("repo", args.repoRoot));
  console.log(fmt("origin", bareRepoSshUrl(args.server, args.repoName)));
  console.log(fmt("github", `https://github.com/${args.mirror.owner}/${args.mirror.repo} (mirror)`));
  console.log(bar);
  if (!args.opts.noMirror) {
    console.log(`\nmirror.yml was added to .stamp/. Commit it through the normal stamp flow:`);
    console.log(`  git checkout -b chore/add-mirror-yml`);
    console.log(`  git add .stamp/mirror.yml && git commit -m "stamp: add mirror.yml"`);
    console.log(`  stamp review --diff main..chore/add-mirror-yml`);
    console.log(`  git checkout main && stamp merge chore/add-mirror-yml --into main`);
    console.log(`  stamp push main`);
  }
}

// ---------- bypass-actor migration ----------

/**
 * Read .stamp/mirror.yml from the current working directory and return
 * the parsed `<owner>/<repo>` of the GitHub mirror destination.
 *
 * Mirrors the post-receive hook's mirror-config parser shape (the
 * canonical reader at runtime) but operates on the working tree rather
 * than a git ref — the operator is running this command in their
 * checkout, so cwd is what we want. Failure modes surface as Error
 * with actionable messages; the caller catches at the top level.
 */
function readMirrorYmlGithubRepo(repoRoot: string): { owner: string; repo: string } {
  const path = join(repoRoot, ".stamp", "mirror.yml");
  if (!existsSync(path)) {
    throw new Error(
      `${path} not found — --migrate-bypass operates on an already-server-gated repo, ` +
        `but this cwd has no .stamp/mirror.yml. If the repo is not yet server-gated, ` +
        `provision it first with \`stamp provision --migrate-existing\`.`,
    );
  }
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    throw new Error(
      `could not read ${path}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  let parsed: unknown;
  try {
    parsed = parseYaml(raw);
  } catch (err) {
    throw new Error(
      `${path} failed to parse as YAML: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${path} is empty or not a map`);
  }
  const obj = parsed as Record<string, unknown>;
  const gh = obj["github"];
  if (!gh || typeof gh !== "object" || Array.isArray(gh)) {
    throw new Error(`${path} has no usable 'github' map`);
  }
  const repoStr = (gh as Record<string, unknown>)["repo"];
  if (typeof repoStr !== "string" || !/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(repoStr)) {
    throw new Error(
      `${path} github.repo is missing or not of form 'owner/repo' (got ${JSON.stringify(repoStr)})`,
    );
  }
  const slashIdx = repoStr.indexOf("/");
  return {
    owner: repoStr.slice(0, slashIdx),
    repo: repoStr.slice(slashIdx + 1),
  };
}

/**
 * `stamp provision --migrate-bypass` — change an existing server-gated
 * repo's GitHub Ruleset bypass actor from `OrganizationAdmin` to
 * `DeployKey` (a per-repo SSH key the stamp server generates on demand).
 *
 * Why: the OrganizationAdmin actor delegates to ANY org admin, which
 * conflicts with locked-down work-org policies that prohibit machine
 * users / GitHub App installs. The DeployKey actor is repo-scoped and
 * survives those constraints. The migration is staged so each repo
 * can be flipped independently and verified before the previous
 * bypass actor is removed.
 *
 * Two phases, controlled by `--remove-orgadmin`:
 *
 *   Phase A → B (default): purely additive. Register the per-repo
 *   deploy key, add `DeployKey` to the ruleset bypass list alongside
 *   any existing actors. No path is closed. Re-running this against
 *   an already-migrated repo is a no-op (idempotent at both the
 *   deploy-key and the ruleset layer).
 *
 *   Phase B → C (`--remove-orgadmin`): strip `OrganizationAdmin` from
 *   the bypass list. After this, the per-repo deploy key is the only
 *   bypass identity. Done last because there is no automated push-
 *   verification step — the operator should land at least one
 *   `stamp push main` between Phase B and Phase C to confirm the
 *   DeployKey transport works against this specific repo's mirror.
 *
 * The cwd MUST be the local checkout of the server-gated repo —
 * `.stamp/mirror.yml` is the source of truth for which GitHub mirror
 * to migrate.
 */
async function runMigrateBypass(
  opts: ProvisionOptions,
  server: ServerConfig,
): Promise<void> {
  const repoRoot = process.cwd();
  const mirror = readMirrorYmlGithubRepo(repoRoot);

  // Pre-flight checks: gh tooling, then the live server's per-repo
  // pubkey wrapper. Both are blocking — without gh we can't read or
  // mutate the ruleset; without the per-repo wrapper there's no
  // per-repo key to register and the migration has no work to do.
  const ghCheck = checkGhAvailable();
  if (!ghCheck.available) {
    throw new Error(
      `--migrate-bypass requires gh: ${ghCheck.reason}. ` +
        `Install/authenticate gh, then re-run.`,
    );
  }

  printMigrateBypassPlan({ mirror, server, opts });

  if (opts.dryRun) {
    console.log("\n(dry run — no changes made)");
    return;
  }

  console.log(`\nFetching per-repo deploy key from stamp server`);
  let pubkey: string;
  try {
    pubkey = fetchServerPubkey(server, mirror);
  } catch (err) {
    throw new Error(
      `failed to fetch per-repo pubkey for ${mirror.owner}/${mirror.repo} ` +
        `from ${server.user}@${server.host}:${server.port}: ` +
        `${err instanceof Error ? err.message : String(err)}`,
    );
  }

  // If a key already exists on the GitHub repo under the canonical
  // stamp-mirror title, decide whether it's the one we want.
  //   - Same public-key body → idempotent, nothing to do (reuse the id).
  //   - Different body (e.g. the legacy shared key registered earlier
  //     for this repo, or a stale per-repo from a re-keyed server)
  //     → delete it before re-POSTing the new one. GitHub rejects a
  //     re-POST under the same title with a different key body.
  console.log(`Checking existing deploy keys on ${mirror.owner}/${mirror.repo}`);
  const existingKeyId = findDeployKey(
    mirror.owner,
    mirror.repo,
    STAMP_MIRROR_DEPLOY_KEY_TITLE,
  );
  let deployKeyId: number;
  if (existingKeyId !== null) {
    const existingBody = fetchDeployKeyPublic(
      mirror.owner,
      mirror.repo,
      existingKeyId,
    );
    if (existingBody === pubkey) {
      console.log(
        `Deploy key: "${STAMP_MIRROR_DEPLOY_KEY_TITLE}" already matches per-repo pubkey (keyId ${existingKeyId}). No change.`,
      );
      deployKeyId = existingKeyId;
    } else {
      console.log(
        `Deploy key: "${STAMP_MIRROR_DEPLOY_KEY_TITLE}" is registered but doesn't match the per-repo pubkey ` +
          `(keyId ${existingKeyId}). Deleting before re-registering.`,
      );
      const del = deleteDeployKey(mirror.owner, mirror.repo, existingKeyId);
      if (del.status === "failed") {
        throw new Error(`deploy-key cleanup failed: ${del.error}`);
      }
      deployKeyId = registerStampMirrorKey(mirror, pubkey);
    }
  } else {
    deployKeyId = registerStampMirrorKey(mirror, pubkey);
  }

  // Locate the ruleset. Three legitimate cases:
  //
  //   - Canonical `stamp-mirror-only` Ruleset exists: update its
  //     bypass list (the main migration path; covers stamp-cli +
  //     dispatch + open-team + open-audit).
  //
  //   - No Ruleset at all: the repo is server-gated only (Railway bare
  //     repo exists, GitHub side is unprotected). ui-leaf fits this
  //     shape. The migration's per-repo-deploy-key registration is
  //     still useful here — it's what unblocks the mirror leg for
  //     the next push — but there's no bypass list to mutate. Warn
  //     and exit cleanly after deploy-key registration.
  //
  //   - A Ruleset exists under a non-canonical name (think-cli's
  //     `Protect Main`): findExistingStampRuleset returns null because
  //     it looks up by exact name. Indistinguishable from "no Ruleset"
  //     at this layer. The warning text below mentions both
  //     possibilities so the operator can disambiguate by inspecting
  //     the repo's settings.
  console.log(`Looking up stamp-mirror-only ruleset on ${mirror.owner}/${mirror.repo}`);
  const rulesetId = findExistingStampRuleset(mirror.owner, mirror.repo);
  if (rulesetId === null) {
    console.log(
      `note: no \`stamp-mirror-only\` Ruleset on ${mirror.owner}/${mirror.repo}. ` +
        `Deploy key is registered; no bypass list to update.`,
    );
    console.log(
      `      If this repo is server-gated only (no GitHub-side enforcement),` +
        ` that's expected and you're done.`,
    );
    console.log(
      `      If you EXPECTED a Ruleset, it may use a non-canonical name` +
        ` (e.g. think-cli's \`Protect Main\`) — rename to \`stamp-mirror-only\`` +
        ` in the GitHub UI and re-run, or migrate by hand.`,
    );
    if (opts.removeOrgadmin) {
      console.log(
        `      --remove-orgadmin requested but there's no Ruleset bypass list to modify; ignoring.`,
      );
    }
    printMigrateBypassSuccess({
      mirror,
      server,
      opts,
      rulesetUpdated: false,
    });
    return;
  }

  // Compute the desired bypass list and let replaceBypassActors handle
  // the read + idempotency check itself. The helper already re-reads
  // GitHub's current state right before PUT and returns `unchanged` if
  // there's nothing to do, so a caller-side pre-read would just
  // duplicate the round-trip without offering anything the helper
  // doesn't. The pre-read here is purely so we can DERIVE the desired
  // list from the current state (preserving any unmanaged actor
  // types); the helper's internal check is the idempotency gate, not
  // a TOCTOU guarantee — a concurrent admin edit between the helper's
  // own pre-read and PUT would still be overwritten by our derived
  // list, but the worst case is overwriting with the operator's
  // intended state, which is what they asked for.
  console.log(`Reading current bypass_actors on ruleset ${rulesetId}`);
  const current = getRulesetBypassActors(mirror.owner, mirror.repo, rulesetId);
  if (current === null) {
    throw new Error(
      `could not read bypass_actors on ${mirror.owner}/${mirror.repo} ruleset ${rulesetId}`,
    );
  }
  const desired = computeDesiredBypassActors(current, deployKeyId, {
    removeOrgadmin: opts.removeOrgadmin === true,
  });
  const result = replaceBypassActors(
    mirror.owner,
    mirror.repo,
    rulesetId,
    desired,
  );
  if (result.status === "failed") {
    throw new Error(`ruleset bypass update failed: ${result.error}`);
  }
  if (result.status === "updated") {
    console.log(
      `Ruleset bypass: updated to [${desired.map((a) => a.actor_type).join(", ")}].`,
    );
  } else {
    console.log(`Ruleset bypass: already up to date. No change.`);
  }

  printMigrateBypassSuccess({ mirror, server, opts, rulesetUpdated: true });
}

/**
 * Wrap registerDeployKey for the migrate-bypass flow: throws on
 * failure (the migration can't proceed without a key id), logs on
 * success. Factored out so the "existing key needs replacing" and
 * "no existing key" branches of runMigrateBypass don't duplicate the
 * registration prose.
 */
function registerStampMirrorKey(
  mirror: { owner: string; repo: string },
  pubkey: string,
): number {
  const reg = registerDeployKey(
    mirror.owner,
    mirror.repo,
    STAMP_MIRROR_DEPLOY_KEY_TITLE,
    pubkey,
  );
  if (reg.status === "failed") {
    throw new Error(`deploy-key registration failed: ${reg.error}`);
  }
  console.log(
    `Deploy key: registered "${STAMP_MIRROR_DEPLOY_KEY_TITLE}" on ${mirror.owner}/${mirror.repo} (id ${reg.keyId}).`,
  );
  return reg.keyId;
}

function printMigrateBypassPlan(args: {
  mirror: { owner: string; repo: string };
  server: ServerConfig;
  opts: ProvisionOptions;
}): void {
  const bar = "─".repeat(72);
  console.log(bar);
  console.log("stamp provision --migrate-bypass — plan");
  console.log(bar);
  console.log(fmt("mirror", `${args.mirror.owner}/${args.mirror.repo}`));
  console.log(fmt("stamp server", `${args.server.user}@${args.server.host}:${args.server.port}`));
  console.log(
    fmt(
      "deploy key",
      `fetch per-repo pubkey from server; register as "${STAMP_MIRROR_DEPLOY_KEY_TITLE}" on the mirror (replacing any prior entry under that title)`,
    ),
  );
  console.log(
    fmt(
      "ruleset",
      `add DeployKey actor to stamp-mirror-only bypass list` +
        (args.opts.removeOrgadmin
          ? `; remove OrganizationAdmin (--remove-orgadmin)`
          : `; preserve OrganizationAdmin`),
    ),
  );
  console.log(bar);
  if (args.opts.removeOrgadmin) {
    // Emit as a standalone `warning:` advisory rather than a row in
    // the plan table — operator-actionable cautions stay one shape
    // across the codebase (matches the warning-prefix convention used
    // in src/commands/server.ts and elsewhere) and don't compete with
    // the key:value formatting of plan rows.
    console.log(
      `warning: --remove-orgadmin strips the OrganizationAdmin bypass before any push-verification` +
        ` step runs. Verify the DeployKey transport works (one stamp push) before running this.`,
    );
  }
}

function printMigrateBypassSuccess(args: {
  mirror: { owner: string; repo: string };
  server: ServerConfig;
  opts: ProvisionOptions;
  /**
   * Whether the Ruleset bypass list was actually mutated (or even
   * exists). False when the repo is server-gated only (no GitHub
   * Ruleset present) — only the deploy-key registration step ran,
   * which is enough to unblock the mirror push but doesn't change
   * any bypass enforcement.
   */
  rulesetUpdated: boolean;
}): void {
  const bar = "─".repeat(72);
  console.log(`\n${bar}`);
  // Branch the headline so the success glyph doesn't overclaim. The
  // no-ruleset path didn't actually mutate any bypass list — only the
  // deploy-key registration ran — so an agent scanning the headline
  // alone shouldn't conclude the bypass shape was migrated when it
  // wasn't. (Product reviewer feedback.)
  console.log(
    args.rulesetUpdated
      ? `✓ bypass migrated`
      : `✓ deploy key registered (no ruleset to migrate)`,
  );
  console.log(bar);
  console.log(fmt("mirror", `${args.mirror.owner}/${args.mirror.repo}`));
  if (args.rulesetUpdated) {
    console.log(
      fmt(
        "bypass actors",
        args.opts.removeOrgadmin
          ? `DeployKey (OrganizationAdmin removed)`
          : `OrganizationAdmin + DeployKey`,
      ),
    );
  } else {
    console.log(
      fmt(
        "bypass actors",
        `n/a (no stamp-mirror-only Ruleset on this repo — server-gated only)`,
      ),
    );
  }
  console.log(bar);
  if (!args.rulesetUpdated) {
    console.log(
      `\nDeploy key is registered; the next stamp push's mirror leg will use it.\n` +
        `No GitHub Ruleset was found on this repo, so there's no bypass enforcement\n` +
        `to verify. If you want GitHub-side protection, apply the stamp-mirror-only\n` +
        `Ruleset separately (see docs/github-ruleset-setup.md).`,
    );
  } else if (!args.opts.removeOrgadmin) {
    console.log(
      `\nNext: do a stamp merge + push to verify the DeployKey transport works,\n` +
        `then re-run with --remove-orgadmin to drop the OrganizationAdmin fallback.`,
    );
  } else {
    console.log(
      `\nThe stamp-mirror-only Ruleset now bypasses ONLY via the per-repo deploy key.\n` +
        `Direct \`git push origin main\` from any non-stamp source will be rejected.`,
    );
  }
}
