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
import { existsSync, writeFileSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { runGit } from "../lib/git.js";
import {
  applyStampRuleset,
  checkGhAvailable,
  lookupAuthenticatedUserId,
} from "../lib/ghRuleset.js";
import {
  bareRepoSshUrl,
  loadServerConfig,
  parseServerFlag,
  type ServerConfig,
} from "../lib/serverConfig.js";
import { runBootstrap } from "./bootstrap.js";

export interface ProvisionOptions {
  /** Repo name. Used for both the bare repo on the server and (if --org) the GitHub mirror. */
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
  /** Mark the GitHub mirror repo as private (default true). */
  privateRepo?: boolean;
}

export async function runProvision(opts: ProvisionOptions): Promise<void> {
  validateRepoName(opts.name);
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
    applyMirrorRuleset(mirrorRepo);
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
  const result = spawnSync(
    "ssh",
    [
      "-p",
      String(server.port),
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
    `    - main\n`;
  const path = `${cloneTarget}/.stamp/mirror.yml`;
  // .stamp/ exists already on the clone (created by the placeholder seed
  // when new-stamp-repo ran on the server side). If it doesn't, the bootstrap
  // step coming next will fail loudly anyway.
  writeFileSync(path, yml);
  console.log(`Wrote mirror.yml → .stamp/mirror.yml (${mirror.owner}/${mirror.repo})`);
}

function applyMirrorRuleset(mirror: { owner: string; repo: string }): void {
  const user = lookupAuthenticatedUserId();
  if (!user) {
    console.log(
      `note: GitHub Ruleset auto-apply skipped — couldn't look up the gh-authenticated user.`,
    );
    console.log(`      Try \`gh auth status\` and re-apply manually via docs/github-ruleset-setup.md.`);
    return;
  }
  const result = applyStampRuleset(mirror.owner, mirror.repo, user.id);
  switch (result.status) {
    case "created":
      console.log(
        `GitHub Ruleset: created stamp-mirror-only on ${mirror.owner}/${mirror.repo} (bypass actor: ${user.login}, id ${user.id}).`,
      );
      break;
    case "exists":
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

