/**
 * `stamp trust grant <short-name> [--repo <path>]`
 *
 * Stages a per-repo trusted-key add for an enrolled user. Workflow:
 *
 *   1. Fetch the user's stamp signing pubkey from the configured stamp
 *      server (SSH to `stamp-users get-stamp-pubkey <short-name>`).
 *   2. Validate the PEM and check whether the repo already trusts a key
 *      with the same fingerprint — short-circuit on no-op.
 *   3. Create a feature branch `stamp-trust/<short-name>`.
 *   4. Write the pubkey to `.stamp/trusted-keys/<short-name>.pub`.
 *   5. git add + git commit (regular operator-signed commit, NOT a
 *      stamp-signed merge — that comes at merge time).
 *   6. Print next-step instructions so the operator can run `stamp
 *      review` and merge through the usual gate.
 *
 * Phase-4 scope: prepare the branch + commit only. We deliberately
 * don't auto-run `stamp review` or push — both are externally-visible
 * actions the operator should confirm. The printed next-steps are
 * copy-pasteable.
 *
 * The trust-grant change itself goes through the standard stamp gate
 * (existing trusted signers must approve the merge that adds a new
 * trusted-keys file), so this CLI has no server-side authorization
 * surface — anyone who can write to the local repo can stage the
 * branch, but the merge will fail without proper review + signatures.
 */

import { spawnSync } from "node:child_process";
import {
  createPublicKey,
  createHash,
} from "node:crypto";
import {
  existsSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import {
  ensureDir,
  stampConfigDir,
  stampTrustedKeysDir,
} from "../lib/paths.js";
import {
  loadServerConfig,
  type ServerConfig,
} from "../lib/serverConfig.js";
import { UsageError } from "./serverRepo.js";

export interface TrustGrantOptions {
  shortName: string;
  /** Defaults to process.cwd(). */
  repoPath?: string;
  /** Skip the working-tree-clean check (use after stashing). */
  forceDirty?: boolean;
}

// Wire contract with src/server/users-cli.ts EXIT constant.
const USERS_EXIT = {
  OK: 0,
  CONFIG: 1,
  USAGE: 2,
  AUTHORITY: 3,
  NOT_FOUND: 4,
} as const;

const SHORT_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;

function resolveServer(): ServerConfig {
  const server = loadServerConfig();
  if (!server) {
    throw new UsageError(
      "no ~/.stamp/server.yml — run `stamp server config <host>:<port>` first",
    );
  }
  return server;
}

function fetchStampPubkey(server: ServerConfig, shortName: string): string {
  const result = spawnSync(
    "ssh",
    [
      "-p",
      String(server.port),
      "--",
      `${server.user}@${server.host}`,
      "stamp-users",
      "get-stamp-pubkey",
      shortName,
    ],
    { stdio: ["ignore", "pipe", "inherit"], encoding: "utf8" },
  );
  if (result.status === 0) {
    return result.stdout;
  }
  if (result.status === USERS_EXIT.NOT_FOUND) {
    throw new UsageError(
      `${server.host}: user ${JSON.stringify(shortName)} is either not enrolled ` +
        `or has no stamp signing pubkey on file. Run \`stamp users list\` to ` +
        `confirm enrollment; ask the user to re-run \`stamp invites accept ` +
        `--stamp-pubkey <path>\` if their signing key was missing at invite time.`,
    );
  }
  if (result.status === USERS_EXIT.CONFIG) {
    throw new Error(
      `server-side identity binding failed against ${server.host}. Your SSH ` +
        `key may not be enrolled in the membership DB yet, or the server is ` +
        `missing 'ExposeAuthInfo yes' in sshd_config.`,
    );
  }
  throw new Error(
    `fetching stamp_pubkey for ${JSON.stringify(shortName)} from ` +
      `${server.user}@${server.host}:${server.port} failed (exit ${result.status}). ` +
      `Common causes: server unreachable, your SSH key isn't enrolled, ` +
      `or the server image predates the get-stamp-pubkey subcommand.`,
  );
}

/**
 * Compute the same "sha256:<hex>" fingerprint shape stamp-cli uses for
 * stamp signing pubkeys (see src/lib/keys.ts). Used here to detect a
 * no-op grant (the repo already trusts this exact key under some name).
 */
function fingerprintFromPem(pem: string): string {
  const pub = createPublicKey(pem);
  const raw = pub.export({ type: "spki", format: "der" }) as Buffer;
  return `sha256:${createHash("sha256").update(raw).digest("hex")}`;
}

function findExistingTrustedKey(
  repoRoot: string,
  fingerprint: string,
): string | null {
  const dir = stampTrustedKeysDir(repoRoot);
  if (!existsSync(dir)) return null;
  for (const f of readdirSync(dir)) {
    if (!f.endsWith(".pub")) continue;
    const fullPath = join(dir, f);
    let pem: string;
    try {
      pem = readFileSync(fullPath, "utf8");
    } catch {
      continue;
    }
    try {
      if (fingerprintFromPem(pem) === fingerprint) return f;
    } catch {
      // Skip malformed key files — they're a pre-existing repo state,
      // not our concern here.
    }
  }
  return null;
}

function runGit(args: string[], cwd: string): string {
  const result = spawnSync("git", args, {
    cwd,
    stdio: ["ignore", "pipe", "pipe"],
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(
      `git ${args.join(" ")} failed (exit ${result.status}):\n${result.stderr ?? ""}`.trim(),
    );
  }
  return result.stdout ?? "";
}

function workingTreeClean(repoRoot: string): boolean {
  const result = spawnSync("git", ["status", "--porcelain"], {
    cwd: repoRoot,
    stdio: ["ignore", "pipe", "inherit"],
    encoding: "utf8",
  });
  if (result.status !== 0) return false;
  return (result.stdout ?? "").trim().length === 0;
}

function branchExists(repoRoot: string, branch: string): boolean {
  const result = spawnSync(
    "git",
    ["show-ref", "--verify", "--quiet", `refs/heads/${branch}`],
    { cwd: repoRoot, stdio: "ignore" },
  );
  return result.status === 0;
}

function currentBranch(repoRoot: string): string {
  return runGit(["rev-parse", "--abbrev-ref", "HEAD"], repoRoot).trim();
}

export function runTrustGrant(opts: TrustGrantOptions): void {
  if (!SHORT_NAME_RE.test(opts.shortName)) {
    throw new UsageError(
      `short-name ${JSON.stringify(opts.shortName)} has an invalid shape ` +
        `(allowed: alphanumerics + . _ -, must start with alnum, max 63 chars).`,
    );
  }

  const repoRoot = resolve(opts.repoPath ?? process.cwd());

  // Verify we're inside a stamp-gated git repo. Both checks together
  // are load-bearing: a plain git repo without .stamp/ has nothing to
  // trust into; a .stamp/ directory without a working git repo can't
  // host a feature branch.
  if (!existsSync(join(repoRoot, ".git"))) {
    throw new UsageError(`${repoRoot} is not a git repository`);
  }
  if (!existsSync(stampConfigDir(repoRoot))) {
    throw new UsageError(
      `${repoRoot} has no .stamp/ directory — run \`stamp init\` first or pass ` +
        `--repo <path> pointing at a stamp-gated repo`,
    );
  }

  if (!opts.forceDirty && !workingTreeClean(repoRoot)) {
    throw new UsageError(
      `${repoRoot} has uncommitted changes. Commit or stash them first, then ` +
        `re-run. (Use --force-dirty to override, but the resulting branch will ` +
        `include unrelated changes.)`,
    );
  }

  // Branch-exists check before the SSH round-trip — a pre-existing branch
  // collision is a synchronous local op that doesn't need a network call
  // to surface.
  const branch = `stamp-trust/${opts.shortName}`;
  if (branchExists(repoRoot, branch)) {
    throw new UsageError(
      `branch ${branch} already exists. Delete it (\`git branch -D ${branch}\`) ` +
        `or finish the in-flight grant by switching to it and pushing/merging.`,
    );
  }

  const server = resolveServer();
  const pemRaw = fetchStampPubkey(server, opts.shortName);
  const pem = pemRaw.trim() + "\n"; // normalize trailing newline

  // Validate the PEM shape before doing anything to the repo.
  let fingerprint: string;
  try {
    fingerprint = fingerprintFromPem(pem);
  } catch (e) {
    throw new Error(
      `server returned an invalid PEM for ${opts.shortName}: ${(e as Error).message}. ` +
        `This is almost always a server-side issue (corrupted membership DB, ` +
        `or a future server version emitting a key format this client can't ` +
        `parse). Contact the server admin with the PEM body.`,
    );
  }

  const existingFile = findExistingTrustedKey(repoRoot, fingerprint);
  if (existingFile) {
    // No-op: the repo already trusts a key with this fingerprint
    // (possibly under a different filename). Don't churn a branch for
    // it; tell the operator and exit cleanly.
    process.stdout.write(
      `note: repo already trusts ${opts.shortName}'s stamp signing key ` +
        `(matching .stamp/trusted-keys/${existingFile}). No changes.\n`,
    );
    return;
  }

  const startingBranch = currentBranch(repoRoot);

  // Create + checkout the feature branch.
  runGit(["checkout", "-b", branch], repoRoot);

  // Write the trusted-keys file.
  const keysDir = stampTrustedKeysDir(repoRoot);
  ensureDir(keysDir, 0o755);
  const keyFile = join(keysDir, `${opts.shortName}.pub`);
  writeFileSync(keyFile, pem, { mode: 0o644 });

  // Stage + commit. The commit message is intentionally specific so
  // future operators reviewing main can see what each trust-grant
  // accomplished without grepping the diff. We leave the commit
  // un-signed by stamp; the merge that lands this branch will be
  // stamp-signed via the normal flow.
  runGit(["add", keyFile], repoRoot);
  // Author info is already in the git commit metadata; no need to
  // duplicate it in the message body. Keep the message terse so the
  // diff is the headline: "add a trusted-keys file."
  runGit(
    [
      "commit",
      "-m",
      `Trust grant: add ${opts.shortName} to .stamp/trusted-keys/\n\n` +
        `Stages ${opts.shortName}'s stamp signing pubkey ` +
        `(fingerprint ${fingerprint}) so their stamp-signed merges into ` +
        `protected branches verify against this repo's trust set.\n\n` +
        `Source: stamp trust grant ${opts.shortName} (server ${server.host})`,
    ],
    repoRoot,
  );

  process.stdout.write(
    `✓ staged trust-grant for ${opts.shortName} on branch ${branch}\n` +
      `  trusted-keys file: ${keyFile}\n` +
      `  fingerprint:       ${fingerprint}\n` +
      `  started from:      ${startingBranch}\n\n` +
      `Next steps:\n` +
      `  stamp review --diff ${startingBranch}..${branch}\n` +
      `  git checkout ${startingBranch}\n` +
      `  stamp merge ${branch} --into ${startingBranch}\n` +
      `  stamp push ${startingBranch}\n`,
  );
}
