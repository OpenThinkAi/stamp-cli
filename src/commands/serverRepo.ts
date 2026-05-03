/**
 * `stamp server-repos <subcmd>` — manage bare repos on the stamp server.
 *
 * Wraps the server-side scripts (delete-stamp-repo, restore-stamp-repo,
 * list-trash) so the operator doesn't have to remember SSH endpoints or
 * server paths. Reads ~/.stamp/server.yml for the connection.
 *
 * Soft-delete semantics: deletion mv's the bare to /srv/git/.trash/...
 * by default. Recoverable via `stamp server-repos restore`. `--purge`
 * makes deletion irreversible.
 */

import { spawnSync } from "node:child_process";
import { createInterface } from "node:readline";
import {
  loadServerConfig,
  parseServerFlag,
  type ServerConfig,
} from "../lib/serverConfig.js";

export interface ServerRepoBaseOptions {
  /** Override ~/.stamp/server.yml with `<host>:<port>`. */
  server?: string;
}

export interface ServerRepoDeleteOptions extends ServerRepoBaseOptions {
  name: string;
  /** Hard delete (no recovery). Skips the trash entirely. */
  purge?: boolean;
  /** Also delete the GitHub mirror repo via `gh repo delete`. Asks for separate confirmation. */
  alsoGithub?: string; // <owner>/<repo>
  /** Skip the typed-confirmation prompt. Use only in non-interactive contexts. */
  yes?: boolean;
}

export interface ServerRepoRestoreOptions extends ServerRepoBaseOptions {
  name: string;
  /** Specific trash entry name (e.g. "20260427T193412Z-myproject.git"). Default: most recent. */
  from?: string;
  /** Restore under a different live name. Default: same as `name`. */
  asName?: string;
}

export async function runServerRepoDelete(opts: ServerRepoDeleteOptions): Promise<void> {
  // Validate inputs BEFORE resolving server config — so a bad name surfaces
  // as a UsageError (exit 2) regardless of whether the server is reachable.
  // normalizeRepoName strips a trailing `.git` so operators can pass either
  // `foo` or `foo.git` (the form `list` displayed before 0.7.7).
  const name = normalizeRepoName(opts.name);
  if (opts.alsoGithub !== undefined) validateGithubRepoSpec(opts.alsoGithub);
  const server = resolveServer(opts.server);

  const action = opts.purge ? "PURGE (irreversible)" : "soft-delete (recoverable via restore)";
  console.log(`About to ${action} bare repo: ${name}`);
  console.log(`On server: ${server.user}@${server.host}:${server.port}`);
  if (opts.alsoGithub) {
    console.log(
      `Also: gh repo delete ${opts.alsoGithub} (PERMANENT, no GitHub-side undo)`,
    );
  }
  console.log();

  if (!opts.yes) {
    const expected = opts.purge ? `purge ${name}` : `delete ${name}`;
    const got = await prompt(`Type "${expected}" to confirm: `);
    if (got.trim() !== expected) {
      console.log("note: aborted");
      return;
    }
  }

  // Server-side delete first. If GitHub deletion is requested, do it AFTER
  // the server side succeeds — failing in either order leaves a recoverable
  // state on at least one side.
  const args = ["delete-stamp-repo", name];
  if (opts.purge) args.push("--purge");
  // `--` before the destination terminates ssh's option processing —
  // belt-and-suspenders for the validation in serverConfig.ts.
  const result = spawnSync(
    "ssh",
    ["-p", String(server.port), "--", `${server.user}@${server.host}`, ...args],
    { stdio: ["ignore", "inherit", "inherit"] },
  );
  if (result.status !== 0) {
    throw new Error(
      `server-side delete failed (exit ${result.status}). The bare repo on the stamp server was NOT touched. ` +
        `If you see "command not found", the server image is older than 0.7.3 — redeploy it first.`,
    );
  }

  // Print stamp-verb-based recovery hints (the server-side script
  // intentionally doesn't, so operators see the right next-action via
  // the CLI they already invoked, not raw ssh syntax).
  if (!opts.purge) {
    console.log();
    console.log(`Recovery:`);
    console.log(`  stamp server-repos restore ${name}                 # bring it back`);
    console.log(`  stamp server-repos delete ${name} --purge          # nuke for real`);
  }

  if (opts.alsoGithub) {
    if (!opts.yes) {
      const expected = `delete github ${opts.alsoGithub}`;
      const got = await prompt(
        `Server-side done. To ALSO delete the GitHub mirror, type "${expected}" (or anything else to skip): `,
      );
      if (got.trim() !== expected) {
        console.log(
          `note: skipped GitHub delete; mirror at https://github.com/${opts.alsoGithub} is intact`,
        );
        return;
      }
    }
    const ghResult = spawnSync(
      "gh",
      ["repo", "delete", opts.alsoGithub, "--yes"],
      { stdio: ["ignore", "inherit", "inherit"] },
    );
    if (ghResult.status !== 0) {
      throw new Error(
        `GitHub repo delete failed (exit ${ghResult.status}). Server-side delete already succeeded; ` +
          `the GitHub mirror is still present at https://github.com/${opts.alsoGithub}.`,
      );
    }
  }
}

export async function runServerRepoRestore(opts: ServerRepoRestoreOptions): Promise<void> {
  // Validate inputs BEFORE resolving server config — so a bad name or
  // --from value surfaces as a UsageError (exit 2) regardless of whether
  // the server is reachable. normalizeRepoName strips a trailing `.git`
  // (operator-natural).
  const name = normalizeRepoName(opts.name);
  const asName = opts.asName !== undefined ? normalizeRepoName(opts.asName) : undefined;
  if (opts.from !== undefined) validateTrashEntryName(opts.from);
  const server = resolveServer(opts.server);

  const args = ["restore-stamp-repo", name];
  if (opts.from) {
    args.push("--from", opts.from);
  }
  if (asName) {
    args.push("--as", asName);
  }
  const result = spawnSync(
    "ssh",
    ["-p", String(server.port), "--", `${server.user}@${server.host}`, ...args],
    { stdio: ["ignore", "inherit", "inherit"] },
  );
  if (result.status !== 0) {
    throw new Error(
      `server-side restore failed (exit ${result.status}). ` +
        `Run \`stamp server-repos list --trash\` to see what's available.`,
    );
  }
}

export interface ServerRepoListOptions extends ServerRepoBaseOptions {
  /** When true, list soft-deleted (trashed) entries instead of live repos. */
  trash?: boolean;
}

export function runServerRepoList(opts: ServerRepoListOptions): void {
  const server = resolveServer(opts.server);
  if (opts.trash) {
    const result = spawnSync(
      "ssh",
      ["-p", String(server.port), "--", `${server.user}@${server.host}`, "list-trash"],
      { stdio: ["ignore", "inherit", "inherit"] },
    );
    if (result.status !== 0) {
      throw new Error(
        `list --trash failed (exit ${result.status}). If you see "command not found", ` +
          `the server image is older than 0.7.3 — redeploy it first.`,
      );
    }
    return;
  }
  // Live repos: reuse plain ls and filter out the on-volume metadata
  // directories that aren't bare repos. Cheap enough that a server-side
  // script for this trivial case isn't worth the round-trip.
  const result = spawnSync(
    "ssh",
    [
      "-p",
      String(server.port),
      "--",
      `${server.user}@${server.host}`,
      "ls",
      "-1",
      "/srv/git/",
    ],
    { stdio: ["ignore", "pipe", "inherit"], encoding: "utf8" },
  );
  if (result.status !== 0) {
    throw new Error(`list failed (exit ${result.status}).`);
  }
  const entries = filterLiveBareRepoNames(result.stdout);
  if (entries.length === 0) {
    console.log("(no live bare repos)");
    return;
  }
  for (const e of entries) console.log(e);
}

// ---------- helpers ----------

function resolveServer(serverFlag: string | undefined): ServerConfig {
  const server = serverFlag ? parseServerFlag(serverFlag) : loadServerConfig();
  if (!server) {
    throw new Error(
      `no stamp server configured. Either:\n` +
        `  - create ~/.stamp/server.yml with at least:\n` +
        `      host: <ssh-host>\n` +
        `      port: <ssh-port>\n` +
        `  - or pass --server <host>:<port> on the command line.`,
    );
  }
  return server;
}

/**
 * Thrown for invalid CLI input (bad name shape, malformed --from, etc.).
 * The action handlers in src/index.ts catch this and exit 2 (the
 * documented usage-error code) instead of 1 (runtime failure), so an
 * agent loop can distinguish "you passed bad args" from "the operation
 * failed mid-flight" without parsing stderr.
 */
export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UsageError";
  }
}

/**
 * Canonicalize a repo name: strip a trailing `.git` (operators copy-paste
 * the bare-repo dirname from `list` and don't realize it's the storage
 * suffix, not the canonical name) then validate the stripped form. Returns
 * the canonical name so callers can use one source of truth without
 * re-stripping. The server-side scripts always append `.git` themselves —
 * passing `<name>.git` produced `<name>.git.git` and a "does not exist"
 * error before this normalization landed.
 */
export function normalizeRepoName(name: string): string {
  const canonical = name.endsWith(".git") ? name.slice(0, -4) : name;
  validateRepoName(canonical);
  return canonical;
}

/**
 * Filter `ls -1 /srv/git/` output to the live bare repos and display them
 * without the `.git` suffix. Drops on-volume metadata (`.trash`,
 * `.ssh-host-keys`) and filesystem artifacts (`lost+found` on ext4
 * volumes). Displaying without `.git` matches the form operators pass
 * to `delete` / `restore` — copy-paste from the list output Just Works.
 */
export function filterLiveBareRepoNames(rawOutput: string): string[] {
  return rawOutput
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean)
    .filter((s) => s.endsWith(".git"))
    .map((s) => s.slice(0, -4))
    .filter((s) => s.length > 0);
}

function validateRepoName(name: string): void {
  // Same shape as stamp provision's validator, plus rejection of
  // consecutive dots so a name like `foo..bar` can't slip past the
  // client and then be rejected by the server-side scripts (which guard
  // against `..` for path-traversal reasons). Keeps both sides honest
  // with each other.
  if (!/^[A-Za-z0-9_][A-Za-z0-9._-]*$/.test(name) || name.includes("..")) {
    throw new UsageError(
      `repo name must start with [A-Za-z0-9_], match [A-Za-z0-9._-]+, and not contain '..' (got "${name}")`,
    );
  }
}

/**
 * --from must point at a trash-entry filename, never a path. Strict shape
 * check matches what the server emits when soft-deleting:
 * <YYYYMMDDTHHMMSSZ>-<name>.git. Without this, a value like
 * "../somerepo.git" would be forwarded to the server's restore script and
 * (until 0.7.3's server-side fix) could escape /srv/git/.trash/.
 */
function validateTrashEntryName(entry: string): void {
  if (!/^[0-9]{8}T[0-9]{6}Z-[A-Za-z0-9_][A-Za-z0-9._-]*\.git$/.test(entry)) {
    throw new UsageError(
      `--from must match <YYYYMMDDTHHMMSSZ>-<name>.git (got "${entry}"). ` +
        `Run \`stamp server-repos list --trash\` to see valid entry names.`,
    );
  }
}

/**
 * --also-github must shape-match `<owner>/<repo>` with no leading dash on
 * either segment (so `gh repo delete` doesn't parse the value as a flag).
 */
function validateGithubRepoSpec(spec: string): void {
  if (!/^[A-Za-z0-9_][A-Za-z0-9-]*\/[A-Za-z0-9_][A-Za-z0-9._-]*$/.test(spec)) {
    throw new UsageError(
      `--also-github must be <owner>/<repo> with no leading '-' on either segment (got "${spec}")`,
    );
  }
}

function prompt(question: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}
