/**
 * `stamp server config` — manage the per-operator stamp server config
 * at ~/.stamp/server.yml without making the operator hand-edit YAML.
 *
 * Three modes, mutually exclusive:
 *
 *   stamp server config <host:port>            write/overwrite the file
 *   stamp server config --show                 print the resolved config
 *   stamp server config --unset                remove the file
 *
 * `<host:port>` reuses parseServerFlag (same parser as `--server`) so
 * the wire format and validation are a single source of truth. `--user`
 * and `--repo-root-prefix` only apply when writing; they let the
 * operator override the defaults (git / /srv/git) when their server
 * image was set up differently.
 *
 * The file is written 0o600 under a 0o700 ~/.stamp dir — same posture
 * the keys/ directory uses. Atomic write via temp + rename so a crash
 * mid-write doesn't leave a half-written config that fails to parse.
 */

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { stringify as stringifyYaml } from "yaml";
import { userServerConfigPath } from "../lib/paths.js";
import { computePerRepoKeyPath } from "../lib/perRepoKey.js";
import {
  loadServerConfig,
  parseServerFlag,
  type ServerConfig,
} from "../lib/serverConfig.js";
import { resolveServer, UsageError } from "./serverRepo.js";

export interface ServerConfigOptions {
  hostPort?: string;
  show?: boolean;
  unset?: boolean;
  user?: string;
  repoRootPrefix?: string;
}

/**
 * Build the YAML body for ~/.stamp/server.yml from validated inputs.
 * Pure function so tests can pin the exact on-disk shape without
 * touching the filesystem.
 */
export function formatServerConfigYaml(opts: {
  host: string;
  port: number;
  user?: string;
  repoRootPrefix?: string;
}): string {
  const body: Record<string, unknown> = {
    host: opts.host,
    port: opts.port,
  };
  if (opts.user && opts.user.trim()) body.user = opts.user.trim();
  if (opts.repoRootPrefix && opts.repoRootPrefix.trim()) {
    body.repo_root_prefix = opts.repoRootPrefix.trim();
  }
  return stringifyYaml(body);
}

export function runServerConfig(opts: ServerConfigOptions): void {
  const modes = [opts.hostPort, opts.show, opts.unset].filter(Boolean).length;
  if (modes !== 1) {
    throw new UsageError(
      "stamp server config: provide exactly one of <host:port>, --show, or --unset",
    );
  }
  if ((opts.show || opts.unset) && (opts.user || opts.repoRootPrefix)) {
    throw new UsageError(
      "stamp server config: --user and --repo-root-prefix only apply when writing (they conflict with --show / --unset)",
    );
  }
  if (opts.show) return showConfig();
  if (opts.unset) return unsetConfig();
  return writeConfig(opts);
}

function showConfig(): void {
  const path = userServerConfigPath();
  if (!existsSync(path)) {
    console.log(`note: no stamp server configured (${path} does not exist)`);
    console.log(`note: run \`stamp server config <host:port>\` to create one`);
    return;
  }
  const cfg = loadServerConfig();
  if (!cfg) {
    console.log(`note: no stamp server configured`);
    return;
  }
  console.log(`config:           ${path}`);
  console.log(`host:             ${cfg.host}`);
  console.log(`port:             ${cfg.port}`);
  console.log(`user:             ${cfg.user}`);
  console.log(`repo_root_prefix: ${cfg.repoRootPrefix}`);
}

function unsetConfig(): void {
  const path = userServerConfigPath();
  if (!existsSync(path)) {
    console.log(`note: ${path} does not exist; nothing to remove`);
    return;
  }
  unlinkSync(path);
  console.log(`removed ${path}`);
}

/**
 * `stamp server pubkey` — fetch the public half of the stamp server's
 * GitHub mirror-push deploy key. Run over SSH against the configured
 * server (~/.stamp/server.yml or `--server <host:port>`).
 *
 * Output is exactly the public-key line emitted by the server-side
 * `stamp-server-pubkey` wrapper — single OpenSSH-format line, no
 * decoration. That makes it pipe-able directly into deploy-key
 * registration (`gh api -X POST /repos/:o/:r/keys --field key=@-`) and
 * lets `stamp provision` reuse fetchServerPubkey() to register the key
 * itself.
 */
export interface ServerPubkeyOptions {
  /** Override ~/.stamp/server.yml with `<host>:<port>`. */
  server?: string;
}

/**
 * Programmatic counterpart to `stamp server pubkey`. Returns the
 * server's mirror-push public-key line (no surrounding whitespace).
 * Throws with an actionable message if the SSH call fails — most
 * commonly because the server image predates the deploy-key feature
 * and `stamp-server-pubkey` isn't on PATH there yet.
 *
 * Two modes:
 *
 *   - `mirror` omitted: fetch the LEGACY shared deploy key. Kept for
 *     back-compat. The server-side wrapper returns the same file the
 *     pre-per-repo-keys design used.
 *
 *   - `mirror` provided: fetch a per-repo key for the named GitHub
 *     mirror. The server's stamp-server-pubkey wrapper will lazily
 *     generate the key on first request (via sudo + stamp-ensure-repo-
 *     key) so the operator never has to ssh in by hand. The returned
 *     pubkey is what to register on `mirror.owner/mirror.repo` as a
 *     deploy key.
 *
 * The trim() is important: the on-the-wire output is "<line>\n" and
 * `gh api --field key=...` would silently encode the trailing newline
 * as part of the key body.
 */
export function fetchServerPubkey(
  server: ServerConfig,
  mirror?: { owner: string; repo: string },
): string {
  // `--` after `-p N` terminates ssh's option processing before the
  // destination — matches the pattern in serverRepo.ts wrappers (defense
  // against a malformed server.yml smuggling a flag-shaped host string).
  //
  // When `mirror` is set, pass <owner>/<repo> as the wrapper's single
  // positional argument. The server-side wrapper validates the shape;
  // we still avoid passing anything shaped like a flag here so a
  // malformed mirror config can't smuggle an option into the ssh
  // command line via remote-command argv.
  const sshArgs = [
    "-p",
    String(server.port),
    "--",
    `${server.user}@${server.host}`,
    "stamp-server-pubkey",
  ];
  if (mirror) {
    sshArgs.push(`${mirror.owner}/${mirror.repo}`);
  }
  const result = spawnSync("ssh", sshArgs, {
    stdio: ["ignore", "pipe", "inherit"],
    encoding: "utf8",
  });
  if (result.status !== 0) {
    const target = mirror ? ` for ${mirror.owner}/${mirror.repo}` : "";
    throw new Error(
      `stamp server pubkey${target} failed (exit ${result.status}) against ` +
        `${server.user}@${server.host}:${server.port}. If you see ` +
        `"command not found", the server image predates the deploy-key ` +
        `feature — redeploy it first.`,
    );
  }
  return result.stdout.trim();
}

export interface ServerPubkeyCliOptions extends ServerPubkeyOptions {
  /**
   * Optional `<owner>/<repo>` to fetch a per-repo key. When unset,
   * fetches the legacy shared key (back-compat).
   */
  repo?: string;
}

export function runServerPubkey(opts: ServerPubkeyCliOptions): void {
  const server = resolveServer(opts.server);
  let mirror: { owner: string; repo: string } | undefined;
  if (opts.repo) {
    // Reuse the canonical spec validator from perRepoKey rather than
    // re-implementing a looser subset here — single source of truth for
    // the shape contract, and the operator gets the same charset/`..`/
    // leading-`-` rejection messages they'd get from any other code
    // path. Re-throwing as UsageError surfaces it at the CLI exit-code
    // layer rather than as an internal error.
    try {
      computePerRepoKeyPath(opts.repo);
    } catch (err) {
      throw new UsageError(
        `--repo ${err instanceof Error ? err.message.replace(/^computePerRepoKeyPath:\s*/, "") : String(err)}`,
      );
    }
    const slashIdx = opts.repo.indexOf("/");
    mirror = {
      owner: opts.repo.slice(0, slashIdx),
      repo: opts.repo.slice(slashIdx + 1),
    };
  }
  const pubkey = fetchServerPubkey(server, mirror);
  // Preserve the trailing newline on the CLI surface so the output is
  // pipe-safe (`stamp server pubkey | tee ~/.ssh/stamp_mirror.pub`).
  process.stdout.write(`${pubkey}\n`);
}

function writeConfig(opts: ServerConfigOptions): void {
  let parsed;
  try {
    parsed = parseServerFlag(opts.hostPort!, "stamp server config: <host:port>");
  } catch (err) {
    throw new UsageError(err instanceof Error ? err.message : String(err));
  }
  const yaml = formatServerConfigYaml({
    host: parsed.host,
    port: parsed.port,
    user: opts.user,
    repoRootPrefix: opts.repoRootPrefix,
  });

  const path = userServerConfigPath();
  const dir = dirname(path);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });

  const tmp = `${path}.tmp.${process.pid}`;
  writeFileSync(tmp, yaml, { mode: 0o600 });
  renameSync(tmp, path);

  console.log(`wrote ${path}`);
  console.log(`host:             ${parsed.host}`);
  console.log(`port:             ${parsed.port}`);
  if (opts.user && opts.user.trim()) {
    console.log(`user:             ${opts.user.trim()}`);
  }
  if (opts.repoRootPrefix && opts.repoRootPrefix.trim()) {
    console.log(`repo_root_prefix: ${opts.repoRootPrefix.trim()}`);
  }
}
