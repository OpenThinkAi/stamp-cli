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

import { existsSync, mkdirSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { stringify as stringifyYaml } from "yaml";
import { userServerConfigPath } from "../lib/paths.js";
import { loadServerConfig, parseServerFlag } from "../lib/serverConfig.js";
import { UsageError } from "./serverRepo.js";

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
