/**
 * Per-user stamp-server config. Tells `stamp provision` and any other
 * server-touching command where to find the operator's stamp server,
 * without baking SSH endpoints into per-repo files (which would force
 * every operator on a multi-operator project to share one server).
 *
 * Lives at ~/.stamp/server.yml. Format:
 *
 *   host: ssh.railway.app
 *   port: 12345
 *   user: git              # optional, default "git"
 *   repo_root_prefix: /srv/git  # optional, default "/srv/git"
 *
 * The `--server <host:port>` flag on `stamp provision` overrides the file.
 */

import { existsSync, readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { userServerConfigPath } from "./paths.js";

export interface ServerConfig {
  host: string;
  port: number;
  user: string;
  repoRootPrefix: string;
}

const DEFAULT_USER = "git";
const DEFAULT_REPO_ROOT = "/srv/git";

// Shape regexes for fields that get interpolated into ssh/scp argv as
// `${user}@${host}` (and into the bare-repo path via `${repoRootPrefix}`).
// The hostile shape we're defending against is anything starting with `-`
// and containing `=` — ssh's getopt re-parses such an arg as an option,
// most dangerously `-oProxyCommand=...` which invokes a shell command.
// All three regexes disallow leading `-`, embedded `=`, whitespace, and
// control characters; the `--`-before-destination guard at every ssh/scp
// call site is the belt-and-suspenders second layer for any future code
// path that bypasses these checks.
const USER_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]*$/;
// Hostnames must start AND end with alphanumeric, with internal `.` and
// `-` allowed. Single-char hostnames are accepted. Matches what
// parseServerFlag's `[^:]+` previously implied (no colons), now stricter:
// no leading `-`, no `=`, no whitespace, no control chars.
const HOST_RE = /^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$/;
// Repo-root prefix: absolute path, segments restricted to alnum/._- and
// each segment must start with a non-dot character so `..` traversal
// segments are structurally impossible. Trailing `/` is allowed for
// operator typing comfort.
const REPO_ROOT_RE = /^(\/[A-Za-z0-9_-][A-Za-z0-9._-]*)+\/?$/;

type Field = "user" | "host" | "repo_root_prefix";

function describeShape(field: Field): string {
  switch (field) {
    case "user":
      return "alphanumerics + . _ -, must not start with -";
    case "host":
      return "hostname-shaped (alphanumerics + . -, must start and end with alphanumeric)";
    case "repo_root_prefix":
      return "absolute path with alphanumeric/. _ - segments, no .. components";
  }
}

function validateField(field: Field, value: string, contextPath: string): void {
  const re =
    field === "user" ? USER_RE : field === "host" ? HOST_RE : REPO_ROOT_RE;
  if (!re.test(value)) {
    throw new Error(
      `${contextPath}: '${field}' has an invalid shape (got ${JSON.stringify(value)}). ` +
        `Allowed: ${describeShape(field)}.`,
    );
  }
}

/**
 * Load and validate ~/.stamp/server.yml. Returns null when the file doesn't
 * exist (so callers can fall back to a flag or print a friendly "set this
 * up first" hint). Throws on malformed content so a typo doesn't get
 * silently treated as "no config."
 */
export function loadServerConfig(): ServerConfig | null {
  const path = userServerConfigPath();
  if (!existsSync(path)) return null;
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    throw new Error(
      `failed to read ${path}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  return parseServerConfig(raw, path);
}

/**
 * Parse a YAML blob and validate it as a ServerConfig. Exposed separately
 * (rather than inlined into loadServerConfig) so tests can validate without
 * touching the filesystem. `--server <host>:<port>` flag parsing has its
 * own helper (parseServerFlag) because the wire format is different.
 */
export function parseServerConfig(
  raw: string,
  contextPath = "<inline>",
): ServerConfig {
  const parsed = parseYaml(raw) as unknown;
  if (!parsed || typeof parsed !== "object") {
    throw new Error(`${contextPath}: must be a YAML mapping with at least 'host' and 'port'`);
  }
  const obj = parsed as Record<string, unknown>;
  if (typeof obj.host !== "string" || !obj.host.trim()) {
    throw new Error(`${contextPath}: 'host' is required and must be a non-empty string`);
  }
  if (typeof obj.port !== "number" || !Number.isInteger(obj.port) || obj.port < 1 || obj.port > 65535) {
    throw new Error(`${contextPath}: 'port' is required and must be an integer 1..65535`);
  }
  const host = obj.host.trim();
  validateField("host", host, contextPath);
  const user =
    typeof obj.user === "string" && obj.user.trim() ? obj.user.trim() : DEFAULT_USER;
  validateField("user", user, contextPath);
  const repoRootPrefix =
    typeof obj.repo_root_prefix === "string" && obj.repo_root_prefix.trim()
      ? obj.repo_root_prefix.trim()
      : DEFAULT_REPO_ROOT;
  validateField("repo_root_prefix", repoRootPrefix, contextPath);
  return {
    host,
    port: obj.port,
    user,
    repoRootPrefix,
  };
}

/**
 * Parse a `<host:port>` value (used by `--server` and by `stamp server
 * config`) into a ServerConfig. Defaults for user / repo_root_prefix;
 * the operator can use the file-based config if they need to override
 * those. `context` controls the prefix on error messages so callers
 * can produce diagnostics that match the surface they're invoked from
 * (default "--server"; `stamp server config` passes its own).
 */
export function parseServerFlag(value: string, context = "--server"): ServerConfig {
  const m = value.trim().match(/^([^:]+):(\d+)$/);
  if (!m) {
    throw new Error(
      `${context} must be in the form <host>:<port> (got "${value}")`,
    );
  }
  const port = Number(m[2]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(
      `${context}: port must be an integer 1..65535 (got "${m[2]}")`,
    );
  }
  const host = m[1]!;
  validateField("host", host, context);
  return {
    host,
    port,
    user: DEFAULT_USER,
    repoRootPrefix: DEFAULT_REPO_ROOT,
  };
}

/**
 * Compose the SSH-style URL for a bare repo on this server, suitable for
 * `git clone` or `git remote add origin`. Matches the path layout
 * setup-repo.sh / new-stamp-repo create on the server side.
 */
export function bareRepoSshUrl(cfg: ServerConfig, repoName: string): string {
  return `ssh://${cfg.user}@${cfg.host}:${cfg.port}${cfg.repoRootPrefix}/${repoName}.git`;
}
