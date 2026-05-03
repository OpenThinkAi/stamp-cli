import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";

/**
 * Built-in allowlist of Claude Agent SDK tool names a reviewer is permitted
 * to use. The set is deliberately tight — read-only investigation tools only.
 *
 * Adding a tool here is a code change, not a config change, so it is
 * reviewed and signed like any other diff. Operators who legitimately need
 * a riskier tool (Bash for compile checks, Edit for codemod review, etc.)
 * must vendor their own stamp-cli build or contribute the addition with
 * the threat model spelled out.
 *
 * Excluded by design:
 *   - Bash / Task            (arbitrary command execution)
 *   - Edit / Write / NotebookEdit  (filesystem mutation in reviewer context)
 *   - WebSearch              (query strings can leak diff content)
 */
export const SAFE_TOOLS = ["Read", "Grep", "Glob", "WebFetch"] as const;
export type SafeTool = (typeof SAFE_TOOLS)[number];

/**
 * Built-in allowlist of MCP launcher commands. The full attack surface here
 * is wider than the launcher (the args still control what runs), so this
 * allowlist is best read as "the launcher itself is not a shell-equivalent
 * primitive." A bare `sh -c '...'` is rejected; `npx -y some-mcp-package`
 * is allowed but the security reviewer is expected to scrutinize the
 * package name and any change to args.
 *
 * Operators can extend this set per-repo by listing additional commands in
 * `.stamp/mcp-allowlist.yml`:
 *   allowed_commands:
 *     - my-internal-mcp-binary
 *     - /opt/vendor/mcp-server
 * That file is reviewer-gated like other .stamp/ contents — adding a
 * command goes through the same merge gate as any other change.
 *
 * Anything matching `node_modules/.bin/<name>` (relative path) is allowed
 * unconditionally because it had to be installed via the project's
 * lockfile, which is itself supply-chain reviewed.
 */
export const SAFE_MCP_LAUNCHERS = [
  "npx",
  "node",
  "python",
  "python3",
  "bun",
  "deno",
] as const;

const NODE_BIN_PREFIX = `node_modules/.bin/`;

export interface McpAllowlistFile {
  allowed_commands?: string[];
}

/**
 * Read `.stamp/mcp-allowlist.yml` from the repo if present. Empty/missing
 * returns an empty allowlist — only built-in launchers + node_modules/.bin
 * commands work in that case.
 */
export function loadMcpAllowlist(repoRoot: string): string[] {
  const path = join(repoRoot, ".stamp", "mcp-allowlist.yml");
  if (!existsSync(path)) return [];
  const raw = readFileSync(path, "utf8");
  const parsed = parseYaml(raw) as unknown;
  if (!parsed || typeof parsed !== "object") return [];
  const obj = parsed as Record<string, unknown>;
  if (!Array.isArray(obj.allowed_commands)) return [];
  const out: string[] = [];
  for (const v of obj.allowed_commands) {
    if (typeof v === "string" && v.length > 0) out.push(v);
  }
  return out;
}

/**
 * Returns null if the command is allowed (built-in launcher, node_modules
 * binary, or in the per-repo allowlist), or a human-readable rejection
 * reason otherwise. Caller decides whether to throw or warn.
 */
export function checkMcpCommand(
  command: string,
  perRepoAllowlist: string[],
): string | null {
  if (!command) return "command is empty";

  // Reject any `..` segment up front, regardless of which downstream rule
  // would otherwise accept the command. Without this, a value like
  // `node_modules/.bin/../../bin/sh` satisfies the node_modules/.bin/
  // prefix check below and escapes to /bin/sh, bypassing the entire
  // allowlist. Per-repo allowlist entries that explicitly contain `..`
  // are also rejected — operators who need a path outside the repo
  // tree should add the resolved path to the allowlist instead.
  if (/(^|\/)\.\.($|\/)/.test(command)) {
    return `command "${command}" contains ".." path segments — not allowed`;
  }

  // Built-in launcher names (bare, no slash).
  if (
    !command.includes("/") &&
    (SAFE_MCP_LAUNCHERS as readonly string[]).includes(command)
  ) {
    return null;
  }

  // node_modules/.bin/<name> — installed via the project lockfile, so
  // already supply-chain reviewed. Match relative paths only
  // (`node_modules/.bin/foo` and `./node_modules/.bin/foo`); absolute
  // paths to a node_modules tree must be added to the per-repo allowlist
  // explicitly so they cannot reach across the filesystem.
  if (command.startsWith(NODE_BIN_PREFIX) || command.startsWith(`./${NODE_BIN_PREFIX}`)) {
    return null;
  }

  // Per-repo opt-in.
  if (perRepoAllowlist.includes(command)) return null;

  return (
    `command "${command}" is not in the built-in MCP launcher set ` +
    `(${SAFE_MCP_LAUNCHERS.join(", ")}), is not under node_modules/.bin/, ` +
    `and is not listed in .stamp/mcp-allowlist.yml. Add it to the per-repo ` +
    `allowlist if it is intentional, or pick one of the safe launchers.`
  );
}
