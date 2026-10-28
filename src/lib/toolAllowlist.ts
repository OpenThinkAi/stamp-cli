import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";

/**
 * Built-in allowlist of Claude Agent SDK tool names a reviewer may list in
 * `reviewers.<name>.tools` in `.stamp/config.yml`. The set is deliberately
 * tight — read-only investigation tools only.
 *
 * Adding a tool here is a code change, not a config change, so it is
 * reviewed and signed like any other diff. Operators who legitimately need
 * a riskier tool (Edit for codemod review, etc.) must vendor their own
 * stamp-cli build or contribute the addition with the threat model
 * spelled out.
 *
 * Excluded by design:
 *   - Edit / Write / NotebookEdit  (filesystem mutation in reviewer context)
 *   - Task                         (sub-agent spawn = recursive capability)
 *   - WebSearch                    (query strings can leak diff content)
 *
 * Bash is intentionally NOT in this list, but is reachable via a separate
 * per-reviewer opt-in: `reviewers.<name>.bash: true` (AGT-472). That field
 * gets folded into the reviewer-prompt hash chain via `hashTools`, so a
 * feature branch cannot silently widen a reviewer's capabilities — flipping
 * `bash: false → true` changes `tools_sha256` and is visible at
 * `stamp verify` time. The `bash` opt-in does not appear in `tools:` because
 * it has no per-call gating shape (no `allowed_hosts`-equivalent for shell);
 * it is a pure boolean capability switch.
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

/**
 * AGT-2270: `npx <pkg>` resolves the package from the registry at review
 * time. Without an exact `name@x.y.z` the reviewer host runs whatever the
 * registry serves that day, with the env vars the server is allowed, and
 * `mcp_sha256` (which hashes the args string) can't tell. Returns a warning
 * for an `npx` launch whose package spec is not an exact version, else
 * null. Not a hard refusal: existing configs keep working, and the warning
 * names the fix (pin the version, or install it and use
 * `node_modules/.bin/<name>`, which the lockfile pins).
 */
export function npxPinWarning(command: string, args: readonly string[] = []): string | null {
  if (command !== "npx") return null;
  const specs: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "-p" || a === "--package") {
      if (args[i + 1] !== undefined) specs.push(args[++i]!);
      continue;
    }
    if (a.startsWith("--package=")) {
      specs.push(a.slice("--package=".length));
      continue;
    }
    if (a.startsWith("-")) continue;
    // First positional is the package (or the bin, when --package named it).
    if (specs.length === 0) specs.push(a);
    break;
  }
  const unpinned = specs.filter((spec) => !EXACT_NPM_SPEC_RE.test(spec));
  if (specs.length > 0 && unpinned.length === 0) return null;
  const shown = unpinned[0] ?? "(no package)";
  return (
    `npx runs ${JSON.stringify(shown)} from the npm registry at review time without an exact ` +
    `version, so a later publish of that package runs on this machine unreviewed. Pin it ` +
    `(e.g. "${shown.replace(/@[^@/]*$/, "")}@1.2.3") or install it and use ` +
    `node_modules/.bin/<name>.`
  );
}

/** `name@1.2.3` or `@scope/name@1.2.3` (prerelease/build suffixes allowed). */
const EXACT_NPM_SPEC_RE = /^(?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*@\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/i;
