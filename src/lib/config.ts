import { readFileSync } from "node:fs";
import { parse, stringify } from "yaml";
import { globToRegex, isGlobPattern } from "./refPatterns.js";
import { SAFE_TOOLS } from "./toolAllowlist.js";

export interface CheckDef {
  /** Short name used in config and attestation payloads — e.g. "build", "test" */
  name: string;
  /** Shell command to run; non-zero exit blocks merge */
  run: string;
}

export interface BranchRule {
  required: string[];
  /** Optional pre-merge check commands; all must pass before merge is signed */
  required_checks?: CheckDef[];
  /**
   * When undefined or true, `stamp merge` requires explicit operator
   * confirmation (interactive y/N prompt, --yes flag, or
   * STAMP_REQUIRE_HUMAN_MERGE=0 env var) before signing. When false, merges
   * proceed unattended. Closes audit H1 (LLM-verdict-→-signed-merge
   * residual risk) by making operator awareness the default — the value
   * lives in committed config so changing it itself goes through stamp
   * review.
   */
  require_human_merge?: boolean;
}

/**
 * A single entry in a reviewer's `tools:` list. Either:
 *   - a bare string for a tool that has no per-tool config (Read, Grep, Glob)
 *   - an object form `{ name, allowed_hosts?, path_prefix? }` for tools that
 *     need per-call gating. WebFetch REQUIRES the object form with a non-empty
 *     `allowed_hosts` array — a bare `"WebFetch"` is rejected at invocation
 *     time because an unrestricted WebFetch is an exfiltration channel for
 *     diff content (a malicious diff plants a URL, the reviewer follows it,
 *     the diff context flows out).
 *
 *     `allowed_hosts` is a *domain-level* allowlist. To pin the URL shape
 *     too — e.g. only `/repos/` paths on `api.github.com` — set
 *     `path_prefix` on the same entry. When present, the runtime hook
 *     rejects any URL whose `URL.pathname` does not begin with that prefix.
 *     Query strings are never inspected (GitHub/Linear/Notion APIs use them
 *     legitimately). AGT-036 / audit M4.
 */
export type ToolSpec =
  | string
  | { name: string; allowed_hosts?: string[]; path_prefix?: string };

/**
 * Loose, policy-free ToolSpec parser used wherever the SAFE_TOOLS policy
 * doesn't apply (hash verification path, network-fetched config). Accepts
 * both string shorthand and object form `{ name, allowed_hosts? }` and
 * filters out structurally-invalid entries silently — callers that need
 * strict validation use `parseTools` (config-load path) instead. Single
 * implementation shared by reviewerHash + reviewers-fetch so the two paths
 * cannot drift on schema additions.
 */
export function parseToolsLoose(input: unknown[]): ToolSpec[] {
  const out: ToolSpec[] = [];
  for (const entry of input) {
    if (typeof entry === "string") {
      if (entry) out.push(entry);
      continue;
    }
    if (entry && typeof entry === "object" && !Array.isArray(entry)) {
      const e = entry as Record<string, unknown>;
      if (typeof e.name !== "string" || !e.name) continue;
      const spec: {
        name: string;
        allowed_hosts?: string[];
        path_prefix?: string;
      } = { name: e.name };
      if (Array.isArray(e.allowed_hosts)) {
        const hosts = e.allowed_hosts.filter(
          (h): h is string => typeof h === "string" && h.length > 0,
        );
        if (hosts.length > 0) spec.allowed_hosts = hosts;
      }
      // Mirror the strict parser: only carry path_prefix when it's a
      // non-empty string starting with "/". Anything else is treated as
      // absent so the loose-parsed canonical form stays hash-equivalent
      // with what the strict parser would have accepted.
      if (
        typeof e.path_prefix === "string" &&
        e.path_prefix.length > 0 &&
        e.path_prefix.startsWith("/")
      ) {
        spec.path_prefix = e.path_prefix;
      }
      out.push(spec);
    }
  }
  return out;
}

export interface ReviewerDef {
  prompt: string;
  /**
   * Claude Agent SDK built-in tools the reviewer may call during review.
   * The set of permitted tool names is constrained at invocation time to
   * the SAFE_TOOLS list in lib/toolAllowlist.ts (read-only investigation
   * tools only — Bash / Edit / Write / Task are disallowed).
   *
   * Object form (e.g. `{ name: "WebFetch", allowed_hosts: ["linear.app"] }`)
   * is required for tools that need per-call gating. Plain strings remain
   * supported for tools without per-tool config.
   *
   * Absent or empty → reviewer runs with zero tools (safe default).
   */
  tools?: ToolSpec[];
  /**
   * MCP servers to expose to the reviewer agent. Keys are server names used
   * in the reviewer prompt (e.g. "linear"); values are stdio server configs.
   * Env values may reference shell env vars via $VAR or ${VAR} — resolved at
   * invocation time, gated by an allowlist (operator env
   * `STAMP_REVIEWER_ENV_ALLOWLIST` and/or per-server `allowed_env`); unset
   * or non-allowlisted names cause `stamp review` to fail fast.
   */
  mcp_servers?: Record<string, McpServerDef>;
  /**
   * When true, this reviewer cannot return `approved` for a diff that
   * touches `.stamp/` paths unless its agent has called `Read` on every
   * modified `.stamp/*` file during the review. Verdict-↔-trace
   * consistency check: prevents a prompt-injected reviewer from waving
   * through a change to its own trust anchors (config.yml, reviewer
   * prompts, trusted-keys/) without inspecting the diff.
   *
   * Defaults to false (back-compat). Recommended on for whichever
   * reviewer is responsible for trust-anchor scrutiny — typically the
   * `security` persona, but the field is reviewer-name-agnostic so
   * operators with custom reviewer sets can opt their own in. Audit-H1
   * defense-in-depth alongside the default-on operator confirmation
   * gate.
   */
  enforce_reads_on_dotstamp?: boolean;
}

export interface McpServerDef {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  /**
   * Per-server opt-in allowlist of operator env-var names that this server's
   * `env:` `$VAR` / `${VAR}` references may resolve. Optional; the operator
   * env `STAMP_REVIEWER_ENV_ALLOWLIST` is the other allowlist source. A
   * `$VAR` reference resolves iff `VAR` appears in the union of these two
   * sources AND is set in `process.env`. Names must be POSIX identifiers
   * (`[A-Za-z_][A-Za-z0-9_]*`) and are validated at config-load time.
   */
  allowed_env?: string[];
}

/**
 * POSIX env-var identifier shape. Used to validate `allowed_env` entries at
 * config-load time (strict — config bytes are committed and re-hashed by
 * verifiers, a typo there is a bug worth surfacing) and to filter the
 * comma-separated `STAMP_REVIEWER_ENV_ALLOWLIST` values at invocation time
 * (lenient — silently drop malformed names rather than block a review on
 * a harness-injected garbage env string).
 */
export const ENV_IDENTIFIER_REGEX = /^[A-Za-z_][A-Za-z0-9_]*$/;

export interface StampConfig {
  branches: Record<string, BranchRule>;
  reviewers: Record<string, ReviewerDef>;
}

export function loadConfig(path: string): StampConfig {
  return parseConfigFromYaml(readFileSync(path, "utf8"));
}

/**
 * Parse a .stamp/config.yml text blob into a validated StampConfig.
 * Delegated from loadConfig and also used by verify-at-sha paths that
 * source the YAML via `git show <sha>:.stamp/config.yml`. Single parser
 * keeps the verifier and the working-tree loader in sync — if one grows
 * a new field, both paths see it.
 */
export function parseConfigFromYaml(raw: string): StampConfig {
  const parsed = parse(raw) as unknown;
  return validateConfig(parsed);
}

function validateConfig(input: unknown): StampConfig {
  if (!input || typeof input !== "object") {
    throw new Error("config must be an object");
  }
  const obj = input as Record<string, unknown>;

  const branches: Record<string, BranchRule> = {};
  const rawBranches = obj.branches;
  if (!rawBranches || typeof rawBranches !== "object") {
    throw new Error("config.branches must be an object");
  }
  for (const [name, rule] of Object.entries(rawBranches)) {
    if (!rule || typeof rule !== "object") {
      throw new Error(`config.branches.${name} must be an object`);
    }
    const r = rule as Record<string, unknown>;
    if (!Array.isArray(r.required)) {
      throw new Error(`config.branches.${name}.required must be an array`);
    }

    const required_checks = parseChecks(r.required_checks, name);

    let require_human_merge: boolean | undefined;
    if (r.require_human_merge !== undefined) {
      if (typeof r.require_human_merge !== "boolean") {
        throw new Error(
          `config.branches.${name}.require_human_merge must be a boolean`,
        );
      }
      require_human_merge = r.require_human_merge;
    }

    branches[name] = {
      required: r.required.map(String),
      ...(required_checks ? { required_checks } : {}),
      ...(require_human_merge !== undefined ? { require_human_merge } : {}),
    };
  }

  const reviewers: Record<string, ReviewerDef> = {};
  const rawReviewers = obj.reviewers;
  if (!rawReviewers || typeof rawReviewers !== "object") {
    throw new Error("config.reviewers must be an object");
  }
  for (const [name, def] of Object.entries(rawReviewers)) {
    if (!def || typeof def !== "object") {
      throw new Error(`config.reviewers.${name} must be an object`);
    }
    const d = def as Record<string, unknown>;
    if (typeof d.prompt !== "string") {
      throw new Error(`config.reviewers.${name}.prompt must be a string`);
    }
    const tools = parseTools(d.tools, name);
    const mcp_servers = parseMcpServers(d.mcp_servers, name);

    let enforce_reads_on_dotstamp: boolean | undefined;
    if (d.enforce_reads_on_dotstamp !== undefined) {
      if (typeof d.enforce_reads_on_dotstamp !== "boolean") {
        throw new Error(
          `config.reviewers.${name}.enforce_reads_on_dotstamp must be a boolean`,
        );
      }
      enforce_reads_on_dotstamp = d.enforce_reads_on_dotstamp;
    }

    reviewers[name] = {
      prompt: d.prompt,
      ...(tools ? { tools } : {}),
      ...(mcp_servers ? { mcp_servers } : {}),
      ...(enforce_reads_on_dotstamp !== undefined
        ? { enforce_reads_on_dotstamp }
        : {}),
    };
  }

  return { branches, reviewers };
}

function parseChecks(input: unknown, branchName: string): CheckDef[] | undefined {
  if (input === undefined || input === null) return undefined;
  if (!Array.isArray(input)) {
    throw new Error(
      `config.branches.${branchName}.required_checks must be an array`,
    );
  }
  const out: CheckDef[] = [];
  for (const entry of input) {
    if (!entry || typeof entry !== "object") {
      throw new Error(
        `config.branches.${branchName}.required_checks entries must be objects`,
      );
    }
    const e = entry as Record<string, unknown>;
    if (typeof e.name !== "string" || !e.name) {
      throw new Error(
        `config.branches.${branchName}.required_checks[].name must be a non-empty string`,
      );
    }
    if (typeof e.run !== "string" || !e.run) {
      throw new Error(
        `config.branches.${branchName}.required_checks[].run must be a non-empty string`,
      );
    }
    out.push({ name: e.name, run: e.run });
  }
  return out;
}

function parseTools(input: unknown, reviewerName: string): ToolSpec[] | undefined {
  if (input === undefined || input === null) return undefined;
  if (!Array.isArray(input)) {
    throw new Error(
      `config.reviewers.${reviewerName}.tools must be an array`,
    );
  }
  const safeSet = new Set<string>(SAFE_TOOLS);
  const out: ToolSpec[] = [];
  for (let i = 0; i < input.length; i++) {
    const entry = input[i];

    // String form: shorthand for tools without per-tool config.
    if (typeof entry === "string") {
      if (!entry) {
        throw new Error(
          `config.reviewers.${reviewerName}.tools[${i}] is an empty string`,
        );
      }
      if (!safeSet.has(entry)) {
        throw new Error(
          `config.reviewers.${reviewerName}.tools[${i}] = "${entry}" is not in the SAFE_TOOLS set ` +
            `(${SAFE_TOOLS.join(", ")}). Adding a new tool requires a code change to ` +
            `src/lib/toolAllowlist.ts so the addition is reviewed and signed.`,
        );
      }
      if (entry === "WebFetch") {
        throw new Error(
          `config.reviewers.${reviewerName}.tools[${i}] = "WebFetch" must use the object form ` +
            `with a non-empty allowed_hosts list, e.g. { name: "WebFetch", allowed_hosts: ["linear.app"] }. ` +
            `An unrestricted WebFetch lets a malicious diff plant a URL the reviewer will follow, ` +
            `exfiltrating diff context to attacker-chosen destinations.`,
        );
      }
      out.push(entry);
      continue;
    }

    // Object form: required for tools with per-call gating (currently WebFetch).
    if (entry && typeof entry === "object" && !Array.isArray(entry)) {
      const e = entry as Record<string, unknown>;
      if (typeof e.name !== "string" || !e.name) {
        throw new Error(
          `config.reviewers.${reviewerName}.tools[${i}].name must be a non-empty string`,
        );
      }
      if (!safeSet.has(e.name)) {
        throw new Error(
          `config.reviewers.${reviewerName}.tools[${i}].name = "${e.name}" is not in the SAFE_TOOLS set ` +
            `(${SAFE_TOOLS.join(", ")}). Adding a new tool requires a code change to ` +
            `src/lib/toolAllowlist.ts so the addition is reviewed and signed.`,
        );
      }
      // allowed_hosts is meaningful only for tools with per-call host gating
      // (currently just WebFetch). Reject it on other tools rather than
      // silently accepting — silently-accepted-but-ignored fields drift
      // into hash divergence between the strict and loose parsers and
      // confuse operators about which fields actually do something.
      if (e.allowed_hosts !== undefined && e.name !== "WebFetch") {
        throw new Error(
          `config.reviewers.${reviewerName}.tools[${i}].allowed_hosts is only valid on WebFetch ` +
            `(got name="${e.name}"). Remove the field or change the entry to use WebFetch.`,
        );
      }
      if (e.path_prefix !== undefined && e.name !== "WebFetch") {
        throw new Error(
          `config.reviewers.${reviewerName}.tools[${i}].path_prefix is only valid on WebFetch ` +
            `(got name="${e.name}"). Remove the field or change the entry to use WebFetch.`,
        );
      }
      const spec: {
        name: string;
        allowed_hosts?: string[];
        path_prefix?: string;
      } = { name: e.name };
      if (e.allowed_hosts !== undefined) {
        if (!Array.isArray(e.allowed_hosts)) {
          throw new Error(
            `config.reviewers.${reviewerName}.tools[${i}].allowed_hosts must be an array of strings`,
          );
        }
        const hosts: string[] = [];
        for (const h of e.allowed_hosts) {
          if (typeof h !== "string" || !h) {
            throw new Error(
              `config.reviewers.${reviewerName}.tools[${i}].allowed_hosts entries must be non-empty strings`,
            );
          }
          hosts.push(h);
        }
        // Match parseToolsLoose's canonical form: drop the property entirely
        // when the array is empty so both parsers produce hash-equivalent
        // output. The next check then fires the "WebFetch requires non-empty"
        // rule consistently for both string and object input shapes.
        if (hosts.length > 0) spec.allowed_hosts = hosts;
      }
      // path_prefix is opt-in. When present it must be a non-empty string
      // starting with "/" so the runtime check (`URL.pathname.startsWith(p)`)
      // is meaningful — a relative or empty value would either match
      // nothing or match everything, neither of which the operator would
      // expect from the YAML. AGT-036 / audit M4.
      if (e.path_prefix !== undefined) {
        if (typeof e.path_prefix !== "string") {
          throw new Error(
            `config.reviewers.${reviewerName}.tools[${i}].path_prefix must be a string`,
          );
        }
        if (e.path_prefix.length === 0) {
          throw new Error(
            `config.reviewers.${reviewerName}.tools[${i}].path_prefix must be non-empty`,
          );
        }
        if (!e.path_prefix.startsWith("/")) {
          throw new Error(
            `config.reviewers.${reviewerName}.tools[${i}].path_prefix must start with "/" ` +
              `(got "${e.path_prefix}"). Use the full URL path prefix, e.g. "/repos/" or "/api/".`,
          );
        }
        spec.path_prefix = e.path_prefix;
      }
      // WebFetch requires non-empty allowed_hosts (the bare-string and
      // empty-array paths both fail here). The runtime PreToolUse hook
      // assumes allowed_hosts is present and non-empty for any WebFetch
      // entry that reaches it.
      if (e.name === "WebFetch" && !spec.allowed_hosts) {
        throw new Error(
          `config.reviewers.${reviewerName}.tools[${i}] WebFetch requires a non-empty allowed_hosts list. ` +
            `In YAML block form:\n` +
            `    - name: WebFetch\n` +
            `      allowed_hosts: [linear.app, github.com]\n` +
            `Everything not in this list is denied at the SDK boundary via canUseTool.`,
        );
      }
      out.push(spec);
      continue;
    }
    throw new Error(
      `config.reviewers.${reviewerName}.tools[${i}] must be a tool name string or { name, allowed_hosts? } object`,
    );
  }
  return out;
}

function parseMcpServers(
  input: unknown,
  reviewerName: string,
): Record<string, McpServerDef> | undefined {
  if (input === undefined || input === null) return undefined;
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error(
      `config.reviewers.${reviewerName}.mcp_servers must be a map of server name → config`,
    );
  }
  const out: Record<string, McpServerDef> = {};
  for (const [serverName, raw] of Object.entries(input)) {
    if (!raw || typeof raw !== "object") {
      throw new Error(
        `config.reviewers.${reviewerName}.mcp_servers.${serverName} must be an object`,
      );
    }
    const r = raw as Record<string, unknown>;
    if (typeof r.command !== "string" || !r.command) {
      throw new Error(
        `config.reviewers.${reviewerName}.mcp_servers.${serverName}.command must be a non-empty string`,
      );
    }
    const args = r.args === undefined ? undefined : parseStringArray(
      r.args,
      `config.reviewers.${reviewerName}.mcp_servers.${serverName}.args`,
    );
    const env = r.env === undefined ? undefined : parseStringMap(
      r.env,
      `config.reviewers.${reviewerName}.mcp_servers.${serverName}.env`,
    );
    const allowed_env = r.allowed_env === undefined ? undefined : parseEnvIdentifierArray(
      r.allowed_env,
      `config.reviewers.${reviewerName}.mcp_servers.${serverName}.allowed_env`,
    );
    out[serverName] = {
      command: r.command,
      ...(args ? { args } : {}),
      ...(env ? { env } : {}),
      ...(allowed_env ? { allowed_env } : {}),
    };
  }
  return out;
}

/**
 * Parse `allowed_env` entries: array of POSIX env-var identifier strings.
 * Strict at config-load time — the bytes are committed and the hash flows
 * into `mcp_sha256` attestation, so a typo or invalid identifier here is a
 * config bug that should surface before the first review, not silently get
 * dropped (which is what `parseEnvAllowlist` does for the operator env var).
 *
 * Exported so the persona-fetch path in `commands/reviewers.ts` (which
 * builds its YAML-path prefixes from `${source}@${ref}`) reuses the same
 * regex + wording — single source of truth for the validator.
 */
export function parseEnvIdentifierArray(input: unknown, path: string): string[] {
  if (!Array.isArray(input)) {
    throw new Error(`${path} must be an array of POSIX env-var identifier strings`);
  }
  return input.map((v, i) => {
    if (typeof v !== "string") {
      throw new Error(`${path}[${i}] must be a string`);
    }
    if (!ENV_IDENTIFIER_REGEX.test(v)) {
      throw new Error(
        `${path}[${i}] "${v}" is not a valid POSIX env-var identifier ` +
          `(must match [A-Za-z_][A-Za-z0-9_]*)`,
      );
    }
    return v;
  });
}

function parseStringArray(input: unknown, path: string): string[] {
  if (!Array.isArray(input)) {
    throw new Error(`${path} must be an array of strings`);
  }
  return input.map((v, i) => {
    if (typeof v !== "string") {
      throw new Error(`${path}[${i}] must be a string`);
    }
    return v;
  });
}

function parseStringMap(input: unknown, path: string): Record<string, string> {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error(`${path} must be a map of string → string`);
  }
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(input)) {
    if (typeof v !== "string") {
      throw new Error(`${path}.${k} must be a string`);
    }
    out[k] = v;
  }
  return out;
}

export function stringifyConfig(config: StampConfig): string {
  return stringify(config);
}

/**
 * Resolve the branch rule for a literal branch name. Map keys may be
 * literal branch names OR glob patterns (`*`, `?` — same grammar as
 * mirror.yml's `tags:` field; see refPatterns.ts).
 *
 * Resolution rule, exact-first then glob:
 *   1. If a key matches `branchName` literally, that rule wins. Exact
 *      keys without metacharacters never participate in glob matching.
 *   2. Otherwise, scan keys that contain `*` or `?` and test each as a
 *      glob. If exactly one matches, return it. If multiple match, throw
 *      with the conflicting keys named so the operator can disambiguate.
 *   3. If nothing matches, return undefined.
 *
 * The undefined return mirrors the prior `branches[name]` behavior so
 * callers that treat "no rule = unprotected" still work. Callers that
 * require a rule should keep their existing throw with the same wording.
 */
export function findBranchRule(
  branches: Record<string, BranchRule>,
  branchName: string,
): BranchRule | undefined {
  const exact = branches[branchName];
  if (exact !== undefined) return exact;

  const matchingKeys: string[] = [];
  for (const key of Object.keys(branches)) {
    if (!isGlobPattern(key)) continue;
    if (globToRegex(key).test(branchName)) matchingKeys.push(key);
  }
  if (matchingKeys.length === 0) return undefined;
  if (matchingKeys.length > 1) {
    throw new Error(
      `branch "${branchName}" matches multiple glob patterns in .stamp/config.yml: ${matchingKeys.map((k) => `"${k}"`).join(", ")}. ` +
        `Tighten the patterns or add an exact-match key for "${branchName}".`,
    );
  }
  return branches[matchingKeys[0]!];
}

/**
 * Default config scaffolded by `stamp init` (three-persona mode).
 * Main requires all three shipped reviewers. No required_checks by default —
 * users add their own per project (e.g. `npm run build`).
 */
export const DEFAULT_CONFIG: StampConfig = {
  branches: {
    main: {
      required: ["security", "standards", "product"],
    },
  },
  reviewers: {
    security: { prompt: ".stamp/reviewers/security.md" },
    standards: { prompt: ".stamp/reviewers/standards.md" },
    product: { prompt: ".stamp/reviewers/product.md" },
  },
};

/**
 * Fallback config scaffolded by `stamp init --minimal`. One placeholder
 * reviewer, for users who want to start from scratch rather than customize
 * shipped defaults.
 */
export const MINIMAL_CONFIG: StampConfig = {
  branches: {
    main: { required: ["example"] },
  },
  reviewers: {
    example: { prompt: ".stamp/reviewers/example.md" },
  },
};

export const EXAMPLE_REVIEWER_PROMPT = `# example reviewer (bootstrap only — auto-approves everything)

> **WARNING — DO NOT use this reviewer for real code review.** It is a
> deterministic auto-approver intended only to land your *real* reviewers
> via the \`stamp bootstrap\` flow (or the manual placeholder→real swap
> documented in \`docs/troubleshooting.md\`). Once your real reviewers are
> in place, remove this one (or leave it defined-but-unrequired forever).
>
> If you reached this prompt via \`stamp init --minimal\`, **replace the
> entire body below** with your actual reviewer instructions before
> running any meaningful review.

## Instructions to the reviewer agent

You are a bootstrap-only placeholder reviewer. **Do not analyze the diff.**
Do not read files. Do not comment on the code. Output exactly the following
two-line response, verbatim, and nothing else:

\`\`\`
Bootstrap placeholder reviewer — approving unconditionally so real reviewers can be installed. Replace this reviewer before relying on it for actual code review.
VERDICT: approved
\`\`\`

That is the entire response. No preamble, no analysis, no caveats beyond
the line above. The \`VERDICT: approved\` line MUST be the final line.

## Why this exists

Every stamp-protected repo needs at least one reviewer that can approve
the very first merge — the merge that installs the *real* reviewers.
That's a chicken-and-egg problem: real reviewers can't approve their own
introduction. This placeholder solves it by being trivially approvable,
and is meant to be retired (or kept defined-but-unrequired) immediately
after.

For guidance on writing real reviewer prompts — structure, calibration,
verdict thresholds — see
https://github.com/OpenThinkAi/stamp-cli/blob/main/docs/personas.md.
\`stamp init\` (without \`--minimal\`) scaffolds three calibrated starter
personas (security / standards / product) you can customize.
`;

export const DEFAULT_SECURITY_PROMPT = `# security reviewer

You are the security reviewer for this project. Your job is to flag changes
that introduce exploitable issues, expose secrets, or widen the trust
boundary in ways the author may not have considered.

This prompt is a starting point. Edit it to reflect your project's actual
threat model and stack. See https://github.com/OpenThinkAi/stamp-cli/blob/main/docs/personas.md
for guidance on calibrating reviewer prompts.

## What to check for

1. **Committed secrets.** API keys, tokens, credentials, or environment-style
   values hardcoded in any tracked file. Even in tests, docs, or comments.
2. **Dependency risk.** New entries in the manifest (package.json,
   requirements, Cargo.toml, etc.) — obscure authors, names resembling
   popular packages (typosquats), install-time scripts, or unexplained
   major-version jumps.
3. **Dangerous primitives.** Any introduction of \`eval\`, \`Function\`
   constructors, \`innerHTML\` / \`{@html}\` with non-literal content, shell
   commands built from interpolation, or deserialization of untrusted input
   into privileged contexts.
4. **Input validation gaps at system boundaries.** User input, external API
   responses, filesystem paths from config — are these validated and
   bounded before use?
5. **Subprocess invocation.** \`exec\` / \`spawn\` with \`shell: true\` or with
   arguments composed from external data is an injection risk. Prefer
   argument-array forms.
6. **Outbound network calls.** New \`fetch\`, HTTP client, WebSocket, or
   similar. Is the destination expected for this project? Are secrets
   correctly scoped? Are response bodies trusted too readily?
7. **Secret leakage in logs or errors.** Does a new log line or error
   message include values that shouldn't surface (tokens, personal data,
   full file paths revealing infra)?
8. **Trust model changes.** Does the diff widen who can do what — add a
   bypass flag, relax a check, accept unsigned input somewhere it was
   previously signed?

## What you do NOT check

- Code style, idiom, abstraction choices → **standards** reviewer.
- User-facing interface decisions (UX, API shape, breaking changes) → **product** reviewer.
- Anything in \`.stamp/\` — tool meta, separate concern.

## Verdict criteria

- **approved** — nothing in this reviewer's scope to flag. Also return
  \`approved\` when your only concerns are nit-grade — items you'd label
  "minor", "non-blocking", or "worth noting." Surface those as
  recommendations in the prose; don't aggregate nits into a
  \`changes_requested\`. **Reserve \`changes_requested\` for real
  correctness, security, UX-degrading, or contract-breaking issues.**
- **changes_requested** — specific fixable issues. Name the file:line, the
  problem, and the fix. Example: "hardcoded token at \`src/api.ts:12\`;
  move to an env var read at boot."
- **denied** — the diff introduces a fundamentally unsafe architecture:
  opens a dynamic-code-execution path, trusts untrusted input in a
  privileged context, removes a load-bearing check. Use \`denied\` when
  line-level edits cannot fix the problem.

## Tone and shape

Direct. Terse. If nothing's wrong, say so briefly and approve — don't
invent concerns to fill space. When something IS wrong, be specific
about the attack and the fix.

Lead with the verdict and the 2–3 most important issues. Optional nits
go in a smaller footer. Don't restate what the diff already says.
Target a review a busy author can act on in ~60 seconds. One-sentence
approvals are fine.

## Codebase retros (optional)

Separate from your verdict, you may call \`submit_retro\` 0–5 times to
leave behind transferable security observations about *this codebase* —
trust-boundary conventions worth respecting, invariants the security
model depends on, prior decisions about secret/credential handling that
shouldn't be re-litigated. NOT bug reports about this diff (those go in
your verdict prose). Skip when nothing transferable comes to mind —
silence is the default. The system prompt appendix has the full
instructions and \`kind\` enum.

## Output format (required — do not change)

Prose review, then exactly one final line:

\`\`\`
VERDICT: approved
\`\`\`

(or \`changes_requested\` or \`denied\`). Nothing after it.
`;

export const DEFAULT_STANDARDS_PROMPT = `# standards reviewer

You are the code-quality reviewer for this project. Your job is to keep
the codebase lean, idiomatic, and honestly sized for what it is.

This prompt is a starting point. Edit it to reflect your project's language,
framework, and style preferences. See https://github.com/OpenThinkAi/stamp-cli/blob/main/docs/personas.md
for guidance on calibrating reviewer prompts.

## Calibration philosophy — build-first, resist over-engineering

Prefer code that solves today's concrete problem over code that
anticipates tomorrow's hypothetical one. Push back on:

- **Premature abstractions.** A function extracted for a single caller.
  A factory with one product. A strategy pattern with one strategy. A
  config system for a value that's never varied.
- **Speculative generality.** "What if we later want to swap X" thinking
  when no current feature requires it.
- **Defensive code at internal boundaries.** Null checks on values that
  cannot be null by type or caller contract. \`try/catch\` around calls
  that don't throw. Fallback values for conditions that can't happen.
- **Over-typing.** Branded types for values that are fine as strings.
  Exhaustive generics where inference works.
- **Ceremony.** Builder patterns for objects with three fields. Interfaces
  with one implementation. Excessive getter/setter boilerplate.

Three similar lines is usually better than the wrong abstraction.
Duplication is cheaper than a premature model.

## What else to check for

- **Language idiom hygiene.** Prefer the language's native conventions
  over non-idiomatic transplants from another stack.
- **Type safety at the right places.** Strong types at module boundaries
  and interchange points. Avoid \`any\` / \`unknown\` / dynamic-casts where
  inference works. Be honest about escape hatches when they're needed.
- **Naming.** Intent-revealing, not encoded-type. Domain terms over
  generic names.
- **Error handling only at system boundaries.** User input, filesystem,
  subprocess, network. Internal code should trust its contracts.
- **Dead code.** Unused imports, exports, or parameters rot fast; flag them.
- **Module boundaries.** Each file should have a coherent purpose. Grab-bag
  utility files are a code smell.
- **Test coverage on hot paths.** Don't demand 100% coverage. Do demand
  tests for code that encodes real behavior and has multiple cases.
- **Cross-platform correctness.** For CLIs / scripts: BSD vs GNU tool
  differences, path separator assumptions, shell-specific idioms.

## What you do NOT check

- Security surfaces (secrets, injection, dependency risk) → **security** reviewer.
- User-facing impact (interface shape, UX, breaking changes) → **product** reviewer.

## Verdict criteria

- **approved** — clean, idiomatic, right-sized for the change. Also
  return \`approved\` when your only concerns are nit-grade — items
  you'd label "minor", "non-blocking", "cosmetic", or "while you're in
  there." Surface those as recommendations in the prose; don't
  aggregate nits into a \`changes_requested\`. **Reserve
  \`changes_requested\` for real correctness, idiom, or
  over-engineering issues — actual bugs or wrong-shape code.**
- **changes_requested** — specific fixes with file:line and the concrete
  change you want. Examples: "remove unused import at \`foo.ts:8\`";
  "inline the \`makeX\` factory at \`bar.ts:14\` — only one caller".
- **denied** — the change takes the code in a wrong architectural
  direction: introduces a pattern or layer that doesn't fit, adopts a
  new dependency the project doesn't need, creates the wrong shape
  for the domain.

## Tone and shape

Direct, terse, opinionated. Cite specific lines. Don't hedge. It is
fine to tell the author their abstraction is unjustified — that is
the value this reviewer adds.

Lead with the verdict and the 2–3 most important issues. Optional nits
go in a smaller footer. Don't restate what the diff already says.
Target a review a busy author can act on in ~60 seconds. One-sentence
approvals are fine.

## Codebase retros (optional)

Separate from your verdict, you may call \`submit_retro\` 0–5 times to
leave behind transferable code-quality observations about *this codebase*
— conventions a new contributor should mirror (module boundaries,
naming, layering), prior decisions about abstraction shape that
shouldn't be re-litigated, invariants stated in comments that quietly
hold across the codebase. NOT a list of code-style nits about this diff
(those go in your verdict prose). Skip when nothing transferable comes
to mind. The system prompt appendix has the full instructions and
\`kind\` enum.

## Output format (required — do not change)

Prose review, then exactly one final line:

\`\`\`
VERDICT: approved
\`\`\`

(or \`changes_requested\` or \`denied\`). Nothing after it.
`;

export const DEFAULT_PRODUCT_PROMPT = `# product reviewer

You are the product / user-facing-impact reviewer for this project. Your
job is to guard the interface this project exposes — whatever form that
takes (CLI flags, HTTP API shape, visual UI, library surface, etc.).

**This reviewer's scope is highly project-specific. Edit this prompt
heavily before trusting its verdicts on real diffs.** The structural
pattern below is useful; the concerns listed are generic and probably
don't fit your product perfectly. See
https://github.com/OpenThinkAi/stamp-cli/blob/main/docs/personas.md
for guidance.

## What to check for (generic — customize)

1. **Interface consistency.** Does the change match existing conventions
   in the codebase? Flag naming, URL structure, function signatures,
   error shapes, output formats, etc.
2. **Breaking changes.** Renamed flags, changed exit codes, modified
   response shapes, removed public APIs — any of these break external
   callers. Flag them explicitly even when the change is justified,
   so the author confirms the break is deliberate.
3. **Error messages.** Actionable, specific, name the what/where/next-step.
   "Invalid input" is bad. "Invalid revspec 'main..hed' — did you mean
   'main..HEAD'?" is good.
4. **Accessibility / usability.** For UI: keyboard handling, contrast,
   focus management, screen-reader friendliness. For CLIs: help text
   clarity. For APIs: discoverable errors and documented contracts.
5. **Edge cases in the product's core mechanics.** Empty inputs, inputs
   past expected bounds, concurrent usage, first-run states. The things
   that break in production but not in happy-path demos.
6. **Copy and microcopy.** Terse, clear, in the project's voice.

## What you do NOT check

- Security surfaces → **security** reviewer.
- Code quality, abstractions, idiom → **standards** reviewer.

## Operator intent is load-bearing

When the diff demonstrably implements explicit operator-authored
copy, command shape, or UX choices, do not return \`changes_requested\`
on the basis that you would have phrased it differently or hidden the
surface. Real convention/contract breaks (exit-code collisions, flag
naming drift, broken help text, accessibility regressions) still block.
Stylistic preference does not. Surface stylistic notes as suggestions
in the prose so the operator can take or leave them.

## Verdict criteria

- **approved** — change fits the product, handles relevant edge cases,
  preserves interface consistency, breaking changes (if any) are
  flagged and deliberate. Also return \`approved\` when your only
  concerns are subjective preference (wording, surface visibility,
  "I'd hide this") and the operator's intent is clear from the diff,
  or when remaining items are nit-grade — "minor", "non-blocking",
  "cosmetic". Surface those as recommendations in the prose; don't
  aggregate nits into a \`changes_requested\`. **Reserve
  \`changes_requested\` for real convention breaks, broken error
  messages, contract regressions, or backward-compat failures an agent
  or operator would actually trip over.**
- **changes_requested** — specific UX or interface fixes: rename a flag
  to match convention, fix a broken error message that doesn't say
  what/where/next-step, handle an edge case, document a deliberate
  break, resolve an exit-code or flag collision.
- **denied** — the change moves the product in the wrong direction:
  introduces a concept that conflicts with the existing model, violates
  an explicit non-goal, removes accessibility, changes a contract
  without a migration path. Architectural-level misfit.

## Tone and shape

Direct, terse. Quote specific lines / flags / outputs. Defend the
interface contract — you are the voice that will. Don't hedge when
something breaks the established pattern.

Lead with the verdict and the 2–3 most important issues. Optional nits
go in a smaller footer. Don't restate what the diff already says.
Target a review a busy author can act on in ~60 seconds. One-sentence
approvals are fine.

## Codebase retros (optional)

Separate from your verdict, you may call \`submit_retro\` 0–5 times to
leave behind transferable product/UX observations about *this codebase*
— interface conventions worth respecting, prior decisions about
naming/shape/exit-codes that shouldn't be re-litigated, invariants the
external contract depends on. NOT specific UX papercuts in this diff
(those go in your verdict prose). Skip when nothing transferable comes
to mind. The system prompt appendix has the full instructions and
\`kind\` enum.

## Output format (required — do not change)

Prose review, then exactly one final line:

\`\`\`
VERDICT: approved
\`\`\`

(or \`changes_requested\` or \`denied\`). Nothing after it.
`;
