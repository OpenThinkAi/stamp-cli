import { readFileSync } from "node:fs";
import { parse, stringify } from "yaml";

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
}

export interface ReviewerDef {
  prompt: string;
  /**
   * Claude Agent SDK built-in tools the reviewer may call during review
   * (e.g. ["Read", "Grep", "WebFetch"]). Absent or empty → reviewer runs
   * with zero tools (the safe default, matches pre-tools stamp behavior).
   * Mapped to the SDK's `allowedTools` option at invocation time.
   */
  tools?: string[];
  /**
   * MCP servers to expose to the reviewer agent. Keys are server names used
   * in the reviewer prompt (e.g. "linear"); values are stdio server configs.
   * Env values may reference shell env vars via $VAR or ${VAR} — resolved at
   * invocation time; unset vars cause `stamp review` to fail fast.
   */
  mcp_servers?: Record<string, McpServerDef>;
}

export interface McpServerDef {
  command: string;
  args?: string[];
  env?: Record<string, string>;
}

export interface StampConfig {
  branches: Record<string, BranchRule>;
  reviewers: Record<string, ReviewerDef>;
}

export function loadConfig(path: string): StampConfig {
  const raw = readFileSync(path, "utf8");
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

    branches[name] = {
      required: r.required.map(String),
      ...(required_checks ? { required_checks } : {}),
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
    reviewers[name] = {
      prompt: d.prompt,
      ...(tools ? { tools } : {}),
      ...(mcp_servers ? { mcp_servers } : {}),
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

function parseTools(input: unknown, reviewerName: string): string[] | undefined {
  if (input === undefined || input === null) return undefined;
  if (!Array.isArray(input)) {
    throw new Error(
      `config.reviewers.${reviewerName}.tools must be an array of tool names`,
    );
  }
  const out: string[] = [];
  for (const entry of input) {
    if (typeof entry !== "string" || !entry) {
      throw new Error(
        `config.reviewers.${reviewerName}.tools entries must be non-empty strings`,
      );
    }
    out.push(entry);
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
    out[serverName] = {
      command: r.command,
      ...(args ? { args } : {}),
      ...(env ? { env } : {}),
    };
  }
  return out;
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

export const EXAMPLE_REVIEWER_PROMPT = `# example reviewer

This is a placeholder reviewer. Replace its body with actual instructions for the
reviewer you want. For guidance on writing effective reviewer prompts — structure,
calibration, verdict thresholds — see stamp-cli's
\`docs/personas.md\` (https://github.com/OpenThinkAi/stamp-cli/blob/main/docs/personas.md).

Three canonical personas to start from:

- **security** — secrets, injection, dependency risk, exfiltration surfaces
- **standards** — code quality, idiom, over-engineering pushback, test discipline
- **product** — user-facing impact, UX, breaking changes, interface consistency

Each should declare its scope, what it does NOT check (handing off to the other
reviewers), verdict criteria, and a tone directive. Parallel execution means
having three focused reviewers is not meaningfully slower than one generic reviewer.

## Output format (required — do not change)

Every reviewer MUST end its response with exactly one final line of this form:

\`\`\`
VERDICT: approved
\`\`\`

Use one of:

- \`approved\` — nothing worth blocking on in this reviewer's concern
- \`changes_requested\` — specific fixable issues; list them with file:line refs
- \`denied\` — the approach itself is wrong; the author should rethink, not tweak

Exactly one \`VERDICT:\` line, at the end of your response. Nothing after it.

---

## Placeholder body (replace this)

You are a placeholder reviewer. Read the provided diff. Return \`approved\` if it
looks fine, \`changes_requested\` with a list if you see fixable problems, or
\`denied\` only if the entire approach seems wrong.

This prompt is deliberately generic. Customize it before shipping.
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

- **approved** — nothing in this reviewer's scope to flag.
- **changes_requested** — specific fixable issues. Name the file:line, the
  problem, and the fix. Example: "hardcoded token at \`src/api.ts:12\`;
  move to an env var read at boot."
- **denied** — the diff introduces a fundamentally unsafe architecture:
  opens a dynamic-code-execution path, trusts untrusted input in a
  privileged context, removes a load-bearing check. Use \`denied\` when
  line-level edits cannot fix the problem.

## Tone

Direct. Terse. If nothing's wrong, say so briefly and approve — don't
invent concerns to fill space. When something IS wrong, be specific
about the attack and the fix.

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

- **approved** — clean, idiomatic, right-sized for the change.
- **changes_requested** — specific fixes with file:line and the concrete
  change you want. Examples: "remove unused import at \`foo.ts:8\`";
  "inline the \`makeX\` factory at \`bar.ts:14\` — only one caller".
- **denied** — the change takes the code in a wrong architectural
  direction: introduces a pattern or layer that doesn't fit, adopts a
  new dependency the project doesn't need, creates the wrong shape
  for the domain.

## Tone

Direct, terse, opinionated. Cite specific lines. Don't hedge. It is
fine to tell the author their abstraction is unjustified — that is
the value this reviewer adds. Approvals can be one sentence.

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

## Verdict criteria

- **approved** — change fits the product, handles relevant edge cases,
  preserves interface consistency, breaking changes (if any) are
  flagged and deliberate.
- **changes_requested** — specific UX or interface fixes: rename a flag
  to match convention, reword an error message, handle an edge case,
  document a deliberate break.
- **denied** — the change moves the product in the wrong direction:
  introduces a concept that conflicts with the existing model, violates
  an explicit non-goal, removes accessibility, changes a contract
  without a migration path. Architectural-level misfit.

## Tone

Direct, terse. Quote specific lines / flags / outputs. Defend the
interface contract — you are the voice that will. Don't hedge when
something breaks the established pattern.

## Output format (required — do not change)

Prose review, then exactly one final line:

\`\`\`
VERDICT: approved
\`\`\`

(or \`changes_requested\` or \`denied\`). Nothing after it.
`;
