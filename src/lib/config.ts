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
    reviewers[name] = { prompt: d.prompt };
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

export function stringifyConfig(config: StampConfig): string {
  return stringify(config);
}

export const DEFAULT_CONFIG: StampConfig = {
  branches: {
    main: { required: ["example"] },
  },
  reviewers: {
    example: { prompt: ".stamp/reviewers/example.md" },
  },
};

export const EXAMPLE_REVIEWER_PROMPT = `# Example Reviewer

This file is the system prompt for an example reviewer. Replace its body with the actual instructions for the reviewer you want (security, standards, product, etc.).

A real reviewer prompt should describe:

1. **Scope** — what this reviewer is responsible for (e.g. security, code quality, UX, API design).
2. **What to check for** — specific patterns, anti-patterns, and concerns in the reviewer's domain.
3. **Verdict criteria** — when to return each verdict (see "Output format" below for how).
4. **Tone** — direct, terse, actionable. No hedging.

## Output format (required — do not change)

You MUST end your review with a single line of exactly this form, on its own line:

\`\`\`
VERDICT: approved
\`\`\`

Use one of:

- \`approved\` — the diff is acceptable for this reviewer's concern
- \`changes_requested\` — specific fixable issues exist; list them above, with file:line refs where possible
- \`denied\` — the approach itself is wrong for this domain; the author should rethink rather than tweak

Exactly one \`VERDICT:\` line, at the end of your response. Nothing after it.

---

## Example reviewer body

You are an example reviewer. Your job is to read the provided diff and return a verdict.

- Return \`approved\` if the diff looks fine.
- Return \`changes_requested\` with a bulleted list of issues if you see fixable problems.
- Return \`denied\` only if the entire approach seems wrong.

This is a placeholder. Customize this file for your actual review needs.
`;
