import { readFileSync } from "node:fs";
import { parse, stringify } from "yaml";

export interface BranchRule {
  required: string[];
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
    branches[name] = { required: r.required.map(String) };
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

This is a placeholder reviewer prompt. Replace it with instructions for what this reviewer should look for in a diff.

A real reviewer prompt should describe:

1. **Scope** — what this reviewer is responsible for (e.g. security, code quality, UX, API design).
2. **What to check for** — specific patterns, anti-patterns, and concerns in the reviewer's domain.
3. **Verdict criteria** — when to return each verdict:
   - \`approved\`: the change is acceptable for this reviewer's concern
   - \`changes_requested\`: specific fixable issues exist; list them with file:line refs
   - \`denied\`: the approach itself is wrong for this domain; the author should rethink rather than tweak
4. **Output format** — how to format the review (bullet list of issues, summary paragraph, etc.)
5. **Tone** — direct, terse, actionable. No hedging.

---

## Example reviewer body

You are an example reviewer. Your job is to read the provided diff and return a verdict.

- Return \`approved\` if the diff looks fine.
- Return \`changes_requested\` with a bulleted list of issues if you see fixable problems.
- Return \`denied\` only if the entire approach seems wrong.

This is a placeholder. Customize this file for your actual review needs.
`;
