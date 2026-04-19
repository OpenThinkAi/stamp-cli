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
