import { query } from "@anthropic-ai/claude-agent-sdk";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { StampConfig } from "./config.js";
import type { Verdict } from "./db.js";

const VERDICT_REGEX = /^VERDICT:\s*(approved|changes_requested|denied)\s*$/im;

export interface ReviewerInvocation {
  reviewer: string;
  prose: string; // the model's full response text
  verdict: Verdict;
}

export async function invokeReviewer(params: {
  reviewer: string;
  config: StampConfig;
  repoRoot: string;
  diff: string;
  base_sha: string;
  head_sha: string;
}): Promise<ReviewerInvocation> {
  const def = params.config.reviewers[params.reviewer];
  if (!def) {
    throw new Error(
      `reviewer "${params.reviewer}" is not defined in .stamp/config.yml`,
    );
  }

  const promptPath = join(params.repoRoot, def.prompt);
  let systemPrompt: string;
  try {
    systemPrompt = readFileSync(promptPath, "utf8");
  } catch (err) {
    throw new Error(
      `failed to read reviewer prompt at ${def.prompt}: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  const userPrompt = buildUserPrompt(params);

  const q = query({
    prompt: userPrompt,
    options: {
      cwd: params.repoRoot,
      systemPrompt,
      tools: [],
      persistSession: false,
    },
  });

  let finalText: string | null = null;
  let errorMessage: string | null = null;

  for await (const msg of q) {
    if (msg.type === "result") {
      if (msg.subtype === "success") {
        finalText = msg.result;
      } else {
        errorMessage = `reviewer "${params.reviewer}" run failed (subtype=${msg.subtype})`;
      }
      break;
    }
  }

  if (errorMessage) throw new Error(errorMessage);
  if (!finalText) {
    throw new Error(
      `reviewer "${params.reviewer}" produced no result message`,
    );
  }

  const verdict = parseVerdict(finalText, params.reviewer);
  const prose = stripVerdictLine(finalText);

  return { reviewer: params.reviewer, prose, verdict };
}

function buildUserPrompt(params: {
  diff: string;
  base_sha: string;
  head_sha: string;
}): string {
  return [
    `Review the following git diff.`,
    ``,
    `Base commit: ${params.base_sha}`,
    `Head commit: ${params.head_sha}`,
    ``,
    `Write your review as prose. Reference specific files and line numbers where applicable.`,
    ``,
    `End your response with a single line of the form:`,
    `  VERDICT: approved`,
    `  VERDICT: changes_requested`,
    `  VERDICT: denied`,
    ``,
    `The line must be exactly "VERDICT: <value>" on its own line. One verdict only.`,
    ``,
    `--- DIFF ---`,
    params.diff,
    `--- END DIFF ---`,
  ].join("\n");
}

function parseVerdict(text: string, reviewer: string): Verdict {
  const match = text.match(VERDICT_REGEX);
  if (!match || !match[1]) {
    throw new Error(
      `reviewer "${reviewer}" did not produce a parseable VERDICT line. ` +
        `Expected a final line "VERDICT: approved|changes_requested|denied". ` +
        `Got:\n${text.slice(-500)}`,
    );
  }
  return match[1] as Verdict;
}

function stripVerdictLine(text: string): string {
  return text.replace(VERDICT_REGEX, "").trimEnd();
}
