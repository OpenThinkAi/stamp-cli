import { query } from "@anthropic-ai/claude-agent-sdk";
import type { McpServerDef, ReviewerDef, StampConfig } from "./config.js";
import type { Verdict } from "./db.js";
import { hashToolInput, type ToolCall } from "./toolCalls.js";

type McpServerResolved = {
  type: "stdio";
  command: string;
  args?: string[];
  env?: Record<string, string>;
};

const VERDICT_REGEX = /^VERDICT:\s*(approved|changes_requested|denied)\s*$/im;

export interface ReviewerInvocation {
  reviewer: string;
  prose: string; // the model's full response text
  verdict: Verdict;
  /** Tool calls the reviewer's agent made during the review. Audit metadata
   *  only — see lib/toolCalls.ts for threat model. */
  tool_calls: ToolCall[];
}

export async function invokeReviewer(params: {
  reviewer: string;
  config: StampConfig;
  repoRoot: string;
  diff: string;
  base_sha: string;
  head_sha: string;
  /**
   * Reviewer prompt text. The caller is responsible for sourcing this from
   * the right place — `runReview` reads it from the base_sha tree (security:
   * prevents feature-branch self-review). `stamp reviewers test` reads from
   * the working tree (intended: prompt-iteration use case). This function
   * does not read from disk; it just runs whatever prompt it's given.
   */
  systemPrompt: string;
}): Promise<ReviewerInvocation> {
  const def = params.config.reviewers[params.reviewer];
  if (!def) {
    throw new Error(
      `reviewer "${params.reviewer}" is not defined in .stamp/config.yml`,
    );
  }

  const userPrompt = buildUserPrompt(params);

  const allowedTools = def.tools ?? [];
  const mcpServers = resolveMcpServers(def, params.reviewer);

  const q = query({
    prompt: userPrompt,
    options: {
      cwd: params.repoRoot,
      systemPrompt: params.systemPrompt,
      allowedTools,
      ...(mcpServers ? { mcpServers } : {}),
      persistSession: false,
    },
  });

  let finalText: string | null = null;
  let errorMessage: string | null = null;
  const toolCalls: ToolCall[] = [];

  for await (const msg of q) {
    // Capture tool-use blocks from assistant messages for the audit trace.
    // SDKAssistantMessage.message.content is an array of content blocks; the
    // tool_use ones carry { type: 'tool_use', name, input }.
    if (msg.type === "assistant") {
      const content = (msg.message as { content?: unknown }).content;
      if (Array.isArray(content)) {
        for (const block of content) {
          if (
            block &&
            typeof block === "object" &&
            (block as { type?: unknown }).type === "tool_use"
          ) {
            const b = block as { name?: unknown; input?: unknown };
            if (typeof b.name === "string") {
              toolCalls.push({
                tool: b.name,
                input_sha256: hashToolInput(b.input),
              });
            }
          }
        }
      }
      continue;
    }
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

  return { reviewer: params.reviewer, prose, verdict, tool_calls: toolCalls };
}

function resolveMcpServers(
  def: ReviewerDef,
  reviewerName: string,
): Record<string, McpServerResolved> | undefined {
  if (!def.mcp_servers) return undefined;
  const out: Record<string, McpServerResolved> = {};
  for (const [serverName, cfg] of Object.entries(def.mcp_servers)) {
    out[serverName] = buildServer(cfg, reviewerName, serverName);
  }
  return out;
}

function buildServer(
  cfg: McpServerDef,
  reviewerName: string,
  serverName: string,
): McpServerResolved {
  const resolved: McpServerResolved = { type: "stdio", command: cfg.command };
  if (cfg.args) resolved.args = cfg.args;
  if (cfg.env) {
    const env: Record<string, string> = {};
    for (const [key, rawValue] of Object.entries(cfg.env)) {
      env[key] = expandEnvRefs(rawValue, {
        reviewer: reviewerName,
        server: serverName,
        field: `env.${key}`,
      });
    }
    resolved.env = env;
  }
  return resolved;
}

// Expands $VAR and ${VAR} references in an MCP env value against process.env.
// Matches POSIX-style identifiers: [A-Za-z_][A-Za-z0-9_]*. Unset vars fail
// fast with a message naming the missing var and where it was declared, so
// an agent loop doesn't get a confusing mid-stream MCP failure.
function expandEnvRefs(
  value: string,
  ctx: { reviewer: string; server: string; field: string },
): string {
  return value.replace(
    /\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g,
    (_, a, b) => {
      const name = a ?? b;
      const resolved = process.env[name];
      if (resolved === undefined) {
        throw new Error(
          `reviewer "${ctx.reviewer}" declared mcp_servers.${ctx.server}.${ctx.field} ` +
            `referencing $${name}, but ${name} is not set in the environment. ` +
            `Export it before running 'stamp review'.`,
        );
      }
      return resolved;
    },
  );
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
