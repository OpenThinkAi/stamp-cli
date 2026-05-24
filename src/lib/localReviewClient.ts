/**
 * Local-model review client — a `ChatClientShape` backed by an
 * OpenAI-compatible `/v1/chat/completions` endpoint (LM Studio, llama.cpp's
 * `llama-server`, vLLM, LM Studio, etc.).
 *
 * This is the unmetered backend for trusted model-1 reviews: the operator
 * runs a local model (e.g. qwen via LM Studio on http://localhost:1234/v1)
 * and stamp drives it through the same one-shot core the Anthropic path
 * uses. No Anthropic API, no Agent SDK, no `claude -p` — nothing crosses
 * the June-15 metered boundary.
 *
 * The adapter's whole job is shape translation:
 *   - Anthropic Messages request  → OpenAI Chat Completions request
 *   - OpenAI Chat Completions reply → Anthropic Messages content blocks
 * so `runOneShotReview` (which speaks the Anthropic-Messages subset) works
 * unchanged. Tool-calling maps to OpenAI `tools`/`tool_calls`; models that
 * don't tool-call reliably fall through to the one-shot core's last-line
 * `VERDICT:` parser.
 */

import type { ChatClientShape } from "./oneShotReview.js";

/** Default base URL for LM Studio's OpenAI-compatible server. */
export const LOCAL_DEFAULT_BASE_URL = "http://localhost:1234/v1";

/**
 * Many local servers ignore the bearer token, but some (and the OpenAI SDK
 * convention) require a non-empty `Authorization` header. Send a harmless
 * placeholder by default; operators can override for servers that gate on
 * a real key.
 */
const PLACEHOLDER_API_KEY = "lm-studio";

/** Minimal `fetch` surface this adapter needs — lets tests inject a fake
 *  without pulling the full DOM lib types. */
export type FetchLike = (
  url: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body: string;
    signal?: AbortSignal | null | undefined;
  },
) => Promise<{
  ok: boolean;
  status: number;
  text: () => Promise<string>;
}>;

export interface LocalReviewClientOptions {
  /** OpenAI-compatible base URL, e.g. http://localhost:1234/v1. Trailing
   *  slash is tolerated. Defaults to LM Studio's local server. */
  baseURL?: string;
  /** Bearer token. Most local servers ignore it; defaults to a placeholder
   *  so the header is always present. */
  apiKey?: string;
  /**
   * Omit the `tools` field from the request. Local OpenAI-compatible servers
   * have wildly inconsistent function-calling support — notably
   * `mlx_lm.server` (the default Apple-Silicon backend) *crashes* server-side
   * when `tools` are present and the model emits non-JSON tool text. With
   * tools omitted, the verdict comes back through the one-shot core's
   * last-line `VERDICT:` fallback, which is reliable across every backend.
   * The trusted local reviewer sets this; flip it off only for a server you
   * know does OpenAI tool-calling correctly. Defaults to false here so the
   * client itself stays faithful to what it's told.
   */
  disableTools?: boolean;
  /** Injectable fetch for testing. Production leaves unset → global fetch. */
  fetchImpl?: FetchLike;
}

/**
 * Chat-template sentinels some local servers (e.g. this build of
 * `mlx_lm.server` with qwen) leak into the decoded `content` instead of
 * stripping. Left in, they break the strict last-line `VERDICT:` parser and
 * pollute prose, so the adapter scrubs them before handing text to the core.
 */
const SPECIAL_TOKEN_RE = /<\|(?:im_end|im_start|endoftext|eot_id)\|>/g;

/** OpenAI chat-completions response subset we read. */
interface OpenAIChatResponse {
  choices?: Array<{
    message?: {
      content?: string | null;
      tool_calls?: Array<{
        function?: { name?: string; arguments?: string };
      }>;
    };
    finish_reason?: string;
  }>;
}

/**
 * Build a `ChatClientShape` that talks to an OpenAI-compatible endpoint.
 * The returned object is a drop-in for the Anthropic client the headless
 * path uses, so `runOneShotReview` can drive either without branching.
 */
export function createLocalReviewClient(
  opts: LocalReviewClientOptions = {},
): ChatClientShape {
  const baseURL = (opts.baseURL ?? LOCAL_DEFAULT_BASE_URL).replace(/\/+$/, "");
  const apiKey = opts.apiKey ?? PLACEHOLDER_API_KEY;
  const disableTools = opts.disableTools ?? false;
  const doFetch: FetchLike = opts.fetchImpl ?? (globalThis.fetch as FetchLike);

  return {
    messages: {
      create: async (params, options) => {
        // Anthropic Messages → OpenAI Chat Completions request shape.
        const body: {
          model: string;
          max_tokens: number;
          messages: Array<{ role: string; content: string }>;
          tools?: Array<{
            type: "function";
            function: { name: string; description: string; parameters: unknown };
          }>;
        } = {
          model: params.model,
          max_tokens: params.max_tokens,
          messages: [
            { role: "system", content: params.system },
            ...params.messages.map((m) => ({
              role: m.role,
              content: m.content,
            })),
          ],
        };
        // Only advertise tools when the backend can handle them. Several
        // local servers (notably mlx_lm.server) crash when `tools` are
        // present; the one-shot core's `VERDICT:` fallback covers those.
        if (!disableTools && params.tools.length > 0) {
          body.tools = params.tools.map((t) => ({
            type: "function" as const,
            function: {
              name: t.name,
              description: t.description,
              parameters: t.input_schema,
            },
          }));
        }

        const res = await doFetch(`${baseURL}/chat/completions`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${apiKey}`,
          },
          body: JSON.stringify(body),
          signal: options?.signal ?? null,
        });

        if (!res.ok) {
          // Surface status + a short body snippet; the one-shot core's catch
          // folds this into result.error so the reviewer fan-out survives.
          const snippet = truncate((await safeText(res)).trim(), 200);
          throw new Error(
            `local model endpoint ${baseURL} returned HTTP ${res.status}` +
              (snippet ? `: ${snippet}` : ""),
          );
        }

        let parsed: OpenAIChatResponse;
        try {
          parsed = JSON.parse(await res.text()) as OpenAIChatResponse;
        } catch (err) {
          throw new Error(
            `local model endpoint ${baseURL} returned unparseable JSON: ` +
              (err instanceof Error ? err.message : String(err)),
          );
        }

        // OpenAI reply → Anthropic Messages content blocks.
        const choice = parsed.choices?.[0];
        const message = choice?.message;
        const content: Array<
          | { type: "text"; text: string }
          | { type: "tool_use"; name: string; input: unknown }
        > = [];

        if (typeof message?.content === "string") {
          // Scrub leaked chat-template sentinels (e.g. mlx_lm.server emits a
          // trailing `<|im_end|>`) that would otherwise break the strict
          // last-line VERDICT: parser and pollute prose.
          const text = message.content.replace(SPECIAL_TOKEN_RE, "").trimEnd();
          if (text.length > 0) content.push({ type: "text", text });
        }
        for (const tc of message?.tool_calls ?? []) {
          const name = tc.function?.name;
          if (typeof name !== "string") continue;
          content.push({
            type: "tool_use",
            name,
            // Tool args arrive as a JSON string. A malformed string just
            // yields `{}`, which the core treats as "no valid verdict" and
            // falls through to the VERDICT: parser — never a crash.
            input: safeJsonParse(tc.function?.arguments),
          });
        }

        return {
          content,
          // extractVerdict reads this on the empty-response error path.
          stop_reason: choice?.finish_reason ?? "unknown",
        };
      },
    },
  };
}

function safeJsonParse(s: string | undefined): unknown {
  if (typeof s !== "string") return {};
  try {
    return JSON.parse(s);
  } catch {
    return {};
  }
}

async function safeText(res: { text: () => Promise<string> }): Promise<string> {
  try {
    return await res.text();
  } catch {
    return "";
  }
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + "…";
}
