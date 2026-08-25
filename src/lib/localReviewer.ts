/**
 * Trusted OpenAI-compatible reviewer.
 *
 * Bridges the one-shot core (`runOneShotReview` over an OpenAI-compatible
 * client) into the `ReviewerInvocation` shape the trusted review path
 * already records and prints. From `runReview`'s perspective this reviewer
 * is interchangeable with the agent-SDK reviewer: same return type, same
 * `recordReview` row, same gate. The only differences are where the
 * inference happens and that there is no tool-use loop.
 *
 * The endpoint may be a model on this box (unmetered, nothing leaves the
 * host) or a hosted provider — OpenAI, DeepSeek, anything that speaks
 * `/chat/completions`. AGT-1138 made the hosted case reachable by resolving
 * a per-provider credential HERE, at the invocation site, rather than
 * carrying one on `ReviewerBackend`: the key's lifetime is a single request,
 * and it never touches the object that gets displayed, stored in
 * `state.db`, or signed into the attestation.
 *
 * Trust note: this path produces a verdict that gates a merge, exactly like
 * the agent-SDK path it sits beside. The trust anchor is unchanged — the
 * operator's machine produces the verdict and the merge signature +
 * pre-receive hook are what the server verifies; stamp never independently
 * re-reviews. Moving inference off the SDK doesn't touch that boundary (see
 * DESIGN.md / docs/local-only-mode.md).
 */

import { randomBytes } from "node:crypto";

import { runGit, showAtRef } from "./git.js";
import {
  createLocalReviewClient,
  LOCAL_DEFAULT_BASE_URL,
  type FetchLike,
} from "./localReviewClient.js";
import { runOneShotReview, type ChatClientShape } from "./oneShotReview.js";
import {
  missingCredentialMessage,
  resolveProviderCredentialFrom,
} from "./providerCredentials.js";
import type { ReviewerInvocation } from "./reviewer.js";
import { loadUserConfig, type UserConfig } from "./userConfig.js";

export interface InvokeLocalReviewerParams {
  reviewer: string;
  /** Base-sourced reviewer prompt bytes (read from base_sha by the caller). */
  systemPrompt: string;
  /** Diff the reviewer evaluates (full base..head, or a narrowed delta). */
  diff: string;
  base_sha: string;
  head_sha: string;
  /** Model id (the suffix after the `openai-compatible:` / `local:` scheme). */
  model: string;
  /** OpenAI-compatible base URL, or undefined to let the adapter default to
   *  LM Studio (http://localhost:1234/v1). */
  endpoint: string | undefined;
  /**
   * Enable the OpenAI `tools` field and the `submit_verdict` structured-
   * verdict path. Off by default — `mlx_lm.server` (the most common Apple-
   * Silicon backend) crashes when `tools` are present. Flip on only for a
   * server you have verified handles OpenAI function-calling correctly.
   * When false the one-shot core's last-line `VERDICT:` fallback is used
   * instead, which is reliable across every backend. Sourced from the
   * `openai_compatible_tools` config field / `STAMP_OPENAI_COMPATIBLE_TOOLS`
   * env var (or their legacy `local_*` spellings) via the
   * `ReviewerBackend.enableTools` property.
   */
  enableTools: boolean;
  repoRoot: string;
  /** When true (the `security` reviewer's default), the full head content of
   *  changed `.stamp/*` files is appended to the diff the model sees —
   *  decision 1a. A one-shot model can't open files itself, so we hand it
   *  the resulting trust-anchor files directly. */
  enforceReadsOnDotstamp: boolean;
  /** Injectable client for tests; production constructs one from the
   *  endpoint + the resolved per-provider credential. */
  client?: ChatClientShape;
  /**
   * Injectable fetch for tests that need the PRODUCTION client-construction
   * path (credential resolution, redaction, the 401 message) without a
   * network. Ignored when `client` is supplied — an injected client owns its
   * own transport.
   */
  fetchImpl?: FetchLike;
  /**
   * Per-user config to resolve credentials against. Tests pass one
   * explicitly; production omits it and the resolver reads
   * `~/.stamp/config.yml`. `null` means "no config", not "load it".
   */
  userConfig?: UserConfig | null;
  /** Env to resolve credentials from. Defaults to `process.env`. */
  env?: Record<string, string | undefined>;
}

/**
 * Run one reviewer against the OpenAI-compatible endpoint and adapt the
 * result to a `ReviewerInvocation`. Throws (so the caller's
 * `Promise.allSettled` marks it failed) when no parseable verdict came back —
 * mirroring the agent-SDK reviewer's throw-on-failure contract so the gate
 * stays closed on an unusable response rather than recording a null verdict.
 * A missing or rejected credential throws here too, for the same reason.
 */
export async function invokeLocalReviewer(
  params: InvokeLocalReviewerParams,
): Promise<ReviewerInvocation> {
  // Per-call random fence hex, same purpose as the agent-SDK reviewer's:
  // the diff author can't guess it, so they can't close the fence and
  // smuggle out-of-band instructions to the reviewer.
  const fence_hex = randomBytes(16).toString("hex");

  let diff = params.diff;
  if (params.enforceReadsOnDotstamp) {
    const extra = collectDotstampContext(
      params.base_sha,
      params.head_sha,
      params.repoRoot,
    );
    if (extra) diff = `${params.diff}\n\n${extra}`;
  }

  const client = params.client ?? buildClient(params);

  const result = await runOneShotReview({
    reviewer: {
      name: params.reviewer,
      prompt: params.systemPrompt,
      fence_hex,
    },
    diff,
    base_sha: params.base_sha,
    head_sha: params.head_sha,
    model: params.model,
    client,
  });

  if (result.verdict === null) {
    const detail = result.error ?? "unknown error";
    // The tool-calling hint is right for "the model answered, we couldn't
    // parse a verdict out of it" and actively misleading for "the endpoint
    // refused the request". A 401 is not fixed by rewording the prompt, and
    // telling an operator it might be is how AC4's "actionable message"
    // becomes an actionable message about the wrong thing.
    const hint = isTransportFailure(detail)
      ? ""
      : ` The model may not support tool-calling — ensure the reviewer ` +
        `prompt ends with a "VERDICT: <choice>" line, or point the reviewer ` +
        `at a tool-capable model.`;
    throw new Error(
      `openai-compatible reviewer "${params.reviewer}" (model ${params.model}) produced ` +
        `no verdict: ${detail}.${hint}`,
    );
  }

  return {
    reviewer: params.reviewer,
    prose: result.prose,
    verdict: result.verdict,
    // One-shot path makes no tool calls, has no retro channel, and runs
    // outside the Claude Agent SDK loop — no MCP server status to record.
    tool_calls: [],
    retros: [],
    mcp_servers_at_init: [],
  };
}

/**
 * Did this failure happen at the transport, rather than in the model's
 * answer? Matched on the prefixes `lib/localReviewClient.ts` and
 * `lib/providerCredentials.ts` build their messages with — both are stamp's
 * own strings, produced a few frames below this one, not text from a
 * provider. A false negative only restores the old (harmless, if
 * unhelpful) hint, so the match is deliberately narrow.
 */
function isTransportFailure(detail: string): boolean {
  return (
    detail.includes("openai-compatible endpoint ") ||
    detail.includes("no API credential")
  );
}

/**
 * Construct the production OpenAI-compatible client for this invocation:
 * resolve the endpoint, resolve the credential that endpoint's provider
 * needs, and refuse to send anything when a required one is missing.
 *
 * The refusal is the point of the `required` check. Without it, a reviewer
 * pointed at OpenAI with no key sends the `"lm-studio"` placeholder, gets a
 * 401, and the operator reads a raw HTTP status — the failure mode AC4
 * exists to remove. With it, nothing is sent at all and the message names
 * the endpoint, the provider, and every place a key could come from.
 *
 * A LOOPBACK or unrecognised endpoint is never "required": that is what
 * keeps `STAMP_REVIEWER_BACKEND=local` against localhost — and against a LAN
 * box or a corporate gateway — working with no credential, exactly as before.
 */
function buildClient(params: InvokeLocalReviewerParams): ChatClientShape {
  // The endpoint the request will ACTUALLY hit, with the adapter default
  // already applied — the provider must be derived from where the bytes go,
  // not from where the operator did or didn't configure something.
  const endpoint = params.endpoint ?? LOCAL_DEFAULT_BASE_URL;
  const cfg =
    params.userConfig !== undefined ? params.userConfig : loadUserConfigSafely();
  const credential = resolveProviderCredentialFrom(
    cfg,
    endpoint,
    params.env ?? process.env,
  );

  if (credential.apiKey === null && credential.required) {
    throw new Error(missingCredentialMessage(endpoint, credential.providerId));
  }

  return createLocalReviewClient({
    // Tool-calling is off by default: mlx_lm.server (the most common
    // Apple-Silicon backend) crashes server-side when `tools` are present.
    // The operator can opt in via STAMP_OPENAI_COMPATIBLE_TOOLS=1 (or the
    // legacy STAMP_LOCAL_TOOLS=1) / `openai_compatible_tools: true` in
    // ~/.stamp/config.yml for a server known to handle it correctly.
    disableTools: !params.enableTools,
    ...(params.endpoint !== undefined ? { baseURL: params.endpoint } : {}),
    // Absent credential → omit the field so the adapter's placeholder path
    // is taken verbatim, rather than sending an explicit null-ish token.
    ...(credential.apiKey !== null ? { apiKey: credential.apiKey } : {}),
    providerId: credential.providerId,
    credentialSource: credential.source,
    ...(params.fetchImpl !== undefined ? { fetchImpl: params.fetchImpl } : {}),
  });
}

/**
 * Load `~/.stamp/config.yml`, treating a malformed file as "no config".
 * Same posture as `resolveReviewerBackend`: this sits on the hot path of
 * every reviewer invocation, and a YAML typo should not take the review
 * down — `stamp config reviewers show` is the surface that reports it.
 */
function loadUserConfigSafely(): UserConfig | null {
  try {
    return loadUserConfig();
  } catch {
    return null;
  }
}

/**
 * Build a labelled block with the full head content of every changed
 * `.stamp/*` file, to append to the diff a `enforce_reads_on_dotstamp`
 * reviewer sees. Returns null when nothing under `.stamp/` changed (or git
 * errors — fail open, same as the agent-SDK path's
 * `findMissingDotstampReads`). The block goes INSIDE the diff fence in the
 * one-shot prompt, so it's treated as data, not instructions.
 */
function collectDotstampContext(
  base: string,
  head: string,
  repoRoot: string,
): string | null {
  let raw: string;
  try {
    raw = runGit(
      ["diff", "--name-only", "--diff-filter=AMR", `${base}..${head}`],
      repoRoot,
    );
  } catch {
    return null;
  }
  const files = raw
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && l.startsWith(".stamp/"));
  if (files.length === 0) return null;

  const parts: string[] = [
    `--- Full content of changed .stamp/ files at head ${head.slice(0, 8)} ` +
      `(included because this reviewer must inspect trust-anchor changes and ` +
      `cannot open files itself) ---`,
  ];
  for (const f of files) {
    let content: string;
    try {
      content = showAtRef(head, f, repoRoot);
    } catch {
      continue;
    }
    parts.push(`\n### ${f}\n${content}`);
  }
  return parts.join("\n");
}
