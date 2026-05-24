/**
 * Trusted local-model reviewer.
 *
 * Bridges the unmetered one-shot core (`runOneShotReview` over a local
 * OpenAI-compatible client) into the `ReviewerInvocation` shape the trusted
 * review path already records and prints. From `runReview`'s perspective a
 * local reviewer is interchangeable with the agent-SDK reviewer: same return
 * type, same `recordReview` row, same gate. The only differences are that
 * the inference happens against a local model (no Anthropic metering) and
 * there is no tool-use loop.
 *
 * Trust note: this path produces a verdict that gates a merge, exactly like
 * the agent-SDK local-LLM path it sits beside. The trust anchor is
 * unchanged — the operator's machine produces the verdict and the merge
 * signature + pre-receive hook are what the server verifies; stamp never
 * independently re-reviews. Moving inference from the SDK to a local model
 * doesn't touch that boundary (see DESIGN.md / docs/local-only-mode.md).
 */

import { randomBytes } from "node:crypto";

import { runGit, showAtRef } from "./git.js";
import { createLocalReviewClient } from "./localReviewClient.js";
import { runOneShotReview, type ChatClientShape } from "./oneShotReview.js";
import type { ReviewerInvocation } from "./reviewer.js";

export interface InvokeLocalReviewerParams {
  reviewer: string;
  /** Base-sourced reviewer prompt bytes (read from base_sha by the caller). */
  systemPrompt: string;
  /** Diff the reviewer evaluates (full base..head, or a narrowed delta). */
  diff: string;
  base_sha: string;
  head_sha: string;
  /** Local model id (the suffix after the `local:` scheme). */
  model: string;
  /** Local endpoint base URL, or undefined to let the adapter default to
   *  LM Studio (http://localhost:1234/v1). */
  endpoint: string | undefined;
  repoRoot: string;
  /** When true (the `security` reviewer's default), the full head content of
   *  changed `.stamp/*` files is appended to the diff the model sees —
   *  decision 1a. A one-shot model can't open files itself, so we hand it
   *  the resulting trust-anchor files directly. */
  enforceReadsOnDotstamp: boolean;
  /** Injectable client for tests; production constructs a local client. */
  client?: ChatClientShape;
}

/**
 * Run one reviewer against the local model and adapt the result to a
 * `ReviewerInvocation`. Throws (so the caller's `Promise.allSettled` marks
 * it failed) when the model produced no parseable verdict — mirroring the
 * agent-SDK reviewer's throw-on-failure contract so the gate stays closed
 * on an unusable response rather than recording a null verdict.
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

  const client =
    params.client ??
    createLocalReviewClient(
      params.endpoint !== undefined ? { baseURL: params.endpoint } : {},
    );

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
    throw new Error(
      `local reviewer "${params.reviewer}" (model ${params.model}) produced ` +
        `no verdict: ${result.error ?? "unknown error"}. The local model may ` +
        `not support tool-calling — ensure the reviewer prompt ends with a ` +
        `"VERDICT: <choice>" line, or point the reviewer at a tool-capable ` +
        `model.`,
    );
  }

  return {
    reviewer: params.reviewer,
    prose: result.prose,
    verdict: result.verdict,
    // One-shot path makes no tool calls and has no retro channel.
    tool_calls: [],
    retros: [],
  };
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
