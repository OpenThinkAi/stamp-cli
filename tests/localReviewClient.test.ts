/**
 * Unit tests for src/lib/localReviewClient.ts.
 *
 * Strategy: inject a fake `fetch` so the tests run with zero network and no
 * LM Studio dependency. Verifies (a) the Anthropic→OpenAI request
 * translation, (b) the OpenAI→Anthropic response translation for both the
 * tool_calls path and the plain-content path, (c) HTTP/JSON error surfacing,
 * (d) malformed tool args degrade to `{}` rather than crashing, and (e) the
 * adapter drives `runOneShotReview` end-to-end to a verdict.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  createLocalReviewClient,
  LOCAL_DEFAULT_BASE_URL,
  type FetchLike,
} from "../src/lib/localReviewClient.ts";
import { runOneShotReview } from "../src/lib/oneShotReview.ts";
import type { ReviewPlanReviewer } from "../src/lib/reviewPlan.ts";

const FIXTURE_REVIEWER: ReviewPlanReviewer = {
  name: "security",
  prompt: "# security reviewer\n\nFlag exploitable changes.\n",
  fence_hex: "deadbeefcafebabe1234567890abcdef",
};

/** Build a fake fetch that records the last request and returns a canned
 *  OpenAI body. */
function fakeFetch(
  responseBody: unknown,
  opts: { ok?: boolean; status?: number; bodyText?: string } = {},
): { fetchImpl: FetchLike; calls: Array<{ url: string; init: any }> } {
  const calls: Array<{ url: string; init: any }> = [];
  const fetchImpl: FetchLike = async (url, init) => {
    calls.push({ url, init });
    return {
      ok: opts.ok ?? true,
      status: opts.status ?? 200,
      text: async () => opts.bodyText ?? JSON.stringify(responseBody),
    };
  };
  return { fetchImpl, calls };
}

function chatParams() {
  return {
    model: "qwen2.5-coder",
    max_tokens: 4096,
    system: "system text",
    messages: [{ role: "user" as const, content: "user text" }],
    tools: [
      {
        name: "submit_verdict",
        description: "submit it",
        input_schema: {
          type: "object" as const,
          properties: { verdict: { type: "string" } },
          required: ["verdict"],
        },
      },
    ],
  };
}

describe("createLocalReviewClient — request translation", () => {
  it("POSTs to <baseURL>/chat/completions with bearer auth and OpenAI shape", async () => {
    const { fetchImpl, calls } = fakeFetch({
      choices: [{ message: { content: "ok" }, finish_reason: "stop" }],
    });
    const client = createLocalReviewClient({
      baseURL: "http://localhost:1234/v1",
      apiKey: "secret-key",
      fetchImpl,
    });
    await client.messages.create(chatParams());

    assert.equal(calls.length, 1);
    assert.equal(calls[0]!.url, "http://localhost:1234/v1/chat/completions");
    assert.equal(calls[0]!.init.method, "POST");
    assert.equal(calls[0]!.init.headers.authorization, "Bearer secret-key");

    const body = JSON.parse(calls[0]!.init.body);
    assert.equal(body.model, "qwen2.5-coder");
    assert.equal(body.max_tokens, 4096);
    // system folded into the first message as role:system
    assert.deepEqual(body.messages[0], { role: "system", content: "system text" });
    assert.deepEqual(body.messages[1], { role: "user", content: "user text" });
    // tools translated to OpenAI function shape
    assert.equal(body.tools[0].type, "function");
    assert.equal(body.tools[0].function.name, "submit_verdict");
    assert.deepEqual(
      body.tools[0].function.parameters,
      chatParams().tools[0]!.input_schema,
    );
  });

  it("defaults baseURL to LM Studio and tolerates a trailing slash", async () => {
    const { fetchImpl, calls } = fakeFetch({
      choices: [{ message: { content: "ok" }, finish_reason: "stop" }],
    });
    const client = createLocalReviewClient({
      baseURL: "http://localhost:1234/v1/",
      fetchImpl,
    });
    await client.messages.create(chatParams());
    assert.equal(calls[0]!.url, "http://localhost:1234/v1/chat/completions");
    // sanity: the exported default points at LM Studio
    assert.equal(LOCAL_DEFAULT_BASE_URL, "http://localhost:1234/v1");
  });
});

describe("createLocalReviewClient — response translation", () => {
  it("maps tool_calls to a tool_use content block with parsed input", async () => {
    const { fetchImpl } = fakeFetch({
      choices: [
        {
          message: {
            content: null,
            tool_calls: [
              {
                function: {
                  name: "submit_verdict",
                  arguments: JSON.stringify({
                    verdict: "approved",
                    prose: "looks fine",
                  }),
                },
              },
            ],
          },
          finish_reason: "tool_calls",
        },
      ],
    });
    const client = createLocalReviewClient({ fetchImpl });
    const res = await client.messages.create(chatParams());
    assert.equal(res.content.length, 1);
    const block = res.content[0] as {
      type: string;
      name: string;
      input: { verdict: string; prose: string };
    };
    assert.equal(block.type, "tool_use");
    assert.equal(block.name, "submit_verdict");
    assert.equal(block.input.verdict, "approved");
    assert.equal(block.input.prose, "looks fine");
  });

  it("maps plain assistant content to a text block", async () => {
    const { fetchImpl } = fakeFetch({
      choices: [
        { message: { content: "VERDICT: approved" }, finish_reason: "stop" },
      ],
    });
    const client = createLocalReviewClient({ fetchImpl });
    const res = await client.messages.create(chatParams());
    assert.equal(res.content.length, 1);
    const block = res.content[0] as { type: string; text: string };
    assert.equal(block.type, "text");
    assert.equal(block.text, "VERDICT: approved");
  });

  it("degrades malformed tool arguments to {} instead of throwing", async () => {
    const { fetchImpl } = fakeFetch({
      choices: [
        {
          message: {
            content: null,
            tool_calls: [
              { function: { name: "submit_verdict", arguments: "{not json" } },
            ],
          },
          finish_reason: "tool_calls",
        },
      ],
    });
    const client = createLocalReviewClient({ fetchImpl });
    const res = await client.messages.create(chatParams());
    const block = res.content[0] as { type: string; input: unknown };
    assert.equal(block.type, "tool_use");
    assert.deepEqual(block.input, {});
  });
});

describe("createLocalReviewClient — disableTools + sanitization", () => {
  it("includes tools in the request by default", async () => {
    const { fetchImpl, calls } = fakeFetch({
      choices: [{ message: { content: "ok" }, finish_reason: "stop" }],
    });
    const client = createLocalReviewClient({ fetchImpl });
    await client.messages.create(chatParams());
    const body = JSON.parse(calls[0]!.init.body);
    assert.ok(Array.isArray(body.tools), "tools should be present by default");
  });

  it("omits tools when disableTools is set (mlx_lm.server crashes on them)", async () => {
    const { fetchImpl, calls } = fakeFetch({
      choices: [{ message: { content: "VERDICT: approved" }, finish_reason: "stop" }],
    });
    const client = createLocalReviewClient({ fetchImpl, disableTools: true });
    await client.messages.create(chatParams());
    const body = JSON.parse(calls[0]!.init.body);
    assert.equal(body.tools, undefined, "tools must be omitted under disableTools");
  });

  it("strips leaked chat-template sentinels from content", async () => {
    const { fetchImpl } = fakeFetch({
      choices: [
        {
          message: { content: "VERDICT: approved<|im_end|>" },
          finish_reason: "stop",
        },
      ],
    });
    const client = createLocalReviewClient({ fetchImpl });
    const res = await client.messages.create(chatParams());
    const block = res.content[0] as { type: string; text: string };
    assert.equal(block.type, "text");
    assert.equal(block.text, "VERDICT: approved");
  });
});

describe("createLocalReviewClient — error surfacing", () => {
  it("throws with status + snippet on non-ok HTTP", async () => {
    const { fetchImpl } = fakeFetch(null, {
      ok: false,
      status: 500,
      bodyText: "model not loaded",
    });
    const client = createLocalReviewClient({ fetchImpl });
    await assert.rejects(client.messages.create(chatParams()), (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.match((err as Error).message, /HTTP 500/);
      assert.match((err as Error).message, /model not loaded/);
      return true;
    });
  });

  it("throws on unparseable JSON body", async () => {
    const { fetchImpl } = fakeFetch(null, { ok: true, bodyText: "<html>oops" });
    const client = createLocalReviewClient({ fetchImpl });
    await assert.rejects(client.messages.create(chatParams()), (err: unknown) => {
      assert.match((err as Error).message, /unparseable JSON/);
      return true;
    });
  });
});

describe("createLocalReviewClient — end-to-end through runOneShotReview", () => {
  it("drives the one-shot core to a verdict via the tool channel", async () => {
    const { fetchImpl } = fakeFetch({
      choices: [
        {
          message: {
            content: null,
            tool_calls: [
              {
                function: {
                  name: "submit_verdict",
                  arguments: JSON.stringify({
                    verdict: "changes_requested",
                    prose: "needs a test",
                  }),
                },
              },
            ],
          },
          finish_reason: "tool_calls",
        },
      ],
    });
    const client = createLocalReviewClient({ fetchImpl });
    const r = await runOneShotReview({
      reviewer: FIXTURE_REVIEWER,
      diff: "diff --git a/foo b/foo\n+hello\n",
      base_sha: "1".repeat(40),
      head_sha: "2".repeat(40),
      model: "qwen2.5-coder",
      client,
    });
    assert.equal(r.verdict, "changes_requested");
    assert.equal(r.prose, "needs a test");
    assert.equal(r.model, "qwen2.5-coder");
    assert.equal(r.error, undefined);
  });

  it("drives the one-shot core to a verdict via the VERDICT: fallback", async () => {
    const { fetchImpl } = fakeFetch({
      choices: [
        {
          message: { content: "Reviewed.\n\nVERDICT: approved" },
          finish_reason: "stop",
        },
      ],
    });
    const client = createLocalReviewClient({ fetchImpl });
    const r = await runOneShotReview({
      reviewer: FIXTURE_REVIEWER,
      diff: "x",
      base_sha: "1".repeat(40),
      head_sha: "2".repeat(40),
      model: "qwen2.5-coder",
      client,
    });
    assert.equal(r.verdict, "approved");
    assert.equal(r.prose, "Reviewed.");
  });
});
