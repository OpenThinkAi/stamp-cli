/**
 * Unit tests for src/lib/localReviewer.ts — the trusted local-model
 * reviewer that adapts the one-shot core into a ReviewerInvocation.
 *
 * An injected ChatClientShape keeps these network-free and git-free
 * (enforceReadsOnDotstamp=false avoids the .stamp/* git read path, which is
 * exercised by the phase-e smoke test against a real repo instead).
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { invokeLocalReviewer } from "../src/lib/localReviewer.ts";
import type { ChatClientShape } from "../src/lib/oneShotReview.ts";

function mockClient(
  response: Awaited<ReturnType<ChatClientShape["messages"]["create"]>>,
): ChatClientShape {
  return { messages: { create: async () => response } };
}

function baseParams(client: ChatClientShape) {
  return {
    reviewer: "security",
    systemPrompt: "# security reviewer\n\nFlag exploitable changes.\n",
    diff: "diff --git a/foo b/foo\n+hello\n",
    base_sha: "1".repeat(40),
    head_sha: "2".repeat(40),
    model: "qwen2.5-coder-32b",
    endpoint: "http://localhost:1234/v1",
    repoRoot: "/tmp/does-not-matter",
    enforceReadsOnDotstamp: false,
    client,
  };
}

describe("invokeLocalReviewer", () => {
  it("adapts a tool-channel verdict into a ReviewerInvocation", async () => {
    const client = mockClient({
      content: [
        {
          type: "tool_use",
          name: "submit_verdict",
          input: { verdict: "approved", prose: "no concerns" },
        },
      ],
    });
    const r = await invokeLocalReviewer(baseParams(client));
    assert.equal(r.reviewer, "security");
    assert.equal(r.verdict, "approved");
    assert.equal(r.prose, "no concerns");
    // One-shot path: no tool calls, no retros.
    assert.deepEqual(r.tool_calls, []);
    assert.deepEqual(r.retros, []);
  });

  it("adapts a VERDICT: fallback verdict too", async () => {
    const client = mockClient({
      content: [{ type: "text", text: "Looks fine.\n\nVERDICT: approved" }],
    });
    const r = await invokeLocalReviewer(baseParams(client));
    assert.equal(r.verdict, "approved");
    assert.equal(r.prose, "Looks fine.");
  });

  it("throws (fails the reviewer) when the model returns no verdict", async () => {
    const client = mockClient({
      content: [{ type: "text", text: "I have no opinion." }],
    });
    await assert.rejects(
      invokeLocalReviewer(baseParams(client)),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.match((err as Error).message, /produced .*no verdict/);
        // Names the model so the operator can see which backend failed.
        assert.match((err as Error).message, /qwen2\.5-coder-32b/);
        return true;
      },
    );
  });

  it("throws when the underlying model call rejects", async () => {
    const client: ChatClientShape = {
      messages: {
        create: async () => {
          throw new Error("connection refused");
        },
      },
    };
    // runOneShotReview folds the call error into result.error + null verdict,
    // which invokeLocalReviewer surfaces as a thrown failure.
    await assert.rejects(invokeLocalReviewer(baseParams(client)), (err: unknown) => {
      assert.match((err as Error).message, /no verdict/);
      assert.match((err as Error).message, /connection refused/);
      return true;
    });
  });
});
