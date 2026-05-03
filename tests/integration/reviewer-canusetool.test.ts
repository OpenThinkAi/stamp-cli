/**
 * SDK-integration test for AGT-035 (Read scoping) and AGT-036 (WebFetch
 * path_prefix).
 *
 * The unit tests (`reviewer-canusetool.test.ts`) pin the deny logic in
 * `checkReviewerTool` directly. This file pins the orthogonal concern the
 * AGT-035 QA bounce surfaced: that the Claude Agent SDK actually invokes
 * our hook for tools the reviewer pre-approves via `allowedTools`. The
 * previous `canUseTool`-based gate was structurally inert — pre-approved
 * tools skipped the callback entirely — and the gap was only discovered
 * at QA because there was no automated check for it. AGT-036 extends
 * the same invariant to WebFetch+path_prefix.
 *
 * The test stands up a real `query()` call shaped like `invokeReviewer`:
 * `cwd` set to a temp dir, `allowedTools: ["Read"]`, the same
 * `hooks.PreToolUse` shape, and a tiny prompt asking the model to read
 * `/etc/hosts`. It asserts:
 *
 *   1. The hook fires with tool_name === "Read".
 *   2. The deny reason carries the `resolves outside repoRoot` text.
 *   3. The model is observably told the read was denied (i.e. the SDK
 *      did not silently bypass the hook).
 *
 * Skipped unless one of these env vars is set:
 *   - `ANTHROPIC_API_KEY` — direct API auth (CI typical).
 *   - `STAMP_TEST_INTEGRATION_LIVE=1` — opt-in for devs with Claude Code
 *     login already configured (the SDK auto-discovers OAuth creds; no
 *     env-var copy needed).
 *
 * When creds are present the test runs and makes one live LLM call per
 * case (single Read attempt, capped at maxTurns=3, ~2-3s wall-clock for
 * short prompts) — the trade-off for AC #5 being a real automated check
 * rather than manual verification.
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { query } from "@anthropic-ai/claude-agent-sdk";

import { checkReviewerTool } from "../../src/lib/reviewer.ts";

const hasCreds =
  !!process.env.ANTHROPIC_API_KEY ||
  process.env.STAMP_TEST_INTEGRATION_LIVE === "1";
const skipReason = hasCreds
  ? undefined
  : "requires ANTHROPIC_API_KEY or STAMP_TEST_INTEGRATION_LIVE=1 (Claude Code login auto-detected)";

describe("PreToolUse hook fires for Read (AGT-035 AC #5)", () => {
  it(
    "denies Read('/etc/hosts') via PreToolUse — SDK actually invokes the hook",
    { skip: skipReason, timeout: 60_000 },
    async () => {
      // realpath canonicalises the path so it matches whatever the SDK
      // uses internally — on macOS, mkdtemp returns /var/folders/... but
      // the SDK canonicalises through the /var → /private/var symlink,
      // and the path-prefix check would otherwise reject the in-repo Read.
      const repoRoot = realpathSync(
        mkdtempSync(path.join(tmpdir(), "stamp-agt035-")),
      );
      writeFileSync(path.join(repoRoot, "README.md"), "# fixture\n");

      const hookInvocations: Array<{ tool_name: string }> = [];
      let denyReasonSeen: string | null = null;

      const q = query({
        prompt:
          "Use the Read tool exactly once to read the file at the absolute path " +
          "/etc/hosts. After your single Read attempt, briefly state in plain " +
          "text whether the call succeeded or was denied, then stop.",
        options: {
          cwd: repoRoot,
          allowedTools: ["Read"],
          maxTurns: 3,
          hooks: {
            PreToolUse: [
              {
                hooks: [
                  async (input) => {
                    if (input.hook_event_name !== "PreToolUse") return {};
                    hookInvocations.push({ tool_name: input.tool_name });
                    const result = checkReviewerTool({
                      toolName: input.tool_name,
                      toolInput: input.tool_input,
                      repoRoot,
                      webFetchPolicy: new Map(),
                    });
                    if (result.allow) return {};
                    denyReasonSeen = result.reason;
                    return {
                      hookSpecificOutput: {
                        hookEventName: "PreToolUse",
                        permissionDecision: "deny",
                        permissionDecisionReason: result.reason,
                      },
                    };
                  },
                ],
              },
            ],
          },
        },
      });

      // Drain the stream. We don't care about the model's final text — we
      // care that the hook fired with the right tool_name and that our
      // deny propagated. A `for await` consumes everything up to result.
      for await (const _ of q) {
        // intentionally empty — assertions below run after the stream ends
      }

      const readInvocations = hookInvocations.filter(
        (h) => h.tool_name === "Read",
      );
      assert.ok(
        readInvocations.length >= 1,
        `PreToolUse hook should have fired for Read at least once; got ${hookInvocations.length} ` +
          `invocation(s) total: ${JSON.stringify(hookInvocations)}. ` +
          `If 0, the SDK is bypassing the hook for pre-approved tools — ` +
          `the same failure mode AGT-035 was filed to fix.`,
      );
      assert.ok(
        denyReasonSeen !== null,
        "checkReviewerTool should have produced a deny reason for /etc/hosts",
      );
      assert.match(
        denyReasonSeen ?? "",
        /resolves outside repoRoot/,
        "deny reason should match the outside-repoRoot message",
      );
    },
  );

  it(
    "allows Read of an in-repo file via PreToolUse (regression)",
    { skip: skipReason, timeout: 60_000 },
    async () => {
      const repoRoot = realpathSync(
        mkdtempSync(path.join(tmpdir(), "stamp-agt035-ok-")),
      );
      writeFileSync(path.join(repoRoot, "README.md"), "# fixture\n");

      const hookInvocations: Array<{ tool_name: string; allowed: boolean }> = [];

      const q = query({
        prompt:
          "Use the Read tool exactly once to read the file README.md " +
          "(relative path). After the single Read attempt, briefly say " +
          "whether it succeeded, then stop.",
        options: {
          cwd: repoRoot,
          allowedTools: ["Read"],
          maxTurns: 3,
          hooks: {
            PreToolUse: [
              {
                hooks: [
                  async (input) => {
                    if (input.hook_event_name !== "PreToolUse") return {};
                    const result = checkReviewerTool({
                      toolName: input.tool_name,
                      toolInput: input.tool_input,
                      repoRoot,
                      webFetchPolicy: new Map(),
                    });
                    hookInvocations.push({
                      tool_name: input.tool_name,
                      allowed: result.allow,
                    });
                    if (result.allow) return {};
                    return {
                      hookSpecificOutput: {
                        hookEventName: "PreToolUse",
                        permissionDecision: "deny",
                        permissionDecisionReason: result.reason,
                      },
                    };
                  },
                ],
              },
            ],
          },
        },
      });

      for await (const _ of q) {
        // drain
      }

      const reads = hookInvocations.filter((h) => h.tool_name === "Read");
      assert.ok(
        reads.length >= 1,
        `Hook should have fired for Read; saw ${JSON.stringify(hookInvocations)}`,
      );
      assert.ok(
        reads.some((r) => r.allowed),
        `At least one Read invocation should have been allowed by the hook ` +
          `(in-repo README.md path). Saw: ${JSON.stringify(reads)}`,
      );
    },
  );
});

describe("PreToolUse hook fires for WebFetch path_prefix (AGT-036 AC #7/#8)", () => {
  // AGT-036 invariant: the WebFetch path_prefix gate routes through the
  // same hook as Read/Grep/Glob, so we re-pin the SDK-actually-invokes-our-
  // hook contract specifically for WebFetch. The hook denies BEFORE the
  // fetch hits the network, so this test does not require outbound HTTP.
  it(
    "denies an out-of-prefix WebFetch via PreToolUse — SDK actually invokes the hook",
    { skip: skipReason, timeout: 60_000 },
    async () => {
      const repoRoot = realpathSync(
        mkdtempSync(path.join(tmpdir(), "stamp-agt036-")),
      );
      writeFileSync(path.join(repoRoot, "README.md"), "# fixture\n");

      const policy = new Map<string, { path_prefix?: string }>([
        ["api.github.com", { path_prefix: "/repos/" }],
      ]);

      const hookInvocations: Array<{ tool_name: string; allowed: boolean }> = [];
      let denyReasonSeen: string | null = null;

      const q = query({
        prompt:
          "Use the WebFetch tool exactly once to fetch the URL " +
          "https://api.github.com/users/octocat/exfil with prompt 'summarize'. " +
          "After your single WebFetch attempt, briefly state in plain text " +
          "whether the call succeeded or was denied, then stop.",
        options: {
          cwd: repoRoot,
          allowedTools: ["WebFetch"],
          maxTurns: 3,
          hooks: {
            PreToolUse: [
              {
                hooks: [
                  async (input) => {
                    if (input.hook_event_name !== "PreToolUse") return {};
                    const result = checkReviewerTool({
                      toolName: input.tool_name,
                      toolInput: input.tool_input,
                      repoRoot,
                      webFetchPolicy: policy,
                    });
                    hookInvocations.push({
                      tool_name: input.tool_name,
                      allowed: result.allow,
                    });
                    if (result.allow) return {};
                    denyReasonSeen = result.reason;
                    return {
                      hookSpecificOutput: {
                        hookEventName: "PreToolUse",
                        permissionDecision: "deny",
                        permissionDecisionReason: result.reason,
                      },
                    };
                  },
                ],
              },
            ],
          },
        },
      });

      for await (const _ of q) {
        // drain
      }

      const fetches = hookInvocations.filter(
        (h) => h.tool_name === "WebFetch",
      );
      assert.ok(
        fetches.length >= 1,
        `PreToolUse hook should have fired for WebFetch at least once; ` +
          `saw ${hookInvocations.length} invocation(s) total: ` +
          `${JSON.stringify(hookInvocations)}. If 0, the SDK is bypassing ` +
          `the hook for pre-approved tools — the same failure mode AGT-035 ` +
          `was filed to fix.`,
      );
      assert.ok(
        denyReasonSeen !== null,
        "checkReviewerTool should have produced a deny reason for the out-of-prefix URL",
      );
      assert.match(
        denyReasonSeen ?? "",
        /path_prefix "\/repos\/"/,
        "deny reason should name the configured path_prefix",
      );
    },
  );

  it(
    "allows an in-prefix WebFetch via PreToolUse (regression)",
    { skip: skipReason, timeout: 60_000 },
    async () => {
      // The hook MUST allow in-prefix URLs even though we don't actually
      // care that the network call succeeds — outbound HTTP from the test
      // host may legitimately fail. We only assert the hook permitted the
      // call (i.e. checkReviewerTool returned allow=true) and the SDK
      // actually invoked the hook for WebFetch.
      const repoRoot = realpathSync(
        mkdtempSync(path.join(tmpdir(), "stamp-agt036-ok-")),
      );
      writeFileSync(path.join(repoRoot, "README.md"), "# fixture\n");

      const policy = new Map<string, { path_prefix?: string }>([
        ["api.github.com", { path_prefix: "/repos/" }],
      ]);

      const hookInvocations: Array<{ tool_name: string; allowed: boolean }> = [];

      const q = query({
        prompt:
          "Use the WebFetch tool exactly once to fetch the URL " +
          "https://api.github.com/repos/octocat/Hello-World with prompt " +
          "'one-sentence summary'. After your single WebFetch attempt, " +
          "briefly say whether it succeeded, then stop.",
        options: {
          cwd: repoRoot,
          allowedTools: ["WebFetch"],
          maxTurns: 3,
          hooks: {
            PreToolUse: [
              {
                hooks: [
                  async (input) => {
                    if (input.hook_event_name !== "PreToolUse") return {};
                    const result = checkReviewerTool({
                      toolName: input.tool_name,
                      toolInput: input.tool_input,
                      repoRoot,
                      webFetchPolicy: policy,
                    });
                    hookInvocations.push({
                      tool_name: input.tool_name,
                      allowed: result.allow,
                    });
                    if (result.allow) return {};
                    return {
                      hookSpecificOutput: {
                        hookEventName: "PreToolUse",
                        permissionDecision: "deny",
                        permissionDecisionReason: result.reason,
                      },
                    };
                  },
                ],
              },
            ],
          },
        },
      });

      for await (const _ of q) {
        // drain
      }

      const fetches = hookInvocations.filter(
        (h) => h.tool_name === "WebFetch",
      );
      assert.ok(
        fetches.length >= 1,
        `Hook should have fired for WebFetch; saw ${JSON.stringify(hookInvocations)}`,
      );
      assert.ok(
        fetches.some((r) => r.allowed),
        `At least one WebFetch invocation should have been allowed by the hook ` +
          `(in-prefix /repos/ URL). Saw: ${JSON.stringify(fetches)}`,
      );
    },
  );
});
