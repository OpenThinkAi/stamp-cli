import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { stampLlmNoticeMarkerPath } from "./paths.js";

/**
 * Print a one-line note about reviewer LLM data flow on the FIRST
 * `stamp review` per repo. Subsequent invocations stay quiet — the
 * marker file under .git/stamp/ records that the operator (or agent
 * harness) has already seen the disclosure for this repo.
 *
 * Every reviewer invocation ships the diff content to Anthropic via
 * the Claude Agent SDK. That's the data-flow contract operators need
 * to know about before pasting customer data, credentials, or
 * proprietary code into a branch they're about to review. Surfacing
 * this once (vs. burying it in README's License section) is the bar
 * the privacy spec asked for.
 *
 * Suppress unconditionally with STAMP_SUPPRESS_LLM_NOTICE=1 — agent
 * loops, CI workers, and operators who've baked the disclosure into
 * their team docs can set this in their environment.
 */
export function maybePrintLlmNotice(repoRoot: string): void {
  if (process.env.STAMP_SUPPRESS_LLM_NOTICE === "1") return;

  const marker = stampLlmNoticeMarkerPath(repoRoot);
  if (existsSync(marker)) return;

  // Print BEFORE writing the marker so a process killed mid-run still
  // re-shows the notice on the next attempt. Worst case: the operator
  // sees the notice twice — strictly preferable to silently missing it.
  process.stderr.write(
    "note: stamp review ships the diff to Anthropic via the Claude Agent SDK.\n" +
      "      See README \"Data flow / privacy\" for what's sent and how to opt out.\n" +
      "      Suppress this notice in future runs: STAMP_SUPPRESS_LLM_NOTICE=1\n" +
      "\n",
  );

  try {
    mkdirSync(dirname(marker), { recursive: true });
    writeFileSync(marker, `${new Date().toISOString()}\n`);
  } catch {
    // Marker write is best-effort. If we can't write, the worst outcome
    // is showing the notice again on the next run — not a correctness bug.
  }
}
