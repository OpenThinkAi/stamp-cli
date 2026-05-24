/**
 * `stamp peer test --event <fixture>` — dry-run the triage call (AGT-430 AC #7).
 *
 * Loads `~/.stamp/peer-watch.md`, reads the given event JSON fixture, runs
 * the Haiku triage call (via the injected seam or real SDK), and prints the
 * `TriageDecision` to stdout as pretty JSON.
 *
 * Exit codes (per design doc table):
 *   0   — success; TriageDecision printed to stdout
 *   1   — peer-watch.md missing or unreadable
 *   3   — Haiku/schema failure (triage returned skip due to API/parse error)
 */

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  runTriage,
  loadPeerWatchRules,
  SKIP_DECISION,
  type TriageDecision,
} from "../lib/peerTriage.js";

// ─── Input types ─────────────────────────────────────────────────────

export interface PeerTestOptions {
  /** Path to the event JSON fixture file. */
  eventPath: string;
  /** Working directory for the SDK call. */
  cwd?: string;
  /**
   * Test-only injection seam: replace the real Haiku SDK call.
   * Receives (systemPrompt, userMessage) and returns raw text response.
   */
  _haikuRunnerForTest?: (system: string, user: string) => Promise<string>;
  /**
   * Test-only injection seam: override the peer-watch.md loader.
   * Pass `null` to simulate a missing file.
   */
  _peerWatchRulesForTest?: { rules: string; hash: string } | null;
  /**
   * Test-only: override process.exit so tests can catch the exit code.
   * Defaults to the real `process.exit`.
   */
  _exitForTest?: (code: number) => never;
}

// ─── Command implementation ──────────────────────────────────────────

/**
 * Core implementation of `stamp peer test --event <fixture>`.
 *
 * Exported as a named function so tests can call it directly with injected
 * seams (no Commander wrapper needed in tests).
 */
export async function runPeerTest(opts: PeerTestOptions): Promise<void> {
  const exitFn = opts._exitForTest ?? ((code: number) => process.exit(code) as never);

  // ─── STAMP_NO_LLM guard (exit 3, design doc table) ───────────────────
  // Check before touching the SDK so the error is clean and there's only one
  // log line. runTriage also checks this env var, but checking it here first
  // avoids the double-log (⟳ from runTriage + ✗ from here) when STAMP_NO_LLM=1.
  if (process.env["STAMP_NO_LLM"] === "1" && !opts._haikuRunnerForTest) {
    process.stderr.write(`✗ dry-run failed: STAMP_NO_LLM=1 prevents triage call\n`);
    exitFn(3);
    return;
  }

  // ─── Load peer-watch.md ───────────────────────────────────────────
  let rulesResult: { rules: string; hash: string } | null;
  if (opts._peerWatchRulesForTest !== undefined) {
    rulesResult = opts._peerWatchRulesForTest;
  } else {
    rulesResult = loadPeerWatchRules();
  }

  if (rulesResult === null) {
    process.stderr.write(
      `✗ peer-watch.md not found at ~/.stamp/peer-watch.md\n` +
        `   Create the file with your triage rules, then retry.\n`,
    );
    exitFn(1);
    // TypeScript: exitFn returns `never`, but if _exitForTest throws something
    // else, fall through gracefully.
    return;
  }

  // ─── Read + parse the fixture ─────────────────────────────────────
  let fixtureRaw: string;
  try {
    fixtureRaw = readFileSync(opts.eventPath, "utf8");
  } catch (err) {
    process.stderr.write(
      `✗ cannot read event fixture ${JSON.stringify(opts.eventPath)}: ` +
        `${err instanceof Error ? err.message : String(err)}\n`,
    );
    exitFn(1);
    return;
  }

  let fixtureParsed: Record<string, unknown>;
  try {
    fixtureParsed = JSON.parse(fixtureRaw) as Record<string, unknown>;
  } catch (err) {
    process.stderr.write(
      `✗ event fixture is not valid JSON: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    exitFn(1);
    return;
  }

  // ─── Extract event fields ─────────────────────────────────────────
  const eventPayload = (
    typeof fixtureParsed["payload"] === "object" && fixtureParsed["payload"] !== null
      ? fixtureParsed["payload"]
      : fixtureParsed
  ) as Record<string, unknown>;

  const repo = typeof eventPayload["repo"] === "string" ? eventPayload["repo"] : "unknown/unknown";
  const title = typeof eventPayload["title"] === "string" ? eventPayload["title"] : "";
  const body =
    typeof eventPayload["body"] === "string"
      ? eventPayload["body"]
      : typeof eventPayload["diff"] === "string"
        ? eventPayload["diff"]
        : "";
  const paths: string[] = Array.isArray(eventPayload["paths_changed"])
    ? (eventPayload["paths_changed"] as unknown[]).filter((p): p is string => typeof p === "string")
    : [];

  // ─── Run triage ───────────────────────────────────────────────────
  const decision = await runTriage({
    rules: rulesResult.rules,
    event: { repo, title, body, paths },
    cwd: opts.cwd ?? process.cwd(),
    _haikuRunnerForTest: opts._haikuRunnerForTest,
  });

  // ─── Detect triage failure (AC #7 exit 3) ────────────────────────
  // Design-doc intent: exit 3 = "Haiku call fails (network/auth/schema)".
  // On the real-SDK path (no seam injected), a `skip` result is ambiguous —
  // it could mean the model decided to skip, or it could mean the call/parse
  // failed. The conservative choice is exit 3, consistent with the design
  // doc's intent that exit 3 covers network/auth/schema failures.
  //
  // The STAMP_NO_LLM path is already handled before the triage call above.
  if (decision.claim_seat === SKIP_DECISION.claim_seat &&
      decision.post_mode === SKIP_DECISION.post_mode &&
      decision.prompt === SKIP_DECISION.prompt &&
      !opts._haikuRunnerForTest) {
    // Real SDK path returned skip — likely a triage failure.
    process.stderr.write(`✗ triage call failed or returned skip; see stderr above\n`);
    exitFn(3);
    return;
  }

  // ─── Print result ─────────────────────────────────────────────────
  process.stdout.write(JSON.stringify(decision, null, 2) + "\n");
  exitFn(0);
}
