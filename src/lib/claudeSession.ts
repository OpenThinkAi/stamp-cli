/**
 * Detect whether the current process is running inside an active Claude Code session.
 *
 * Claude Code sets these env vars in every process it spawns:
 *   CLAUDECODE=1
 *   CLAUDE_CODE_SESSION_ID=<uuid-or-hex string>
 *
 * The detection is intentionally lightweight (env-var only). Tightening to
 * parent-process introspection is deferred — env spoofing isn't a meaningful
 * threat for a no-trust-weight feature. The function is pure (takes env as an
 * argument) so tests don't need to mutate `process.env`.
 */

export interface ClaudeSession {
  sessionId: string;
}

/**
 * Probe `env` for an active Claude Code session.
 *
 * Returns `{ ok: true, session }` when:
 *   - `CLAUDECODE === "1"`, AND
 *   - `CLAUDE_CODE_SESSION_ID` is present and matches a hex/UUID-ish shape
 *     (`/^[0-9a-fA-F-]{8,}$/`)
 *
 * Returns `{ ok: false, reason }` otherwise.
 */
export function detectClaudeSession(
  env: NodeJS.ProcessEnv = process.env,
): { ok: true; session: ClaudeSession } | { ok: false; reason: string } {
  if (env["CLAUDECODE"] !== "1") {
    return { ok: false, reason: "CLAUDECODE env var is not set to '1'" };
  }
  const sessionId = env["CLAUDE_CODE_SESSION_ID"];
  if (!sessionId) {
    return { ok: false, reason: "CLAUDE_CODE_SESSION_ID env var is not set" };
  }
  if (!/^[0-9a-fA-F-]{8,}$/.test(sessionId)) {
    return {
      ok: false,
      reason: `CLAUDE_CODE_SESSION_ID value ${JSON.stringify(sessionId)} does not match expected hex/UUID shape`,
    };
  }
  return { ok: true, session: { sessionId } };
}
