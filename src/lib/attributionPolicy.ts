/**
 * AI-agent attribution policy (AGT-1724 / GH#81).
 *
 * A deterministic, opt-in commit-MESSAGE check that refuses commits
 * carrying AI-agent attribution — `Claude-Session:` trailers,
 * `Co-Authored-By: Claude …`, "Generated with Claude Code" footers,
 * `claude.ai/code/session_…` links. Reviewer prompts can't enforce this
 * reliably (they see the diff, and they're probabilistic); this is a
 * plain regex pass over commit messages, never over diffs.
 *
 * Shared by both enforcement points so they can't drift:
 *   - `stamp merge` (src/commands/merge.ts) — refuses before writing the
 *     merge commit, checking every commit in base..head plus the merge
 *     message.
 *   - the server `pre-receive` hook (src/hooks/pre-receive.ts) — rejects
 *     pushes whose NEWLY INTRODUCED commits match. Existing history never
 *     blocks a push.
 *
 * Toggle:
 *   - `STAMP_FORBID_AI_ATTRIBUTION=1` turns it on (off by default).
 *   - `.stamp/config.yml` may override per repo:
 *
 *       commit_policy:
 *         forbid_ai_attribution:
 *           enabled: true            # optional; overrides the env var either way
 *           extra_patterns:          # optional; literal strings added to the defaults
 *             - '^Assisted-By:'      #   (leading ^ = start of line)
 *           disable_patterns:        # optional; default pattern ids to drop
 *             - claude-ai-session-url
 *
 * Every pattern is applied case-insensitively to each LINE of the
 * message independently, so `^` anchors to the start of a line.
 *
 * `extra_patterns` are deliberately LITERAL strings, not regexes: they
 * run in the server hook against attacker-controllable message text, and
 * a user-authored regex there is a ReDoS vector (catastrophic
 * backtracking would hang every push). A literal case-insensitive
 * substring test is linear-time. Only the built-in defaults, which are
 * fixed and reviewed, are regexes.
 *
 * This module is imported by the CJS-bundled pre-receive hook, so it must
 * stay dependency-free (node built-ins only, no yaml — callers hand it
 * the already-parsed config object).
 */

export const ATTRIBUTION_ENV_VAR = "STAMP_FORBID_AI_ATTRIBUTION";

export interface AttributionPattern {
  /** Stable id — the handle `disable_patterns` refers to. */
  id: string;
  /** Pattern source as written (regex for defaults, literal for extras). */
  source: string;
  test: (line: string) => boolean;
}

function pattern(id: string, source: string): AttributionPattern {
  const regex = new RegExp(source, "i");
  return { id, source, test: (line) => regex.test(line) };
}

/**
 * Literal, case-insensitive substring match. A leading `^` anchors it to
 * the start of the line (leading whitespace ignored). Linear-time by
 * construction — see the module comment on why extras aren't regexes.
 */
function literalPattern(id: string, source: string): AttributionPattern {
  const anchored = source.startsWith("^");
  const needle = (anchored ? source.slice(1) : source).toLowerCase();
  return {
    id,
    source,
    test: (line) => {
      const hay = line.toLowerCase();
      return anchored ? hay.trimStart().startsWith(needle) : hay.includes(needle);
    },
  };
}

export const DEFAULT_ATTRIBUTION_PATTERNS: readonly AttributionPattern[] = [
  pattern("claude-session-trailer", "^\\s*Claude-Session:"),
  pattern(
    "co-authored-by-claude",
    "^\\s*Co-Authored-By:.*\\b(Claude|anthropic)\\b",
  ),
  pattern("generated-with-claude-code", "Generated with \\[?Claude Code"),
  pattern("claude-ai-session-url", "claude\\.ai/code/session_"),
];

export interface AttributionPolicyConfig {
  enabled?: boolean;
  extra_patterns?: string[];
  disable_patterns?: string[];
}

export interface ParsedAttributionConfig {
  config: AttributionPolicyConfig;
  /** Problems found while parsing. Callers decide whether these are fatal
   *  (`stamp merge` refuses) or advisory (the hook prints and continues
   *  with whatever parsed cleanly). */
  errors: string[];
}

const CONFIG_PATH = "commit_policy.forbid_ai_attribution";

/**
 * Extract and validate `commit_policy.forbid_ai_attribution` from a parsed
 * `.stamp/config.yml` object. Absent block → empty config, no errors.
 */
export function parseAttributionConfig(
  stampConfig: unknown,
): ParsedAttributionConfig {
  const errors: string[] = [];
  const config: AttributionPolicyConfig = {};
  if (!stampConfig || typeof stampConfig !== "object") {
    return { config, errors };
  }
  const commitPolicy = (stampConfig as Record<string, unknown>).commit_policy;
  if (commitPolicy === undefined || commitPolicy === null) {
    return { config, errors };
  }
  if (typeof commitPolicy !== "object" || Array.isArray(commitPolicy)) {
    errors.push("commit_policy must be a mapping");
    return { config, errors };
  }
  const block = (commitPolicy as Record<string, unknown>).forbid_ai_attribution;
  if (block === undefined || block === null) return { config, errors };
  if (typeof block === "boolean") {
    // Shorthand: `forbid_ai_attribution: true|false`.
    config.enabled = block;
    return { config, errors };
  }
  if (typeof block !== "object" || Array.isArray(block)) {
    errors.push(`${CONFIG_PATH} must be a boolean or a mapping`);
    return { config, errors };
  }
  const b = block as Record<string, unknown>;

  if (b.enabled !== undefined) {
    if (typeof b.enabled === "boolean") config.enabled = b.enabled;
    else errors.push(`${CONFIG_PATH}.enabled must be a boolean`);
  }

  if (b.extra_patterns !== undefined) {
    if (!Array.isArray(b.extra_patterns)) {
      errors.push(`${CONFIG_PATH}.extra_patterns must be a list of strings`);
    } else {
      const extra: string[] = [];
      b.extra_patterns.forEach((p, i) => {
        if (typeof p !== "string" || p.length === 0 || p === "^") {
          errors.push(`${CONFIG_PATH}.extra_patterns[${i}] must be a non-empty string`);
          return;
        }
        extra.push(p);
      });
      config.extra_patterns = extra;
    }
  }

  if (b.disable_patterns !== undefined) {
    if (!Array.isArray(b.disable_patterns)) {
      errors.push(`${CONFIG_PATH}.disable_patterns must be a list of pattern ids`);
    } else {
      const known = new Set(DEFAULT_ATTRIBUTION_PATTERNS.map((p) => p.id));
      const disable: string[] = [];
      for (const id of b.disable_patterns) {
        if (typeof id !== "string" || !known.has(id)) {
          errors.push(
            `${CONFIG_PATH}.disable_patterns: unknown pattern id ${JSON.stringify(id)} ` +
              `(known: ${[...known].join(", ")})`,
          );
          continue;
        }
        disable.push(id);
      }
      config.disable_patterns = disable;
    }
  }

  return { config, errors };
}

/** True iff the env var is set to an enabling value ("1" / "true" / "yes" / "on"). */
export function envEnablesAttributionPolicy(
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  const raw = env[ATTRIBUTION_ENV_VAR];
  if (raw === undefined) return false;
  return ["1", "true", "yes", "on"].includes(raw.trim().toLowerCase());
}

export interface ResolvedAttributionPolicy {
  enabled: boolean;
  patterns: AttributionPattern[];
}

/**
 * Combine the env toggle with the per-repo config. A repo-level
 * `enabled:` wins over the env var in either direction; otherwise the env
 * var decides.
 */
export function resolveAttributionPolicy(
  config: AttributionPolicyConfig,
  env: NodeJS.ProcessEnv = process.env,
): ResolvedAttributionPolicy {
  const enabled = config.enabled ?? envEnablesAttributionPolicy(env);
  const disabled = new Set(config.disable_patterns ?? []);
  const patterns = DEFAULT_ATTRIBUTION_PATTERNS.filter(
    (p) => !disabled.has(p.id),
  );
  (config.extra_patterns ?? []).forEach((src, i) => {
    patterns.push(literalPattern(`extra_patterns[${i}]`, src));
  });
  return { enabled, patterns };
}

export interface AttributionMatch {
  patternId: string;
  line: string;
}

/** Every (pattern, line) hit in one commit message. Empty → clean. */
export function findAttributionMatches(
  message: string,
  patterns: readonly AttributionPattern[],
): AttributionMatch[] {
  const matches: AttributionMatch[] = [];
  for (const line of message.split(/\r?\n/)) {
    for (const p of patterns) {
      if (p.test(line)) {
        matches.push({ patternId: p.id, line: line.trim() });
      }
    }
  }
  return matches;
}

export interface CommitMessage {
  sha: string;
  message: string;
}

export interface AttributionViolation {
  sha: string;
  subject: string;
  matches: AttributionMatch[];
}

export function scanCommitMessages(
  commits: readonly CommitMessage[],
  patterns: readonly AttributionPattern[],
): AttributionViolation[] {
  const out: AttributionViolation[] = [];
  for (const c of commits) {
    const matches = findAttributionMatches(c.message, patterns);
    if (matches.length > 0) {
      out.push({
        sha: c.sha,
        subject: c.message.split(/\r?\n/, 1)[0] ?? "",
        matches,
      });
    }
  }
  return out;
}

/**
 * Parse the output of
 *   git log -z --format=%H%n%B <range…>
 * (NUL-separated entries, SHA on the first line, raw body after) into
 * `{ sha, message }` records. Both call sites shell out to git with this
 * exact format so parsing lives in one place.
 */
export const COMMIT_MESSAGE_LOG_ARGS = ["log", "-z", "--format=%H%n%B"] as const;

export function parseCommitMessageLog(raw: string): CommitMessage[] {
  const out: CommitMessage[] = [];
  for (const entry of raw.split("\0")) {
    const trimmed = entry.replace(/^\n+/, "");
    if (!trimmed) continue;
    const nl = trimmed.indexOf("\n");
    const sha = (nl === -1 ? trimmed : trimmed.slice(0, nl)).trim();
    if (!/^[0-9a-f]{40,64}$/.test(sha)) continue;
    out.push({ sha, message: nl === -1 ? "" : trimmed.slice(nl + 1) });
  }
  return out;
}

/** Human-readable listing of each offending commit and the matched lines. */
export function formatViolations(violations: readonly AttributionViolation[]): string {
  const lines: string[] = [];
  for (const v of violations) {
    const id = /^[0-9a-f]+$/.test(v.sha) ? v.sha.slice(0, 12) : v.sha;
    lines.push(`${id} ${v.subject}`);
    for (const m of v.matches) {
      lines.push(`    [${m.patternId}] ${m.line}`);
    }
  }
  return lines.join("\n");
}
