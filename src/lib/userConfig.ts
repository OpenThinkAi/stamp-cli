/**
 * Per-user stamp config (~/.stamp/config.yml).
 *
 * Today's only knob is reviewer-model selection — the file lets an operator
 * decide which Anthropic model each reviewer (security/standards/product/…)
 * runs on, without committing that choice to the per-repo `.stamp/config.yml`
 * (which is hash-pinned via the v3 attestation chain). The intentional split
 * is "review policy as code" lives per-repo; "cost/speed tradeoff" lives
 * per-user.
 *
 * Format:
 *
 *   reviewers:
 *     security: claude-sonnet-4-6
 *     standards: claude-sonnet-4-6
 *     product:  claude-sonnet-4-6
 *
 * Every key under `reviewers:` is optional. A reviewer not listed here
 * resolves to `null` from `resolveReviewerModel`, which the SDK call site
 * translates to "let the agent SDK pick its own default" — current
 * behaviour for stamp-cli operators who haven't yet upgraded to a version
 * that knows about this file.
 *
 * Atomic writes (temp + rename) and 0o600 under a 0o700 ~/.stamp dir
 * mirror the posture used by ~/.stamp/server.yml and ~/.stamp/keys/.
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { userConfigPath } from "./paths.js";

export interface UserConfig {
  reviewers: Record<string, string>;
}

/**
 * Default reviewer-model assignments shipped to first-time operators.
 *
 * Sonnet across the board is the project-level default coming out of the
 * oteam-model-tiers planning: most reviewer work (standards-style nits,
 * AC-shaped product checks) is comfortably within Sonnet's ceiling, and
 * the 5-10× cost gap vs. Opus shows up loudly across multi-ticket runs.
 * Operators who want a sharper security reviewer can opt into Opus with
 * one command: `stamp config reviewers set security claude-opus-4-7`.
 *
 * Reviewer names that don't exist in the per-repo .stamp/config.yml here
 * are harmless — they're just unused entries the operator can clean up
 * with `stamp config reviewers clear <name>`. Mismatched names (e.g.
 * `securitee`) similarly degrade gracefully: the resolver returns null
 * for the actual reviewer name, falling back to the SDK default.
 */
export const DEFAULT_REVIEWER_MODELS: Readonly<Record<string, string>> = {
  security: "claude-sonnet-4-6",
  standards: "claude-sonnet-4-6",
  product: "claude-sonnet-4-6",
};

// Reviewer name shape, kept in sync with VALID_REVIEWER_NAME in
// src/commands/reviewers.ts. Validated at config-load (rejecting a malformed
// key) and at CLI-input time (`stamp config reviewers set <name>`) so the
// surface is uniform regardless of whether the user hand-edited or
// scripted the file.
const REVIEWER_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/;

// Model IDs are passed opaque-string into the agent SDK (`query({ model })`).
// We don't try to enum them — every Anthropic release would otherwise lag
// stamp-cli — but a minimal shape check catches obvious typos (empty, with
// embedded whitespace) at config-load rather than at API-call time. The
// regex permits the documented Anthropic ID shape (`claude-opus-4-7`,
// `claude-sonnet-4-6`, dated variants like `claude-haiku-4-5-20251001`)
// and equivalent forms; it is intentionally not anchored on the literal
// "claude-" prefix so that a future provider/proxy override would still
// land cleanly.
const MODEL_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/;

export function isValidReviewerName(name: string): boolean {
  return REVIEWER_NAME_RE.test(name);
}

export function isValidModelId(id: string): boolean {
  return MODEL_ID_RE.test(id) && id.length <= 128;
}

/**
 * Load and validate ~/.stamp/config.yml. Returns null when the file is
 * absent — callers that want defaults should prefer
 * `loadOrCreateUserConfig`. Throws on malformed content so a typo doesn't
 * silently degrade to "no per-user config" (which would be invisible until
 * the operator wonders why their reviewer model setting isn't taking
 * effect).
 */
export function loadUserConfig(): UserConfig | null {
  const path = userConfigPath();
  if (!existsSync(path)) return null;
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    throw new Error(
      `failed to read ${path}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  return parseUserConfig(raw, path);
}

/**
 * Parse a YAML blob and validate it as a UserConfig. Exposed separately
 * (rather than inlined into loadUserConfig) so tests can validate without
 * touching the filesystem.
 */
export function parseUserConfig(
  raw: string,
  contextPath = "<inline>",
): UserConfig {
  const trimmed = raw.trim();
  if (trimmed === "") {
    // An empty file is a legitimate "operator wrote nothing yet" state, not
    // an error. Fall through to an empty-reviewers config so the resolver
    // returns null for every reviewer and the SDK picks its own defaults.
    return { reviewers: {} };
  }
  const parsed = parseYaml(raw) as unknown;
  if (parsed === null || parsed === undefined) {
    return { reviewers: {} };
  }
  if (typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(
      `${contextPath}: must be a YAML mapping (got ${Array.isArray(parsed) ? "array" : typeof parsed})`,
    );
  }
  const obj = parsed as Record<string, unknown>;
  const reviewersRaw = obj.reviewers;
  const reviewers: Record<string, string> = {};
  if (reviewersRaw !== undefined && reviewersRaw !== null) {
    if (typeof reviewersRaw !== "object" || Array.isArray(reviewersRaw)) {
      throw new Error(
        `${contextPath}: 'reviewers' must be a mapping of <reviewer-name> to <model-id>`,
      );
    }
    for (const [name, value] of Object.entries(
      reviewersRaw as Record<string, unknown>,
    )) {
      if (!isValidReviewerName(name)) {
        throw new Error(
          `${contextPath}: reviewer name '${name}' under 'reviewers' is invalid ` +
            `(letters, digits, underscores, hyphens; max 64 chars; no leading hyphen)`,
        );
      }
      if (typeof value !== "string" || value.trim() === "") {
        throw new Error(
          `${contextPath}: reviewers.${name} must be a non-empty string (model id)`,
        );
      }
      const id = value.trim();
      if (!isValidModelId(id)) {
        throw new Error(
          `${contextPath}: reviewers.${name} = ${JSON.stringify(value)} is not a valid model id ` +
            `(expected a token like 'claude-sonnet-4-6'; the SDK accepts opaque strings, ` +
            `but stamp rejects shapes with whitespace or control chars)`,
        );
      }
      reviewers[name] = id;
    }
  }
  return { reviewers };
}

/**
 * Render a UserConfig back to YAML, suitable for writing to
 * `~/.stamp/config.yml`. Pure function so tests can pin the on-disk shape
 * without touching the filesystem. Stable key ordering is left to the
 * `yaml` package's defaults (insertion order).
 */
export function stringifyUserConfig(cfg: UserConfig): string {
  return stringifyYaml({ reviewers: cfg.reviewers });
}

/**
 * Atomic temp + rename write to `~/.stamp/config.yml` with 0o600 perms
 * under a 0o700 ~/.stamp directory. Mirrors the posture used by
 * ~/.stamp/server.yml + ~/.stamp/keys/. Crash mid-write doesn't leave a
 * half-written config that fails to parse on the next read.
 */
export function writeUserConfig(cfg: UserConfig): string {
  const path = userConfigPath();
  const dir = dirname(path);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = `${path}.tmp.${process.pid}`;
  writeFileSync(tmp, stringifyUserConfig(cfg), { mode: 0o600 });
  renameSync(tmp, path);
  return path;
}

/**
 * Load `~/.stamp/config.yml`, creating it with defaults if absent. Returns
 * `created: true` ONLY when the file was just written from defaults, so
 * the caller can surface a one-line "what's now configured" notice on
 * first run after upgrade.
 *
 * Idempotent: on the second call (file now exists), defaults are NOT
 * re-applied — operator customisation is preserved verbatim.
 */
export function loadOrCreateUserConfig(): {
  config: UserConfig;
  created: boolean;
  path: string;
} {
  const path = userConfigPath();
  const existed = existsSync(path);
  if (!existed) {
    const defaults: UserConfig = {
      reviewers: { ...DEFAULT_REVIEWER_MODELS },
    };
    writeUserConfig(defaults);
    return { config: defaults, created: true, path };
  }
  const config = loadUserConfig() ?? { reviewers: {} };
  return { config, created: false, path };
}

/**
 * Return the configured model id for a reviewer, or null if the operator
 * hasn't pinned one. The reviewer-spawning code threads the result into
 * the agent SDK's `query({ model })` option; null means "fall back to the
 * SDK's default", which preserves prior behaviour for operators who
 * haven't yet upgraded to a version that knows about ~/.stamp/config.yml.
 *
 * Errors loading the file are swallowed and treated as "no config" — the
 * resolver is on the hot path of every reviewer invocation, and a malformed
 * config shouldn't break the review. The CLI surface (`stamp config
 * reviewers show`) re-loads with throw-on-malformed semantics so operators
 * see the parse error when they explicitly inspect.
 */
export function resolveReviewerModel(reviewer: string): string | null {
  let cfg: UserConfig | null;
  try {
    cfg = loadUserConfig();
  } catch {
    return null;
  }
  if (!cfg) return null;
  const id = cfg.reviewers[reviewer];
  return typeof id === "string" && id.length > 0 ? id : null;
}

/**
 * Remove `~/.stamp/config.yml` (no-op if it doesn't exist). Used by the
 * `stamp config reviewers clear` CLI when the operator wants to wipe all
 * customisation back to "no per-user config" (resolver returns null,
 * agent SDK picks its own defaults).
 */
export function deleteUserConfig(): boolean {
  const path = userConfigPath();
  if (!existsSync(path)) return false;
  unlinkSync(path);
  return true;
}
