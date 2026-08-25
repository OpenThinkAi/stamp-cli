/**
 * Per-user stamp config (~/.stamp/config.yml).
 *
 * The file lets an operator decide which model each reviewer
 * (security/standards/product/…) runs on, and on which backend, without
 * committing that choice to the per-repo `.stamp/config.yml` (which is
 * hash-pinned via the v3 attestation chain). The intentional split is
 * "review policy as code" lives per-repo; "cost/speed tradeoff" and machine
 * infrastructure live per-user.
 *
 * Format:
 *
 *   reviewers:
 *     security: openai-compatible:gpt-5   # OpenAI-compatible endpoint
 *     standards: claude-sonnet-4-6        # Anthropic agent SDK
 *     product:  claude-sonnet-4-6
 *   openai_compatible_endpoint: https://api.openai.com/v1
 *   provider_keys:
 *     openai: sk-…
 *
 * Every key under `reviewers:` is optional. A reviewer not listed here
 * resolves to `null` from `resolveReviewerModel`, which the SDK call site
 * translates to "let the agent SDK pick its own default" — current
 * behaviour for stamp-cli operators who haven't yet upgraded to a version
 * that knows about this file.
 *
 * Atomic writes (temp + rename) and 0o600 under a 0o700 ~/.stamp dir
 * mirror the posture used by ~/.stamp/server.yml and ~/.stamp/keys/ — which
 * matters more since AGT-1138, because `provider_keys:` can hold an API key.
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
  /**
   * Base URL of the OpenAI-compatible model server a reviewer with the
   * `openai-compatible:` scheme talks to — a local one (LM Studio,
   * `mlx_lm.server`, vLLM) or a hosted one (OpenAI, DeepSeek). Optional;
   * when omitted the adapter falls back to its own default (LM Studio's
   * http://localhost:1234/v1). Machine-specific, which is exactly why it
   * lives here in per-user config rather than the hash-pinned per-repo
   * `.stamp/config.yml`.
   *
   * Canonical key. `local_endpoint:` below is the pre-AGT-1138 spelling and
   * still works; this one wins if both are present.
   */
  openai_compatible_endpoint?: string;
  /**
   * Legacy spelling of `openai_compatible_endpoint`. Kept working
   * unchanged — the open-team and schnap-it flows write it today. Preserved
   * verbatim on round-trip so `stamp config reviewers set` never silently
   * rewrites an operator's file into the new spelling.
   */
  local_endpoint?: string;
  /**
   * Enable the OpenAI `tools` / `submit_verdict` structured-verdict path.
   * Off by default because `mlx_lm.server` (the most common Apple-Silicon
   * backend) crashes server-side when `tools` are present. Flip on only for
   * a server you have verified accepts OpenAI function-calling correctly.
   * When off, the verdict falls through to the one-shot core's last-line
   * `VERDICT:` parser, which is reliable across every backend. Overridable
   * per-run via `STAMP_OPENAI_COMPATIBLE_TOOLS=1` (or the legacy
   * `STAMP_LOCAL_TOOLS=1`).
   *
   * Canonical key; `local_tools:` is the legacy alias.
   */
  openai_compatible_tools?: boolean;
  /** Legacy spelling of `openai_compatible_tools`. Still honoured. */
  local_tools?: boolean;
  /**
   * Per-provider API credentials for the openai-compatible backend
   * (AGT-1138), keyed by the provider id derived from the endpoint host —
   * `openai`, `deepseek`, or the host itself for anything stamp does not
   * recognise. See `lib/providerCredentials.ts` for resolution order.
   *
   *   provider_keys:
   *     openai: sk-…
   *     deepseek: sk-…
   *
   * This is the one place stamp's per-user config holds a secret, so it is
   * treated like one: never echoed by `stamp config reviewers show`, never
   * quoted back in a validation error, and written with the same 0600-under-
   * 0700 posture as the rest of the file. Prefer the env-var form
   * (`STAMP_<PROVIDER>_API_KEY`) where you have one — it keeps the secret
   * out of a file entirely.
   */
  provider_keys?: Record<string, string>;
}

/**
 * A reviewer's value under `reviewers:` may carry this scheme prefix to
 * route the review through the OpenAI-compatible backend instead of the
 * Anthropic API: `security: openai-compatible:gpt-5`. The suffix is the
 * model id the endpoint expects; the endpoint comes from
 * `openai_compatible_endpoint` (or the adapter default). This keeps the
 * existing `reviewers: { name: <string> }` shape — no structural config
 * change — while letting an operator move any reviewer off the metered path.
 */
export const OPENAI_COMPATIBLE_MODEL_PREFIX = "openai-compatible:";

/**
 * Pre-AGT-1138 spelling of `OPENAI_COMPATIBLE_MODEL_PREFIX`. `local:` was
 * accurate when the only reachable endpoint was a model on this box and is a
 * misnomer for a hosted DeepSeek one — but it is written into live
 * `~/.stamp/config.yml` files and into the open-team and schnap-it flows, so
 * it keeps resolving identically, forever. Renaming a concept is not a
 * licence to break the configs that used the old name.
 */
export const LOCAL_MODEL_PREFIX = "local:";

/** Both accepted `reviewers:` scheme prefixes, canonical first. */
const MODEL_PREFIXES = [
  OPENAI_COMPATIBLE_MODEL_PREFIX,
  LOCAL_MODEL_PREFIX,
] as const;

/**
 * Strip whichever backend scheme prefix a `reviewers:` value carries and
 * return the model id, or null when the value carries neither.
 */
function stripModelPrefix(raw: string): string | null {
  for (const prefix of MODEL_PREFIXES) {
    if (raw.startsWith(prefix)) return raw.slice(prefix.length).trim();
  }
  return null;
}

/**
 * The endpoint the openai-compatible backend will use, from config alone
 * (env overrides are applied by the resolver, which sits above this).
 * Canonical key wins; the legacy one is the fallback.
 */
export function configuredOpenAICompatibleEndpoint(
  cfg: UserConfig | null,
): string | undefined {
  return cfg?.openai_compatible_endpoint ?? cfg?.local_endpoint;
}

/**
 * Resolved execution backend for a reviewer. The trusted review path
 * branches on `kind`: `anthropic` runs the existing agent-SDK reviewer (or
 * SDK default when `model` is null); `openai-compatible` runs the one-shot
 * core against an OpenAI-compatible `/chat/completions` endpoint — a local
 * model (unmetered) or a hosted provider such as OpenAI or DeepSeek.
 *
 * `enableTools` (openai-compatible only): when true, the client sends the
 * `tools` field and prefers the `submit_verdict` structured-verdict path;
 * when false (the default), tools are suppressed and the one-shot core's
 * `VERDICT:` text fallback is used instead — safe for backends (like
 * `mlx_lm.server`) that crash on the OpenAI tools param.
 *
 * **No credential lives on this type**, by design. This object is printed by
 * `stamp config reviewers show`, mapped into `ReviewProvenance`, written to
 * `state.db`, and signed into the attestation payload; an `apiKey` field
 * here would reach all four for free. Credentials are resolved separately,
 * at the invocation site — see `lib/providerCredentials.ts`.
 */
export type ReviewerBackend =
  | { kind: "anthropic"; model: string | null }
  | {
      kind: "openai-compatible";
      model: string;
      endpoint: string | undefined;
      enableTools: boolean;
    };

/** The `ReviewerBackend["kind"]` for the OpenAI-compatible one-shot path. */
export const BACKEND_KIND_OPENAI_COMPATIBLE = "openai-compatible";

/**
 * The accepted values for `stamp review --backend` / `STAMP_REVIEWER_BACKEND`
 * (canonical + the legacy `local` alias). Shared by the CLI's parse-time
 * validation (AGT-1139 AC5) and anything that needs to render the accepted
 * set in a usage error.
 */
export const REVIEWER_BACKEND_FLAG_VALUES = [
  "anthropic",
  BACKEND_KIND_OPENAI_COMPATIBLE,
  "local",
] as const;

/**
 * `stamp review --backend` / `--model` / `--endpoint` (AGT-1139): a per-run,
 * per-invocation override that sits ABOVE the env-var tier the resolver
 * already has (`STAMP_REVIEWER_BACKEND` / `STAMP_OPENAI_COMPATIBLE_*` /
 * `STAMP_LOCAL_*`), giving the full precedence chain flag > env > config >
 * default. It is not a second selection mechanism — it is threaded straight
 * into `resolveReviewerBackendFrom`, the same function every other tier
 * already resolves through, and it applies uniformly to every reviewer in
 * the run (the same way the env-var tier already does).
 *
 * Deliberately carries no credential and is never persisted: the CLI layer
 * builds this from `process.argv`-derived flags each run and it is not
 * written to `~/.stamp/config.yml` (AC2). `undefined` in every field is
 * indistinguishable from "no override was passed" — every existing caller
 * that omits the parameter sees byte-identical behaviour to before this type
 * existed.
 */
export interface ReviewerBackendOverride {
  /** `--backend`. One of `REVIEWER_BACKEND_FLAG_VALUES`, case-insensitive. */
  backend?: string;
  /** `--model`. Applies to whichever kind the backend resolves to. */
  model?: string;
  /**
   * `--endpoint`. Only meaningful for the openai-compatible kind; the CLI
   * layer rejects `--endpoint` combined with `--backend anthropic` at parse
   * time (AC5) before this ever reaches the resolver.
   */
  endpoint?: string;
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

  // Optional endpoint, under either spelling. Validated as an http(s) URL so
  // a typo surfaces at config-load rather than as a confusing fetch error
  // mid-review. Absence is fine — the adapter has its own default. Both keys
  // are parsed and preserved independently; the resolver prefers the
  // canonical one, and round-tripping keeps an operator's chosen spelling.
  const openai_compatible_endpoint = parseEndpointField(
    obj.openai_compatible_endpoint,
    "openai_compatible_endpoint",
    contextPath,
  );
  const local_endpoint = parseEndpointField(
    obj.local_endpoint,
    "local_endpoint",
    contextPath,
  );

  // Optional tools flag, under either spelling. Controls whether the
  // openai-compatible reviewer sends the OpenAI `tools` field (enabling the
  // structured submit_verdict path). Defaults to false (tools off) — safe
  // for mlx_lm.server which crashes on the tools param. Flip on only for a
  // verified tool-capable server.
  const openai_compatible_tools = parseBooleanField(
    obj.openai_compatible_tools,
    "openai_compatible_tools",
    contextPath,
  );
  const local_tools = parseBooleanField(
    obj.local_tools,
    "local_tools",
    contextPath,
  );

  // Optional per-provider credentials (AGT-1138). Validation deliberately
  // never quotes the VALUE back in an error message — every other field in
  // this parser does (`reviewers.x = "…" is not a valid model id`), and
  // doing it here would print an operator's API key to stderr the first time
  // they fat-fingered the YAML.
  let provider_keys: Record<string, string> | undefined;
  const providerKeysRaw = obj.provider_keys;
  if (providerKeysRaw !== undefined && providerKeysRaw !== null) {
    if (typeof providerKeysRaw !== "object" || Array.isArray(providerKeysRaw)) {
      throw new Error(
        `${contextPath}: 'provider_keys' must be a mapping of <provider-id> to <api-key>`,
      );
    }
    const keys: Record<string, string> = {};
    for (const [provider, value] of Object.entries(
      providerKeysRaw as Record<string, unknown>,
    )) {
      if (!PROVIDER_ID_RE.test(provider)) {
        throw new Error(
          `${contextPath}: provider_keys key '${provider}' is invalid ` +
            `(expected a provider id like 'openai', 'deepseek', or an endpoint host)`,
        );
      }
      if (typeof value !== "string" || value.trim() === "") {
        throw new Error(
          `${contextPath}: provider_keys.${provider} must be a non-empty string ` +
            `(an API key; its value is deliberately not echoed here)`,
        );
      }
      keys[provider] = value.trim();
    }
    if (Object.keys(keys).length > 0) provider_keys = keys;
  }

  const result: UserConfig = { reviewers };
  if (openai_compatible_endpoint !== undefined)
    result.openai_compatible_endpoint = openai_compatible_endpoint;
  if (local_endpoint !== undefined) result.local_endpoint = local_endpoint;
  if (openai_compatible_tools !== undefined)
    result.openai_compatible_tools = openai_compatible_tools;
  if (local_tools !== undefined) result.local_tools = local_tools;
  if (provider_keys !== undefined) result.provider_keys = provider_keys;
  return result;
}

// Provider ids are derived from endpoint hosts (see providerCredentials.ts),
// so the accepted shape is "hostname or simple token" — letters, digits,
// dots, hyphens. Deliberately excludes whitespace and control characters so
// a malformed key can't smuggle a newline into a rendered message.
const PROVIDER_ID_RE = /^[a-zA-Z0-9][a-zA-Z0-9.\-_]{0,127}$/;

/** Shared validation for the two endpoint spellings. */
function parseEndpointField(
  raw: unknown,
  key: string,
  contextPath: string,
): string | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (typeof raw !== "string" || raw.trim() === "") {
    throw new Error(
      `${contextPath}: ${key} must be a non-empty string (an OpenAI-compatible base URL like 'http://localhost:1234/v1')`,
    );
  }
  const url = raw.trim();
  if (!/^https?:\/\//.test(url)) {
    throw new Error(
      `${contextPath}: ${key} = ${JSON.stringify(raw)} must be an http(s) URL ` +
        `(e.g. 'http://localhost:1234/v1' for LM Studio, 'https://api.openai.com/v1' for OpenAI)`,
    );
  }
  return url;
}

/** Shared validation for the two tools-flag spellings. */
function parseBooleanField(
  raw: unknown,
  key: string,
  contextPath: string,
): boolean | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (typeof raw !== "boolean") {
    throw new Error(`${contextPath}: ${key} must be a boolean (true or false)`);
  }
  return raw;
}

/**
 * Render a UserConfig back to YAML, suitable for writing to
 * `~/.stamp/config.yml`. Pure function so tests can pin the on-disk shape
 * without touching the filesystem. Stable key ordering is left to the
 * `yaml` package's defaults (insertion order).
 */
export function stringifyUserConfig(cfg: UserConfig): string {
  const out: Record<string, unknown> = { reviewers: cfg.reviewers };
  // Every optional field is written back under the SAME key it was read
  // from. `stamp config reviewers set` loads, mutates, and rewrites the
  // whole file, so normalising the legacy spellings here would silently
  // rewrite a working operator config — and `provider_keys` dropping out
  // would silently delete their credentials.
  if (cfg.openai_compatible_endpoint !== undefined)
    out.openai_compatible_endpoint = cfg.openai_compatible_endpoint;
  if (cfg.local_endpoint !== undefined) out.local_endpoint = cfg.local_endpoint;
  if (cfg.openai_compatible_tools !== undefined)
    out.openai_compatible_tools = cfg.openai_compatible_tools;
  if (cfg.local_tools !== undefined) out.local_tools = cfg.local_tools;
  if (cfg.provider_keys !== undefined) out.provider_keys = cfg.provider_keys;
  return stringifyYaml(out);
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
  // Anthropic callers (the agent-SDK reviewer, the headless path) must never
  // receive a `local:` value as a model id — it would fail at API-call time.
  // Delegate to the backend resolver and surface a model only for the
  // anthropic kind; local-configured reviewers resolve to null here (SDK
  // default), and the trusted path routes them to the openai-compatible
  // backend instead.
  const backend = resolveReviewerBackend(reviewer);
  return backend.kind === "anthropic" ? backend.model : null;
}

/**
 * Resolve a reviewer's execution backend from `~/.stamp/config.yml`. A
 * value with the `local:` scheme prefix routes to the local OpenAI-
 * compatible endpoint; anything else is an Anthropic model id (or null when
 * unset → SDK default).
 *
 * `override` (AGT-1139): `stamp review --backend` / `--model` / `--endpoint`,
 * threaded straight through to `resolveReviewerBackendFrom` — see that
 * function for the precedence this adds. Omitted by every caller that
 * predates the flags, so behaviour is unchanged when no flag is passed.
 *
 * Errors loading the file are swallowed and treated as "no config / SDK
 * default" — this is on the hot path of every reviewer invocation, and a
 * malformed config shouldn't break the review. The CLI surface (`stamp
 * config reviewers show`) re-loads with throw-on-malformed semantics so
 * operators see the parse error when they explicitly inspect.
 */
export function resolveReviewerBackend(
  reviewer: string,
  override?: ReviewerBackendOverride,
): ReviewerBackend {
  let cfg: UserConfig | null;
  try {
    cfg = loadUserConfig();
  } catch {
    cfg = null;
  }
  return resolveReviewerBackendFrom(cfg, reviewer, override);
}

/**
 * The pure half of `resolveReviewerBackend`: resolve against an already-loaded
 * config instead of reading `~/.stamp/config.yml`.
 *
 * Split out for `stamp config reviewers show` (AGT-1137), which has to report
 * the backend that will ACTUALLY run for each reviewer — including on a
 * machine with no config file yet, where the next `stamp review` will write
 * `DEFAULT_REVIEWER_MODELS` before resolving. Reporting against the defaults
 * it is about to write is the only way `show` answers "what will happen"
 * rather than "what have I typed". Also makes the resolution rules testable
 * without touching the filesystem.
 *
 * Env-var precedence (`STAMP_REVIEWER_BACKEND`, `STAMP_LOCAL_*`) is honored
 * here, not in the loader, so it applies identically on both paths.
 *
 * `override` (AGT-1139) adds a FOURTH tier above env, giving the full chain
 * `--backend`/`--model`/`--endpoint` flag > env var > config > default. It is
 * not a parallel resolution path: every branch below reads `override.model`
 * / `override.endpoint` at the same point it already reads the env var and
 * config equivalents, so `undefined` fields (the case for every pre-AGT-1139
 * caller, which doesn't pass a third argument at all) fall through to
 * exactly the logic that existed before this parameter did.
 */
export function resolveReviewerBackendFrom(
  cfg: UserConfig | null,
  reviewer: string,
  override?: ReviewerBackendOverride,
): ReviewerBackend {
  const raw = cfg?.reviewers[reviewer];
  const modelOverride = override?.model?.trim() || undefined;
  const endpointOverride = override?.endpoint?.trim() || undefined;

  // Operator override via `--backend` (highest) or STAMP_REVIEWER_BACKEND
  // (next) — force a backend per-run regardless of config, and crucially
  // WITHOUT mutating the shared ~/.stamp/config.yml (which would collide
  // across concurrent runs, e.g. open-team's autonomous dispatch). Accepted
  // values:
  //   anthropic         — force the agent-SDK path (logged-in Claude session).
  //   openai-compatible — force the one-shot OpenAI-compatible backend.
  //   local             — legacy alias for openai-compatible; still honoured.
  const backendOverride = (
    override?.backend?.trim() || process.env.STAMP_REVIEWER_BACKEND?.trim()
  )?.toLowerCase();
  if (backendOverride === "anthropic") {
    // `--model` wins outright. Otherwise: an `openai-compatible:` / `local:`
    // config value carries a model id that isn't valid for Anthropic, so it
    // drops to null (SDK default); a real Anthropic model id is preserved.
    if (modelOverride) return { kind: "anthropic", model: modelOverride };
    return typeof raw === "string" &&
      raw.length > 0 &&
      stripModelPrefix(raw) === null
      ? { kind: "anthropic", model: raw }
      : { kind: "anthropic", model: null };
  }
  if (
    backendOverride === BACKEND_KIND_OPENAI_COMPATIBLE ||
    backendOverride === "local"
  ) {
    // Model: `--model` wins; then STAMP_OPENAI_COMPATIBLE_MODEL (or legacy
    // STAMP_LOCAL_MODEL); else the reviewer's configured scheme value
    // (prefix stripped). Endpoint: `--endpoint` wins; then
    // STAMP_OPENAI_COMPATIBLE_ENDPOINT (or legacy STAMP_LOCAL_ENDPOINT);
    // else the configured endpoint; else undefined (the adapter's own
    // default). If no model can be resolved at all, fall back to the
    // anthropic default rather than handing the endpoint an empty model.
    const envModel = firstEnv([
      "STAMP_OPENAI_COMPATIBLE_MODEL",
      "STAMP_LOCAL_MODEL",
    ]);
    const cfgModel = typeof raw === "string" ? stripModelPrefix(raw) : null;
    const model = modelOverride ?? envModel ?? cfgModel ?? "";
    if (!model) return { kind: "anthropic", model: null };
    const endpoint =
      endpointOverride ??
      firstEnv(["STAMP_OPENAI_COMPATIBLE_ENDPOINT", "STAMP_LOCAL_ENDPOINT"]) ??
      configuredOpenAICompatibleEndpoint(cfg);
    const enableTools = resolveOpenAICompatibleTools(cfg);
    return {
      kind: BACKEND_KIND_OPENAI_COMPATIBLE,
      model,
      endpoint,
      enableTools,
    };
  }

  if (typeof raw !== "string" || raw.length === 0) {
    // No config entry and no `--backend` forcing a kind. A bare `--model`
    // pins the Anthropic model id (the default kind); a bare `--endpoint`
    // has nothing to attach to here (the CLI already rejects `--endpoint`
    // with `--backend anthropic` at parse time, and with no config entry
    // there is no openai-compatible kind for it to apply to either).
    return { kind: "anthropic", model: modelOverride ?? null };
  }
  const schemeModel = stripModelPrefix(raw);
  if (schemeModel !== null) {
    // A bare `openai-compatible:` / `local:` with no model id is a
    // misconfiguration; fall back to anthropic-default rather than handing
    // the endpoint an empty model. `--model` can still supply one.
    if (schemeModel.length === 0 && !modelOverride) {
      return { kind: "anthropic", model: null };
    }
    const enableTools = resolveOpenAICompatibleTools(cfg);
    return {
      kind: BACKEND_KIND_OPENAI_COMPATIBLE,
      model: modelOverride ?? schemeModel,
      // `--endpoint` wins outright here too — an operator pointing a
      // config-selected openai-compatible reviewer at a different endpoint
      // for one run is exactly the flag's job. Below that: config-only,
      // deliberately — this is the pre-existing config-driven branch and
      // STAMP_LOCAL_ENDPOINT has never applied to it. Honouring the env var
      // here would change which endpoint an existing setup hits whenever
      // the operator has that variable exported for something else — a
      // silent redirect of review traffic is not a back-compat-safe change
      // to smuggle into a rename ticket. (The forced-backend branch above
      // reads env because it always has.)
      endpoint: endpointOverride ?? configuredOpenAICompatibleEndpoint(cfg),
      enableTools,
    };
  }
  return { kind: "anthropic", model: modelOverride ?? raw };
}

/**
 * First non-empty value among a list of env var names, canonical name first.
 * Returns undefined when none is set, so callers can `??` onward to config.
 */
function firstEnv(names: readonly string[]): string | undefined {
  for (const name of names) {
    const v = process.env[name]?.trim();
    if (v) return v;
  }
  return undefined;
}

/**
 * Resolve whether tools should be enabled for the openai-compatible
 * reviewer. The default is `false` (tools off — safe for mlx_lm.server which
 * crashes on the OpenAI tools param). Opt in via:
 *   - `STAMP_OPENAI_COMPATIBLE_TOOLS=1` (or legacy `STAMP_LOCAL_TOOLS=1`)
 *     env var (per-run, highest precedence), or
 *   - `openai_compatible_tools: true` (or legacy `local_tools: true`) in
 *     `~/.stamp/config.yml` (per-machine persistent).
 * Any truthy-looking value for the env var counts: "1", "true", "yes".
 */
function resolveOpenAICompatibleTools(cfg: UserConfig | null): boolean {
  const envVal = firstEnv([
    "STAMP_OPENAI_COMPATIBLE_TOOLS",
    "STAMP_LOCAL_TOOLS",
  ])?.toLowerCase();
  if (envVal === "1" || envVal === "true" || envVal === "yes") return true;
  return (cfg?.openai_compatible_tools ?? cfg?.local_tools) === true;
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
