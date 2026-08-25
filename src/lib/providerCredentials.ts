/**
 * Per-provider credentials for the OpenAI-compatible reviewer backend
 * (AGT-1138).
 *
 * The backend already spoke OpenAI-compatible `/chat/completions` with an
 * `Authorization: Bearer` header — it just never had a real key to put in
 * it, because `invokeLocalReviewer` constructed the client with only a base
 * URL. That single omission is what kept the path at "runs local Qwen"
 * instead of "runs any OpenAI-compatible provider". This module supplies the
 * missing half, and nothing more: no per-provider SDKs, no new transport.
 *
 * ## The one rule: a credential belongs to an endpoint, not to stamp
 *
 * Resolution is keyed on the **endpoint the request is about to hit**, never
 * on a single ambient "the API key". Pointing a reviewer at DeepSeek must not
 * send an OpenAI key — not because it would fail (it would), but because
 * shipping one vendor's secret to another vendor's server is a leak whether
 * or not it is accepted. So:
 *
 *   1. The endpoint's host determines a **provider id** (`openai`,
 *      `deepseek`, `local` for loopback, else the host itself).
 *   2. Only that provider's credential sources are consulted.
 *   3. A conventional vendor variable (`OPENAI_API_KEY`) is read ONLY when
 *      the endpoint is that vendor's own host. An arbitrary endpoint never
 *      receives a well-known vendor key, however it is configured.
 *
 * ## Back-compat is load-bearing
 *
 * `STAMP_REVIEWER_BACKEND=local` against localhost with no credential at all
 * must keep working byte-for-byte — the open-team and schnap-it flows run it
 * today. So a credential is *required* only for providers known to reject
 * unauthenticated requests (OpenAI, DeepSeek). Every other endpoint — a
 * loopback server, a LAN box, a corporate gateway — falls through to the
 * adapter's placeholder exactly as before when nothing is configured, and
 * picks up a key only if one was explicitly set for it.
 *
 * ## Secrets never travel with the backend descriptor
 *
 * Note what is NOT here: `ReviewerBackend` (lib/userConfig.ts) carries no
 * credential. That is deliberate. `ReviewerBackend` is printed by
 * `stamp config reviewers show`, mapped into `ReviewProvenance`, persisted
 * to `.git/stamp/state.db`, and signed into the attestation payload. A key
 * placed on it would reach all four by construction. Instead the key is
 * resolved at the invocation site, lives only as long as the request, and
 * every path that could echo it goes through `redactSecrets` first.
 */

import type { UserConfig } from "./userConfig.js";

/** Provider id used for any loopback endpoint (LM Studio, mlx_lm.server, …). */
export const LOOPBACK_PROVIDER_ID = "local";

/** Provider id when the endpoint is unparseable as a URL. */
export const UNKNOWN_PROVIDER_ID = "unknown";

/** Marker substituted for a secret in any text that gets printed or spooled. */
export const REDACTED_MARKER = "[redacted]";

/**
 * A provider stamp knows by name. Being on this list buys two things: the
 * conventional vendor env var is consulted for it, and a missing credential
 * is a hard, actionable failure rather than a silent fallback to the
 * placeholder (because the request is certain to come back 401).
 *
 * Hosts are matched exactly, lowercased, port-stripped. No suffix matching:
 * `api.openai.com.evil.test` must NOT be treated as OpenAI.
 */
interface KnownProvider {
  id: string;
  label: string;
  hosts: readonly string[];
  /** Conventional vendor variable, consulted only for this provider's hosts. */
  vendorEnv: string;
  /** Documentation URL fragment for the error message; kept short. */
  keyHint: string;
}

const KNOWN_PROVIDERS: readonly KnownProvider[] = [
  {
    id: "openai",
    label: "OpenAI",
    hosts: ["api.openai.com"],
    vendorEnv: "OPENAI_API_KEY",
    keyHint: "https://platform.openai.com/api-keys",
  },
  {
    id: "deepseek",
    label: "DeepSeek",
    hosts: ["api.deepseek.com"],
    vendorEnv: "DEEPSEEK_API_KEY",
    keyHint: "https://platform.deepseek.com/api_keys",
  },
];

/**
 * Hosts that mean "this box". A review against one of these sends nothing
 * off-host, which is the property the data-flow gate in `stamp review`
 * depends on — and the reason no credential is ever required for them.
 */
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set([
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "::1",
  "[::1]",
]);

/**
 * Derive a provider id from an OpenAI-compatible base URL.
 *
 * The id is what the credential is filed under: it names the env var
 * (`STAMP_<ID>_API_KEY`) and the `provider_keys:` config entry. Deriving it
 * from the host rather than taking it as separate configuration is what makes
 * "the DeepSeek key never goes to OpenAI" structural instead of a convention
 * the operator has to maintain.
 */
export function providerIdForEndpoint(endpoint: string): string {
  let host: string;
  try {
    host = new URL(endpoint).hostname.toLowerCase();
  } catch {
    return UNKNOWN_PROVIDER_ID;
  }
  if (host === "") return UNKNOWN_PROVIDER_ID;
  if (LOOPBACK_HOSTS.has(host)) return LOOPBACK_PROVIDER_ID;
  for (const p of KNOWN_PROVIDERS) {
    if (p.hosts.includes(host)) return p.id;
  }
  return host;
}

/**
 * Whether an endpoint is on this box.
 *
 * Load-bearing beyond credentials: `stamp review`'s AGT-415 data-flow gate
 * asks "does any reviewer's diff leave this host?", and before AGT-1138 the
 * answer for this backend was always "no" because the only reachable
 * endpoint was a local one. It is now reachable at api.openai.com, so the
 * question has to be asked of the endpoint rather than of the backend kind.
 *
 * An unparseable endpoint is NOT treated as loopback — the safe default for
 * a disclosure gate is to assume the data leaves.
 */
export function isLoopbackEndpoint(endpoint: string): boolean {
  return providerIdForEndpoint(endpoint) === LOOPBACK_PROVIDER_ID;
}

function knownProvider(id: string): KnownProvider | undefined {
  return KNOWN_PROVIDERS.find((p) => p.id === id);
}

/**
 * The stamp-namespaced env var that supplies a provider's credential, e.g.
 * `openai` → `STAMP_OPENAI_API_KEY`, `my-llm.corp.test` →
 * `STAMP_MY_LLM_CORP_TEST_API_KEY`. Deterministic from the provider id so an
 * operator can read the variable name straight off an error message.
 */
export function providerEnvVar(providerId: string): string {
  const slug = providerId.toUpperCase().replace(/[^A-Z0-9]+/g, "_");
  return `STAMP_${slug}_API_KEY`;
}

/**
 * Whether a request to this provider without a credential is certain to be
 * rejected. True only for providers stamp knows are authenticated; an
 * unrecognised host is given the benefit of the doubt so today's LAN and
 * gateway setups keep working untouched.
 */
export function providerRequiresCredential(providerId: string): boolean {
  return knownProvider(providerId) !== undefined;
}

/**
 * Outcome of credential resolution. `apiKey` is the only secret-bearing
 * field; `source` is a *variable name or config key*, never a value, so it
 * is safe to print, log, and put in an error message.
 */
export interface ResolvedCredential {
  /** Provider id the endpoint resolved to. */
  providerId: string;
  /** The credential, or null when none was configured for this provider. */
  apiKey: string | null;
  /** Where it came from (env var name / config key), or null when absent. */
  source: string | null;
  /** True when absence is a hard failure rather than a placeholder fallback. */
  required: boolean;
}

/**
 * Resolve the credential for an endpoint against an already-loaded config.
 *
 * Precedence, highest first:
 *
 *   1. `STAMP_<PROVIDER>_API_KEY` — per-run, per-provider, and the only form
 *      that works for an endpoint stamp does not recognise.
 *   2. the vendor's conventional variable (`OPENAI_API_KEY`,
 *      `DEEPSEEK_API_KEY`) — consulted ONLY when the endpoint is that
 *      vendor's own host, so an ambient key in the operator's shell cannot
 *      be forwarded somewhere it does not belong.
 *   3. `provider_keys.<provider>` in `~/.stamp/config.yml` — the persistent
 *      form, 0600 under a 0700 dir like every other secret stamp stores.
 *
 * Env before config is the same precedence the rest of the resolver uses
 * (`STAMP_LOCAL_ENDPOINT` beats `local_endpoint:`), and it keeps a
 * concurrent automation run from having to mutate the shared config file.
 */
export function resolveProviderCredentialFrom(
  cfg: UserConfig | null,
  endpoint: string,
  env: Record<string, string | undefined> = process.env,
): ResolvedCredential {
  const providerId = providerIdForEndpoint(endpoint);
  const required = providerRequiresCredential(providerId);

  const stampVar = providerEnvVar(providerId);
  const fromStampEnv = env[stampVar]?.trim();
  if (fromStampEnv) {
    return { providerId, apiKey: fromStampEnv, source: stampVar, required };
  }

  const known = knownProvider(providerId);
  if (known) {
    const fromVendorEnv = env[known.vendorEnv]?.trim();
    if (fromVendorEnv) {
      return {
        providerId,
        apiKey: fromVendorEnv,
        source: known.vendorEnv,
        required,
      };
    }
  }

  const fromConfig = cfg?.provider_keys?.[providerId]?.trim();
  if (fromConfig) {
    return {
      providerId,
      apiKey: fromConfig,
      source: `provider_keys.${providerId} in ~/.stamp/config.yml`,
      required,
    };
  }

  return { providerId, apiKey: null, source: null, required };
}

/**
 * The actionable "you have no credential for this endpoint" message (AC4).
 *
 * Names the endpoint, the provider it resolved to, and every place a key
 * could have come from — an operator who hits this should not have to read
 * source or docs to fix it. Contains no secret by construction: every value
 * in it is a URL, a provider id, or a variable name.
 */
export function missingCredentialMessage(
  endpoint: string,
  providerId: string,
): string {
  const known = knownProvider(providerId);
  const vendorPart = known ? ` (or ${known.vendorEnv})` : "";
  const label = known ? known.label : providerId;
  return (
    `no API credential for the openai-compatible reviewer endpoint ${endpoint} ` +
    `— it resolves to provider "${providerId}" (${label}), which rejects ` +
    `unauthenticated requests. Supply a key with ` +
    `${providerEnvVar(providerId)}=<key>${vendorPart} in the environment, or add ` +
    `a \`provider_keys:\` entry for "${providerId}" to ~/.stamp/config.yml` +
    (known ? ` — keys: ${known.keyHint}` : "") +
    `. Nothing is sent until a credential is available.`
  );
}

/**
 * The actionable "the endpoint rejected the credential" message (AC4).
 *
 * Split from the generic HTTP-error path because 401/403 has exactly one
 * cause worth naming and one fix worth suggesting, and because "which key
 * did we even send" is the operator's first question. Answered with the
 * SOURCE (a variable name), never the value.
 */
export function unauthorizedMessage(args: {
  endpoint: string;
  providerId: string;
  status: number;
  source: string | null;
}): string {
  const what =
    args.source === null
      ? `no credential was sent (none is configured for provider "${args.providerId}")`
      : `the credential from ${args.source} was rejected`;
  const fix =
    args.source === null
      ? `set ${providerEnvVar(args.providerId)}=<key> or add \`provider_keys.${args.providerId}\` to ~/.stamp/config.yml`
      : `check that the key in ${args.source} is valid for ${args.endpoint} and has not expired or been revoked`;
  return (
    `openai-compatible endpoint ${args.endpoint} returned HTTP ${args.status} ` +
    `(unauthorized) — ${what}. Provider "${args.providerId}": ${fix}.`
  );
}

/**
 * Replace every occurrence of each secret with `[redacted]`.
 *
 * Applied to anything derived from a provider response before it reaches an
 * error message, stdout/stderr, or a spool file. It exists for the case that
 * looks paranoid and is not: several OpenAI-compatible gateways echo the
 * presented bearer token back inside a 401 body, and that body is exactly
 * what the adapter truncates into its error string.
 *
 * Substring replacement rather than omission of the field: the surrounding
 * text ("model not loaded", the upstream's own explanation) is the reason
 * the snippet is surfaced at all, and dropping it to be safe would trade a
 * real diagnostic for a hypothetical one. Short values are skipped — a
 * 1-3 character "secret" would blank out unrelated text and tell an attacker
 * more by its blast radius than the value itself would.
 */
export function redactSecrets(
  text: string,
  secrets: ReadonlyArray<string | null | undefined>,
): string {
  let out = text;
  for (const s of secrets) {
    if (typeof s !== "string") continue;
    const trimmed = s.trim();
    if (trimmed.length < 4) continue;
    out = out.split(trimmed).join(REDACTED_MARKER);
  }
  return out;
}
