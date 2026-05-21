/**
 * Server-side canonical reviewer-prompt fetch — the load-bearing security
 * step of server-attested reviews (stamp 2.x).
 *
 * The trust property of server-attested reviews collapses unless the SERVER
 * (not the client) controls which prompt bytes get fed to the LLM. If the
 * client could supply the prompt the substitution attack returns: an
 * operator passes a permissive prompt to the LLM, but embeds the canonical
 * prompt's hash in the attestation, and the verifier sees a perfectly
 * consistent claim about a real LLM call that bears no relationship to what
 * the model actually read.
 *
 * This module is the choke point. AGT-370 moved the prompt source from
 * a server-side bare git clone to a server-side filesystem cache
 * populated out-of-band (HiveDB writes reviewer prompts directly into
 * `STAMP_PROMPTS_DIR`; see the parallel HiveDB reconfig ticket). The
 * fetch reads `${cacheRoot}/<reviewer>.md` synchronously via
 * `fs.readFileSync` — never via `git show`, never with a caller-
 * controlled fallback, never from anywhere outside the resolver-returned
 * path.
 *
 * The AGT-330 SSH-verb handler (and the future HTTP handler) calls this
 * exactly once per review request and pipes the returned bytes directly
 * into the Anthropic system message; the resulting `prompt_sha256` lives
 * inside the `ApprovalV4` body that the server then signs.
 *
 * --- Why no fallback parameter ---
 *
 * The module's surface deliberately offers no way to pass a substitute
 * prompt, an override path, an extra search root, or a "use this if the
 * fetch fails" fallback. Adding any such knob — even one gated behind a
 * dev-only flag — would re-open the substitution attack. The whole point
 * of moving the fetch server-side is that the (reviewer_name) tuple is
 * the ONLY input that determines what the server reads. Anything else,
 * by construction, is forbidden.
 *
 * If the fetch fails for any reason (no such file, filesystem error),
 * this module returns a typed error and the verb handler maps it to a
 * clean SSH response. Falling back to a different prompt is forbidden.
 *
 * --- Routing via injected resolver ---
 *
 * The default Phase-1 resolver maps `(reviewer)` → `${cacheRoot}/<reviewer>.md`.
 * Multi-tenant SaaS deployments inject a custom resolver that translates
 * `(reviewer)` into a tenant-aware path (e.g. `<state>/<tenant-id>/<reviewer>.md`);
 * the rest of this module — file read, error mapping, hashing — stays
 * identical. The resolver is a synchronous pure function returning a
 * string path: no I/O (no `existsSync`, no network) — keeping it pure
 * means the handler can pre-compute the path for logging before we hit
 * the fetch, and test injection becomes trivial. Existence checks
 * happen via the file read itself (an absent file surfaces as
 * `no_such_file`).
 *
 * --- Hash convention ---
 *
 * `FetchedPrompt.sha256` is BARE HEX (no `sha256:` prefix), matching
 * `ApprovalV4.prompt_sha256` in `src/lib/attestationV4.ts`. This is the
 * opposite convention from `src/lib/trustedKeysManifest.ts`, which uses
 * `sha256:<hex>` for KEY fingerprints — different field, different
 * convention, do not conflate. The caller folds this value directly into
 * the approval body before canonical serialization + signing.
 */

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

// Circular-by-name import (prompts-cache.ts re-exports REVIEWER_NAME_RE
// from this module): safe because `getPromptPath` is only invoked
// inside the resolver closure at request time, never at module-load
// time. ESM resolves the binding lazily — both modules' top-level
// initialization completes before any closure body runs. See AGT-373
// for the design rationale (single source of truth for path layout
// lives in prompts-cache.ts).
import { getPromptPath } from "./prompts-cache.js";

/**
 * Resolves a `(reviewer, org?, repo?)` tuple to the absolute path of
 * the prompt file on this server's filesystem.
 *
 * AGT-373 (Phase B) widened the signature from `(reviewer) => path` to
 * `(reviewer, org?, repo?) => path` so per-repo prompt overrides
 * (`<cacheRoot>/<org>/<repo>/<reviewer>.md`) can take precedence over
 * the cache-root-level default (`<cacheRoot>/<reviewer>.md`) when both
 * exist. `org` and `repo` are optional so existing Phase A callsites
 * that don't carry repo context still compile — a single-arg call
 * gets the fallback path.
 *
 * Synchronous — but NOT strictly pure under AGT-373: the default
 * resolver calls `existsSync` once to decide between the override and
 * the fallback path. Multi-tenant resolvers MAY remain pure if their
 * tenancy model doesn't need a stat. No thrown errors for "not
 * found" — an absent path surfaces naturally as `no_such_file` from
 * the read in `fetchCanonicalPrompt`.
 *
 * The default `defaultPromptCacheResolver` delegates to `getPromptPath`
 * from `prompts-cache.ts`, which validates the reviewer name against
 * `REVIEWER_NAME_RE` (the same regex `src/commands/reviewers.ts`
 * enforces) and the org/repo slugs against a slightly broader shape.
 * Multi-tenant resolvers do whatever path layout their tenancy model
 * requires; they MUST validate any input that gets interpolated into
 * a filesystem path.
 */
export type PromptResolver = (
  reviewer: string,
  org?: string,
  repo?: string,
) => string;

/**
 * The successful fetch result. `bytes` is the raw `.md` file content as
 * read from disk — no normalization, no trimming, no line-ending fixes.
 * Whatever is on disk is what the LLM sees and what the hash binds.
 * `sha256` is bare hex (see file-header doc).
 */
export interface FetchedPrompt {
  kind: "ok";
  bytes: Buffer;
  /** Hex sha256 of `bytes`. Bare — no `sha256:` prefix. Matches the
   *  `ApprovalV4.prompt_sha256` convention in `src/lib/attestationV4.ts`. */
  sha256: string;
}

/**
 * Typed failure mode. Each `kind` maps to a stable client-facing error
 * category; the verb handler translates these to SSH responses.
 *
 * `detail` is server-side diagnostic surface — log it, do NOT surface it
 * verbatim to the caller (filesystem error messages can leak server
 * filesystem layout). The verb handler should respond with a generic
 * "<kind>: not available" message and rely on operator-visible logs for
 * the detail.
 *
 * Categories:
 *   - `no_such_file`         — resolver returned a path; the file does
 *                              not exist there. The reviewer isn't
 *                              provisioned in the prompt cache, or the
 *                              reviewer name is misspelled. AGT-370:
 *                              this is the dominant failure now that
 *                              prompts live in a filesystem cache
 *                              rather than a bare git repo.
 *   - `invalid_input`        — `reviewer_name` failed shape validation.
 *                              Caller bug or attempted injection.
 *   - `io_error`             — filesystem read failed for a reason
 *                              other than ENOENT (permission denied,
 *                              I/O error, file too large, etc.).
 *                              Operator-actionable.
 */
export interface PromptFetchError {
  kind: "no_such_file" | "invalid_input" | "io_error";
  detail: string;
}

export type PromptFetchResult = FetchedPrompt | PromptFetchError;

// ─── Limits ─────────────────────────────────────────────────────────

/** Hard cap on a single fetched prompt. Reviewer prompts are normally a
 *  few KB; a megabyte is already huge. 1 MB gives plenty of headroom for
 *  rich prompts without leaving DoS surface open. */
const MAX_PROMPT_BYTES = 1024 * 1024;

// ─── Input validation ───────────────────────────────────────────────

/** Reviewer-name shape; mirrors `VALID_REVIEWER_NAME` in
 *  `src/commands/reviewers.ts` so a name that round-trips through the
 *  client `reviewers add` UI also round-trips through the server fetch.
 *
 *  Exported (AGT-372) so the Phase B `prompts-cache` module can reuse the
 *  same canonical source rather than redefining it. The regex is the one
 *  thing both modules MUST agree on — a divergence would let a name
 *  validate at one layer and reject at the other, opening a confused-deputy
 *  path. Keep the export; do not inline a copy. */
export const REVIEWER_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/;

// ─── Public surface ─────────────────────────────────────────────────

/**
 * Build the default single-tenant resolver. `cacheRoot` is the
 * directory holding the reviewer prompt files (e.g. `/etc/stamp/reviewers`
 * for Phase A, or `/srv/git/.prompts-cache` once Phase B's
 * `STAMP_PROMPTS_REPO_URL` is set).
 *
 * `cacheRoot` is taken at resolver-construction time, not at each call,
 * so the verb handler can build the resolver once at startup from the
 * env-resolved cache root and inject it into every request.
 *
 * AGT-373 (Phase B) widened the returned resolver from
 * `(reviewer) => path` to `(reviewer, org?, repo?) => path` and
 * delegates the path-construction logic to `getPromptPath` from
 * `prompts-cache.ts`. The override-vs-default decision (`<cacheRoot>/<org>/<repo>/<reviewer>.md`
 * when that file exists, else `<cacheRoot>/<reviewer>.md`) lives in
 * `getPromptPath` so the resolver and the prompts-cache module agree
 * on layout by construction. Phase A callsites that omit org/repo get
 * the fallback path — they keep compiling, they keep working.
 *
 * AGT-370: replaces the old `defaultRepoResolver` (which mapped `(org,
 * repo)` to a bare-repo path on disk and then used `git show` to read
 * the prompt at `base_sha`). The bare-repo source forced stamp-server
 * to maintain a clone of every reviewed repo, blocking private/internal
 * repos whose code must never leave its git host. The filesystem-cache
 * source decouples the prompt provisioning channel from the review
 * channel — HiveDB (Phase A) / a github prompts repo via webhook
 * (Phase B, AGT-374) writes canonical prompts into the cache
 * out-of-band.
 */
export function defaultPromptCacheResolver(cacheRoot: string): PromptResolver {
  if (!cacheRoot || typeof cacheRoot !== "string") {
    throw new Error("defaultPromptCacheResolver: cacheRoot must be a non-empty string");
  }
  // The closure captures `cacheRoot` and forwards every call to
  // `getPromptPath`, which owns the trailing-slash normalization, the
  // reviewer-name regex check, the override-vs-fallback decision, and
  // the org/repo slug validation. One source of truth for "which file
  // do I read for this triple?" lives in `prompts-cache.ts`; this
  // function only wires the resolver's cacheRoot in.
  return (reviewer: string, org?: string, repo?: string): string =>
    getPromptPath(cacheRoot, reviewer, org, repo);
}

/**
 * Fetch the canonical reviewer prompt for `reviewerName` from the
 * server's local filesystem cache via the injected `promptResolver`.
 * Returns a discriminated-union result: callers branch on `result.kind`
 * — `"ok"` carries the bytes + hash, any other value is a
 * `PromptFetchError`.
 *
 * The flow:
 *   1. Validate `reviewerName` shape.
 *   2. Resolve the prompt path via the injected resolver.
 *   3. `fs.readFileSync(path)` — captures the bytes; ENOENT maps to
 *      `no_such_file`, any other error maps to `io_error`.
 *   4. Hash the bytes with SHA-256 (bare hex).
 *   5. Return `{ kind: "ok", bytes, sha256 }`.
 *
 * Buffered output is bounded by `MAX_PROMPT_BYTES`. Reviewer prompts in
 * the wild are kilobytes; the cap defends against a future runaway
 * provisioning script that drops a multi-megabyte file at the prompt
 * path.
 *
 * AGT-370 + AGT-373 note: `base_sha` is NOT a prompt-resolution input
 * (server is manifest-blind and base-sha-blind for prompts). It still
 * flows over the SSH wire to populate `ApprovalV4.base_sha`. `org` and
 * `repo` ARE now resolution inputs (AGT-373 Phase B) so the default
 * resolver can pick a `<cacheRoot>/<org>/<repo>/<reviewer>.md`
 * override when one exists. Both are optional — Phase A callsites
 * that omit them keep working, falling back to `<cacheRoot>/<reviewer>.md`.
 */
export async function fetchCanonicalPrompt(
  promptResolver: PromptResolver,
  reviewerName: string,
  org?: string,
  repo?: string,
): Promise<PromptFetchResult> {
  if (!REVIEWER_NAME_RE.test(reviewerName)) {
    return {
      kind: "invalid_input",
      detail: `reviewerName must match ${REVIEWER_NAME_RE.source} (got ${JSON.stringify(reviewerName)})`,
    };
  }

  let promptPath: string;
  try {
    // Forward org/repo to the resolver. The default resolver
    // (defaultPromptCacheResolver → getPromptPath) consults the
    // override path `<cacheRoot>/<org>/<repo>/<reviewer>.md` if both
    // are present and the file exists, else falls back to
    // `<cacheRoot>/<reviewer>.md`. Custom (multi-tenant) resolvers
    // may ignore the extra args entirely — the wider signature is
    // covariant so older one-arg resolvers stay assignable.
    promptPath = promptResolver(reviewerName, org, repo);
  } catch (err) {
    return {
      kind: "invalid_input",
      detail: `resolver rejected (reviewer=${JSON.stringify(reviewerName)}): ${
        err instanceof Error ? err.message : String(err)
      }`,
    };
  }

  let bytes: Buffer;
  try {
    bytes = readFileSync(promptPath);
  } catch (err) {
    const e = err as { code?: string; message?: string };
    if (e.code === "ENOENT") {
      return {
        kind: "no_such_file",
        detail: `prompt cache miss: ${promptPath} does not exist (reviewer=${JSON.stringify(reviewerName)})`,
      };
    }
    return {
      kind: "io_error",
      detail: `readFileSync(${promptPath}) failed: ${e.message ?? String(err)}`,
    };
  }
  if (bytes.length > MAX_PROMPT_BYTES) {
    return {
      kind: "io_error",
      detail: `prompt file ${promptPath} is ${bytes.length} bytes — exceeds cap (${MAX_PROMPT_BYTES} bytes). Operator: shrink the prompt or raise the cap.`,
    };
  }

  const sha256 = createHash("sha256").update(bytes).digest("hex");
  return { kind: "ok", bytes, sha256 };
}
