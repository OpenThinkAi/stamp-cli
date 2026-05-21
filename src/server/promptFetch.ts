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

/**
 * Resolves a `(reviewer)` name to the absolute path of the prompt file
 * on this server's filesystem. Synchronous, pure — no I/O, no async,
 * no thrown errors for "not found" (an absent path surfaces naturally
 * as `no_such_file` from the read).
 *
 * The default `defaultPromptCacheResolver` maps `reviewer` to
 * `<cacheRoot>/<reviewer>.md` after validating the reviewer name
 * against the same regex `src/commands/reviewers.ts` enforces.
 * Multi-tenant resolvers do whatever path layout their tenancy model
 * requires; they MUST validate inputs that get interpolated into a
 * filesystem path. The default resolver is conservative: it rejects
 * any reviewer name not matching `REVIEWER_NAME_RE`.
 */
export type PromptResolver = (reviewer: string) => string;

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
 *  client `reviewers add` UI also round-trips through the server fetch. */
const REVIEWER_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/;

// ─── Public surface ─────────────────────────────────────────────────

/**
 * Build the default single-tenant resolver. `cacheRoot` is the
 * directory holding the reviewer prompt files (e.g. `/etc/stamp/reviewers`).
 * The resolver returns `<cacheRoot>/<reviewer>.md` after validating the
 * reviewer name against `REVIEWER_NAME_RE`.
 *
 * `cacheRoot` is taken at resolver-construction time, not at each call,
 * so the verb handler can build the resolver once at startup from
 * `STAMP_PROMPTS_DIR` and inject it into every request.
 *
 * AGT-370: replaces the old `defaultRepoResolver` (which mapped `(org,
 * repo)` to a bare-repo path on disk and then used `git show` to read
 * the prompt at `base_sha`). The bare-repo source forced stamp-server
 * to maintain a clone of every reviewed repo, blocking private/internal
 * repos whose code must never leave its git host. The filesystem-cache
 * source decouples the prompt provisioning channel from the review
 * channel — HiveDB (or whichever upstream owns the prompts) writes
 * canonical prompts directly into the cache out-of-band.
 */
export function defaultPromptCacheResolver(cacheRoot: string): PromptResolver {
  if (!cacheRoot || typeof cacheRoot !== "string") {
    throw new Error("defaultPromptCacheResolver: cacheRoot must be a non-empty string");
  }
  // Strip exactly one trailing slash so `<cacheRoot>/<reviewer>.md`
  // doesn't produce `//`.
  const normalized = cacheRoot.endsWith("/") ? cacheRoot.slice(0, -1) : cacheRoot;
  return (reviewer: string): string => {
    if (!REVIEWER_NAME_RE.test(reviewer)) {
      throw new Error(
        `defaultPromptCacheResolver: invalid reviewer name '${reviewer}' (must match ${REVIEWER_NAME_RE.source})`,
      );
    }
    return `${normalized}/${reviewer}.md`;
  };
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
 * AGT-370 note: the function signature accepts ONLY a `reviewerName` —
 * no `baseSha`, no `org`, no `repo`. The server is manifest-blind and
 * repo-blind under the new shape. `base_sha` still flows over the SSH
 * wire (used to populate `ApprovalV4.base_sha`) but is irrelevant to
 * prompt resolution. The wire protocol is unchanged; only the
 * server's internal handling drops the bare-repo dependency.
 */
export async function fetchCanonicalPrompt(
  promptResolver: PromptResolver,
  reviewerName: string,
): Promise<PromptFetchResult> {
  if (!REVIEWER_NAME_RE.test(reviewerName)) {
    return {
      kind: "invalid_input",
      detail: `reviewerName must match ${REVIEWER_NAME_RE.source} (got ${JSON.stringify(reviewerName)})`,
    };
  }

  let promptPath: string;
  try {
    promptPath = promptResolver(reviewerName);
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
