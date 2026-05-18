/**
 * Transport-free shared pipeline for server-attested reviews
 * (stamp 2.x, AGT-328 scaffold).
 *
 * This module is the AC #5 reusable handler: the SSH verb in
 * `src/server/stamp-review.ts` (Phase 1) and the future HTTP entrypoint
 * (Phase 2 SaaS) both delegate to `runReviewPipeline` here. The shape is
 * deliberately stdin/stdout-free — the caller passes already-buffered
 * diff bytes + a parsed `ParsedReviewRequest` + a resolved `UserRow` and
 * receives a structured `{ approval, signature, prose, verdict }` back.
 * Anything I/O-shaped (reading stdin, writing JSON to stdout, mapping
 * exit codes) is the transport's job.
 *
 * --- Scope of this scaffold ---
 *
 * AGT-328 lands the SCAFFOLD only:
 *   - real request validation (delegated to the verb's parser, which
 *     calls back through `parsedReviewRequestSchema` here)
 *   - real auth resolution (handled by the verb)
 *   - PLACEHOLDER `runReviewPipeline` body that produces an obvious
 *     fixture verdict + an obvious fixture signature
 *
 * The placeholder values are NOT a valid attestation. They're shaped
 * correctly so downstream code (`stamp merge`, the verifier in AGT-335)
 * can be wired up against the real response shape now, without waiting
 * for the LLM integration in AGT-330 + the signing pass in AGT-331.
 *
 * Real work that lands in follow-up tickets:
 *   - AGT-330: replace the placeholder LLM call with the Anthropic
 *     Messages API + internal `submit_verdict` tool. `promptFetch.ts`
 *     (AGT-329) is already imported here so the call site is in the
 *     right shape — the placeholder currently calls it for its side
 *     effect of catching mis-routed (org, repo, base_sha) tuples at
 *     scaffold time. The Anthropic SDK invocation lands later.
 *   - AGT-331: replace the placeholder `signature` with a real
 *     Ed25519 signature over `canonicalSerializeApproval(approval)`
 *     produced via the `reviewSigningKey` from AGT-327. Capture the
 *     real `trusted_keys_snapshot_sha256` from the bare repo's
 *     `.stamp/trusted-keys/manifest.yml` at base_sha.
 *
 * The placeholder body MUST throw or return obvious fixtures rather
 * than silently producing real-looking output — see the inline
 * `PLACEHOLDER_*` constants below for the markers. A future agent who
 * accidentally ships the scaffold to production should see "not
 * implemented" in their logs immediately.
 */

import type { ApprovalV4 } from "../lib/attestationV4.js";
import type { UserRow } from "../lib/serverDb.js";

/**
 * Hard cap on stdin bytes (the diff). The verb's stdin reader is the
 * load-bearing enforcer — accumulate-then-check would let an attacker
 * push the server toward OOM before the cap rejects. Stream the input
 * chunk by chunk and abort the moment cumulative bytes exceed this.
 *
 * 5 MB is the design-doc default; override via `MAX_DIFF_BYTES` env
 * var at server startup. Read once at module load (not per request)
 * so operators can tune via a restart, never per-call.
 */
export const DEFAULT_MAX_DIFF_BYTES = 5_000_000;

/**
 * Read MAX_DIFF_BYTES from env, falling back to DEFAULT_MAX_DIFF_BYTES.
 * Exported so the verb's stdin reader can pin the same cap the pipeline
 * documents. Rejects non-positive / non-integer values defensively (a
 * typo'd "5MB" would otherwise parse to NaN and disable the cap).
 */
export function resolveMaxDiffBytes(): number {
  const raw = process.env["MAX_DIFF_BYTES"];
  if (!raw) return DEFAULT_MAX_DIFF_BYTES;
  const n = Number(raw);
  if (!Number.isInteger(n) || n <= 0) return DEFAULT_MAX_DIFF_BYTES;
  return n;
}

/**
 * The structured request the verb's parser produces and the pipeline
 * consumes. Mirrors the SSH verb's flag set 1:1 so the parsed object is
 * a direct projection of the operator's command line.
 *
 * All sha-shaped strings are full lowercase 40-char hex (legacy SHA-1)
 * for `base_sha` / `head_sha`, and bare 64-char hex for `diff_sha256`
 * (matches the bare-hex convention in `ApprovalV4.diff_sha256` and
 * `prompt_sha256`). The `reviewer` / `org` / `repo` strings are validated
 * by the verb against the same regexes `promptFetch.ts` uses, so a
 * value reaching this struct has already cleared shape validation.
 */
export interface ParsedReviewRequest {
  reviewer: string;
  org: string;
  repo: string;
  baseSha: string;
  headSha: string;
  /** Bare hex sha256 the client computed over the diff bytes it
   *  streamed on stdin. The verb cross-checks this against the server's
   *  own hash of the received bytes before invoking the pipeline; a
   *  mismatch surfaces as a clean "diff_sha256 mismatch" error rather
   *  than reaching the LLM. */
  diffSha256: string;
}

/**
 * What the pipeline returns. The transport packages this into the JSON
 * response shape defined in design.md (`{ verdict, prose, approval,
 * signature }`); the pipeline itself stays opinion-free about wire
 * format. The transport is responsible for ensuring the order matches
 * the design.md spec when it emits to its caller.
 */
export interface ReviewPipelineResult {
  /** Mirrors `approval.verdict` for the top-level response field —
   *  surfaced separately so a future HTTP transport can return
   *  it in a header without re-parsing the approval body. */
  verdict: ApprovalV4["verdict"];
  /** Human-readable review prose from the LLM. Persisted in the
   *  client's local DB and shown in `stamp log --reviews`. */
  prose: string;
  /** The signed approval body — the `ApprovalV4` whose canonical
   *  serialization the `signature` was computed over. */
  approval: ApprovalV4;
  /** Base64 Ed25519 signature over `canonicalSerializeApproval(approval)`. */
  signature: string;
}

/** Pipeline input. Kept as a single bag-of-args object so callers don't
 *  have to remember positional order across the SSH/HTTP entrypoints. */
export interface ReviewPipelineInput {
  diff: Buffer;
  params: ParsedReviewRequest;
  caller: UserRow;
}

// ─── Placeholder markers ────────────────────────────────────────────
//
// These exist so the scaffold's output is OBVIOUSLY-not-real to any
// human or downstream verifier. AGT-330 replaces PLACEHOLDER_PROSE,
// AGT-331 replaces PLACEHOLDER_SIGNATURE + the placeholder verdict and
// snapshot hash. Don't relax the "obvious" property — silent
// scaffold-leaks into production are exactly the failure mode these
// markers exist to make impossible.

const PLACEHOLDER_VERDICT: ApprovalV4["verdict"] = "changes_requested";
const PLACEHOLDER_PROSE =
  "scaffold response — Anthropic API integration lands in AGT-330";
const PLACEHOLDER_SIGNATURE = "PLACEHOLDER_SIGNATURE__AGT-331__NOT_REAL";
const PLACEHOLDER_SERVER_KEY_ID =
  "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const PLACEHOLDER_SNAPSHOT =
  "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const PLACEHOLDER_PROMPT_SHA256 =
  "0000000000000000000000000000000000000000000000000000000000000000";

/**
 * Run a review request through the pipeline.
 *
 * **Scaffold contract** (AGT-328): this function returns a structurally
 * correct `ReviewPipelineResult` populated with the
 * `PLACEHOLDER_*` constants above. The `verdict` is hard-coded to
 * `changes_requested` (the safest no-op verdict — clients receiving a
 * placeholder won't accidentally treat the merge as approved) and the
 * `signature` is a marker string that fails Ed25519 verification by
 * construction.
 *
 * Real implementation arrives in:
 *   - AGT-330: call Anthropic Messages API with `promptFetch`-resolved
 *     prompt as system message + diff as user message + internal
 *     `submit_verdict` tool. Populate `verdict`, `prose`, and
 *     `approval.prompt_sha256` from the response.
 *   - AGT-331: capture `trusted_keys_snapshot_sha256` from the bare
 *     repo's manifest at `base_sha`; sign
 *     `canonicalSerializeApproval(approval)` with the
 *     `reviewSigningKey` from AGT-327; populate `signature` +
 *     `approval.server_key_id`.
 *
 * The scaffold deliberately does NOT call into `promptFetch.ts` yet:
 * doing so would couple the SSH-verb tests to a bare-repo fixture
 * before AGT-330 is even started. The import is held by the verb
 * (`stamp-review.ts`) instead, so the call-site path stays visible
 * and future agents have one obvious place to wire it up.
 */
export async function runReviewPipeline(
  input: ReviewPipelineInput,
): Promise<ReviewPipelineResult> {
  // Touch every input so a future maintainer who shrinks the input
  // shape can't silently break the contract. TypeScript would flag
  // unused params at compile time anyway, but the explicit reads
  // double as documentation for what each field is used for once the
  // real implementation lands.
  void input.diff;
  void input.params;
  void input.caller;

  // ISO-8601 UTC timestamp the server assigns at signing time. The
  // real implementation (AGT-331) emits this from the actual signing
  // moment; the scaffold emits "now" so the response is shaped
  // correctly and tests can pin the format with a regex.
  const issued_at = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

  const approval: ApprovalV4 = {
    reviewer: input.params.reviewer,
    verdict: PLACEHOLDER_VERDICT,
    prompt_sha256: PLACEHOLDER_PROMPT_SHA256,
    diff_sha256: input.params.diffSha256,
    base_sha: input.params.baseSha,
    head_sha: input.params.headSha,
    trusted_keys_snapshot_sha256: PLACEHOLDER_SNAPSHOT,
    issued_at,
    server_key_id: PLACEHOLDER_SERVER_KEY_ID,
  };

  return {
    verdict: PLACEHOLDER_VERDICT,
    prose: PLACEHOLDER_PROSE,
    approval,
    signature: PLACEHOLDER_SIGNATURE,
  };
}
