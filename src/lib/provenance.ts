/**
 * Reviewer provenance — which backend kind, which model, and which endpoint
 * actually produced a verdict (AGT-1137).
 *
 * The problem this exists to solve: a `reviews` row said "security approved
 * a1b2c3..d4e5f6" and nothing more. A verdict minted by a 3B model on
 * localhost and one minted by a frontier model were byte-identical in the
 * record that unlocks `stamp merge`, and answering "what reviewed this?"
 * meant reading `userConfig.ts`, `commands/review.ts`, `localReviewer.ts`
 * and a server env var. Provenance makes the record answer it.
 *
 * Three storage fields, persisted as three nullable TEXT columns on
 * `reviews` and mirrored into the signed attestation payload:
 *
 *   backend_kind      which execution path ran the reviewer
 *   backend_model     the model id, or null when the caller never pinned one
 *   backend_endpoint  the base URL the request went to, or null on-SDK
 *
 * NULL on all three means "recorded before provenance shipped" — read sites
 * render that as `unknown` and MUST NOT back-fill a guess. A legacy row
 * genuinely does not know what reviewed it, and inventing a plausible answer
 * would be worse than admitting the gap.
 *
 * Provenance is also part of the verdict-cache key (see `findCachedVerdict`),
 * so a verdict minted on one backend is never replayed for a review requested
 * against a different one.
 */

import { LOCAL_DEFAULT_BASE_URL } from "./localReviewClient.js";
import type { ReviewerBackend } from "./userConfig.js";

/**
 * Persisted shape of a verdict's provenance. Deliberately three flat scalars
 * rather than a JSON blob: they go into the verdict-cache WHERE clause, and
 * `stamp log` renders them without a parse step.
 */
export interface ReviewProvenance {
  /** One of the `PROVENANCE_KIND_*` values below. */
  backend_kind: string;
  /** Model id the backend was asked for, or null when unpinned (the Agent
   *  SDK picks its own default) or unknown (a review the server ran). */
  backend_model: string | null;
  /** Base URL the inference request went to, or null for the Agent SDK path
   *  (which has no operator-visible endpoint — the SDK owns the transport). */
  backend_endpoint: string | null;
}

/** Claude Agent SDK path (`lib/reviewer.ts`). Endpoint is always null. */
export const PROVENANCE_KIND_ANTHROPIC = "anthropic";

/**
 * The OpenAI-compatible one-shot path (`lib/localReviewer.ts` →
 * `lib/localReviewClient.ts`).
 *
 * The stored string is the literal `ReviewerBackend["kind"]` the code uses
 * today, which is `local`. That name is already a misnomer for a remote
 * OpenAI-compatible endpoint, and AGT-1138 renames the concept to
 * `openai-compatible`. Storing what the code calls it today keeps this
 * ticket's rows honest, and the rename can alias `local` on the READ side —
 * no second data migration, no rewrite of rows already in the field.
 */
export const PROVENANCE_KIND_OPENAI_COMPATIBLE = "local";

/**
 * How the stored `"local"` kind is DISPLAYED after AGT-1138 renamed the
 * concept. The stored value stays `"local"` forever — rewriting rows already
 * in the field would be a data migration in service of a label — so the
 * rename lives entirely on the read side, here.
 *
 * Two rows both reading `local` told an operator nothing about whether a
 * verdict came from OpenAI, DeepSeek, or a model on their desk. They are now
 * `openai-compatible @ <endpoint>`, and the endpoint is what separates the
 * providers (AC6).
 */
export const PROVENANCE_LABEL_OPENAI_COMPATIBLE = "openai-compatible";

/**
 * Map a STORED `backend_kind` to its display label. Only the
 * openai-compatible kind differs; every other kind is shown as stored, so an
 * unrecognised value from a future writer renders as itself rather than
 * being swallowed.
 */
export function provenanceKindLabel(storedKind: string): string {
  return storedKind === PROVENANCE_KIND_OPENAI_COMPATIBLE
    ? PROVENANCE_LABEL_OPENAI_COMPATIBLE
    : storedKind;
}

/**
 * Server-attested transport (`review_server` on the branch rule). The
 * reviewer ran on the stamp-server, so the client knows the endpoint it
 * asked but NOT which model the server chose — `backend_model` is null and
 * stays null. Recording the kind anyway is what keeps a server-attested row
 * distinguishable from a legacy pre-provenance row, which would otherwise
 * both read as `unknown`.
 */
export const PROVENANCE_KIND_SERVER = "server";

/** Rendered when a row carries no provenance at all (pre-AGT-1137). */
export const PROVENANCE_UNKNOWN_LABEL = "unknown";

/**
 * Derive the provenance of a verdict from the resolved execution backend.
 *
 * For the local/OpenAI-compatible kind the endpoint is resolved to what the
 * request will ACTUALLY hit — `backend.endpoint` is undefined when neither
 * `STAMP_LOCAL_ENDPOINT` nor `local_endpoint:` is set, and the adapter then
 * falls back to `LOCAL_DEFAULT_BASE_URL`. Recording the effective URL rather
 * than the configured one is the whole point: "which endpoint produced this
 * verdict" must not answer "whatever the default was at the time".
 */
export function backendProvenance(backend: ReviewerBackend): ReviewProvenance {
  // AGT-1138: the resolver's kind is now `openai-compatible`, but the STORED
  // value stays `PROVENANCE_KIND_OPENAI_COMPATIBLE` (the literal `"local"`).
  // This function is the seam that keeps the rename off the data.
  if (backend.kind === "anthropic") {
    return {
      backend_kind: PROVENANCE_KIND_ANTHROPIC,
      backend_model: backend.model,
      backend_endpoint: null,
    };
  }
  return {
    backend_kind: PROVENANCE_KIND_OPENAI_COMPATIBLE,
    backend_model: backend.model,
    backend_endpoint: backend.endpoint ?? LOCAL_DEFAULT_BASE_URL,
  };
}

/**
 * Provenance for a verdict produced by a stamp-server over the `stamp-review`
 * SSH verb. Model is null by construction — the server resolves it (from its
 * own `STAMP_REVIEWER_MODEL`) and does not report it back over the wire.
 */
export function serverReviewProvenance(
  reviewServerUrl: string,
): ReviewProvenance {
  return {
    backend_kind: PROVENANCE_KIND_SERVER,
    backend_model: null,
    backend_endpoint: reviewServerUrl,
  };
}

/**
 * Lift the three nullable columns off a DB row into a `ReviewProvenance`, or
 * null when the row predates the columns.
 *
 * `backend_kind` is the sentinel: it is the one field every provenance-aware
 * writer populates, so a NULL there means "no provenance recorded" no matter
 * what the other two hold. (Same dispatch discipline as `stamp log`'s
 * signed-by marker keying on `server_key_id`.)
 */
export function provenanceFromRow(row: {
  backend_kind: string | null;
  backend_model: string | null;
  backend_endpoint: string | null;
}): ReviewProvenance | null {
  if (!row.backend_kind) return null;
  return {
    backend_kind: row.backend_kind,
    backend_model: row.backend_model,
    backend_endpoint: row.backend_endpoint,
  };
}

/**
 * One-line human rendering, e.g.
 *
 *   anthropic / claude-sonnet-4-6
 *   anthropic / (sdk default)
 *   openai-compatible / qwen3-coder-30b @ http://localhost:8000/v1
 *   openai-compatible / gpt-5 @ https://api.openai.com/v1
 *   openai-compatible / deepseek-chat @ https://api.deepseek.com/v1
 *   server / (model unknown) @ ssh://stamp@host/org/repo
 *   unknown
 *
 * The endpoint is what makes an OpenAI review and a DeepSeek review
 * separable in `stamp log --reviews` — the kind alone cannot, since both ride
 * the one adapter (AGT-1138 AC6).
 *
 * Null input renders `unknown` rather than an empty string so the operator
 * sees the gap instead of a blank they might read as "nothing special".
 */
export function formatProvenance(p: ReviewProvenance | null): string {
  if (!p) return PROVENANCE_UNKNOWN_LABEL;
  const model =
    p.backend_model ??
    (p.backend_kind === PROVENANCE_KIND_ANTHROPIC
      ? "(sdk default)"
      : "(model unknown)");
  const endpoint = p.backend_endpoint ? ` @ ${p.backend_endpoint}` : "";
  return `${provenanceKindLabel(p.backend_kind)} / ${model}${endpoint}`;
}

/**
 * Attestation-payload projection of provenance (see `Approval.provenance` in
 * `lib/attestation.ts`). Null-valued fields are OMITTED rather than emitted
 * as `null`, so an Agent-SDK approval with no pinned model produces exactly
 * `{ backend: "anthropic" }` — the smallest honest statement, and no larger a
 * trailer than it has to be.
 */
export function provenanceForAttestation(p: ReviewProvenance | null):
  | { backend: string; model?: string; endpoint?: string }
  | undefined {
  if (!p) return undefined;
  return {
    backend: p.backend_kind,
    ...(p.backend_model !== null ? { model: p.backend_model } : {}),
    ...(p.backend_endpoint !== null ? { endpoint: p.backend_endpoint } : {}),
  };
}

/**
 * Render an attestation's `provenance` sub-object for `stamp log <sha>`.
 * Takes the payload shape (optional `model` / `endpoint`) rather than the DB
 * shape so the commit-detail view can read provenance straight out of the
 * signed payload — which works on any clone, without the local `state.db`
 * that produced the review.
 */
export function formatAttestedProvenance(
  p: { backend: string; model?: string; endpoint?: string } | undefined,
): string {
  if (!p) return PROVENANCE_UNKNOWN_LABEL;
  return formatProvenance({
    backend_kind: p.backend,
    backend_model: p.model ?? null,
    backend_endpoint: p.endpoint ?? null,
  });
}
