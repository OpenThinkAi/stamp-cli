/**
 * Repo binding for server-signed approvals (AGT-2272).
 *
 * The problem this closes (AGT-2252 residual): the stamp server picks a
 * reviewer prompt by the caller-supplied `--org` / `--repo`
 * (`<cacheRoot>/<org>/<repo>/<reviewer>.md` when a per-repo override
 * exists). Before this module the signed `ApprovalV4` did not record
 * that pair, and since AGT-370 the verifier trusts `prompt_sha256`
 * without recomputing it. A member granted both a lenient repo and a
 * protected one could review a protected-repo diff under the lenient
 * repo's override and present the signed approval on the protected
 * repo.
 *
 * The fix has three parts, all keyed on one canonical repo id:
 *
 *   - **Canonical id = the server's prompt-selection key**, written
 *     `<org>/<repo>`. It is the exact pair the server used to choose
 *     the prompt, so binding it binds the prompt choice. It is NOT
 *     derived from a remote URL at verify time (a stamp-server remote
 *     parses to org `git`, GitHub mirror names differ); the repo
 *     declares it in `.stamp/config.yml` as top-level `repo_id:`, a
 *     trust-anchor file (gated by `path_rules` / admin signatures on
 *     2.x repos).
 *   - **The server signs it**: `stamp-review` adds `repo_id` to every
 *     `ApprovalV4` it signs (`src/server/reviewPipeline.ts`).
 *   - **Verifiers enforce it** (`verifyV4RepoBinding` in
 *     `src/lib/v4Trust.ts`, used by the pre-receive hook and
 *     `stamp verify-pr`): when the repo declares a `repo_id`, every
 *     approval must carry a server-signed `repo_id` equal to it,
 *     byte-for-byte. An approval with no `repo_id` (an older server,
 *     or a pre-binding approval) is rejected too, so an attacker cannot
 *     downgrade by presenting an unbound approval.
 *
 * The cutover marker is the declaration itself, not the envelope's
 * `schema_version`: the outer envelope is operator-signed, so the
 * operator could always pick an older version; the config is a trust
 * anchor the operator cannot change alone. Repos that declare no
 * `repo_id` keep the pre-AGT-2272 behaviour (no binding) so existing
 * history and un-migrated repos keep verifying.
 *
 * The comparison is exact (case-sensitive): the server resolves the
 * override on a case-sensitive filesystem, so `Acme/Widget` and
 * `acme/widget` can select different prompts and must not be treated as
 * the same id.
 */

import { parse as parseYaml } from "yaml";

import { REPO_SLUG_RE } from "./repoAccess.js";

/** Top-level `.stamp/config.yml` key declaring the canonical repo id. */
export const REPO_ID_CONFIG_KEY = "repo_id";

/** Compose the canonical id from the `stamp-review` verb's org/repo. */
export function formatRepoId(org: string, repo: string): string {
  return `${org}/${repo}`;
}

/** Whether `value` is a well-formed `<org>/<repo>` id (both halves
 *  match the `stamp-review` verb's slug shape). */
export function isWellFormedRepoId(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const parts = value.split("/");
  if (parts.length !== 2) return false;
  return REPO_SLUG_RE.test(parts[0]!) && REPO_SLUG_RE.test(parts[1]!);
}

/** Split a well-formed id back into the verb's `--org` / `--repo`. */
export function splitRepoId(id: string): { org: string; repo: string } {
  const [org, repo] = id.split("/") as [string, string];
  return { org, repo };
}

/**
 * Parse the raw `repo_id` value from a parsed config map.
 * `undefined` / `null` → not declared. Anything else must be a
 * well-formed id.
 */
export function parseRepoIdDeclaration(
  raw: unknown,
): { ok: true; value: string | null } | { ok: false; reason: string } {
  if (raw === undefined || raw === null) return { ok: true, value: null };
  if (isWellFormedRepoId(raw)) return { ok: true, value: raw };
  return {
    ok: false,
    reason:
      `${REPO_ID_CONFIG_KEY} must be "<org>/<repo>" (each part matching ` +
      `${REPO_SLUG_RE.source}); got ${JSON.stringify(raw)}`,
  };
}

/**
 * Pull the raw `repo_id` value out of a `.stamp/config.yml` text.
 * `null` text (config absent at that ref), unparsable YAML or a
 * non-map document yield `undefined` — "not declared" — matching how
 * the verifiers already treat an unreadable config for `path_rules`.
 * The value itself is returned unvalidated; `resolveRepoBinding`
 * validates it (and fails closed on a malformed one).
 */
export function repoIdRawFromConfigYaml(yamlText: string | null): unknown {
  if (yamlText === null) return undefined;
  let parsed: unknown;
  try {
    parsed = parseYaml(yamlText);
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  return (parsed as Record<string, unknown>)[REPO_ID_CONFIG_KEY];
}

/**
 * What a verifier enforces for one merge:
 *
 *   - `unbound`: no config consulted declares `repo_id` — approvals are
 *     accepted with or without a `repo_id` (pre-AGT-2272 behaviour).
 *   - `bound`: every approval's signed `repo_id` must be one of
 *     `accepted`. `preferred` is the id a client should request.
 *   - `invalid`: a consulted config declares a malformed `repo_id`.
 *     Fails closed: every approval is rejected until it is fixed.
 */
export type RepoBinding =
  | { kind: "unbound" }
  | { kind: "bound"; accepted: string[]; preferred: string }
  | { kind: "invalid"; reason: string };

export const UNBOUND: RepoBinding = { kind: "unbound" };

/**
 * Combine the `repo_id` declarations from the configs a verifier
 * consults. Callers pass them in preference order — the target
 * branch's current tip first, then the merge base:
 *
 *   - the TIP is consulted so a branch forked before the repo declared
 *     its id (merge base without `repo_id`) cannot slip past the
 *     binding by its choice of fork point;
 *   - the BASE is consulted so a declaration is honoured for merges
 *     whose base already carries it, the same trust boundary as every
 *     other `.stamp/` artifact.
 *
 * Both are trust anchors; an id declared by either is accepted (so a
 * rename does not strand in-flight branches), and binding is required
 * if either declares one. A malformed declaration in either fails
 * closed.
 */
export function resolveRepoBinding(
  declarations: ReadonlyArray<{ where: string; raw: unknown }>,
): RepoBinding {
  const accepted: string[] = [];
  for (const d of declarations) {
    const parsed = parseRepoIdDeclaration(d.raw);
    if (!parsed.ok) {
      return { kind: "invalid", reason: `.stamp/config.yml at ${d.where}: ${parsed.reason}` };
    }
    if (parsed.value !== null && !accepted.includes(parsed.value)) {
      accepted.push(parsed.value);
    }
  }
  if (accepted.length === 0) return UNBOUND;
  return { kind: "bound", accepted, preferred: accepted[0]! };
}

/**
 * Check one approval's signed `repo_id` against the binding. Pure — the
 * caller has already verified the server signature over the approval
 * body (so `approvalRepoId` is server-attested), or does so afterwards.
 */
export function checkApprovalRepoId(
  approvalRepoId: unknown,
  binding: RepoBinding,
): { ok: true } | { ok: false; reason: string } {
  if (binding.kind === "unbound") return { ok: true };
  if (binding.kind === "invalid") {
    return {
      ok: false,
      reason:
        `${binding.reason}. Approvals cannot be checked against a malformed ` +
        `repo id, so they are refused until it is fixed (land the fix as an ` +
        `admin-signed .stamp/ change).`,
    };
  }
  const want = binding.accepted.map((id) => JSON.stringify(id)).join(" or ");
  if (approvalRepoId === undefined) {
    return {
      ok: false,
      reason:
        `the approval carries no server-signed repo_id, but .stamp/config.yml ` +
        `declares repo_id ${want}. It was signed by a stamp server that ` +
        `predates repo binding (AGT-2272) or minted before the repo declared ` +
        `its id. Upgrade the stamp server and re-run \`stamp review\`.`,
    };
  }
  if (typeof approvalRepoId !== "string" || !binding.accepted.includes(approvalRepoId)) {
    return {
      ok: false,
      reason:
        `the approval was server-signed for repo ${JSON.stringify(approvalRepoId)}, ` +
        `but this repo's .stamp/config.yml declares repo_id ${want}. An ` +
        `approval minted for another repo (under that repo's prompts) cannot ` +
        `gate this one. Re-run \`stamp review\` so the server reviews under ` +
        `this repo's id.`,
    };
  }
  return { ok: true };
}
