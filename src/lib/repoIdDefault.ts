/**
 * Default `repo_id:` for repos stamp sets up (AGT-2276).
 *
 * AGT-2272 binds server-signed approvals to the repo's declared
 * `repo_id`, but only for repos that declare one. `stamp provision`,
 * `stamp bootstrap` and `stamp init --migrate-to-server-attested` use
 * this module to declare it by default, under two conditions:
 *
 *   - the id is the exact `<org>/<repo>` pair `stamp review` sends as
 *     `--org` / `--repo` for an undeclared repo (the last two segments
 *     of the `origin` URL), so declaring it does not change which
 *     prompts the server selects; a pair that is not a well-formed id
 *     is refused (never written);
 *   - the review server reports, via the capability probe, that it signs
 *     `repo_id` into approvals. Against a server that predates AGT-2272
 *     the declaration would make every approval fail, so on any probe
 *     failure nothing is written and the caller prints the note.
 */

import { deriveOrgRepoFromRemote } from "./remote.js";
import { REPO_ID_CONFIG_KEY, formatRepoId, isWellFormedRepoId, parseRepoIdDeclaration } from "./repoBinding.js";
import {
  describeProbeTarget,
  probeServerCapabilities,
  type CapabilityProbeTarget,
} from "./serverCapabilities.js";

/** The remote `stamp review` derives `--org` / `--repo` from. */
export const REVIEW_ORG_REPO_REMOTE = "origin";

export type RepoIdDefault =
  /** Write `repo_id: <repoId>` into `.stamp/config.yml`. */
  | { kind: "write"; repoId: string }
  /** The config already declares a `repo_id`; leave it. */
  | { kind: "declared"; repoId: string }
  /** Do not write; print `note`. */
  | { kind: "skip"; note: string };

/**
 * Note for a repo left without `repo_id` (same advice `stamp review`
 * prints for an unbound repo).
 */
function unboundRepoNote(reason: string, candidate: string | null): string {
  const add = candidate
    ? `Add \`${REPO_ID_CONFIG_KEY}: ${candidate}\``
    : `Add \`${REPO_ID_CONFIG_KEY}: <org>/<repo>\` (the id this repo's prompts live under on the review server)`;
  return (
    `note: .stamp/config.yml was left without ${REPO_ID_CONFIG_KEY}, so verifiers do not bind ` +
    `server-signed approvals to this repo: ${reason}.\n  ${add} as an admin-signed .stamp/ change ` +
    `once the review server signs ${REPO_ID_CONFIG_KEY} (AGT-2272) to refuse approvals minted for another repo.`
  );
}

/**
 * Pure part of the decision: the candidate id from a derived org/repo
 * pair, or the reason there is none.
 */
export function candidateRepoId(
  pair: { org: string; repo: string } | null,
): { ok: true; repoId: string } | { ok: false; reason: string } {
  if (!pair) {
    return {
      ok: false,
      reason: `the ${REVIEW_ORG_REPO_REMOTE} remote URL has no recognizable <org>/<repo> shape`,
    };
  }
  const id = formatRepoId(pair.org, pair.repo);
  if (!isWellFormedRepoId(id)) {
    return {
      ok: false,
      reason:
        `the <org>/<repo> derived from the ${REVIEW_ORG_REPO_REMOTE} remote, ${JSON.stringify(id)}, ` +
        `is not a well-formed repo id`,
    };
  }
  return { ok: true, repoId: id };
}

/**
 * Decide whether to declare `repo_id`.
 *
 * @param existingRaw the config's current raw `repo_id` value (undefined
 *   when absent). A declared value is never overwritten.
 * @param target the review server to probe, or null when the caller
 *   cannot tell which server signs this repo's approvals.
 */
export function decideRepoIdDefault(args: {
  repoRoot: string;
  existingRaw: unknown;
  target: CapabilityProbeTarget | null;
}): RepoIdDefault {
  const existing = parseRepoIdDeclaration(args.existingRaw);
  if (existing.ok && existing.value !== null) {
    return { kind: "declared", repoId: existing.value };
  }
  if (!existing.ok) {
    // Config validation already refuses this; never paper over it.
    return { kind: "skip", note: `note: ${existing.reason}; left as is.` };
  }

  const candidate = candidateRepoId(deriveOrgRepoFromRemote(REVIEW_ORG_REPO_REMOTE, args.repoRoot));
  if (!candidate.ok) {
    return { kind: "skip", note: unboundRepoNote(candidate.reason, null) };
  }
  if (!args.target) {
    return {
      kind: "skip",
      note: unboundRepoNote("no stamp server to ask whether it signs repo_id", candidate.repoId),
    };
  }
  const where = describeProbeTarget(args.target);
  console.error(`asking the stamp server at ${where} whether it signs repo_id into approvals…`);
  const probe = probeServerCapabilities(args.target);
  if (!probe.ok) {
    return {
      kind: "skip",
      note: unboundRepoNote(
        `the stamp server at ${where} did not answer the capability probe (${probe.reason})`,
        candidate.repoId,
      ),
    };
  }
  if (!probe.capabilities.approvalRepoId) {
    return {
      kind: "skip",
      note: unboundRepoNote(`the stamp server at ${where} does not report signing repo_id`, candidate.repoId),
    };
  }
  return { kind: "write", repoId: candidate.repoId };
}
