/**
 * Post-provision mirror verification (issue #64).
 *
 * `stamp provision` used to declare `✓ provisioned` without ever checking
 * that the GitHub mirror's deploy key and Ruleset actually exist. When the
 * deploy-key step was skipped (or aborted with it), the result was a repo
 * that LOOKED provisioned but whose every later `stamp push` half-failed:
 * the stamp-server leg accepted, the mirror leg died on
 * `Permission denied (publickey)` — and the only symptom appeared well
 * after provisioning "succeeded".
 *
 * This module holds the pure decision logic: given what a fresh read of
 * GitHub's state says (owner type, deploy key id, ruleset id), enumerate
 * the problems that make the mirror not-actually-provisioned. The gh
 * round-trips live at the call site in provision.ts; keeping this half
 * pure makes the policy unit-testable without a network.
 */

import { STAMP_MIRROR_DEPLOY_KEY_TITLE } from "./ghRuleset.js";

export interface MirrorProvisionState {
  /**
   * Owner type of the mirror repo, from lookupRepoOwnerType. `null` when
   * the gh lookup itself failed — verification can't pass in that case
   * (we can't assert anything about a repo we can't read).
   */
  ownerType: "Organization" | "User" | null;
  /**
   * Deploy-key id registered under the canonical `stamp-mirror` title,
   * or null when absent. Only REQUIRED for org repos — personal repos
   * bypass the Ruleset via a User actor and push the mirror over the
   * legacy transport, so an absent key is not a defect there.
   */
  deployKeyId: number | null;
  /** `stamp-mirror-only` Ruleset id, or null when absent. */
  rulesetId: number | null;
}

/**
 * Enumerate what's wrong with a freshly-provisioned mirror. Empty array
 * means the mirror is verified. Each problem is a self-contained,
 * operator-actionable sentence — they get printed verbatim and the
 * provision exits non-zero, so each must name its own repair.
 */
export function computeMirrorProvisionProblems(
  state: MirrorProvisionState,
  mirror: { owner: string; repo: string },
  cloneTarget: string,
): string[] {
  const problems: string[] = [];
  const repo = `${mirror.owner}/${mirror.repo}`;

  if (state.ownerType === null) {
    problems.push(
      `couldn't read ${repo} via gh to verify the deploy key + Ruleset — ` +
        `check \`gh auth status\` and that the repo exists, then re-verify by hand ` +
        `(\`gh api repos/${repo}/keys\` and \`gh api repos/${repo}/rulesets\`).`,
    );
    // Without owner type we can't judge whether a missing key matters,
    // and the key/ruleset probes likely failed for the same reason —
    // don't stack three copies of the same auth failure.
    return problems;
  }

  if (state.ownerType === "Organization" && state.deployKeyId === null) {
    problems.push(
      `no "${STAMP_MIRROR_DEPLOY_KEY_TITLE}" deploy key is registered on ${repo} — ` +
        `every mirror push will fail with 'Permission denied (publickey)'. ` +
        `Repair: cd ${cloneTarget} && stamp provision --migrate-bypass`,
    );
  }

  if (state.rulesetId === null) {
    problems.push(
      `no \`stamp-mirror-only\` Ruleset exists on ${repo} — the mirror has no ` +
        `GitHub-side enforcement (anyone with write access can push to it directly). ` +
        `Apply it via docs/github-ruleset-setup.md.`,
    );
  }

  return problems;
}
