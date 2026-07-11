/**
 * `.github/workflows/stamp-verify.yml` scaffolding shared by
 * `stamp init` and `stamp init --migrate-to-server-attested`. The
 * workflow file template, its pinned action ref, and the idempotent
 * write wrapper all live here so the two callers stay byte-identical
 * and a single bump (e.g. WS3's SHA-pinning) touches one location.
 */

import { existsSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import type { AgentsMdMode } from "./agentsMd.js";
import { ensureDir } from "./paths.js";

/**
 * Upstream source of the `stamp/verify-attestation` action. Operators
 * consuming a fork override via `--action-source <org/repo>`. Exported
 * so tests + the workflow renderer agree on the default.
 */
export const DEFAULT_ACTION_SOURCE = "OpenThinkAi/stamp-cli";

/**
 * stamp/verify-attestation Action ref, pinned to an immutable commit
 * SHA on `OpenThinkAi/stamp-cli`. A 40-char hex SHA — NOT a mutable git
 * tag — so the rendered workflow identifies the action's bytes
 * unambiguously and CI does not silently re-resolve to a different
 * commit if the tag is moved upstream. (Security reviewers flag the
 * mutable-tag form on every audit; SHA-pinning is the precedent.)
 *
 * When bumping, the source of truth for resolving a human-readable
 * release to a commit SHA is:
 *
 *   gh api repos/OpenThinkAi/stamp-cli/git/ref/tags/<vX.Y.Z>
 *
 * If the response's `object.type === "tag"` (annotated tag), dereference:
 *
 *   gh api repos/OpenThinkAi/stamp-cli/git/tags/<sha>
 *
 * Then update both this constant and the trailing-version note below in
 * lockstep with the stamp-cli release that contains the matching
 * `action.yml`. Bumping stamp-cli without bumping this ref would point
 * users at an Action that doesn't exist (or worse, that semantically
 * differs from the stamp version they have installed locally).
 */
// SHA for the stamp/verify-attestation action as of the 3.2.0 release
// (rich check output + collapsed setup-log groups; the action's
// stamp-version input defaults to the 1.11.0 verifier, which accepts
// the v2 envelopes local-key repos produce).
export const VERIFY_ACTION_REF =
  "795271bedebfb02354c8b17382f5c22916e1da30";

/** Human-readable version that `VERIFY_ACTION_REF` corresponds to.
 *  Surfaced in the rendered workflow's comment line so operators can
 *  cross-reference the SHA against release notes without resolving the
 *  SHA themselves. Update in lockstep with `VERIFY_ACTION_REF`. */
export const VERIFY_ACTION_VERSION = "v3.2.0";

/**
 * Drop the `.github/workflows/stamp-verify.yml` workflow file when
 * appropriate for the resolved deployment mode. Returns a small
 * { action, path } object so the init summary block can report what
 * happened without re-deriving the answer.
 */
export function maybeWriteVerifyWorkflow(
  repoRoot: string,
  prCheckOpt: boolean | undefined,
  effectiveMode: AgentsMdMode,
  actionSource: string = DEFAULT_ACTION_SOURCE,
): { action: "wrote" | "exists" | "skipped"; path: string } {
  const path = ".github/workflows/stamp-verify.yml";
  const fullPath = join(repoRoot, path);

  // Mode-aware default: forge-direct + local-only get the workflow;
  // server-gated doesn't (server enforces at the receive hook). The
  // operator's explicit prCheckOpt overrides the default in either
  // direction.
  const defaultForMode = effectiveMode !== "server-gated";
  const shouldWrite = prCheckOpt ?? defaultForMode;
  if (!shouldWrite) return { action: "skipped", path };

  if (existsSync(fullPath)) {
    // Idempotent re-init: don't clobber operator edits to a workflow
    // they may have customized (added concurrency, fork-PR conditions,
    // etc.). The summary line distinguishes "exists" from "wrote" so
    // a re-init is honest about not touching the file.
    return { action: "exists", path };
  }

  ensureDir(dirname(fullPath));
  writeFileSync(fullPath, renderVerifyWorkflow(actionSource));
  return { action: "wrote", path };
}

/**
 * Build the workflow file body. Pulled into its own function so a test
 * can verify the action reference, the trigger, and the permissions
 * shape without re-rendering or string-grepping. Inline rather than
 * file-loaded because the template is short and version-bound to this
 * release.
 */
export function renderVerifyWorkflow(
  actionSource: string = DEFAULT_ACTION_SOURCE,
): string {
  return [
    "name: stamp verify",
    "",
    `# Runs stamp/verify-attestation (SHA-pinned to ${VERIFY_ACTION_REF}; corresponds to ${VERIFY_ACTION_VERSION}) on every PR.`,
    "# Wire `stamp verify` (this job's name) into branch protection",
    "# Required Status Checks to make a green attestation a merge",
    "# precondition.",
    "",
    "on:",
    "  pull_request:",
    "    branches: [main]",
    "",
    "permissions:",
    "  # checkout + read .stamp/{config,trusted-keys}/ from the base ref",
    "  contents: read",
    "  # for the workflow's check-run summary on the PR",
    "  checks: write",
    "",
    "jobs:",
    "  stamp-verify:",
    "    name: stamp verify",
    "    runs-on: ubuntu-latest",
    "    timeout-minutes: 5",
    "    steps:",
    "      - name: checkout",
    "        uses: actions/checkout@v4",
    "        with:",
    "          # Full history so the action can fetch the base ref's tree",
    "          # and resolve refs/stamp/attestations/*. Shallow clones",
    "          # would force per-step refetches.",
    "          fetch-depth: 0",
    "      - name: stamp/verify-attestation",
    `        uses: ${actionSource}/.github/actions/verify-attestation@${VERIFY_ACTION_REF}`,
    "",
  ].join("\n");
}
