/**
 * Idempotent injection of stamp-specific guidance into AGENTS.md and CLAUDE.md
 * at the repo root. Stamp sections live between HTML-comment delimiters so
 * re-running `stamp init` / `stamp bootstrap` replaces the section in place
 * without disturbing any other content (oteam blocks, think blocks, etc.).
 *
 * Both AGENTS.md and CLAUDE.md use the same `<!-- stamp:begin -->` /
 * `<!-- stamp:end -->` marker pair (different files, zero collision risk —
 * each `ensureXxxMd` is path-scoped). Legacy CLAUDE.md files used the
 * distinct `<!-- stamp:claude:begin -->` / `<!-- stamp:claude:end -->` markers;
 * the next `stamp init` migrates them to the unified shape automatically.
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const STAMP_BEGIN = "<!-- stamp:begin (managed by `stamp init` — do not edit between markers) -->";
export const STAMP_END = "<!-- stamp:end -->";

// Legacy markers kept for backward-compat detection and sweep.
// AGENTS.md: old wording used "stamp-cli" instead of "`stamp init`".
export const STAMP_BEGIN_LEGACY = "<!-- stamp:begin (managed by stamp-cli — do not edit between markers) -->";
// CLAUDE.md: old files used distinct stamp:claude:begin / stamp:claude:end.
export const STAMP_CLAUDE_BEGIN_LEGACY = "<!-- stamp:claude:begin (managed by stamp-cli — do not edit between markers) -->";
export const STAMP_CLAUDE_END_LEGACY = "<!-- stamp:claude:end -->";

// Detection prefixes (cover both old and new marker wordings).
const STAMP_BEGIN_PREFIX = "<!-- stamp:begin ";
const STAMP_CLAUDE_BEGIN_PREFIX = "<!-- stamp:claude:begin ";

/**
 * Deployment shape selector for the AGENTS.md content. The three shapes
 * have meaningfully different invariants — only `server-gated` and
 * `attested-pr` can truthfully promise rejection, and they reject in
 * different places (server pre-receive hook vs. GitHub PR check). Lying
 * to a future agent that the gate is enforced when it isn't is worse
 * than not writing anything.
 *
 * - `server-gated`  — Shape 1: origin is a stamp server with a pre-receive
 *                     hook. Direct pushes to protected branches are rejected
 *                     server-side.
 * - `local-only`    — Shape 2/3: origin is a public forge (GitHub / GitLab /
 *                     etc.) directly. No server-side rejection; enforcement
 *                     is on the agent's discipline.
 * - `attested-pr`   — Shape 4: origin is GitHub (mirror-as-source-of-truth),
 *                     and a `stamp-verify` GitHub Actions PR check
 *                     verifies the attestation before merge. Direct pushes
 *                     to `main` are rejected by GitHub branch protection
 *                     once configured; the workflow gates everything else.
 */
export type AgentsMdMode = "server-gated" | "local-only" | "attested-pr";

/**
 * Sniffable phrase constants — one distinctive string embedded in each
 * mode's body. The drift sniffer uses these to read back which mode a
 * live AGENTS.md was generated for, without re-running classifyRemote.
 *
 * Picked to be unambiguous: each phrase must appear ONLY in its own body,
 * not in either of the other two. Tests pin this invariant (see
 * `agentsMdDrift.test.ts`); if any of them start collating, change a
 * phrase rather than weakening the sniffer.
 */
export const SNIFF_PHRASE_SERVER_GATED = "server-side pre-receive hook";
export const SNIFF_PHRASE_LOCAL_ONLY = "The agent following these instructions is the gate.";
export const SNIFF_PHRASE_ATTESTED_PR = "Shape 4 — attested-pr mode (GitHub-primary)";

/**
 * Mode-agnostic guidance about when to stop iterating on stamp review. Same
 * dynamic (LLM cost, amend churn, SHA-bound verdict refresh) applies to both
 * server-gated and local-only repos, so the text is shared rather than
 * duplicated. Concatenated into both section bodies below.
 */
const REVIEW_LOOP_HEURISTIC = `### Knowing when to stop the review loop (diminishing returns)

Each \`stamp review\` run is non-trivial — reviewer LLM calls, your context, and amend
churn to fix what they flag. After 2–3 rounds the value tapers. A useful pattern:

- **Round 1** catches structure (real bugs, missing rollback, wrong source of truth).
- **Round 2** catches consistency (code dup, conflicting defaults, broken back-compat).
- **Round 3** typically surfaces only stylistic polish (comma placement, comment
  wording, JSDoc rot — things no end user will ever notice).

**Heuristic:** if every reviewer's request includes phrases like "minor", "nit",
"not blocking", or "cosmetic", apply the fixes and re-run review **only because
verdicts are SHA-bound and need refreshing** — then merge. Don't iterate further looking
for more issues. By round 4 you're paying full LLM cost for marginal value, and reviewers
will sometimes invent new categories of nit just to fill the response.

Exception: if any reviewer returns \`denied\` (not \`changes_requested\`), the change has a
structural problem regardless of round number — keep iterating until the denial is
addressed or the design is reconsidered.`;

/**
 * Server-gated section body. Speaks to a future agent dropped into a repo
 * whose origin is a stamp server with the pre-receive hook installed. Names
 * the gate model, the canonical loop, and the concrete things NOT to do.
 */
export const STAMP_AGENTS_SECTION_SERVER_GATED = `## Stamp-protected repository — read before changing code

This repository is gated by [stamp-cli](https://github.com/OpenThinkAi/stamp-cli).
Direct commits to protected branches (typically \`main\`) **will be rejected by
the server-side pre-receive hook**, even with valid credentials. Every change
to a protected branch must be a \`stamp merge\` signed locally and pushed via
\`stamp push\`.

### The canonical workflow

\`\`\`sh
git checkout -b feature
# ...edit, commit, repeat...

stamp review --diff main..feature       # all configured reviewers run in parallel
stamp status --diff main..feature       # exit 0 if every required reviewer approved

# When green:
git checkout main
stamp merge feature --into main         # signs an Ed25519 attestation into the merge trailer
stamp push main                         # server hook verifies; main advances on the remote
\`\`\`

If a reviewer returns \`changes_requested\`, read its prose in the \`stamp review\`
output (or via \`stamp log --reviews --limit 1\`), fix the code, commit, and
re-review. Verdicts are bound to the exact \`(base_sha, head_sha)\` pair, so a
new commit invalidates prior approvals.

### What NOT to do

- **Do not** \`git push origin main\` directly — bypasses the gate; will be rejected.
- **Do not** commit to \`main\` directly — same.
- **Do not** use \`--no-verify\` to skip hooks. Investigate hook failures, don't bypass them.
- **Do not** edit \`.stamp/config.yml\` or \`.stamp/reviewers/*.md\` casually — those changes
  go through the same reviewer gate as any other code change. Treat them as security-sensitive
  edits.
- **Do not** delete \`.stamp/trusted-keys/*.pub\` files unless you genuinely intend to revoke
  a signer; doing so locks that signer out of all future merges.

### The one exception: the bootstrap commit

The single commit that ADDS \`.stamp/\` + \`AGENTS.md\` + \`CLAUDE.md\` to a fresh
repo for the first time is the chicken-and-egg moment — \`stamp review\` has
no base tree to read prompts from. That one commit can land directly on
\`main\`. Recent \`stamp init\` runs do this commit automatically; older
versions need it done by hand. Every subsequent change to \`.stamp/\` (or
anything else) goes through the normal stamp flow.

### Where things live

- \`.stamp/config.yml\` — branch rules (which reviewers are required, optional \`required_checks\`)
- \`.stamp/reviewers/*.md\` — reviewer prompt files; this is your project's review policy as code
- \`.stamp/trusted-keys/*.pub\` — Ed25519 public keys allowed to sign merges into protected branches
- \`~/.stamp/keys/ed25519{,.pub}\` — your local signing keypair (generated by \`stamp init\` /
  \`stamp keys generate\`; never committed)

### Useful commands

\`\`\`sh
stamp --help                              # full command list
stamp reviewers list                      # configured reviewers + prompt file status
stamp reviewers test <name> --diff <rev>  # iterate on a reviewer prompt without polluting the DB
stamp log                                 # recent stamped merges with attestation summaries
stamp verify <sha>                        # re-verify a specific merge commit's attestation
\`\`\`

### When stamp blocks you

See [\`docs/troubleshooting.md\`](./docs/troubleshooting.md) if it exists in this repo, or the
upstream copy at https://github.com/OpenThinkAi/stamp-cli/blob/main/docs/troubleshooting.md.
Common cases:

- \`gate CLOSED: missing approved verdicts\` — re-run \`stamp review\` (verdicts are SHA-bound;
  every new commit invalidates prior approvals)
- \`pre-merge checks failed\` — a \`required_check\` exited non-zero; the merge was rolled back
- \`remote: stamp-verify: rejecting refs/heads/main\` — server hook caught a bypass attempt
- \`required by rule but not defined\` — chicken-and-egg on a reviewer config change; see the
  troubleshooting entry, or use \`stamp bootstrap\` for the placeholder→real swap case

${REVIEW_LOOP_HEURISTIC}
`;

/**
 * Local-only section body. The repo has stamp config committed but no server
 * is enforcing it — origin is GitHub/GitLab/etc directly. Direct pushes will
 * NOT be rejected. The text is deliberately honest about this so an agent
 * reading it doesn't act on the false premise that the gate is enforced.
 */
export const STAMP_AGENTS_SECTION_LOCAL_ONLY = `## Stamp-protected repository — agent instructions (READ THIS BEFORE ANY GIT COMMAND)

**You — the AI agent reading this — are required to use the stamp flow for any
change to this repository's protected branches (typically \`main\`).** Direct
\`git commit\` to \`main\` and direct \`git push origin main\` are explicit
violations of this repo's process, even though the remote will technically
accept them.

The remote does not reject unsigned pushes (this is local-only / advisory mode
— see "How enforcement works here" below). That means **enforcement is on you,
not the server**. Bypassing the stamp flow because "the push will succeed
anyway" is the most common failure mode and is exactly what this notice exists
to prevent.

### The required workflow for every change to a protected branch

\`\`\`sh
git checkout -b feature
# ...edit, commit, repeat on the feature branch...

stamp review --diff main..feature       # all configured reviewers run in parallel
stamp status --diff main..feature       # exit 0 if every required reviewer approved

# When green:
git checkout main
stamp merge feature --into main         # signs an Ed25519 attestation into the merge trailer
git push origin main                    # plain git push — remote accepts anything,
                                        # but the merge commit now carries a verifiable signature
\`\`\`

If a reviewer returns \`changes_requested\`, read its prose in the \`stamp review\`
output (or via \`stamp log --reviews --limit 1\`), fix on the feature branch,
commit, and re-review. Verdicts are bound to \`(base_sha, head_sha)\`, so a new
commit invalidates prior approvals.

### What you must NOT do

- **Do not** \`git commit\` directly to \`main\`. Always work on a feature branch.
- **Do not** \`git push origin main\` of a commit that wasn't produced by \`stamp merge\`.
- **Do not** use \`--no-verify\` to skip hooks.
- **Do not** edit \`.stamp/config.yml\` or \`.stamp/reviewers/*.md\` outside the stamp
  review/merge cycle. Those changes go through the same reviewer gate.
- **Do not** rationalize bypassing the gate because "this is local-only mode
  so it doesn't matter." The mode describes who enforces the gate
  (server vs. agent discipline), not whether the gate exists. **The gate exists.**

### The one exception: the bootstrap commit

When \`stamp init\` runs on a repo that doesn't have stamp installed yet, the
commit that ADDS \`.stamp/\` + \`AGENTS.md\` + \`CLAUDE.md\` is a chicken-and-egg
case — there is no prior trusted state to review against, so \`stamp review\`
has no meaningful base. That single commit is allowed to land directly on the
current branch. Recent versions of stamp-cli handle this commit automatically
inside \`stamp init\`; if you're working with an older version, make exactly
that one commit + push by hand and then go through the stamp flow for
everything afterward. **This exception is for the literal first stamp commit
only**, not for any subsequent change to \`.stamp/\` or any other code.

### How enforcement works here (and why you have to be the enforcer)

This repo's origin is a public forge (GitHub / GitLab / etc.) directly, not a
stamp server with a pre-receive hook. So:

- The remote will accept any push, including unsigned ones, force-pushes, and
  direct GitHub web-UI merges.
- The reviewer prompts and config in \`.stamp/\` are committed code-as-policy,
  not server-enforced rules.
- **The agent following these instructions is the gate.**

If the operator wants real server-side enforcement, they need to migrate to a
stamp server: deploy [stamp-cli's server image](./docs/quickstart-server.md),
repoint \`origin\` at it, configure GitHub as a downstream mirror with a Ruleset
locking direct pushes, and regenerate this guidance via
\`stamp init --mode server-gated\`. Until that happens, the rules above are
mandatory but unenforced — your job is to follow them anyway.

\`stamp verify <sha>\` works on any clone to validate a merge commit's
attestation, so the audit trail is preserved even without server-side rejection.

### Where things live

- \`.stamp/config.yml\` — branch rules (which reviewers are required, optional \`required_checks\`)
- \`.stamp/reviewers/*.md\` — reviewer prompt files
- \`.stamp/trusted-keys/*.pub\` — Ed25519 public keys (would be enforced by a server hook if one existed)
- \`~/.stamp/keys/ed25519{,.pub}\` — your local signing keypair

${REVIEW_LOOP_HEURISTIC}
`;

/**
 * Attested-PR section body — Shape 4 (server-attested mirror). Origin is
 * GitHub (the canonical mirror-as-source-of-truth), and the stamp server
 * never sees a git push from the operator. Enforcement happens in two
 * places: GitHub branch protection rejects direct pushes to \`main\`, and
 * the \`stamp-verify\` Actions PR check rejects PRs whose merge commit
 * lacks a valid server-attested envelope.
 *
 * The body is deliberately honest about the two-part contract: branch
 * protection has to be configured on GitHub or the PR check can be
 * bypassed. We name the prerequisite so a future agent reading this
 * doesn't assume the gate is closed when it isn't.
 *
 * The first line — "Shape 4 — attested-pr mode (GitHub-primary)" — is the
 * sniffable phrase the drift checker keys on. Do not change it without
 * updating SNIFF_PHRASE_ATTESTED_PR in lockstep (or the regression tests
 * that pin the invariant).
 */
export const STAMP_AGENTS_SECTION_ATTESTED_PR = `## Stamp-protected repository — Shape 4 — attested-pr mode (GitHub-primary)

This repository is gated by [stamp-cli](https://github.com/OpenThinkAi/stamp-cli)
in **attested-pr mode**: origin is GitHub (the canonical source-of-truth
mirror) and a server-side stamp instance signs review attestations that
get verified by a GitHub Actions \`stamp-verify\` PR check before a
maintainer can merge. **Direct commits to \`main\` are rejected by
GitHub branch protection**; every change lands via a PR whose merge
commit carries a verifiable server-attested envelope.

### The two-part enforcement model (read this carefully)

Enforcement is not in any single hook. It is the **conjunction** of:

1. **GitHub branch protection on \`main\`** — must be configured to require
   the \`stamp-verify\` check AND block direct pushes. If branch protection
   is missing or misconfigured, the PR check still runs but a maintainer
   can merge a PR that failed it. The operator who set this repo up is
   responsible for the protection rules; verify with
   \`gh api repos/<owner>/<repo>/branches/main/protection\`.
2. **\`.github/workflows/stamp-verify.yml\`** — the Action that verifies
   the attestation envelope on each PR. Its required job name appears in
   the branch-protection \`required_status_checks\` list.

If either is absent, the gate is **partially open**. Do not assume the
mode name "attested-pr" means rejection is automatic — confirm both
pieces are live before treating a green PR check as authoritative.

### The canonical workflow

\`\`\`sh
git checkout -b feature
# ...edit, commit, repeat on the feature branch...

stamp review --diff main..feature       # reviewers run; server signs the attestation
stamp status --diff main..feature       # exit 0 if every required reviewer approved

# Open the PR (GitHub UI or \`gh pr create\`). The \`stamp-verify\`
# Actions check runs against the merge commit's attestation envelope.
# A maintainer merges via GitHub once the check is green and branch
# protection's other requirements (reviews, etc.) are satisfied.
\`\`\`

\`stamp merge\` and \`stamp push\` are NOT the merge path here — they're
the server-gated (Shape 1) flow. In attested-pr mode the merge happens
through GitHub's UI/API, and the attestation lives in the merge commit
trailers (signed by the server's review-signing key, verified by the
PR check against \`.stamp/trusted-keys/review-server-prod.pub\`).

### What NOT to do

- **Do not** \`git push origin main\` directly — branch protection rejects.
- **Do not** merge a PR whose \`stamp-verify\` check is failing or skipped.
  A skipped check on a PR that touches code is a signal the workflow
  didn't run; investigate before merging.
- **Do not** disable or weaken the branch-protection rules without
  understanding that doing so unilaterally opens the gate.
- **Do not** edit \`.stamp/config.yml\` or \`.stamp/trusted-keys/*.pub\`
  casually — those changes go through the same review + attestation gate
  as any other code change. They are security-sensitive edits.
- **Do not** delete \`.stamp/trusted-keys/review-server-prod.pub\`. That
  pubkey is what the workflow uses to verify the server's signature; its
  removal locks the repo out of all future merges until restored.

### Contributor onboarding

A new contributor needs:

1. Read access to the repo (no special stamp setup for plain reviewers).
2. To trigger \`stamp review\` for their own PR, write access to push the
   feature branch, plus the server endpoint reachable (configured by
   \`~/.stamp/server.yml\` or per-repo \`.stamp/config.yml\`'s
   \`review_server\`). No client-side signing key is needed — the server
   holds the review-signing key.
3. The \`stamp-verify\` workflow is already in the repo; PRs from new
   contributors run it automatically (assuming the operator's Actions
   settings allow Action runs from fork PRs, which is the GitHub default
   for collaborators).

### Where things live

- \`.stamp/config.yml\` — branch rules + \`review_server\` URL (where to send review requests)
- \`.stamp/trusted-keys/manifest.yml\` — fingerprint-to-capability map (server, operator, admin)
- \`.stamp/trusted-keys/review-server-prod.pub\` — the server's review-signing pubkey (the workflow verifies attestations against this)
- \`.github/workflows/stamp-verify.yml\` — the Actions PR check that enforces the attestation envelope
- \`~/.stamp/server.yml\` — your local pointer to the stamp server endpoint (host:port)

### Useful commands

\`\`\`sh
stamp --help                              # full command list
stamp reviewers list                      # configured reviewers + prompt file status
stamp review --diff main..feature         # request reviews (server-signed)
stamp verify <sha>                        # re-verify a specific merge commit's attestation against the trusted pubkey
\`\`\`

### When the gate blocks you

- \`stamp-verify\` PR check failed — read the Actions log. Common causes:
  the merge commit doesn't carry an attestation trailer (the operator
  merged without going through the stamp flow), the trailer signature
  doesn't match \`review-server-prod.pub\` (server key rotated without a
  manifest update), or the diff doesn't match what was reviewed
  (post-review commits invalidated the verdict).
- Branch protection blocked a direct push — that's working as intended.
  Open a PR instead.
- The server-side review request failed — see
  \`docs/troubleshooting.md\` (server unreachable, reviewer prompt
  mismatch, etc.).

${REVIEW_LOOP_HEURISTIC}
`;


/**
 * Find a managed block in `text` whose open line starts with `openPrefix` and
 * whose close is `closeMarker`. Returns the character indices bounding the
 * block (inclusive of both markers and everything between them), or null if no
 * such block is found.
 *
 * Uses prefix matching so that wording changes inside the opening comment
 * (e.g. "stamp-cli" → "`stamp init`") are recognised without producing a
 * duplicate stale block.
 */
function findManagedBlock(
  text: string,
  openPrefix: string,
  closeMarker: string,
): { beginIdx: number; afterEnd: number } | null {
  let searchStart = 0;
  while (searchStart < text.length) {
    const candidateIdx = text.indexOf(openPrefix, searchStart);
    if (candidateIdx === -1) return null;
    // Must be at the start of a line (beginning of text, or preceded by \n).
    if (candidateIdx === 0 || text[candidateIdx - 1] === "\n") {
      const closeStart = text.indexOf(closeMarker, candidateIdx);
      if (closeStart === -1) return null;
      return { beginIdx: candidateIdx, afterEnd: closeStart + closeMarker.length };
    }
    searchStart = candidateIdx + 1;
  }
  return null;
}

/**
 * Insert or replace the stamp-managed section in an AGENTS.md body.
 *
 * - If `existing` already contains a line starting with `<!-- stamp:begin `
 *   (covers both old "stamp-cli" wording and new "`stamp init`" wording),
 *   the content between the open and close markers is replaced in place and
 *   everything outside is preserved verbatim.
 * - If `existing` lacks the delimiters but is non-empty, the stamp section
 *   is appended after a blank-line separator.
 * - If `existing` is empty/undefined, a complete AGENTS.md is generated
 *   with a brief preamble + the stamp section.
 *
 * Idempotent: calling injectStampSection on its own output is a no-op.
 *
 * The `mode` selects which body gets injected — server-gated promises
 * server-side rejection (true on a stamp-server origin); local-only is
 * honest about the lack of enforcement (true when origin is GitHub etc.
 * directly). Lying to a future agent is worse than the smaller content
 * difference.
 */
export function injectStampSection(
  existing: string | undefined,
  mode: AgentsMdMode = "server-gated",
): string {
  const body = bodyForMode(mode);
  const stampBlock = `${STAMP_BEGIN}\n\n${body.trimEnd()}\n\n${STAMP_END}`;

  if (existing === undefined || existing.trim() === "") {
    return `# AGENTS.md

Guidance for AI agents working in this repository.

${stampBlock}
`;
  }

  // Prefix-based detection catches both the old "stamp-cli" wording and the
  // new "`stamp init`" wording without requiring a full-string match.
  const found = findManagedBlock(existing, STAMP_BEGIN_PREFIX, STAMP_END);
  if (found) {
    const before = existing.slice(0, found.beginIdx);
    const after = existing.slice(found.afterEnd);
    return `${before}${stampBlock}${after}`;
  }

  return `${existing.trimEnd()}\n\n${stampBlock}\n`;
}

/**
 * Create or refresh the stamp-managed section of AGENTS.md at the repo root.
 *
 * `mode` defaults to server-gated for back-compat with the previous
 * single-mode behavior. Callers that know they're in local-only deployment
 * (init --mode local-only) should pass "local-only" explicitly.
 *
 * Returns:
 *   "created"   — file did not exist; wrote a fresh AGENTS.md
 *   "replaced"  — file existed with stamp markers; replaced the section in place
 *   "appended"  — file existed without stamp markers; appended a new block
 *   "unchanged" — file already contains the exact target content (no write)
 */
export function ensureAgentsMd(
  repoRoot: string,
  mode: AgentsMdMode = "server-gated",
): "created" | "replaced" | "appended" | "unchanged" {
  const path = join(repoRoot, "AGENTS.md");
  if (!existsSync(path)) {
    writeFileSync(path, injectStampSection(undefined, mode));
    return "created";
  }
  const existing = readFileSync(path, "utf8");
  const updated = injectStampSection(existing, mode);
  if (updated === existing) return "unchanged";
  // "replaced" if either the new or legacy marker was already present.
  const action =
    existing.includes(STAMP_BEGIN) || existing.includes(STAMP_BEGIN_LEGACY)
      ? "replaced"
      : "appended";
  writeFileSync(path, updated);
  return action;
}

/**
 * Body for the stamp-managed CLAUDE.md section. Deliberately *short* — Claude
 * Code auto-loads CLAUDE.md and prepends it to the model's context, so the
 * goal here is "attention-grab + pointer to AGENTS.md", NOT a full guide.
 * AGENTS.md carries the workflow detail; CLAUDE.md exists to make sure an
 * agent that never explicitly opens AGENTS.md still sees the rule.
 *
 * Mode-agnostic: the rule "use stamp flow, don't push directly" applies the
 * same way in both server-gated and local-only deployment shapes.
 */
export const STAMP_CLAUDE_SECTION = `## Stamp-protected repository — read AGENTS.md before any git operation

This repository is gated by [stamp-cli](https://github.com/OpenThinkAi/stamp-cli).
**Do not \`git commit\` directly to protected branches** (typically \`main\`)
**and do not \`git push origin main\`** of any commit you didn't produce via
\`stamp merge\`. The required flow is:

\`\`\`sh
git checkout -b feature
# ... edit, commit on the feature branch ...
stamp review --diff main..feature       # all reviewers run in parallel
stamp status --diff main..feature       # gate check (exit 0 = open)
git checkout main
stamp merge feature --into main         # signs the merge
git push origin main                    # OR \`stamp push main\` if origin is a stamp server
\`\`\`

Key commands: \`stamp provision\` — provision a new repo; \`stamp review\` — run reviewers; \`stamp merge\` — sign a merge; \`stamp push\` — push to a stamp server.

**The full reference is at [\`AGENTS.md\`](./AGENTS.md) at the repo root** —
read it before any git command. It covers the mode (server-gated vs.
local-only), what NOT to do, where things live, and how to recover when stamp
blocks you.

**One exception:** the very first commit that ADDS \`.stamp/\` + \`AGENTS.md\` +
\`CLAUDE.md\` to a fresh repo is allowed to land directly on the current branch
(there's nothing to review against). Recent \`stamp init\` runs do this commit
automatically. Every subsequent change goes through the stamp flow.`;

/**
 * Insert or replace the stamp-managed CLAUDE.md section. Uses the same
 * `<!-- stamp:begin -->` / `<!-- stamp:end -->` markers as AGENTS.md (unified
 * marker convention — no collision risk since each ensureXxxMd is path-scoped).
 *
 * Legacy CLAUDE.md files use `<!-- stamp:claude:begin -->` / `<!-- stamp:claude:end -->`.
 * This function detects the legacy form and migrates it to the new shape on
 * the next `stamp init`, leaving no duplicate block behind.
 *
 * Same three-case logic as injectStampSection:
 *   replace-in-place (new or legacy markers found) → append → generate-fresh.
 */
export function injectClaudeSection(existing: string | undefined): string {
  const stampBlock = `${STAMP_BEGIN}\n\n${STAMP_CLAUDE_SECTION.trimEnd()}\n\n${STAMP_END}`;

  if (existing === undefined || existing.trim() === "") {
    return `# CLAUDE.md

Project-specific instructions for Claude Code (auto-loaded into the model's context).

${stampBlock}
`;
  }

  // Check for either the new unified marker or the legacy stamp:claude:begin marker.
  const found =
    findManagedBlock(existing, STAMP_BEGIN_PREFIX, STAMP_END) ??
    findManagedBlock(existing, STAMP_CLAUDE_BEGIN_PREFIX, STAMP_CLAUDE_END_LEGACY);

  if (found) {
    const before = existing.slice(0, found.beginIdx);
    const after = existing.slice(found.afterEnd);
    return `${before}${stampBlock}${after}`;
  }

  return `${existing.trimEnd()}\n\n${stampBlock}\n`;
}

/**
 * Create or refresh the stamp-managed section of CLAUDE.md at the repo root.
 * Same return shape and semantics as ensureAgentsMd. Default-on when called
 * by stamp init / stamp bootstrap; the operator can opt out with
 * `--no-claude-md`.
 */
export function ensureClaudeMd(
  repoRoot: string,
): "created" | "replaced" | "appended" | "unchanged" {
  const path = join(repoRoot, "CLAUDE.md");
  if (!existsSync(path)) {
    writeFileSync(path, injectClaudeSection(undefined));
    return "created";
  }
  const existing = readFileSync(path, "utf8");
  const updated = injectClaudeSection(existing);
  if (updated === existing) return "unchanged";
  // "replaced" if any known stamp marker (new or legacy, either file variant)
  // was already present — covers AGENTS-style legacy wording too.
  const action =
    existing.includes(STAMP_BEGIN) ||
    existing.includes(STAMP_BEGIN_LEGACY) ||
    existing.includes(STAMP_CLAUDE_BEGIN_LEGACY)
      ? "replaced"
      : "appended";
  writeFileSync(path, updated);
  return action;
}

/**
 * Map a mode to its rendered section body. Exposed (private to module)
 * so injectStampSection and the drift sniffer don't drift apart — both
 * route through the same lookup.
 */
function bodyForMode(mode: AgentsMdMode): string {
  switch (mode) {
    case "server-gated":
      return STAMP_AGENTS_SECTION_SERVER_GATED;
    case "local-only":
      return STAMP_AGENTS_SECTION_LOCAL_ONLY;
    case "attested-pr":
      return STAMP_AGENTS_SECTION_ATTESTED_PR;
  }
}

/**
 * Read a repo's live `AGENTS.md` and infer which `AgentsMdMode` it was
 * generated for by looking for distinctive phrase constants embedded in
 * each body.
 *
 * Returns:
 *   - the inferred `AgentsMdMode` when exactly one sniffable phrase matches
 *   - `"absent"` when no AGENTS.md exists at the repo root, or when one
 *     exists but contains no managed stamp block
 *   - `"unknown"` when a managed block exists but no sniffable phrase
 *     matches — covers legacy hand-written content, future variants we
 *     don't yet recognise, or a heavily customised body. Treated as a
 *     silent (no-warning) case by the drift checker; the goal is not to
 *     punish operators who've forked the template.
 *
 * Deliberately tolerant: returns the FIRST mode whose phrase matches,
 * with ties broken in `AgentsMdMode` enum order. Phrase constants are
 * picked to be mutually exclusive (regression test pins this) so ties
 * shouldn't happen in practice; if a future edit collides them, the
 * test goes red and a phrase has to be re-picked.
 */
export function sniffAgentsMdMode(
  repoRoot: string,
): AgentsMdMode | "absent" | "unknown" {
  const path = join(repoRoot, "AGENTS.md");
  if (!existsSync(path)) return "absent";
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return "absent";
  }
  // Locate the managed block first — sniffing outside the managed block
  // would let unrelated user content trip the phrase check. Only the
  // unified `<!-- stamp:begin -->` marker is searched here; legacy
  // markers carry no sniffable mode-specific phrase by definition
  // (they predate the per-mode bodies) so they'd resolve to "unknown"
  // anyway. The injectStampSection path migrates legacy markers on the
  // next stamp init, so anyone with a legacy block still in place will
  // get one no-op silent run and then start matching on the next push.
  const found = findManagedBlock(text, STAMP_BEGIN_PREFIX, STAMP_END);
  if (!found) return "absent";
  const managed = text.slice(found.beginIdx, found.afterEnd);

  if (managed.includes(SNIFF_PHRASE_ATTESTED_PR)) return "attested-pr";
  if (managed.includes(SNIFF_PHRASE_SERVER_GATED)) return "server-gated";
  if (managed.includes(SNIFF_PHRASE_LOCAL_ONLY)) return "local-only";
  return "unknown";
}

/**
 * Result of `expectedModeFromRemoteShape`. `null` means "no opinion" —
 * the remote shape doesn't tell us enough to assert a particular mode,
 * so the drift checker should NOT warn (a warning without confidence
 * is just noise).
 */
export type ExpectedAgentsMdMode = AgentsMdMode | null;

/**
 * Map a `classifyRemote` deployment shape to the AGENTS.md mode it
 * implies. The mapping is conservative:
 *
 *   - `stamp-server` → `server-gated` (pre-receive hook will enforce)
 *   - `forge-direct` → `local-only`  (no server-side enforcement; if the
 *                      operator has migrated to Shape 4, they'll have
 *                      run `--migrate-to-server-attested` which writes
 *                      the `attested-pr` body — and that case is read
 *                      by the sniffer, so no drift warning fires.
 *                      The asymmetry is intentional: we cannot tell
 *                      a Shape 4 GitHub-mirror remote apart from a plain
 *                      forge-direct remote by URL alone, so we default
 *                      to the more cautious `local-only` expectation
 *                      and rely on the sniffer to say "actually it's
 *                      attested-pr" when the migration has happened.)
 *   - `unknown`/`unset` → null (no opinion; never warn)
 *
 * The `forge-direct → local-only` mapping is the trigger for AC #5
 * variant (a): a repo that was init'd with local-only AGENTS.md and
 * then had its origin re-pointed at a stamp server — origin is now
 * `stamp-server`, but AGENTS.md still says local-only. Sniffed mode
 * `local-only` ≠ expected `server-gated` → warn.
 */
export function expectedAgentsMdModeFromShape(
  shape: "stamp-server" | "forge-direct" | "unknown" | "unset",
  sniffed: AgentsMdMode | "absent" | "unknown",
): ExpectedAgentsMdMode {
  // If the sniffer already reports `attested-pr`, the operator opted into
  // Shape 4 via `--migrate-to-server-attested`. The forge-direct origin
  // shape is what Shape 4 is supposed to look like (GitHub-mirror), so
  // no drift. Return `attested-pr` (the live mode) as the expectation
  // so the drift checker compares apples to apples.
  if (sniffed === "attested-pr" && shape === "forge-direct") {
    return "attested-pr";
  }
  switch (shape) {
    case "stamp-server":
      return "server-gated";
    case "forge-direct":
      return "local-only";
    case "unknown":
    case "unset":
      return null;
  }
}

/** Environment variable name that suppresses the drift warning. Exported
 *  so docs and tests can reference the constant rather than the literal
 *  string. */
export const DRIFT_WARNING_SUPPRESS_ENV = "STAMP_SUPPRESS_AGENTS_MD_DRIFT_WARNING";

/**
 * Options for `maybeWarnAgentsMdDrift`. Accepting a pre-computed
 * `remoteShape` instead of calling `classifyRemote` ourselves keeps the
 * lib leaf pure (no git dep) and lets tests inject arbitrary shapes
 * without standing up a fake git repo.
 */
export interface AgentsMdDriftCheckOptions {
  /** Repo root — where to look for AGENTS.md. */
  repoRoot: string;
  /** The deployment shape returned by `classifyRemote(remote, repoRoot)`. */
  remoteShape: "stamp-server" | "forge-direct" | "unknown" | "unset";
  /** Command name to surface in the warning ("push", "merge", "status"). */
  command: string;
  /**
   * Name of the remote that was classified. Templated into the warning so
   * `stamp push upstream` reports "upstream looks like ..." rather than
   * hardcoded "origin". Default `"origin"`.
   */
  remote?: string;
  /** Stream to write the warning to. Default `process.stderr`. Injectable for tests. */
  stderr?: { write(s: string): boolean | void };
  /** Env reader. Default `process.env`. Injectable for tests. */
  env?: NodeJS.ProcessEnv;
}

/**
 * Emit a single non-blocking stderr warning when the sniffed AGENTS.md
 * mode disagrees with the mode implied by the remote shape. Silent on:
 *
 *   - `absent` AGENTS.md or no managed block (no claim to drift from)
 *   - `unknown` sniffed mode (operator forked the template; don't punish)
 *   - null expectation (remote shape doesn't imply a specific mode)
 *   - matched mode (the happy path)
 *   - `STAMP_SUPPRESS_AGENTS_MD_DRIFT_WARNING=1` in env
 *
 * Returns `true` iff a warning was emitted; useful for tests that need
 * to assert silence on the no-warning branches.
 */
export function maybeWarnAgentsMdDrift(opts: AgentsMdDriftCheckOptions): boolean {
  const env = opts.env ?? process.env;
  if (env[DRIFT_WARNING_SUPPRESS_ENV] === "1") return false;

  const sniffed = sniffAgentsMdMode(opts.repoRoot);
  if (sniffed === "absent" || sniffed === "unknown") return false;

  const expected = expectedAgentsMdModeFromShape(opts.remoteShape, sniffed);
  if (expected === null) return false;
  if (expected === sniffed) return false;

  const stderr = opts.stderr ?? process.stderr;
  const remoteName = opts.remote ?? "origin";
  const remind = `         Refresh: \`stamp init --mode ${expected}\`.`;
  const suppress = `         Suppress: ${DRIFT_WARNING_SUPPRESS_ENV}=1.`;
  stderr.write(
    `warning: AGENTS.md says \`${sniffed}\` but ${remoteName} looks like ${describeShapeShort(opts.remoteShape)} (expected \`${expected}\`).\n` +
      `         The committed agent guidance is stale; future agents will read the wrong enforcement story.\n` +
      `${remind}\n` +
      `${suppress}\n`,
  );
  return true;
}

/** One-word human label for a deployment shape, used inside the drift
 *  warning prose. Kept local so it doesn't get mistaken for a public
 *  describeShape replacement. The expected mode appears separately
 *  inside the same warning line (`expected \`<mode>\``); this label
 *  deliberately does NOT repeat it to avoid the double-parenthetical
 *  noise an earlier draft produced. */
function describeShapeShort(
  shape: "stamp-server" | "forge-direct" | "unknown" | "unset",
): string {
  switch (shape) {
    case "stamp-server":
      return "a stamp server";
    case "forge-direct":
      return "a public forge (GitHub etc.)";
    case "unknown":
      return "an unrecognized remote";
    case "unset":
      return "no remote";
  }
}
