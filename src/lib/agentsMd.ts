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
 * Deployment shape selector for the AGENTS.md content. The two shapes have
 * meaningfully different invariants — only the server-gated one can truthfully
 * promise rejection. Lying to a future agent that the gate is enforced when
 * it isn't is worse than not writing anything.
 */
export type AgentsMdMode = "server-gated" | "local-only";

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
  const body =
    mode === "server-gated"
      ? STAMP_AGENTS_SECTION_SERVER_GATED
      : STAMP_AGENTS_SECTION_LOCAL_ONLY;
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
