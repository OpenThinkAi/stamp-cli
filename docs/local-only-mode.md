# Local-only mode

Local-only mode is the no-server, no-trust iteration sibling to stamp's trusted-mode review flow. It gives agents fast reviewer feedback during iteration without requiring a stamp server deployment, at the cost of producing **no attestation** — the verdicts are advisory only.

Use it when you want quick reviewer feedback while iterating on a feature branch and either (a) haven't deployed a stamp server yet, or (b) don't need a verifiable verdict for this particular cycle.

> **Not to be confused with the local-model reviewer _backend_.** This page is about the no-trust `--plan` / `--headless` iteration modes. A *separate* feature lets a normal **trusted** reviewer run against a local model (the `local:` model scheme + `local_endpoint`) so its merge-gating verdict is produced unmetered — see [Local-model reviewer backend](../README.md#local-model-reviewer-backend-unmetered). That backend *does* gate a merge; local-only mode (this page) does not.

If you need a signed, verifiable verdict that can gate a merge, you need [trusted mode](../README.md#concepts) instead: configure a `review_server` in `.stamp/config.yml` and run `stamp review` (without `--plan`).

## How it works

```
agent runs: stamp review --plan --diff main..feature
  ↓
stamp emits a structured JSON plan on stdout:
  { schema_version, revspec, base_sha, head_sha, diff, reviewers[] }
and a `note:`-prefixed no-trust advisory on stderr.
  ↓
parent agent (e.g. a Claude Code session) parses the plan
  ↓
parent dispatches N parallel subagents — one per reviewer
  ↓
each subagent reviews independently and returns prose + verdict
  ↓
parent surfaces the verdicts directly to the operator
  (no stamp CLI verb involved on this side — stamp's role ends after
  emitting the plan)
```

The plan is a stable contract — see `src/lib/reviewPlan.ts` (`ReviewPlan`, `schema_version: 1`). Field renames, removals, or type changes bump the schema version; additive changes leave it unchanged.

## Two ways to consume the plan

### 1. From Claude Code: the `stamp-review` skill

The Claude Code consumer ships in this repo at [`skills/stamp-review.md`](../skills/stamp-review.md). It instructs the parent agent to:

1. Print the no-trust banner so the operator sees the framing first.
2. Run `stamp review --plan --diff <revspec>` and parse the JSON.
3. Dispatch one Task subagent per reviewer, in parallel (single message, multiple `tool_use` blocks).
4. Collect and surface each subagent's prose + verdict.
5. Reprint the no-trust banner so the operator's last line of attention is the no-attestation framing.

The skill is **purely orchestration**. It does not introduce a new stamp CLI verb, does not write to `.git/stamp/state.db`, and does not unlock `stamp merge`. There is no `stamp record-feedback` — the parent agent already has each subagent's response and surfaces it directly.

To invoke from Claude Code: trigger the `stamp-review` skill (e.g. via the `Skill` tool, or however your harness exposes skills) and pass the diff revspec you want reviewed.

### 2. Headless / scripted: `stamp review --headless`

For cron jobs, git hooks, CI steps, or any context with no parent agent in the loop, use the built-in headless mode. Stamp calls the Anthropic Messages API directly via `@anthropic-ai/sdk` — one request per reviewer, no tool-use loop, no MCP — and folds each reviewer's verdict + prose into the same JSON envelope that `--plan` mode emits.

```sh
export ANTHROPIC_API_KEY=sk-ant-...
plan=$(stamp review --headless --diff main..feature)
echo "$plan" | jq -r '.reviewers[] | "\(.name): \(.verdict)\n\(.prose)\n"'
```

The exit code mirrors trusted-mode behaviour: `0` if every reviewer returned `approved`, `1` if any reviewer failed or returned a non-null non-approved verdict. Cron / hook callers can gate off the exit code without parsing the JSON. (`2` is reserved for usage errors like a missing `ANTHROPIC_API_KEY`.)

**Output shape parity with `--plan`.** Each entry in `reviewers[]` carries the same `name`, `prompt`, `fence_hex` keys as `--plan` mode, plus the headless additions: `verdict`, `prose`, `model`, and (on failure) `error`. The top-level plan adds `mode: "headless"` so a single consumer that wants to handle both modes can switch on that field; absent `mode` means `"plan"` (the pre-AGT-341 default).

**Model selection.** Per-reviewer model pins from `~/.stamp/config.yml` (set via `stamp config reviewers set <name> <model-id>`) apply to headless mode too. With no pin, headless falls back to `claude-sonnet-4-6` — same as the trusted-mode default — so flipping between `--plan` and `--headless` doesn't silently change the model behind a reviewer.

**Missing key.** Without `ANTHROPIC_API_KEY` exported, `stamp review --headless` exits 2 with a clean error pointing back at this doc. The check happens before any API call so an unkeyed environment fails fast.

**Metering caveat.** Headless mode uses your `ANTHROPIC_API_KEY` and is billed per token by Anthropic. `--plan` mode runs reviewers through the parent's Claude Code session, which is unmetered by the June 15 API/subscription split. The stderr no-trust banner in headless mode explicitly flags this so a script-running operator sees the billing implication without needing to re-read this doc — the banner divergence is intentional.

**No-trust posture is identical to `--plan`.** Headless mode produces NO attestation, does NOT write to `state.db`, does NOT unlock `stamp merge`. It's iteration feedback only. For a verifiable, signed verdict, configure a `review_server` per [trusted mode](../README.md#concepts).

**When to skip headless and reach for `--plan` instead.** When you have a parent Claude Code session, `--plan` is cheaper (unmetered subscription billing) and gives the parent agent richer dispatch control. Use `--headless` specifically when there is no parent agent — cron, post-receive hooks, ad-hoc bash scripts, CI steps. (Auto-detect was considered and skipped — the SDK doesn't expose a reliable "no parent agent" signal, and `isTTY` false-triggers in CI. Explicit flag is the contract.)

## Security boundary: what local-only mode does NOT promise

Local-only mode is **untrusted by design**. The parent agent (you, or a Claude Code session) is the orchestrator; nothing about the verdicts it surfaces is signed, persisted on a server, or independently verifiable. An operator-controlled parent agent can fabricate any verdict it wants — there is no cryptographic check that catches it.

This is why the no-trust banner is mandatory on every invocation, and why the skill insists on reprinting it both before AND after the verdicts. The operator's attention naturally settles on the last thing they see; the last thing they should see is "no attestation produced", not a green verdict that could be mistaken for a merge gate.

Concretely, local-only mode does not:

- Sign the verdicts (no Ed25519 attestation).
- Persist them to a server (no `review_server` interaction).
- Write to the local verdict cache (`.git/stamp/state.db`). That cache only holds trusted-mode verdicts.
- Unlock `stamp merge`. `stamp merge` still requires the trusted-mode gate to be open per `.stamp/config.yml`.

If you need any of those properties, configure a `review_server` and use trusted mode.

## Security properties that DO transfer from trusted mode

The plan-emission step itself preserves the trusted-mode security invariants on the bytes it emits:

- **Merge-base sourcing.** Both `.stamp/config.yml` AND each reviewer prompt are read from the tree at `base_sha`, not the working tree. A feature branch cannot ship a modified reviewer prompt and have that prompt review its own introduction — same boundary as trusted-mode `stamp review`.
- **Reviewer set is base-pinned.** The reviewers listed in the plan are the ones configured at `base_sha`. If the branch ADDS a new reviewer, the new reviewer is not included — the deliberate "new reviewer cannot review its own introduction" rule.
- **Per-reviewer fence hex.** Each plan entry has a fresh 16-byte random hex (`fence_hex`) used as the diff-fence boundary. The skill embeds the diff between `<<<DIFF-{fence_hex}>>>` markers so an attacker controlling diff content cannot trivially close the fence and emit out-of-band instructions to the reviewer subagent. Each reviewer gets a fresh hex so two subagent prompts cannot collide on the same marker.

These transfer because they're properties of the bytes stamp emits, not properties of how the consumer dispatches reviews. The consumer can still betray you (it's local-only — there is no trust), but stamp's plan emission doesn't give it an easier path than necessary.

## Schema versioning

The plan JSON carries a top-level `schema_version` field, currently `1`. A consumer that sees an unrecognized major version should refuse to proceed and surface the version mismatch — adding new optional fields keeps the version stable, but renaming or removing fields bumps it.

The skill in this repo is pinned to `schema_version: 1` and will refuse to run against a future incompatible plan.

## See also

- [`skills/stamp-review.md`](../skills/stamp-review.md) — the Claude Code skill that consumes the plan
- [`src/lib/reviewPlan.ts`](../src/lib/reviewPlan.ts) — `ReviewPlan` type + `PLAN_NO_TRUST_BANNER` constant
- [`README.md`](../README.md) — overview, install, deployment shapes
- [`DESIGN.md`](../DESIGN.md) — trust model, security boundary, attestation schema
- External design.md — "Local-only mode (Option E)" section in the OpenThink stamp-server-attested-reviews project (not in this repo) — design rationale and trust-model justification
