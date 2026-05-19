# Migrating from stamp 1.x to 2.x

stamp 2.x introduces **server-attested reviews**: the LLM call moves into stamp-server, which holds its own signing key and signs every verdict. The operator no longer constructs both sides of "what the LLM saw" and "what the LLM said" — a forged review now requires forging a server signature, which requires either compromising the server or stealing its key.

This guide walks you through the upgrade. Read [`plans/server-attested-reviews.md`](./plans/server-attested-reviews.md) first if you want the full design rationale; this doc focuses on the operational steps.

> **Scope.** stamp 2.0.1 is the current GA. All commands referenced below are
> shipped. If you're upgrading from a 1.x install older than the bridge
> release, run `stamp update` (or `npm i -g @openthink/stamp@latest`) first.

---

## Why upgrade

Today's stamp 1.x attestation proves *"a keyholder signed off that reviewer X returned verdict V on commit Y, against a prompt whose hash matches the committed `.stamp/reviewers/X.md` file."* It does **not** prove that the LLM actually received that prompt, or that the LLM actually produced that verdict — both are constructed on the operator's machine. The hash and the model input can disagree, and the verifier has no way to tell. See [`DESIGN.md`'s security model section](../DESIGN.md#security-model) for the full restating.

stamp 2.x closes that gap structurally. Three concrete properties it adds:

- **Server-attested verdicts.** The verdict, prompt hash, and diff hash are signed by stamp-server's review-signing key. Forging an approval now requires forging a signature the operator does not hold.
- **Role-gated trust-anchor changes.** Modifications to `.stamp/**` (prompts, config, the trusted-keys manifest) require admin-capability signatures, not reviewer verdicts. The rotating-prompt attack (land a permissive prompt via the reviewer cycle, then merge bad code that the new prompt would approve) is structurally prevented.
- **Diff binding.** The server signs the actual diff hash. An operator cannot get a verdict for a sanitized diff and push a malicious one.

What 2.x *doesn't* promise:

- **Local-only attestation.** Local mode produces no attestation in 2.x by design — anything producible without a server can be forged by the operator. Use it for fast iteration feedback, not for trust. See [`local-only-mode.md`](./local-only-mode.md).
- **Server compromise resistance.** If the server's signing key is stolen, forged verdicts verify cleanly until rotation. Mitigated by standard infra hygiene + lenient revocation.

---

## What stays the same

The day-to-day surface barely changes for operators who already deployed a stamp server in 1.x:

- **The local agent iteration loop.** `stamp review` still returns verdicts in seconds; the server proxies the LLM call but adds no perceptible latency.
- **The git surface.** `stamp merge` still produces a signed merge commit. `stamp push` still hands off to the server's pre-receive hook.
- **The deployment artifact.** Same Docker image (extended with new env vars); no second service to run.
- **Your signing keypair.** Your operator-capability key (`~/.stamp/keys/`) is reused — it becomes the outer-envelope key in v4 and you may also promote it to `admin` capability for trust-anchor changes.
- **`stamp log`, `stamp verify`, `stamp keys` surface.** All continue to work; old v2/v3 attestations remain readable.

---

## What changes

| Surface | 1.x | 2.x |
|---|---|---|
| **Trust model** | Operator-only signature | Operator + server + admin capabilities (additive on a single key, or split across keys) |
| **Attestation envelope** | `schema_version: 3` ([`src/lib/attestation.ts`](../src/lib/attestation.ts); v2 / v1 no longer accepted by verifiers) | `schema_version: 4` ([`src/lib/attestationV4.ts`](../src/lib/attestationV4.ts)) |
| **Reviewer features** | `tools:` + `mcp_servers:` per reviewer; Read/Grep/WebFetch allowlisted | Phase 1 reviewers are diff-only; `tools` / `mcp_servers` config is warned + ignored |
| **`stamp review` (trusted mode)** | Runs LLM locally via Claude Agent SDK | Calls stamp-server's `stamp-review` SSH verb; server runs the LLM and signs the verdict |
| **Trust anchor (`.stamp/**`) changes** | Gated by the same reviewer cycle as any other diff | Gated by `path_rules` requiring `admin`-capability signatures; reviewer cycle bypassed for these paths |
| **`stamp review` with no `review_server`** | Runs locally and writes the verdict to `state.db` (gate-eligible) | Errors out with a pointer to this guide or to `--plan` / `--headless` ([`local-only-mode.md`](./local-only-mode.md)) |

**What gets dropped:**

- `tools_sha256`, `mcp_sha256`, `tool_calls` envelope fields — Phase 1 reviewers don't have tools.
- Reviewer file access (`Read`, `Grep`, `Glob`, `WebFetch`) — the server reviewer sees only the diff.
- MCP integrations — Linear/Notion/etc. MCPs are not wired into Phase 1 reviewers.

If you rely on the dropped surfaces (e.g. a `product` reviewer that does Linear ticket reconciliation via an MCP), see the [FAQ on `mcp_servers`/`tools`](#what-about-my-mcp_servers--tools-config) below.

---

## Pick your deployment shape

stamp 2.x supports three deployment shapes. Pick deliberately — the upgrade path differs.

### Shape 1 — stamp-server as the primary git remote

You push directly to stamp-server; the pre-receive hook is the source of truth. Best fit if you already deployed stamp-server in 1.x or if you want the strongest enforcement and don't need GitHub's PR UI in the loop.

Go to [Upgrade walkthrough — Shape 1](#upgrade-walkthrough--shape-1-stamp-server-primary).

### Shape 2 — GitHub primary, stamp-server mirrors for review (PR mode)

GitHub holds the source of truth and runs the PR UI. A GitHub Action auto-mirrors every push to stamp-server, which runs reviews and signs verdicts. `stamp/verify-attestation@v1` validates v4 attestations as a required PR check.

Best fit if your team already lives in GitHub PRs and you don't want to migrate the dev surface.

Go to [Upgrade walkthrough — Shape 2](#upgrade-walkthrough--shape-2-pr-mode).

### Shape 3 — Local-only (iteration feedback, no trust)

No server. `stamp review --plan` emits a structured plan for a parent Claude Code session to dispatch, or `stamp review --headless` calls Anthropic directly with `ANTHROPIC_API_KEY`. **Produces no attestation in 2.x** — verdicts are advisory.

If your 1.x deployment was already operator-trust-only without a server, this is your natural landing shape. The functional behavior doesn't change; the framing does ("no trust" is now explicit rather than implicit-and-unfortunate).

Go to [Local-only operators](#local-only-operators).

---

## Upgrade walkthrough — Shape 1 (stamp-server primary)

### Step 0 — Pin operator workstations on a 2.x-aware stamp

Before flipping anything, upgrade every operator workstation that interacts
with the stamp-protected repos. If you've installed stamp before, the
fastest path is `stamp update`; otherwise install fresh:

```sh
stamp update                          # in-place upgrade of an existing install
# OR
npm i -g @openthink/stamp@latest      # fresh install of GA (2.0.1+)
```

Operators who explicitly need to stay on the 1.x line can pin to
`@openthink/stamp@legacy-1` once that dist-tag is published (the bridge
release ships deprecation notices pointing at this guide and supports both
1.x operator-trust and 2.x server-attested verification side by side
per-repo via `review_server` config). Existing repos keep working on
operator-trust until you flip them.

### Step 1 — Upgrade stamp-server to a 2.x-capable build

```sh
# Railway / Fly / K8s: redeploy from the 2.x image
# Self-hosted Docker: pull and restart
docker pull openthinkai/stamp-server:2.x
```

Add the new env vars:

| Var | Purpose | Default |
|---|---|---|
| `ANTHROPIC_API_KEY` | Server-side Anthropic credential | Required if reviews enabled |
| `MAX_DIFF_BYTES` | Reject review requests larger than this | `5_000_000` |
| `REVIEW_TIMEOUT_MS` | Per-review wall-clock timeout | `300_000` |
| `REVIEW_SIGNING_KEY_PATH` | Override signing-key location | `$STATE_DIR/review-signing-key.pem` |

Without `ANTHROPIC_API_KEY`, the server still runs and accepts existing 1.x pushes; review verbs return a clear "review capability not configured" error. Reviews are opt-in.

### Step 2 — Capture the server's review-signing pubkey

On first boot with `ANTHROPIC_API_KEY` set, the server generates an Ed25519 review-signing keypair at `$STATE_DIR/review-signing-key.pem` (mode `0600`) and prints the pubkey loudly to stderr. AGT-327 shipped this; see [`src/server/bootstrap-review-key.ts`](../src/server/bootstrap-review-key.ts).

Fetch it (or grab it from the boot logs):

```sh
ssh -p <port> git@<stamp-server-host> stamp-server-pubkey --review-signing
```

Hold onto the output — you'll commit it into each repo's `.stamp/trusted-keys/`.

### Step 3 — Per-repo: scaffold v4 trust anchors

For each repo on this server:

```sh
git checkout -b stamp-2x-migration

# Commit the server's review-signing pubkey
mkdir -p .stamp/trusted-keys
echo "<paste pubkey from step 2>" > .stamp/trusted-keys/review-server.pub

# Scaffold the manifest + path_rules
stamp init --migrate-to-server-attested
# (pass --dry-run first to preview what gets written)
```

`stamp init --migrate-to-server-attested` does:

1. Creates `.stamp/trusted-keys/manifest.yml` listing every existing `.pub` in `.stamp/trusted-keys/` with its fingerprint and `capabilities: [operator]` by default (conservative — keys are not auto-promoted to `admin` or `server`).
2. Appends a default `path_rules: ".stamp/**":` block to `.stamp/config.yml` with `require_capability: admin`, `minimum_signatures: 2`, `bypass_review_cycle: true`.
3. From a TTY, prompts you to pick which existing operator keys should also gain `admin` capability for trust-anchor changes. **From non-interactive stdin (agent migrations), no keys are promoted** — a `warning:` line surfaces this; you must hand-edit the manifest before any `.stamp/**` change can land.

Two follow-up edits the command does NOT do for you (it can't infer the
values) — you make them by hand before the migration commit lands:

- **Promote the review-server entry to `[server]`.** Edit
  `.stamp/trusted-keys/manifest.yml` to change the review-server pubkey's
  entry to `capabilities: [server]` and add `role_source: server`.
- **Add `review_server` to `.stamp/config.yml`.** Under your branch rule
  (e.g. `branches.main`), add `review_server: ssh://git@<host>:<port>`
  pointing at your stamp-server.

**Single-trusted-key repos:** if your `.stamp/trusted-keys/` has only one
pubkey, `minimum_signatures: 2` will block every future `.stamp/**` change
(only one key can sign, two are required). Either set
`minimum_signatures: 1` in the appended `path_rules` block or add a second
admin key to the manifest before landing the migration commit.

After the scaffold, `.stamp/trusted-keys/manifest.yml` looks something like:

```yaml
keys:
  alice:
    fingerprint: sha256:aaa...
    capabilities: [admin, operator]
  bob:
    fingerprint: sha256:bbb...
    capabilities: [admin, operator]
  agent-bot:
    fingerprint: sha256:ccc...
    capabilities: [operator]
  review-server-prod:
    fingerprint: sha256:ddd...
    capabilities: [server]
    role_source: server
```

`path_rules` in `.stamp/config.yml`:

```yaml
path_rules:
  ".stamp/**":
    require_capability: admin
    minimum_signatures: 2     # tune per team — 1 is permitted but reduces blast radius protection
    bypass_review_cycle: true
```

### Step 4 — Land the migration commit through the 1.x gate

The migration commit itself goes through the existing 1.x reviewer flow (you don't yet have v4 enforcement live for this repo):

```sh
git add .stamp
git commit -m "stamp 2.x migration: scaffold v4 trust anchors"
stamp review --diff main..stamp-2x-migration
stamp status --diff main..stamp-2x-migration
git checkout main
stamp merge stamp-2x-migration --into main
stamp push main
```

From the next commit forward on `main`, the server's pre-receive hook enforces v4 verification:

- Every approval needs a valid `server_attestation.signature`.
- Every `.stamp/**` change needs `minimum_signatures` admin-capability signatures.
- `trusted_keys_snapshot_sha256` must match the manifest at `base_sha`.

### Step 5 — First review under v4

```sh
git checkout -b first-2x-feature
# ...edit, commit...
stamp review --diff main..first-2x-feature
```

`stamp review` now talks SSH to the server's `stamp-review` verb (AGT-328 shipped the SSH-verb scaffold). Each verdict comes back signed; `stamp merge` folds those signatures into a v4 envelope.

### Step 6 — Repeat for each repo

Steps 3–5 are per-repo. Different repos can be on different stamp lines simultaneously — `review_server` is per-repo opt-in. Migrate at your team's pace.

---

## Upgrade walkthrough — Shape 2 (PR mode)

If GitHub is your primary remote and you don't want to flip dev surface to stamp-server, run stamp-server as a review-only secondary. A GitHub Action auto-mirrors every push to stamp-server, which signs verdicts; `stamp/verify-attestation@v1` validates them as a required PR check.

### Step 1 — Same as Shape 1

Upgrade stamp-server to 2.x and capture the review-signing pubkey (see [Shape 1 steps 1–2](#step-1--upgrade-stamp-server-to-a-2x-capable-build)).

### Step 2 — Mint a mirror SSH user on stamp-server

The mirror Action pushes to stamp-server using an SSH keypair stored as a GitHub organization secret.

```sh
# On stamp-server: mint a service-account user the mirror Action will push as
ssh -p <port> git@<host> stamp-mint-invite mirror --role member

# Generate an SSH keypair locally; private goes to GitHub, pub goes to stamp-server
ssh-keygen -t ed25519 -f /tmp/stamp-mirror -N ""
# Register /tmp/stamp-mirror.pub against the `mirror` user via the invite flow
# (one keypair for the whole org — same key used by every repo's mirror workflow)
```

Add the private key as a GitHub **organization secret** (e.g. `STAMP_MIRROR_KEY`), scoped to repos using stamp.

### Step 3 — Per-repo: scaffold the mirror workflow + v4 trust anchors

In each repo:

```sh
git checkout -b stamp-2x-migration

# Same trust-anchor scaffold as Shape 1. Run this FIRST, then hand-add
# `review_server` to .stamp/config.yml (so the next step can substitute
# host/port into the workflow template).
stamp init --migrate-to-server-attested

# Scaffold the GitHub Action that mirrors every push to stamp-server.
# Reads host/port from the `review_server` URL the previous step added,
# and org/repo from `git remote get-url origin`.
stamp init --pr-mode
```

`stamp init --pr-mode` installs:

- `.github/workflows/stamp-mirror.yml` — pushes the ref to stamp-server on every GitHub push, using `STAMP_MIRROR_KEY` (org-level secret). Host, port, org, repo are substituted from `review_server` + `origin`.
- Prints a walkthrough to stdout covering keypair generation, the `stamp-mint-invite mirror --role member` step on stamp-server, and the GitHub org-secret registration URL.

The PR-check workflow (`.github/workflows/stamp-verify.yml`) is dropped separately by the mode-aware default in `stamp init` (it lands automatically for forge-direct / local-only modes; opt out with `--no-pr-check`). The trust-anchor scaffold from `--migrate-to-server-attested` is identical to Shape 1's step 3.

> Running `--pr-mode` is idempotent — an existing `stamp-mirror.yml` is left in place so operator customizations (concurrency block, fork-PR gating, etc.) survive re-runs. Pass `--pr-mode-force` to overwrite (useful after configuring `review_server` so the host/port placeholders fill in).

### Step 4 — Land the migration commit through 1.x

Same as Shape 1 step 4. Once main moves, v4 enforcement is live for this repo via the GitHub Action.

### Step 5 — Per-PR developer flow under v4

```sh
git checkout -b feature
# ...edit, commit...
stamp review --diff main..HEAD          # reviews via stamp-server, signed verdicts in local DB
stamp attest --into main --push origin  # signs envelope, pushes branch + attestation ref
# Open PR; mirror workflow pushes to stamp-server; verify workflow checks the attestation;
# green check → merge in GitHub UI
```

The attestation is keyed on `git patch-id`, so it survives squash / rebase / merge-commit — same property as 1.x PR-mode.

#### v3 PR-attestation shape (verifier + producer, AGT-338 + AGT-355)

The Action's verifier ships in 2.x at envelope `schema_version: 3`. v3 envelopes carry the same v4-trust fields the server-gated commit-trailer envelope does — per-approval server attestations (one per required reviewer, byte-canonical `ApprovalV4` shape), a top-level `diff_sha256` binding the operator's outer signature to the actual diff, the manifest snapshot hash for lenient revocation, and `trust_anchor_signatures` (admin counter-signatures) populated when the diff touches a `path_rules` glob. The shared `verifyV4*` phase helpers in `src/lib/v4Trust.ts` run against both the v3 PR-envelope's embedded fields and the v4 commit-trailer envelope, but PR-mode runs a deliberate **subset** of the phases (`PR_MODE_PHASES_V4` omits `verifyV4MergeStructure` because PR-mode runs BEFORE a 2-parent merge commit exists). The shared phase logic is identical; the phase set differs.

The verifier rejects v2 envelopes (produced by 1.x `stamp attest` or by 2.x `stamp attest` against a branch rule without `review_server`) with a "schema_version too old" actionable error. v2 envelopes pre-date the v4 trust model and cannot be upgraded in place — re-attestation against a 2.x stamp-server is required.

**End-to-end v3 production is live as of 2.0.1.** When a branch rule declares `review_server`, `stamp review` requests server-attested verdicts via SSH and persists the server-signed approval rows in the local DB, then `stamp attest` folds those rows into a v3 PR-attestation envelope and operator-signs the outer. The GH Action accepts the envelope directly — no 1.x-action pin or bridge-window workaround needed. The wire-protocol surface for the server-signed bytes is documented in `src/server/reviewPipeline.ts` (`ReviewPipelineResult.pr_attestation_v3_*` fields).

### Step 6 — Repeat for each repo

Each repo independently opts in via its own `review_server` config and mirror workflow. Mix-and-match across the org is supported.

---

## Local-only operators

If your 1.x deployment is purely local-only (`stamp init --mode local-only`, no server, attestations signed but no remote enforcement), 2.x changes very little for you functionally — and clarifies the framing.

**What changes:**

- `stamp review` without a configured `review_server` now errors out instead of running the LLM locally and silently producing a verdict that looks like a trust gate.
- Use `stamp review --plan` (AGT-339, shipped) or `stamp review --headless` (AGT-341, shipped) for the iteration loop.
- No v4 attestation is produced. The "local-only attestation" of 1.x was operator-trust-only; 2.x is honest about it and does not pretend to offer one.

**What stays:**

- `stamp review --plan` emits the structured plan a parent Claude Code session can dispatch to subagents. Fast feedback loop preserved.
- `stamp review --headless` calls the Anthropic API directly via `@anthropic-ai/sdk` — billed against your `ANTHROPIC_API_KEY`, no parent agent required. Suitable for cron, git hooks, CI.
- The signing key, the git surface, and `stamp verify` against any v2/v3 commit all continue to work.

See [`local-only-mode.md`](./local-only-mode.md) for the full local-only contract, the security boundary, and the headless billing caveat.

If you later decide you want the trust property, you can flip the same repo into Shape 1 or Shape 2 by deploying stamp-server and adding `review_server` — there's nothing to undo on the local-only side.

---

## FAQ

### Will my old (1.x v2/v3) attestations still verify?

**Yes.** v4 enforcement applies forward from the point a repo opts in via `path_rules` + `review_server` config. Past commits on `main` retain their v2/v3 attestations and remain verifiable under their original schema rules. `stamp log` shows both. The pre-receive hook and `stamp/verify-attestation@v1` accept v2/v3 attestations on commits that predate the migration commit.

This is the "lenient revocation" pattern applied to schema upgrades: revoking trust forward never retroactively invalidates clean history.

### Can I run stamp 1.x and 2.x side by side?

**Yes, per-repo.** Whether a repo enforces v4 is determined by whether `review_server` is configured in `.stamp/config.yml` at `base_sha`. Repos without it stay on operator-trust 1.x verification. Repos with it require v4 server signatures.

Across an org, you can migrate one repo at a time. The same stamp-server can host both 1.x and 2.x repos simultaneously — the review-capability env vars are server-wide, but each repo's enforcement is repo-local.

The bridge release (1.x final) is the only stamp-cli version that accepts *either* trust model on the operator side. stamp 2.0 GA enforces 2.x semantics where `review_server` is configured and errors out where it is missing (with a pointer to `--plan` / `--headless` for local-only).

### What about my `mcp_servers` / `tools` config?

**Warned and ignored in Phase 1.** The Phase 1 server reviewer is diff-only: no Read/Grep/WebFetch, no MCP servers. If your `.stamp/config.yml` declares `tools:` or `mcp_servers:` blocks for a reviewer, stamp 2.x emits a warning at review time and ignores them. The v4 attestation envelope drops `tools_sha256`, `mcp_sha256`, and `tool_calls`.

**If you rely on these surfaces** (e.g. a `product` reviewer that uses a Linear MCP to cross-check ticket references), you have three options:

1. **Adapt the reviewer prompt to work from the diff alone.** Most "look up the linked ticket" use cases can be satisfied with a stricter convention on what the diff itself must include (e.g. require the PR description to summarize ticket state in the diff context). See the "Diff context sufficiency" open question in [`plans/server-attested-reviews.md`](./plans/server-attested-reviews.md).
2. **Move the integration to a pre-merge `required_checks` entry.** Mechanical checks (the Linear ticket exists and is in the expected state) can run as a check, not as reviewer-tool access. The check exit code gates the merge; the reviewer reads only the diff.
3. **Stay on 1.x for that specific repo.** If the MCP-driven reviewer is load-bearing and can't be adapted, defer the migration on that repo until the Phase 2 "richer-context reviewer" surface is re-introduced (no committed timeline; tracked in the plan doc's "Deferred to Phase 2" list).

We expect option 1 to cover the majority of cases. Option 3 is an honest escape hatch; the bridge release exists to make it possible.

### What's the cost story?

**Phase 1 requires an `ANTHROPIC_API_KEY` on stamp-server.** Per-review token spend is billed against that key. Order-of-magnitude: a single reviewer running against a typical feature diff (< 200 LoC) on Sonnet 4.6 costs single-digit cents; a heavy `product` reviewer with a verbose prompt against a large diff can reach low double-digit cents per invocation.

**Headless local-only mode (`stamp review --headless`)** also bills against `ANTHROPIC_API_KEY`, but the key lives on the operator's workstation. Same per-token economics.

**`stamp review --plan` mode** dispatches reviewers through the parent Claude Code session — unmetered by the June 15 API/subscription split. Cheapest path during fast iteration; produces no attestation. See the "Metering caveat" note in [`local-only-mode.md`](./local-only-mode.md).

For most teams the per-merge cost is dwarfed by hosting (Railway / Fly / etc.). For high-volume agent fleets, set `STAMP_REVIEWER_MAX_TURNS` and per-reviewer `max_turns` / `timeout_ms` defensively — see [`README.md` "Reviewer execution budgets"](../README.md#reviewer-execution-budgets).

### Re-key cadence?

- **`server` capability keys:** Rotate annually or immediately on suspected compromise. Lenient revocation means rotation does not retroactively invalidate clean history — past merges remain valid because their `trusted_keys_snapshot_sha256` references the pre-rotation manifest. Future merges fail until the new key is committed to the manifest.
- **`admin` capability keys:** Rotate when team membership changes (a departing admin's key should not stay trusted) or on compromise. Use multi-sig (`minimum_signatures: 2+`) so a single admin departure doesn't lock anyone out of trust-anchor changes.
- **`operator` capability keys:** No required cadence. Rotate on machine compromise or workstation replacement; otherwise leave alone.

The operator surface for rotation lives under `stamp admin`:

```
stamp admin list-keys                                   # enumerate manifest entries
stamp admin add-key <pubkey.pub> --name <n> --capabilities admin,operator
stamp admin revoke <sha256:fingerprint>                 # remove a manifest entry
stamp admin sign --pending [<sha>]                      # collect multi-admin counter-sigs
```

`add-key` and `revoke` mutate `.stamp/trusted-keys/manifest.yml`, so the
resulting commits trip the `path_rules` gate and need admin counter-sigs
collected via `stamp admin sign --pending <sha>` (notes-ref-backed) before
they can land via `stamp merge`. The `add-key` command refuses any PEM
that lacks `-----BEGIN PUBLIC KEY-----` — guards against a typo'd path to
the private key file silently copying the secret into the trusted-keys
directory.

### Do I have to commit `.stamp/trusted-keys/manifest.yml`?

**Yes** — it's part of the trust anchor and the verifier reads it from the merge commit's own tree. The pre-receive hook computes `trusted_keys_snapshot_sha256` from the committed file and rejects on mismatch with the value the server signed.

The manifest is human-editable but **the changes that land it must be admin-signed** (because manifest.yml is under `.stamp/**`, which is gated by `path_rules`). Bootstrapping the first manifest into a repo goes through the 1.x reviewer cycle one last time during the migration commit (Step 4); from there forward, admin signatures replace the reviewer cycle for `.stamp/**`.

### What if my operator key is already in `.stamp/trusted-keys/` — does it gain admin capability automatically?

**No.** `stamp init --migrate-to-server-attested` defaults every existing key to `capabilities: [operator]`. You explicitly promote selected keys to `[admin, operator]` during the migration scaffold (interactive prompt — see the plan doc's open question on the exact UX).

This is deliberate. An automated promotion would conflate "this key can merge code" (operator) with "this key can change the rules" (admin), which is exactly the conflation v4 is designed to break.

---

## Deprecation timeline

- **Bridge release (1.x final, `@openthink/stamp@1.10.0`)** — ships with
  deprecation notices wired into `stamp init` and `stamp merge` (one-line
  stderr banner on each invocation), a README banner, and the operator-trust
  caveat at the top of `DESIGN.md`'s security-model section. Both 1.x and
  2.x verification work side by side, per-repo. The CLI banner is
  suppressible with `STAMP_SUPPRESS_DEPRECATION=1` for CI / scripted
  automation; interactive operators are expected to see it.
- **stamp 2.0 GA (`@openthink/stamp@2.0.0`)** and **2.0.1** — `stamp review`
  requires `review_server` configured (or `--plan` / `--headless` for
  local-only). Old v2/v3 attestations on already-merged commits remain
  verifiable indefinitely. Default `stamp init` scaffolds 2.x-aware config;
  `--mode local-only` opts into no-trust mode with an explicit banner.
- **2.x maintenance:** the 1.x line moves to security-patches-only after
  2.0 GA. Operators who can't migrate immediately can pin to
  `@openthink/stamp@legacy-1` (the 1.10.0 release) — the patch window is
  per-issue rather than a fixed N-month commitment.

If your team has a long-running 1.x deployment that can't migrate
immediately, `@legacy-1` is your stable landing pad.

---

## Common migration issues

For the path-of-most-operators issues, see the expanded entries in [`troubleshooting.md`](./troubleshooting.md). The most common migration-specific gotchas:

- **`stamp review` errors with "review_server not configured."** You're on stamp 2.x but `.stamp/config.yml` lacks `branches.<name>.review_server`. Either configure a `review_server`, or use `stamp review --plan` / `stamp review --headless` for local-only iteration.
- **Pre-receive hook rejects "trusted_keys_snapshot_sha256 mismatch."** The manifest at `base_sha` doesn't match what the server signed. Most common cause: you edited `.stamp/trusted-keys/manifest.yml` on the feature branch without admin signatures. `.stamp/**` changes need to go through the `path_rules` gate, not the reviewer cycle.
- **Pre-receive hook rejects "no trusted server key matches `server_key_id`."** The review-signing pubkey on stamp-server doesn't have a matching entry in `.stamp/trusted-keys/manifest.yml` with `capabilities: [server]`. Re-run step 2 to fetch the current pubkey, commit it, and land the change as an admin-signed `.stamp/**` update.
- **Migration commit itself fails to merge under v4.** The migration commit must land via the 1.x flow because v4 enforcement only kicks in for commits *after* the trust anchors are committed. If you accidentally pushed `path_rules` to the manifest before committing the migration scaffold itself, you may need to roll back to the last pre-migration commit and re-attempt. See [`troubleshooting.md`](./troubleshooting.md)'s "stamp push is rejected" section.
- **`tools:` / `mcp_servers:` warnings.** Expected — Phase 1 doesn't support them; they're warned + ignored. See the [FAQ entry](#what-about-my-mcp_servers--tools-config) for adaptation strategies.

---

## Implementation status

All of the migration surface referenced in this guide is shipped on `main`
and published to npm at `@openthink/stamp@2.0.1`:

- **Trust-anchor scaffold** — `stamp init --migrate-to-server-attested`
  (with `--dry-run`).
- **Bridge-release deprecation messaging** — `stamp init` / `stamp merge`
  stderr banner, README banner, `DESIGN.md` operator-trust caveat
  (suppressible via `STAMP_SUPPRESS_DEPRECATION=1`).
- **`stamp review` enforcement** — errors when `review_server` is missing
  in 2.x; falls through to `--plan` / `--headless` for local-only.
- **Server-side v3 PR-attestation production** — stamp-server signs and
  returns the v3 PR-attestation payload via the SSH `stamp-review` verb;
  `stamp attest` folds the server-signed approvals into a v3 envelope
  when the branch rule declares `review_server`. The 2.x action accepts
  this envelope directly — no 1.x-action pin or bridge-window workaround
  required.
- **Trust-anchor administration** — `stamp admin list-keys`,
  `stamp admin add-key`, `stamp admin revoke`, `stamp admin sign --pending`
  for multi-admin counter-sig collection (notes-ref-backed).

See [`plans/server-attested-reviews.md`](./plans/server-attested-reviews.md)'s
"Implementation status" block for the per-ticket file references.

---

## See also

- [`plans/server-attested-reviews.md`](./plans/server-attested-reviews.md) — full design + threat model
- [`../DESIGN.md`](../DESIGN.md) — current attestation schema and security model (v4 resolution)
- [`quickstart-server.md`](./quickstart-server.md) — from-zero server setup walkthrough
- [`local-only-mode.md`](./local-only-mode.md) — `--plan` / `--headless` iteration paths
- [`troubleshooting.md`](./troubleshooting.md) — common failures with concrete fixes
- [`../server/README.md`](../server/README.md) — stamp-server deployment guide
