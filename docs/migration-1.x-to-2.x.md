# Migrating from stamp 1.x to 2.x

stamp 2.x introduces **server-attested reviews**: the LLM call moves into stamp-server, which holds its own signing key and signs every verdict. The operator no longer constructs both sides of "what the LLM saw" and "what the LLM said" — a forged review now requires forging a server signature, which requires either compromising the server or stealing its key.

This guide walks you through the upgrade. Read [`plans/server-attested-reviews.md`](./plans/server-attested-reviews.md) first if you want the full design rationale; this doc focuses on the operational steps.

> **Scope.** Some of the commands referenced below ship in tickets that have not yet landed on `main`. Those are flagged inline (e.g. *will ship via AGT-342*). The shape is settled; the exact UX may move slightly. Check the linked ticket if a command name has drifted.

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
| **Attestation envelope** | `schema_version: 2` / `3` | `schema_version: 4` ([`src/lib/attestationV4.ts`](../src/lib/attestationV4.ts)) |
| **Reviewer features** | `tools:` + `mcp_servers:` per reviewer; Read/Grep/WebFetch allowlisted | Phase 1 reviewers are diff-only; `tools` / `mcp_servers` config is warned + ignored |
| **`stamp review` (trusted mode)** | Runs LLM locally via Claude Agent SDK | Calls stamp-server's `stamp-review` SSH verb; server runs the LLM and signs the verdict |
| **Trust anchor (`.stamp/**`) changes** | Gated by the same reviewer cycle as any other diff | Gated by `path_rules` requiring `admin`-capability signatures; reviewer cycle bypassed for these paths |
| **`stamp review` with no `review_server`** | Runs locally and writes the verdict to `state.db` (gate-eligible) | Errors out with a pointer to this guide or to `--plan` / `--headless` ([`local-only-mode.md`](./local-only-mode.md)) — *enforcement lands in AGT-347* |

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

### Step 0 — On the 1.x bridge release

Before flipping anything, upgrade your operator workstations to the **bridge release** (stamp 1.x final). The bridge release ships with deprecation notices pointing at this guide; both 1.x operator-trust and 2.x server-attested verification work side by side per-repo via `review_server` config.

```sh
npm install -g @openthink/stamp@1.x-final   # exact tag TBD by AGT-346
```

Existing repos keep working on operator-trust until you flip them.

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

# Scaffold the manifest + path_rules + config additions
stamp init --migrate-to-server-attested   # _will ship via AGT-342_
```

`stamp init --migrate-to-server-attested` (scaffolded in AGT-342) does:

1. Creates `.stamp/trusted-keys/manifest.yml` listing every existing `.pub` in `.stamp/trusted-keys/` with its fingerprint.
2. Assigns `capabilities: [operator]` to every existing key by default (conservative — you promote selected human keys to `admin` interactively).
3. Adds `capabilities: [server]` and `role_source: server` to the review-server entry.
4. Adds `branches.<name>.review_server: ssh://git@<host>:<port>` and a `path_rules: ".stamp/**":` block to `.stamp/config.yml`.
5. Prompts you to pick which existing operator keys should also gain `admin` capability for trust-anchor changes.

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

# Scaffold the GitHub Action that mirrors every push to stamp-server
stamp init --pr-mode           # _will ship via AGT-343_

# Same trust-anchor scaffold as Shape 1
stamp init --migrate-to-server-attested   # _will ship via AGT-342_
```

`stamp init --pr-mode` (scaffolded in AGT-343) installs:

- `.github/workflows/stamp-mirror.yml` — pushes the ref to stamp-server on every GitHub push, using `STAMP_MIRROR_KEY`.
- `.github/workflows/stamp-verify.yml` — runs `stamp/verify-attestation@v1` on every PR; required check via GitHub branch protection.

The trust-anchor scaffold from AGT-342 is identical to Shape 1's step 3.

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

### Step 6 — Repeat for each repo

Each repo independently opts in via its own `review_server` config and mirror workflow. Mix-and-match across the org is supported.

---

## Local-only operators

If your 1.x deployment is purely local-only (`stamp init --mode local-only`, no server, attestations signed but no remote enforcement), 2.x changes very little for you functionally — and clarifies the framing.

**What changes:**

- `stamp review` without a configured `review_server` now errors out instead of running the LLM locally and silently producing a verdict that looks like a trust gate ([AGT-347](#in-flight-references) finalizes this).
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

The exact `stamp admin revoke-key <fingerprint>` flow is still being finalized — see the plan doc's open questions on revocation tooling.

### Do I have to commit `.stamp/trusted-keys/manifest.yml`?

**Yes** — it's part of the trust anchor and the verifier reads it from the merge commit's own tree. The pre-receive hook computes `trusted_keys_snapshot_sha256` from the committed file and rejects on mismatch with the value the server signed.

The manifest is human-editable but **the changes that land it must be admin-signed** (because manifest.yml is under `.stamp/**`, which is gated by `path_rules`). Bootstrapping the first manifest into a repo goes through the 1.x reviewer cycle one last time during the migration commit (Step 4); from there forward, admin signatures replace the reviewer cycle for `.stamp/**`.

### What if my operator key is already in `.stamp/trusted-keys/` — does it gain admin capability automatically?

**No.** `stamp init --migrate-to-server-attested` defaults every existing key to `capabilities: [operator]`. You explicitly promote selected keys to `[admin, operator]` during the migration scaffold (interactive prompt — see the plan doc's open question on the exact UX).

This is deliberate. An automated promotion would conflate "this key can merge code" (operator) with "this key can change the rules" (admin), which is exactly the conflation v4 is designed to break.

---

## Deprecation timeline

The detailed timeline + deprecation messaging lands in **AGT-346**. Rough shape:

- **Bridge release (stamp 1.x final):** ships with prominent deprecation notices wired into `stamp init`, `stamp review`, and `stamp merge` output. Both 1.x and 2.x verification work side by side, per-repo. README and `DESIGN.md` carry forward-pointers to this guide.
- **stamp 2.0 GA:** `stamp review` requires `review_server` configured (or `--plan` / `--headless` for local-only). Old v2/v3 attestations on already-merged commits remain verifiable indefinitely. Default `stamp init` scaffolds 2.x-aware config; `--local-only` flag opts into no-trust mode with an explicit banner.
- **2.x maintenance:** 1.x receives security patches only for N months after 2.0 GA — exact window finalized by AGT-346.

If your team has a long-running 1.x deployment that can't migrate immediately, the bridge release is your stable landing pad until AGT-346 publishes the patch window.

---

## Common migration issues

For the path-of-most-operators issues, see the expanded entries in [`troubleshooting.md`](./troubleshooting.md). The most common migration-specific gotchas:

- **`stamp review` errors with "review_server not configured."** You're on stamp 2.x but `.stamp/config.yml` lacks `branches.<name>.review_server`. Either configure a `review_server`, or use `stamp review --plan` / `stamp review --headless` for local-only iteration.
- **Pre-receive hook rejects "trusted_keys_snapshot_sha256 mismatch."** The manifest at `base_sha` doesn't match what the server signed. Most common cause: you edited `.stamp/trusted-keys/manifest.yml` on the feature branch without admin signatures. `.stamp/**` changes need to go through the `path_rules` gate, not the reviewer cycle.
- **Pre-receive hook rejects "no trusted server key matches `server_key_id`."** The review-signing pubkey on stamp-server doesn't have a matching entry in `.stamp/trusted-keys/manifest.yml` with `capabilities: [server]`. Re-run step 2 to fetch the current pubkey, commit it, and land the change as an admin-signed `.stamp/**` update.
- **Migration commit itself fails to merge under v4.** The migration commit must land via the 1.x flow because v4 enforcement only kicks in for commits *after* the trust anchors are committed. If you accidentally pushed `path_rules` to the manifest before committing the migration scaffold itself, you may need to roll back to the last pre-migration commit and re-attempt. See [`troubleshooting.md`](./troubleshooting.md)'s "stamp push is rejected" section.
- **`tools:` / `mcp_servers:` warnings.** Expected — Phase 1 doesn't support them; they're warned + ignored. See the [FAQ entry](#what-about-my-mcp_servers--tools-config) for adaptation strategies.

---

## In-flight references

This guide forward-points to several tickets that ship the migration commands. Status as of writing:

- **AGT-342** — `stamp init --migrate-to-server-attested` scaffolding. *In flight.* Until it ships, the scaffold steps can be done by hand following the manifest + path_rules examples above.
- **AGT-343** — `stamp init --pr-mode` workflow scaffolding. *In flight.* Until it ships, copy `.github/workflows/stamp-mirror.yml` + `stamp-verify.yml` from a reference deployment.
- **AGT-346** — bridge-release deprecation messaging + the exact 1.x EOL window. *In flight.*
- **AGT-347** — finalizes the `stamp review` no-`review_server` error path in 2.0 GA. *In flight.*

Already shipped on `main`:

- **AGT-325 / AGT-326 / AGT-327 / AGT-329 / AGT-333 / AGT-339 / AGT-340 / AGT-341 / AGT-344 / AGT-350** — see [`plans/server-attested-reviews.md`](./plans/server-attested-reviews.md)'s "Implementation status" block for the per-ticket file references.

When a command's exact UX is settled, this guide will be updated to drop the *will ship via AGT-XXX* annotations.

---

## See also

- [`plans/server-attested-reviews.md`](./plans/server-attested-reviews.md) — full design + threat model
- [`../DESIGN.md`](../DESIGN.md) — current attestation schema and security model (v4 resolution)
- [`quickstart-server.md`](./quickstart-server.md) — from-zero server setup walkthrough
- [`local-only-mode.md`](./local-only-mode.md) — `--plan` / `--headless` iteration paths
- [`troubleshooting.md`](./troubleshooting.md) — common failures with concrete fixes
- [`../server/README.md`](../server/README.md) — stamp-server deployment guide
