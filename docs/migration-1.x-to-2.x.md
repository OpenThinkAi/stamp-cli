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

stamp 2.x supports four deployment shapes. Pick deliberately — the upgrade path differs.

### Shape 1 — stamp-server as the primary git remote

You push directly to stamp-server; the pre-receive hook is the source of truth. Best fit if you already deployed stamp-server in 1.x or if you want the strongest enforcement and don't need GitHub's PR UI in the loop.

Go to [Upgrade walkthrough — Shape 1](#upgrade-walkthrough--shape-1-stamp-server-primary).

### Shape 2 — removed (was: GitHub primary, stamp-server mirrors for review)

Shape 2 (mirror-mode PR — a GitHub Action mirrored every push to stamp-server) was **removed**, superseded by **Shape 4**, which delivers the same server-attested PR verification without mirroring your full source. If you're on Shape 2, see [Shape 2 (mirror-mode PR) — removed](#shape-2-mirror-mode-pr--removed) for the migration steps.

### Shape 3 — Local-only (iteration feedback, no trust)

No server. `stamp review --plan` emits a structured plan for a parent Claude Code session to dispatch, or `stamp review --headless` calls Anthropic directly with `ANTHROPIC_API_KEY`. **Produces no attestation in 2.x** — verdicts are advisory.

If your 1.x deployment was already operator-trust-only without a server, this is your natural landing shape. The functional behavior doesn't change; the framing does ("no trust" is now explicit rather than implicit-and-unfortunate).

Go to [Local-only operators](#local-only-operators).

### Shape 4 — GitHub primary, server-attested without code transfer (private repos)

GitHub holds the source of truth and runs the PR UI. **stamp-server never receives a clone** — `stamp review` SSHes only the diff plus identifying metadata; the server reads its own bundled reviewer prompts from `/etc/stamp/reviewers/` (baked into the Docker image at build time), hashes them, runs the LLM, and signs the verdict. The signed verdict travels back over SSH; the operator folds it into a v4 envelope locally and `stamp/verify-attestation@v1` validates it as a required PR check.

Best fit if your code must not leave its git host — private/internal codebases, compliance constraints, or any repo where mirroring the full source to stamp-server is a non-starter.

Trust model: the server's review-signing key controls the prompt bytes (because prompts are image-baked, not host-mounted), and the verifier validates the server's signature against the manifest at base_sha — with no mirror workflow and no bare-repo clone on stamp-server.

Go to [Upgrade walkthrough — Shape 4](#upgrade-walkthrough--shape-4-server-attested-without-code-transfer).

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

`stamp update` itself is a stable 1.x+2.x command (see
[README "Maintenance"](../README.md#commands)) — operators on any 1.x
release ≥ 0.7.x can use it to step forward to 2.0.1.

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

## Shape 2 (mirror-mode PR) — removed

> **Shape 2 was removed.** `stamp init --pr-mode` / `--pr-mode-force`, the scaffolded `.github/workflows/stamp-mirror.yml`, and the `STAMP_MIRROR_KEY` org secret are gone. Shape 2 mirrored your full source into stamp-server on every push; **Shape 4 (server-attested without code transfer)** delivers the same server-signed PR attestation without that mirror.
>
> **If you were on Shape 2:**
> 1. Migrate to Shape 4 — follow the [Shape 4 walkthrough](#upgrade-walkthrough--shape-4-server-attested-without-code-transfer).
> 2. Delete `.github/workflows/stamp-mirror.yml` from your repo.
> 3. Remove the `STAMP_MIRROR_KEY` org secret (no longer used).
> 4. The `stamp/verify-attestation@v1` required check stays — Shape 4 uses the same verification.
>
> No attestation history is lost: existing signed merges verify unchanged.

### v3 PR-attestation envelope (shared verifier shape, AGT-338 + AGT-355)

The Action's verifier ships in 2.x at envelope `schema_version: 3`, used by the server-attested PR flow (Shape 4). v3 envelopes carry the same v4-trust fields the server-gated commit-trailer envelope does — per-approval server attestations (one per required reviewer, byte-canonical `ApprovalV4` shape), a top-level `diff_sha256` binding the operator's outer signature to the actual diff, the manifest snapshot hash for lenient revocation, and `trust_anchor_signatures` (admin counter-signatures) populated when the diff touches a `path_rules` glob. The shared `verifyV4*` phase helpers in `src/lib/v4Trust.ts` run against both the v3 PR-envelope's embedded fields and the v4 commit-trailer envelope, but the PR-attestation flow runs a deliberate **subset** of the phases (`PR_MODE_PHASES_V4` omits `verifyV4MergeStructure` because the PR flow runs BEFORE a 2-parent merge commit exists). The shared phase logic is identical; the phase set differs.

The verifier rejects v2 envelopes (produced by 1.x `stamp attest` or by 2.x `stamp attest` against a branch rule without `review_server`) with a "schema_version too old" actionable error. v2 envelopes pre-date the v4 trust model and cannot be upgraded in place — re-attestation against a 2.x stamp-server is required.

**End-to-end v3 production is live as of 2.0.1.** When a branch rule declares `review_server`, `stamp review` requests server-attested verdicts via SSH and persists the server-signed approval rows in the local DB, then `stamp attest` folds those rows into a v3 PR-attestation envelope and operator-signs the outer. The GH Action accepts the envelope directly — no 1.x-action pin or bridge-window workaround needed. The wire-protocol surface for the server-signed bytes is documented in `src/server/reviewPipeline.ts` (`ReviewPipelineResult.pr_attestation_v3_*` fields).

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

If you later decide you want the trust property, you can flip the same repo into Shape 1 or Shape 4 by deploying stamp-server and adding `review_server` — there's nothing to undo on the local-only side.

---

## Upgrade walkthrough — Shape 4 (server-attested without code transfer)

For repos that need server-attested reviews but cannot mirror their code to stamp-server. Full server-attested trust properties; no mirror workflow, no bare repo on the server, no per-repo deploy key. The server reads canonical reviewer prompts from its bundled image directory; the operator's repo never carries `.stamp/reviewers/*.md`.

The migration is a **single PR**. `stamp init --migrate-to-server-attested` scaffolds the complete Shape 4 surface (manifest, server pubkey, review_server URL, reviewer-cleanup, path_rules, verify workflow, reviewer-prompt deletions); `stamp attest --migrate-existing` produces the bootstrap envelope that lands in the same PR.

### Step 1 — Same as Shape 1

Upgrade stamp-server to a 2.1+ build (server-bundled reviewer prompts require 2.1).

The server image bundles canonical reviewer prompts (`security.md`, `standards.md`, `product.md`) at `/etc/stamp/reviewers/` at build time. Operators who maintain a fork of stamp-server edit `server/reviewers/*.md` in the fork and rebuild — see [`server/README.md`](../server/README.md#reviewer-prompts) for the editing workflow. Upstream `openthinkai/stamp-server:2.x` ships with the default prompt set.

### Step 2 — Per-repo: one-command scaffold

```sh
git checkout -b stamp-shape-4-activation
stamp init --migrate-to-server-attested --server <host:port>
```

The `--server <host:port>` flag tells the init flow where to fetch the server's review-signing pubkey. If you've already persisted the endpoint via `stamp server config --server <host:port>` (which writes `~/.stamp/server.yml`), the flag is optional — `stamp init` falls back to that file. If neither source is set the command refuses with a message naming both options.

**Non-interactive contexts (CI, agent runs): use `--admin-keys`.** The interactive admin-promotion prompt only fires when stdin is a TTY. Without a TTY, the command refuses to run unless you declare which detected key(s) should carry the `[admin]` capability via `--admin-keys`:

```sh
stamp init --migrate-to-server-attested \
  --server <host:port> \
  --admin-keys sha256:<alice-fingerprint>,sha256:<bob-fingerprint>
```

The flag accepts a comma-separated list of `sha256:<64hex>` fingerprints. Each must match a detected key under `.stamp/trusted-keys/`; unknown fingerprints are rejected with an error listing the available set. The flag is also accepted in TTY mode as an escape from the prompt. (Run the command once with `--dry-run` from a TTY to see the available fingerprints if you don't have them recorded.)

**Backward-compat note:** prior to this release `stamp init --migrate-to-server-attested` produced an offline Phase-1 scaffold (comment-out only, no server connection). That intermediate flow is gone — the command now reaches the server before writing. Automation that called it without a server endpoint will fail with the actionable error above instead of silently producing a partial scaffold.

The scaffold does ALL of the following in one command:

1. Detects existing `.stamp/trusted-keys/*.pub` files and writes (or extends) `.stamp/trusted-keys/manifest.yml`. On a fresh 1.x repo with no manifest, the operator picks which keys gain `admin` capability via an interactive prompt; existing manifests are preserved entry-for-entry (the bootstrap whitelist refuses any modification of an existing entry).
2. Fetches the stamp-server's review-signing public key over SSH (the wire protocol is `ssh -p <port> git@<host> stamp-server-pubkey --review-signing`; same SSH surface as the rest of stamp's server-side commands). Writes the pubkey to `.stamp/trusted-keys/review-server-prod.pub` and adds a `review-server-prod` manifest entry with `capabilities: [server]` and `role_source: server`.
3. Adds `review_server: ssh://git@<host>:<port>` to the default branch's rule in `.stamp/config.yml` (prefers `main`; otherwise the first branch listed).
4. Rewrites every reviewer entry in `.stamp/config.yml` to `{}` form (Shape 4 server-bundled prompt mode). The reviewer NAMES stay; the per-reviewer `prompt:`, `tools:`, `mcp_servers:` fields go.
5. Smart-defaults `path_rules: .stamp/**` `minimum_signatures` based on the admin-capability count: 1 when exactly one admin was selected (with a warning), 2 otherwise. A two-signature gate on a single-admin repo would deadlock every subsequent `.stamp/**` PR.
6. Deletes every `.stamp/reviewers/*.md` file (Shape 4 retires the in-repo prompt copies; the server holds the canonical bytes).
7. Writes `.github/workflows/stamp-verify.yml` (if absent) so subsequent PRs get verified in CI.

The combined effect produces a diff that `stamp attest --migrate-existing` accepts cleanly: the `.stamp/**` subset (config edit + manifest entry + new pubkey + reviewer-prompt deletions) is whitelisted by `validateShape4ActivationDiff`; the workflow file lives outside `.stamp/**` and is therefore outside the activation envelope (it doesn't need to be — the verifier runs in CI on the NEXT PR onward, not on the bootstrap PR itself).

**Trust model for the server pubkey: TOFU on the SSH transport.** The first fetch trusts whatever public key the server returns over the SSH channel. This is the same trust posture as every other stamp SSH operation (`stamp provision`, `stamp review`, `stamp server pubkey`). To harden post-setup, verify the fetched fingerprint out-of-band against the operator's independent record — the command prints the fingerprint at the end of its summary block. The recommended verification is:

```sh
ssh -p <port> git@<host> stamp-server-pubkey --review-signing | \
  openssl pkey -pubin -in - -outform DER | sha256sum
```

The output's hex digest, prefixed with `sha256:`, must equal the fingerprint in the freshly-written `.stamp/trusted-keys/manifest.yml` under the `review-server-prod` entry.

The flow is idempotent: re-running on a partially-migrated repo skips writes that already match the desired state (pubkey file with matching content, manifest entry, review_server URL, etc.), and warns to stderr without clobbering when something exists but differs.

**`--dry-run`** prints the proposed scaffold without writing or invoking the SSH fetch. The dry-run preview uses a `<SERVER_REVIEW_SIGNING_PUBKEY>` placeholder for the pubkey and a `sha256:<computed-at-real-run>` placeholder for the fingerprint, so the preview is offline-safe.

If you're moving from Shape 2 (mirror) to Shape 4: also delete `.github/workflows/stamp-mirror.yml`, remove the `stamp-mirror-only` ruleset on GitHub, drop the `STAMP_MIRROR_KEY` org secret, and on stamp-server delete the now-orphan `/srv/git/<repo>.git` bare and disable the mirror SSH user. These changes ride alongside the activation diff in the same PR.

**`required_checks` must be empty in PR mode.** PR-mode `stamp attest` writes `checks: []` into the v3 envelope by design — pre-merge tests run as GitHub Action checks (not at attest time), so duplicating them on the local side would produce a weaker signal at twice the cost (see [`src/commands/attest.ts`](../src/commands/attest.ts)'s file-level comment). If your repo's `.stamp/config.yml` carries a non-empty `required_checks: [...]` under the activated branch rule from a previous Shape 1 / 2.x deployment, the verifier will reject every Shape 4 attestation produced by `stamp attest` because the envelope's `checks: []` does not satisfy the rule. Set `required_checks: []` (or omit the key) on the activated branch rule as part of the Shape 4 activation diff. The whitelist accepts `required_checks` edits on the same branch rule that gains `review_server:`.

### Step 3 — SHA-pinning the verify Action

The `.github/workflows/stamp-verify.yml` file scaffolded by `--migrate-to-server-attested` references `stamp/verify-attestation` by **commit SHA**, not by mutable git tag:

```yaml
- name: stamp/verify-attestation
  uses: OpenThinkAi/stamp-cli/.github/actions/verify-attestation@<40-char-sha>
```

SHA-pinning is deliberate. A mutable tag (e.g. `@v1.6.1`) lets the upstream silently re-resolve to a different commit if the tag is force-moved; SHA-pinning makes the workflow identify the action's bytes immutably, which is the standard security-review posture for third-party GitHub Actions. The trailing-comment line in the rendered workflow names both the SHA and the human-readable version (e.g. `# Runs stamp/verify-attestation (SHA-pinned to <sha>; corresponds to v1.6.1) on every PR.`) so operators can cross-reference release notes without re-resolving.

**Bumping the pinned SHA (operators who fork the action source).** When stamp-cli ships a new `stamp/verify-attestation` release, the source of truth for resolving the human-readable tag to a commit SHA is:

```sh
gh api repos/OpenThinkAi/stamp-cli/git/ref/tags/<vX.Y.Z>
```

Take the `object.sha` from the JSON response. If `object.type` is `tag` (annotated tag), dereference one level:

```sh
gh api repos/OpenThinkAi/stamp-cli/git/tags/<sha>
```

Then update both the `uses:` line and the trailing-comment line on `.github/workflows/stamp-verify.yml` in your repos. Operators consuming a fork of stamp-cli's action (`--action-source <org/repo>` on `stamp init`) substitute their fork's path and use the same resolve command against their fork to pin to an immutable byte set in their own repo.

### Step 4 — Land the activation PR with `stamp attest --migrate-existing`

The Shape 4 activation commit deadlocks the normal flow because of a structural chicken-and-egg: `stamp review` sources `.stamp/config.yml` from `base_sha` (a security boundary — a feature branch cannot unilaterally point review at an attacker-controlled server), so review at base runs LOCALLY and the DB has no server signatures. `stamp attest` sources from the working tree, sees `review_server`, and demands a v3 envelope with the server signatures it cannot produce.

`stamp attest --migrate-existing` is the dedicated bootstrap flow for exactly this PR:

```sh
git add .
git commit -m "Shape 4: activate server-attested reviews"
stamp attest --into main --migrate-existing --push origin
# Open the PR; stamp/verify-attestation@v1 accepts the bootstrap envelope.
```

The bootstrap envelope is a v3-shaped envelope with empty `server_signatures`, a `migration_bootstrap` marker in the operator-signed payload naming the activated paths, and one operator-self admin counter-signature in `trust_anchor_signatures`. The verifier accepts it ONLY when ALL of:

- the diff matches a narrow Shape 4 activation whitelist (adds `review_server:` to a branch rule + adds `[server]`+`role_source:server` entries to the manifest + adds new `*.pub` files + deletes `.stamp/reviewers/*.md` files);
- the marker's `activated_paths` equals the actual changed files;
- the operator outer signature verifies;
- exactly one admin-capability signature is present, and it verifies against the bootstrap signing bytes;
- `path_rules` at `base_sha` covers every activated path with `bypass_review_cycle: true`;
- `approvals` is empty (a non-empty array is rejected as structurally invalid for a bootstrap envelope).

The narrow whitelist is the security boundary: an attacker cannot smuggle non-trust-anchor changes through the bootstrap path. The whitelist refuses any file outside `.stamp/`, any modification (not addition) of an existing manifest entry or pubkey, any branch-rule change other than `review_server:` addition, and any add or modification of `.stamp/reviewers/*.md` (deletions only are accepted there, mirroring the Shape 4 retirement of in-repo prompts). Run `stamp attest --migrate-existing` only on a PR whose diff is exactly the Shape 4 activation that `stamp init --migrate-to-server-attested` produces.

The `.github/workflows/stamp-verify.yml` change rides in the same PR but is outside the activation envelope — that's fine, the verifier doesn't gate on it. The workflow file becomes active on the NEXT PR.

Subsequent PRs use the normal flow (`stamp attest --into main --push origin`) once `main` carries the activated config.

### Step 5 — Per-PR developer flow under v4

```sh
git checkout -b feature
# ...edit, commit...
stamp review --diff main..HEAD          # SSHes diff to server; server reads its bundled prompts; signs verdicts
stamp attest --into main --push origin  # signs envelope, pushes branch + attestation ref
# Open PR; verify Action checks the attestation against the committed manifest at base_sha;
# green check → merge in GitHub UI
```

The wire protocol is the standard server-attested SSH flow — `stamp review` sends `--reviewer`, `--org`, `--repo`, `--base-sha`, `--head-sha`, `--diff-sha256` plus the diff on stdin. The server uses `--reviewer` to look up its bundled prompt at `/etc/stamp/reviewers/` (no bare-repo clone is involved). The reviewer name is validated against `REVIEWER_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/` before path construction (see `src/server/promptFetch.ts`) so `--reviewer` cannot be used to traverse out of `/etc/stamp/reviewers/`. No mirror workflow runs because none exists.

### Step 6 — Repeat for each repo

Each repo independently opts into server-attested review via its own `review_server` config. Mix-and-match across the org is supported against the same stamp-server.

### Verifier behavior (Shape 4 specifics)

`stamp/verify-attestation@v1` validates each approval's signature against the server key resolved from the manifest at base_sha, and re-runs the envelope-level `manifest_snapshot_sha256` check. It does NOT recompute `prompt_sha256` from the merge-base tree — in Shape 4 the prompts are not in the operator's repo, so there's nothing to recompute against. The trust chain for prompt bytes is: manifest (at base_sha) → server key with `server` capability → signed approval body → `prompt_sha256`. The recompute step that the server-gated path (Shape 1) runs was a belt-and-suspenders second-line defense; in Shape 4 it's structurally impossible and the signed chain is the trust anchor. See [`src/lib/v4Trust.ts`](../src/lib/v4Trust.ts) `verifyV4ApprovalSignatures` for the in-code rationale.

---

## Phase A → Phase B (external reviewer prompts)

stamp-server 2.1+ supports sourcing reviewer prompts from a separate github repo instead of (or in addition to) the prompts baked into the Docker image. This is **Phase B** in the project's roll-out. The trust property is unchanged — the server still controls which prompt bytes get fed to the LLM and still signs the resulting verdict against `prompt_sha256` — but the storage layer for those bytes is virtualized so you can iterate on reviewer prompts via `git push` instead of an image rebuild + redeploy.

This section is the **migration narrative**. The full configuration reference — env vars, deploy-key flow, webhook setup, first-boot expectations, troubleshooting matrix, threat-model table — lives in [`server/README.md`'s "Phase B — external prompts via webhook" section](../server/README.md#phase-b--external-prompts-via-webhook). Read this section first to decide *whether* and *when* to opt in; jump to the server README for the *how*.

### Phase B is opt-in. Doing nothing is a valid migration path.

Phase B is layered on top of Phase A, not a replacement. If you don't set `STAMP_PROMPTS_REPO_URL` on the stamp-server, you stay on the image-bundled `/etc/stamp/reviewers/*.md` path with zero behavior change:

- No prompt-cache populate runs at boot.
- No webhook listener accepts deliveries (the route returns `503 prompts_repo_url_unconfigured`).
- No periodic-poll worker arms.
- Boot logs look identical to a 2.0.x deployment — no new `prompts-cache:` or `prompts-poll:` lines.
- Per-review path resolution is exactly Phase A: `${STAMP_PROMPTS_DIR:-/etc/stamp/reviewers}/<reviewer>.md`.

If your team is happy with the redeploy-to-edit-a-prompt cycle, ignore this section. The Phase B code paths are gated entirely on `STAMP_PROMPTS_REPO_URL`; they sit dark until you opt in.

### When to opt in

Opt into Phase B when **any** of the following starts hurting:

- **Prompt iteration cadence > image-rebuild cadence.** You're tweaking reviewer prompts every few days but the server rebuilds on a weekly or monthly schedule, so prompt changes pile up behind unrelated infra changes.
- **Prompts are owned by a different team than the server image.** Security wants to edit `security.md` without filing a server-deploy ticket.
- **You operate multiple stamp-server deployments** (staging + prod, multiple regions, per-tenant) that should share a single source of truth for reviewer prompts.
- **You want per-repo overrides.** Phase B's optional `<org>/<repo>/<reviewer>.md` layer lets a specific repo opt out of a fleet-wide default without touching the server image.

If none of these bite, stay on Phase A. The bundled-prompts path is simpler, has fewer moving parts (no webhook, no deploy key, no cache directory), and is the design's "secure by default" stance.

### Step-by-step opt-in

Each step links into [`server/README.md`'s Phase B section](../server/README.md#phase-b--external-prompts-via-webhook) for the configuration detail; the narrative below sequences them.

#### Step 1 — Create the prompts repo

A new github repo (e.g. `your-org/stamp-reviewers`). Public or private; both work. The server fetches read-only — it never pushes — so the access posture is "anything that lets the server clone."

Seed the repo with copies of the prompts you currently maintain at `server/reviewers/*.md` in your stamp-cli fork. **Lay them out flat at the repo root** — `security.md`, `standards.md`, `product.md` at the top level — NOT under a `default/` directory. This is the single most common first-boot gotcha (see "The `default/` layout gotcha" below).

#### Step 2 — (Private repos only) Register a deploy key

Generate an ed25519 keypair locally. Register the **public** half as a read-only deploy key on the prompts repo. Drop the **private** half onto the stamp-server's persistent volume at `/srv/git/.ssh-client-keys/prompts_repo_key` (mode `0600`, git-owned). Full flow in [`server/README.md`'s "Private-repo deploy-key flow"](../server/README.md#private-repo-deploy-key-flow).

For HTTPS URLs to public repos, skip this step — `STAMP_PROMPTS_DEPLOY_KEY_PATH` can stay unset and github's TLS handles host verification.

#### Step 3 — Configure the github webhook

On the prompts repo: Settings → Webhooks → Add webhook. Payload URL `https://<your-stamp-server-host>/webhook/prompts`, content type `application/json`, generate a shared secret with `openssl rand -hex 32` (you'll need this string in step 4), events "Just the `push` event." Full webhook field-by-field in [`server/README.md`'s "Webhook configuration"](../server/README.md#webhook-configuration-on-the-prompts-repo).

#### Step 4 — Set env vars on the stamp-server deployment

In Railway (Settings → Variables) or your platform's equivalent:

| Var | Value |
|---|---|
| `STAMP_PROMPTS_REPO_URL` | `git@github.com:your-org/stamp-reviewers.git` (SSH for private repos) or `https://github.com/your-org/stamp-reviewers.git` (HTTPS for public) |
| `STAMP_PROMPTS_REPO_REF` | Defaults to `main`; override only if you track a different branch/tag |
| `STAMP_PROMPTS_WEBHOOK_SECRET` | Paste the same string you typed into the github webhook config in step 3 |
| `STAMP_PROMPTS_DEPLOY_KEY_PATH` | Defaults to `/srv/git/.ssh-client-keys/prompts_repo_key`; override only if you stored the key elsewhere |

Optional tuning:

| Var | When to set |
|---|---|
| `STAMP_PROMPTS_POLL_INTERVAL_SEC` | Defaults to `3600` (one hour). Lower it during a webhook-secret rotation window (see "Webhook secret rotation" below); set the literal string `"0"` (and only `"0"`) to disable polling entirely for webhook-only mode. |
| `STAMP_PROMPTS_CACHE_ROOT` | Defaults to `/srv/git/.prompts-cache`. Only override if your volume layout differs. |
| `STAMP_PROMPTS_KNOWN_HOSTS_PATH` | Only for self-hosted github enterprise. |

The full env-var reference table is in [`server/README.md`'s "Env-var reference"](../server/README.md#env-var-reference).

#### Step 5 — Redeploy

Trigger a redeploy on Railway (or `docker restart` / equivalent). Confirm the first boot via container logs — you should see:

```
prompts-cache: populating cache at /srv/git/.prompts-cache from git@github.com:your-org/stamp-reviewers.git@main (deploy key: /srv/git/.ssh-client-keys/prompts_repo_key)
prompts-cache: ready (cacheRoot=/srv/git/.prompts-cache sha=<40-hex> files=product.md,security.md,standards.md)
prompts-poll: started (interval=3600s, url=..., ref=main, cacheRoot=/srv/git/.prompts-cache)
```

The `files=<comma-list>.md` is the verification step: it enumerates the `*.md` files the cache module sees at the cache root. If it shows `files=<none>`, your prompts repo's layout doesn't match what `getPromptPath` expects — see the next subsection.

From here on, edits to the prompts repo trigger webhook deliveries that refresh the local cache within seconds. `stamp review` against any reviewed repo reads from the cache; behavior at review time is identical to Phase A — the difference is only in how the prompt bytes got there.

### The `default/` layout gotcha

The project README and `server/README.md` both document an *example* prompts-repo layout that uses a `default/` directory:

```
default/security.md
default/standards.md
default/product.md
your-org/your-repo/security.md       # optional per-repo override
```

`getPromptPath` in [`src/server/prompts-cache.ts`](../src/server/prompts-cache.ts) does NOT honor the `default/` prefix. It resolves prompts in this order:

1. `<cacheRoot>/<org>/<repo>/<reviewer>.md` (per-repo override, when the SSH verb supplies org + repo context)
2. `<cacheRoot>/<reviewer>.md` (flat default — what gets used for everyone else)

If you literally copy the project README's example and end up with `default/security.md` etc. at the cache root, the lookup will return `<none>` files because `<cacheRoot>/security.md` does not exist — only `<cacheRoot>/default/security.md` does. The boot log shows this as `files=<none>` despite a populated prompts repo.

The fix is to **lay your prompts repo out flat at the root** — `security.md`, `standards.md`, `product.md` directly at the top level of the prompts repo, with per-repo overrides under `<org>/<repo>/` siblings. The cache module clones the prompts repo verbatim into the cache root, so flat-at-repo-root = flat-at-cache-root = lookup hit.

If you've already populated a prompts repo with the `default/` convention and don't want to restructure it, the workaround is a one-line `mv default/* . && rmdir default` rewrite in the prompts repo. The webhook fires on push as usual; the next boot's `files=` line should enumerate the reviewer files at the cache root.

### Rollback to Phase A

If Phase B doesn't work out — flaky webhook deliveries, the prompts repo's branch protection is blocking the team, you want to roll back during an incident — the rollback is a single env-var unset:

1. **Unset `STAMP_PROMPTS_REPO_URL`** in your platform's env-var config (delete the var; do not set it to empty string — the gate checks for the var being defined). Optionally leave the other Phase B vars (`_WEBHOOK_SECRET`, `_DEPLOY_KEY_PATH`, `_REPO_REF`) set; they're inert when `_REPO_URL` is unset.
2. **Redeploy.** Boot will skip the cache populate, skip arming the poll worker, and the webhook route will 503 any incoming deliveries.
3. **Per-review path resolution reverts to `${STAMP_PROMPTS_DIR:-/etc/stamp/reviewers}/<reviewer>.md`** — the bundled image path, exactly as before opting in.

No data migration is needed. The `/srv/git/.prompts-cache/` directory remains on the volume but is no longer consulted (the env-var gate in `resolvePromptCacheRoot` short-circuits to the Phase A path). You can leave it in place against a future re-enable, or `rm -rf` it from a container shell to reclaim disk — neither affects correctness.

The Phase A bundled prompts at `/etc/stamp/reviewers/*.md` remain in the image regardless of which mode you're in — Phase B never modifies them, never overwrites them, and never deletes them. They're inert during a Phase B opt-in (the resolver shifts to the cache root) and load-bearing the moment you opt back out. You do not need to "restore" anything on rollback; they were always there.

### Webhook secret rotation

There's no special tooling for rotating the webhook secret — operators rotate by editing the github webhook config + the `STAMP_PROMPTS_WEBHOOK_SECRET` env var on the server. The order matters but the consequence of getting it wrong is bounded.

**Recommended order:**

1. Generate a fresh secret (`openssl rand -hex 32`).
2. **Update the github webhook config first.** Settings → Webhooks → click the prompts webhook → paste the new secret → Save. Github does NOT accept two secrets simultaneously, so from this moment until step 3 lands, any inbound delivery to the server will fail HMAC validation against the *old* secret the server still holds.
3. **Update `STAMP_PROMPTS_WEBHOOK_SECRET` on the server, redeploy.** On the first boot after the redeploy, the server starts validating against the new secret. Deliveries that arrived during the rotation window are visible as `401 invalid_signature` in the container logs — they're lost from the webhook channel but recoverable on the next periodic-poll tick (default 3600s).

**For high-throughput repos**, lower `STAMP_PROMPTS_POLL_INTERVAL_SEC` temporarily during the rotation (e.g. `60` or `30`) so the backstop catches up faster after the secret swap. Revert to the default after the rotation completes.

**The periodic-poll backstop is the safety net.** Even if every webhook delivery in the rotation window 401s, the next poll-tick refreshes the cache from origin. The webhook is an optimization for "prompt edit → review uses the new prompt" latency; the poll is the correctness guarantee.

### Threat-model footnote (signed commits on the prompts repo)

The stamp-server does NOT verify commit signatures on the prompts repo at refresh time. This is an explicit deferred item in the Phase B scope — `cloneOrFetchPromptsCache` performs a `git fetch + checkout` against the configured ref and trusts whatever's at HEAD. There's no equivalent of pre-receive verification on the prompts-repo side.

If your threat model depends on tamper-evident prompt history, **enforce signed commits via the prompts repo's branch protection** (github → Settings → Rules → Rulesets → require signed commits on the tracked branch). The same rule pattern documented in [`docs/github-ruleset-setup.md`](./github-ruleset-setup.md) for the code-mirror case applies here.

This is a deliberate layer-shift relative to Phase A. In Phase A, the trust chain for prompt bytes is "operator controls the image build → image controls the prompts → server reads from `/etc/stamp/reviewers/` → server signs verdict against `prompt_sha256`." Every link in that chain is enforced inside stamp-server (or its image-build pipeline) and verifiable post-hoc by the verifier. In Phase B, the chain extends one link outward: "operator controls the prompts repo → server clones from prompts repo → server reads from cache → server signs verdict against `prompt_sha256`." That new first link — *operator controls the prompts repo* — is not enforced by stamp-server code. It's enforced by github (branch protection, signed commits, audit log) at the operator's discretion.

This is the explicit operator-responsibility line. The trust property is "operator controls prompt bytes" in both phases; the *mechanism* by which the operator exercises that control shifts from "image build pipeline" to "github branch-protected repo." Pick a Phase B posture deliberately, not by accident.

### What signing & topology don't change

Phase B does NOT touch the v4 attestation envelope, the signing-key trust anchors, the `path_rules` gate, the SSH verb wire protocol, the mirror workflow, or the pre-receive hook's verification logic. From the verifier's perspective the only thing that changes is *where the bytes the server signed against came from* — and even that's invisible, because `prompt_sha256` in the signed envelope is computed from the in-memory bytes the LLM received, not from the upstream source.

Concretely:
- **Operator signing key, admin key, server-attestation key:** unchanged.
- **`.stamp/trusted-keys/manifest.yml`** on each reviewed repo: unchanged. The server's review-signing key entry has the same `[server]` capability + `role_source: server`; it does NOT need a new capability for Phase B.
- **`path_rules` for `.stamp/**`:** unchanged. Trust-anchor changes still require admin counter-sigs; Phase B does not introduce a new gated path.
- **`stamp/verify-attestation@v1` Action:** unchanged. The verifier resolves `prompt_sha256` against the server-signed approval body; the storage layer behind the server is opaque to it.
- **Shape selection (1/4):** unchanged. Phase B sits orthogonally to topology — you can run Phase B on Shape 1 or Shape 4. Shape 4 is the most common pairing (since both reach for "the prompts are server-owned, not repo-owned"), but nothing about the trust model requires it.

If you had a working v4 setup before opting into Phase B, you have a working v4 setup after. The migration is purely on the server's prompt-storage layer.

### Per-repo opt-in is unchanged

A reviewed repo's `.stamp/config.yml` does NOT change between Phase A and Phase B. The Shape 4 convention — empty-object reviewer entries that defer prompt bytes to the server — applies identically:

```yaml
reviewers:
  security: {}
  standards: {}
  product: {}
required_reviewers:
  - security
  - standards
```

The repo doesn't know or care which prompt-storage backend the server is using. Mix-and-match across an org is supported: server X can be Phase A while server Y is Phase B, and a reviewed repo that pushes to either gets the appropriate prompt bytes for that server's mode.

### Dead-weight in the image after opt-in

The bundled `server/reviewers/*.md` files in your stamp-cli fork remain in the image after a Phase B opt-in, but become inert. The `resolvePromptCacheRoot()` dispatch in [`src/server/reviewPipeline.ts`](../src/server/reviewPipeline.ts) shifts the cache root to `/srv/git/.prompts-cache/` the moment `STAMP_PROMPTS_REPO_URL` is set — the bundled files at `/etc/stamp/reviewers/` exist but are never consulted by the review path.

**No rush to remove them.** They're harmless dead-weight, and they're load-bearing again the moment you roll back to Phase A. A future major release of your fork can clean them up if you're certain you're never rolling back; for the migration commit itself, leave them alone — the cleanup adds risk of merge conflicts during the rollout for no operational benefit.

### See also (Phase B specifics)

- [`server/README.md`'s "Phase B — external prompts via webhook"](../server/README.md#phase-b--external-prompts-via-webhook) — the configuration reference: env vars, deploy-key flow, webhook setup, first-boot expectations, periodic-poll log lines, troubleshooting matrix, threat-model table.
- [`server/README.md`'s "Migrating bundled prompts (Phase A → Phase B)"](../server/README.md#migrating-bundled-prompts-phase-a--phase-b) — the seed-the-prompts-repo-from-`server/reviewers/` recipe.
- [`src/server/prompts-cache.ts`](../src/server/prompts-cache.ts) — `cloneOrFetchPromptsCache` (atomic refresh) and `getPromptPath` (lookup order including the `default/` gotcha).
- [`src/server/reviewPipeline.ts`](../src/server/reviewPipeline.ts) — `resolvePromptCacheRoot()` env-var dispatch and the `PHASE_B_CACHE_ROOT` export shared by the webhook + poll workers.

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
- [`../server/README.md`](../server/README.md) — stamp-server deployment guide; the [Phase B — external prompts via webhook](../server/README.md#phase-b--external-prompts-via-webhook) section is the configuration reference paired with the [Phase A → Phase B](#phase-a--phase-b-external-reviewer-prompts) migration narrative above
