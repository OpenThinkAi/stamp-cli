# Changelog

All notable changes to `@openthink/stamp` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow [SemVer](https://semver.org/).

---

## 2.1.1 — 2026-05-21

Adds `stamp attest --migrate-existing` for the **Shape 4 migration bootstrap PR**: the one-time PR that activates Shape 4 (server-attested without code transfer) on an existing repo. AGT-398.

### Background — why this exists

2.1.0 introduced Shape 4 but assumed the migration commit would land "via stamp flow." First operator to actually try it (hivedb, Anglepoint-Inc) hit a deadlock:

- `stamp review` reads `.stamp/config.yml` from `base_sha` (security boundary — feature branch can't unilaterally point at attacker-controlled server). Base lacks `review_server` → review runs locally → no server signatures captured.
- `stamp attest` reads `.stamp/config.yml` from the working tree, sees the newly-added `review_server`, takes the v3 server-attested branch, demands server signatures that don't exist.
- v2 fallback rejected by the verifier (`MIN_ACCEPTED_PR_ATTESTATION_VERSION = 3`).
- `path_rules` `.stamp/**` `bypass_review_cycle: true` doesn't help — it bypasses the reviewer gate, but the schema-floor check is downstream.

Shape 2 dodges the same deadlock via the 1.x bridge ("Step 4 — Land the migration commit through 1.x"). Shape 4 didn't exist in 1.x, so no equivalent fallback. Every Shape 4 migration of an existing repo would hit this — 2.1.1 fixes it permanently.

### Added

- **`stamp attest --migrate-existing` flag.** Produces a v3 envelope with an empty `server_signatures` block plus a `migration_bootstrap: { activated_paths: [...] }` marker inside the operator-signed payload. Accepted by the verifier only when all of these hold: (a) the marker is present, (b) the operator signature over the payload verifies, (c) an admin-capability signature in `trust_anchor_signatures` covers the diff, (d) `path_rules` at `base_sha` covers all touched paths with `bypass_review_cycle: true`, (e) the diff matches the narrow Shape-4-activation whitelist (re-validated at verify time, not just attest time).
- **Shape-4-activation whitelist** (`src/lib/migrationBootstrap.ts`). The bootstrap path accepts ONLY: adding `review_server:` to a branch rule in `.stamp/config.yml`, optionally cleaning the `reviewers:` block from prompt-paths form to `{}` form, adding new `[server]+role_source: server` entries to `.stamp/trusted-keys/manifest.yml`, and adding new matching `*.pub` files. Touching anything else fails with a named-offender error. Operators who need broader changes land them via the normal flow after the bootstrap commit.
- **Migration doc walkthrough step.** `docs/migration-1.x-to-2.x.md` Shape 4 walkthrough explains the bootstrap PR: run `stamp attest --migrate-existing` for the FIRST PR that activates Shape 4; subsequent PRs use the normal `stamp attest --into main --push origin`.

### Constraints (deliberate)

- `MIN_ACCEPTED_PR_ATTESTATION_VERSION` stays at 3. The bootstrap envelope IS a v3 envelope; it just has an empty `server_signatures` block + a marker. No schema-floor relaxation.
- `minimum_signatures > 1` on the matched `path_rule` is refused at attest time (the bootstrap flag does a single operator-self admin sig; multi-admin envelope collection isn't supported by current tooling). Operators with `minimum_signatures: 2+` see an actionable error; workaround is to temporarily lower the rule in a prior PR.
- The bootstrap marker is part of the operator-signed bytes — not a trailer addendum. Spoofing requires forging the operator's signature.

### Provenance

- AGT-398: commits `cd0c001`, `c20c94b`, `d830c24`, `f660d0e`.

---

## 2.1.0 — 2026-05-21

Adds **Shape 4** as a documented and supported deployment topology: GitHub primary + server-attested reviews + no code transfer to stamp-server. Driven by the [shape-2-topology-correction](https://github.com/OpenThinkAi/stamp-cli/blob/main/docs/migration-1.x-to-2.x.md#shape-4--github-primary-server-attested-without-code-transfer-private-repos) project — the topology lets private/internal repos keep code on its git host while still getting server-attested verdicts. Includes a v4→v5 envelope schema bump (breaking; v4 envelopes are rejected with a clear "schema too old" error) and a config validator change that's backward-compatible for Shape 1/2 deployments but unlocks the cleaner Shape 4 config shape.

### Added

- **Shape 4 deployment shape.** New section in [`docs/migration-1.x-to-2.x.md`](docs/migration-1.x-to-2.x.md) describing GitHub primary + server-attested + no code mirror. The stamp-server reads canonical reviewer prompts from `/etc/stamp/reviewers/<name>.md` bundled into its Docker image at build time; the operator's repo never carries `.stamp/reviewers/*.md`. Trust property is identical to Shape 2 (server controls prompt bytes), but without the bare-repo dependency that forced operators to mirror their full source.
- **Server-side prompt cache.** `src/server/promptFetch.ts` replaces the bare-repo `git show base_sha:.stamp/reviewers/<name>.md` fetch with `readFileSync(${STAMP_PROMPTS_DIR:-/etc/stamp/reviewers}/<name>.md)`. The server no longer maintains a bare clone of every reviewed repo for prompt resolution.
- **Image-bundled reviewer prompts.** `server/reviewers/{security,standards,product}.md` are now part of the repo and the `server/Dockerfile` copies them into `/etc/stamp/reviewers/` at build time (mode `0644` root:root). `server/entrypoint.sh` emits a one-line stderr boot inventory of the prompt files for ops visibility. New [`server/README.md#reviewer-prompts`](server/README.md#reviewer-prompts) documents the editing/rebuild workflow.
- **Optional `reviewers.<name>.prompt`.** `src/lib/config.ts` accepts a `reviewers:` block where `prompt:` is omitted on a per-reviewer basis. In server-attested mode the omitted field is fine — the server is the canonical source. In local-only modes (`stamp review --plan`, `--headless`, or `stamp review` against a branch rule without `review_server:`), the command errors with a clear "no `prompt:` configured for reviewer X" message naming both resolution paths (add `prompt:` or add `review_server:`).

### Changed (breaking)

- **v4 envelope → v5 envelope.** `CURRENT_V4_SCHEMA_VERSION` and `MIN_ACCEPTED_V4_SCHEMA_VERSION` both bump from 4 to 5. The manifest-snapshot binding (`manifest_snapshot_sha256`) moves from per-approval (`ApprovalV4.trusted_keys_snapshot_sha256`, removed) to the outer envelope (`AttestationPayloadV4.manifest_snapshot_sha256`, signed by the operator). `verifyV4ManifestSnapshot` runs once per envelope; the per-approval check is gone. v4 envelopes are rejected by the v5 verifier with the actionable error `v4 attestation schema_version 4 is below minimum 5 — re-create the merge with a current stamp-cli build`. No live v4 envelopes exist in production (HiveDB had rolled back to operator-attested in May 2026), so the breaking bump is consequence-free for known deployments.
- **Verifier no longer recomputes `prompt_sha256` from the merge-base tree.** With Shape 4 in scope, the prompts aren't in the operator's repo — there's nothing to recompute against. The server-signed `prompt_sha256` inside each approval body is now trusted by transitivity: manifest (at `base_sha`) → server key with `server` capability → signed approval body → `prompt_sha256`. The tree-recompute was a belt-and-suspenders second-line defense, not the trust anchor; documented in `src/lib/v4Trust.ts`'s `verifyV4ApprovalSignatures` docstring with explicit "do not re-introduce without re-opening the topology decision" guidance.

### Removed

- `ApprovalV4.trusted_keys_snapshot_sha256` field (moved to outer envelope as `manifest_snapshot_sha256`).
- `defaultRepoResolver` and `fetchManifestAtBaseSha` from `src/server/promptFetch.ts` (replaced by `defaultPromptCacheResolver`).
- `STAMP_REPO_ROOT` env var on the server-attested path (replaced by `STAMP_PROMPTS_DIR`, default `/etc/stamp/reviewers`). `src/server/reviewPipeline.ts` emits a one-time stderr warning at boot if `STAMP_REPO_ROOT` is set, naming the rename and the new default.

### Migration notes for operators

- **Shape 2 (mirror) deployments**: no action required. Server-attested mode continues to work; the new validator accepts your existing `reviewers:` block with `prompt:` paths unchanged.
- **Shape 4 deployments** (GitHub primary + server-attested + no mirror): see the new `docs/migration-1.x-to-2.x.md` Shape 4 walkthrough. Re-key is NOT required — the server review-signing key persists across the upgrade.
- **Self-hosted forks of stamp-server**: rebuild the Docker image from the 2.1.0 source so `/etc/stamp/reviewers/` is populated. Without this, server-attested reviews return `no_such_file` errors on every request.

### Provenance

- AGT-370 (envelope reshape + prompt-cache resolver + verifier updates): commits `84bd1f7`, `1cb08d8`, `298c15c`, `7abd8cf`, `e3555d0`, `3e7bc69`.
- AGT-371 (Docker image prompt bundle): commits `a179c71`, `4a918bb`.
- AGT-372 (Shape 4 docs): commit `dc74d68`.
- AGT-397 (validator relax for optional `prompt:`): commits `815c9f8`, `09531b9`.

---

## 2.0.2 — 2026-05-19

Three setup-friction bug fixes surfaced from a real Anglepoint-Inc/hivedb
operator onboarding session. No protocol or trust changes.

### Fixed

- **`stamp init --dry-run` outside `--migrate-to-server-attested` now errors loudly** instead of silently no-op'ing. The flag previously only applied to the migration code path; pairing it with `--pr-mode` (or any other init shape) ignored the flag and executed the real scaffold, including remote GitHub Ruleset creation. The error message names two resolution paths: pair with the migration flag, or drop `--dry-run`.
- **1.x deprecation banner no longer fires on 2.x+ installs.** `maybePrintDeprecationNotice` now reads the installed `package.json` version and emits the bridge-release banner only when major < 2. Operators on 2.0+ stop seeing the misleading "stamp 1.x is in maintenance" line on every `stamp init` / `stamp merge`. Suppression via `STAMP_SUPPRESS_DEPRECATION=1` is unchanged.
- **`stamp init --action-source <org/repo>`** added so operators consuming a fork can scaffold `.github/workflows/stamp-verify.yml` against their fork instead of the default upstream. Default remains `OpenThinkAi/stamp-cli`; pass `--action-source Anglepoint-Inc/anglepoint-stamp-server` (or similar) to track a fork. The constant is exported as `DEFAULT_ACTION_SOURCE` from `src/commands/init.ts`.

### Known remaining setup-friction gaps (not fixed in this release)

Surfaced from the same smoke test, filed as follow-up issues:

- [#35](https://github.com/OpenThinkAi/stamp-cli/issues/35) — non-interactive `--migrate-to-server-attested` produces unusable repo (no admin keys promoted)
- [#36](https://github.com/OpenThinkAi/stamp-cli/issues/36) — `minimum_signatures: 2` default breaks single-trusted-key repos
- [#37](https://github.com/OpenThinkAi/stamp-cli/issues/37) — proposed `stamp migrate status` for batch-migration visibility

---

## 2.0.1 — 2026-05-19

Fast-follow for 2.0.0 GA: closes the Shape 2 (server-attested PR mode)
end-to-end loop by shipping the server-side production of v3
PR-attestation envelopes ([AGT-355](https://github.com/OpenThinkAi/stamp-cli/issues)).

### What changed

- **Server**: `stamp-review` SSH verb response now surfaces the
  canonical per-approval bytes + signature as
  `pr_attestation_v3_payload_b64` and `pr_attestation_v3_signature_b64`
  alongside the existing `approval` + `signature` fields. The
  `ReviewPipelineResult` docstring in
  [`src/server/reviewPipeline.ts`](./src/server/reviewPipeline.ts)
  documents the wire-format contract; the bytes are byte-identical to
  `canonicalSerializeApproval(approval)` so the client never has to
  re-canonicalize.
- **Client**: `stamp attest` now dispatches on the branch rule's
  `review_server` field — when set, folds the server-signed approval
  rows from the local DB into a v3 PR-attestation envelope and
  operator-signs the outer; when absent, continues to produce v2
  (the 1.6.0 PR-check path). The dispatch mirrors `stamp merge`'s
  v3/v4 dispatch verbatim.
- **GitHub Action**: no change. The `stamp/verify-attestation@v1`
  verifier shipped in 2.0 (AGT-338) accepts the production envelope
  directly. The 1.x-action-pin bridge-window workaround documented in
  the 2.0 migration guide is no longer needed.

### Migration

No action required for operators already on 2.0 Shape 2 (PR mode) —
upgrade `stamp-cli` on both server and dev machines to 2.0.1, drop the
`stamp-version: 1.x` pin from `.github/workflows/stamp-verify.yml` if
one was added during the bridge window, and the next `stamp review` +
`stamp attest` cycle produces a v3 envelope the Action accepts.
Forward-compatible: 2.0.1 clients work against 2.0.0 servers (the new
response fields are optional on parse); 2.0.1 servers work against
2.0.0 clients (the new fields are additive). See
[`docs/migration-1.x-to-2.x.md`](./docs/migration-1.x-to-2.x.md) for
the updated walkthrough.

---

## 2.0.0 — 2026-05-19

stamp 2.0 ships **server-attested reviews**: the LLM call moves into
stamp-server, which holds its own signing key and signs every verdict. The
operator no longer constructs both sides of "what the LLM saw" and "what
the LLM said" — a forged review now requires forging a server signature.

This is the first major version cut; it's a breaking release. Read
[`docs/migration-1.x-to-2.x.md`](./docs/migration-1.x-to-2.x.md) for the
operational walkthrough and [`docs/plans/server-attested-reviews.md`](./docs/plans/server-attested-reviews.md)
for the full design rationale.

### Why 2.0 is direct-GA

No alpha / beta / rc cuts. Milestones M3 (merge folds v4 envelope), M4
(pre-receive v4 verification + path_rules + multi-sig collection),
M5 (local-only `--plan` / `--headless`), and M6 (deprecation messaging +
release prep) all landed on `main` ahead of this cut, with the AGT-354
v4 round-trip E2E harness covering the verifier chain end-to-end (1086
tests passing at GA). The `next` dist-tag convention for future majors
is documented in [`CONTRIBUTING.md`](./CONTRIBUTING.md).

### Trust model

- **`schema_version: 4` attestation envelope** ([`src/lib/attestationV4.ts`](./src/lib/attestationV4.ts)).
  Each per-approval slot carries: server-signed verdict, prompt hash, diff
  hash, server key id, trusted-keys manifest snapshot hash, and the
  operator's outer signature. v3 envelopes remain readable for historical
  verification; v2 is rejected (the 2026-04-27 self-review-attack fix made
  v2 structurally unsafe).
- **Trust capabilities** (`admin`, `operator`, `server`) declared in
  `.stamp/trusted-keys/manifest.yml`. A single key may carry multiple
  capabilities. The manifest's canonical-JSON snapshot hash is bound into
  every attestation, enabling **lenient revocation**: revoking a key
  blocks future merges without invalidating past ones.
- **Server-signed verdicts.** Stamp-server's `stamp-review` SSH verb
  fetches the canonical reviewer prompt from its own bare repo, calls
  Anthropic, and returns a verdict signed by the server's review-signing
  key. The operator's machine never sees the prompt the server used.
- **Role-gated `.stamp/**` changes.** `path_rules` in
  `.stamp/config.yml` require `admin`-capability signatures for changes
  to trust-anchor paths. The reviewer cycle is bypassed for these paths
  (reviewers structurally can't approve their own prompt changes).
- **Trust-anchor multi-sig collection.** `stamp admin sign --pending`
  collects counter-signatures in a git notes-ref
  (`refs/notes/stamp-trust-anchor-sigs`), folded into the v4 envelope at
  merge time. Notes are mutable, keyed by commit SHA, so re-signing flows
  don't require everyone to re-sign each time a sig is added.

### New surface

- **`stamp review`** (trusted mode) calls stamp-server's SSH verb when
  `review_server` is configured; persists the signed approval.
- **`stamp review --plan`** emits a structured plan for a parent Claude
  Code session; the local-only iteration path, no attestation claim.
- **`stamp review --headless`** direct-Anthropic call from the operator's
  workstation for cron / git-hook contexts. Local-only, no attestation.
- **`stamp init --migrate-to-server-attested`** scaffolds
  `.stamp/trusted-keys/manifest.yml`, `path_rules`, and `review_server`
  config in an existing 1.x repo.
- **`stamp admin sign --pending [<sha>]`** collects admin counter-sigs
  for in-flight `.stamp/**` changes.
- **`stamp admin revoke <fingerprint>`** removes a key from the manifest.
- **`stamp admin add-key <pubkey> --capabilities <list> --name <name>`**
  adds a key. Refuses any PEM lacking `-----BEGIN PUBLIC KEY-----`
  (closes a foot-gun where a typo'd path to the private key would copy
  the private file into `.stamp/trusted-keys/`).
- **`stamp admin list-keys`** displays manifest entries.
- **PR-mode mirror workflow.** `stamp init --pr-mode` installs
  `.github/workflows/stamp-mirror.yml`; the GitHub-primary deployment
  shape (Shape 2). `stamp/verify-attestation@v1` validates v4
  attestations as a required PR check.

### Removed

- **Reviewer file-access tools.** `tools_sha256`, `mcp_sha256`, and
  `tool_calls` envelope fields are no longer produced; Phase 1 reviewers
  see only the diff. `tools` / `mcp_servers` in reviewer prompts are
  warned and ignored.
- **MCP integrations.** Linear / Notion / etc. MCP servers are not wired
  into Phase 1 reviewers. If you relied on a reviewer that reconciled
  against an external system, see the migration guide FAQ.
- **`stamp review` fall-through to local LLM.** In 1.x, missing
  `review_server` falls through to the local Claude Agent SDK; in 2.x
  it errors with a pointer to `--plan` or `--headless`.

### Migration

The 1.x → 2.x upgrade is **per-repo and additive**:

1. Upgrade stamp-server to the 2.x-capable build (`ANTHROPIC_API_KEY`
   plus the review-capability env vars).
2. Capture the server's review-signing pubkey via
   `stamp-server-pubkey --review-signing`.
3. For each repo: commit the pubkey to `.stamp/trusted-keys/`,
   `stamp init --migrate-to-server-attested`, land the migration commit
   through the existing 1.x reviewer flow. From the next commit, v4
   enforcement is live.

Past v2 / v3 attestations on already-merged commits remain verifiable
indefinitely. The bridge release (final 1.x) accepts both models
side-by-side per-repo so teams can migrate incrementally.

### Deployment shapes

Three shapes supported (pick deliberately — guarantees differ):

| Shape | Origin | Enforcement |
|---|---|---|
| **Server-gated** (Shape 1) | stamp-server you deployed | Pre-receive hook rejects unstamped pushes |
| **PR mode** (Shape 2) | GitHub | GitHub Action `stamp/verify-attestation@v1` as required check |
| **Local-only** (Shape 3) | Anywhere | None — `--plan`/`--headless` produce no attestation |

### npm dist-tags at GA

- `latest` → `2.0.0`
- `legacy-1` → `1.10.0` (final 1.x; security patches only going forward)
- `next` — unused for this cut; reserved for future major prereleases

### Carry-forwards (resolved in 2.0.1)

- **AGT-355** — server-side production of the extended PR-attestation v3+
  blob in Shape 2. Shipped in 2.0.1; see the [2.0.1 entry](#201--2026-05-19)
  above for the upgrade path.

---

## Pre-2.0 history

The 1.x line shipped via `@openthink/stamp@0.1.0` through `@openthink/stamp@1.10.0`.
Notable milestones:

- **1.6.0** — PR-check mode (third deployment shape via GitHub Actions);
  `stamp attest` keys on git patch-id; `stamp/verify-attestation@v1.6.0`
  Action.
- **1.2.0** — per-reviewer model selection via
  `~/.stamp/config.yml`.
- **1.1.0** — STAMP-RETRO stdout fences for iterative learning loops with
  `@openthink/team`.
- **0.7.2 → 1.0** — multi-user onboarding, invites, membership store,
  `stamp users` / `stamp trust` surface.

For per-release detail prior to 2.0, see `git log` and the
[`docs/ROADMAP.md`](./docs/ROADMAP.md) milestone history.
