# Changelog

All notable changes to `@openthink/stamp` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow [SemVer](https://semver.org/).

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
