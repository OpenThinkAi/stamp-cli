# stamp-cli roadmap

Status, upcoming priorities, deferred items. Paired with [`DESIGN.md`](../DESIGN.md) (technical spec) and [`README.md`](../README.md) (user-facing docs).

## Two release lines

stamp-cli is on two tracks:

- **1.x — operator-trust line.** The shipped product through `stamp-cli@0.2.x`. The merge attestation is signed by the operator's local key. This is honest about what it proves — "a keyholder claims reviewer X returned verdict V" — but the operator constructs both sides of the LLM call, so the verdict cannot be cryptographically tied to a real model invocation. 1.x is now in **maintenance + deprecation**. See [1.x maintenance](#1x-line--operator-trust-maintenance-only) below.
- **2.x — server-attested line.** Active development. The LLM call moves into stamp-server with its own signing key; verdicts are signed by the server, the prompt is fetched by the server from its own bare repo, and the operator can no longer forge approvals without compromising the server. The v4 attestation envelope binds the diff hash, prompt hash, and a snapshot of the trusted-keys manifest. See [2.x line](#2x-line--server-attested-active-development) below.

The 1.x → 2.x upgrade is per-repo and incremental. The bridge release (final 1.x) accepts both models side by side so teams can migrate one repo at a time. See [`migration-1.x-to-2.x.md`](./migration-1.x-to-2.x.md) for the operational walkthrough, or [`plans/server-attested-reviews.md`](./plans/server-attested-reviews.md) for the full design rationale.

---

## 2.x line — server-attested (active development)

The centerpiece of 2.x is **server-attested reviews**. Stamp-server gains a `stamp-review` SSH verb that fetches the canonical reviewer prompt from its own bare repo, calls Anthropic with prompt + diff, and returns a verdict signed by the server's review-signing key. The operator's machine never sees the prompt the server used and cannot forge the server's signature. The trust property that 1.x could only assert by convention is now structural.

The full design — threat model, attestation v4 schema, trust model with `admin` / `server` / `operator` capabilities, role-gated `path_rules` for `.stamp/**` changes, lenient revocation semantics, and the two supported deployment shapes (stamp-server primary; GitHub primary with mirror Action) — lives in [`plans/server-attested-reviews.md`](./plans/server-attested-reviews.md).

### What's shipped on `main`

Foundational work has landed but is not yet user-visible without `review_server` configured:

- **v4 attestation envelope** — schema types, canonical serializer, tests (`src/lib/attestationV4.ts`).
- **Trusted-keys manifest** — parser, canonical serializer, snapshot hashing, capability resolution (`src/lib/trustedKeysManifest.ts`).
- **Server review-signing key bootstrap** — generated on first boot at `$STATE_DIR/review-signing-key.pem`; pubkey printable via `stamp-server-pubkey --review-signing`.
- **`stamp review --plan`** — emits a structured plan for a parent Claude Code session to dispatch to subagents; the local-only iteration path with no attestation claim.
- **DB schema for server signatures** — `reviews` table carries `server_approval_json`, `server_signature_b64`, `server_key_id`, `schema_version`; `stamp log` shows a SIGNED-BY marker.
- **Pre-receive hook refactor** — `src/hooks/pre-receive.ts` split into named phase functions so the new v4 verification phases land cleanly.
- **DESIGN.md security model** — operator-trust caveat promoted to the headline with a forward-pointer to the v4 resolution.
- **Migration guide** — [`migration-1.x-to-2.x.md`](./migration-1.x-to-2.x.md).

### Remaining work

Tracked in the `stamp-server-attested-reviews` vault project. Roughly:

- **`stamp-review` SSH verb on stamp-server** — the actual server-side endpoint that fetches the prompt, invokes Anthropic, and returns a signed verdict.
- **`stamp review` (trusted-mode client)** — calls the SSH verb instead of the local SDK, persists the signed approval, requires `review_server` in `.stamp/config.yml`.
- **`stamp init --migrate-to-server-attested`** — scaffolds `.stamp/trusted-keys/manifest.yml`, `path_rules`, and `review_server` config in an existing 1.x repo.
- **`path_rules` enforcement in pre-receive + `stamp/verify-attestation@v1`** — admin-capability signatures gate `.stamp/**` changes; reviewer cycle bypassed for those paths.
- **`stamp review --headless`** — direct Anthropic call from the operator's workstation for cron / git-hook contexts that have no parent agent. Local-only, no attestation.
- **Bridge release + 2.0 GA cutover** — 1.x final ships with deprecation notices; 2.0 GA requires `review_server` (or explicit `--plan` / `--headless` opt-in for local-only).

### Migration story

The migration is per-repo and additive. An operator on a 1.x stamp-server upgrades the server to a 2.x-capable build (adds `ANTHROPIC_API_KEY` and a few review-capability env vars), captures the server's review-signing pubkey, then for each repo: commits the pubkey to `.stamp/trusted-keys/`, runs `stamp init --migrate-to-server-attested` to scaffold the manifest + `path_rules` + `review_server` config, and lands that commit through the existing 1.x reviewer flow. From the next commit forward, v4 enforcement is live for that repo. Past v2/v3 attestations on already-merged commits remain verifiable indefinitely.

Three deployment shapes are supported: stamp-server as the primary git remote; GitHub primary with a mirror Action pushing to stamp-server for review (PR mode); and local-only iteration (`--plan` / `--headless`) which produces no attestation and makes no trust claim. The migration guide walks through all three:

- [`migration-1.x-to-2.x.md`](./migration-1.x-to-2.x.md) — operator-facing walkthrough, FAQ, common gotchas.
- [`plans/server-attested-reviews.md`](./plans/server-attested-reviews.md) — full design, threat model, deferred-to-Phase-2 list.

---

## 1.x line — operator-trust (maintenance only)

The 1.x line is **feature-frozen as of `stamp-cli@0.2.x`**. The final 1.x release will ship as the bridge release with prominent deprecation notices pointing at the 2.x migration guide; both 1.x operator-trust and 2.x server-attested verification work side by side per-repo via `review_server` config. After 2.0 GA, 1.x receives security patches only.

The deprecation messaging and exact 1.x EOL window are finalized by the bridge-release ticket in the `stamp-server-attested-reviews` vault project.

### Shipped in 1.x

**Phase 1 MVP.** Full agent-driven cycle on a Railway-hosted bare-git remote:

- `stamp init` scaffolds `.stamp/` + generates Ed25519 keypair
- `stamp review --diff <revspec>` fans out to all configured reviewers in parallel via Claude Agent SDK, records verdicts
- `stamp status` evaluates gate against `.stamp/config.yml` required reviewers
- `stamp merge` does `git merge --no-ff`, signs payload with Ed25519, attaches as commit trailers
- `stamp verify` + server-side pre-receive hook re-run all checks (signature, SHA binding, approvals)
- `stamp push` is a thin wrapper over `git push`; hook stderr surfaces cleanly on rejection
- `stamp log`, `stamp keys`, `stamp reviewers` (list/edit) — operator surface
- `server/Dockerfile` + `setup-repo.sh` + `new-stamp-repo` wrapper for Railway/VPS deploys

**Phase 2.A — pre-merge test gate.** `.stamp/config.yml` supports `required_checks` per branch; `stamp merge` runs each check on the post-merge tree before signing; attestation payload records `{name, command, exit_code, output_sha}`; server hook verifies attestation lists every required check with exit 0. This exists because LLM reviewers miss compile/syntax errors a build step catches trivially.

**Phase 2.B — enhanced `stamp log`.** Default view shows first-parent merge history with one-line attestation summaries (signer, reviewers ✓/✗, checks ✓/✗); `stamp log <sha>` drills into one commit with decoded attestation, signature status, review prose from DB, and check details; `--reviews` keeps the raw DB-rows view accessible. **Breaking changes:**

- Old `stamp log --diff <revspec>` (DB-row filter) is now `stamp log --reviews --diff <revspec>`. Any agent loop that parsed the old default output needs updating.
- `stamp keys export --pub` is now just `stamp keys export` (the flag is accepted as a no-op for backward compat).

**Phase 2.C — reviewer management.** `stamp reviewers add/remove/edit/test/show`. The `test` subcommand is the key iteration tool — invokes a reviewer against a diff without recording to DB. `show` surfaces aggregate verdict stats for calibration.

**Phase 2.D — gated mirror to github.com.** Post-receive hook mirrors verified commits to a configured GitHub repo using a bot PAT. `.stamp/mirror.yml` committed per-repo declares destination; `GITHUB_BOT_TOKEN` env var on the server holds the PAT; hook reads it from `/etc/stamp/env`. Mirror failures log to stderr but don't block the stamped push.

**Phase 2.E — pre-public release hardening.** The repo is public and `stamp-cli@0.2.0` is on npm. Personal references scrubbed; proprietary `@anthropic-ai/claude-agent-sdk` dependency disclosed; `required_checks` shell-execution tradeoff documented; `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `.github/workflows/ci.yml` landed; `AGENTS.md` + `CLAUDE.md` added.

**Breaking change in 2.E:** `stamp init` now scaffolds three starter reviewers by default (`security`, `standards`, `product`) with `required: [security, standards, product]`. `stamp init --minimal` preserves the prior single-`example` behavior. This motivated the `0.1.x → 0.2.0` bump under pre-1.0 semver.

**Phase 3 — verified reviewer configs.** All four steps shipped: per-reviewer `tools:` and `mcp_servers:` in `.stamp/config.yml`; prompt/tools/mcp hashes in the attestation payload (v2), verified against the merge commit's committed tree; `stamp reviewers fetch <name> --from <source>@<ref>` + `stamp reviewers verify` + lock files + exit code 3 for drift; audit-only tool-invocation trace `{ tool, input_sha256 }[]` embedded per approval. Full design in [`plans/verified-reviewer-configs.md`](./plans/verified-reviewer-configs.md). **Superseded in 2.x:** hashing the committed config does not constrain what the local LLM actually received; server-attested verdicts do.

### Deferred and not picked up

These were in the 1.x plan but are lower priority and unlikely to ship before 1.x EOL. Re-evaluated for 2.x where they still apply.

- **`stamp serve` HTTP API** — read-only endpoints (commits, verification, diffs) for custom frontends. Deferred until a real consumer materializes; `stamp log` covers the immediate visibility need. In 2.x this is folded into the stamp-server HTTP surface (Phase 2 of the server-attested plan).
- **Reviewer output caching** — skip reviewer re-invocation when files under that reviewer's scope haven't changed. Cost savings, not a product gap. Re-evaluate against 2.x token spend on the server side.
- **Large-diff chunking** — split oversize diffs into logical units for parallel review. Not yet painful. 2.x server enforces `MAX_DIFF_BYTES` (default 5 MB) which surfaces this when it does.
- **Keychain integration (macOS)** — move signing keys from `~/.stamp/keys/` to Keychain. Security hygiene. Re-scoped to 2.x trusted-keys handling.
- **Full TUI (`stamp ui`)** — interactive terminal app for browsing. Not pursued; the prose `stamp log` covers the need.
- **`THIRD-PARTY-NOTICES.md`** for Apache-2.0 transitive deps. Nice-to-have, not done.
- **Genericize `docs/personas.md`'s** concrete example project reference. Nice-to-have, not done.

## Non-goals (both lines)

- Not a GitHub replacement
- No web UI in the core product (the HTTP API lets operators build their own)
- No human-facing review comment threads
- No multi-user PR collaboration UX
- No CI/CD system (pre-merge checks run locally, attested, verified — not a build farm)
- Not a git server (relies on stock `git` + `sshd`)

## Open questions (live)

Items where the right answer is still being shaped by ongoing dogfooding. Most are 2.x-specific; the residual 1.x questions are listed for completeness even though the line is in maintenance.

**2.x:**

1. **Trust-anchor multi-sig collection UX.** With `minimum_signatures: 2`, how does admin A's signature reach admin B for counter-signing? An inbox-style `stamp admin sign --pending <sha>` flow is friendlier than out-of-band coordination — settled during implementation of the path-rules verifier.
2. **Per-commit revocation tooling.** Lenient revocation works mechanically; admins need a clear `stamp admin revoke-key <fingerprint>` flow that updates the manifest and produces an admin-signed commit.
3. **`stamp init --migrate-to-server-attested` defaults.** Existing trusted-keys default to `[operator]`; the interactive promotion-to-`admin` UX is still being designed.
4. **Diff-context sufficiency for reviewers without file access.** Phase 1 server reviewers see only the diff. Reviewer authors may need to update prompts that assumed `Read` / `Grep` / `WebFetch` access. The migration guide includes adaptation guidance.

**1.x residual:**

1. **`changes_requested` vs `denied` in reviewer contracts** — the distinction earns less than its complexity, but rewriting the contract on a maintenance line isn't worth it. Carried forward into 2.x reviewer prompts.
2. **Multi-remote pushes** — gated mirror (2.D) adds a second remote; 2.x PR-mode adds a third pattern. Currently expressed per-shape; a unified config story may emerge in 2.x.

## Referenced docs

- [`DESIGN.md`](../DESIGN.md) — technical spec (data model, signing, attestation schema, CLI surface)
- [`README.md`](../README.md) — user-facing installation + quick-start
- [`migration-1.x-to-2.x.md`](./migration-1.x-to-2.x.md) — 1.x → 2.x operational walkthrough
- [`plans/server-attested-reviews.md`](./plans/server-attested-reviews.md) — 2.x design + threat model
- [`plans/verified-reviewer-configs.md`](./plans/verified-reviewer-configs.md) — 1.x Phase 3 plan (superseded by 2.x)
- [`server/README.md`](../server/README.md) — server deployment (Railway walkthrough, Dockerfile explanation)

Deployment-specific plans (a particular operator's Railway setup, reviewer persona development for a specific project) live outside this repo — specifics of any given install aren't part of the OSS product.
