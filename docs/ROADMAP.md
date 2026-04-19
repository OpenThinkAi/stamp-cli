# stamp-cli roadmap

Status, upcoming priorities, deferred items. Paired with [`DESIGN.md`](../DESIGN.md) (technical spec) and [`README.md`](../README.md) (user-facing docs).

## Current state (April 2026)

**Phase 1 MVP — shipped.** Full agent-driven cycle works end-to-end on a Railway-hosted bare-git remote:

- `stamp init` scaffolds `.stamp/` + generates Ed25519 keypair
- `stamp review --diff <revspec>` fans out to all configured reviewers in parallel via Claude Agent SDK, records verdicts
- `stamp status` evaluates gate against `.stamp/config.yml` required reviewers
- `stamp merge` does `git merge --no-ff`, signs payload with Ed25519, attaches as commit trailers
- `stamp verify` + server-side pre-receive hook re-run all checks (signature, SHA binding, approvals)
- `stamp push` is a thin wrapper over `git push`; hook stderr surfaces cleanly on rejection
- `stamp log`, `stamp keys`, `stamp reviewers` (list/edit) — operator surface
- `server/Dockerfile` + `setup-repo.sh` + `new-stamp-repo` wrapper for Railway/VPS deploys

**Phase 2.A pre-merge test gate — shipped.** `.stamp/config.yml` supports `required_checks` per branch; `stamp merge` runs each check on the post-merge tree before signing; attestation payload records `{name, command, exit_code, output_sha}`; server hook verifies attestation lists every required check with exit 0. This exists because LLM reviewers miss compile/syntax errors a build step catches trivially — dogfooding surfaced that gap on the first real project.

## Phase 2.B–D — shipped

All three near-term priorities Matt called out are now live and dogfooded on keeb-cooker.

**2.B — Enhanced `stamp log`.** Default view shows first-parent merge history with one-line attestation summaries (signer, reviewers ✓/✗, checks ✓/✗); `stamp log <sha>` drills into one commit with decoded attestation, signature status, review prose from DB, and check details; `--reviews` keeps the raw DB-rows view accessible. **Breaking changes:**
- Old `stamp log --diff <revspec>` (DB-row filter) is now `stamp log --reviews --diff <revspec>`. Any agent loop that parsed the old default output needs updating.
- `stamp keys export --pub` is now just `stamp keys export` (the flag is accepted as a no-op for backward compat). Old scripts still work.

**2.C — Reviewer management.** `stamp reviewers add/remove/edit/test/show`. The `test` subcommand is the key iteration tool — invokes a reviewer against a diff without recording to DB. `show` surfaces aggregate verdict stats for calibration.

**2.D — Gated mirror to github.com.** Post-receive hook mirrors verified commits to a configured GitHub repo using a bot PAT. `.stamp/mirror.yml` committed per-repo declares destination; `GITHUB_BOT_TOKEN` env var on the server holds the PAT; hook reads it from `/etc/stamp/env` (persisted by entrypoint because sshd strips env from sessions). Mirror failures log to stderr but don't block the stamped push. Server README walks through setup including GitHub branch protection.

## Remaining Phase 2 items (deferred)

These were in the original plan but are lower priority given current dogfood pain points.

- **`stamp serve` HTTP API** — read-only endpoints (commits, verification, diffs) for custom frontends. Deferred until we actually want a web view; `stamp log` covers the immediate visibility need.
- **Reviewer output caching** — skip reviewer re-invocation when the files under that reviewer's scope haven't changed. Real cost savings, not a product gap. Ship when tokens become painful.
- **Large-diff chunking** — split oversize diffs into logical units for parallel review. Not yet painful. Ship when we hit a real >3000-line diff.
- **Keychain integration (macOS)** — move signing keys from `~/.stamp/keys/` to Keychain. Security hygiene. Ship before multi-machine / team use.
- **Full TUI (`stamp ui`)** — interactive terminal app for browsing. Only builds if 2.B's prose log isn't sufficient.

## Phase 3

Further out; broader architectural changes.

- **GitHub adapter** — staging-branch + Action pattern for teams that only have github.com and can't run their own remote. Workaround path, not the canonical story.
- **Multi-key / team key rotation UX** — clean "add collaborator," "rotate compromised key" flows.
- **Sigstore / gitsign integration** — replace long-lived Ed25519 keys with short-lived OIDC-backed certs from a transparency log.

## Non-goals

- Not a GitHub replacement
- No web UI in the core product (the HTTP API lets operators build their own)
- No human-facing review comment threads
- No multi-user PR collaboration UX
- No CI/CD system (pre-merge checks run locally, attested, verified — not a build farm)
- Not a git server (relies on stock `git` + `sshd`)

## Open questions (live)

Items where the "right" answer should be informed by continued dogfooding before committing to an implementation.

1. **`changes_requested` vs `denied`** — current reviewer contract says `denied` = "rethink approach" vs `changes_requested` = "fix specifics." In practice, the generic example reviewer almost never emits `denied`. Does this distinction earn its complexity? Revisit after three real personas exist.
2. **Cache invalidation for reviewer outputs (2.B above deferred)** — caching on file patterns is brittle; caching on semantic change scope needs LLM-derived heuristics. What's the right granularity?
3. **Multi-remote pushes** — current `stamp push` assumes one origin. Gated mirror (2.D) adds a second. If a repo needs to mirror to multiple destinations, how is that expressed?

## Referenced docs

- [`DESIGN.md`](../DESIGN.md) — technical spec (data model, signing, attestation schema, CLI surface)
- [`README.md`](../README.md) — user-facing installation + quick-start
- [`server/README.md`](../server/README.md) — server deployment (Railway walkthrough, Dockerfile explanation)

Matt's personal deployment plan (commitsonmain specifics, reviewer persona Tracks A/B/C) lives at `~/Ideas/commitsonmain.md` outside the repo — deployment specifics aren't part of the OSS product.
