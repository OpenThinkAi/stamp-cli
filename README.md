# stamp-cli

> **stamp 2.0 — server-attested reviews.** The LLM call moves into stamp-server,
> which holds its own signing key and signs every verdict. A forged review now
> requires forging a server signature — the operator no longer constructs both
> sides of "what the LLM saw" and "what the LLM said." On the 1.x line and
> upgrading? See the [**1.x → 2.x migration guide**](./docs/migration-1.x-to-2.x.md).
> 1.x receives security patches only; pin to `@openthink/stamp@legacy-1` if you
> need to stay on it.

Local, headless pull-request system for agent-to-agent code review workflows.

An author-agent opens a diff, reviewer-agents consume it and return structured
feedback, the author iterates until merge rules are satisfied, and the merge
is pushed to a remote that cryptographically rejects any push that wasn't
properly reviewed and signed. In 2.x, the reviewer LLM lives on stamp-server,
the verdict carries a server signature, and trust-anchor changes (the
reviewer prompts themselves, the trusted-key manifest, `path_rules`) require
admin counter-signatures.

**Not a GitHub replacement.** GitHub is for humans collaborating. stamp-cli
is for agent fleets cycling fast while keeping `main` clean. No web UI, no
PR dashboard, no human comment threads in core. Just a CLI + a git hook.

Part of the [OpenThink](https://openthink.dev) suite.

**Docs:** [server quickstart](./docs/quickstart-server.md) (from-zero project on a stamp server) · [DESIGN](./DESIGN.md) (spec) · [server-attested reviews](./docs/plans/server-attested-reviews.md) (2.x design + threat model) · [threat model](./docs/threat-model.md) (who attacks, how, what defends) · [ROADMAP](./docs/ROADMAP.md) (what's shipped + what's next) · [personas](./docs/personas.md) (writing reviewer prompts) · [local-only mode](./docs/local-only-mode.md) (no-trust iteration via `stamp review --plan` + Claude Code skill) · [1.x → 2.x migration](./docs/migration-1.x-to-2.x.md) (upgrade guide) · [troubleshooting](./docs/troubleshooting.md) · [server](./server/README.md) (Railway deploy) · [CHANGELOG](./CHANGELOG.md)

## Install

```sh
npm install -g @openthink/stamp
```

Node 22.5+ required (we use `node:sqlite` and `node:crypto`'s Ed25519 APIs,
both of which are built-in but gated on 22.5+).

Published tarballs carry an SLSA build attestation via npm's Trusted
Publishing, so you can verify chain-of-custody against the GitHub Actions
run that produced the release:

```sh
npm audit signatures
```

## Quick start

**Pick your trust model first** — it determines which command you run and
what trust guarantees you actually get. In 2.x, the trust ladder is explicit:

| Mode | Origin is… | Trust source | Enforcement |
|---|---|---|---|
| **Server-gated attestations** (trust model, recommended) | A stamp server you deployed | Server signs every verdict; admin-cap keys gate `.stamp/**` changes | Pre-receive hook rejects unstamped pushes; v4 envelope verified end-to-end |
| **Attested PRs** (trust model) | GitHub | Server signs every verdict; verified in CI against a public key (asymmetric) | `stamp/verify-attestation@v1` required PR check |
| **Local-only** (advisory, no trust) | Anywhere | None — `--plan` / `--headless` produce no attestation | Discipline-only; signs merges but the remote doesn't enforce anything |

The two **trust models** are server-gated attestations and Attested PRs;
both ride on server-attested verdicts and produce verifying v4 attestations.
Local-only is an advisory mode for fast reviewer iteration when you haven't
deployed a server — it makes no trust claim. **Pick deliberately**; they're
not interchangeable.

The GitHub-primary path (PR verification) is the natural fit for teams that
already merge through GitHub PRs. The reviewer flow stays local (`stamp review` runs your AI personas on
your machine, full speed and full control), the resulting attestation is
content-addressed (survives squash + rebase + merge-commit), and the PR's
green-check requirement keeps the human in the merge loop. No server to
host, no on-call, no separate trust root.

### Server-gated path

If you've deployed a stamp server (see [`docs/quickstart-server.md`](./docs/quickstart-server.md)
for the full Railway walkthrough), the from-zero flow is three commands:

```sh
ssh stamp new-stamp-repo myproject              # provision bare repo + hook
git clone ssh://stamp/srv/git/myproject.git
cd myproject && stamp bootstrap                  # install real reviewers + trusted-keys manifest, push
```

`stamp bootstrap` detects the freshly-provisioned placeholder state, scaffolds
the three starter reviewers (security, standards, product) plus the
`.stamp/trusted-keys/manifest.yml` declaring trust capabilities, and lands
them on `main` via a single signed merge that the server hook accepts. From
there `stamp review` calls the server's `stamp-review` SSH verb to fetch each
verdict; verdicts come back signed and persist in the v4 attestation envelope
the merge commit carries.

Migrating an existing 1.x repo? Use `stamp init --migrate-to-server-attested`
— it scaffolds the trusted-keys manifest, `path_rules`, and `review_server`
config without touching your reviewer prompts. See the
[migration guide](./docs/migration-1.x-to-2.x.md) for the full walkthrough.

### GitHub-primary path — Attested PRs

For teams whose source of truth is GitHub, `stamp init` against a github.com
origin auto-scaffolds `.github/workflows/stamp-verify.yml` (the verifier that
runs `stamp/verify-attestation@v1` on every PR):

```sh
cd myproject
stamp init                               # scaffolds .stamp/ + stamp-verify.yml (auto)
git add .stamp .github && git commit -m "stamp: scaffold PR verification"
git push origin main
# In GitHub: Settings → Branches → main → Require status checks →
# add `stamp verify` (the workflow's job name) as required
```

`stamp init` wires the advisory PR-check: the verifier runs on every PR and
verdicts are produced locally. For **server-attested** verdicts (signed by
stamp-server) without mirroring your full source into the server, use the
server-attested deployment — see the
[migration guide](./docs/migration-1.x-to-2.x.md).

Per-PR developer flow:

```sh
git checkout -b feature
# ...make changes, commit...
stamp review --diff main..HEAD           # calls stamp-server's stamp-review verb;
                                          # verdicts come back signed by the server key
stamp attest --into main --push origin   # signs the v4 attestation envelope + atomically
                                          # pushes branch + refs/stamp/attestations/<patch-id>
# Open the PR; the workflow runs stamp/verify-attestation against your branch
# Reviewer's check goes green → human clicks merge in the GitHub UI
```

> **2.0.1:** server-side v3 PR-attestation production (AGT-355) ships in
> this release. `stamp attest` now folds server-signed approvals into a
> v3 envelope when the branch rule declares `review_server`; the GH
> Action accepts the envelope directly with no 1.x-action pin needed.

The attestation is keyed on the **content** of the diff (`git patch-id`), so
it survives every GitHub merge strategy: squash, rebase, and merge-commit
all preserve the same patch-id and the same attestation.

By default the gate is **loose on base advancement** (matches GitHub's
"approval persists when main moves" semantic) — the patch-id-equivalence is
sufficient. Set `strict_base: true` under your branch rule in
`.stamp/config.yml` to require re-attest whenever the target branch's tip
advances.

### Local-only path

`--mode local-only` and `--no-pr-check` are independent flags — local-only
controls what `AGENTS.md` says about enforcement; `--no-pr-check` controls
whether the workflow file is scaffolded. To get the pre-1.6.0 behavior
(`.stamp/` + `AGENTS.md` only, no GitHub Action), pass BOTH:

```sh
cd myproject
stamp init --mode local-only --no-pr-check   # scaffolds .stamp/ + AGENTS.md only
git add .stamp AGENTS.md && git commit -m "stamp: advisory config"
git push origin main
```

`--mode local-only` alone (without `--no-pr-check`) still drops the workflow
— operators using local-only often mirror to GitHub for visibility, and the
PR check makes that mirror useful as a gate. Skip the workflow only when you
explicitly don't want it.

You can still run `stamp review` / `stamp merge` / `stamp verify` against this
repo — the merge commits carry signed attestations and `stamp verify <sha>`
validates them on any clone. What you don't get: server-side rejection of
unstamped pushes. Anyone with repo write access can `git push origin main`
of any commit, stamped or not.

### Local-only iteration mode (no server, no attestation)

Local-only mode is a sibling pathway focused on fast reviewer feedback during iteration when you have not deployed a stamp server. `stamp review --plan --diff <revspec>` emits a structured JSON plan (diff + reviewers + per-reviewer prompts + fence hex) on stdout and a `note:`-prefixed no-trust advisory on stderr. The plan is consumed by a parent agent — the [`stamp-review` Claude Code skill](./skills/stamp-review.md) ships in this repo — which fans out one subagent per reviewer in parallel, surfaces their verdicts, and reprints the no-attestation banner. **No verdict signed, no server round-trip, no `stamp merge` gate change.** See [`docs/local-only-mode.md`](./docs/local-only-mode.md) for the consumer contract, the schema-versioning rules, the security boundary, and the headless fallback (AGT-341, in flight).

### Local-test (no server, on-disk bare repo)

Run everything on one machine using a bare git repo on disk as the "remote".
Useful for learning the flow before deploying a real server.

```sh
# Install + initialize a fresh project
mkdir myproject && cd myproject
git init -b main
stamp init                     # scaffolds .stamp/ with three starter reviewers
                               #   (security, standards, product) + keypair in
                               #   ~/.stamp/keys/. Use --minimal to scaffold a
                               #   single placeholder reviewer instead.

# Commit the scaffolded .stamp/ directory so the reviewers + trusted key are
# part of the repo's history before you start working.
git add .stamp && git commit -m "stamp: scaffold starter reviewers"

# Provision a bare "remote" with the verify hook
cd ..
./node_modules/@openthink/stamp/scripts/setup-repo.sh \
    /tmp/myproject.git \
    ./node_modules/@openthink/stamp/dist/hooks/pre-receive.cjs \
    ~/.stamp/keys/ed25519.pub

# Wire up the remote
cd myproject
git remote add origin /tmp/myproject.git

# Work:
git checkout -b feature
# ...make changes, commit...
stamp review --diff main..feature    # three reviewers run in parallel
stamp status --diff main..feature    # gate status; exit 0 if open, 1 if closed
git checkout main
stamp merge feature --into main      # signed merge commit
stamp push main                      # hook verifies; main advances on remote
```

The scaffolded reviewer prompts are generic starting points. Before relying
on them for real code review, edit them to match your project's stack,
conventions, and domain — see [`docs/personas.md`](./docs/personas.md).

Any push that isn't a properly signed stamped merge will be rejected by the
hook with a clear reason.

## Concepts

- **Reviewer** — a persona defined by a prompt file at
  `.stamp/reviewers/<name>.md`. `stamp init` scaffolds three starter
  reviewers (`security`, `standards`, `product`) calibrated for generic
  TS/JS projects — edit them to fit your codebase. Use `--minimal` for
  a single placeholder instead. Prompts must end with a `VERDICT:
  approved|changes_requested|denied` line.
- **Verdict** — a reviewer's judgment on a specific diff. Recorded per
  reviewer per `(base_sha, head_sha)` in `.git/stamp/state.db`.
- **Gate** — for each required reviewer, the latest verdict must be
  `approved`. Config lives at `.stamp/config.yml`.
- **Attestation** — `stamp merge` signs a payload (base/head/target/approvals)
  with Ed25519 and attaches it as `Stamp-Payload` + `Stamp-Verified`
  commit-message trailers on the merge commit.
- **Hook** — `stamp-verify` runs server-side on pre-receive. Reads config
  and trusted keys from the target branch's tree at push time, re-runs
  every check the client ran.

See [`DESIGN.md`](./DESIGN.md) for the full spec and [`docs/ROADMAP.md`](./docs/ROADMAP.md) for current status + upcoming work.

## Commands

**Core review cycle:**

```
stamp init [--mode <mode>]                 # scaffold .stamp/ + keypair; idempotent. Also ensures
                                           #   AGENTS.md at repo root with deployment-mode-aware
                                           #   guidance. --mode is server-gated|local-only;
                                           #   auto-detected from origin if omitted (forge-direct
                                           #   origins default to local-only with a loud warning).
stamp bootstrap                            # one-shot: replace placeholder example reviewer
                                           #   with real reviewers on a fresh server-provisioned
                                           #   repo. See `stamp bootstrap --help`.
stamp review --diff <revspec>              # run all configured reviewers in parallel
stamp review --diff <revspec> --only <name> # run a single reviewer
stamp status --diff <revspec>              # gate check; exit 0 if open, 1 if closed
stamp merge <branch> --into <target>       # operator confirmation → merge → required_checks → sign
                                           #   prompts y/N (with base/head SHAs) before any ref moves.
                                           #   bypass: --yes flag, STAMP_REQUIRE_HUMAN_MERGE=0,
                                           #   or branches.<name>.require_human_merge: false in config.
                                           #   audit H1.
stamp push <target>                        # plain git push; hook stderr forwarded
stamp verify <sha>                         # verify a merge commit's attestation locally
```

**PR-check mode (alternative to `stamp merge` for GitHub PR workflows):**

```
stamp attest [<branch>] --into <target> [--push <remote>]
                                           # validate the gate, sign an attestation envelope,
                                           #   write to refs/stamp/attestations/<patch-id>;
                                           #   with --push, also git push --atomic branch +
                                           #   attestation ref to <remote> in one transaction
stamp verify-pr <head> --base <ref> --into <branch>
                                           # consumer side; used by stamp/verify-attestation@v1
                                           # action and runnable locally for debugging
```

**User & invite management (server-gated mode only):**

```
stamp invites mint <name> --role <admin|member>     # mint a single-use invite token
stamp invites accept <share-url>                    # redeem an invite token
stamp users list                                    # enumerate enrolled users
stamp users promote <name> --to <admin|owner>       # owner-only
stamp users demote <name> --to <admin|member>       # owner-only
stamp users remove <name>                           # owner / admin-removes-member
stamp users set-name <name> --to <new-name>         # claim a human name (default is user-<hex>)
stamp users prune --idle-for <Nd>                   # remove idle users (never owners/self)
stamp trust grant <name>                            # stage a per-repo signing-trust PR
```

> **Identity privacy (AGT-422).** `stamp users list` is readable by every
> enrolled user, so short_names are visible to the whole team. To avoid
> exposing the PII conventionally found in SSH key comments
> (`firstname.lastname@laptop`), env-seeded keys default to a
> **content-addressed** `user-<8-hex>` short_name and the key comment is
> **stripped** before the pubkey is stored. A human-readable name is set
> only when someone explicitly runs `stamp users set-name`. `last_seen_at`
> is recorded on every authenticated command so `stamp users prune
> --idle-for <Nd>` can retire stale accounts.

**Browsing history:**

```
stamp log                                  # first-parent commit list w/ attestation summary
stamp log <sha>                            # drill-down: decoded attestation + review prose
stamp log --branch <name>                  # filter by branch
stamp log --reviews                        # raw DB-row view of every review invocation
stamp ui                                   # interactive TUI: list → detail → review prose
```

**Managing reviewers (persona development):**

```
stamp reviewers list                              # configured reviewers + prompt file status
stamp reviewers add <name> [--no-edit]            # scaffold + register; --no-edit skips $EDITOR
stamp reviewers edit <name>                       # open existing reviewer's prompt
stamp reviewers test <name> --diff <revspec>      # invoke reviewer w/o recording to DB
stamp reviewers show <name> [--limit <n>]         # verdict history + stats for calibration
stamp reviewers remove <name> [--delete-file]     # de-register; optional rm of .md
stamp reviewers fetch <name> --from <source@ref>  # install + pin from canonical source
                                                   #   add --expect-prompt-sha <hex> (or --expect-tools-sha / --expect-mcp-sha)
                                                   #   to anchor first-fetch trust against an out-of-band published manifest
stamp reviewers verify [<name>]                   # check prompt/tool/mcp against lock; exit 3 on drift
```

**Key management:**

```
stamp keys generate                        # create ~/.stamp/keys/ed25519{,.pub}
stamp keys list                            # local + trusted keys in this repo
stamp keys export                          # print your public key
stamp keys trust <pub-file>                # deposit a key into .stamp/trusted-keys/
```

**Trust-anchor administration (2.x, server-gated mode):**

```
stamp admin list-keys                                # show manifest entries (name, fingerprint, capabilities)
stamp admin add-key <pubkey.pub> --name <n> --capabilities admin,operator
                                                     # add a key to .stamp/trusted-keys/manifest.yml +
                                                     #   copy the pubkey into .stamp/trusted-keys/.
                                                     #   refuses non-public-key PEMs.
stamp admin revoke <sha256:fingerprint>              # remove entry from manifest.yml
stamp admin sign --pending [<sha>]                   # list/collect admin counter-sigs for
                                                     #   in-flight .stamp/** commits. Sigs land in
                                                     #   refs/notes/stamp-trust-anchor-sigs, folded
                                                     #   into the v4 envelope at merge time
```

`revoke` and `add-key` mutate `.stamp/trusted-keys/manifest.yml`, so the
resulting commits trip the `path_rules` gate and need admin counter-sigs
collected via `stamp admin sign --pending <sha>` before they can land.
Revocation is **lenient**: past attestations remain valid (they reference
the manifest snapshot as it was at attestation time); only future merges
are blocked.

**Maintenance:**

```
stamp update                               # upgrade stamp to the latest npm release
```

## Configuration

`.stamp/config.yml`:

```yaml
branches:
  main:
    required: [security, standards, product]   # reviewers that must approve
    required_checks:                           # mechanical checks run pre-merge
      - name: build
        run: npm run build
      - name: typecheck
        run: npx tsc --noEmit
  develop:
    required: [security]

reviewers:
  security:  { prompt: .stamp/reviewers/security.md }
  standards: { prompt: .stamp/reviewers/standards.md }
  product:   { prompt: .stamp/reviewers/product.md }
```

Reviewer names are arbitrary — pick whatever matches your team's review
dimensions. The prompt file is the reviewer's full system prompt; the only
contract is that it must end with a `VERDICT:` line. See
[`docs/personas.md`](./docs/personas.md) for how to write good reviewer prompts.

`required_checks` run on the **post-merge tree** before the commit is signed.
Any non-zero exit blocks the merge and rolls it back. Results are attested
into the commit's signed payload; the server hook verifies that attestation
matches the committed config.

> **Security note.** `required_checks[].run` values execute as shell commands
> on the merger's machine via `spawnSync(cmd, { shell: true })`. Anyone who
> can land a PR that touches `.stamp/config.yml` can introduce arbitrary
> code that will run on the next person to call `stamp merge`. The 1.x
> mitigation is the reviewer gate itself: `.stamp/config.yml` changes go
> through the same reviewers as any other code change, and your security
> reviewer prompt should treat `required_checks` edits as high-scrutiny.
> Unlike GitHub Actions, these commands are **not** sandboxed. See
> [`DESIGN.md`](./DESIGN.md#security-model) for the full threat model and
> the 2.x server-attested resolution, which moves `.stamp/**` (including
> `required_checks`) under admin-only signing via `path_rules`.

Optional: `.stamp/mirror.yml` enables GitHub mirroring via the post-receive
hook. See [`server/README.md`](./server/README.md).

### 2.x: server-attested config

In 2.x server-gated mode, three additional config surfaces apply:

```yaml
# .stamp/config.yml — review_server tells stamp where to fetch signed verdicts
review_server:
  host: stamp                                # ssh alias for your stamp-server
  pubkey_fingerprint: sha256:abc...          # the server's review-signing key fingerprint
  trusted_keys_snapshot_sha256: sha256:def... # optional pin; verifier recomputes if absent

branches:
  main:
    required: [security, standards, product]
    path_rules:
      - pattern: ".stamp/**"
        require_capability: admin
        minimum_signatures: 2
        bypass_review_cycle: true            # reviewers can't approve their own prompt changes
```

```yaml
# .stamp/trusted-keys/manifest.yml — declares each key's capabilities
keys:
  alice:
    fingerprint: sha256:aaa...
    capabilities: [admin, operator]
  review-server-prod:
    fingerprint: sha256:ddd...
    capabilities: [server]
    role_source: server                      # auto-published by stamp-server; don't hand-edit
```

The manifest's canonical-JSON snapshot hash is bound into every attestation
as `trusted_keys_snapshot_sha256` — that's the load-bearing primitive behind
lenient revocation. Hand-edit by running `stamp admin add-key` /
`stamp admin revoke` (see the [Trust-anchor administration](#trust-anchor-administration-2x-server-gated-mode)
commands above), not by editing the YAML directly.

### Per-user reviewer-model selection

`~/.stamp/config.yml` lets each operator pick which Anthropic model each
reviewer runs on. Defaults are written by `stamp init` (and lazily on
first `stamp review` after upgrade) — Sonnet across the three starter
personas:

```yaml
reviewers:
  security: claude-sonnet-4-6
  standards: claude-sonnet-4-6
  product: claude-sonnet-4-6
```

Tune with the CLI rather than hand-editing:

```
stamp config reviewers show
stamp config reviewers set security claude-opus-4-7
stamp config reviewers clear security        # remove one entry
stamp config reviewers clear --all           # delete the whole file
```

Reviewers without a pinned model fall back to the agent SDK's default. The
file is per-user (not committed) and intentionally NOT included in the
reviewer attestation hash chain — cost/speed is operator infrastructure,
not committed review policy. Different operators on the same repo can
pick different models without merge-conflicting over preference.

Note: when two operators run reviews on the same diff with different
models pinned, each operator records their own verdict in their own
state.db (same as today's reviewer-prompt model). Stamp does not assume
verdicts are model-portable.

#### Local-model reviewer backend (unmetered)

A reviewer can run against a **local** OpenAI-compatible model server (LM
Studio, llama.cpp's `llama-server`, vLLM, …) instead of the Anthropic API.
Pin the reviewer's model with the `local:` scheme and the review runs
entirely on your own machine — no Anthropic Agent SDK, no `claude -p`, no
API call, nothing metered:

```yaml
reviewers:
  security: local:lmstudio-community/Qwen3-Coder-30B-A3B-Instruct-MLX-4bit  # local
  standards: claude-sonnet-4-6                                              # Anthropic
local_endpoint: http://localhost:8080/v1   # e.g. mlx_lm.server; LM Studio uses :1234
```

The id after `local:` is whatever the server reports at `GET <endpoint>/models`.

`stamp config reviewers set security local:<model-id>` works through the
same CLI; `local_endpoint` is hand-edited (it's machine-specific). Mix and
match — some reviewers local, some Anthropic — per reviewer.

**Per-run override.** Set `STAMP_REVIEWER_BACKEND=anthropic` to force every
reviewer onto the Anthropic agent-SDK path for a single run, ignoring any
`local:` config — for someone who normally runs local but wants to review on
Claude this time:

```
STAMP_REVIEWER_BACKEND=anthropic stamp review --diff main..feature
```

It uses your logged-in Claude session (no `ANTHROPIC_API_KEY` needed) and
accepts the post-June-15 metering. A `local:` reviewer's model id isn't valid
for Anthropic, so it falls back to the SDK default model; reviewers pinned to
a real Anthropic model keep it.

**Trust posture is identical to the Anthropic local-LLM path.** A local
reviewer produces a verdict that gates `stamp merge` exactly like the SDK
reviewer; the trust anchor is unchanged — your machine produces the verdict,
the signed merge + the server's pre-receive hook are what get verified.
Moving inference to a local model doesn't touch that boundary, it just takes
the review off the metered path. (And because an all-local run sends nothing
off-host, it skips the Anthropic data-flow consent gate — useful for
regulated / air-gapped repos.)

**Setup.** Any OpenAI-compatible server works. Two common ones:

- **`mlx_lm.server`** (Apple Silicon): `mlx_lm.server --model <hf-repo-id> --port 8080` → endpoint `http://localhost:8080/v1`.
- **LM Studio**: load the model → **Developer** → **Start Server** → endpoint `http://localhost:1234/v1`.

Then `curl <endpoint>/models` for the exact model id, put it after `local:`, and set `local_endpoint` to match.

**v1 limitations.** The local reviewer is one-shot (a single model turn, no
agentic file-reading tools): it sees the diff, not the surrounding tree. For
a reviewer with `enforce_reads_on_dotstamp` (the `security` default), stamp
auto-includes the full content of changed `.stamp/*` files in the prompt so
trust-anchor changes are still inspected. It does **not** use tool-calling —
several local servers (notably `mlx_lm.server`) mishandle or crash on the
`tools` parameter — so the verdict comes through a `VERDICT:` line that
stamp's prompt appends automatically and parses leniently (markdown/case
tolerant); just write your reviewer prompt normally. The prior-review
"ratchet" prose is Anthropic-path-only for now — the local path still gets
the narrowed delta diff across rounds.

### Reviewer execution budgets

Each reviewer subprocess runs under bounds that can be set in three
places, narrowest-wins: per-reviewer fields in `.stamp/config.yml`
(committed policy, hashed into the attestation), operator env vars on
the calling shell (per-shell, not committed), or the built-in default.

| Knob | Env var (default) | `.stamp/config.yml` field | What it caps |
|---|---|---|---|
| Turn cap | `STAMP_REVIEWER_MAX_TURNS` (`8`) | `reviewers.<name>.max_turns` | Model/tool round-trips. Hitting it surfaces as `reviewer "<name>" run failed (subtype=error_max_turns) — turn trace at <path>; raise STAMP_REVIEWER_MAX_TURNS or set reviewers.<name>.max_turns to extend it`. |
| Wall-clock | `STAMP_REVIEWER_TIMEOUT_MS` (`300000`) | `reviewers.<name>.timeout_ms` | Time per reviewer. Hitting it aborts the SDK call and writes a turn trace. |
| Diff size | `STAMP_REVIEW_DIFF_CAP_BYTES` (`204800`) | — (operator-side only) | Per-reviewer diff size; bypass per-invocation with `--allow-large`. Lives here because diff size is operator-bounded input rather than per-reviewer execution policy. |

The defaults are tight enough that a pathological reviewer gives up in
single-digit minutes rather than racking up Anthropic spend silently.
Reach for the committed `.stamp/config.yml` form when one reviewer
legitimately needs headroom (e.g. a `product` reviewer that does Linear
ticket reconciliation) but raising the global env would over-budget the
others; reach for the env vars for ad-hoc operator overrides.

```yaml
# .stamp/config.yml — example: heavy product reviewer
reviewers:
  security:  { prompt: .stamp/reviewers/security.md }
  standards: { prompt: .stamp/reviewers/standards.md }
  product:
    prompt: .stamp/reviewers/product.md
    max_turns: 20
    timeout_ms: 600000
```

```sh
# Operator-side global override for a one-off ad-hoc run
STAMP_REVIEWER_MAX_TURNS=20 STAMP_REVIEWER_TIMEOUT_MS=600000 \
  stamp review --diff main..HEAD
```

When a reviewer trips the cap, a structured turn trace is written to
`<repoRoot>/.git/stamp/failed-runs/<unix-ms>-<reviewer>.log` (mode
`0600`, parent `0700`, JSON; lists the tool-call sequence and input
hashes that the reviewer made before failure — never raw model prose
or unhashed inputs). Use it to distinguish a looping prompt from a
legitimately under-budgeted reviewer. `stamp prune --older-than <dur>`
walks both `failed-runs/` and `failed-parses/`. See
[`docs/troubleshooting.md`](./docs/troubleshooting.md) for the full
runbook.

## Deployment topologies

Three ways to run stamp-cli in a real setting, trading setup cost for
enforcement strength. This is the *topology* axis (where the remote lives
and what can enforce a gate) — orthogonal to the trust model you pick in
the quick-start above. Choose based on whether your remote can run a
pre-receive hook — GitHub can't, so the choice matters.

**1. Self-hosted remote — full enforcement (recommended).**
A server you control runs `git + sshd` with stamp-cli's pre-receive
hook installed. Every push is rejected at the server if it isn't a
properly signed stamped merge, so author-agents can't bypass the gate
even with working credentials.
Easiest path: deploy `server/Dockerfile` to Railway, Fly, or any
container host — see [`server/README.md`](./server/README.md) for the
Railway walkthrough. Minimalist alternative: any Linux host with `git +
sshd + Node 22.5+` — create a bare repo, drop
`dist/hooks/pre-receive.cjs` into `hooks/pre-receive` (chmod +x), done.
The hook is self-contained.

**2. Self-hosted remote + GitHub mirror — full enforcement + GitHub ecosystem.**
Run the stamp server as source-of-truth; commit `.stamp/mirror.yml` to
mirror verified commits to a GitHub repo via the post-receive hook.
Deploy pipelines (Actions, Vercel, Netlify) integrate with the GitHub
copy. GitHub branch protection restricts pushes on the mirror to the
bot identity, so the only way anything lands on GitHub's `main` is via
a verified push through your stamp server. Humans can still fork/PR on
GitHub, but those PRs can't merge. See
[`server/README.md`](./server/README.md)'s GitHub mirror section.

**3. Local-only — weakest enforcement, lowest setup.**
Skip the server entirely. stamp-cli still produces signed merge commits
locally, and `stamp verify <sha>` validates them anywhere — but anyone
with push access to your remote (e.g. GitHub `main` without branch
protection, or with protection that doesn't require the hook) can
bypass the gate. You get the attestation audit trail without running
infrastructure. Suitable for solo use or small trusted teams.

## For agent authors

stamp-cli is designed for agents as the primary user. What that means in
practice:

- **Output is prose**, not JSON. LLMs read prose natively. No `--json` flag.
- **Control flow is exit codes.** Agent loops branch on them.
- **State is files.** `.stamp/config.yml`, `.git/stamp/state.db` (chmoded
  `0600`; parent `.git/stamp/` chmoded `0700`), git commit trailers. Easy
  to inspect, hard to lose. To bound retention on long-lived repos, run
  `stamp prune --older-than 30d` — one invocation cleans both DB rows
  and any failed-parse spool files under `.git/stamp/failed-parses/`.
  Use `--dry-run` first to preview.
- **Operations are idempotent.** `stamp init` is safe to re-run. `stamp
  review` accumulates history; re-invoking doesn't corrupt anything.

The canonical unattended loop:

```sh
# Unattended-loop intent: agent has no TTY, so confirm-on-merge would
# block forever. Declare the bypass once at shell scope.
export STAMP_REQUIRE_HUMAN_MERGE=0

while :; do
  stamp review --diff main..$BRANCH
  if stamp status --diff main..$BRANCH; then
    git checkout main
    stamp merge "$BRANCH" --into main
    stamp push main
    break
  fi
  # author-agent reads review output, patches code, commits, loops
done
```

`stamp merge` defaults to interactive confirmation (audit H1: residual
risk of LLM-verdict-as-merge-authorization). Three opt-out paths:
`--yes` per-invocation, `STAMP_REQUIRE_HUMAN_MERGE=0` per-shell, or
`branches.<name>.require_human_merge: false` in `.stamp/config.yml`
(committed and reviewer-gated like any other config).

For trust-anchor changes specifically, set
`reviewers.<name>.enforce_reads_on_dotstamp: true` on the reviewer
that verifies them (typically `security`). When that reviewer
approves a diff that touches `.stamp/*`, every modified path must
appear in its `Read` trace; otherwise the verdict is overridden to
`changes_requested` with a diagnostic prose pointing at the missing
files. Defends against a prompt-injected reviewer waving through
its own trust anchors. Audit-H1 defense-in-depth.

**Exit-code cheat sheet:**

| Command | 0 | non-zero (check stderr to disambiguate) |
|---|---|---|
| `stamp review` | reviewers ran and recorded | invocation failed (reviewer crash, DB error) — verdict may or may not be approved; always follow with `stamp status` to check the gate |
| `stamp status` | gate open (all required reviewers approved) | gate closed — at least one required reviewer missing or non-approved |
| `stamp merge` | merge signed, on main | stderr says which case: `gate CLOSED:` (need reviews), `confirmation required:` (no TTY + no opt-out — set `STAMP_REQUIRE_HUMAN_MERGE=0` or pass `--yes`), `merge cancelled:` (operator answered 'n' at the prompt), `pre-merge checks failed:` (merge rolled back, need fix), or a git-merge conflict message (working tree needs resolution) |
| `stamp push` | remote accepted | stderr has `remote: stamp-verify: rejecting ...` for hook rejections, or a standard git error for network/auth issues |
| `stamp verify` | attestation valid | stderr names the specific verification step that failed (signature invalid, untrusted signer, SHA mismatch, missing check, etc.) |

Distinct exit codes per failure mode are on the roadmap — for now, agents should regex on the stderr markers above to disambiguate.

**Tuning reviewer prompts.** Use `stamp reviewers test <name> --diff <revspec>`
when iterating on a prompt — it invokes the reviewer against a diff **without
recording to the DB**, so you can tweak the prompt, retest, and not pollute
history. Pattern:

```sh
$EDITOR .stamp/reviewers/my-reviewer.md
stamp reviewers test my-reviewer --diff main..test-violations
# read output, adjust prompt, repeat
```

See [`docs/personas.md`](./docs/personas.md) for reviewer-prompt guidance and
[`docs/troubleshooting.md`](./docs/troubleshooting.md) for common failures
with concrete fixes.

## Data flow / privacy

stamp-cli runs reviewers by sending the diff to Anthropic. Operators
working with sensitive content should know the data-flow contract before
running their first `stamp review`. To disable LLM-using stamp surfaces
entirely on a host (regulated environment, DPA-bound deployment, air-gap),
set `STAMP_NO_LLM=1` — `stamp review`, `stamp reviewers test`, and
`stamp bootstrap` will refuse to start with a clear error, and no diff
content will leave the host. The signing, verification, merge, and log
primitives (`stamp keys`, `stamp merge`, `stamp verify`, `stamp log`,
the pre-receive hook) all continue to work; an operator can capture
manual-review verdicts in `state.db` out-of-band before merge if
required.

**What gets sent to Anthropic on every `stamp review`:**

- The full unified diff between `base_sha` and `head_sha`, including all
  added and removed lines, comments, fixtures, and any strings or
  credentials present in the changeset.
- The reviewer's prompt file (read from the merge-base tree).
- The configured tool allowlist + MCP server names for that reviewer.

**What stays local:**

- Reviewer prose, verdicts, and tool-call traces are persisted to
  `.git/stamp/state.db` (a sqlite file under the repo's git common
  dir; per-machine, not committed, not pushed). The DB is chmoded
  `0600` and its parent directory `0700` on every open so peer users
  on shared/dev machines can't read review prose. Failed parses
  additionally write the raw model output to a per-machine file under
  `.git/stamp/failed-parses/<unix-ms>-<reviewer>.txt` (mode `0600`),
  also never pushed. To bound retention — long-lived repos accumulate
  every review's verbatim model output indefinitely — use
  `stamp prune --older-than <duration>` (e.g. `stamp prune
  --older-than 30d`; one invocation cleans both DB rows and old spool
  files under the same threshold; `--dry-run` previews both passes
  without deleting).
- **Content posture of the `issues` (prose) column.** Reviewer prompts
  instruct the model to quote specific `file:line` snippets, so the
  `reviews.issues` column accumulates verbatim excerpts of the most
  sensitive parts of every diff reviewed on this machine. The `0600`/`0700`
  modes protect against peer users, but `state.db` is **not** excluded from
  backups or `tar`-the-repo workflows and is shared across worktrees (it
  lives in the git common dir). **On a machine reviewing PHI/PCI or other
  regulated content, treat `.git/stamp/state.db` (and the
  `.git/stamp/failed-parses/` spool) as carrying that classification** —
  apply matching backup and retention controls. Three retention knobs:
  `stamp init` prints a weekly `stamp prune` schedule snippet;
  `STAMP_REVIEW_PROSE_TTL_DAYS` makes `stamp prune` null prose older than
  the TTL (keeping the verdict rows); and `stamp review --no-prose` records
  verdict + hashes only, never persisting prose for that run.
- Your Ed25519 signing key (`~/.stamp/keys/`) never leaves your machine.

**What gets attached to the merge commit and mirrored to GitHub:**

- The signed `Stamp-Payload` trailer carrying approvals, base/head
  SHAs, signer key fingerprint, and a tool-call audit trace (tool
  names + input hashes — not the diff content itself).

**Disclosure on run.** Two notices fire on stderr:

- The first `stamp review` in a repo prints a short one-time note
  pointing at this section, recorded under `.git/stamp/llm-notice-shown`
  and not repeated.
- **Every** `stamp review` prints a terse per-invocation marker —
  `note: diff sent off-host for review (N reviewers).` — so the data
  flow is visible even in an agent loop or CI run that misses the
  one-time note. It is mode-neutral: it reads accurately whether the
  diff goes directly to Anthropic or through a `review_server` that
  calls Anthropic on the client's behalf.

Both are suppressed unconditionally with `STAMP_SUPPRESS_LLM_NOTICE=1`
— agent loops, CI workers, environments where the disclosure is already
baked into team docs.

**Sub-processor disclosure & consent (`data_flow`).** Anthropic is a
**sub-processor** for stamp-cli: every review ships the diff to it (or to
a `review_server` that does). An optional top-level `data_flow:` block in
`.stamp/config.yml` lets operators make that explicit and, for regulated
repos, gate review on a committed acknowledgement:

```yaml
data_flow:
  # Echoed to stderr on every `stamp review` (suppressible). Free-form prose.
  disclosure: |
    Reviews send the diff to Anthropic (sub-processor). Do not place
    PHI/PCI in a branch reviewed on an account without a ZDR contract.
  # Opt-in regulated gate. When true, `stamp review` REFUSES to run unless
  # `confirmed: true` is also committed. Omit (or set false) for
  # disclosure-only behaviour — the block echoes but never blocks.
  require_confirmation: true
  # The committed acknowledgement. Reviewed like any other config change,
  # so accepting the sub-processor disclosure leaves an audit record.
  confirmed: true
```

The block is read from the merge-base tree like every other policy field,
so a feature branch cannot ship its own `confirmed: true` to wave its own
introduction past the gate. It is purely additive — it does **not** enter
the reviewer attestation hash, so existing attestations and `stamp verify`
are unaffected.

**Anthropic's data handling.** Reviewer calls go through the Claude
Agent SDK, which inherits whatever auth + retention posture you have
configured for Claude Code on your machine (Anthropic API key, Zero
Data Retention contract, etc.). **`STAMP_ANTHROPIC_NO_RETAIN=1` is a
documented no-op** in this build: the Agent SDK exposes no honoured
request-level zero-retention control, and Anthropic
[Zero Data Retention](https://docs.anthropic.com/en/docs/about-claude/data-retention)
is an *account-level* contract — it cannot be toggled per request via an
env var or header. Setting the flag prints a warning to that effect rather
than implying a guarantee that isn't there; to actually bound exposure,
arrange a ZDR contract with Anthropic or set `STAMP_NO_LLM=1` to stop
sending diffs off-host. See Anthropic's
[privacy policy](https://www.anthropic.com/privacy) and
[usage policy](https://www.anthropic.com/legal/aup) for the
authoritative terms; configure accordingly before running stamp on
content you're not free to share.

## Security model

**What this protects against.** Author-agents cannot merge unreviewed code,
cannot forge merges (the signing key isn't on disk anywhere they can
exfiltrate without the operator's explicit consent), and cannot bypass the
remote's verification. In 2.x server-gated mode, the operator also cannot
forge a reviewer verdict without compromising stamp-server's signing key
or stealing it from the server — the operator's machine never sees the
prompt the server used, and the server signs the verdict, prompt hash, and
diff hash together.

**What this doesn't protect against:**

- **Server compromise.** If stamp-server's review-signing key is stolen,
  forged verdicts verify cleanly until rotation. Mitigated by standard
  infra hygiene plus lenient revocation: revoking the compromised key
  via `stamp admin revoke` blocks future merges without invalidating past
  ones. Rotate by adding the new key first, collecting admin sigs on the
  manifest change, then revoking the old key in a follow-up commit.
- **Local-only mode (no server).** Produces no attestation by design — `--plan`
  and `--headless` are iteration aids, not trust claims. Anything producible
  without a server can be forged by the operator. See
  [`docs/local-only-mode.md`](./docs/local-only-mode.md).
- **The human holding the operator key in 1.x.** 1.x operator-trust mode
  still relies on convention to bind verdict to model invocation. The 2.x
  upgrade closes this gap structurally; the
  [migration guide](./docs/migration-1.x-to-2.x.md) walks the upgrade per-repo.

For the full threat model, deferred-to-Phase-2 list, and the cryptographic
guarantees behind the v4 envelope, see
[`docs/plans/server-attested-reviews.md`](./docs/plans/server-attested-reviews.md)
and [`DESIGN.md#security-model`](./DESIGN.md#security-model).

## License

stamp-cli itself is MIT-licensed.

**Third-party dependency notice.** stamp-cli invokes reviewers via
[`@anthropic-ai/claude-agent-sdk`](https://www.npmjs.com/package/@anthropic-ai/claude-agent-sdk),
which is distributed under Anthropic's proprietary license ("SEE LICENSE IN
README.md" on the package). Running `stamp review` — or installing stamp-cli
via npm at all — binds you to Anthropic's terms of service for API usage and
their SDK's license. Review those before integrating stamp-cli into
distributed products.

All other runtime dependencies are permissively licensed (MIT, ISC, BSD,
Apache-2.0).
