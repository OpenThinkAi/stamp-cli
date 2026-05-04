# stamp-cli

Local, headless pull-request system for agent-to-agent code review workflows.

An author-agent opens a diff, reviewer-agents consume it and return structured
feedback, the author iterates until merge rules are satisfied, and the merge
is pushed to a remote that cryptographically rejects any push that wasn't
properly reviewed and signed.

**Not a GitHub replacement.** GitHub is for humans collaborating. stamp-cli
is for agent fleets cycling fast while keeping `main` clean. No web UI, no
PR dashboard, no human comment threads in core. Just a CLI + a git hook.

Part of the [OpenThink](https://openthink.dev) suite.

**Docs:** [server quickstart](./docs/quickstart-server.md) (from-zero project on a stamp server) · [DESIGN](./DESIGN.md) (spec) · [threat model](./docs/threat-model.md) (who attacks, how, what defends) · [ROADMAP](./docs/ROADMAP.md) (what's shipped + what's next) · [personas](./docs/personas.md) (writing reviewer prompts) · [troubleshooting](./docs/troubleshooting.md) · [server](./server/README.md) (Railway deploy)

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

**Pick your deployment shape first** — it determines which command you run and
what guarantees you actually get:

| Shape | Origin is… | Enforcement | Command to run |
|---|---|---|---|
| **Server-gated** (recommended) | A stamp server you deployed | The server's pre-receive hook rejects any push without a valid stamped merge | `stamp bootstrap` on a clone of a server-provisioned repo |
| **Local-only** (advisory) | GitHub / GitLab / etc. directly | None — direct `git push origin main` succeeds; the stamp config is documentation + a discipline aid | `stamp init --mode local-only` |

These are not interchangeable. Server-gated is the only shape where the gate
is actually enforced; local-only signs your merges with a verifiable
attestation but the remote does not reject anything. Pick deliberately.

### Server-gated path

If you've deployed the stamp server (see [`docs/quickstart-server.md`](./docs/quickstart-server.md)
for the full Railway walkthrough), the from-zero flow is three commands:

```sh
ssh stamp new-stamp-repo myproject              # provision bare repo + hook
git clone ssh://stamp/srv/git/myproject.git
cd myproject && stamp bootstrap                  # install real reviewers + push
```

`stamp bootstrap` detects the freshly-provisioned placeholder state, scaffolds
the three starter reviewers (security, standards, product), and lands them on
`main` via a single signed merge that the server hook accepts. From there it's
the normal review/merge cycle.

### Local-only path

When origin is a public forge directly (GitHub etc.), `stamp init` defaults to
local-only and prints a prominent warning that the gate is unenforced. Pass
`--mode local-only` to acknowledge explicitly and silence the warning:

```sh
cd myproject
stamp init --mode local-only             # scaffolds .stamp/ + AGENTS.md (advisory mode)
git add .stamp AGENTS.md && git commit -m "stamp: advisory config"
git push origin main
```

You can still run `stamp review` / `stamp merge` / `stamp verify` against this
repo — the merge commits carry signed attestations and `stamp verify <sha>`
validates them on any clone. What you don't get: server-side rejection of
unstamped pushes. Anyone with repo write access can `git push origin main`
of any commit, stamped or not.

### Local-test (no server, on-disk bare repo)

Run everything on one machine using a bare git repo on disk as the "remote".
Useful for learning the shape before deploying a real server.

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
stamp init [--mode <shape>]                # scaffold .stamp/ + keypair; idempotent. Also ensures
                                           #   AGENTS.md at repo root with deployment-shape-aware
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
> code that will run on the next person to call `stamp merge`. The mitigation
> is the reviewer gate itself: `.stamp/config.yml` changes go through the
> same reviewers as any other code change, and your security reviewer prompt
> should treat `required_checks` edits as high-scrutiny. Unlike GitHub
> Actions, these commands are **not** sandboxed. See
> [`DESIGN.md`](./DESIGN.md#security-model) for the full threat model.

Optional: `.stamp/mirror.yml` enables GitHub mirroring via the post-receive
hook. See [`server/README.md`](./server/README.md).

## Deployment shapes

Three ways to run stamp-cli in a real setting, trading setup cost for
enforcement strength. Pick based on whether your remote can run a
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
- Your Ed25519 signing key (`~/.stamp/keys/`) never leaves your machine.

**What gets attached to the merge commit and mirrored to GitHub:**

- The signed `Stamp-Payload` trailer carrying approvals, base/head
  SHAs, signer key fingerprint, and a tool-call audit trace (tool
  names + input hashes — not the diff content itself).

**Disclosure on first run.** The first `stamp review` in a repo prints
a short note (to stderr) pointing at this section. The notice is
recorded under `.git/stamp/llm-notice-shown` and not repeated. To
suppress it unconditionally — agent loops, CI workers, environments
where the disclosure has already been baked into team docs — set
`STAMP_SUPPRESS_LLM_NOTICE=1`.

**Anthropic's data handling.** Reviewer calls go through the Claude
Agent SDK, which inherits whatever auth + retention posture you have
configured for Claude Code on your machine (Anthropic API key, Zero
Data Retention contract, etc.). See Anthropic's
[privacy policy](https://www.anthropic.com/privacy) and
[usage policy](https://www.anthropic.com/legal/aup) for the
authoritative terms; configure accordingly before running stamp on
content you're not free to share.

## Security model

**What this protects against.** Author-agents cannot merge unreviewed code,
cannot forge merges (the signing key isn't on disk anywhere they can
exfiltrate without the operator's explicit consent), and cannot bypass the
remote's verification.

**What this doesn't protect against.** You, the human holding the signing
key, can still produce a valid signed merge for arbitrary content. That's
inherent to any local-first system. What signing gives you is
**non-repudiation** — every merge on `main` is permanently attributed to a
specific key's owner, provable from git history alone. For the
agent-can't-bypass threat model this is exactly right.

See [`DESIGN.md`](./DESIGN.md) for the full bootstrap, key-management, and
verification-rule details, including the security model around user-configured
pre-merge checks.

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
