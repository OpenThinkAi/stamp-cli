# stamp-cli — design

Local, headless pull-request system for agent-to-agent code review workflows. Part of the OpenThink suite.

## Product vision

- An author-agent works on a branch, runs `stamp review` against a diff, gets prose feedback, iterates, and when the gate opens, runs `stamp merge` and `stamp push` — all without human involvement. The remote verifies the push cryptographically and rejects if the merge wasn't properly reviewed.
- **GitHub is for humans collaborating. stamp is for agents cycling fast while keeping main clean.**
- The **write path** (review, merge, verify, push) is agent-only. The **read path** (browsing history, rendering commits, exposing verification data publicly) is for anyone — operators expose it through `stamp serve` or their own frontend.
- Explicit non-goals: GitHub parity, visual diff rendering, human-facing comment threads, multi-user collaboration, web UI in core, CI system.

## Product shape

stamp-cli ships as three pieces:

1. **`stamp` client CLI** — the author-agent and operator tool. Commands: `init`, `review`, `status`, `merge`, `push`, `keys`, `reviewers`, `verify`, `log`.
2. **`stamp-verify` pre-receive hook** — a Node script distributed with the package, installed into a bare git repo's `hooks/pre-receive`. Enforces the verification gate on pushes server-side.
3. **`stamp serve` HTTP API** (Phase 2) — read-only endpoints exposing commit history + verification data. Consumers build their own frontends.

Core product ships no UI. Operators who want a web surface consume the API; operators who want a TUI can use a Phase 2 `stamp ui` command.

## Canonical server stack

stamp-cli does not ship a git server and does not depend on one being pre-built. Canonical deployment:

- Any Linux host (VPS, Railway container, Fly, bare-metal)
- `git` + `sshd` (standard packages)
- Bare repos under `/srv/git/<name>.git`
- `stamp-verify` hook installed in each protected repo's `hooks/pre-receive`
- SSH key-based auth for agents/devs

Users may also install the hook into any git forge that supports pre-receive hooks (Gitea, GitLab self-hosted, GHE) — the hook is forge-agnostic.

## Core concepts

**Reviewer** — a persona defined by a prompt file under `.stamp/reviewers/<name>.md`. stamp-cli ships no opinionated reviewers; it provides a contract. Each deployment supplies its own reviewers (security, standards, product, API-design, style — whatever the team chooses). `stamp init` scaffolds one example stub that demonstrates the format.

**Verdict** — a reviewer's judgment on a specific diff. One of:
- `approved` — contributes to gate
- `changes_requested` — specific issues to fix; re-review after patching
- `denied` — approach is wrong, rethink the whole change (still blocks, but signals "redesign" rather than "adjust")

**Diff** — always an explicit git revspec, e.g. `main..my-feature`. The tool never infers "current branch vs configured base." The agent says what to review.

**Gate** — for a given `(base_sha, head_sha)`: for each required reviewer, take the *latest* verdict. If all are `approved`, gate is open. Verdicts are SHA-bound — advancing the branch produces a new `head_sha` and prior verdicts don't apply.

**Stamp** — informal term for an attestation on a merge commit. The *tool*'s brand, not a database entity. A merge commit is "stamped" when it carries a valid `Stamp-Verified` trailer + approved verdicts for all required reviewers.

## Data model

Single SQLite table, append-only:

```sql
CREATE TABLE reviews (
  id         INTEGER PRIMARY KEY,
  reviewer   TEXT    NOT NULL,
  base_sha   TEXT    NOT NULL,
  head_sha   TEXT    NOT NULL,
  verdict    TEXT    NOT NULL,  -- approved | changes_requested | denied
  issues     TEXT,               -- prose feedback
  created_at TEXT    NOT NULL
);
CREATE INDEX idx_reviews_shas ON reviews(base_sha, head_sha, reviewer);
```

Gate query (latest verdict per reviewer, for a given SHA pair):

```sql
SELECT reviewer, verdict
FROM (
  SELECT
    reviewer,
    verdict,
    ROW_NUMBER() OVER (PARTITION BY reviewer ORDER BY created_at DESC, id DESC) AS rn
  FROM reviews
  WHERE base_sha = ? AND head_sha = ?
)
WHERE rn = 1;
```

`id DESC` as the tiebreaker handles pathological case where two verdicts arrive in the same second.

## Storage

- **Committed** (at repo root): `.stamp/config.yml` + `.stamp/reviewers/*.md` + `.stamp/trusted-keys/*.pub` — team conventions, versioned with the code
- **Local-only**: `.git/stamp/state.db` — SQLite DB, never committed, never pushed. Survives `git gc`, dies with the clone.
- **Per-user keys**: `~/.stamp/keys/` — Ed25519 private key with 600 perms. Public key is committed to the repo's `.stamp/trusted-keys/<machine-name>.pub`.

Uses `node:sqlite` (Node 22.5+ built-in) — same pattern as `open-think`. Zero external SQLite deps.

## Config schema

`.stamp/config.yml`:

```yaml
branches:
  main:
    required: [security, standards, product]   # reviewer approval gate
    required_checks:                            # mechanical pre-merge gate
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

Names are user-chosen. The above is an example, not a fixed set. `required_checks` is optional; if omitted, only the reviewer gate applies.

**`required_checks` semantics (Phase 2.A):**

- Each check is `{ name, run }` — `run` is a shell command.
- `stamp merge` runs every check **on the post-merge tree** (after `git merge --no-ff` has been applied, before the commit is signed). Running on the post-merge state is correct because that's the state that would actually land on the target branch.
- Non-zero exit blocks the merge. stamp-cli rolls back via `git reset --hard HEAD~1` so the working tree ends up exactly as it was before `stamp merge` was invoked.
- Results of each check — `{ name, command, exit_code, output_sha }` where `output_sha = sha256(stdout + stderr)` — are written into the signed attestation payload under the `checks` field.
- Server-side hook verifies the attestation's `checks` array contains every required check from the committed config with `exit_code: 0`. The server does not re-run the checks; it trusts the signer's attestation (this is the intentional "attested local check execution" tradeoff — see README security model).

**Optional: `.stamp/mirror.yml` for GitHub mirroring (Phase 2.D):**

```yaml
github:
  repo: owner/repo
  branches:
    - main
```

Read by the server-side post-receive hook after a push is accepted. For each configured branch, the hook pushes to `https://x-access-token:$GITHUB_BOT_TOKEN@github.com/<repo>.git`. `GITHUB_BOT_TOKEN` comes from `/etc/stamp/env` on the server (populated by the entrypoint from a Railway env var; sshd strips custom env vars from sessions, so a file is the reliable transport). Mirror failures log to stderr but don't block the stamped push.

## Signing & attestation

`stamp merge` produces a merge commit whose message includes two trailers:

```
Stamp-Payload: <base64 JSON>
Stamp-Verified: <base64 Ed25519 signature>
```

**Payload schema:**

```json
{
  "base_sha": "abc123...",
  "head_sha": "def456...",
  "target_branch": "main",
  "approvals": [
    { "reviewer": "security",  "verdict": "approved", "review_sha": "..." },
    { "reviewer": "standards", "verdict": "approved", "review_sha": "..." },
    { "reviewer": "product",   "verdict": "approved", "review_sha": "..." }
  ],
  "checks": [
    { "name": "build",     "command": "npm run build",  "exit_code": 0, "output_sha": "..." },
    { "name": "typecheck", "command": "npx tsc --noEmit", "exit_code": 0, "output_sha": "..." }
  ],
  "signer_key_id": "sha256:a1b2c3..."
}
```

Where `base_sha` and `head_sha` identify the diff: for `stamp merge <branch> --into <target>`, `base_sha = merge-base(branch, target)` and `head_sha = <branch>` tip prior to the merge commit.

The signature covers the base64-decoded payload bytes. `signer_key_id` is a SHA-256 fingerprint of the public key (`sha256:<hex>`), not a human-readable name — names collide and can be forged; fingerprints don't.

**Verification (both local `stamp verify` and server-side hook):**

1. Extract `Stamp-Payload` and `Stamp-Verified` trailers from the commit message
2. Look up the signer's public key by fingerprint among `.stamp/trusted-keys/*.pub` (fingerprint derived from the key file, not the filename)
3. Verify Ed25519 signature over the payload bytes
4. Confirm `base_sha` and `head_sha` in the payload match the commit's actual parent and tree lineage
5. Confirm `target_branch` matches the branch being pushed into
6. Confirm `approvals` satisfies `.stamp/config.yml`'s `branches.<target>.required`, where config is read from the repo's HEAD of the target branch **as it existed before this push**
7. Confirm `checks` in the payload covers every entry in `branches.<target>.required_checks` from that same config, with each recording `exit_code: 0`

All seven checks must pass. Any failure → push rejected (or `stamp verify` returns non-zero).

**Trailer size note:** Trailers are single-line. A 3-approval payload serializes to ~400–600 bytes base64 — well within any reasonable line-length limit. If payloads grow beyond a few KB (many approvals, verbose metadata), migrate storage to `git notes` under `refs/notes/stamp/attestations` with the trailer holding only a note reference. Not an MVP concern.

## Bootstrap

A brand-new bare repo has no `.stamp/config.yml` and no `.stamp/trusted-keys/` to verify against. The hook needs an explicit rule for this initial state.

**Rule — operator seeds the repo at creation.** When provisioning a new stamp-protected repo, the operator (via `setup-repo.sh` or equivalent) creates the initial commit on the server's filesystem directly, before any remote pushes are possible. That commit contains:

- `.stamp/config.yml` declaring required reviewers for each branch
- `.stamp/trusted-keys/<operator-fingerprint>.pub` — the operator's public key, which can later trust additional keys
- At minimum one example reviewer prompt stub under `.stamp/reviewers/`

Because this commit is written directly to the bare repo's object store via local git operations (not a push), it does not pass through the pre-receive hook. From that point on, all remote pushes are verified normally — the hook reads the committed config and trusted-keys from the target branch's HEAD, and will reject any push whose attestation doesn't validate.

**Rejected alternatives:**
- *"Hook accepts first unverified push"* — anyone with SSH access can bootstrap the repo with malicious config or trust their own key
- *"Hook reads config from the incoming tree"* — creates a chicken-and-egg verification of the config commit itself

## CLI surface

```
# Core review cycle
stamp init                                  # scaffold .stamp/ + keypair; idempotent
stamp review --diff <revspec>               # run all configured reviewers in parallel
stamp review --diff <revspec> --only <name> # run a single reviewer
stamp status --diff <revspec>               # gate state; exit 0 if open, 1 if closed
stamp merge <branch> --into <target>        # run required_checks → sign → merge
stamp push <target>                         # git push; surfaces hook stderr on reject
stamp verify <sha>                          # verify an existing merge commit's attestation

# Browsing history
stamp log                                   # first-parent commits w/ attestation summary
stamp log <sha>                             # drill into one commit (decoded payload + prose)
stamp log --branch <name>                   # filter by branch
stamp log --reviews [--diff <revspec>]      # raw DB-row view of every review invocation
stamp ui                                    # interactive TUI (list → detail → prose)

# Reviewer management
stamp reviewers list                        # configured reviewers + file status
stamp reviewers add <name> [--no-edit]      # scaffold + register; --no-edit skips $EDITOR
stamp reviewers edit <name>                 # open existing prompt in $EDITOR
stamp reviewers test <name> --diff <revspec> # invoke w/o recording to DB (prompt tuning)
stamp reviewers show <name> [--limit <n>]   # verdict history + aggregate stats
stamp reviewers remove <name> [--delete-file]  # de-register; --delete-file also removes the .md

# Keys
stamp keys generate                         # generate Ed25519 keypair
stamp keys list                             # show local + trusted keys
stamp keys export                           # print public key PEM
                                            # (--pub still accepted as no-op; deprecated)
stamp keys trust <pub-file>                 # deposit a pub key into .stamp/trusted-keys/
```

**Output format: prose.** Not JSON. The consumer is another Claude agent; LLMs read prose natively and JSON adds parse overhead without helping the reader. Control flow happens via exit codes.

## Agent loop (canonical)

```bash
while :; do
  stamp review --diff main..my-feature
  if stamp status --diff main..my-feature; then
    stamp merge my-feature --into main
    stamp push main
    break
  fi
  # author-agent reads the review output, patches code, commits, loops
done
```

## Stack

- Node 22.5+, TypeScript, ESM
- `tsup` — build
- `commander` — CLI
- `@anthropic-ai/claude-agent-sdk` — reviewer invocation
- `node:sqlite` — storage
- `node:crypto` — Ed25519 signing/verification
- `yaml` — config parsing

Matches the `open-think` shape exactly.

## Build order (MVP — Phase 1)

1. **Skeleton** — `src/` layout, tsup config, commander wired, `stamp --help` works
2. **`stamp init`** — scaffold `.stamp/config.yml` + one example reviewer stub + trusted-keys dir; generate local keypair; print public key for user to commit
3. **DB layer** — `node:sqlite` open, migrations, `recordReview()` / `latestVerdicts()`
4. **`stamp review --diff <revspec>`** — compute diff, invoke one reviewer via Agent SDK, record verdict, print prose
5. **Parallel reviewers** — fan out to all configured reviewers concurrently
6. **`stamp status`** — gate evaluation + prose report + exit code
7. **Signing primitives** — Ed25519 keygen + sign + verify wrappers
8. **`stamp merge`** — gated `git merge --no-ff`, build payload, sign, attach trailers
9. **`stamp-verify` hook** — Node script that reads trusted keys, parses trailers, verifies signature + approvals + SHA binding, exits 0/1 with stderr message
10. **`stamp push`** — plain `git push`; surface hook stderr on rejection
11. **`stamp log`** — pretty-print review history on current branch
12. **Dogfood** — run a full cycle on stamp-cli's own repo against a self-hosted bare-git remote

## Decisions confirmed

- Verdicts not stamps (single-table model; "stamp" is the tool's brand)
- Explicit `--diff` revspecs (no implicit "current branch vs default base")
- Prose output, no `--json` flag
- Control flow via exit codes
- Storage in `.git/stamp/state.db`, local-only
- Reviewers as external prompt `.md` files — stamp-cli ships a contract, not opinions
- Verdicts are SHA-bound; advancing HEAD invalidates prior verdicts
- Canonical remote stack: bare git + sshd + `stamp-verify` hook (no forge required)
- Ed25519 signing with Node's built-in crypto; per-machine keypair; public keys committed to `.stamp/trusted-keys/`
- Pre-receive hook is the primary enforcement mechanism
- `signer_key_id` is a SHA-256 fingerprint of the public key, not a human-readable name
- Bootstrap: operator seeds new repo directly on server at creation time; hook always verifies post-bootstrap

## Phase 2

- **`stamp serve` HTTP API** — read-only endpoints: `GET /commits`, `GET /commits/:sha`, `GET /commits/:sha/verify`, `GET /commits/:sha/diff`, `GET /trees/:sha`
- **`stamp ui` TUI** — interactive terminal UI for browsing reviews, editing prompts with live test, managing keys
- **Gated mirror** — post-receive hook extension to push verified commits to a downstream remote (e.g. github.com) as a bot account
- **Pre-merge test gate** — configurable command runs before `stamp merge` signs the commit
- **Keychain integration (macOS)** — move signing key from filesystem to Keychain
- **Large-diff chunking** — split oversized diffs into logical units for parallel review
- **Reviewer output caching** — skip re-review when files under a reviewer's scope haven't changed

## Phase 3

- **GitHub adapter** — staging-branch + Action pattern for teams locked into github.com
- **Multi-key / team key rotation UX**
- **Sigstore/gitsign integration** — short-lived OIDC-backed certs instead of long-lived Ed25519 keys

## Open questions for first build session

1. **`changes_requested` vs `denied` semantics** — proposed: `changes_requested` = "fix specifics," `denied` = "rethink approach." Confirm before example reviewer stub is written.
2. **Does `review` / `status` strictly require `--diff`?** — leaning yes. Alternative: config default base, so `stamp status` alone means `--diff <default-base>..HEAD`.
3. **Does `stamp merge` take explicit `<branch> --into <target>` or infer from current branch?** — leaning explicit.
4. **Pre-merge test gate** — MVP or Phase 2? Leaning Phase 2.

## Naming note

Tool brand is **stamp** (binary `stamp`, npm package `stamp-cli`). "Stamp" survives as the naming metaphor even though there's no `stamps` table — reviewers stamp a diff with their approval, the remote checks for the required stamps before accepting a push.
