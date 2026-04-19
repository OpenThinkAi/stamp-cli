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

## Install

```sh
npm install -g stamp-cli
```

Node 22.5+ required (we use `node:sqlite` and `node:crypto`'s Ed25519 APIs,
both of which are built-in but gated on 22.5+).

## Quick start (local test)

This runs everything on one machine using a bare git repo on disk as the
"remote". Good for learning the shape before deploying.

```sh
# Install + initialize a fresh project
mkdir myproject && cd myproject
git init -b main
stamp init                     # scaffolds .stamp/ + generates ~/.stamp/keys/

# Provision a bare "remote" with the verify hook
cd ..
./node_modules/stamp-cli/scripts/setup-repo.sh \
    /tmp/myproject.git \
    ./node_modules/stamp-cli/dist/hooks/pre-receive.cjs \
    ~/.stamp/keys/ed25519.pub

# Wire up the remote
cd myproject
git remote add origin /tmp/myproject.git

# Work:
git checkout -b feature
# ...make changes, commit...
stamp review --diff main..feature    # reviewers run in parallel, verdicts land in DB
stamp status --diff main..feature    # gate status; exit 0 if open, 1 if closed
git checkout main
stamp merge feature --into main      # signed merge commit
stamp push main                      # hook verifies; main advances on remote
```

Any push that isn't a properly signed stamped merge will be rejected by the
hook with a clear reason.

## Concepts

- **Reviewer** — a persona defined by a prompt file at
  `.stamp/reviewers/<name>.md`. Each deployment supplies its own; stamp-cli
  ships no opinionated reviewers. Prompts must end with a `VERDICT:
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

```
stamp init                                 # scaffold .stamp/ and keypair
stamp review --diff <revspec>              # run reviewers; optional --only <name>
stamp status --diff <revspec>              # gate check; exit 0/1
stamp merge <branch> --into <target>       # signed merge commit
stamp push <target>                        # plain git push; hook stderr forwarded
stamp verify <sha>                         # verify a merge commit's attestation locally
stamp log [--diff <revspec>] [--limit N]   # prose review history
stamp reviewers list                       # inspect configured reviewers
stamp reviewers edit <name>                # open a reviewer prompt in $EDITOR
stamp keys generate                        # create ~/.stamp/keys/ed25519{,.pub}
stamp keys list                            # local + trusted keys in this repo
stamp keys export                          # print your public key
stamp keys trust <pub-file>                # deposit a key into .stamp/trusted-keys/
```

## Configuration

`.stamp/config.yml`:

```yaml
branches:
  main:
    required: [security, standards, product]   # every merge to main requires these
  develop:
    required: [security]

reviewers:
  security:  { prompt: .stamp/reviewers/security.md }
  standards: { prompt: .stamp/reviewers/standards.md }
  product:   { prompt: .stamp/reviewers/product.md }
```

Reviewer names are arbitrary — pick whatever matches your team's review
dimensions. The prompt file is the reviewer's full system prompt; there
are no conventions beyond ending with a `VERDICT:` line.

## Running your own remote

The quick-start above uses a bare repo on disk. For real use, you want
a server other machines can push to.

**Easiest path:** deploy `server/Dockerfile` to Railway (or any container
host). See [`server/README.md`](./server/README.md) for the full Railway
walkthrough.

**Minimalist path:** any Linux host with `git` + `sshd` + Node 22.5+ works.
Create a bare repo, drop `dist/hooks/pre-receive.cjs` into `hooks/pre-receive`
(chmod +x), and you're done. The hook is self-contained.

## How agents use it

The canonical unattended loop:

```sh
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

Output is prose — LLMs read it natively. Control flow is exit codes —
loops branch on `stamp status` / `stamp push` success.

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
verification-rule details.

## License

MIT.
