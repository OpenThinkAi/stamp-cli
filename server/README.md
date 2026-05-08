# stamp server

A minimal Docker image that runs a bare git server with `sshd` and the
`stamp-verify` pre-receive hook installed. Any git client with SSH access
can push to it; the hook enforces stamp-cli's verification rules on the
protected branches defined in each repo's committed `.stamp/config.yml`.

## What's in the image

- `git` + `openssh-server` + `nodejs` (Alpine-based, ~200 MB)
- `/etc/stamp/pre-receive` — the built hook
- `/usr/local/bin/setup-repo.sh` — bootstrap script
- `/usr/local/bin/new-stamp-repo <name>` — one-line repo provisioner
- `/entrypoint.sh` — sets up `authorized_keys` + operator pub key from env,
  then boots sshd

## Build locally

From the repo root (not from `server/`):

```sh
docker build -f server/Dockerfile -t stamp-server .
```

## Run locally (test)

```sh
docker run -d \
  --name stamp-server \
  -p 2222:22 \
  -v stamp-data:/srv/git \
  -e AUTHORIZED_KEYS="$(cat ~/.ssh/id_ed25519.pub)" \
  -e OPERATOR_PUB_KEY="$(cat ~/.stamp/keys/ed25519.pub)" \
  stamp-server

# create a repo
ssh -p 2222 git@localhost new-stamp-repo myproject

# clone it from your working machine
git clone ssh://git@localhost:2222/srv/git/myproject.git
```

## Deploy to Railway

1. **Push this repo to GitHub** (or fork and push your own copy).
2. **Create a new Railway project** and connect it to the repo.
3. **Configure the build**:
   - Settings → Build → Dockerfile Path: `server/Dockerfile`
   - Settings → Build → Build Context Path: leave blank (use repo root)
4. **Configure the volume**:
   - Attach a Railway volume to `/srv/git` — this persists your bare repos
     across deployments.
5. **Configure environment variables** (Settings → Variables):
   - `AUTHORIZED_KEYS` — newline-delimited list of SSH public keys allowed
     to connect. Start with your own: `cat ~/.ssh/id_ed25519.pub`.
   - `OPERATOR_PUB_KEY` — the stamp-cli public key that will be seeded as
     the initial trusted signer in each new repo: `cat ~/.stamp/keys/ed25519.pub`.
   - `GITHUB_BOT_TOKEN` — **optional**, only needed if you want to mirror
     verified commits to a GitHub repo (see "GitHub mirror" below). A
     fine-scoped GitHub PAT with `contents: write` on the target repo(s).
6. **Expose port 22** via Railway's TCP proxy:
   - Settings → Networking → Public Networking → TCP Proxy → create one
     pointing at container port 22. Railway gives you a public host +
     high-numbered port (e.g. `ssh.railway.app:12345`).
7. **Point a domain at it (optional)**:
   - CNAME your domain at Railway's TCP proxy host. Note you'll still
     connect on the assigned high port; SSH doesn't do the Host header
     trick HTTP does.

### Connecting from your laptop

```sh
# Add a host entry for convenience (optional)
cat >> ~/.ssh/config <<EOF
Host stamp
  HostName ssh.railway.app
  Port 12345
  User git
  IdentityFile ~/.ssh/id_ed25519
EOF

# Provision a new repo
ssh stamp new-stamp-repo myproject

# Clone it
git clone ssh://stamp/srv/git/myproject.git
```

## Daily workflow

Once a repo exists on the server, stamp-cli handles everything from your
laptop — the server just enforces the hook on pushes.

```sh
git clone ssh://stamp/srv/git/myproject.git
cd myproject
stamp init                          # creates .git/stamp/state.db + keypair
# ...hack on a feature branch...
stamp review --diff main..HEAD      # reviewers give verdicts
stamp status --diff main..HEAD      # gate check
git checkout main
stamp merge my-feature --into main  # signed merge commit
stamp push main                     # hook verifies, main advances
```

## GitHub mirror (optional)

After a successful stamped push lands on the server, a **post-receive hook**
can automatically mirror the ref to a GitHub repo. The stamp server stays
source-of-truth; GitHub becomes a read-only public mirror that deploy
pipelines (Actions, Vercel, Netlify, etc.) can integrate with natively.

### Per-repo config

Commit `.stamp/mirror.yml` at the repo root declaring the GitHub destination:

```yaml
github:
  repo: your-user/your-repo       # GitHub "owner/repo" of the mirror destination
  branches:
    - main
    - "release/*"                  # glob patterns; literal names match exactly
  tags:                            # optional — mirror tags to GitHub too
    - "v*"                         # glob patterns (or `true` for all tags)
```

Only branches and tags whose names match an entry are mirrored — `branches:`
takes the same `*` / `?` glob grammar as `tags:`, so a literal `main` matches
just that branch and `release/*` catches every branch under that prefix.
Other refs are pushed to your stamp server but not to GitHub. The `tags:`
field is optional — when absent or empty, no tags are mirrored (the
pre-0.7.8 behavior).

Tag mirroring exists for repos that publish on tag push (npm `on: push: tags`,
Cargo, PyPI, etc.). Without it, `git push origin v1.0.0` lands on the stamp
server but the GitHub action never fires; the workaround was a parallel
`git push github v1.0.0` that bypasses the stamp gate.

### Server-side credentials

Set `GITHUB_BOT_TOKEN` as a Railway env var with a GitHub PAT (or GitHub App
installation token) that has `contents: write` on the target repo. The
post-receive hook reads it from `/etc/stamp/env` (written by the entrypoint,
chmod 600, git-owned) and constructs:

```
https://x-access-token:$GITHUB_BOT_TOKEN@github.com/<owner>/<repo>.git
```

to push the ref.

### GitHub-side protection (recommended)

On the GitHub mirror repo, restrict pushes to `main` so only your
designated mirror identity (the user/App that owns `GITHUB_BOT_TOKEN`)
can update the branch. This ensures the only way a commit lands on
GitHub's `main` is via a verified push through your stamp server.
Humans with repo access can still fork/PR via GitHub's standard flow,
but those PRs cannot merge — the ruleset blocks everyone except the
bypass actor.

GitHub is phasing out the legacy "Branch protection rules" UI in favor
of **Rulesets** (Settings → Rules → Rulesets). Many newer accounts only
see the Ruleset surface now.

See [`docs/github-ruleset-setup.md`](../docs/github-ruleset-setup.md)
for the full walkthrough (UI + CLI paths, the same-PAT-owner-bypass
footgun, and the machine-user pattern that fixes it). The repo also
ships [`docs/github-ruleset-template.json`](../docs/github-ruleset-template.json)
— a sanitized config you edit (set the bypass actor's numeric ID) and
import via `gh api -X POST /repos/<owner>/<repo>/rulesets --input ...`.

### Behaviors

- Mirror failures do **not** block the stamped push — the stamp main push
  already succeeded by the time post-receive runs. Mirror failures are
  logged to stderr (visible to the client via git's `remote:` prefix).
- A failed mirror leaves GitHub out-of-sync until the next successful push
  or a manual retry. Not data-loss, just staleness.
- First push to a fresh GitHub repo requires the GitHub repo to already
  exist (create it empty on github.com first).

## Adding more pushers

Anyone else who wants to push needs:

1. Their SSH public key added to `AUTHORIZED_KEYS` (so they can connect).
2. Their **stamp** public key added to `.stamp/trusted-keys/` **in the repo**
   (so their signed merges verify). They generate it with `stamp keys
   generate`, then you commit the `.pub` file to the repo.

## Onboarding a new machine (agent-driven walkthrough)

The recipe below is structured for an agent running on the new machine
to walk the operator through onboarding step-by-step — instruct, run,
verify, then move on. Each step has a check the agent can run to
confirm success before continuing to the next.

### What the agent needs upfront

- The stamp server's host and port.
- Credentials for the server's hosting environment, with permission to
  read and update `AUTHORIZED_KEYS` and trigger a service restart.
  Every platform exposes this differently — the recipe says *what* to
  do, not *how* on a specific platform.

### Step 1 — generate a stamp-specific SSH keypair

Don't reuse `~/.ssh/id_ed25519`. A separate keypair means revoking
server access later doesn't affect unrelated hosts.

```sh
ssh-keygen -t ed25519 -N "" -f ~/.ssh/stamp_server -C "stamp-$(hostname)"
```

**Verify:**

```sh
test -f ~/.ssh/stamp_server && test -f ~/.ssh/stamp_server.pub && echo OK
```

Expect `OK`.

### Step 2 — generate the operator's stamp signing keypair

The signing keypair is **separate** from the SSH keypair:

| Keypair         | Question it answers                              |
|-----------------|--------------------------------------------------|
| SSH             | "Can I connect to the server?"                   |
| Stamp signing   | "Are my reviews/merges trusted by a given repo?" |

```sh
stamp keys generate
```

**Verify:**

```sh
test -f ~/.stamp/keys/ed25519 && test -f ~/.stamp/keys/ed25519.pub && echo OK
```

Expect `OK`.

### Step 3 — tell the local stamp CLI where the server lives

```sh
mkdir -p ~/.stamp
cat > ~/.stamp/server.yml <<EOF
host: <stamp-server-host>
port: <stamp-server-port>
EOF
```

**Verify:**

```sh
cat ~/.stamp/server.yml
```

Expect to see the host and port the operator was given.

### Step 4 — pin the SSH key to the server host

So that plain `ssh <stamp-server-host>` and `git clone
ssh://<stamp-server-host>/...` use the right key on the right port
without further flags.

```sh
cat >> ~/.ssh/config <<EOF

Host <stamp-server-host>
  Port <stamp-server-port>
  User git
  IdentityFile ~/.ssh/stamp_server
  IdentitiesOnly yes
EOF
```

**Verify:**

```sh
ssh -G <stamp-server-host> | grep -E '^(identityfile|port|user) '
```

Expect to see `stamp_server` in the `identityfile` line, the right
`port`, and `user git`.

### Step 5 — append the new SSH pubkey to AUTHORIZED_KEYS and restart the server

This is the only step that touches the server's hosting environment.
Read the current `AUTHORIZED_KEYS` env var, append this machine's SSH
pubkey on its own line, write it back, and trigger a service restart
so `entrypoint.sh` re-writes `/home/git/.ssh/authorized_keys` inside
the container on next boot.

The pubkey to append:

```sh
cat ~/.ssh/stamp_server.pub
```

The env-var update and restart use the hosting platform's API or CLI —
the agent should already have the credentials it needs.

**Verify** (from the new machine, after the restart settles):

```sh
ssh <stamp-server-host> list-trash
```

Expect a trash listing (an empty `[]` is fine — the point is that auth
succeeded). A `Permission denied (publickey)` or hang means the env-var
update or restart didn't take; recheck both before continuing.

### Step 6 — request trust in each repo this operator will land merges in

For every stamp-gated repo where this operator needs to merge, their
signing pubkey must live in the repo's `.stamp/trusted-keys/`
directory. **Adding a trusted signer is itself a stamp-gated change** —
an existing trusted operator has to land it on a feature branch
through the standard `stamp review → merge → push` cycle.

This asymmetry is intentional: it means a compromised hosting account
can't silently add a rogue signer to every repo. The first trusted-key
for any new operator is always landed by an existing one.

The new operator hands over their pubkey:

```sh
cat ~/.stamp/keys/ed25519.pub
```

An existing operator commits it under
`.stamp/trusted-keys/<short-name>.pub` on a feature branch in each
target repo and runs the stamp gate.

**Verify** (after the trust-key change has landed in a target repo):

```sh
diff -q <repo>/.stamp/trusted-keys/<short-name>.pub ~/.stamp/keys/ed25519.pub
```

Expect silent output (files match). After this, the new operator can
run the full flow (`stamp init`, branch, review, merge, push) on their
own.

## Backup

The entire state is in the Railway volume at `/srv/git/`. Back it up by
copying that directory periodically; a freshly-provisioned container
pointed at the same volume will pick up exactly where it left off.

## Updating the hooks

When stamp-cli releases new hook code, redeploy the container — the builder
stage recompiles and the fresh hook bundle lands at `/etc/stamp/pre-receive.cjs`
and `/etc/stamp/post-receive.cjs`. On container restart, `entrypoint.sh`
automatically walks `/srv/git/*.git/hooks/` and overwrites each repo's
`pre-receive` + `post-receive` with the fresh bundle from `/etc/stamp/`. No
manual step required — Railway's auto-deploy on push triggers the restart,
and the refresh loop runs before sshd starts accepting connections.

**Break-glass manual refresh** (useful if you need to push a hook update
without restarting the container, or you're debugging):

The git account uses `git-shell` and does not accept interactive commands,
so the previous `ssh git@<host> '<pipeline>'` form no longer works. Use
your platform's web console / container exec instead — Railway's
in-dashboard shell, `fly ssh console`, `docker exec`, etc.:

```sh
# Inside the container, as root:
for r in /srv/git/*.git; do
  cp /etc/stamp/pre-receive.cjs  "$r/hooks/pre-receive"
  cp /etc/stamp/post-receive.cjs "$r/hooks/post-receive"
  chown root:root "$r/hooks/pre-receive" "$r/hooks/post-receive"
  chmod 0755 "$r/hooks/pre-receive" "$r/hooks/post-receive"
done
```

## SSH access model

The `git` account is configured with `git-shell` rather than `bash`.
Authenticated pushers can:

- `git push` / `git fetch` / `git clone` (via the built-in
  `git-receive-pack`, `git-upload-pack`, `git-upload-archive` commands)
- `ssh git@<host> new-stamp-repo <name> [...]`
- `ssh git@<host> delete-stamp-repo <name> [--purge]`
- `ssh git@<host> restore-stamp-repo <name> [--from <trash-entry>] [--as <new-name>]`
- `ssh git@<host> list-trash`

…but cannot get an interactive shell, run arbitrary commands, or read
the per-deployment env file (`/etc/stamp/env`, which holds the GitHub
mirror token and is owned `root:git` mode 0640). The wrapper scripts are
symlinked under `/home/git/git-shell-commands/` at image build time.

For container-level diagnostics — log inspection, manual hook refresh,
disk usage — use your platform's web console or `<platform> exec`.

## Container runtime — runs as root (accepted trade-off)

The stamp server container runs as root in-container. `server/Dockerfile`
deliberately does not include a `USER` directive. This is an accepted
trade-off, not an oversight.

### Why root is load-bearing

Two parts of startup require root and don't have a straightforward
in-image workaround under current orchestration:

1. **sshd binds privileged port 22.** Operators connect via `ssh
   git@<host>` on a Railway TCP proxy fronting container port 22. Binding
   any port below 1024 requires `CAP_NET_BIND_SERVICE`, which in practice
   means sshd starts as root.
2. **`entrypoint.sh` manages permissions on persistent state before any
   service starts.** Each boot it `chown`s `/srv/git/` (the volume comes
   up root-owned on platform mounts) to the git user, generates/pins SSH
   host keys to `root:root` mode `0600` in `/srv/git/.ssh-host-keys/`,
   writes `/etc/stamp/operator.pub` as `root:root` mode `0444`, writes
   `/etc/stamp/env` (which holds `GITHUB_BOT_TOKEN`) as `root:git` mode
   `0640`, and refreshes every per-repo hook to `root:root` mode `0755`.
   Several of these objects must remain unwritable by the git user
   (which runs the SSH session and the hook process), so whatever sets
   them up has to outrank that user.

Both apply on every boot — not one-time setup that could happen in a
privileged init followed by a `USER git` drop.

### What this means in practice

Authenticated SSH users are constrained to the `git` account with
`git-shell` (see "SSH access model" above) — they cannot get an
interactive shell, run arbitrary commands, or read `/etc/stamp/env`. The
hardening in place (sticky bit on `/srv/git`, root-owned per-repo hooks,
mode `0640 root:git` on the env file, root-owned `.ssh-host-keys/`) is
defense in depth against the **git user**, not against in-container
root. A future sshd RCE, a bug in the stamp pre-receive hook, or a
compromised Alpine package would run with full root in the container —
including read access to `GITHUB_BOT_TOKEN`, every bare repo, and the
persistent host keys.

This is the trade-off being accepted.

### Deferred alternative

If the trade-off is ever re-evaluated, the path forward is:

1. Run sshd on an unprivileged port inside the container (e.g. `2222`).
2. Have the platform's TCP proxy front the public port — Railway TCP
   proxy 22→2222, equivalent on Fly/Docker/etc.
3. After `entrypoint.sh` finishes its privileged setup (chowns, host-key
   generation, env-file writes, hook refresh), drop to the git user —
   either via `gosu` / `su-exec` at the end of the entrypoint, or by
   structuring the entrypoint as a privileged setup phase that re-execs
   sshd under a `USER git` directive.

This is more invasive than the current shape and not currently warranted
— it couples the public-port binding to a platform proxy hop and
requires operator host config to follow. Documented so a future operator
who decides the threat model has changed has a starting point.

### Provenance

This posture was reviewed in the May 2026 audit pass — finding **L4** in
`oaudit-may-2-2026-rerun-3.md`, against repo HEAD `8e77f2f`. (The audit
doc lives in the operator's local audit archive outside this repo, not
in the repo tree; commit `8e77f2f` is the audited HEAD on `main`.) The
auditor's pragmatic recommendation was option (a): accept the trade-off
and document it. This section is that documentation; the deferred
alternative above mirrors the auditor's option (b).
