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
  repo: mattpardini/keeb-cooker   # GitHub "owner/repo"
  branches:
    - main
```

Only branches listed here are mirrored. Other refs are pushed to your stamp
server but not to GitHub.

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

On the GitHub mirror repo, enable branch protection on `main`:

- Settings → Branches → Add rule: `main`
- "Restrict who can push to matching branches" → only the bot identity
  that owns the PAT

This ensures the only way a commit lands on GitHub's `main` is via a
verified push through your stamp server. Humans with repo access can still
fork/PR via GitHub's standard flow, but those PRs cannot merge (branch
protection blocks everyone except the bot).

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

## Backup

The entire state is in the Railway volume at `/srv/git/`. Back it up by
copying that directory periodically; a freshly-provisioned container
pointed at the same volume will pick up exactly where it left off.

## Updating the hooks

When stamp-cli releases new hooks, redeploy the container — the builder
stage recompiles, and the new hooks land at `/etc/stamp/pre-receive.cjs`
and `/etc/stamp/post-receive.cjs`. Existing bare repos under `/srv/git/`
still point at the old copies, so refresh them:

```sh
ssh git@stamp 'for r in /srv/git/*.git; do
  cp /etc/stamp/pre-receive.cjs  "$r/hooks/pre-receive"
  cp /etc/stamp/post-receive.cjs "$r/hooks/post-receive"
  chmod +x "$r/hooks/pre-receive" "$r/hooks/post-receive"
done'
```

A future stamp-cli release will automate this.
