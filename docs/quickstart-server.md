# Quickstart: from zero to a stamp-protected repo on a server

This walks through standing up a stamp-server, provisioning a repo on it, landing real reviewers, and (optionally) mirroring verified commits to GitHub. End-to-end, ~15 minutes.

This is the **server-gated** deployment shape — the only shape where the gate is actually enforced (the server's pre-receive hook rejects unstamped pushes). If you instead want to use stamp's reviewer/signing flow as a discipline aid against a GitHub repo *without* server-side enforcement (no rejection of direct `git push origin main`), see the [local-only path in the README](../README.md#local-only-path) — that's `stamp init --mode local-only`, not this walkthrough.

## Trust topology — read this first

stamp inverts the usual GitHub-as-source-of-truth model. The shape is:

```
   your laptop  ──push──▶  stamp server  ──mirror──▶  GitHub (read-only)
   (signs locally)         (verifies + accepts)       (deploy targets read here)
```

- The **stamp server** is origin. It runs the pre-receive hook that rejects any push that isn't a properly signed stamped merge. This is where enforcement lives.
- **GitHub** is downstream — a mirror that updates only after the server accepts a push. Branch protection on GitHub locks `main` to the bot identity that does the mirroring, so the only way commits land on GitHub's `main` is by going through the server.
- Your laptop holds the signing key. Every merge is Ed25519-signed locally before being pushed.

The mental shift: **you `git push` to the stamp server, not to GitHub.** GitHub becomes a public read-only view + integration target for Actions/Vercel/Netlify/etc.

You can skip GitHub entirely if you don't need it — the stamp server alone is a complete remote.

## Step 1 — Deploy the stamp server

The fastest path is Railway, but the image runs on any Docker host (Fly, a Linux VPS, your laptop). Detailed Railway walkthrough lives in [`server/README.md`](../server/README.md). The summary:

1. Push this repo (or your fork) to GitHub so Railway can build it.
2. Create a new Railway project pointed at the repo. Set:
   - **Build → Dockerfile Path:** `server/Dockerfile`
   - **Volume:** mount one at `/srv/git` (this persists your bare repos)
   - **Variables:**
     - `AUTHORIZED_KEYS` — your laptop's SSH pubkey (`cat ~/.ssh/id_ed25519.pub`); newline-delimited list if multiple operators
     - `OPERATOR_PUB_KEY` — your stamp signing key (`cat ~/.stamp/keys/ed25519.pub`); generate with `stamp keys generate` if you don't have one
     - `GITHUB_BOT_TOKEN` — *optional*, only if you want GitHub mirroring (PAT with `contents: write` on the mirror repo)
   - **Networking:** add a TCP proxy for container port 22; Railway gives you `<host>:<port>`.
3. Add a convenient SSH alias on your laptop:
   ```sh
   cat >> ~/.ssh/config <<EOF
   Host stamp
     HostName <railway-tcp-host>
     Port <railway-tcp-port>
     User git
     IdentityFile ~/.ssh/id_ed25519
   EOF
   ```

## Step 2 — Tell stamp-cli where your server is (one-time, per-operator)

```sh
stamp server config <your-stamp-server-ssh-host>:<your-stamp-server-ssh-port>
```

For Railway TCP proxies the host/port show up under Settings → Networking → TCP Proxy. The `git` user and `/srv/git` repo path are the defaults; only override with `--user <name>` / `--repo-root-prefix <path>` if you've changed them on the server image.

`stamp server config` writes `~/.stamp/server.yml` (mode 0o600). To inspect or remove it later:

```sh
stamp server config --show       # print the resolved config
stamp server config --unset      # delete ~/.stamp/server.yml
```

This file is per-operator config, not committed to any repo — it just tells your local stamp-cli which server commands like `stamp provision` should reach for.

## Step 3 — Provision and bootstrap a repo (one command)

```sh
stamp provision myproject --org <github-org-or-user>
```

This single command does everything: SSHes to your stamp server and creates the bare repo via `new-stamp-repo`, clones it locally, runs `stamp bootstrap` (which lands the three real reviewers via a signed merge), creates a private GitHub mirror repo, writes `.stamp/mirror.yml`, and applies the `stamp-mirror-only` Ruleset on the mirror so direct pushes from any other identity are rejected by GitHub.

End state: `main` requires `security`, `standards`, `product` reviewers. Origin is your stamp server. GitHub holds the mirror, locked down to the bypass actor. The clone is at `./myproject` and ready to work in.

```sh
stamp provision myproject --dry-run                   # preview without changes
stamp provision myproject --no-mirror                 # skip GitHub mirror entirely
stamp provision myproject --org acme --public         # public mirror instead of private
stamp provision myproject --server alt.host:2222      # one-off override of ~/.stamp/server.yml
stamp provision myproject --into /elsewhere/myproj    # clone somewhere other than ./myproject
```

### Manual fallback (rarely needed)

If `stamp provision` doesn't fit (custom server layout, unusual mirror config, debugging), the manual steps are:

```sh
ssh git@<stamp-host> -p <port> new-stamp-repo myproject
git clone ssh://git@<stamp-host>:<port>/srv/git/myproject.git
cd myproject
stamp bootstrap                          # land real reviewers via the placeholder swap
# (manually create the GitHub mirror, write .stamp/mirror.yml, apply ruleset)
```

`stamp bootstrap` accepts `--from /path/to/.stamp/` if you want to install a pre-prepared reviewer set instead of the three starters.

## Step 4 — Customize the reviewer prompts

The starter prompts in `.stamp/reviewers/*.md` are calibrated for generic TS/JS projects. **Edit them to match your stack and conventions** — this is the highest-value step in setting up stamp. See [`personas.md`](./personas.md) for guidance.

```sh
$EDITOR .stamp/reviewers/security.md
$EDITOR .stamp/reviewers/standards.md
$EDITOR .stamp/reviewers/product.md

# Iterate on a sample diff without recording to the DB:
stamp reviewers test security --diff main..some-branch
```

Once you're happy, commit and push the customizations through a normal stamp review/merge cycle.

## Step 5 (optional) — Mirror to GitHub

If you want a public GitHub mirror that deploy pipelines can integrate with:

1. **Create the mirror repo on github.com** (empty; the post-receive hook needs it to exist).
2. **Set `GITHUB_BOT_TOKEN`** as a Railway env var if you didn't in Step 1. The bot needs `contents: write` on the mirror repo.
3. **Commit `.stamp/mirror.yml`** in your repo:
   ```yaml
   github:
     repo: your-user/your-repo
     branches:        # literal names or `*` / `?` glob patterns
       - main
       - "release/*"
   ```
4. **Set up the GitHub-side ruleset** on the mirror's `main` so only your designated mirror identity can update the branch. Without this, anyone with repo write access can `git push origin main` and bypass the entire stamp gate. See [`github-ruleset-setup.md`](./github-ruleset-setup.md) for the full walkthrough — both UI and CLI paths, plus a [`github-ruleset-template.json`](./github-ruleset-template.json) you can `gh api`-import after editing in your bypass actor's numeric ID. (Note: GitHub is phasing out the legacy "Branch protection rules" UI in favor of "Rulesets"; many newer repos only see the Ruleset surface now.)

Push the mirror.yml change through the normal flow. From the next stamped merge onward, every accepted push is mirrored to GitHub automatically.

Mirror failures don't block the stamp push — main on the stamp server already advanced. See [`server/README.md`](../server/README.md#github-mirror-optional) for the full mirror docs.

## Step 6 (optional) — Add `required_checks`

Pre-merge mechanical checks live in `.stamp/config.yml`:

```yaml
branches:
  main:
    required: [security, standards, product]
    required_checks:
      - name: build
        run: npm run build
      - name: typecheck
        run: npx tsc --noEmit
```

These run on the post-merge tree before the merge is signed. Non-zero exit blocks the merge and rolls it back. Results are attested into the commit's signed payload; the server hook verifies that attestation matches the committed config.

> **Security note:** `required_checks[].run` executes as a shell command on the merger's machine. Anyone who can land a PR that touches `.stamp/config.yml` can introduce arbitrary code that runs on the next person to call `stamp merge`. The reviewer gate IS the mitigation — `.stamp/config.yml` changes go through the same reviewers as any other code change. See [`DESIGN.md`](../DESIGN.md#security-model) for the threat model.

## Adding more pushers

Anyone else who wants to push needs:

1. Their **SSH** pubkey added to the server's `AUTHORIZED_KEYS` (so they can connect).
2. Their **stamp signing** pubkey committed to `.stamp/trusted-keys/` in the repo (so their signed merges verify). They generate it with `stamp keys generate`, then you commit the `.pub` file via the normal stamped review/merge cycle.

## What's next

- [`personas.md`](./personas.md) — writing real reviewer prompts that earn their seat in the gate
- [`troubleshooting.md`](./troubleshooting.md) — common failures with concrete fixes
- [`../DESIGN.md`](../DESIGN.md) — the spec and security model
- [`../server/README.md`](../server/README.md) — server deploy details (Railway, mirroring, hook updates)
