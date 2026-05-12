# GitHub mirror branch protection (Rulesets)

If you're using stamp-cli with the [GitHub mirror](./quickstart-server.md#step-5-optional--mirror-to-github) — i.e. your stamp server is origin and a GitHub repo is the downstream public mirror — you want GitHub itself to refuse any push to `main` that didn't come through the stamp server. Without this, anyone with repo write access can `git push origin main` directly, bypassing the entire stamp gate.

GitHub's mechanism for this used to be **Branch Protection Rules** (`Settings → Branches → Add rule`). That UI is being phased out in favor of **Rulesets** (`Settings → Rules → Rulesets`), and many newer accounts only see the Rulesets surface now. This doc walks through the Ruleset version, since it's where everyone is converging.

## What you're protecting against

The threat model is **agents and humans with repo write access pushing directly to GitHub's `main` and bypassing the stamp gate**. The stamp server's pre-receive hook can only enforce verification on pushes it sees — pushes that go straight to GitHub never touch it. The Ruleset's job is to make GitHub *itself* reject any push to the protected branches that doesn't come from your designated mirror identity.

## The recommended bypass actor: a per-repo deploy key

stamp-cli's recommended setup uses a `DeployKey` bypass actor — a write-enabled SSH deploy key registered on the GitHub mirror, with the matching private half held only by the stamp server. The mirror's post-receive hook authenticates as that key when pushing to GitHub, and the Ruleset's bypass list whitelists exactly that key.

Why this shape over alternatives:

- **Survives locked-down work orgs.** Many work organizations forbid machine-user accounts and gate GitHub App installations behind admin approval. Deploy keys are *per-repo* resources and don't touch org-level third-party-application policy, so they keep working in environments where the other two routes are blocked.
- **Tight scope.** A deploy key bypasses *only* the repo it's registered on. Contrast `OrganizationAdmin`, which delegates bypass to anyone with the org-admin role across every protected repo in the org.
- **No PAT in process env.** The mirror push uses SSH auth; nothing carries a personal access token on the wire or in `/proc/<pid>/environ` for the duration of the push.

### Trust property worth understanding

GitHub's Ruleset evaluator treats `DeployKey` as a repo-scoped *role*, not a key-id-scoped reference: at the API level, you POST `actor_id: <numeric>` but it round-trips back as `actor_id: null`, and the semantics are "**any deploy key on this repo can bypass**." The defense is therefore "*only the stamp-mirror key should ever exist on a mirror repo*." If a CI deploy key gets added later for a different purpose, it ALSO becomes a bypass actor on the same ruleset — keep the mirror repo's deploy-keys list to one entry.

## Two preconditions before you start

1. **Your stamp server image must include the deploy-key features** (server-side lazy keypair generation + the sudo-elevated `stamp-ensure-repo-key` helper). Verify by running `ssh git@<your-stamp-server> stamp-server-pubkey <owner>/<repo>` against a real repo on the server — if it returns an `ssh-ed25519 …` line, you have it; if it returns "missing argument" or "command not found," redeploy the container against a recent build of this repo.
2. **Your GitHub org must allow deploy keys.** Some orgs disable them under `Settings → Code, planning, and automation → Repository policies → Deploy keys`. If you're an org admin you can flip the toggle yourself; if it's a managed work org you may need IT to approve. A 422 response with body `"Deploy keys are disabled for this repository"` from any of the steps below means the org-level policy is in the way.

## Apply via the stamp-cli CLI (recommended)

For most operators this is one command. The flow registers a per-repo deploy key on the GitHub mirror, applies the `stamp-mirror-only` Ruleset, and wires the deploy key into the bypass list.

### Greenfield — a new repo

`stamp provision <name> --org <github-org>` already does all of the above. The CLI:

1. Provisions a bare repo on the stamp server.
2. Creates the GitHub mirror repo and writes `.stamp/mirror.yml`.
3. Asks the stamp server to lazy-generate a per-repo SSH keypair (`stamp-server-pubkey <owner>/<repo>` triggers it).
4. Registers the public half as a deploy key titled `stamp-mirror` on the new GitHub repo.
5. Applies the `stamp-mirror-only` Ruleset with `DeployKey` (org repo) or `User` (personal repo) as the bypass actor.

No additional UI clicks. If you want to inspect the plan first, pass `--dry-run`.

### Brownfield — an existing server-gated repo

For a repo that's already server-gated but using an older bypass model (the `OrganizationAdmin` magic-constant approach, or a `User` bypass that no longer reflects the right identity), use `stamp provision --migrate-bypass`. Run it in the repo's checkout:

```sh
cd path/to/your/repo            # checkout has .stamp/mirror.yml + a github remote
stamp provision --migrate-bypass --dry-run     # see the plan
stamp provision --migrate-bypass               # Phase A → B: add DeployKey alongside existing actors
# ...land at least one stamp merge + push to verify the DeployKey transport works...
stamp provision --migrate-bypass --remove-orgadmin    # Phase B → C: strip OrganizationAdmin from the bypass list
```

The phased structure is deliberate. `--migrate-bypass` alone is purely additive (`DeployKey` joins the bypass list; nothing is removed) so a misconfiguration can be recovered by re-running with the old bypass still in place. `--remove-orgadmin` is the destructive step that should only run after you've confirmed the new transport actually works.

The migration tool handles:

- **Idempotent re-runs.** If `stamp-mirror` is already registered with the matching key body, re-running is a no-op.
- **Stale key replacement.** If `stamp-mirror` is registered but its public key doesn't match what the server currently generates (typical after a server-side restart regenerates the per-repo file — see the caveat below), the existing key is deleted and the new one re-registered.
- **Stray-actor preservation.** Bypass actors of other types (e.g. a leftover `User` entry from a prior migration) are preserved unless `--remove-orgadmin` explicitly targets `OrganizationAdmin`. We don't strip what the migration didn't introduce.
- **Non-canonical ruleset names.** If your repo's ruleset isn't named exactly `stamp-mirror-only` (e.g. an older repo with `Protect Main`), the migration registers the deploy key and warns that no canonical ruleset was found rather than guessing at the wrong target.

### Caveat — Railway-style container restarts can invalidate per-repo keys

The stamp server's per-repo keypairs live at `/srv/git/.ssh-client-keys/<owner>_<repo>_ed25519` and are generated **lazily** on first request via the sudo-elevated `stamp-ensure-repo-key` helper. If your hosting platform (e.g. Railway) restarts the container in a way that doesn't preserve the keys directory, the per-repo files are regenerated on the next `stamp-server-pubkey <repo>` call — producing a **new** keypair with the **same name**. The previously-registered public key on GitHub becomes stale, and the mirror push starts failing with "Permission denied to deploy-key."

The fix is to re-run `stamp provision --migrate-bypass` against each affected repo. The migration tool's "delete the mismatched key + re-register" path is the recovery flow. If you have many repos behind one stamp server it's worth wrapping this in a loop after each restart.

(The legacy shared `github_ed25519` key persists across restarts because the entrypoint script re-creates it if missing — but per-repo files have no equivalent boot-time regeneration. A future change may add a per-mirror.yml scan in the entrypoint to fix this; the current model relies on the migration tool's recovery path.)

### Key-file ownership and the lost "git-shell escape can't substitute" defense

The stamp-server's per-repo deploy-key files (and the legacy shared key) are owned `git:git` mode `0600`. This is the standard SSH posture — the file is readable only by the user running the SSH client, and OpenSSH's strict-perms check accepts it.

An earlier design used `root:git 0640` (root-owned, group-readable so the unprivileged git user could load the key without write access). That posture was meant to prevent a git-shell escape from substituting a key whose public half the attacker holds. It was abandoned because OpenSSH 9.x's client-side strict-perms check rejects any private key with group or other read bits — the legacy posture broke the SSH transport with "WARNING: UNPROTECTED PRIVATE KEY FILE!".

What this means for the threat model:

- A git-shell escape on the stamp server can now read AND overwrite the per-repo key file content — substituting a private key whose public half the attacker holds.
- But to actually exploit the substitution, the attacker has to ALSO register their public key on the GitHub mirror's deploy-keys list, which requires repo-admin auth they don't get from a server-side escape.
- The remaining exposure: if the attacker can also socially-engineer the operator into running `stamp provision --migrate-bypass` after substituting the local key, the migration's "register the server's current pubkey on GitHub" step would register the attacker's key as the new `stamp-mirror` deploy key. Bounded exploit chain (multi-step + requires operator action) rather than the single-step substitution the old posture defended against.

## Apply via the GitHub UI

If you prefer clicking, or are setting up a one-off without the stamp CLI:

1. **`Settings → Rules → Rulesets → New ruleset → New branch ruleset`**
2. **Ruleset name:** `stamp-mirror-only`
3. **Enforcement status:** Active
4. **Target branches:** Add target → Include by pattern → `main` (add other mirrored branches the same way)
5. **Bypass list → Add bypass:** add a Deploy key, OR your designated mirror identity (your user / machine user / GitHub App). `bypass_mode: always`. For deploy keys, you need to register the key first under `Settings → Deploy keys → Add deploy key` (paste the output of `ssh git@<stamp-server> stamp-server-pubkey <owner>/<repo>`, allow write access).
6. **Branch rules** to enable:
   - **Restrict deletions** — on
   - **Restrict updates** — **on** (the load-bearing one — blocks normal users from updating `main`)
   - **Block force pushes** — on (`non_fast_forward`)
   - **Restrict creations** — off (the mirror needs to be able to create branches if you ever expand the mirror set)
   - **Require linear history** — **off**. Stamp produces `--no-ff` two-parent merge commits; turning this on rejects every stamp merge before the bypass even applies. Leave it off.
   - **Require a pull request before merging** — **off**. Stamp pushes the merge directly via the mirror; turning PR-required on blocks the mirror.
   - **Require status checks** — off. Your gating happened server-side at the stamp server already; GitHub Actions are an additional layer if you want them, but not part of the stamp gate.
   - **Require signed commits** — off. Stamp's signatures live in the commit-message trailer (`Stamp-Payload` + `Stamp-Verified`), not as GPG/SSH-signed commits at the git level; GitHub doesn't recognize them as "signed."
7. **Save changes.**

## Apply via the `gh` CLI (manual)

This repo ships [`docs/github-ruleset-template.json`](./github-ruleset-template.json) — a sanitized copy of the same configuration. The template defaults to a `DeployKey` actor with `actor_id: 0` (an invalid placeholder); **replace the actor_id** with the numeric key id you got back from registering the deploy key.

```sh
# Step 1 — register the per-repo deploy key on the GitHub mirror.
KEY=$(ssh git@<stamp-server> stamp-server-pubkey <owner>/<repo>)
gh api -X POST /repos/<owner>/<repo>/keys \
  -f title=stamp-mirror \
  -f key="$KEY" \
  -F read_only=false
# Response includes the new key's numeric "id" — note it. The id is
# required by the POST schema, but GitHub's Ruleset evaluator treats
# DeployKey as a repo-scoped role and ignores actor_id; you still need
# to splice SOMETHING numeric in because the POST validator rejects 0.

# Step 2 — splice the id into the ruleset template.
KEY_ID=<from step 1>
sed -i.bak "s/\"actor_id\": 0/\"actor_id\": $KEY_ID/" docs/github-ruleset-template.json
rm docs/github-ruleset-template.json.bak

# Step 3 — apply the ruleset.
gh api -X POST /repos/<owner>/<repo>/rulesets --input docs/github-ruleset-template.json

# Step 4 — verify the bypass list (GitHub round-trips DeployKey actor_id to null, that's normal).
gh api /repos/<owner>/<repo>/rulesets --jq '.[] | select(.name=="stamp-mirror-only") | .bypass_actors'
```

For a **user** bypass (personal repo) or a **GitHub App** bypass, look up the id with `gh api /users/<name> --jq .id` or `gh api /repos/<owner>/<repo>/installation --jq .id` and set `actor_type` accordingly.

### Verify it's working

From a machine that is NOT the bypass actor:

```sh
git push origin main
# → ! [remote rejected] main -> main (push declined due to repository rule violations)
```

From the stamp server's mirror push (using the registered deploy key as the SSH identity) — should sail through normally.

## Bypass-actor choices: when to use which

GitHub's Ruleset bypass-actor evaluator behaves differently across repo ownership types. stamp-cli's tooling auto-picks the right shape, but if you're applying by hand:

- **Personal repos** (`owner.type === "User"`): `User` actor with the gh-authenticated user's id works.
- **Org-owned repos**: prefer `DeployKey` (the recommended setup). `OrganizationAdmin` (magic `actor_id: 1`) works as a fallback but delegates bypass to anyone with org-admin role. `User` is **silently ignored** by GitHub's evaluator on org repos — the API accepts it but `current_user_can_bypass` evaluates to `"never"` even for the named user.

## Why we omit `required_linear_history`

Your raw GitHub-exported ruleset will often include `{ "type": "required_linear_history" }`. **Remove it before importing for stamp.** Stamp's `stamp merge` produces `--no-ff` merge commits with two parents (the previous main + the feature branch's HEAD). `required_linear_history` rejects any commit whose parent isn't a fast-forward ancestor — i.e., it explicitly rejects merge commits. Bypass actors are exempt from this rule too, so a correctly-configured bypass list still works around it; but it's confusing to leave a rule in place that exists only to be bypassed. The template ships without it.

## Updating the ruleset later

To modify, find the ruleset ID (`gh api /repos/<owner>/<repo>/rulesets --jq '.[0].id'`) and PUT a new payload:

```sh
gh api -X PUT /repos/<owner>/<repo>/rulesets/<id> --input docs/github-ruleset-template.json
```

To delete entirely:

```sh
gh api -X DELETE /repos/<owner>/<repo>/rulesets/<id>
```

## Troubleshooting

### `! [remote rejected] main -> main (push declined due to repository rule violations)` from a stamp push

The authenticating identity doesn't match a bypass actor. Check, in order:

1. **The deploy key is registered.** `gh api /repos/<owner>/<repo>/keys --jq '.[] | select(.title=="stamp-mirror")'` should show one entry; if absent, the registration step was skipped.
2. **The registered key matches the server's current per-repo pubkey.** Compare `gh api /repos/<owner>/<repo>/keys/<id> --jq .key` against `ssh git@<stamp-server> stamp-server-pubkey <owner>/<repo>`. If they differ, your container restarted and regenerated the key — re-run `stamp provision --migrate-bypass` to reconcile.
3. **The ruleset's bypass list contains a `DeployKey` actor.** `gh api /repos/<owner>/<repo>/rulesets/<id> --jq .bypass_actors`. If not, the ruleset apply step was skipped or got rolled back.

### Mirror is out of sync after a transport failure

The stamp server's post-receive hook fires once per push and has no retry. If a push hits the stamp server but the mirror leg fails (most commonly: pre-migration, before the deploy key was registered), subsequent pushes don't retroactively re-mirror the stuck commits. Manually catch up — preconditions: you have SSH access to the stamp server (to fetch the gap) AND a bypass identity on the GitHub mirror's Ruleset (OrgAdmin if you haven't run `--remove-orgadmin` yet, or a temporary UI-side re-add of an actor you control):

```sh
mkdir /tmp/recover && cd /tmp/recover && git init -q --bare
git fetch ssh://git@<stamp-server>/srv/git/<repo>.git main:refs/heads/stamp-main
git push git@github.com:<owner>/<repo>.git stamp-main:refs/heads/main
```

### "Deploy keys are disabled for this repository"

The org-level "Allow deploy keys" toggle is off. Flip it under `Settings → Code, planning, and automation → Repository policies → Deploy keys` at the **org** level (not the repo level), or have an org admin do it. After flipping, re-run the registration step.

### `WARNING: UNPROTECTED PRIVATE KEY FILE! Permissions 0640 for '/srv/git/.ssh-client-keys/...' are too open`

A per-repo key file on the stamp server has too-permissive file permissions and OpenSSH's strict-perms check refused to load it. The server's post-receive output looks like:

```
remote: mirror: WARNING: UNPROTECTED PRIVATE KEY FILE!
remote: mirror: Permissions 0640 for '/srv/git/.ssh-client-keys/<owner>_<repo>_ed25519' are too open.
remote: mirror: This private key will be ignored.
remote: mirror: Load key "/srv/git/.ssh-client-keys/...": bad permissions
remote: mirror: git@github.com: Permission denied (publickey).
```

Cause: an earlier stamp-cli helper version generated per-repo key files at `0640 root:git`, which the modern entrypoint script auto-repairs on boot. If you see this, your server image predates the perms-repair entrypoint block. Two ways to fix:

1. **Redeploy the stamp server image** against a recent build of this repo (anything past the perms-repair commit). The entrypoint's boot-scan iterates `/srv/git/.ssh-client-keys/*_ed25519` and reapplies `chown git:git` + `chmod 0600` to each, fixing the existing broken files in place. Then any subsequent stamp push uses the per-repo SSH path successfully.
2. **One-shot manual fix** (if you can't redeploy right now): shell into the server (`railway shell` or equivalent) and run:
   ```sh
   chmod 0600 /srv/git/.ssh-client-keys/*_ed25519
   chown git:git /srv/git/.ssh-client-keys/*_ed25519
   ```
   This is what the entrypoint boot-scan does. Has the same effect, just without redeploying.
