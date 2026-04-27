# GitHub mirror branch protection (Rulesets)

If you're using stamp-cli with the [GitHub mirror](./quickstart-server.md#step-5-optional--mirror-to-github) — i.e. your stamp server is origin and a GitHub repo is the downstream public mirror — you want GitHub itself to refuse any push to `main` that didn't come through the stamp server. Without this, anyone with repo write access can `git push origin main` directly, bypassing the entire stamp gate.

GitHub's mechanism for this used to be **Branch Protection Rules** (`Settings → Branches → Add rule`). That UI is being phased out in favor of **Rulesets** (`Settings → Rules → Rulesets`), and many newer accounts only see the Rulesets surface now. This doc walks through the Ruleset version, since it's where everyone is converging.

## What you're protecting against

The threat model is **agents and humans with repo write access pushing directly to GitHub's `main` and bypassing the stamp gate**. The stamp server's pre-receive hook can only enforce verification on pushes it sees — pushes that go straight to GitHub never touch it. The Ruleset's job is to make GitHub *itself* reject any push to the protected branches that doesn't come from your designated mirror identity.

## Two configurations

The right setup depends on whether the identity that owns the mirror's `GITHUB_BOT_TOKEN` is the same as your personal GitHub user, or a separate account/App. **The identity choice matters more than the ruleset choice** — the ruleset can't tell apart a mirror push and a direct push if they authenticate as the same user.

| Config | Bypass actor | Footgun |
|---|---|---|
| **Solo, your personal PAT** | Your own user | You can still `git push origin main` from your laptop (same identity); discipline-only enforcement against your own slips. |
| **Machine user account** | The machine user only | Your personal account is genuinely blocked from direct push to `main`. Bypassing requires explicitly switching to the machine-user PAT. Recommended once a project has more than one human contributor — or any time you want a hard guardrail against your own slips. |
| **GitHub App** | The App's installation | Same end-state as machine user, plus the App identity is more clearly distinguishable in audit logs. Highest setup cost. |

## Apply via the GitHub UI

If you prefer clicking:

1. **`Settings → Rules → Rulesets → New ruleset → New branch ruleset`**
2. **Ruleset name:** `stamp-mirror-only`
3. **Enforcement status:** Active
4. **Target branches:** Add target → Include by pattern → `main` (add other mirrored branches the same way)
5. **Bypass list → Add bypass:** add your designated mirror identity (your user / the machine user / the App). `bypass_mode: always`.
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

## Apply via the CLI

This repo ships [`docs/github-ruleset-template.json`](./github-ruleset-template.json) — a sanitized copy of the same configuration. The only edit you must make is `bypass_actors[0].actor_id`, which is `0` in the template (an invalid placeholder) and **must be replaced** with the numeric ID of the actor you want to bypass.

### Step 1 — look up the actor ID

For a **user** (your account or a machine user):

```sh
gh api /users/<username> --jq .id
# → 12345678
```

For a **GitHub App**, you need the App's installation ID on this specific repo:

```sh
gh api /repos/<owner>/<repo>/installation --jq .id
# → 87654321
```

…and set `actor_type: "Integration"` instead of `"User"`.

### Step 2 — edit the template

Replace `actor_id` and (if needed) `actor_type` in `docs/github-ruleset-template.json`. For a quick in-place edit:

```sh
ACTOR_ID=$(gh api /users/<your-bypass-user> --jq .id)
sed -i.bak "s/\"actor_id\": 0/\"actor_id\": $ACTOR_ID/" docs/github-ruleset-template.json
rm docs/github-ruleset-template.json.bak
```

### Step 3 — apply to the repo

```sh
gh api -X POST /repos/<owner>/<repo>/rulesets --input docs/github-ruleset-template.json
```

Successful response is a JSON object with a fresh ruleset `id`. To verify:

```sh
gh api /repos/<owner>/<repo>/rulesets --jq '.[] | {id, name, enforcement}'
```

### Step 4 — verify it's working

From a machine that is NOT the bypass actor:

```sh
git push origin main
# → ! [remote rejected] main -> main (push declined due to repository rule violations)
```

From the stamp server's mirror push (same identity as the bypass actor) — should sail through normally.

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

## When the ruleset blocks your stamp push

If you see `! [remote rejected] main -> main (push declined due to repository rule violations)` from a stamp push (post-receive mirror or your local `stamp push main`), the bypass actor doesn't match the authenticating identity. Check:

1. **`GITHUB_BOT_TOKEN`** is the PAT issued by the user/App in your bypass list (not a different account that happens to have repo write).
2. The `actor_id` in the ruleset is the right numeric ID — typo'd IDs fail silently with this same error. Look it up again with `gh api /users/<name> --jq .id` and compare.
3. The `actor_type` matches: `"User"` for a personal/machine user PAT; `"Integration"` for a GitHub App installation token.

The fastest disambiguator is to push from the same machine the stamp server uses, with the same token, by hand:

```sh
git push https://x-access-token:$GITHUB_BOT_TOKEN@github.com/<owner>/<repo>.git main
```

If that fails, the ruleset is rejecting the identity. If it succeeds, the issue is on the stamp server's side (env var not set, etc.).
