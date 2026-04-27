# Troubleshooting

Common failures with concrete fixes. Ordered roughly by how often they come up during dogfooding.

---

## `stamp merge` fails with "gate CLOSED"

```
error: gate CLOSED: missing approved verdicts for: standards.
```

**Cause:** One or more required reviewers hasn't approved for the current `(base_sha, head_sha)` pair. Verdicts are SHA-bound — if you've committed new changes since your last review, the old approvals are for a different diff and don't count.

**Fix:**
```sh
stamp review --diff main..my-feature   # re-run reviewers on current HEAD
stamp status --diff main..my-feature   # confirm gate is open
stamp merge my-feature --into main
```

If a reviewer returns `changes_requested`, read its prose (in the `stamp review` output) or via `stamp log --reviews --limit 1`, apply the fix, commit, and re-review. Each commit moves `head_sha`, so always re-review after every commit.

---

## `stamp merge` fails with "pre-merge checks failed"

```
running 1 required check against merged tree: build
  ✗ build              exit=1  1245ms
FAILED: build (npm run build)
──────────────────────────────────
error: pre-merge checks failed: build. Merge rolled back. Fix and re-run.
```

**Cause:** One of `.stamp/config.yml`'s `required_checks` for the target branch exited non-zero. The merge has been **rolled back** — your working tree is exactly as it was before `stamp merge`.

**Fix:** Run the failing command locally (it's printed in the failure output) to see the real error. Fix it on your feature branch. Commit. Re-review (head_sha changed). Re-merge.

```sh
npm run build           # reproduce locally
# ... fix the bug ...
git commit -am "fix build"
stamp review --diff main..my-feature
stamp merge my-feature --into main
```

---

## `stamp push` is rejected by the server

```
remote: stamp-verify: rejecting refs/heads/main
remote:   commit 8b4f3c12 has no Stamp-Payload / Stamp-Verified trailers. 
remote:   Every commit to 'main' must be a stamped merge.
 ! [remote rejected] main -> main (pre-receive hook declined)
```

**Possible causes + fixes:**

1. **You made a direct commit to main** (not via `stamp merge`). Every commit on a protected branch must be a signed merge.
   Fix: reset main to the last stamped commit, put your change on a feature branch, go through `stamp review → merge → push`.

   ```sh
   git log --oneline -5                  # find the last stamped merge
   git reset --hard <last-stamped-sha>
   git checkout -b fix-something
   # ...re-apply the change...
   ```

2. **`signer_key_id` not in `.stamp/trusted-keys/`**. Your local signing key's public half isn't committed to the repo. Solution:
   ```sh
   stamp keys list                       # shows your local fingerprint
   stamp keys trust ~/.stamp/keys/ed25519.pub    # copy your pub key into trusted-keys
   git add .stamp/trusted-keys && git commit -m "stamp: trust my machine's key"
   # now repeat the review → merge → push cycle so the trusted-keys commit
   # itself lands first
   ```

3. **The server-side hook is stale** — you redeployed stamp-cli to Railway but existing repos still have the old hook copy. Refresh:
   ```sh
   ssh <your-stamp-remote> 'for r in /srv/git/*.git; do
     cp /etc/stamp/pre-receive.cjs  "$r/hooks/pre-receive"
     cp /etc/stamp/post-receive.cjs "$r/hooks/post-receive"
     chmod +x "$r/hooks/pre-receive" "$r/hooks/post-receive"
   done'
   ```

4. **Non-fast-forward push** — someone else pushed to main in the meantime, or you rebased. Pull, re-review, re-merge.
   ```sh
   git fetch origin
   # at this point main and origin/main have diverged — resolve per your workflow
   ```

---

## Reviewer returns `denied` unexpectedly

The reviewer thinks the *approach* is wrong, not just the implementation details. Check:

1. Is the reviewer right? Sometimes the answer is yes and you should pick a different approach.
2. If not, the prompt is miscalibrated. `denied` should be rare — reserved for architectural mismatches and identity violations. If it's firing on things that should be `changes_requested`, the verdict-criteria section of the prompt needs tightening. See `docs/personas.md`.

Either way, the merge is blocked until this reviewer's latest verdict on this SHA pair is `approved`. Your options:

- Rework the change so the reviewer is happy → commit → re-review
- Edit the reviewer's prompt to fix calibration → re-review (`stamp reviewers test <name> --diff ...` to iterate without polluting the DB)
- Remove the reviewer from the branch's `required` list if it's fundamentally wrong for this project (rare)

---

## `stamp merge` fails with "required by rule but not defined"

```
error: reviewer "old-reviewer" is required by branch rule "main" but not
       defined in the merged .stamp/config.yml ... Merge rolled back.
```

**Cause:** You tried to remove a reviewer from `reviewers:` while it was still in `branches.<name>.required:`, in a single change. The branch rule is enforced against the *committed* config (the post-merge tree), and that config no longer defines the reviewer it requires — so the merge can't be attested.

**Why this is subtle:** the *gate* check (whose approvals are needed) uses the **pre-merge** required list, so the merge passes the gate. It's the post-merge attestation step that catches the inconsistency. The merge is rolled back, so your working tree is exactly as it was before `stamp merge`.

**Fix — split into two commits:**

```sh
# 1. Drop it from required: but keep it defined.
$EDITOR .stamp/config.yml      # remove `old-reviewer` from branches.main.required
                               # leave reviewers.old-reviewer in place
git commit -am "stamp: drop old-reviewer from required"
stamp review --diff main..HEAD
stamp merge HEAD --into main
stamp push main

# 2. Now that main no longer requires old-reviewer, remove it entirely.
$EDITOR .stamp/config.yml      # delete reviewers.old-reviewer
git rm .stamp/reviewers/old-reviewer.md
git commit -m "stamp: drop old-reviewer entirely"
stamp review --diff main..HEAD
stamp merge HEAD --into main
stamp push main
```

**For the placeholder→real swap specifically:** if you're trying to replace the `example` placeholder with real reviewers on a freshly-provisioned repo, **use `stamp bootstrap` instead** — it handles the chicken-and-egg automatically in one command (and keeps `example` defined-but-unrequired so the swap is re-runnable).

---

## `stamp init` says "already initialized"

Fine if you cloned a repo that was already stamped. `stamp init` is idempotent — in that case it just ensures your local keypair exists in `~/.stamp/keys/` and initializes `.git/stamp/state.db`. The output will say "synced to existing .stamp/ config" rather than "scaffolded fresh repo."

If you genuinely want to re-scaffold from scratch (lose existing `.stamp/` config + reviewer prompts), delete `.stamp/` manually and re-run `stamp init`.

---

## `stamp ui` crashes with "Raw mode is not supported"

You're running stamp ui under a non-interactive shell (pipe, non-TTY). The TUI needs a real terminal. Run it directly:

```sh
stamp ui
```

not:

```sh
echo q | stamp ui              # won't work
stamp ui | less                # won't work either
```

Modern versions of stamp-cli detect this before invoking ink and print a clear error + exit 1. If you see the "Raw mode is not supported" stacktrace instead, you're on an old build — `npm install -g stamp-cli` the latest.

---

## Mirror push to GitHub fails

Visible in the push output as:
```
remote: mirror: push to github.com/<you>/<repo> failed (exit 128)
remote: mirror: fatal: Authentication failed
remote: mirror: main push already accepted; mirror out-of-sync.
```

**Note:** the main push already succeeded — your stamp-protected remote advanced correctly. Only the GitHub mirror is behind.

**Likely causes:**

1. **`GITHUB_BOT_TOKEN` env var not set** on the server. Check:
   ```sh
   ssh <stamp-server> 'test -s /etc/stamp/env && grep -q GITHUB_BOT_TOKEN /etc/stamp/env && echo YES || echo NO'
   ```
   If `NO`, set it on Railway: `railway variables --set "GITHUB_BOT_TOKEN=<pat>"`. A redeploy happens automatically.

2. **PAT expired or revoked.** Regenerate at github.com/settings/tokens, update the Railway var.

3. **Branch protection rule** on the GitHub mirror doesn't allow the bot's identity. Check `Settings → Branches → main`'s "Restrict who can push" list.

4. **Target GitHub repo doesn't exist.** First push to a fresh mirror requires the GitHub repo to already exist. Create it empty and retry.

After fixing, manually sync:
```sh
git fetch origin
git push https://x-access-token:$GITHUB_BOT_TOKEN@github.com/<owner>/<repo>.git main
```

---

## "Reviewer not configured" from `stamp reviewers test`

```
error: reviewer "standards" is not configured. Run `stamp reviewers list`.
```

`stamp reviewers test` requires the reviewer to be registered in `.stamp/config.yml` with a `prompt:` pointing to an existing file. If you're writing a new reviewer:

```sh
stamp reviewers add standards
# ^ creates the prompt file AND registers in config
```

Just dropping a `.md` file in `.stamp/reviewers/` isn't enough — the config entry is what makes it visible to the tool.

---

## "No reviews for this commit" in `stamp log <sha>`

You're looking at a commit whose reviews happened on a **different machine** (fresh clone; teammate's laptop; CI). The reviewer verdicts on the attestation payload are there (they're part of the signed trailer), but the *prose* lives in `.git/stamp/state.db` per-machine — only on the machine where `stamp review` ran.

No real fix: the prose is gone as far as your local install is concerned. The verdicts (approved / requested / denied) and check results are still visible from the attestation alone.

Future improvement: push reviewer prose as git notes so it travels with the commit. Not yet implemented.

---

## Typecheck / build check passes locally but fails in merge

`stamp merge` runs checks on the **post-merge tree**, not your current branch's tree. If your feature branch passes `npm run build` but the merge fails, something in main has changed since you branched off and the combination fails.

Fix:
```sh
git checkout my-feature
git merge main                       # pull main into feature first
# ...resolve conflicts or fix combined-state errors...
git commit -am "merge main"
stamp review --diff main..my-feature
stamp merge my-feature --into main
```

---

## When all else fails

- `stamp log --limit 5` — see what recently landed (or didn't)
- `stamp verify <sha>` — re-run the full local verification on any commit; tells you exactly which verification step fails
- `git log --first-parent main` — raw git view of what's on main, for cross-reference
- Railway logs — if the failure is server-side, the hook's stderr is there: `railway logs -n 50 -d`
