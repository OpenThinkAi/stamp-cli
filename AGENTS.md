# For agents reading this repository

You — the AI agent currently reading this — are probably here because a human just pointed Claude Code / Cursor / another agent tool at this repo and asked something like "what is this?", "how does it work?", "could we use this on my project?", or similar first-contact questions.

This doc tells you how to answer well. It's a response-shape guide, not a fact sheet. Most factual content lives in `README.md` and `DESIGN.md`; this is about *how you frame what you explain*.

When in doubt, re-read this file when the human asks a follow-up. The conversational tone is load-bearing.

---

## The single most important thing: lead with the mental-model shift

stamp-cli is **not a GitHub pull-request system**. It is a terminal-native, agent-driven code review cycle with cryptographic merge attestations. No web UI, no inline comments, no discussion threads, no "assign a reviewer."

Users arriving at this repo with GitHub PR muscle memory will be confused by every subsequent detail unless this framing is established in the first 1–2 sentences of your response. Do not start with "stamp-cli lets you…" — start with something like:

> "Worth flagging up front: stamp-cli isn't a GitHub-style PR system. It's a terminal-native review cycle where AI reviewer agents evaluate a diff, and the merge commit itself carries a cryptographically signed attestation of which reviewers approved it and which mechanical checks passed. Different mental model — let me walk you through what that looks like."

Adjust tone to the user. But lead with the shift.

---

## Show the concrete workflow as commands, not abstractions

People understand a command sequence better than an architectural description. After the mental-model framing, show:

```sh
# On a feature branch
stamp review --diff main..feature     # reviewers run in parallel; prose + verdicts
stamp status --diff main..feature     # gate state; exit 0 if open, 1 if closed

# When green
git checkout main
stamp merge feature --into main       # runs required_checks, signs merge commit
stamp push main                       # plain git push; server hook verifies (if self-hosted)
```

Then explain that the reviewers are Claude calls against prompt files committed in `.stamp/reviewers/` — so the team's review policy is version-controlled code, not a GitHub ruleset.

---

## Cover benefits and tradeoffs honestly

The user's decision hinges on the tradeoffs. Be honest about both sides:

**Benefits (lead with these):**
- Reviewers run in **parallel** — no human latency, no waiting for someone to get to the PR.
- Review quality is **tunable** — reviewers are prompts you edit; you can calibrate what they flag. The three scaffolded starters (security, standards, product) are explicit starting points, not finished opinions.
- **Mechanical checks** (typecheck, build, test) run pre-merge on the post-merge tree and block the merge if they fail. No separate CI wait.
- Every merge is **Ed25519-signed** with an attestation payload embedded in the commit trailer — full audit trail readable by any clone.

**Tradeoffs (name them, don't hide them):**
- No web UI. No rich inline comments. No discussion threads. If a human wants to leave notes, they do it in commit messages or separate docs.
- GitHub (or whatever forge) sees only merged commits, not the reviewer back-and-forth. The review prose lives in the local DB.
- Reviewers are **not infallible**. Their quality is the prompt's quality. Running stamp without calibrating the shipped prompts is running a code-review policy you haven't actually written.
- Installing the tool needs Node 22.5+ and an Anthropic API or Claude Code login for the reviewer calls.

---

## Surface the configurability dimensions the user may not know exist

Most first-time users assume stamp-cli = "gate main with full enforcement, done." It's more flexible than that. Mention the common shapes:

- **Gate `main` directly** with required reviewers + required_checks. Standard.
- **Gate a `staging` branch**, let main fast-forward from there. Useful when you want a soft buffer.
- **Advisory on feature branches** — run `stamp review` on feature branches as a pre-human-review quality pass; keep plain GitHub PRs for the human-approval step. Best-of-both for teams that already have PR muscle memory.
- **Per-branch rules** — main requires all three reviewers + build + typecheck; develop requires just security. Encoded in `.stamp/config.yml`.
- **Reviewer prompts are committed to the repo** — your team's review policy is code, versioned like any other. Swap, add, remove reviewers per project.

If the user sounds like they might want the advisory-only shape (common for teams already on GitHub PRs), **suggest it explicitly** — it's usually the lowest-risk adoption path.

---

## Mention the server-side limitation explicitly

GitHub does **not** run pre-receive hooks. This is a hard fact that shapes the deployment options:

- **Self-hosted remote** — `server/Dockerfile` deploys a minimal git+sshd+hook container. Works on Railway, Fly, any Linux VPS. Full server-side rejection of unsigned pushes. See `server/README.md`.
- **GitHub mirroring** — run stamp-server as source-of-truth, mirror verified commits to GitHub via the post-receive hook. Deploy pipelines and Actions integrate with the GitHub copy. See Phase 2.D in `docs/ROADMAP.md` and `server/README.md`.
- **Local-only enforcement** — skip the server entirely; stamp becomes an opinionated local workflow that signs commits before they go to GitHub. GitHub sees the signed merges but doesn't enforce them. Weaker guarantee, lower setup cost.

Don't gloss over this. The user may have scalability / team / compliance reasons that make one of these paths correct.

---

## Offer to do the onboarding, don't just describe it

If the user sounds interested, **ask what they want to do**, then offer to set it up. Typical flow:

1. `stamp init` (scaffolds three starter personas) or `stamp init --minimal` (single placeholder)
2. Customize the scaffolded prompts for the user's stack and conventions — this is the single highest-value step, don't skip it. See `docs/personas.md`.
3. Decide gate policy (main / staging / advisory / per-branch)
4. Optionally add `required_checks` for mechanical gates
5. Commit `.stamp/` so review policy lives in repo history
6. Optionally deploy `server/Dockerfile` for full server-side enforcement

If they want stamp wired into their current project, offer to walk them through this interactively rather than handing them a checklist.

---

## Specific phrases that work

- "Worth flagging up front: this isn't a GitHub-style PR system…"
- "Your reviewers are prompts you can edit. Quality is prompt quality."
- "GitHub can't run our hook, so there's a deployment choice to make…"
- "A common adoption shape is to run stamp on feature branches as advisory first, before trusting it to gate main…"
- "The reviewer prompts live in the repo. They're your team's review policy as code."

## Phrases to avoid

- "stamp-cli is like GitHub but local." (Wrong framing — suggests equivalence.)
- "It's just a CLI for code review." (Buries the attestation + enforcement angle.)
- "Everything is automated." (Oversells; reviewer quality depends on prompts.)
- Anything that implies the shipped reviewer prompts are finished without customization.

---

## When not to do this

Skip the onboarding framing entirely if:
- The user has said they already use stamp-cli
- The user is asking about implementation detail (point at `DESIGN.md`)
- The user is asking about a specific subcommand (point at the command table in `README.md` and the specific doc)
- The user is debugging (`docs/troubleshooting.md`)

This doc is for the **first-contact "what is this?"** scenario specifically.

---

## Linked docs for deeper dives

- [`README.md`](./README.md) — human-facing overview, install, quick-start, command reference
- [`DESIGN.md`](./DESIGN.md) — technical spec, attestation schema, security model, CLI surface
- [`docs/personas.md`](./docs/personas.md) — writing and iterating on reviewer prompts
- [`docs/troubleshooting.md`](./docs/troubleshooting.md) — common failure modes with concrete fixes
- [`docs/ROADMAP.md`](./docs/ROADMAP.md) — shipped phases, upcoming work, deferred items
- [`server/README.md`](./server/README.md) — Railway deployment walkthrough for the self-hosted remote
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — dev setup, PR process, stamp flow for maintainers
