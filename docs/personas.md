# Writing reviewer personas

`stamp init` scaffolds three starter reviewers — `security`, `standards`, `product` — with generic prompts calibrated for TypeScript/JavaScript projects. They work out of the box for first use, but they are **starting points, not finished opinions**: edit them to fit your codebase's stack, conventions, and domain.

The contract for a reviewer is tiny (prompt file + a final `VERDICT:` line). This doc covers both how to customize the shipped defaults and how to write new ones from scratch.

**If you prefer a zero-opinion scaffold**, run `stamp init --minimal` — it produces a single placeholder reviewer for you to replace, and a config requiring just that one.

## The contract

A reviewer is a markdown file at `.stamp/reviewers/<name>.md`, registered in `.stamp/config.yml`. When `stamp review` invokes it, the file content becomes the system prompt for the underlying Claude call, the diff becomes the user message, and the response must end with a line of the form:

```
VERDICT: approved
```

(or `changes_requested`, or `denied`). Exactly one verdict line, at the end. Nothing after it. `stamp review` parses it out, records the verdict in `.git/stamp/state.db`, and strips it from the printed prose.

That's the entire machine contract. Everything else is prompt engineering.

## What actually matters in the prompt

Prompts that perform well in practice share five pieces. Each of the three personas stamp-cli uses to gate its own development ([security](https://github.com/OpenThinkAi/stamp-cli/blob/main/.stamp/reviewers/security.md), [standards](https://github.com/OpenThinkAi/stamp-cli/blob/main/.stamp/reviewers/standards.md), [product](https://github.com/OpenThinkAi/stamp-cli/blob/main/.stamp/reviewers/product.md)) follows this structure.

### 1. Identity + project context (2–4 sentences)

Tell the reviewer **who it is** and **what the project is**. Enough context that the reviewer can reason about what "appropriate" means for this codebase.

Example (from our `product` reviewer for a browser typing test):

> You are the product/UX reviewer for **keeb cooker**, a single-page browser typing speed test with an unapologetically retro amber-phosphor CRT aesthetic. Your job is to make sure every change respects the user experience and the aesthetic coherence of this thing.

Versus the `product` reviewer for stamp-cli (a CLI tool):

> You are the product/UX reviewer for **stamp-cli**, a Node/TypeScript CLI tool used by AI coding agents and their human operators. (...) The "users" of this product are: 1. Agents (...) 2. Human operators (...).

Same "product" role; very different expectations. The project context is load-bearing.

### 2. Scope — what to check for (bulleted)

A focused list of the specific things this reviewer cares about. Avoid generalities like "code quality" — spell out patterns.

Good example (security reviewer for a static frontend):

- Committed secrets
- Dependency risk (postinstall scripts, typosquats)
- Dangerous JS primitives (`eval`, `innerHTML` with user input, `{@html}`)
- Third-party script loading
- Outbound network requests
- Exfiltration surfaces
- Subresource integrity

Bad example:

- "security stuff"

The LLM can't infer what you care about from vague framing. List the patterns.

### 3. What you do NOT check

Equally important. Without this, every reviewer drifts into every other reviewer's lane and you get three overlapping reports. Every persona in our example set declares its **non**-scope:

```
## What you do NOT check

- Code style, idiom, clean-code concerns → **standards** reviewer.
- UX, keyboard handling, visual design → **product** reviewer.
- Anything in `.stamp/` (reviewer prompts, stamp config) — tool meta.
```

When a reviewer spots something outside its lane, it can still mention it in one line ("worth flagging for X reviewer"), but it shouldn't base its verdict on it.

### 4. Verdict criteria

The three-verdict model (`approved` / `changes_requested` / `denied`) only earns its keep if the prompt calibrates the thresholds. Always include concrete criteria:

- **approved** — clean or with only trivial nits
- **changes_requested** — specific fixable issues (name the file:line and the fix)
- **denied** — architectural mismatch (wrong abstraction, wrong pattern, identity violation) that requires rethinking the approach, not tweaking lines

Without this, reviewers default to a soft `approved` on almost everything, or swing randomly between the three. A well-calibrated prompt includes concrete *examples* of when to pick each — see `standards.md` in the stamp-cli repo for the strongest example of this.

### 5. Tone

A one-paragraph tone guide. What we use:

> Direct, terse, opinionated. Cite specific lines. Don't hedge. It is fine to tell the author their abstraction is unjustified — that's the value this reviewer adds. Approvals can be one sentence.

Without a tone directive, reviewers tend toward hedging prose that's hard to scan and harder to act on.

## Customizing the shipped defaults

`stamp init` produces three reviewer files you're expected to customize:

- `.stamp/reviewers/security.md` — secrets, dependency risk, dangerous primitives, input validation, subprocess invocation, outbound network, secret leakage, trust model changes
- `.stamp/reviewers/standards.md` — build-first philosophy, language idiom hygiene, type safety, naming, dead code, boundary-only error handling
- `.stamp/reviewers/product.md` — interface consistency, breaking changes, error messages, accessibility, edge cases, microcopy — **this one is the most project-specific and needs the heaviest editing**

All three follow the 5-piece structural pattern below. Customize the *content* (scope items, concrete examples, tone) while keeping the *structure* (non-scope handoff, verdict criteria, output format) intact.

### Editing a shipped reviewer in place

```sh
stamp reviewers edit security
# ...edits to .stamp/reviewers/security.md in $EDITOR...
stamp reviewers test security --diff main..HEAD  # try the new version
# iterate until calibrated
```

No need to remove and re-add — the reviewer's config entry stays the same, only the prompt file changes.

### Adding a new reviewer beyond the three

Say you want an `accessibility` reviewer for a web project, or an `api-design` reviewer for a library:

```sh
stamp reviewers add accessibility       # scaffolds + opens in $EDITOR
# ...write the prompt following the skeleton at the bottom of this doc...
```

Then to make it gate merges, edit `.stamp/config.yml`:

```yaml
branches:
  main:
    required:
      - security
      - standards
      - product
      - accessibility   # add here
```

Reviewers live in `.stamp/reviewers/` but only appear in the gate if they're listed under `branches.<target>.required`.

### Removing a shipped reviewer that doesn't apply

Some projects don't need all three. A throwaway prototype probably doesn't need a `security` reviewer running on every merge; a backend service with no UI may want `product` scope covered differently.

```sh
# First edit .stamp/config.yml to remove the reviewer from any `required` lists.
# Then:
stamp reviewers remove security --delete-file
```

`stamp reviewers remove` refuses to run if the reviewer is still in a `required` list — it prevents you from orphaning a branch rule. Remove from config first, then from reviewers.

### Changing required reviewers per branch

`.stamp/config.yml` supports per-branch `required` lists. Example: main needs all three, develop needs only security:

```yaml
branches:
  main:
    required:
      - security
      - standards
      - product
  develop:
    required:
      - security
```

The gate runs against the rule for the branch you're merging into (`stamp merge <branch> --into <target>` reads `branches.<target>.required`). A reviewer can exist in `reviewers:` without being required by any branch — it still runs on `stamp review` but doesn't gate merges.

Branch keys also accept `*` / `?` glob patterns. Common shapes:

```yaml
branches:
  main:
    required: [security, standards, product]
  "release/*":            # everything under refs/heads/release/
    required: [security, product]
  "team-?/*":             # one-character team code, then anything
    required: [security]
```

Lookup is exact-key-first: a literal `release/v3.2:` entry overrides `release/*` for that one branch. Two glob keys that both match the same branch (e.g. `release/*` and `*/v3.2`) is a config error — add an exact-match key for the overlap.

## Calibration workflow

Writing a persona in the abstract doesn't work. Calibrate against real diffs:

```sh
# 1. Draft the prompt. The default `stamp reviewers add <name>` opens $EDITOR
#    for you immediately — use that for the normal case. The --no-edit flag
#    (shown here so the steps are explicit) is useful for scripted setup or
#    when you want to write the prompt in a separate editor session.
stamp reviewers add my-reviewer --no-edit
$EDITOR .stamp/reviewers/my-reviewer.md

# 2. Test against a known-good diff
stamp reviewers test my-reviewer --diff main..HEAD

# 3. Test against a known-problematic diff (real or synthetic)
git checkout -b test-violations
# ...introduce a deliberate issue...
stamp reviewers test my-reviewer --diff main..test-violations

# 4. Iterate on the prompt until both verdicts are calibrated as expected
```

`stamp reviewers test` is built for exactly this loop — it runs the reviewer without recording to the DB, so you can iterate without polluting history.

## Giving a reviewer tools

By default, reviewers see only the diff and their prompt. No file reads, no web calls, nothing. That's the safe baseline, but it rules out some genuinely useful patterns:

- The standards reviewer cross-checking the diff against a committed `STANDARDS.md`
- The product reviewer fetching the referenced Linear ticket to verify acceptance criteria
- The security reviewer looking up a CVE by ID when a dependency bump is proposed

Reviewer definitions in `.stamp/config.yml` can opt each reviewer in to specific tools:

```yaml
reviewers:
  standards:
    prompt: .stamp/reviewers/standards.md
    tools: [Read, Grep]          # Claude built-in tools

  product:
    prompt: .stamp/reviewers/product.md
    tools:
      - name: WebFetch
        allowed_hosts: [api.github.com]
        path_prefix: /repos/      # optional URL-shape pin; see below
    mcp_servers:
      linear:
        command: npx
        args: ["-y", "@tacticlabs/linear-mcp-server"]
        env:
          LINEAR_API_KEY: $LINEAR_API_KEY   # resolved from caller's env at invocation
        allowed_env: [LINEAR_API_KEY]       # required: which operator env-vars this server may read
```

`tools:` names Claude Agent SDK built-ins (`Read`, `Grep`, `WebFetch`, etc.). `mcp_servers:` declares stdio-transport MCP servers as a map of `name → { command, args?, env?, allowed_env? }`. Env values may reference `$VAR` or `${VAR}` — resolved from `process.env` at invocation, gated by an allowlist (see below); an unset or non-allowlisted reference fails the `stamp review` run with a clear error naming the missing var.

**MCP env interpolation is allowlist-gated.** A `$VAR` reference in `mcp_servers.<server>.env` only resolves if `VAR` appears in the union of two sources, otherwise the run fails fast:

- **`STAMP_REVIEWER_ENV_ALLOWLIST`** (operator env, comma-separated): the security trust anchor. Lives outside the committed config so a hostile in-tree edit cannot widen it. Set this to the tight set of names your operator environment is willing to expose (e.g. `STAMP_REVIEWER_ENV_ALLOWLIST=LINEAR_API_KEY,GITHUB_TOKEN`). Names that don't match the POSIX identifier shape (`[A-Za-z_][A-Za-z0-9_]*`) are silently dropped.
- **`mcp_servers.<server>.allowed_env: [NAMES]`** (per-config, optional): documentation that travels with the reviewer config. The field's bytes flow into the reviewer's `mcp_sha256` attestation, so a config flip from `[LINEAR_API_KEY]` to `[AWS_SECRET_ACCESS_KEY]` is visible as attestation drift to verifiers. Validated strictly at config-load time — entries must be POSIX identifier strings.

Default is **deny-all**: a config that uses `$VAR` interpolation while neither allowlist contains the name will fail at invocation. The fix is to either widen `STAMP_REVIEWER_ENV_ALLOWLIST` or add the name to the server's `allowed_env`.

**The contents of `process.env` at invocation time are the only un-fabricable input — both allowlists are advisory and visible in attestation.** A hostile in-tree edit can flip its own `allowed_env` (and the operator-env list, while harder to tamper with, is itself just a list of names that has to ultimately reference what the operator chose to export). The practical security floor is therefore: keep `process.env` on the machine that runs `stamp review` lean — export only the secrets reviewers genuinely need, and prefer scoped tokens over broad credentials. `STAMP_REVIEWER_ENV_ALLOWLIST` is the second line of defense (reduces blast radius if a hostile config flip widens `allowed_env`); per-server `allowed_env` is documentation that flows into `mcp_sha256` so a flip from `[LINEAR_API_KEY]` to `[AWS_SECRET_ACCESS_KEY]` is visible as attestation drift to any verifier. AGT-038 / audit L2.

**`allowed_hosts` is a domain-level allowlist, not a path-level one.** It constrains *which host* a reviewer's WebFetch can target, but by default does not constrain *which URL* on that host. A bare `allowed_hosts: [linear.app]` means the reviewer can fetch any path on `linear.app`. For personas that talk to a narrow API — `api.github.com/repos/...`, `api.linear.app/api/...`, etc. — set the optional `path_prefix:` on the same WebFetch entry to pin the URL shape:

```yaml
tools:
  - name: WebFetch
    allowed_hosts: [api.github.com]
    path_prefix: /repos/      # only /repos/* paths on api.github.com
```

Query strings are never inspected — `?state=open&per_page=5` and similar legitimate API parameters pass through. Avoid listing bare broad hosts like `linear.app` or `github.com` without a `path_prefix` unless the reviewer genuinely needs the full domain; otherwise an injected diff could coerce a reviewer with `Read` access to encode repo bytes into a path on the allowed host. AGT-036 / audit M4.

Tell the reviewer in its prompt what the tools are for. For example, in `standards.md`:

> Before reviewing the diff, read `docs/STANDARDS.md`. Evaluate the diff against those conventions; cite specific standards sections in any `changes_requested`.

And in `product.md`:

> If the commit message or diff mentions a ticket ID matching `[A-Z]+-[0-9]+`, use the `linear` MCP to fetch that ticket and evaluate whether the diff satisfies its acceptance criteria. If the ticket is missing or the scope doesn't match, flag it.

Security tradeoffs worth naming: granting tools expands what a malicious reviewer prompt can do. See DESIGN.md's security model for the full discussion — the short version is `Read`/`Grep`/`Glob` are sandboxed to `repoRoot` by an explicit allowlist enforced in the SDK's `hooks.PreToolUse` callback (paths that resolve outside the repo are denied, and a small denylist of reviewer-internal targets — the attestation DB and trusted-key pubkeys — is denied even inside the repo), `WebFetch` is host-allowlisted by the same hook against `allowed_hosts` from `.stamp/config.yml` (with optional `path_prefix:` to additionally pin the URL path on a per-host basis) and can otherwise exfiltrate diff contents if the prompt is hostile, and MCP servers run as subprocesses with whatever permissions their binaries ask for. Treat `tools:` and `mcp_servers:` additions in `.stamp/config.yml` as security-sensitive diffs; calibrate your security reviewer's prompt to flag them explicitly.

Verified-config enforcement (cryptographic proof that a reviewer ran with the tool config the org expected) is planned — see [`plans/verified-reviewer-configs.md`](./plans/verified-reviewer-configs.md). Today's model trusts the committed config.

## Pinning a reviewer to a canonical source

For teams that want consistent reviewer policy across repositories, publish your personas in a central git repo and `stamp reviewers fetch` them into each project. The command writes a lock file alongside the prompt; `stamp review` refuses to run if the committed config has drifted from the lock.

**Source repo layout** (the canonical side):

```
personas/
  standards/
    prompt.md           # required — the reviewer's system prompt
    config.yaml         # optional — tools + mcp_servers for this reviewer
  security/
    prompt.md
  product/
    prompt.md
    config.yaml
```

`config.yaml` (when present) mirrors the per-reviewer shape from `.stamp/config.yml`:

```yaml
tools:
  - Read
  - Grep
  - name: WebFetch
    allowed_hosts: [api.github.com]
    path_prefix: /repos/
mcp_servers:
  linear:
    command: npx
    args: ["-y", "@tacticlabs/linear-mcp-server"]
    env:
      LINEAR_API_KEY: $LINEAR_API_KEY
    allowed_env: [LINEAR_API_KEY]
```

Tag the source repo with versions (e.g. `v3.2`). Consumers pin to specific tags.

**Consuming side** — in the repo that wants to use a canonical reviewer:

```sh
# install + pin 'standards' from acme/stamp-personas at tag v3.2
stamp reviewers fetch standards --from acme/stamp-personas@v3.2
```

This writes:

- `.stamp/reviewers/standards.md` — the prompt bytes from the source
- `.stamp/reviewers/standards.lock.json` — pinned hashes of the fetched prompt + tools + mcp_servers

The command prints the YAML snippet you should paste into `.stamp/config.yml`'s `reviewers:` section. We deliberately don't auto-modify your config — your config is your declared intent, and we don't want a fetch to silently rewrite it.

**Enforcement.** Every subsequent `stamp review` hashes the committed prompt + declared tools/mcp against the lock file. If anything drifts, the review refuses to run:

```
error: reviewer 'standards' prompt hash mismatch
  expected: sha256:abc1234567890123...  (from .stamp/reviewers/standards.lock.json, source=acme/stamp-personas@v3.2)
  observed: sha256:def4567890123456...  (current config)
  fix: re-run 'stamp reviewers fetch standards --from acme/stamp-personas@v3.2' or update the lock file deliberately
```

Exit code **3** is reserved for lock-file drift — distinct from exit 1 ("review rejected") and exit 2 (commander usage errors). Agent loops can branch on it to decide whether to re-fetch and retry or halt and flag.

**Pre-flight check without invoking reviewers.** `stamp reviewers verify` runs the same drift check without calling the Claude API — useful for CI gates or pre-commit hooks. `stamp reviewers verify <name>` scopes to a single reviewer.

**Updating a pinned reviewer.** Re-run `stamp reviewers fetch <name> --from <source>@<new-ref>`. There's no separate `update` verb; `fetch` is idempotent and versioned.

**Removing the pin.** Delete `.stamp/reviewers/<name>.lock.json`. `stamp review` will then treat the reviewer as unpinned (current behavior for reviewers with no lock file).

**Anchoring trust at first fetch.** The first `stamp reviewers fetch` is trust-on-first-use — whatever bytes the network returns get pinned into the lock file, and a MITM at that moment poisons every subsequent verification. To anchor trust out-of-band, pass the expected SHA-256 from a published manifest:

```sh
# Publish your manifest somewhere with stronger trust than raw.githubusercontent.com
# (signed release notes, changelog entry on a HTTPS-pinned domain, OIDC-attested
# build artifact, etc.) listing the expected hashes per reviewer per tag, then:
stamp reviewers fetch standards \
  --from acme/stamp-personas@v3.2 \
  --expect-prompt-sha 4f1c...e9a2
```

If the served bytes hash to a different value, the fetch refuses and writes nothing — your tree is left in the same state as before the attempt. Sibling flags `--expect-tools-sha` and `--expect-mcp-sha` pin the canonicalized hashes of the `tools:` and `mcp_servers:` sections from `config.yaml` (only meaningful when the persona ships one). Each flag is independent — supply the one(s) you have a published value for. Omit all three to keep the existing TOFU behaviour. The flags are an interim defence-in-depth; full manifest signing is on the roadmap.

**Source formats supported today:**

- `<owner>/<repo>` — GitHub shorthand; resolves to `https://raw.githubusercontent.com/<owner>/<repo>/<ref>/personas/<reviewer>/...`
- Full `https://` URLs — appended as `<base>/<ref>/personas/<reviewer>/...`

Private repos, git+ssh URLs, and non-git sources are not yet supported. For private GitHub orgs, host the canonical personas in a public repo and rely on the attestation's signed hashes for audit.

Effective tests:
- **One clean diff** the reviewer should approve
- **Three deliberate violations** that the reviewer should catch (one per major concern on your scope list)
- **One violation from another reviewer's lane** — your reviewer should gracefully decline to own it

## Sizing the reviewer set

Most projects do well with **three personas**:

- `security` — all the things an attacker could exploit or compromise
- `standards` — code quality, idiom, over-engineering pushback, testing discipline
- `product` — user-facing impact, UX, aesthetic, breaking-change awareness

Fewer than three tends to let real categories slip through unnoticed. More than three tends to produce overlapping reports. Adjust the scope of the three instead.

Parallel execution means three reviewers isn't meaningfully slower than one — typically 10–15s per reviewer, all at once.

## Verdict semantics in practice

Our own calibration after dogfooding:

- **approved** is the default for clean diffs. Reviewers shouldn't invent concerns to fill space.
- **changes_requested** is the workhorse. Used for specific, nameable fixes — typically 1–4 items. Author reads, patches, re-reviews.
- **denied** is rare and earned. "The approach itself is wrong" or "this change is an identity violation" — not "this has a few bugs." When a reviewer uses `denied` it should be obvious why in the first paragraph of the prose.

If a reviewer uses `denied` more than once in every ~20 reviews, the prompt is too aggressive; tighten the examples. If it never uses `denied`, it's too permissive; add an explicit "use `denied` when …" clause.

## Per-reviewer model selection (operator knob)

Which Anthropic model each reviewer runs on is **operator infrastructure**, not committed review policy. It lives per-user in `~/.stamp/config.yml` (written by `stamp init` with Sonnet defaults across the three starter personas), separately from the per-repo `.stamp/config.yml` that pins the reviewer's prompt + tools.

Why per-user, not per-repo: cost/speed is a tradeoff each operator legitimately makes differently — one runs Opus on `security` for the lowest-frequency / highest-cost catches; another runs Sonnet across the board. Putting that choice in the per-repo config would force a merge-conflict over operator preference (and pull the model choice into the v3 attestation hash chain, where it doesn't belong). The reviewer prompt is the policy; the model is how a given operator chooses to execute it.

Tune with the CLI:

```sh
stamp config reviewers show
stamp config reviewers set security claude-opus-4-7
stamp config reviewers clear security        # remove one entry
stamp config reviewers clear --all           # delete the whole file
```

Reviewers without a pinned model fall back to the agent SDK's default. When two operators run `stamp review` on the same diff with different models pinned, each records their own verdict in their own per-machine `state.db` — same shape as today's reviewer-prompt cycle. Verdicts are not assumed model-portable.

## Cross-project variants

The `product` reviewer in particular benefits from project-specific variants. A browser app's product reviewer shouldn't check CLI flag naming; a CLI tool's shouldn't check aesthetic coherence. When you add stamp to a new project, fork the template rather than trying to make one product reviewer cover everything.

Security and standards tend to generalize better across Node/TypeScript projects (minor tweaks for domain specifics). Still worth reading every reviewer prompt cold before trusting it on a new project.

## Example structure (copyable skeleton)

```markdown
# <reviewer name> reviewer — <project>

You are the <role> reviewer for **<project>**, a <one-sentence project description>.

Your job: <one sentence stating what this reviewer is uniquely responsible for>.

## What to check for

1. **<concern>** — <specific guidance>. Example: <concrete pattern>.
2. **<concern>** — ...
<5–9 items>

## What you do NOT check

- <other reviewer's lane> → **<other reviewer>** reviewer.
- <out-of-scope surface> — not in this reviewer's remit.

## Verdict criteria

- **approved** — <specific conditions>.
- **changes_requested** — <specific conditions>. Example: "<concrete example of the format for a fix>".
- **denied** — <specific architectural-class violations>. Example: <concrete example>.

## Tone

<one paragraph: direct / terse / opinionated / cite lines / don't hedge>.

## Output format (required)

Prose review, then exactly one final line:

\`\`\`
VERDICT: approved
\`\`\`

(or `changes_requested` or `denied`). Nothing after it.
```

## When to rewrite a reviewer

A reviewer prompt is stale when:

- It approves diffs with obvious issues in its declared scope
- It denies or requests changes on diffs in another reviewer's lane
- Its verdict distribution drifts (use `stamp reviewers show <name>` to check counts)
- A bug makes it past the gate that the reviewer should have caught

The last one is the most important signal. When we dogfood-caught a Svelte 5 rune syntax bug that the generic `example` reviewer missed, the fix wasn't to add retry logic — it was to write a `standards` reviewer with Svelte 5 rune gotchas explicitly called out in its prompt. Reviewers are documentation of what you've learned to care about.
