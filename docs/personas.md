# Writing reviewer personas

stamp-cli ships no opinionated reviewers — the contract for a reviewer is tiny (prompt file + a final `VERDICT:` line), and each deployment supplies its own. This doc covers how to write ones that are actually useful.

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
