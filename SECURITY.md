# Security policy

## Supported versions

Only the latest published version of `@openthink/stamp` on npm receives
security fixes. Users are expected to upgrade promptly; semver caveats noted
in [`docs/ROADMAP.md`](./docs/ROADMAP.md) apply.

## Reporting a vulnerability

**Do not open a public GitHub issue for security reports.**

Use GitHub's private vulnerability reporting for this repository:
<https://github.com/OpenThinkAi/stamp-cli/security/advisories/new>

That routes the report directly to the maintainers without any public trace.
Include:

- A description of the issue and which component is affected (CLI, hook
  bundle, server image, etc.).
- A proof-of-concept or step-by-step reproduction if you have one.
- Your assessment of impact (what a malicious author-agent or pusher could
  achieve).
- Any suggested fix or mitigation.

### What to expect

- Acknowledgment within **3 business days** of the report landing.
- A triage response within **7 business days** including severity assessment
  and likely fix timeline.
- Coordinated disclosure: once a fix is published, we'll credit you in the
  release notes unless you prefer to remain anonymous.

### Scope

**In scope:**

- The stamp-cli CLI (signing, verification, attestation parsing, config
  loading, reviewer invocation).
- The hook bundle (`dist/hooks/pre-receive.cjs`, `dist/hooks/post-receive.cjs`).
- The reference server image (`server/Dockerfile`, `server/entrypoint.sh`,
  `server/setup-repo.sh`).
- Any documented trust boundary — pre-receive hook enforcement, attestation
  verification, key-trust rules.

**Out of scope:**

- Vulnerabilities in Anthropic's Claude models or the
  `@anthropic-ai/claude-agent-sdk` package itself — report those directly
  to Anthropic.
- Weaknesses that require an operator to voluntarily install a malicious
  reviewer prompt or commit secrets to a public repo.
- Issues in third-party deploy platforms (Railway, Fly, etc.) or a user's
  own git server.
- Reviewer prompts producing poor judgments — prompt quality is operator
  responsibility.

## Audit posture

stamp-cli runs the [`oaudit`](https://github.com/OpenThinkAi/open-audit)
suite (`trusted/security`, `trusted/supply-chain`, `trusted/infra`,
`trusted/llm-security`, `trusted/privacy`) as the canonical security review.

**Cadence.** The maintainer re-runs all five specs after every change that
touches the trust boundary — the pre-receive hook, the reviewer-tool gate
(`src/lib/reviewer.ts`), the attestation schema, the signing key path, the
server image, or the setup-repo flow. A clean run is also produced at the
start of each release cycle so the published version's audit posture is
known.

**LLM auditor variance.** `oaudit`'s specs run a Claude-driven analysis;
across multiple runs of the same spec on the same commit the auditor's
chosen findings vary at the margins. **High-severity items are stable
across runs; low-severity items are not.** A low not re-flagged in a later
run is treated as latent, not closed, until a commit specifically addresses
it. Closure-status corrections (when a prior audit doc inferred closure
from "audit no longer flags") are documented in subsequent audit docs.

**Where to find the current audit doc.** The canonical audit doc tracks
HEAD: (1) closed findings with the closing commit cited, (2) re-emerged
findings with the original audit they came from, and (3) latent findings
not yet addressed. It supersedes prior audit docs and is the artifact to
read when assessing whether this version is fit for adoption.

The doc itself is published separately from this repo (it cites file
paths and exploit chains that are useful to a deciding operator but
verbose for a SECURITY.md). For access, contact the maintainer via the
private vulnerability reporting channel above.

**Architecturally residual risk.** The `trusted/llm-security` spec's
canonical HIGH is "LLM verdict directly authorizes signed merges to
protected branches." This is a property of the architecture (LLM verdict
→ signed merge), not a discoverable bug, and persists across audits
regardless of code changes. Mitigations — random hex diff fence, structured
`submit_verdict` channel, last-line `VERDICT:` regex, MCP launcher
allowlist, WebFetch path-prefix pinning, and (since v1.2) on-by-default
operator confirmation before signing — are listed in the
[`DESIGN.md`](./DESIGN.md) security-model section. Operators running
unattended agent loops opt out via `STAMP_REQUIRE_HUMAN_MERGE=0` (per-shell)
or `branches.<name>.require_human_merge: false` (committed config); the
stance is stamp's, the posture is the operator's.

**Threat model.** A reader-focused enumeration of attackers, paths, and
defenses lives at [`docs/threat-model.md`](./docs/threat-model.md). It
names five attacker positions (external pusher, SSH-pusher with no
key, author-agent, author-agent with key compromise, operator-as-
attacker), walks each path, and ties defenses to file/line citations
where applicable. Useful as the reference for "does stamp's posture
match my threat expectations?" without reading the full DESIGN.md.

## Known trade-offs

Some behaviors are intentional trade-offs, not vulnerabilities:

- **`required_checks[].run` executes as shell commands on the merger's
  machine.** Mitigation: the reviewer gate on `.stamp/config.yml` changes.
  See [`DESIGN.md`](./DESIGN.md#security-model).
- **Local-only deployment mode provides no server-side enforcement.** By
  design; see the Deployment shapes section of
  [`README.md`](./README.md).
- **The signing key holder can produce valid signed merges for arbitrary
  content.** Non-repudiation, not authorization — inherent to local-first
  signing. Documented in the README security-model section.

## Operator-tunable safety bounds

The reviewer subprocess runs under bounds that can be set in three
places (narrowest-wins): per-reviewer fields in `.stamp/config.yml`
(committed, hashed into the attestation), operator env vars on the
calling shell (per-shell, not committed), or the built-in default.
Defaults are deliberately tight so a misbehaving reviewer prompt with
`WebFetch` + MCP can't iterate indefinitely against the operator's
Anthropic account. These bounds are security-relevant defenses, not
just performance knobs — raising them widens the resource budget a
malicious reviewer prompt can consume per invocation.

| Knob | Env var (default) | `.stamp/config.yml` field | Security role |
|---|---|---|---|
| Turn cap | `STAMP_REVIEWER_MAX_TURNS` (`8`) | `reviewers.<name>.max_turns` | Caps model/tool round-trips so a looping or prompt-injected reviewer gives up rather than racking up spend. Cluster-B mitigation in the May 2026 audit. |
| Wall-clock | `STAMP_REVIEWER_TIMEOUT_MS` (`300000`) | `reviewers.<name>.timeout_ms` | AbortController-driven guard against a stuck MCP subprocess holding the review open indefinitely. |
| Diff size | `STAMP_REVIEW_DIFF_CAP_BYTES` (`204800`) | — | Caps per-reviewer diff size (each required reviewer gets the full diff, so an oversized review is expensive at scale). |

The per-reviewer committed form is the right knob when one reviewer in
a repo needs durable headroom (e.g. a `product` reviewer that does
ticket reconciliation) and raising the global env would over-budget the
others. Because the field enters the reviewer config hash chain,
changes go through the reviewer gate like any other policy edit; a
feature branch cannot unilaterally widen its own review budget (config
is read from the merge-base tree).

On failure, a structured turn trace (tool-call sequence + input hashes,
no raw prose) is written to `<repoRoot>/.git/stamp/failed-runs/` — mode
`0600`, parent `0700`, never pushed. Operators can `cat` the file to
diagnose loop-vs-headroom before raising the budget. The README's
"Reviewer execution budgets" section and
[`docs/troubleshooting.md`](./docs/troubleshooting.md) cover the full
workflow.
