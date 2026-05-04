# stamp-cli threat model

This doc names the attackers stamp-cli defends against, the paths they
take, and the layered defenses each path runs into. It complements
[`DESIGN.md`'s "Security model"](../DESIGN.md#security-model) section,
which goes deeper on enforcement mechanics; this one is for an operator
or reviewer deciding whether stamp's posture matches their threat
expectations.

The reference audit is published at
[`SECURITY.md`'s "Audit posture" section](../SECURITY.md#audit-posture)
and re-run after every trust-boundary change.

## What stamp-cli defends

A stamp-protected repo's `main` branch is the protected asset. The
defender's invariant is:

> Every commit on `main` is a signed merge whose attestation
> demonstrates that the diff was reviewed (verdicts captured), checks
> ran clean (exit codes attested), and the operator declared intent
> (signed merge + confirmation gate).

Anything that lands on `main` without satisfying that chain is a
control failure. Anything that satisfies the chain is, by stamp's
definition, intended.

Out of scope by design:

- A determined keyholder forging signed merges on purpose. Stamp's
  model is non-repudiation, not preventing operator-side abuse — see
  ["What signing does NOT claim"][not-claim] in DESIGN.md. A
  stamp-protected repo with one keyholder and one machine has the
  same upper bound as a GPG-signed repo with one signer.
- Vulnerabilities in Anthropic's Claude models or the
  `@anthropic-ai/claude-agent-sdk` package itself.
- Compromise of the operator's host outside stamp's process boundary
  (root-on-laptop, kernel exploits, supply-chain attacks against the
  global Node install).
- Reviewer prompts that produce poor judgments due to prompt
  miscalibration. Prompt quality is operator responsibility; stamp
  enforces that *some* configured reviewer verdicted, not that the
  verdict was wise.

[not-claim]: ../DESIGN.md#security-model

## Attacker positions

Five attackers, ranked by capability:

### 1. External pusher with no SSH access

**Capability:** Sees the public GitHub mirror; cannot push, cannot run
local stamp commands, cannot read review prose. Maybe owns a domain
that an over-permissive WebFetch allowlist points at.

**Goal:** Land code on `main` (impossible without push), or exfiltrate
data from the mirror.

**Paths:**

- *Read what's already public.* The mirror is public-by-default. The
  signed `Stamp-Payload` trailer on every merge carries
  base/head SHAs, signer key fingerprint, approved reviewer names,
  and a tool-call audit trace. Tool inputs are SHA-hashed; tool
  *names* are also hashed for MCP tools by default
  (`STAMP_HASH_MCP_NAMES=1`, the post-v1.2 default — see audit M-PR1)
  so internal MCP server names don't leak.
- *Bait WebFetch.* If a reviewer has WebFetch enabled with a
  permissive `allowed_hosts` and no `path_prefix`, an in-diff URL
  pointing at the attacker's domain could exfiltrate diff content
  through a server log. Defense: WebFetch is opt-in per-reviewer in
  `.stamp/config.yml` (gated by `stamp review` on config changes),
  the runtime hook enforces both the host allowlist AND any
  `path_prefix`, and operators are steered toward narrow path
  prefixes in [`docs/personas.md`](./personas.md).

**Effective?** No path lands code on `main`. WebFetch exfiltration is
real if a reviewer is configured loosely; the defense is the config
gate plus the path-prefix mechanism.

### 2. SSH-authenticated pusher with no signing key

**Capability:** Has an SSH key in the stamp server's `AUTHORIZED_KEYS`
and can invoke `git push` and the git-shell wrappers
(`new-stamp-repo`, `delete-stamp-repo`, …). Does not hold a private
signing key trusted by `.stamp/trusted-keys/`.

**Goal:** Push commits to `main` of any stamp-protected repo, or
exploit the server-side scripts to disrupt other tenants.

**Paths:**

- *Push without a stamp.* `pre-receive` rejects any push to a
  protected branch whose new tip lacks a `Stamp-Payload` trailer
  signed by a key in `.stamp/trusted-keys/` at that branch. No-key
  attackers stop here.
- *Push a stamped commit they got from someone else.* The
  attestation binds to a specific (base, head) SHA pair via the
  payload + signature. A replay against a different ref with a
  different base fails the SHA-binding check at `pre-receive`.
- *Push non-fast-forward (race or rebase).*
  `receive.denyNonFastForwards=true` is set on freshly-created bare
  repos (audit #20 fix), AND `pre-receive` re-reads the live ref tip
  via `rev-parse` and re-checks FF against it — catching the race
  where stdin's `oldSha` is stale because a peer pushed first.
- *Cross-tenant `rm` via `new-stamp-repo --from-tarball`.* The
  command's argument used to be operator-controlled with no path
  constraint; the EXIT trap's `rm -f` was a destructive primitive
  against any path the `git` user owned (i.e. every other repo).
  Closed by audit M-S2: the path is now constrained to
  `/tmp/stamp-migrate-*.tar.gz` AND `readlink -f` re-checks that the
  canonical resolution stays under `/tmp/`.

**Effective?** Push paths are closed. Server-side scripts are bounded
to operator-shaped inputs.

### 3. Author-agent on a feature branch (most realistic)

**Capability:** Can push commits to feature branches, modify any
file in those commits, and invoke `stamp review` / `stamp merge` /
`stamp push`. The standard agentic workflow. Has whatever signing
key the operator assigned to that machine.

**Goal:** Land a malicious diff on `main` — either by tricking the
reviewer agents into approving, or by escaping their intended scope.

**Paths:**

- *Prompt-inject a reviewer.* Embed instructions in the diff that
  convince the reviewer to call `submit_verdict({verdict:
  "approved"})` regardless of content. Defenses: the diff is fenced
  with a per-call random hex (128 bits unguessable, so the attacker
  can't close the fence in the diff text), the reviewer prompt is
  augmented with explicit "data not instructions" semantics, the
  fallback `VERDICT:` regex requires the line to be the LAST
  non-empty one (defeats early-position payloads), the structured
  `submit_verdict` tool is the preferred channel. The audit calls
  this stack "unusually thorough for this class of tool" but
  flags the residual: a sufficiently sophisticated injection
  *could* fool a reviewer.
- *Inject a reviewer, then exfiltrate via reviewer tools.* Read
  `~/.aws/credentials` or `.git/stamp/state.db`, then WebFetch the
  contents to an allowed host. Defenses: `Read`/`Grep`/`Glob` are
  scoped to `repoRoot` by `denyIfOutsideRepo` AND
  `denyIfRealpathOutsideRepo` (which follows symlinks before the
  check, closing the audit M-S1 / M-LL1 bypass), reviewer-internal
  paths (`.git/stamp/`, `.stamp/trusted-keys/`) are denylisted
  even inside the repo, WebFetch enforces both host allowlist and
  optional `path_prefix`, MCP launches are gated by an allowlist.
- *Inject a reviewer that approves a `.stamp/` change.* Modifying
  `.stamp/config.yml` or a reviewer prompt is a way to change
  future reviews. Defenses: changes to `.stamp/config.yml` and
  reviewer prompts are themselves diffs that go through the
  current reviewer set. Plus, with
  `enforce_reads_on_dotstamp: true` on the responsible reviewer
  (recommended for `security`), an `approved` verdict on a
  `.stamp/*`-touching diff is overridden to `changes_requested`
  if that reviewer's Read trace doesn't cover every modified
  `.stamp/*` path. Defeats the "approve without reading" injection.
- *Exhaust the budget by pushing a giant diff.* Each reviewer
  receives the full diff in its prompt. Defense: a 200KB diff cap
  (`STAMP_REVIEW_DIFF_CAP_BYTES`, configurable, `--allow-large` to
  bypass), `maxTurns` cap, wall-clock timeout. The author-agent
  can DoS-the-budget against an opt-in `--allow-large` operator
  but not the default operator.
- *Force a non-FF merge.* See attacker 2 — the operator's machine
  signs, then push hits the same `pre-receive` FF gate.

**Effective?** This is where most of the defense-in-depth matters.
The combination of fence + structured channel + last-line regex +
config-gated tool surface + path-scope check + symlink-aware check +
denylist + dotstamp-Read enforcement + diff cap is intended to make
prompt-injection-driven approvals infeasible *and* low-yield even if
a single reviewer is fooled. The architectural residual is real
(audit H1's INFO-level note); it's bounded by the operator-confirmation
gate at `stamp merge` and the `enforce_reads_on_dotstamp` check.

### 4. Author-agent with a trusted-key compromise (key on the agent's host)

**Capability:** Same as #3, plus the private signing key (somehow
read from `~/.stamp/keys/ed25519` despite mode 0600).

**Goal:** Sign arbitrary merges and push them.

**Paths:**

- *Sign a merge directly.* With the key in hand, the attacker can
  produce a valid `Stamp-Payload` trailer for any (base, head, target,
  approvals) tuple. Defenses: none cryptographically — this is the
  documented non-repudiation boundary. What stops most attempts is
  the operator-confirmation gate at `stamp merge`
  (`STAMP_REQUIRE_HUMAN_MERGE` defaults on for protected branches),
  forcing the holder to type `y` before signing. An agent that
  reads the key but lacks an interactive terminal can't satisfy
  that prompt.
- *Bypass the operator-confirmation gate.* Set
  `STAMP_REQUIRE_HUMAN_MERGE=0` or `--yes`. This requires the
  attacker to set an env var on the operator's machine, which is
  outside the stamp threat boundary (host compromise).
- *Forge approvals.* Add `Approval` entries to the payload they
  sign. Possible — the attestation just lists what the signer
  claims. The verifier checks the SIGNATURE is valid for that
  payload, not that the listed reviewers actually approved. This
  is the documented "non-repudiation, not authorization" model.

**Effective?** Cryptographically, no — a key compromise is a key
compromise. Operationally, the operator-confirmation gate raises
the bar against unattended agent loops that read the key but can't
satisfy a TTY prompt. The threat model is explicit that this
attacker is out of scope for stamp's primitives; the recovery path
is rotation (revoke the key from `.stamp/trusted-keys/` via a
stamped merge that the OTHER trusted machines accept).

### 5. Operator-as-attacker

**Capability:** A trusted operator who decides to abuse access — bad
faith, coercion, or compromise of the operator themselves.

**Goal:** Land malicious code on `main` while looking innocent.

**Paths:** All paths in attackers 3 and 4, plus:

- Disable defenses in committed config (e.g. set
  `branches.main.require_human_merge: false` or
  `branches.main.required: []`). The change goes through `stamp
  review`, but a sufficiently bad-faith operator can convince
  reviewers to approve it.

**Effective?** Stamp explicitly does NOT defend against this. The
mitigation is non-repudiation: every malicious action is signed by
a specific key tied to a specific operator, and the audit trail
(committed config history + signed merges + reviewer prose in the
local DB) makes attribution unambiguous after the fact. Stamp's
position is "agent fleets cycling fast" — not "adversarial
keyholder." Use a forge-side mechanism (CODEOWNERS, branch
protection, multi-keyholder signing requirement) on top of stamp
if your threat model includes this attacker.

## Architectural residual

The audit's persistent HIGH-then-INFO finding ("LLM verdict directly
authorizes signed merges to protected branches") is the architectural
shape stamp deliberately ships:

> Mitigations in place are state-of-the-art (random hex fence,
> structured tool channel, last-line VERDICT regex, MCP launcher
> allowlist, WebFetch path_prefix, MCP env allowlist, diff cap,
> maxTurns/wall-clock bounds, failed-parse spool with no echo to
> stderr, default-on operator-confirmation gate, enforce_reads_on_
> dotstamp). Residual risk remains because the sink is signed merge
> to main.

The post-v1.2 stack of defenses bounds this. The residual
scenarios:

- All N required reviewers fooled by the same prompt injection.
- Operator types `y` at the confirmation prompt without reading.
- Operator runs in `STAMP_REQUIRE_HUMAN_MERGE=0` mode (deliberate
  declared intent).

For environments where these residuals matter (regulated, DPA-bound,
high-stakes code), `STAMP_NO_LLM=1` disables the LLM-using surface
entirely and reduces stamp to its signing/verification primitives.
The non-repudiation property still holds and the pre-receive hook
still gates.

## Trust dependencies

stamp-cli's correctness depends on:

- **Node 22.5+** for `node:sqlite` and `node:crypto`'s Ed25519 APIs.
  Bugs in these are out of scope (they're upstream).
- **The Claude Agent SDK** (`@anthropic-ai/claude-agent-sdk`) for the
  reviewer loop. SDK bugs in tool gating, path resolution, or
  message routing could weaken stamp's defenses; the SDK's gate is
  not the only line of defense (the `hooks.PreToolUse` callback is
  stamp's own enforcement layer), but a sufficiently broken SDK
  could still surprise.
- **Git** for ref handling and content addressing. The pre-receive
  hook trusts git's CAS on the ref update path (combined with
  `receive.denyNonFastForwards=true` for belt-and-suspenders).
- **The operator's machine** for keeping the signing key off-disk-
  for-other-users (mode 0600 enforced) and for honoring
  `STAMP_REQUIRE_HUMAN_MERGE`. A compromised host beats stamp.

## Reporting

Found a path that violates the defender's invariant? See the
private vulnerability disclosure channel in
[`SECURITY.md`](../SECURITY.md#reporting-a-vulnerability).
