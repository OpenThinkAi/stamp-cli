# Plan — server-attested reviews

Status: in progress · Owner: maintainer · Target: stamp 2.x

> **Implementation status (as of `main`).** Several spec and infrastructure
> tickets have already landed on `main` and are visible in the in-repo code
> rather than this plan:
>
> - **AGT-325** — `src/lib/attestationV4.ts` (v4 schema types + canonical
>   serializer + tests).
> - **AGT-326** — `src/lib/trustedKeysManifest.ts` (manifest parser, JSON-
>   canonical serializer, `snapshotSha256`, `resolveCapability`).
> - **AGT-327** — `src/lib/reviewSigningKey.ts` +
>   `src/server/bootstrap-review-key.ts` + `server/stamp-server-pubkey
>   --review-signing` (server boots a review-signing keypair).
> - **AGT-329** — `src/server/promptFetch.ts` (canonical reviewer-prompt
>   fetch from the local bare repo, with multi-tenant resolver injection).
> - **AGT-333** — `src/lib/db.ts` migration adding
>   `server_approval_json`, `server_signature_b64`, `server_key_id`, and
>   `schema_version` columns to `reviews`; `stamp log` shows a SIGNED-BY
>   marker.
> - **AGT-339** — `stamp review --plan` emission via `src/commands/review.ts`
>   + `src/lib/reviewPlan.ts`.
> - **AGT-340** — Claude Code skill for local-only reviewer dispatch
>   (`skills/stamp-review.md`, `docs/local-only-mode.md`).
> - **AGT-350** — `src/hooks/pre-receive.ts` refactored into eight named
>   phase functions to make the new v4 verification phases land cleanly.
>
> Remaining work is tracked in the `stamp-server-attested-reviews` vault
> project. Names below (e.g. "AGT-330 reviewer is from-scratch raw
> `@anthropic-ai/sdk`") refer to that ticket set.

## Motivation

Today's stamp attestation proves: *"a keyholder signed off that reviewer X
returned verdict V on commit Y, against a prompt whose hash matches the
committed `.stamp/reviewers/X.md` file at the merge commit."*

It does **not** prove:

- The LLM actually received that prompt as input
- The LLM actually produced that verdict in response

These properties cannot be cryptographically established by any code running
on the operator's machine. The operator constructs what gets sent to the
LLM and constructs what gets recorded as the response. Any local signature
attests to what the operator *claims* happened, not what happened. This gap
is structural — well-documented in `verified-reviewer-configs.md` and
`DESIGN.md`'s security section ("same failure modes as a GPG-signed git
repo with one signer") — but the practical implication is significant: an
operator who wants to forge an approval can do so by passing a permissive
prompt to the LLM while embedding the canonical prompt's hash in the
attestation. The verifier sees a perfectly consistent claim and a real LLM
call took place; only the relationship between them is a lie.

This design closes that gap by moving the LLM call to stamp-server with its
own signing key. The operator cannot forge the server's signature, and the
server (not the operator) controls which prompt the LLM receives.

## Design constraints

**Preserve the local agent iteration loop.** The fast cycle — agent edits,
runs `stamp review`, gets verdicts in seconds, iterates — is stamp's core
value. Anything that breaks it (e.g. PR-based asynchronous reviews) is out
of scope. The server proxies the LLM call; the round-trip latency is
dominated by LLM inference, not orchestration, so a server in the loop is
imperceptible vs. today's direct SDK call.

**Server-mandatory in the trust model.** There is no version of "local-only
attested reviews." Local-only mode exists separately (see below) as an
iteration aid with no trust property. The trust property requires the
server, full stop.

**Reviews live inside stamp-server, not a separate component.** Stamp-server
already has SSH auth, `users.db` role system, per-repo bare git access,
post-receive hooks, signing-key handling infrastructure. Reviews are a
capability stamp-server gains, not a parallel service to deploy alongside
it. One Docker image, one process, one deployment.

**Phase 1 server is minimal.** The reviewer is given only the diff. No
file-access tools, no MCP, no tool-use loop. The server is barely more
than a signed LLM proxy. This radically shrinks the implementation, the
attack surface, and the per-request operational surface (no temp
workspaces, no subprocess management). Richer-context reviewers can be
re-introduced in a later version if real demand materializes; explicitly
deferred from Phase 1.

**Portable.** The Phase 1 deployment artifact is the existing stamp-server
Docker image (extended) plus instructions for running as a bare process.
Runs identically on Railway, Fly.io, K8s, AWS ECS, bare VPS, and operator
laptops for testing. 12-factor: env vars for configuration, single state
mount, external TLS termination, stdout logging. The review-capability
code paths must NOT introduce platform-specific bootstrap logic.

**Reuse existing role system.** Stamp-server's 3-tier role system
(`owner` / `admin` / `member`) stored in `users.db` extends to gate
trust-anchor changes. No new role vocabulary, no new key-storage
directory.

**SaaS forward-compatibility.** The Phase 1 self-hosted image must be
deployable as the same image in a future multi-tenant SaaS variant.
Request handlers carry an explicit `org` / `repo` context from day one
even though Phase 1 deployments are single-tenant; signing-key resolution
is parameterizable per-tenant via a function that returns the current
tenant's key (Phase 1 always returns the singleton).

## Honest scope — what this delivers vs. doesn't

**Cryptographically strong:**

- *Server-attested verdicts.* The verdict, prompt hash, and diff hash are
  signed by stamp-server's review-signing key. The operator cannot
  produce a valid attestation without obtaining a signature from a real
  server invocation, which means a real LLM call against the canonical
  prompt happened.
- *Role-gated trust-anchor changes.* Modifications to `.stamp/**` paths
  require signatures from keys with the `admin` capability in the
  trusted-keys manifest. The rotating-prompt attack (degrade prompts via
  merge, then merge bad code, then restore prompts) is structurally
  prevented because the prompt-modification commit must be signed by an
  admin and the regular review cycle cannot approve those changes.
- *Diff binding.* The server signs `diff_sha256`. An operator cannot get
  a verdict for a sanitized version of the diff and then push a malicious
  one — verifier hashes the actual merge diff and rejects on mismatch.

**Best-effort (not cryptographically sealed):**

- *Server compromise.* If the server's signing key is stolen, the attacker
  can forge arbitrary verdicts that verify cleanly until the key is
  rotated and revoked. Mitigations: standard infra security, key rotation
  policies, optional short-lived per-request keys with a published
  rotation cadence.
- *Admin key compromise.* If admin signing keys are stolen, the attacker
  can sign trust-anchor changes. Mitigations: multi-sig requirement
  (`minimum_signatures: 2` or higher), cold storage for admin keys,
  separate keys from agent/automation keys.

**Deliberately not delivered:**

- *Local-only attestation.* Local mode is for iteration only, has no
  attestation, makes no trust claim. Any "attestation" producible without
  a server can be forged by the operator, so we don't pretend to offer
  one. See [`../local-only-mode.md`](../local-only-mode.md).
- *Reviewer file access.* Reviewers see only the diff. No
  `Read`/`Grep`/`Glob`/`WebFetch` against the repo or web. Reviewer
  prompts have to be written to work from the diff alone.
- *Reviewer MCP integrations.* No Linear / Notion / etc. MCP servers
  wired into reviewers in Phase 1.

## Architecture overview

```
┌────────────────────────────────────────────────────────────┐
│  OPERATOR'S MACHINE                                         │
│                                                             │
│  agent loop:                                                │
│    edit code                                                │
│    stamp review --diff main..feat ──ssh────────┐            │
│       (signed verdict returned here ◄──────────┤            │
│    apply fixes, iterate                         │            │
│    stamp merge feat --into main                 │            │
│       (builds attestation referencing           │            │
│        server signatures from earlier reviews)  │            │
│    git push ─────────────────────────────────┐  │            │
└───────────────────────────────────────────────│──│────────────┘
                                                │  │
                              ┌─────────────────┘  │
                              │ git push           │ ssh stamp-review ...
                              ▼                    ▼
┌────────────────────────────────────────────────────────────┐
│  STAMP-SERVER (existing component, gains review capability) │
│                                                             │
│  Existing surface:                                          │
│    • SSH endpoint (git push/pull, admin verbs)              │
│    • Pre-receive hook verifies merge attestations           │
│    • users.db with owner/admin/member roles                 │
│    • Post-receive hook (GitHub mirroring)                   │
│                                                             │
│  New review capability:                                     │
│    • SSH verb: `stamp-review --reviewer X --base S --head H`│
│        (auth via existing SSH key → users.db lookup)        │
│    • Fetches canonical prompt from local bare repo at base  │
│    • Calls Anthropic API with prompt + diff                 │
│    • Signs verdict payload with server's review key         │
│    • Returns signed payload on stdout                       │
│                                                             │
│  New pre-receive verification:                              │
│    • Verifies each approval's server signature              │
│    • Enforces path_rules (admin signatures for .stamp/**)   │
└────────────────────────────────────────────────────────────┘
```

For PR-check mode (operator's primary git remote is GitHub, not
stamp-server): same verification logic runs in
`stamp/verify-attestation@v1` against the operator-provided server pubkeys
committed to `.stamp/trusted-keys/`. Reviews still happen via SSH to
stamp-server; stamp-server gets a copy of the bare repo via an
operator-configured **GitHub Action auto-mirror** (see "Deployment shapes"
below).

## Server API surface — Phase 1 uses SSH command verbs

Phase 1 adds SSH verbs to stamp-server, reusing the existing
AuthorizedKeysCommand/ssh-wrapper auth that already powers
`stamp-mint-invite` etc. No new HTTP server, no new auth surface, no new
TLS concerns. The wire format is JSON on stdin/stdout.

### `stamp-review`

```sh
ssh -p <port> git@<stamp-server-host> stamp-review \
    --reviewer security \
    --org acme \
    --repo widget-co \
    --base-sha abc123... \
    --head-sha def456... \
    --diff-sha256 ... \
    < diff_content_on_stdin
```

Authenticated by the operator's SSH key → resolved against `users.db` to
identify caller. Caller must have `role: member` or higher and (in
multi-tenant Phase 2) access to the named org/repo.

Response on stdout:

```json
{
  "verdict": "approved",
  "prose": "...review prose...",
  "approval": {
    "reviewer": "security",
    "verdict": "approved",
    "prompt_sha256": "...",
    "diff_sha256": "...",
    "base_sha": "...",
    "head_sha": "...",
    "trusted_keys_snapshot_sha256": "sha256:...",
    "issued_at": "2026-05-17T18:42:13Z",
    "server_key_id": "sha256:..."
  },
  "signature": "<base64 Ed25519 over canonical-form `approval` object>"
}
```

The client persists `approval + signature` in its local DB (existing
`reviews` table, extended in AGT-333). `stamp merge` later folds these
into the attestation payload (see "Attestation schema (v4)" below).

**Server fetches the prompt itself** — the client does not send it. The
server runs `git --git-dir=/srv/git/<repo>.git show
<base_sha>:.stamp/reviewers/<reviewer>.md` against its local bare repo
(see `src/server/promptFetch.ts`). This is the load-bearing security
property: if the client could send the prompt, the substitution attack
returns.

**No tool-use loop.** The server calls the Anthropic Messages API with
the prompt as system message and the diff as user message. The model's
response is the prose review; the verdict is captured via a single
structured tool (the internal `submit_verdict` mechanism — an Anthropic
API tool definition, not user-facing MCP). No file reads, no web fetches,
no MCP server spawning. The reviewer prompt has to work from the diff
alone.

### Admin verbs (existing pattern, extended)

Out of scope for the first sketch. Phase 1 ships with admin state managed
directly via filesystem edits + restart, matching the existing
`stamp-mint-invite` provenance model. Web UI is Phase 2 SaaS territory.

### HTTP — Phase 2

When the SaaS variant ships, the same server gains an HTTP endpoint
(`POST /review`) backed by the same handlers, with bearer-token auth
instead of SSH-key auth. Phase 1 does not ship HTTP. The handler logic is
structured (request → resolve auth → invoke shared review pipeline →
sign → respond) so the SSH and HTTP entrypoints share everything below
the auth boundary.

## Attestation schema (v4)

> **Schema version numbering note.** The integer `3` was already taken
> by the in-code v3 envelope (the 0.5.0 merge-base self-review fix); see
> `src/lib/attestation.ts`. The new envelope is `schema_version: 4` to
> avoid collision. The two systems are unrelated — v4 lives in
> `src/lib/attestationV4.ts` and is the centerpiece of the stamp 2.x
> line.

> **Hash convention.** Three conventions coexist deliberately:
> - **JSON-canonical sha256, `sha256:<hex>` prefix** —
>   `trusted_keys_snapshot_sha256` (manifest hash from
>   `snapshotSha256()` in `src/lib/trustedKeysManifest.ts`).
> - **Bare hex** — `prompt_sha256` and `diff_sha256` (content hashes
>   without any namespace prefix; matches the convention already in use
>   by v3).
> - **`sha256:<hex>` prefix** — fingerprints (`server_key_id`,
>   `signer_key_id`). Matches `fingerprintFromPem()`.
>
> The prefix marks "this is a fingerprint identifier" vs. "this is a
> content hash." Verifiers must check the form before comparing strings.

```json
{
  "schema_version": 4,
  "base_sha": "abc123...",
  "head_sha": "def456...",
  "target_branch": "main",
  "diff_sha256": "...",

  "approvals": [
    {
      "reviewer": "security",
      "verdict": "approved",
      "prompt_sha256": "...",
      "trusted_keys_snapshot_sha256": "sha256:...",
      "server_attestation": {
        "issued_at": "...",
        "server_key_id": "sha256:...",
        "signature": "<base64 Ed25519>"
      }
    }
  ],

  "checks": [
    { "name": "build", "command": "npm run build", "exit_code": 0, "output_sha": "..." }
  ],

  "trust_anchor_signatures": [
    {
      "signer_key_id": "sha256:...",
      "signature": "<base64>"
    }
  ],

  "signer_key_id": "sha256:..."
}
```

Field notes that don't fit in the JSON body itself:

- `trust_anchor_signatures` is only present if this merge modifies
  `.stamp/**` paths. Each entry signs a canonical-form payload
  describing the `.stamp/**` changes; signers must have the `admin`
  capability in the manifest.
- Top-level `signer_key_id` is the operator's key — it signs the whole
  envelope. Per-approval `server_attestation.server_key_id` is the
  stamp-server's review-signing key.

**Fields explicitly dropped from v2:**
- `tools_sha256` — no tools in Phase 1
- `mcp_sha256` — no MCP in Phase 1
- `tool_calls` — no meaningful tool calls to trace

**Fields added in v4:**
- `server_attestation` per approval — the server's signature over the
  verdict + hashes
- `trusted_keys_snapshot_sha256` per approval — hash of the manifest at
  the time the verdict was issued; enables lenient revocation semantics
- `trust_anchor_signatures` at the top level — multi-sig signatures from
  admin-capability keys, present when the diff touches `.stamp/**`

The merge commit trailer carries `Stamp-Payload` (base64 of this JSON)
and `Stamp-Verified` (operator's Ed25519 over the payload bytes).

For the exact canonical serializer (the bytes the server's signature
covers), see `canonicalSerializeApproval` and the surrounding type
definitions in `src/lib/attestationV4.ts`.

## Trust model

Three key categories, non-overlapping responsibilities, all stored in the
same `.stamp/trusted-keys/` directory with capability metadata in a YAML
manifest:

| Capability | Held by | Signs | Compromise blast radius |
|---|---|---|---|
| **`admin`** | Humans, ideally cold storage / hardware token | Changes to `.stamp/**` (prompts, config, trusted-keys manifest) | Can land arbitrary trust-anchor changes. Mitigation: multi-sig (`minimum_signatures: 2+`), short rotation cadence. |
| **`server`** | Stamp-server's review-signing key (warm, in `$STATE_DIR/review-signing-key.pem`) | Per-review verdicts via `stamp-review` SSH verb | Can forge verdicts that verify cleanly. Mitigation: rotation + revocation, snapshot-at-attestation-time semantics so revoking a key blocks future merges without retroactively invalidating past ones. |
| **`operator`** | Operator's machine (warm) | The final merge attestation envelope (wraps server + admin signatures) | Can sign merges but verifier still requires valid server signatures on each approval. Operator-only compromise cannot forge reviews. |

The merge attestation requires valid signatures from all three categories.
Each category enforces what it's actually competent to attest to. Today's
model collapses all three into the operator's single signature — that's
the design defect this plan corrects.

### Trusted-keys manifest

`.stamp/trusted-keys/manifest.yml` (new file, hash-bound into attestation
via `trusted_keys_snapshot_sha256`):

```yaml
keys:
  alice:
    fingerprint: sha256:aaa...
    capabilities: [admin]
  bob:
    fingerprint: sha256:bbb...
    capabilities: [admin]
  agent-bot:
    fingerprint: sha256:ccc...
    capabilities: [operator]
  review-server-prod:
    fingerprint: sha256:ddd...
    capabilities: [server]
    role_source: server     # auto-published by the server, not human-managed
```

Pubkeys live in `.stamp/trusted-keys/*.pub` as today; manifest references
them by fingerprint. Capabilities are additive (a single human key could
be both `admin` and `operator`). Capability vocabulary is small and
fixed: `admin`, `operator`, `server`.

### Lenient revocation

When a `server`-capability key is compromised and rotated:

1. Admins update the manifest to remove the compromised key and add the
   new one (admin-signed commit to `.stamp/`)
2. Future `stamp-review` calls return verdicts signed by the new key
3. Future merges embed the new `trusted_keys_snapshot_sha256`
   referencing the new manifest
4. **Past merges remain valid** because their
   `trusted_keys_snapshot_sha256` references the manifest as it was at
   *their* attestation time, when the now-revoked key was still trusted

This matches DESIGN.md's existing "snapshot at attestation time" pattern
for other moving-target checks.

## Path rules (role-gated trust-anchor changes)

New `path_rules` section in `.stamp/config.yml`:

```yaml
branches:
  main:
    required_reviewers: [security, standards, product]
    review_server: ssh://git@stamp.acme.internal:22

path_rules:
  ".stamp/**":
    require_capability: admin
    minimum_signatures: 2
    bypass_review_cycle: true   # these changes don't go through stamp reviewers at all
```

**`bypass_review_cycle: true`** — `.stamp/**` changes are gated by admin
signatures, not by reviewer verdicts. This is deliberate: the regular
reviewer cycle is structurally vulnerable to the rotating-prompt attack
(a permissive new prompt could approve its own merging). Admin gate
replaces reviewer gate for these paths.

**Capability resolution** — at verification time, the pre-receive hook
looks up each `trust_anchor_signatures[].signer_key_id` against
`.stamp/trusted-keys/manifest.yml` to find the key's capabilities.
Signers without the `admin` capability don't count toward
`minimum_signatures`.

**Local-only mode** (no server, no signed verdicts) — `path_rules` are
inert by definition. Trust-anchor changes work the same as any other
change. Documented as: "local-only mode offers no trust property; this is
expected." See [`../local-only-mode.md`](../local-only-mode.md).

## Local-only mode (Option E)

Local-only mode is a separate transport with explicit no-trust framing.
It exists to give agents fast feedback during iteration without requiring
server deployment. Implementation reference:
[`../local-only-mode.md`](../local-only-mode.md),
[`skills/stamp-review.md`](../../skills/stamp-review.md).

```
agent runs `stamp review --plan --diff main..feat`
  ↓
stamp emits structured plan to stdout:
  {
    diff: "...",
    base_sha: "...", head_sha: "...",
    reviewers: [
      { name: "security", prompt: "<full text>", fence_hex: "..." },
      ...
    ]
  }
  ↓
parent agent (Claude Code session) reads plan
  ↓
parent dispatches N parallel subagents via its Agent tool
  ↓
each subagent reviews, returns verdict + prose
  ↓
parent reads subagent outputs directly and surfaces them
  (no stamp CLI verb involved on this side — stamp's role ends after emitting the plan)
  ↓
agent iterates
```

Subagent calls are interactive Claude Code → unmetered by the June 15
split.

Key vocabulary differences from the trusted-mode CLI:

- `stamp review --plan` (not `stamp review` — that's the trusted-mode
  default with `review_server` configured)
- No `stamp record-feedback` verb. The parent agent already has the
  subagent's response; it doesn't need to round-trip through stamp to
  read or format it. Local-only mode's responsibility ends after
  emitting the plan.
- No `stamp merge` step that uses local feedback as a gate
- Plan emission includes a banner directing the parent agent: *"This
  produces iteration feedback only. No attestation will be created. To
  produce a verifiable verdict, configure a `review_server` in
  `.stamp/config.yml`."*

For headless local-only (cron, git hooks, scripts with no parent agent):
fall back to direct `@anthropic-ai/sdk` with `ANTHROPIC_API_KEY`.
Standard subscription-vs-API-key billing applies; documented workaround
for the June 15 split.

## Deployment shapes

Two Phase 1 deployment shapes, both well-supported. PR-mode (GitHub
primary remote) requires the extra auto-mirror step.

### Shape 1: stamp-server is the primary git remote

Operator pushes directly to stamp-server. Reviews and merges all happen
through stamp-server's SSH endpoint. Pre-receive hook verifies on push.

Setup:
1. Deploy stamp-server Docker image (Railway, Fly, K8s, bare VPS —
   operator's choice; see [`../../server/README.md`](../../server/README.md))
2. Set env vars: `ANTHROPIC_API_KEY` (for reviews), plus existing
   stamp-server config
3. Operator commits the server's review pubkey to
   `.stamp/trusted-keys/manifest.yml` with `capabilities: [server]`
   (the server prints it loudly on first boot — see AGT-327)
4. Configure `review_server: ssh://git@<stamp-server>:22` in
   `.stamp/config.yml`

### Shape 2: GitHub is the primary git remote (PR mode), stamp-server does reviews

> **Historical (removed).** Shape 2 (mirror-mode PR — `stamp init
> --pr-mode` + `.github/workflows/stamp-mirror.yml` + the `STAMP_MIRROR_KEY`
> org secret) was removed; it is superseded by Shape 4 (server-attested
> without code transfer). This section is retained as a design record. See
> [`shape-2-3-deprecation.md`](./shape-2-3-deprecation.md).

GitHub holds the source of truth and runs the PR UI. Stamp-server runs
reviews and signs verdicts. The two are kept in sync via a GitHub Action
that auto-mirrors GitHub → stamp-server on every push.

Setup:
1. Deploy stamp-server with `ANTHROPIC_API_KEY` (same as Shape 1)
2. Generate one SSH keypair for the org's stamp-server mirror
3. Register the public key on stamp-server (e.g. as a `mirror`
   service-account user via `stamp-mint-invite mirror --role member`)
4. Add the private key as a **GitHub organization secret** (e.g.
   `STAMP_MIRROR_KEY`), scoped to the repos using stamp
5. Each repo using stamp drops in a mirror workflow file:
   `.github/workflows/stamp-mirror.yml` (scaffolded by `stamp init
   --pr-mode`). On every push to GitHub, the workflow pushes to
   stamp-server's bare repo.
6. Configure `review_server: ssh://git@<stamp-server>:22` in
   `.stamp/config.yml`
7. `stamp/verify-attestation@v1` runs as a required GitHub PR check;
   verifies the v4 attestation including server signatures.

**Result:** one-time org-level secret + one workflow file per repo.
Stamp-server stays credential-free with respect to GitHub (no GitHub PAT,
no deploy keys on stamp-server's side).

### Server deployment artifact

The existing stamp-server Docker image, extended. No new image to
publish.

New review-capability env vars layered on existing stamp-server config:

| Var | Purpose | Default |
|---|---|---|
| `ANTHROPIC_API_KEY` | Server's Anthropic credential | Required if reviews enabled |
| `MAX_DIFF_BYTES` | Reject review requests larger than this | `5_000_000` |
| `REVIEW_TIMEOUT_MS` | Per-review wall-clock timeout | `300_000` |
| `REVIEW_SIGNING_KEY_PATH` | Override signing-key location | `$STATE_DIR/review-signing-key.pem` |

Absent `ANTHROPIC_API_KEY` → stamp-server runs as today, rejecting
review requests with a clear "review capability not configured" error.
Reviews are opt-in.

The review signing key lives at `$STATE_DIR/review-signing-key.pem`,
mode 0600. Generated on first boot if absent (AGT-327 shipped this in
`src/server/bootstrap-review-key.ts`; the pubkey is printed loudly to
stderr with an instruction to commit it to the manifest).

No platform-specific bootstrap. No `/etc/stamp/env`-style shims in the
review-capability code paths. Same binary on Docker / systemd / bare
process.

### Deferred to Phase 2

- **Stamp-server clones from GitHub on-demand with a deploy key** — saves
  the auto-mirror setup ceremony in Shape 2. Implementation requires
  stamp-server to grow GitHub-auth code; deferred.
- **HTTP API endpoint + bearer-token auth** — shipped alongside the SaaS
  variant.
- **Multi-tenant data model** — Phase 1 is single-tenant; Phase 2 SaaS
  adds tenant isolation, per-tenant signing keys, billing.
- **Reviewer file-access tools** (`Read`, `Grep`, `Glob`, `WebFetch`) —
  explicit Phase 1 omission; re-add later if demand materializes.
- **Reviewer MCP integrations** — explicit Phase 1 omission; re-add
  later if demand materializes.
- **Per-reviewer `review_server` overrides** — branch-level default only
  in Phase 1.

## Verifier extensions

Both the pre-receive hook and `stamp/verify-attestation@v1` extend their
verification logic. AGT-350 refactored `src/hooks/pre-receive.ts` into
named phase functions so the new v4 phases below can land cleanly as
discrete additions.

1. Existing steps (signature validity, SHA binding, branch rule, checks)
   unchanged
2. **New:** For each approval, verify `server_attestation.signature`
   against the `capabilities: [server]` key in
   `.stamp/trusted-keys/manifest.yml` matching `server_key_id`. Reject
   if no trusted server key matches the fingerprint.
3. **New:** Confirm `approval.diff_sha256` equals `sha256` of the actual
   diff between `base_sha` and `head_sha` on the merge commit.
4. **New:** Recompute `approval.prompt_sha256` from the merge commit's
   own `.stamp/` tree and confirm equality with the value the server
   signed. The server fetched the prompt from its bare repo at
   `base_sha`; the verifier reads it from the merge commit's tree. The
   two agree because `path_rules` with `bypass_review_cycle: true`
   prevents `.stamp/**` changes from landing via the reviewer cycle —
   the prompt the server reviewed and the prompt the verifier sees are
   guaranteed to be the same file. Deployments without `path_rules`
   configured do not get this guarantee.
5. **New:** Verify `approval.trusted_keys_snapshot_sha256` matches the
   manifest committed at `base_sha`. This is the lenient-revocation
   hook — revoked keys remain valid for attestations whose snapshot
   predates the revocation.
6. **New:** If the diff touches any `path_rules` glob, count
   `trust_anchor_signatures` entries whose `signer_key_id` resolves to a
   key with the required capability in the manifest. Reject if count <
   `minimum_signatures`.

## Migration path

> _Detailed walkthrough: [`../migration-1.x-to-2.x.md`](../migration-1.x-to-2.x.md)._

Hard version bump: stamp 1.x stays on the operator-trust local model with
its documented caveats; stamp 2.x is server-attested-only for the trust
property.

**Bridge release (1.x final):** ships with deprecation notices. README and
`stamp init` output prominently link to a migration guide. The
operator-trust caveat in DESIGN.md gets a much louder restating.

**stamp 2.0 release:**

- `stamp review` now requires `review_server` configured in
  `.stamp/config.yml` (otherwise errors with link to migration guide or
  `--plan` mode)
- `stamp review --plan` for local-only iteration mode (shipped in
  AGT-339)
- Old DB rows in `.git/stamp/state.db` stay readable for `stamp log` but
  no longer serve as merge-gate input
- `stamp init` defaults assume server-attested deployment; `--local-only`
  flag opts into no-trust mode with explicit banner

**Existing repos on stamp 1.x:** upgrade path:
1. Upgrade stamp-server to a 2.x version with review capability + provide
   `ANTHROPIC_API_KEY`
2. Server generates its review signing key; commit pubkey to
   `.stamp/trusted-keys/manifest.yml` with `capabilities: [server]`
3. Add `review_server: ssh://...` to `.stamp/config.yml`
4. Run `stamp init --migrate-to-server-attested` to scaffold path_rules
   + capability metadata for existing trusted keys (existing keys
   default to `[operator]`; humans get manually promoted to `[admin,
   operator]` as appropriate)
5. From this commit forward, attestations require server signatures;
   older commits' attestations remain valid under v2 semantics
6. Any `mcp_servers` or `tools` config blocks get a warning + ignored
   (Phase 1 doesn't support them)

## Threat model — what each step catches

| Attack | Caught by | Notes |
|---|---|---|
| Operator passes fake prompt to local LLM, signs canonical prompt's hash | **Server-attested verdicts** | Server fetches canonical prompt itself; operator cannot influence what the LLM sees |
| Operator signs a verdict for a sanitized diff, pushes a malicious one | **`diff_sha256` binding** | Verifier hashes actual merge diff; mismatch rejected |
| Operator embeds a permissive prompt's hash to justify approval | **`prompt_sha256` cross-check against committed tree** | Verifier recomputes from merge commit's `.stamp/` tree |
| Operator pushes commit modifying `.stamp/reviewers/*.md` with permissive content, signed via normal review flow | **`path_rules` + `admin` capability + `bypass_review_cycle`** | `.stamp/**` requires admin signatures, not reviewer verdicts |
| Operator pushes commit adding a new pubkey to `.stamp/trusted-keys/` | Same as above | Same gate covers all of `.stamp/**` |
| Replay: reuse an old verdict's signature for a new diff | **`diff_sha256` binding + `issued_at` in signed payload** | Server's signature binds to specific `diff_sha256` |
| Server signing-key theft → forged verdicts | **Rotation + revocation, lenient snapshot semantics** | Manifest update removes compromised key; future merges blocked; past merges grandfathered because their `trusted_keys_snapshot_sha256` references the pre-revocation manifest |
| Admin key theft → forged trust-anchor changes | **Multi-sig + rotation** | `minimum_signatures: 2+` requires multiple compromises |
| Operator key theft → forged merges | **Server signatures on every approval are still required** | Stolen operator key alone cannot produce a valid attestation |
| Prompt-injection of orchestrator agent (Option E concern) | **N/A in trusted mode — server runs reviews** | Local-only mode is vulnerable but produces no attestation, so no trust claim to break |
| Server compromised by attacker who can issue arbitrary signed verdicts | **Trust scope reduction + audit logs + rotation** | Self-hosted: same as any infra compromise. Not structurally preventable. |

## Open questions

Most of the original open questions were settled during design discussion.
Remaining items, all operational:

- **Trust-anchor multi-sig collection UX.** When `minimum_signatures:
  2`, how does admin A's signature reach admin B for counter-signing?
  Out-of-band (admin A creates commit + signature, sends commit SHA to
  admin B, B counter-signs) is workable but clunky. A `stamp admin sign
  --pending <sha>` inbox-style flow would be friendlier. Settle during
  M4 implementation.
- **Per-commit revocation tooling.** The lenient revocation model works
  mechanically, but admins need a clear `stamp admin revoke-key
  <fingerprint>` flow that updates the manifest and produces a properly
  admin-signed commit. UX detail to design during M4.
- **`stamp init --migrate-to-server-attested` defaults.** Existing
  trusted-keys default to `[operator]` capability; how does the
  operator promote selected keys to `[admin, operator]` during the
  migration? Probably an interactive prompt listing existing keys.
- **Diff context sufficiency for reviewers without file access.** Phase
  1's reviewer prompts have to work from the diff alone. Reviewer
  authors may need to update their prompts (e.g. drop "if you need to
  check the test file, use Read"). The migration guide should include
  guidance on adapting prompts.

## Referenced docs

- [`../../DESIGN.md`](../../DESIGN.md) — current attestation schema and
  security model. The security section opens with the v4 resolution and
  links back to this plan.
- [`./verified-reviewer-configs.md`](./verified-reviewer-configs.md) —
  v2 plan that introduced prompt/tools/mcp hash pinning. v4 supersedes
  its threat model: hashing the committed config does not constrain
  what the local LLM actually received; server-attested verdicts do.
- [`../ROADMAP.md`](../ROADMAP.md) — phase tracking. Server-attested
  reviews are the centerpiece of a stamp 2.x line.
- [`../troubleshooting.md`](../troubleshooting.md) — runbook; gains
  new sections for review-capability setup, key rotation, capability
  assignment as M2–M6 ship.
- [`../../server/README.md`](../../server/README.md) — existing
  stamp-server deployment guide. Reviews are an additive section.

## Next concrete steps

1. **File M1 implementation tickets** — see the 24-ticket decomposition
   discussed alongside this plan. M1 covers spec work (attestation v4
   schema, manifest format, signed-payload canonical serializer) that
   blocks the remaining milestones. *(M1 shipped — see "Implementation
   status" at top.)*
2. **DESIGN.md security model rewrite** — promote the operator-trust
   caveat to the security model's headline; link to this plan as the
   resolution path. *(This ticket — AGT-344.)*
3. **Migration guide doc** — separate doc on the 1.x → 2.x upgrade UX,
   deprecation timeline, backward-compat story for the bridge release.
4. **PR-mode workflow scaffold** — write the
   `.github/workflows/stamp-mirror.yml` template that `stamp init
   --pr-mode` will install, along with the org-secret setup walkthrough.
   *(Shipped — AGT-343; see `src/commands/init.ts`'s
   `renderMirrorWorkflow` + `printPrModeWalkthrough`, and
   `tests/initPrModeMirrorWorkflow.test.ts`.)*
