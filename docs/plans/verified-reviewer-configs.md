# Plan — verified reviewer configs

Status: proposed · Owner: maintainer · Target: Phase 3

## Motivation

Today's stamp attestation proves: *"a key holder signed off that reviewer `X` returned `approved` for commit `Y`."* It does **not** prove:

- What prompt the reviewer actually ran
- What tools or MCP servers the reviewer had access to
- Whether the reviewer's prompt matches a canonical/org-approved version
- Whether tool calls the prompt assumes happened actually happened

A motivated operator holding the signing key can edit `.stamp/reviewers/standards.md` to say "always approve," invoke the reviewer, get a clean `approved`, and sign the attestation. Downstream verifiers see a valid signed merge and have no way to detect the prompt drift.

This matters for organizations that want canonical reviewer personas (e.g., "ACME's standards persona must check this requirements doc; ACME's product persona must cross-check the referenced Linear ticket"). Without verifiable configs, the personas are suggestions, not enforced policy.

## Design constraints

**Local-first is non-negotiable.** The fast review cycle — author-agent produces a diff, reviewers run in parallel on the operator's machine, verdicts return in seconds — is what makes stamp-cli useful. Moving reviewers to a remote service (e.g., an org-hosted review API that returns org-signed verdicts) solves the trust problem cryptographically but breaks the latency/friction that's the tool's whole point. Out of scope for this plan.

**Everything stays on the operator's machine.** Reviewers still invoke the Claude Agent SDK locally. Operators still hold the merge-signing key. The only remote component is the source of canonical reviewer definitions, fetched and cached ahead of time.

## Honest scope — what this delivers vs. what it doesn't

**Cryptographically strong:**

- *Config-was-what-the-org-expected.* Attestation embeds hashes of the prompt file and tool/MCP configuration used. A verifier with a canonical manifest can detect any drift — a modified prompt, a removed tool, a stripped MCP server.

**Best-effort (not cryptographically sealed):**

- *Review-did-what-the-config-said.* The prompt tells the agent to cross-check a Linear ticket. The agent *might* skip that tool call. The SDK surfaces the tool-call trace, and we can embed it in the attestation, but a determined operator running locally could still forge the trace. Comparable to how an SBOM proves which deps were used but not that they weren't exploited.

This split is the honest, defensible guarantee a local-first tool can make. Organizations that need stronger guarantees (cryptographic proof the review *actually ran with the right tools*) need Tier 3 / server-side review — out of scope here.

## Implementation sequence

### Step 1 — Reviewer tools + MCP plumbing

Wire `.stamp/config.yml` to the Claude Agent SDK's `query()` options. Reviewers can now declare a `tools` list (built-in Claude tools: `Read`, `Grep`, `WebFetch`, etc., mapped internally to the SDK's `allowedTools`) and optional `mcp_servers` per reviewer. No verification yet — this just enables richer reviews.

Schema sketch:

```yaml
reviewers:
  standards:
    prompt: .stamp/reviewers/standards.md
    tools: [Read, Grep]
  product:
    prompt: .stamp/reviewers/product.md
    tools: [WebFetch]
    mcp_servers:
      linear:
        command: npx
        args: ["-y", "@linear/mcp"]
        env:
          LINEAR_API_KEY: $LINEAR_API_KEY
```

Security model update: DESIGN.md names the new threat expansion — a malicious reviewer prompt with tool access could exfiltrate diff contents, read local files in the repo tree, or make external network calls. Conservative defaults (Read/Grep only, no Bash/Write); MCP servers explicit opt-in.

**Invocation-time error handling:** when `mcp_servers[*].env` references an env var (e.g. `LINEAR_API_KEY`) that isn't set at the caller's shell, `stamp review` fails fast with exit 1 and a stderr line naming the missing var and which reviewer declared it — rather than silently passing `undefined` into the MCP config and producing a confusing mid-stream tool failure. Open Q4 covers the hashing side; this covers the runtime error.

### Step 2 — Prompt + tool config hashing in attestation

Each approval entry in the signed payload grows three fields:

```
{ name, verdict, prompt_sha256, tools_sha256, mcp_sha256 }
```

- `prompt_sha256` — hash of the resolved prompt file contents at review time
- `tools_sha256` — hash of the tool allowlist (canonical-form JSON)
- `mcp_sha256` — hash of the MCP config (canonical-form JSON, excluding resolved env values)

Server hook's verification step grows: recompute the hashes against the committed `.stamp/` tree and reject if they don't match the attestation. (This catches an operator who signs an attestation that references different configs than what was in the repo.)

At this step, verifiers have a hash to compare against *something* — but without a canonical manifest, it's self-referential. Step 3 makes the hash meaningful.

**Backward compat:** attestations produced before this feature shipped don't carry the hash fields. The attestation payload already has a `version` integer; this step bumps it. The server hook and `stamp verify` treat attestations at the old payload version as valid without hash checks (fail-open on legacy), and attestations at the new version as invalid without hash checks (fail-closed). That keeps existing stamp repos from breaking mid-upgrade while forcing new attestations to include the stronger evidence.

### Step 3 — Remote canonical personas + lock files

Organizations publish canonical reviewer definitions to a source (git repo, npm package, or HTTP endpoint). A manifest lists acceptable `(persona, version, prompt_sha256, tools_sha256, mcp_sha256)` tuples.

New subcommand: `stamp reviewers fetch <source>@<version> <reviewer>`. Downloads the prompt and config into `.stamp/reviewers/`, writes a lock file `.stamp/reviewers/<name>.lock.json` recording:

```json
{
  "source": "github.com/acme/stamp-personas",
  "version": "v3.2",
  "reviewer": "standards",
  "prompt_sha256": "...",
  "tools_sha256": "...",
  "mcp_sha256": "...",
  "fetched_at": "2026-04-19T14:00:00Z"
}
```

At review time, `stamp review` hashes the current prompt + config and compares against the lock file. Mismatch → exit 3 (new dedicated code for config drift, distinct from exit 1 "review genuinely rejected" so agent loops can branch on the difference). Error message shape:

```
error: reviewer 'standards' prompt hash mismatch
  expected: sha256:abc123...  (from .stamp/reviewers/standards.lock.json)
  observed: sha256:def456...  (current .stamp/reviewers/standards.md)
  fix: re-run 'stamp reviewers fetch <source>@<version> standards' or update the lock file deliberately
```

Planned verbs in the `stamp reviewers` family at completion of Step 3: existing `list / add / edit / remove / test / show` + new `fetch` (pull + pin from remote manifest) + new `verify` (run the hash check without invoking the reviewer, useful for CI pre-flight). No separate `update` verb — `fetch` with a newer version string is the update path.

The attestation's per-reviewer entry grows `reviewer_source` pointing at the manifest. Downstream verifiers (server hook, third-party auditors) can independently query the manifest source, confirm the `(source, version, hashes)` tuple is listed as acceptable, and reject attestations referencing unknown or obsolete versions.

Optional: sign the manifest itself with an org key. Verifier checks the signature before trusting the hash list.

### Step 4 — Tool-invocation trace in attestation (optional)

The Claude Agent SDK surfaces tool-call events during `query()`. Record a minimal trace per review:

```json
[
  { "tool": "linear.get_issue", "input_sha256": "..." },
  { "tool": "Read", "input_sha256": "..." }
]
```

Embed in the attestation. Doesn't cryptographically prove the tools ran with the right inputs — the operator could forge the trace — but it creates an audit trail that catches lazy tampering and gives downstream verifiers something concrete to reason about ("for diffs mentioning LIN-123, we expect a `linear.get_issue` call").

Weak guarantee, real audit value. Lands if there's demand after Steps 1–3.

## Threat model impact per step

| Step | Catches | Misses |
|---|---|---|
| 1 | Nothing new (capability enablement only) | — |
| 2 | Operator editing prompt/tools after `.stamp/` is committed, attestation claiming wrong config | Operator editing prompt *and* re-committing on the stamp branch |
| 3 | All tampering outside the org-approved version set; drift from canonical personas | Server-side tampering of the manifest itself (mitigated by signed manifests) |
| 4 | Lazy skipping of required tools ("prompt says call Linear, trace shows no call") | Operator forging tool-call entries |

## Open questions

- **Manifest format and discovery.** Git repo? npm package? Plain HTTP JSON? The answer likely depends on what teams already have for prompt distribution.
- **Lock file conflict resolution.** When the manifest updates a reviewer, what does `stamp review` do? Fail closed (reject run) vs. warn-and-continue vs. auto-update.
- **Env var resolution in MCP configs.** `$LINEAR_API_KEY` must resolve at invocation time, not leak into attestation hashes. Canonical-form hashing excludes resolved env values.
- **Built-in tool versioning.** Claude's `Read`, `Grep`, etc. are defined by the SDK version. A new SDK release could silently change tool semantics. Do we pin SDK version in the attestation too?
- **`stamp reviewers fetch` arg order.** Plan currently commits to `fetch <source>@<version> <reviewer>`. Every other verb in the `reviewers` family takes reviewer name as the primary identifier; consider `fetch <reviewer> --from <source>@<version>` or `fetch <reviewer>@<version> --from <source>` instead, so noun-verb-identifier ordering is consistent. Settle before the verb ships.
- **`add` vs `fetch` disambiguation.** Existing `reviewers add` creates a local unpinned reviewer; new `reviewers fetch` downloads and pins from a remote manifest. Help-text must make the choice obvious at `--help` without reading both long descriptions.
- **Exit-code audit.** Plan reserves exit 3 for config drift. Verify at implementation time that no other command/path is already using 3 for a different failure mode before committing.

## Referenced docs

- [`DESIGN.md`](../../DESIGN.md) — current attestation schema and security model
- [`docs/personas.md`](../personas.md) — reviewer prompt authoring
- [`docs/ROADMAP.md`](../ROADMAP.md) — phase tracking
