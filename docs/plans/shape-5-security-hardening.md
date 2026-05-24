# Plan — security hardening, post-Shape-2/3 surface

Status: ready · Owner: maintainer · Ticket: AGT-408

> Scoping doc. Inventories every candidate security-hardening thread on
> the leaner post-cleanup stamp-cli surface, scores each (threat model +
> severity + effort), sequences them highest-severity-first, and maps
> each MEDIUM+ thread to a filed follow-on ticket. It ships **no
> production code** — only this doc and the tickets it spawns.
>
> Soft dependency: **[AGT-407](./shape-2-3-deprecation.md)** (Shape 2/3
> removal). Hardening lands cleaner on the post-cleanup surface but is not
> strictly blocked by it — none of the threads below touch the
> `--pr-mode` scaffold being removed.
>
> Companion: [`docs/plans/peer-agentic-reviews.md`](./peer-agentic-reviews.md)
> (the Phase 4 work this hardening precedes).

## Why this exists

Before Phase 4 (Peer-agentic reviews) lands on stamp-cli, the existing
surface should have its sharp edges scored and sequenced into landable
tickets — so Phase 4 doesn't build on top of unaddressed gaps.

## Methodology

Two independent passes, reconciled:

1. **Surface scan** — a structured read of the 8 threat surfaces named in
   AGT-408's AC #1 (path_rules, prompt-fetch boundary, v4/v5 verification,
   signature timing, revocation concurrency, SSH-verb validation,
   migrate-existing whitelist, Peer-agentic-reviews PR-body injection).
2. **External audit** — the `2026-05-22` five-spec audit
   (`trusted/security`, `trusted/llm-security`, `trusted/privacy`,
   `trusted/infra`, `trusted/supply-chain`), 9 findings MEDIUM+ across the
   suite.

**Reconciliation result:** the audit independently *confirmed* the
surfaces the scan judged already-guarded (it raised no finding against
constant-time crypto, v4/v5 version gating, path_rules glob matching, or
SSH-verb input parsing), and it *added* a dozen findings the scan's
narrow 8-thread brief did not cover (invite-URL downgrade, reviewer
sandbox escapes, privacy/retention, supply-chain). The audit is treated
as the authoritative severity source where the two differ.

## Threat inventory

Severity: CRITICAL / HIGH / MEDIUM / LOW. Effort: S / M / L. Disposition:
filed ticket, fixed already, or LOW→doc-only (per AC #4, only MEDIUM+
get a per-thread ticket).

### Actionable — HIGH

| Thread | Threat model | Sev | Eff | Ticket |
|---|---|---|---|---|
| **LLM verdict authorizes signed merges (H1 residual).** A prompt-injection surviving every mitigation flips an unreviewed diff into a verifiable signed commit. Lower the residual: enforce_reads_on_dotstamp default-on for security reviewer; `git diff --stat` in the confirm prompt; typed confirmation phrase for `require_human_merge: strict`; path_rules + admin-sig count in the merge banner. `src/commands/merge.ts` | Attacker: author of a malicious diff. Asset: protected-branch integrity. | HIGH | M | **AGT-414** |
| **Every `stamp review` ships full diff to Anthropic; consent is a one-time stderr note.** Per-invocation marker; `data_flow:` block in `.stamp/config.yml`; optional `data_flow.confirmed` gate for regulated repos; `STAMP_ANTHROPIC_NO_RETAIN=1` passthrough; README data-flow section. `src/lib/reviewer.ts:245` | Attacker: n/a (disclosure gap). Asset: proprietary code / secrets / regulated data in diffs. | HIGH | M | **AGT-415** |
| **`STAMP_PROMPTS_DIR` runtime prompt substitution.** Env override points the resolver at an attacker-writable path; substituted prompts still produce cleanly-verifying signatures. Refuse start when set ≠ default unless an explicit insecure-test toggle AND non-prod `STAMP_ENV`. `server/entrypoint.sh:287`, `src/server/promptFetch.ts` | Attacker: anyone with platform-config/env access to the server. Asset: prompt-integrity trust anchor. | HIGH¹ | S | **AGT-411** |

¹ Audit rated this `trusted/infra` MEDIUM; the scan rated it HIGH (it
defeats the server's core prompt-integrity guarantee). Either way it is
ticketed; sequenced among the HIGHs given the trust-anchor blast radius.

### Actionable — MEDIUM

| Thread | Threat model | Sev | Eff | Ticket |
|---|---|---|---|---|
| **Reviewer can `Read(.git/config)` / `.git/credentials`.** Denylist scopes to repoRoot but misses `.git/`; credential-helper tokens, signing passphrases, internal hostnames reachable → flow into context, attestation prose, WebFetch. Deny all of `.git/` and `.stamp/` for Read/Grep/Glob. `src/lib/reviewer.ts:35` | Attacker: prompt-injected reviewer. Asset: git credentials / internal infra. | MEDIUM | S | **AGT-418** |
| **prompts-cache `git` invocation hardening.** Operator URL passed positionally with no `--` terminator or shape validation (CVE-2017-1000117 class); failures leak embedded creds via argv. Regex-validate URL, add `--`, scrub argv in errors. `src/server/prompts-cache.ts:459,470` | Attacker: env/CI-secret tamperer (or typo). Asset: RCE on server `git` user / credential leak. | MEDIUM | S | **AGT-417** |
| **Invite `?insecure=1` downgrade.** Share-URL param forces the token POST onto plaintext HTTP; token + pubkey sniffable, token redeemable by attacker. Drop the param; choose transport client-side via opt-in flag. `src/lib/inviteUrl.ts:52` | Attacker: network MITM / phisher. Asset: single-use invite token. | MEDIUM | S | **AGT-416** |
| **WebFetch ignores query strings.** Allowlisted hosts double as exfil channels — diff bytes encoded into query params. Per-host `query_param_allowlist` + length cap. `src/lib/reviewer.ts:290` | Attacker: prompt-injected reviewer. Asset: diff/context confidentiality. | MEDIUM | M | **AGT-419** |
| **SSH `stamp-review` verb has no rate limit.** Any enrolled member replays valid diffs; each call bills the server's `ANTHROPIC_API_KEY`. Per-fingerprint token bucket + server-side verdict cache. `src/server/stamp-review.ts` | Attacker: any invited member (or compromised key). Asset: operator's Anthropic budget. | MEDIUM² | M | **AGT-420** |
| **Reviewer prose persisted indefinitely.** `reviews.issues` archives diff quotes forever; `stamp prune` is opt-in. Default prune schedule / TTL env / `--no-prose` flag. `src/lib/db.ts:270` | Attacker: local shell access. Asset: archived sensitive diff snippets. | MEDIUM | M | **AGT-421** |
| **SSH key-comment PII in membership DB.** `firstname.lastname@host` imported verbatim, readable via `stamp users list`, never pruned. Strip comment on seed-import; content-addressed short_name; populate `last_seen_at`. `src/server/seed-users.ts:31` | Attacker: any enrolled user. Asset: teammates' real-name PII. | MEDIUM | M | **AGT-422** |
| **Soft-deleted repos retain full history in `.trash/`.** No GC, no max age; PII-bearing repos persist after "delete". TTL sweep + `server-repos purge-old`. `src/commands/serverRepo.ts:38` | Attacker: server-disk access / future operator. Asset: committed PII in deleted repos. | MEDIUM | M | **AGT-423** |
| **Peer-agentic-reviews triage-call PR-body injection (FUTURE).** When the Peer-agentic-reviews Haiku triage ships, the operator-controlled PR body feeds the LLM context. Build-time requirement: body must be delimited/escaped untrusted data, never concatenated into rules. `docs/plans/peer-agentic-reviews.md` | Attacker: PR author. Asset: triage disposition integrity. | MEDIUM | S | **AGT-412**³ |

² Appears as `trusted/security` LOW and `trusted/llm-security` MEDIUM —
taken at the higher rating, the two findings grouped into one ticket.

³ Not buildable today (Peer-agentic reviews unbuilt). The ticket gates
Peer-agentic-reviews Phase 4d; listed here so the requirement isn't lost.

### Already resolved this session

| Thread | Disposition |
|---|---|
| **Lockfile drift** — `package.json` 2.2.0 vs lock 2.1.1, `npm ci` fails (`trusted/supply-chain` MEDIUM). | **Fixed** — merge `4507fab2` (lock synced to 2.2.0, no transitive bumps). |

### LOW — inventoried, no per-thread ticket (per AC #4)

- **prompts-cache stale-lock steal race** (`trusted/security`,
  `src/server/prompts-cache.ts:273`) — two refreshes can both pass the
  lock; worst case is a failed/inconsistent refresh, not compromise. Fix:
  atomic-rename or `flock(2)`. Fold into AGT-417's prompts-cache work if
  convenient.
- **Webhook client-IP logging** (`trusted/privacy`,
  `src/server/http-server.ts:480`) — drop IP on happy path; gate
  rejected-peer logging behind an env flag.
- **Server short_name / fingerprint logging** (`trusted/privacy`,
  `src/server/http-server.ts:230`) — log numeric user_id by default;
  names behind `--verbose`. Pairs with AGT-422.
- **HEALTHCHECK probes only sshd** (`trusted/infra`,
  `server/Dockerfile:277`) — HTTP listener can crash while container
  reports healthy. Probe both ports, or add a supervisor (Phase 5).
- **Dual `@anthropic-ai/sdk` (0.81.0 + 0.96.0)** (`trusted/supply-chain`)
  — doubles future-CVE patch surface. `npm dedupe` blocked until
  `claude-agent-sdk` widens its peer dep; track upstream.

### Confirmed guarded — no action (named threads from AC #1)

The scan and audit agree these are sound; recorded so they aren't
re-investigated:

- **path_rules enforcement** (`src/lib/v4Trust.ts:755,934,999`) — globs
  anchored, metacharacters escaped, `**` vs `*` distinguished; `*` does
  not cross `/`. No traversal/bypass.
- **v4/v5 envelope verification** (`src/hooks/pre-receive.ts:371,697`) —
  explicit `schema_version` gating, v3 rejects v2/v1, v4 rejects
  schema < 5. No fail-open, no content-sniffing.
- **Signature-verification timing** (`src/lib/signing.ts:22`,
  `src/server/http-server.ts:465`) — Ed25519 via native `crypto.verify`
  (constant-time); webhook HMAC via `timingSafeEqual` after length check.
- **SSH-verb input validation** (`src/server/stamp-review.ts:91–95`) —
  strict per-field regexes (reviewer/org/repo/SHA/diff-sha256) validated
  before pipeline load and before any JSON parse; diff size cap + sha
  cross-check.
- **Revocation semantics** (`src/lib/trustedKeysManifest.ts`,
  `v4Trust.ts`) — manifest pinned at `base_sha`; intentional lenient
  revocation (future merges blocked, past attestations stand); snapshot
  recomputed canonically. No TOCTOU. The related **AGT-413** is
  belt-and-suspenders negative tests only — the audit found the
  migrate-existing whitelist structurally sound, so AGT-413 is LOW
  priority (lock the invariant against regression, not close a gap).

### INFO (good posture, keep)

- **MCP tool-name redaction default-on** (`src/lib/toolCalls.ts:65`) —
  hashed names on public mirrors preserve the audit invariant without
  leaking internal service inventory. Keep; document as the canonical
  pattern for future telemetry fields (covered by AGT-415's README work).
- **Agent topology** — consider a `docs/agent-architecture.md` mapping
  diff → fenced message → LLM → submit_verdict → DB → merge envelope →
  server signature → manifest verification. Nice-to-have; not ticketed.

## Sequenced landing order

Highest-severity first; each independently landable through the normal
stamp flow with `npm run test:unit` green. Server-side and client-side
threads are interleaved by severity, not by subsystem.

1. **AGT-414** (HIGH) — H1 residual merge-time defenses.
2. **AGT-415** (HIGH) — diff-to-Anthropic consent + data_flow.
3. **AGT-411** (HIGH) — `STAMP_PROMPTS_DIR` prod refusal.
4. **AGT-418** (MED, S) — reviewer `.git/`/`.stamp/` denylist. *(quick, high-value sandbox tightening)*
5. **AGT-417** (MED, S) — prompts-cache git hardening (+ LOW lock race).
6. **AGT-416** (MED, S) — invite `?insecure=1` removal.
7. **AGT-419** (MED) — WebFetch query-string allowlist.
8. **AGT-420** (MED) — SSH-verb rate limit + verdict cache.
9. **AGT-421** (MED) — reviewer prose retention.
10. **AGT-422** (MED) — SSH key-comment PII (+ LOW short_name logging).
11. **AGT-423** (MED) — trash retention sweep.
12. **AGT-412** (MED) — Peer-agentic-reviews PR-body injection — **blocked** on Peer-agentic-reviews Phase 4d; lands as a build-time requirement there.
13. **AGT-413** (LOW) — migrate-existing whitelist negative tests — opportunistic.

LOW items 4f-style (logging, HEALTHCHECK, SDK dedupe) fold into the
nearest related ticket or land as a small batch when convenient.

## Dependencies & out of scope

- **Soft dependency (satisfied path):** AGT-407 Shape 2/3 removal —
  hardening lands cleaner afterward but none of these threads touch the
  removed `--pr-mode` surface.
- **No production code in this ticket** — doc + the AGT-411…AGT-423
  follow-on tickets only (AC #6).
- **Architecture unchanged** — every thread is a bounded hardening of the
  existing surface; none re-opens the attestation envelope, signing, or
  trust-manifest design.
