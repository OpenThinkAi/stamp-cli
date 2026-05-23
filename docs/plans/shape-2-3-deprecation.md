# Plan — Shape 2/3 deprecation removal

Status: ready · Owner: maintainer · Ticket: AGT-407

> Precursor to the actual removal tickets. This doc inventories the full
> Shape 2 (mirror-mode PR) and Shape 3 (local-only deployment-topology
> branding) surface, proposes a per-PR cut sequence each individually
> landable through the normal stamp flow, and drafts the breaking-change
> CHANGELOG entry. It does **not** remove any code itself.
>
> Hard dependency: **[AGT-406](./shape-cleanup-coverage-baseline.md)**
> (coverage baseline) must be landed before any removal PR this doc
> spawns. AGT-406 landed on `main` as merge `fcd90723` on 2026-05-23 —
> dependency satisfied.
>
> Companion: [`docs/plans/shape-5-peer-review.md`](./shape-5-peer-review.md)
> (the Phase 4 work this cleanup unblocks).

## Why this exists

Phase 2 of the Shape 5 rollout deprecates two deployment topologies:

- **Shape 2 (mirror-mode PR)** — `stamp init --pr-mode` scaffolds a
  `.github/workflows/stamp-mirror.yml` Action that mirrors every GitHub
  push *into* the stamp-server for server-attested review. Superseded by
  **Shape 4** (server-attested without code transfer), which delivers the
  same attestation guarantee without forcing operators to mirror their
  full source. Shape 2 is removed **entirely** — flag, scaffold, template,
  docs, tests.
- **Shape 3 (local-only)** — the *deployment-topology branding* for
  running stamp without server enforcement. This is a **branding-only**
  deprecation: the numbered-"Shape 3" framing goes from the docs, but the
  underlying capability (`stamp review --plan` / `--headless`, and the
  honest local-only AGENTS.md content) **stays**.

Cutting either without a written inventory + sequenced cut plan risks
orphan references and silent regressions — a Shape 2 path that's quietly
load-bearing for a Shape 4 case, or a "Shape 3" doc strip that
accidentally removes the surviving `--plan`/`--headless` command surface.

## Two scoping corrections vs. the AGT-407 ticket

The original ticket framing (AC #1, AC #2) needs two corrections that
this plan adopts. Both narrow the blast radius; both are called out so the
divergence is deliberate, not accidental.

### Correction 1 — server-side post-receive mirror is OUT of scope

AGT-407 AC #1 lists "server-side mirror handling" under Shape 2 removal.
**That is the wrong mirror.** There are two unrelated mirror mechanisms:

| Mechanism | Direction | Topology | Disposition |
|---|---|---|---|
| `stamp init --pr-mode` GitHub Action (`stamp-mirror.yml`) | GitHub → stamp-server | **Shape 2** | **REMOVE** |
| post-receive hook `.stamp/mirror.yml` (`mirrorPush.ts`, `mirrorStatus.ts`) | stamp-server → GitHub | Shape 1 / Shape 4 (server-primary) | **KEEP** |

The post-receive mirror is **load-bearing for the current server-gated
topology** — including this very repo. Evidence: a `stamp push main`
against `origin` (the Railway bare repo) emits
`remote: mirror: pushed branch main → github.com/OpenThinkAi/stamp-cli`.
Removing it would break stamp-cli's own GitHub mirror. It is therefore
explicitly **excluded** from this removal. `src/lib/mirrorPush.ts`,
`src/lib/mirrorStatus.ts`, `src/hooks/post-receive.ts` mirror logic, and
their tests (`tests/post-receive.test.ts`, `tests/mirrorPush.test.ts`,
`tests/perRepoKey.test.ts`) all stay untouched.

### Correction 2 — the `AgentsMdMode` enum collapse is NOT part of Shape 3 branding removal

AGT-406's working doc anticipated that AGT-407 would "collapse the
`AgentsMdMode` enum (remove the `local-only` variant)." On inspection,
**that is a behavioral change, not branding**, and this plan recommends
**against** it as part of the cleanup.

`resolveMode()` (`src/commands/init.ts:767`) returns `effectiveMode:
"local-only"` for forge-direct / unset / unknown remotes, which drives
`ensureAgentsMd(repoRoot, "local-only")` to write *honest* AGENTS.md
content — i.e. "the committed `.stamp/` config is NOT enforced; the agent
following these instructions is the gate." That honesty is the whole
point of the `local-only` body (`STAMP_AGENTS_SECTION_LOCAL_ONLY`,
`src/lib/agentsMd.ts:158`). It is the same surviving capability as
`--plan`/`--headless`, not the deprecated numbered topology.

Collapsing the enum would force a single `server-gated` AGENTS.md body
onto repos that *aren't* server-gated — making the generated guidance
lie about enforcement. That regresses behavior the
`tests/agentsMdEnsure.test.ts` characterization suite (AGT-406) was
written to protect.

**Decision:** Shape 3 removal in this plan is **docs/branding only**. The
`AgentsMdMode` enum, the `local-only` body, and `resolveMode()`'s
local-only branches all **stay**. If a future ticket wants to rename the
enum value (e.g. `local-only` → `no-server`) for clarity, that is a
separate, independently-reviewed refactor gated on the `resolveMode`
export follow-up — not this cleanup. Filed as a note under
"Follow-ups," below.

---

## Shape 2 removal inventory (REMOVE)

### S2-code — `src/commands/init.ts` + `src/index.ts`

- `src/index.ts:142` — `--pr-mode` flag definition.
- `src/index.ts:146` — `--pr-mode-force` flag definition.
- `src/index.ts:143` — `STAMP_MIRROR_KEY` mention in `--pr-mode` help.
- `src/commands/init.ts:840` — `export const PR_MODE_WORKFLOW_PATH`.
- `src/commands/init.ts:881–902` — `maybeWritePrModeMirrorWorkflow()`.
- `src/commands/init.ts:918–963` — `derivePrModeSubstitution()`.
- `src/commands/init.ts:982–1076` — `renderMirrorWorkflow()` (template
  body; lines 995–998 carry the "Shape 2 (PR mode) auto-mirror" comment;
  1000/1029/1040 carry `STAMP_MIRROR_KEY`).
- `src/commands/init.ts:1105–1207` — `printPrModeWalkthrough()`.
- `src/commands/init.ts:276` — call site `maybeWritePrModeMirrorWorkflow(...)`.
- `src/commands/init.ts:405` — call site `printPrModeWalkthrough(prModeResult)`.
- `src/commands/init.ts:132, 272` — `STAMP_MIRROR_KEY` comments.
- `src/commands/init.ts` — the `opts.prMode` / `opts.prModeForce` wiring
  in `runInit` (around 270–280, 405) and any `prModeResult` plumbing.

### S2-tests

- `tests/initPrModeMirrorWorkflow.test.ts` — **delete the file**
  (428 lines; the only dedicated Shape 2 suite). Covers
  `derivePrModeSubstitution`, `maybeWritePrModeMirrorWorkflow`,
  `renderMirrorWorkflow`, `STAMP_MIRROR_KEY` injection/guard.
- `tests/migrationBootstrap.test.ts:197, 271, 407` — Shape 2 strings in a
  Shape 2→4 migration harness. Re-label the harness, **keep the test**
  (it exercises the surviving migration path, not the `--pr-mode`
  scaffold).
- `tests/adminSign.test.ts:828` — "auto-detect picks pr-mode when branch
  rule has review_server" — verify against the surviving auto-detect
  behavior; this is about `review_server` branch rules (Shape 4), not the
  `--pr-mode` flag. Keep unless it asserts the removed flag.

### S2-docs

- `README.md:54` — table row `| **PR mode** (Shape 2) | ... |`.
- `README.md:93–112` — section `### PR mode (Shape 2)` (delete).
- `README.md:105` — `# + stamp-mirror.yml (--pr-mode opt-in)` callout.
- `docs/migration-1.x-to-2.x.md:73–79` — `### Shape 2 — ...` summary.
- `docs/migration-1.x-to-2.x.md:260–340` — `## Upgrade walkthrough —
  Shape 2 (PR mode)` (replace with the migration note in this plan).
- `docs/migration-1.x-to-2.x.md:282, 304, 422` — `STAMP_MIRROR_KEY` /
  `stamp-mirror.yml` references.
- `docs/ROADMAP.md:34` — PR-mode mirror scaffold bullet.
- `docs/plans/server-attested-reviews.md:551` — `STAMP_MIRROR_KEY`
  reference (design doc; update or annotate as historical).

### S2-changelog

CHANGELOG mentions are **historical record** and stay as written
(they describe shipped releases). The *new* removal release gets a fresh
breaking-change entry (drafted below). Do not rewrite history;
`CHANGELOG.md:63, 89, 107, 127, 143, 171, 252–254, 294, 306` stay.

---

## Shape 3 branding inventory (REMOVE branding; KEEP commands)

Strip the numbered-"Shape 3" / "Local-only mode as a deployment topology"
framing. Reframe survivors as "running without a server" — a capability,
not a numbered Shape.

### S3-docs (branding to remove / reframe)

- `README.md:55` — table row `| **Local-only** (Shape 3, no trust) | ...`
  — drop the "(Shape 3, no trust)" label; keep the row describing the
  no-server capability.
- `README.md:248–250` — `--mode is server-gated|local-only` help comment
  — keep (describes the live flag), drop any "Shape 3" framing.
- `README.md:548–556` — comparison table "Local-only — weakest
  enforcement" — keep the capability description, drop the Shape number.
- `docs/migration-1.x-to-2.x.md:81–87` — `### Shape 3 — Local-only` —
  reframe heading to "Local-only (no server)".
- `docs/migration-1.x-to-2.x.md:342–359` — `## Local-only operators` —
  keep (operator guidance for the surviving capability); drop Shape
  numbering.
- `CHANGELOG.md:295` — table row `| **Local-only** (Shape 3) | ...` —
  historical; stays.

### S3-keep (DO NOT TOUCH — surviving command surface)

These are the `--plan` / `--headless` capability and its honest
local-only content. Removal authors must **not** touch them:

- `src/commands/review.ts` — `--plan` / `--headless` implementations.
- `src/lib/agentsMd.ts:37` — `AgentsMdMode` enum (KEEP, see Correction 2).
- `src/lib/agentsMd.ts:158–245` — `STAMP_AGENTS_SECTION_LOCAL_ONLY` (KEEP).
- `src/commands/init.ts:767–832` — `resolveMode()` local-only branches (KEEP).
- `tests/reviewPlan.test.ts`, `tests/headlessReviewer.test.ts`,
  `tests/headlessReviewCommand.test.ts`, `tests/stampReviewSkill.test.ts`,
  `tests/agentsMdEnsure.test.ts`, `tests/validators.test.ts:606–663` (KEEP).
- `skills/stamp-review.md`, `docs/local-only-mode.md` — keep the command
  contract; drop only "Shape 3" branding if present.

---

## Per-PR cut sequence

Each PR is independently landable through the normal stamp flow with
`npm run test:unit` green at every step. Ordered so code+tests move
together (suite stays green) and docs follow.

| PR | Scope | Tests | Notes |
|---|---|---|---|
| **C1** | Shape 2 code cut: remove `--pr-mode`/`--pr-mode-force` flags (`index.ts`), the four scaffold helpers + `PR_MODE_WORKFLOW_PATH` + their `runInit` wiring (`init.ts`), and **delete** `tests/initPrModeMirrorWorkflow.test.ts`. | Suite green (deleted file's cases go with it). Re-label `migrationBootstrap.test.ts` Shape 2 strings. | The behavioral cut. Largest diff. Verify `adminSign.test.ts:828` still passes (it tests `review_server` auto-detect, not the flag). |
| **C2** | Shape 2 docs cut: README §"PR mode (Shape 2)" + table row; `docs/ROADMAP.md` bullet; `docs/plans/server-attested-reviews.md` annotation. | n/a (docs). Pass `--allow-large` if the diff trips the 200KB cap. | Docs-only; lands after C1 so docs never describe a removed flag for long. |
| **C3** | Shape 2 migration doc: replace the `## Upgrade walkthrough — Shape 2 (PR mode)` section + `### Shape 2` summary with the **migration note** (below) pointing operators at Shape 4. | n/a (docs). | Separated from C2 so the operator-facing migration note gets focused review. |
| **C4** | Shape 3 branding strip: README + `docs/migration-1.x-to-2.x.md` "Shape 3"/numbered-topology labels reframed to "local-only (no server)". **No code.** | n/a (docs). | Smallest, safest. Explicitly leaves `--plan`/`--headless` and the `AgentsMdMode` enum untouched. |

Optional release PR (**C5**, when cutting the version): land the
breaking-change CHANGELOG entry (below) + version bump. Kept separate so
the release is its own reviewable unit.

### Per-cut verification (from AGT-406)

1. Run `npm run test:unit` after every cut. A red
   `tests/agentsMdEnsure.test.ts` is the surgical signal that something
   touched the `AgentsMdMode` surface that this plan said to leave alone.
2. The `resolveMode` follow-up is **not** a blocker for C1–C4 (none of
   them touch `resolveMode`). It only matters if a later enum-rename
   ticket is taken up.
3. Re-measure coverage at the end of the sequence (same command as the
   AGT-406 baseline) to confirm no new gaps.

---

## Migration note for Shape 2 operators (drop-in for C3)

> ### Shape 2 (mirror-mode PR) was removed in vNEXT
>
> `stamp init --pr-mode` and the scaffolded
> `.github/workflows/stamp-mirror.yml` are gone. Shape 2 mirrored your
> full source into the stamp-server on every push; **Shape 4
> (server-attested without code transfer)** delivers the same
> server-signed PR attestation without that mirror.
>
> **If you're on Shape 2 today:**
> 1. Migrate to Shape 4 — see [Shape 4 walkthrough](./migration-1.x-to-2.x.md).
> 2. Delete `.github/workflows/stamp-mirror.yml` from your repo.
> 3. Remove the `STAMP_MIRROR_KEY` org secret (no longer used).
> 4. The `stamp/verify-attestation@v1` required check stays — Shape 4
>    uses the same PR-attestation verification.
>
> No attestation history is lost: existing signed merges verify
> unchanged.

(C3 should verify the existing Shape 2 → Shape 4 path in
`migration-1.x-to-2.x.md` is clean and operator-actionable before
deleting the Shape 2 walkthrough — AC #4.)

---

## CHANGELOG entry draft (for C5 / the release)

```markdown
## [vNEXT] — breaking changes

### Removed
- **Shape 2 (mirror-mode PR) deployment topology.** `stamp init
  --pr-mode` and `--pr-mode-force`, the scaffolded
  `.github/workflows/stamp-mirror.yml`, and the `STAMP_MIRROR_KEY`
  org-secret flow are removed. Shape 2 is superseded by **Shape 4**
  (server-attested reviews without code transfer), which provides the
  same server-signed PR attestation without mirroring your source into
  the stamp-server.

  **Migration:** move to Shape 4 (see the migration guide), delete
  `.github/workflows/stamp-mirror.yml`, and drop the `STAMP_MIRROR_KEY`
  secret. The `stamp/verify-attestation@v1` required check is unchanged.
  Existing signed merges continue to verify.

### Changed
- Documentation no longer brands the no-server / local-only path as
  "Shape 3." The capability is unchanged — `stamp review --plan` and
  `stamp review --headless` work exactly as before; only the
  numbered-topology framing was retired for clarity.
```

(Rationale to include in the release notes: the numbered-Shape taxonomy
collapsed to the two topologies operators actually deploy — server-gated
and the no-server local path — plus Shape 4 for GitHub-primary teams.
Shape 2's full-source mirror was the friction Shape 4 was built to
remove.)

---

## Dependencies & follow-ups

- **Hard dependency (satisfied):** AGT-406 coverage baseline — landed
  `fcd90723`.
- **Follow-up (optional, separate ticket):** add `export` to
  `resolveMode()` (`src/commands/init.ts:767`) then characterize it
  (`tests/initResolveMode.test.ts`). Trivially safe (pure function, no
  I/O). Only needed if an enum-rename refactor is later taken up.
- **Explicitly deferred (NOT this cleanup):** collapsing/renaming the
  `AgentsMdMode` `local-only` variant. See Correction 2. If pursued, it
  is its own behavioral PR gated on the export follow-up, with the
  honest-AGENTS.md-content invariant preserved.

## Out-of-scope reminder

- Post-receive `.stamp/mirror.yml` server→GitHub mirror: **untouched**.
- `--plan` / `--headless` command surface: **untouched**.
- `AgentsMdMode` enum + `local-only` body + `resolveMode()`: **untouched**.
- Attestation envelope, signing, trust manifest: **untouched**.
- Historical CHANGELOG entries: **not rewritten**.
