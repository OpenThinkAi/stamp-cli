# Coverage baseline + gap-fill — pre Shape 2/3 cleanup

Status: complete · Owner: maintainer · Ticket: AGT-406

> Working doc landed under `stamp-cli-hardening`. Companion to
> [`docs/plans/shape-5-peer-review.md`](./shape-5-peer-review.md). The
> Shape 2/3 cleanup work itself lives in AGT-407 (per-PR removal plan);
> this doc establishes the *test safety net* AGT-407's removal tickets
> land against.

## Why this exists

Before any Shape 2 (mirror-mode PR topology) or Shape 3 (local-only
deployment-topology branding) code can be cut from `stamp-cli`, the test
suite needs a measured baseline and at least minimal coverage on the
code paths the removal will touch. Otherwise a Shape 2 path that's
silently load-bearing for a Shape 4 case regresses without anything
turning red.

This doc captures: the baseline, the in-scope-for-removal inventory,
the gap-fill that landed, the post-fill numbers, and the one gap the
hard-constraints prevented us from closing here (with a recommended
follow-up).

## Methodology

- **Test runner:** `node --test --import tsx` (existing convention; no new
  dev deps).
- **Coverage:** Node's built-in `--experimental-test-coverage` (stable in
  Node 22; project requires `>=22.5.0`).
- **Suite scope:** unit tests only (`tests/*.test.ts`, ~70 files). The
  integration suite (`tests/integration/*.test.ts`, 2 files) is not
  included in this baseline — it covers reviewer/agent SDK behavior, not
  Shape-2/3 code paths.
- **Threshold for gap-fill:** **80% line / 70% branch** per AC #3.
  Below either threshold *and* in the Shape 2/3 removal inventory → gap
  candidate.

To regenerate either snapshot:

```sh
mkdir -p .coverage-baseline
node --test --import tsx --experimental-test-coverage \
  --test-reporter=spec --test-reporter-destination=.coverage-baseline/unit-spec.txt \
  --test-reporter=lcov --test-reporter-destination=.coverage-baseline/unit-lcov.info \
  'tests/*.test.ts'
```

The raw artifacts live under `.coverage-baseline/` (gitignored — they
are regeneratable from the suite at any time).

## Baseline (pre-fill)

**Suite:** 1227 tests, 0 failures.

**Overall:** 89.06% line · 79.85% branch · 80.17% function.

The full per-file table is in `.coverage-baseline/unit-spec.txt`. The
files below are the cross-section that intersects the Shape 2 + Shape 3
removal inventory (sourced from the AGT-407 inventory pass):

| File | Line % | Branch % | Func % | In-scope because |
|---|---|---|---|---|
| `src/commands/init.ts` | **69.06** | 91.30 | **41.67** | `--pr-mode` flag, `maybeWritePrModeMirrorWorkflow`, `derivePrModeSubstitution`, `renderMirrorWorkflow`, `printPrModeWalkthrough`, and `resolveMode` all live here. Shape 2 *and* Shape 3 cleanup both touch this file. |
| `src/lib/agentsMd.ts` | 96.15 | 86.96 | **66.67** | Defines `AgentsMdMode = "server-gated" \| "local-only"` (Shape 3 enum) and the `STAMP_AGENTS_SECTION_LOCAL_ONLY` constant. AGT-407 collapses the enum. |
| `src/index.ts` | (unmeasured) | — | — | CLI flag definitions for `--pr-mode` / `--pr-mode-force` / `--mode`. Not imported by any test → never loaded → not measured. Out of gap-fill scope (see below). |
| `src/commands/attest.ts` | 86.99 | 64.86 | 95.24 | Comment-only Shape 2 references. Doc cleanup, not code-path removal. Out of gap-fill scope. |
| `src/commands/verifyPr.ts` | 85.99 | 54.63 | 94.74 | Same — comment-only. Out of scope. |
| `src/lib/trustAnchorPayload.ts` | 100.00 | 100.00 | 100.00 | Comment-only. Out of scope. |
| `src/lib/migrationBootstrap.ts` | 86.79 | 56.78 | 100.00 | Comment-only Shape 2 deadlock-context references. Out of scope. |
| `src/lib/remote.ts` | 85.47 | 77.78 | 66.67 | Comment-only. Out of scope. |
| `src/server/reviewPipeline.ts` | 99.89 | 85.71 | 100.00 | Comment-only. Out of scope. |
| `src/lib/verifyWorkflow.ts` | 100.00 | 100.00 | 100.00 | Mode-aware default comment ("forge-direct + local-only get the workflow"). Workflow generation itself stays; only the *Shape-3-as-topology* comment goes. Out of scope. |

**Why "comment-only" files are out of scope:** AGT-406 is about
catching *behavioral* regressions during code removal. Removing a
comment doesn't change behavior. AGT-407 handles the doc/comment
cleanup as part of its per-PR cut plan.

## Gap-fill scope (chosen targets)

Two files genuinely intersect Shape 2/3 *code paths* AND sit below
threshold:

1. **`src/commands/init.ts`** — line 69.06% / function 41.67%. The
   helpers (`derivePrModeSubstitution`, `maybeWritePrModeMirrorWorkflow`,
   `renderMirrorWorkflow`) are well-tested in
   `tests/initPrModeMirrorWorkflow.test.ts`. The orchestration
   (`runInit` + `resolveMode`) is not.
2. **`src/lib/agentsMd.ts`** — function 66.67%. `injectStampSection` /
   `injectClaudeSection` are tested in `tests/validators.test.ts`. The
   filesystem-side wrappers `ensureAgentsMd` / `ensureClaudeMd` are
   not.

Planned new test files:

- `tests/initResolveMode.test.ts` — pin `resolveMode()` permutations.
- `tests/agentsMdEnsure.test.ts` — pin `ensureAgentsMd()` /
  `ensureClaudeMd()` per-mode filesystem behavior.

## What actually landed

### `tests/agentsMdEnsure.test.ts` (landed)

**12 `it()` cases across 9 `describe` blocks.** Pins:

- `ensureAgentsMd(repoRoot, "server-gated")` on empty repo — writes
  AGENTS.md with `STAMP_AGENTS_SECTION_SERVER_GATED` body. Asserts
  presence of `pre-receive hook` + `stamp push` framing.
- `ensureAgentsMd(repoRoot, "local-only")` on empty repo — writes
  with `STAMP_AGENTS_SECTION_LOCAL_ONLY` body. Asserts presence of
  `agent following these instructions is the gate` + `advisory mode`
  framing; asserts absence of server-gated framing.
- Idempotency: re-call produces no duplicate block (both modes).
- Re-injection: legacy stamp block gets `replaced`; no-marker file gets
  `appended`.
- Pre-existing user content outside the markers is preserved verbatim.
- Parallel `describe` block for `ensureClaudeMd` with the same coverage
  pattern.

**All four return-value enum cases** (`created` / `replaced` /
`appended` / `unchanged`) exercised for each wrapper.

**Why this matters for AGT-407:** the per-mode assertions are tied to
*literal text* from each mode's body. When AGT-407 collapses
`AgentsMdMode` (removes the `local-only` variant), the local-only
assertions go red exactly at the lines that need the removal author's
decision. Surgically locatable.

Standalone run: `12 tests, 0 failures`. Full-suite run included.

### `tests/initResolveMode.test.ts` (NOT landed — blocked, accepted gap)

`resolveMode()` at `src/commands/init.ts:767` is **not exported**. Of
the 8 exports in `init.ts`, none reach `resolveMode`. The only paths to
characterize it from a test file would be:

1. **Add a one-line export** — forbidden by AC #5 ("no production code
   changes ship in this ticket").
2. **Drive `runInit` end-to-end** — off-pattern (existing tests in this
   repo test small exported helpers, not the runInit orchestration),
   and brittle (`runInit` writes a keypair, state DB, `.stamp/` config,
   AGENTS.md, CLAUDE.md, attempts a git commit + push, attempts a `gh`
   ruleset apply, prints a deprecation banner — many side effects to
   wrangle, and resulting tests characterize `runInit`, not
   `resolveMode`).

Subagent that was dispatched to write the file bailed clean per
pre-authorized "happy with coverage as is if snags appear" guidance.

The function's full behavior matrix is documented inline below, so a
future follow-up can pick this up trivially:

| `userMode` | `remoteClass.shape` | result `effectiveMode` | warnings |
|---|---|---|---|
| `"local-only"` | any | `"local-only"` | none |
| `"server-gated"` | any (caller pre-rejects `forge-direct`) | `"server-gated"` | none |
| `undefined` | `"stamp-server"` | `"server-gated"` | none |
| `undefined` | `"forge-direct"` | `"local-only"` | 1 (`warning:` prefix) |
| `undefined` | `"unset"` | `"local-only"` | 1 (`note:` prefix) |
| `undefined` | `"unknown"` | `"local-only"` | 1 (`note:` prefix) |

The `--no-pr-check` flag does NOT feed into `resolveMode` (consumed
downstream by `maybeWriteVerifyWorkflow`). The hard-error case
(`--mode server-gated` + forge-direct origin) is intercepted by the
caller (`runInit`, lines 191–204), not by `resolveMode` itself.

**Recommended follow-up:** file a one-AC ticket "add `export` keyword
to `resolveMode()` in `src/commands/init.ts:767`", let it land via the
normal stamp flow, then file the `tests/initResolveMode.test.ts`
characterization ticket against the post-export surface. The export is
trivially safe — pure function, no I/O, no shell-out — and existing
test patterns make characterization a ~150 LOC file once the export
exists.

**Net effect on `src/commands/init.ts` coverage:** unchanged. 69.06%
line / 41.67% function remain. AGT-407 will need to lean on the
existing `tests/initPrModeMirrorWorkflow.test.ts` helpers (well-covered)
and accept that `runInit` orchestration changes will be human-reviewed
rather than test-caught. Acceptable for the scope of this cleanup; the
follow-up closes the gap properly.

## Before / after

| File | Metric | Baseline | Post-fill | Δ |
|---|---|---|---|---|
| `src/lib/agentsMd.ts` | line % | 96.15 | **100.00** | +3.85 |
| `src/lib/agentsMd.ts` | branch % | 86.96 | **94.59** | +7.63 |
| `src/lib/agentsMd.ts` | function % | 66.67 | **100.00** | +33.33 |
| `src/commands/init.ts` | line % | 69.06 | 69.06 | 0 (blocked) |
| `src/commands/init.ts` | function % | 41.67 | 41.67 | 0 (blocked) |
| **Overall src/ + server/** | line % | 89.06 | **89.11** | +0.05 |
| **Overall src/ + server/** | branch % | 79.85 | **79.97** | +0.12 |
| **Overall src/ + server/** | function % | 80.17 | **80.41** | +0.24 |

**Suite:** 1227 → 1233 tests, 0 failures throughout.

## Known limitations + follow-up

1. **`src/commands/init.ts` `resolveMode()`** — uncovered; export
   blocked by AC #5 of this ticket. See the recommended follow-up
   above. *Severity for AGT-407: low.* The Shape-2-removal cuts touch
   the helpers (well-tested) and the orchestration is small enough
   that human review catches regressions; the Shape-3-removal cut on
   `resolveMode` is the case where this matters most, and it should be
   gated on closing the follow-up first.
2. **`src/index.ts` flag definitions** (0% measured) — out of gap-fill
   scope by design. The `--pr-mode` / `--pr-mode-force` / `--mode`
   flag definitions are 5 lines of `commander.js` boilerplate. A
   regression here is "you deleted the flag but the impl still
   references it" — which the `init.ts` test surface catches via
   integration when the impl is wrong. Investing in CLI argv testing
   for these flags has low ROI on a 5-line surface that's about to be
   reduced.
3. **Integration suite (`tests/integration/*`) not measured** — these
   cover reviewer / Agent SDK behavior, not Shape-2/3 code. Adding
   them to the baseline would inflate run time substantially without
   moving the in-scope numbers. AGT-407 can re-include them if its cut
   sequence touches reviewer code, but that's unlikely on the
   inventory we have.

## How AGT-407 should consume this

When sequencing per-PR cuts for Shape 2/3 removal:

1. **Run the suite after every cut**: `npm run test:unit`. A failure
   in `tests/agentsMdEnsure.test.ts` is a surgical signal that the
   `AgentsMdMode` enum or per-mode body content changed in a way the
   removal author needs to update intentionally.
2. **Don't sweat the `resolveMode` follow-up first** *unless* the cut
   touches `resolveMode` itself. Most Shape 2 cuts (workflow
   scaffold, helper functions, README/CHANGELOG/migration sections)
   don't.
3. **Re-measure coverage at the end** of the cleanup PR sequence to
   confirm no new gaps were introduced. Same command as the baseline
   regen, above.
