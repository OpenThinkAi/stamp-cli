# Peer-agentic reviews: end-to-end validation runbook

**AGT-433** — Two/three-laptop end-to-end validation

**Time budget**: < 30 minutes for a prepared operator.

---

## Prerequisites

### Software

- `stamp` CLI >= 2.2.0 (`stamp --version`)
- `gh` CLI authenticated with your GitHub identity
- Node.js >= 22

### Test repository

Use `anglepoint-engineering/stamp-peer-review-validation` as the target repo.
Create it on GitHub if it does not exist; it needs at least one commit on `main`.

### Stamp server

A running stamp server with `STAMP_PEER_REVIEWS_ENABLED=1` set. Record the
server host:port:

```sh
STAMP_SERVER="<host>:<port>"
```

### Key setup and manifest membership

Each laptop/machine must have its own `~/.stamp/keys/ed25519` keypair registered
in the test repo's `.stamp/trusted-keys/manifest.yml` at `operator` capability.

```sh
# On each machine (if no key exists):
stamp keys generate

# On the machine that maintains the test repo:
stamp trust add <fingerprint> --name <machine-name> --capabilities operator
git -C <test-repo-path> add .stamp/trusted-keys/
git -C <test-repo-path> commit -m "chore: register <machine-name> for peer-review validation"
git -C <test-repo-path> push
```

The **author** machine (Machine A) must also be a registered `operator`.

### Peer-watch rules

Copy the appropriate fixture to `~/.stamp/peer-watch.md` on each reviewer machine:

- **Auto-post persona**: `test/fixtures/peer/peer-watch-auto-post.md`
- **Draft persona**: `test/fixtures/peer/peer-watch-draft.md`

For Tests 1–6, use the auto-post persona unless the test specifically calls for
draft behavior.

> **CAVEAT**: use `post_mode: draft` (not `dry-run`) to suppress GitHub posting
> in your peer-watch rules. `post_mode: dry-run` is declared in the triage schema
> but currently falls through to the real `gh pr review` call (AGT-452 will fix
> this). Until AGT-452 lands, `draft` is the only mode that reliably suppresses
> the GitHub post.

### Default review prompt

Copy the fixture to `~/.stamp/personal/peers/default.md` on each reviewer machine:

```sh
mkdir -p ~/.stamp/personal/peers
cp test/fixtures/peer/peers-default.md ~/.stamp/personal/peers/default.md
```

---

## Running the automated single-machine simulation (AC5/AC6)

Before running multi-machine tests, confirm the single-machine simulation passes:

```sh
npm test
```

The simulation (`tests/peerSim.test.ts`) runs with zero outbound network and
covers: seat-1 claim, seat-2 claim, self-collision (409), author-exclusion (403),
seats-full (409), re-review fanout, and cost-cap enforcement.

Expected: all `peerSim` tests pass. The output contains:
```
✔ AC5: re-review-requested delivered to both seat-holders via in-process fanout
✔ AC5: seat protocol via SSH verbs
✔ AC5: cost-cap enforcement
```

---

## Test 1 — Two-laptop basic review (AC8)

**Goal**: Machine B's listener posts a GitHub PR review under B's GitHub identity
within 5 minutes; Machine A's listener log shows author-exclusion (403).

### Machine A (author)

```sh
# 1a. Open a test PR (creates a branch, pushes, opens PR):
cd <test-repo-path>
git checkout -b test/peer-review-validation-$(date +%s)
echo "# peer review test $(date)" >> peer-review-test.md
git add peer-review-test.md
git commit -m "test: peer-review validation run"
git push origin HEAD

PR_URL=$(gh pr create --title "Peer-review validation run" --body "Validation PR for AGT-433" --head $(git rev-parse --abbrev-ref HEAD) --repo anglepoint-engineering/stamp-peer-review-validation)
echo "PR URL: $PR_URL"

# 1b. Open Machine A's listener (optional — validates author-exclusion):
stamp pr listen --org anglepoint-engineering --server "$STAMP_SERVER" --ws
```

**Expected on Machine A listener** (if running):
```
note: skipping event for PR #N — author matches own fingerprint
```

### Machine B (reviewer)

```sh
# Start listener before Machine A opens the PR:
stamp pr listen --org anglepoint-engineering --server "$STAMP_SERVER" --ws
```

**Expected on Machine B listener**:
```
⟳ subscribed (WS); listening for PR events
⟳ triaging event for PR #N
⟳ claimed seat 1; running review
⟳ running review with prompt "default"
✓ posted review to https://github.com/anglepoint-engineering/stamp-peer-review-validation/pull/N
```

### Pass criteria

- [ ] B's terminal shows `✓ posted review to <PR_URL>`
- [ ] GitHub PR shows a review comment under B's GitHub identity
- [ ] A's terminal (if running) shows `note: skipping event for PR #N — author matches own fingerprint`
- [ ] Elapsed: < 5 minutes from `stamp pr open` to GitHub review appearing

---

## Test 2 — Two-laptop draft mode (AC8)

**Goal**: B's listener writes a draft to `~/.stamp/drafts/<patch_id>.md` instead
of posting to GitHub.

### Setup

On Machine B, update `~/.stamp/peer-watch.md` to use draft mode for this repo:
```
copy test/fixtures/peer/peer-watch-draft.md → ~/.stamp/peer-watch.md
```
Then re-open the listener (restart it so the new rules load).

### Steps

Repeat Test 1 steps (open a new PR from Machine A). This time B's listener
should write a draft file.

**Expected on Machine B listener**:
```
⟳ triaging event for PR #N
⟳ claimed seat 1; running review
⟳ saved draft for PR #N to ~/.stamp/drafts/<patch_id>.md
```

### Pass criteria

- [ ] `ls ~/.stamp/drafts/` shows a new `<patch_id>.md` file
- [ ] File content is a valid markdown review
- [ ] No GitHub review posted for this PR
- [ ] Elapsed: < 5 minutes

---

## Test 3 — Three-laptop seat capacity (AC9)

**Goal**: Two of three reviewers (B, C) receive primary seat assignments;
D's `claim_seat: if_available` claim is logged as "seats full". If you only
have two physical machines, run Machine C's listener on Machine B using a
different keypair via `--key` (if supported) or in a separate terminal with
a different `STAMP_KEYS_DIR`.

### Setup

- Machine B: auto-post peer-watch rules, `~/.stamp/personal/peers/default.md`
- Machine C: same as B
- Machine D: peer-watch with `claim_seat: if_available` (default), auto-post

All three machines must have their keys in the test repo manifest at `operator`.

### Steps

```sh
# Machine A: open a new PR
stamp pr open --pr <PR_URL> --server "$STAMP_SERVER"
```

On Machines B, C, D (listeners started before Machine A broadcasts):
```sh
stamp pr listen --org anglepoint-engineering --server "$STAMP_SERVER" --ws
```

**Expected**:
- Machine B: `⟳ claimed seat 1` then `✓ posted review`
- Machine C: `⟳ claimed seat 2` then `✓ posted review`
- Machine D: `note: seats full for PR #N; skipping`

### Pass criteria

- [ ] Machine B terminal shows `claimed seat 1`
- [ ] Machine C terminal shows `claimed seat 2`
- [ ] Machine D terminal shows `seats full`
- [ ] GitHub PR shows exactly two review comments (from B and C identities)
- [ ] Elapsed: < 10 minutes

---

## Test 4 — Re-review ping (AC10)

**Goal**: `stamp pr ping` causes B and C (prior seat-holders) to receive
`re-review-requested` and post fresh GitHub PR reviews.

**Prerequisites**: Test 3 completed with B and C as seat-holders on the same PR.

### Steps

```sh
# Machine A: ping the PR (re-review-requested broadcast)
PATCH_ID="<patch_id from Test 3>"
stamp pr ping --patch-id "$PATCH_ID" --server "$STAMP_SERVER"
```

Ensure B and C listeners are still running.

**Expected on B and C terminals**:
```
⟳ triaging event for PR #N
⟳ claimed seat <N>; running review
✓ posted review to <PR_URL>
```

**Expected on Machine A** (pr ping output):
```
re-review-requested: 2 seat-holder(s) notified
```

### Pass criteria

- [ ] B's and C's terminals show new `✓ posted review` entries
- [ ] GitHub PR shows fresh review comments from both identities
- [ ] `stamp pr ping` exits 0 with "2 seat-holder(s) notified" output
- [ ] Elapsed: < 5 minutes from ping to both reviews appearing

---

## Test 5 — Cost-cap enforcement (AC11)

**Goal**: First review runs to completion; second review is skipped with
"Daily review cap ... reached" in the log and a desktop notification.

### Setup

On Machine B, update `~/.stamp/peer-watch.md` to set a $0.01 cap:
```yaml
claim_seat: if_available
post_mode: auto-post
prompt: default
cost_cap_usd: 0.01
```

Restart B's listener so the new rules load.

### Steps

```sh
# Machine A: open two PRs in quick succession
stamp pr open --pr <PR_URL_1> --server "$STAMP_SERVER"
stamp pr open --pr <PR_URL_2> --server "$STAMP_SERVER"
```

**Expected on Machine B terminal (first PR)**:
```
⟳ triaging event for PR #N
⟳ claimed seat 1; running review
✓ posted review to <PR_URL_1>
```

**Expected on Machine B terminal (second PR)**:
```
⟳ triaging event for PR #M
note: triage decision is skip for PR #M; not claiming seat
```

A desktop notification "stamp peer / Daily review cap ($0.01) reached — skipping PR #M"
should appear on Machine B.

### Pass criteria

- [ ] First PR review appears on GitHub under B's identity
- [ ] Second PR listener log shows `triage decision is skip`
- [ ] Desktop notification appears on Machine B with "Daily review cap" message
- [ ] `~/.stamp/peer-watch.log` last entry shows `reason: "daily cap hit"` for the second PR
- [ ] Elapsed: < 5 minutes

---

## Test 6 — Author-exclusion and self-collision (AC12)

**Goal**: Author's listener shows `403 author-cannot-claim-own-pr`;
self-collision attempt shows `409 already-holds-other-seat`.

### Steps

```sh
# Machine A: run the listener while also being the PR author
stamp pr listen --org anglepoint-engineering --server "$STAMP_SERVER" --ws &
LISTENER_PID=$!

# Open a PR from Machine A
stamp pr open --pr <PR_URL> --server "$STAMP_SERVER"
```

**Expected on Machine A listener (author-exclusion)**:
```
note: skipping event for PR #N — author matches own fingerprint
```

For self-collision (Machine B has already claimed seat 1):
- Machine B claims seat 1 on a PR.
- Run a second instance of the listener on Machine B's same key. It should also
  try to claim a seat and fail.

**Expected on second Machine B terminal**:
```
note: already holding another seat (already_holds_other_seat); skipping PR #N
```

### Pass criteria

- [ ] Machine A's listener log shows `author matches own fingerprint` (not `claimed seat`)
- [ ] No GitHub review posted from Machine A's identity
- [ ] Second Machine B instance shows `already_holds_other_seat`
- [ ] Elapsed: < 5 minutes

---

## Pass criteria checklist (summary)

Complete all six tests and confirm each criterion:

- [ ] **Test 1**: GitHub PR review posted under B's GitHub identity; A's log shows author-exclusion
- [ ] **Test 2**: Draft file at `~/.stamp/drafts/<patch_id>.md`; no GitHub review posted
- [ ] **Test 3**: `seat 1` and `seat 2` assigned; third listener logs `seats full`; two GitHub reviews appear
- [ ] **Test 4**: Both B and C post fresh reviews after ping; A's `stamp pr ping` exits 0
- [ ] **Test 5**: First review runs; second is skipped with `daily cap hit` log + desktop notification
- [ ] **Test 6**: `author matches own fingerprint` and `already_holds_other_seat` log lines present

Total elapsed time: _______ minutes (target: < 30)

**Verdict** (circle one): **SHIPPABLE** / BLOCKED (list failing tests)

---

## Appendix: architecture notes

The peer-review loop is a **hybrid transport**:

- **Event delivery** (server → listeners) rides the WebSocket endpoint `/peer/listen`
  via `connectWsTransport` in `prListen.ts`. Use `--ws` on all `stamp pr listen`
  invocations during these tests.
- **Seat protocol** (claim/heartbeat/release/re-review) rides SSH subprocess verbs
  (`src/server/claim-seat.ts`, `src/server/re-review-request.ts`, etc.). These are
  short-lived processes; the seat assignments persist in the server's SQLite DB.
- **WS `handleWsMessage`** verifies signatures and operator capability for incoming
  messages but does NOT call `claimSeatTx` directly — seat-claim is SSH-verb-only
  in V1 (AGT-453 will add WS seat-claim).

**Descoped items** (do not test in this runbook — separate tickets):
- `claim_seat: always` extras-post path → AGT-451
- `post_mode: dry-run` → AGT-452 (use `draft` instead)
- Seat-claim over WS → AGT-453
