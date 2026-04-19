# Contributing to stamp-cli

Thanks for your interest. This doc covers local dev setup, the build + check loop, and how pull requests are handled.

## Quick dev loop

stamp-cli is a Node 22.5+ TypeScript CLI. Dev is straightforward:

```sh
git clone https://github.com/OpenThinkAi/stamp-cli.git
cd stamp-cli
npm install
npm run build       # tsup produces dist/
npm run typecheck   # tsc --noEmit; no tolerance for ts errors
npm link            # makes `stamp` resolve to your working copy globally
```

After `npm link`, `stamp --help` anywhere on your system invokes the build you just produced. `npm run build` again after any change.

### Running against a real repo

stamp-cli is per-repo: initializing a new stamp-protected project is the normal way to exercise it:

```sh
cd /tmp
mkdir scratch && cd scratch
git init -b main
stamp init
# scaffolds .stamp/, generates ~/.stamp/keys/, creates .git/stamp/state.db
```

From there, anything in the [README](./README.md) and [DESIGN.md](./DESIGN.md) quick-starts applies.

## Code style

- **Build-first**, as described in `docs/personas.md` and encoded in the `standards` reviewer. Resist premature abstractions, speculative generality, and defensive code at internal boundaries.
- **Strict TypeScript**: `strict: true` + `noUncheckedIndexedAccess: true` are required to stay on. Don't relax them to silence a problem; fix the types.
- **Node-native idioms**: prefer `node:` prefix on built-ins (`import { readFileSync } from "node:fs"`), prefer `execFileSync` / `spawnSync` over `exec` (argument safety), prefer top-level `await` over callbacks.
- **No `any`** outside genuine external boundaries. `unknown` + a type guard is almost always the right move.
- **Cross-platform**: development and CI run on both macOS and Linux. BSD-vs-GNU tool differences (`sed -i ''`, `find -maxdepth` argument position, etc.) will break on the other platform. Prefer node-native helpers.

## Pull request process

### If you're an outside contributor

1. Fork `OpenThinkAi/stamp-cli` on GitHub
2. Create a feature branch
3. Make your change with a focused scope (one thing per PR)
4. Run `npm run build && npm run typecheck` — both must pass
5. Push to your fork, open a PR against `main`
6. Maintainers will run the stamp review cycle locally before merging (see next section)

Your PR doesn't need to be signed through stamp for submission. Maintainers carry the signing key for this repo and will merge through the stamp gate themselves.

### If you're a maintainer (or working from a fork set up as a stamp-protected remote)

The repo is stamp-gated on `main`. Every merge must satisfy:

- **Required reviewers** (defined in `.stamp/config.yml`): `security`, `standards`, `product`. The prompts live in `.stamp/reviewers/`.
- **Required checks**: `npm run build` + `npm run typecheck` on the post-merge tree.
- **Ed25519 signature** from a key whose public half is in `.stamp/trusted-keys/`.

The flow:

```sh
git checkout -b my-change
# ... implement ...
stamp review --diff main..my-change
stamp status --diff main..my-change   # exit 0 means gate is open
git checkout main
stamp merge my-change --into main     # runs checks, signs merge commit
git push                              # push to GitHub (not stamp-gated for OSS repo currently)
```

If a reviewer returns `changes_requested`, read its prose, patch the code, commit, and re-run `stamp review`. Approvals are SHA-bound — any new commit on the feature branch invalidates prior approvals and requires a re-review.

See [`docs/troubleshooting.md`](./docs/troubleshooting.md) for common failure modes with concrete fixes.

## Scope norms

stamp-cli is deliberately small. Non-goals that won't be accepted:

- Web UI in core (the tool is CLI/TUI only; `stamp serve` is a thin read-only API for external frontends)
- CI/CD integration (the `required_checks` gate is local-execution attested; we are not a build farm)
- Human-review comment threads or multi-user PR collaboration (use GitHub for that)
- Git server implementation (we depend on stock `git` + `sshd`)

If your PR adds one of these, it'll be declined. Propose a design discussion in an issue first if you think the project should move in that direction.

## Reviewer prompt changes

Changing a file in `.stamp/reviewers/` is a meaningful PR — it alters the project's review policy going forward. Include rationale in the commit message: what you noticed the reviewer missing or over-flagging, and how the prompt change addresses it.

Use `stamp reviewers test <name> --diff <revspec>` against multiple diffs (both clean and deliberately problematic) before proposing a prompt change. That command is built for exactly this iteration loop.

See [`docs/personas.md`](./docs/personas.md) for prompt-writing guidance.

## Release process

- Version in `package.json` is the source of truth.
- Publishing is automated: `.github/workflows/publish.yml` fires on every push to `main` (including the stamp server's post-receive mirror) and publishes to npm **only if** `package.json` declares a version that isn't already on the registry. So the maintainer flow is:
  1. Bump `package.json` version in a branch.
  2. `stamp review → stamp merge → stamp push main` as usual.
  3. The mirror carries the commit to GitHub; the publish workflow picks up the new version and runs `npm publish` + creates a `v<version>` git tag.
- Every non-bump merge safely no-ops the publish step.
- Alpha/beta/rc versions (e.g., `0.2.0-alpha.0`) publish under the `alpha` dist-tag.

The workflow requires an `NPM_TOKEN` secret (npm Automation token, publish scope on `stamp-cli`) in repo Settings → Secrets and variables → Actions.

Current state: we are pre-1.0. Breaking changes are allowed between minor versions.

## Code of conduct

This project follows the [Contributor Covenant](./CODE_OF_CONDUCT.md). By participating, you agree to uphold it.

## Questions

Open a GitHub issue. For non-trivial design questions, propose the change in an issue before opening a PR so we can align on scope first.
