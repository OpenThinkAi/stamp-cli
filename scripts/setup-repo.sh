#!/usr/bin/env bash
#
# setup-repo.sh — operator bootstrap for a stamp-protected bare git repo.
#
# Run this on the server (or anywhere you're provisioning a bare repo).
# It:
#   1. Creates a bare repo
#   2. Installs the stamp-verify pre-receive hook
#   3. Seeds an initial commit with .stamp/config.yml + trusted key + reviewer(s)
#
# Because the seed commit is written by local git operations (not a push),
# it bypasses the hook — which is exactly what DESIGN.md "Bootstrap" requires.
# After this, every subsequent push is verified normally.
#
# Usage:
#   setup-repo.sh <repo-dir> <hook-script> <trusted-pub-key> [<seed-stamp-dir>]
#
# Example (default placeholder seed):
#   setup-repo.sh /srv/git/myproject.git \
#                 /path/to/stamp-cli/dist/hooks/pre-receive.cjs \
#                 ~/.stamp/keys/ed25519.pub
#
# Example (project-specific seed — operator brings the real reviewers):
#   setup-repo.sh /srv/git/myproject.git \
#                 /path/to/stamp-cli/dist/hooks/pre-receive.cjs \
#                 ~/.stamp/keys/ed25519.pub \
#                 /tmp/myproject-stamp-seed
#
# Arguments:
#   <repo-dir>         Path where the bare repo will be created
#   <hook-script>      Path to the stamp-verify hook (dist/hooks/pre-receive.js)
#   <trusted-pub-key>  Path to an Ed25519 public key PEM file — the first
#                      trusted signer for this repo
#   <seed-stamp-dir>   Optional. Path to a directory whose contents will be
#                      copied into the seed commit's `.stamp/` directory. Must
#                      contain at minimum `config.yml` and `reviewers/` (with
#                      at least one prompt file matching what config.yml
#                      requires). When omitted, a placeholder example reviewer
#                      is seeded — fine for trying stamp out, but you'll need
#                      to swap it for project-specific reviewers later, which
#                      is a fiddly process (see DESIGN.md). Bringing your own
#                      seed avoids that swap.
#
set -euo pipefail

REPO_DIR="${1:-}"
HOOK_SCRIPT="${2:-}"
PUB_KEY="${3:-}"
SEED_DIR=""
FROM_TARBALL=""

# Fourth arg is either a seed-dir path (existing behavior) or
# `--from-tarball <tarball-path>` (brownfield migration: the tarball IS a
# bare clone of the operator's existing repo, extracted in place as the
# bare repo so the existing history is preserved).
case $# in
  3)
    : # placeholder seed
    ;;
  4)
    SEED_DIR="$4"
    ;;
  5)
    if [[ "$4" != "--from-tarball" ]]; then
      echo "usage: $0 <repo-dir> <hook-script> <trusted-pub-key> [<seed-stamp-dir> | --from-tarball <tarball-path>]" >&2
      exit 2
    fi
    FROM_TARBALL="$5"
    ;;
  *)
    echo "usage: $0 <repo-dir> <hook-script> <trusted-pub-key> [<seed-stamp-dir> | --from-tarball <tarball-path>]" >&2
    exit 2
    ;;
esac

if [[ -e "$REPO_DIR" ]]; then
  echo "error: $REPO_DIR already exists" >&2
  exit 1
fi
if [[ ! -f "$HOOK_SCRIPT" ]]; then
  echo "error: hook script not found at $HOOK_SCRIPT" >&2
  exit 1
fi
if [[ ! -f "$PUB_KEY" ]]; then
  echo "error: public key not found at $PUB_KEY" >&2
  exit 1
fi
if [[ -n "$SEED_DIR" ]]; then
  if [[ ! -d "$SEED_DIR" ]]; then
    echo "error: seed dir not found at $SEED_DIR" >&2
    exit 1
  fi
  if [[ ! -f "$SEED_DIR/config.yml" ]]; then
    echo "error: seed dir missing config.yml at $SEED_DIR/config.yml" >&2
    exit 1
  fi
  if [[ ! -d "$SEED_DIR/reviewers" ]]; then
    echo "error: seed dir missing reviewers/ at $SEED_DIR/reviewers" >&2
    exit 1
  fi
fi

# Compute the SHA-256 fingerprint of the public key so we can name the trust file
# consistently with the client-side naming convention.
compute_fingerprint() {
  node --input-type=module -e "
    import { createPublicKey, createHash } from 'node:crypto';
    import { readFileSync } from 'node:fs';
    const pem = readFileSync(process.argv[1], 'utf8');
    const pub = createPublicKey(pem);
    const raw = pub.export({ type: 'spki', format: 'der' });
    const hash = createHash('sha256').update(raw).digest('hex');
    process.stdout.write('sha256_' + hash);
  " "$1"
}

FP=$(compute_fingerprint "$PUB_KEY")
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT

if [[ -n "$FROM_TARBALL" ]]; then
  # Brownfield migration path: the tarball IS a bare clone of the
  # operator's existing repo (history, .stamp/, trusted-keys, the works).
  # Its refs and objects are imported into a fresh bare repo (see below).
  # No seed commit is created — the operator's existing history becomes
  # the bare's history. Hooks install AFTER, so
  # the existing commits never go through verification (they came from
  # before this repo was server-gated). Per DESIGN.md "Bootstrap" rule:
  # filesystem operations bypass the hook by definition.
  if [[ ! -f "$FROM_TARBALL" ]]; then
    echo "error: --from-tarball file not found at $FROM_TARBALL" >&2
    exit 1
  fi
  # Pre-extraction entry-name check. Reject the tarball outright if any
  # entry is absolute (`^/`) or contains a `..` path segment. We do this
  # ahead of extraction because (a) busybox tar (older Alpine images) has
  # had weaker path-traversal protections than GNU tar, and (b) even with
  # GNU tar refusing such entries by default, an explicit reject + clear
  # error message is more useful than tar's silent skip + nonzero exit.
  # The regex matches a leading `/` OR a `..` segment bounded by start-of-
  # string / `/` on each side (so legitimate names like `..foo` or
  # `foo..bar` are not rejected). `tar -tzf` lists entries without
  # extracting; works identically with busybox or GNU tar.
  echo "→ inspecting tarball entries before extraction"
  if BAD=$(tar -tzf "$FROM_TARBALL" | grep -E '^/|(^|/)\.\.(/|$)' | head -n 1); then
    if [[ -n "$BAD" ]]; then
      echo "error: tarball $FROM_TARBALL contains unsafe entry: $BAD" >&2
      echo "       entries must not be absolute (^/) or contain a '..' path segment" >&2
      exit 1
    fi
  fi

  # The tarball is NOT trusted as a bare repo in place (AGT-2266). A bare
  # clone carries more than history: `config` (core.hooksPath would make
  # git ignore the stamp pre-receive we install below; receive.* could
  # weaken push checks; include.* can pull in other files), `hooks/`
  # (update / post-update / reference-transaction / proc-receive would run
  # as the git user on every push), `objects/info/alternates` and
  # `commondir` (point object/ref lookup at OTHER repos on the host), and
  # `info/grafts` (rewrites the history git sees). None of that may reach
  # the server repo.
  #
  # So: extract into a scratch dir, strip it down to refs + objects, then
  # `git init --bare` a FRESH repo at $REPO_DIR and fetch every ref into
  # it. $REPO_DIR ends up with git's own default config/hooks plus the
  # server settings applied below, and only the tarball's refs and the
  # objects they reach.
  IMPORT_DIR="$SCRATCH/import.git"
  mkdir -p "$IMPORT_DIR"
  echo "→ extracting existing repo from tarball into scratch dir"
  # The tarball was created with `tar -czf - -C <parent> <bare.git>`, so it
  # contains a single top-level directory (the bare clone) — strip that
  # component so contents land directly in IMPORT_DIR.
  #
  # Hardening flags (GNU tar; ignored or no-op on busybox tar):
  #   --no-same-owner        ignore uid/gid in tar headers; chown to current
  #                          user. Prevents a tarball from claiming root- or
  #                          other-user-owned files.
  #   --no-same-permissions  apply current umask to extracted files instead
  #                          of honoring tar header mode bits. Prevents
  #                          setuid/setgid surprises and overly-loose perms.
  #   --no-overwrite-dir     refuse to replace an existing directory's
  #                          metadata with a tar entry's metadata.
  tar -xzf "$FROM_TARBALL" -C "$IMPORT_DIR" --strip-components=1 \
      --no-same-owner --no-same-permissions --no-overwrite-dir

  # A bare clone produced by `git clone --bare` contains no symlinks. One
  # in the extracted tree could redirect the sanitizing `rm` below, or the
  # fetch's object reads, into another repo on the host (e.g. `objects` ->
  # /srv/git/other.git/objects). Refuse rather than reason about it.
  # (Rejecting link entries before extraction is AGT-2267.)
  # (`| head` rather than `-quit`, which busybox find may lack; `|| true`
  # because pipefail would otherwise turn find's SIGPIPE into a skip.)
  LINK=$(find "$IMPORT_DIR" -type l -print | head -n 1 || true)
  if [[ -n "$LINK" ]]; then
    echo "error: tarball $FROM_TARBALL contains a symlink: ${LINK#"$IMPORT_DIR"/}" >&2
    exit 1
  fi

  # Read the object format from the tarball's config WITHOUT letting git
  # interpret that config as a repo config: `git config --file` reads one
  # file and does not follow include.* directives. Only sha1/sha256 are
  # accepted; anything else is rejected rather than passed to git init.
  OBJECT_FORMAT=sha1
  if [[ -f "$IMPORT_DIR/config" ]]; then
    OBJECT_FORMAT=$(git config --file "$IMPORT_DIR/config" --get extensions.objectformat 2>/dev/null || echo sha1)
  fi
  case "$OBJECT_FORMAT" in
    sha1|sha256) ;;
    *)
      echo "error: $FROM_TARBALL has unsupported extensions.objectformat '$OBJECT_FORMAT'" >&2
      exit 1
      ;;
  esac

  # A shallow source can't be imported whole (its history is cut off), so
  # say that plainly instead of failing later with a generic fetch error.
  if [[ -e "$IMPORT_DIR/shallow" ]]; then
    echo "error: $FROM_TARBALL is a shallow clone; brownfield import needs full history (git fetch --unshallow, then re-run)" >&2
    exit 1
  fi

  # Allowlist, not denylist: copy ONLY what a bare repo's history lives in
  # (HEAD, refs/, packed-refs, objects/) into a second scratch dir, and give
  # it a minimal known-good config. Everything else the tarball shipped
  # (config, hooks/, commondir, info/grafts, a stray `.git` gitfile or dir
  # that upload-pack's path discovery would follow into another repo, ...)
  # never reaches a directory git treats as a repository. Alternates inside
  # objects/ are dropped too: they would point object lookup at other repos.
  CLEAN_DIR="$SCRATCH/clean.git"
  mkdir -p "$CLEAN_DIR"
  for entry in HEAD refs packed-refs objects; do
    if [[ -e "$IMPORT_DIR/$entry" ]]; then
      mv "$IMPORT_DIR/$entry" "$CLEAN_DIR/$entry"
    fi
  done
  rm -rf "$IMPORT_DIR"
  mkdir -p "$CLEAN_DIR/refs" "$CLEAN_DIR/objects"
  rm -f "$CLEAN_DIR/objects/info/alternates" "$CLEAN_DIR/objects/info/http-alternates"
  {
    printf '[core]\n\trepositoryformatversion = %s\n\tbare = true\n' \
      "$([[ "$OBJECT_FORMAT" == sha256 ]] && echo 1 || echo 0)"
    if [[ "$OBJECT_FORMAT" == sha256 ]]; then
      printf '[extensions]\n\tobjectformat = sha256\n'
    fi
  } > "$CLEAN_DIR/config"
  IMPORT_DIR="$CLEAN_DIR"

  # Verify it really is a bare repo. `git rev-parse --is-bare-repository`
  # exits 0 only inside a bare repo with the right layout.
  if ! GIT_DIR="$IMPORT_DIR" git rev-parse --is-bare-repository >/dev/null 2>&1; then
    echo "error: $FROM_TARBALL did not contain a bare git repository" >&2
    exit 1
  fi

  # The tarball's default branch, if it names one under refs/heads/.
  IMPORT_HEAD=$(GIT_DIR="$IMPORT_DIR" git symbolic-ref -q HEAD 2>/dev/null || true)

  echo "→ creating bare repo at $REPO_DIR"
  git init --bare --quiet --initial-branch=main --object-format="$OBJECT_FORMAT" "$REPO_DIR"

  echo "→ importing refs and objects from tarball into $REPO_DIR"
  # Hooks are not installed yet, and fetch never runs receive hooks anyway:
  # the existing history predates server gating (DESIGN.md "Bootstrap").
  # `upload-pack --strict` serves exactly $IMPORT_DIR, with no `.git` /
  # `.git`-suffix discovery on the source path (defense in depth on top of
  # the allowlist copy above).
  if ! git --git-dir="$REPO_DIR" fetch --quiet --no-tags --update-head-ok \
      --upload-pack='git-upload-pack --strict' \
      "$IMPORT_DIR" '+refs/*:refs/*'; then
    rm -rf "$REPO_DIR"
    echo "error: could not import refs/objects from $FROM_TARBALL (removed partial $REPO_DIR)" >&2
    exit 1
  fi
  if [[ "$IMPORT_HEAD" == refs/heads/* ]] && \
     git --git-dir="$REPO_DIR" check-ref-format "$IMPORT_HEAD" && \
     git --git-dir="$REPO_DIR" rev-parse -q --verify "$IMPORT_HEAD" >/dev/null; then
    git --git-dir="$REPO_DIR" symbolic-ref HEAD "$IMPORT_HEAD"
  fi
else
  echo "→ creating bare repo at $REPO_DIR"
  git init --bare --quiet --initial-branch=main "$REPO_DIR"

  # Seed BEFORE installing the hook — this is the bootstrap bypass per DESIGN.md.
  # Once the hook is in place, every push is verified.
  echo "→ seeding initial commit (pre-hook, per DESIGN.md bootstrap rule)"
  git init --quiet --initial-branch=main "$SCRATCH/work"
  cd "$SCRATCH/work"
  git config user.email "stamp-setup@local"
  git config user.name "stamp-setup"

  mkdir -p .stamp/reviewers .stamp/trusted-keys

  if [[ -n "$SEED_DIR" ]]; then
    echo "→ using project-specific seed from $SEED_DIR"
    cp "$SEED_DIR/config.yml" .stamp/config.yml
    cp -R "$SEED_DIR/reviewers/." .stamp/reviewers/
    if [[ -f "$SEED_DIR/mirror.yml" ]]; then
      cp "$SEED_DIR/mirror.yml" .stamp/mirror.yml
    fi
  else
    cat > .stamp/config.yml <<'EOF'
branches:
  main:
    required:
      - example
reviewers:
  example:
    prompt: .stamp/reviewers/example.md
EOF

    cat > .stamp/reviewers/example.md <<'EOF'
# example reviewer (bootstrap only — auto-approves everything)

> **WARNING — DO NOT use this reviewer for real code review.** It is a
> deterministic auto-approver intended only to land your *real* reviewers
> via the `stamp bootstrap` flow on first clone. Once your real reviewers
> are in place, remove this one (or leave it defined-but-unrequired
> forever).

## Instructions to the reviewer agent

You are a bootstrap-only placeholder reviewer. **Do not analyze the diff.**
Do not read files. Do not comment on the code. Output exactly the following
two-line response, verbatim, and nothing else:

```
Bootstrap placeholder reviewer — approving unconditionally so real reviewers can be installed. Replace this reviewer before relying on it for actual code review.
VERDICT: approved
```

That is the entire response. No preamble, no analysis, no caveats beyond
the line above. The `VERDICT: approved` line MUST be the final line.

## Why this exists

Every stamp-protected repo needs at least one reviewer that can approve
the very first merge — the merge that installs the *real* reviewers.
This placeholder solves that bootstrap problem and is meant to be retired
(or kept defined-but-unrequired) immediately after. Run `stamp bootstrap`
on first clone to land real reviewers automatically.
EOF
  fi

  cp "$PUB_KEY" ".stamp/trusted-keys/${FP}.pub"

  git add .stamp
  git commit --quiet -m "bootstrap: seed stamp config + first trusted key"

  git push --quiet "$REPO_DIR" main
fi  # end of seed-vs-tarball branch

# Belt-and-suspenders to the pre-receive hook's FF check (issue #20).
# git defaults `receive.denyNonFastForwards` to false on bare repos, so
# without this, a buggy or race-blind hook could let a non-FF push land.
# With this set, git itself rejects non-FF before pre-receive even sees
# the push — pre-receive's check then becomes the second line of defense.
# Applied on BOTH paths: the brownfield import gets it too (AGT-2266).
git --git-dir="$REPO_DIR" config receive.denyNonFastForwards true

echo "→ installing stamp-verify hook (now active for all subsequent pushes)"
install -m 0755 "$HOOK_SCRIPT" "$REPO_DIR/hooks/pre-receive"

# Optional: install post-receive mirror hook if it's alongside the pre-receive
# script. Path convention: <dir>/pre-receive.cjs + <dir>/post-receive.cjs.
HOOK_DIR="$(dirname "$HOOK_SCRIPT")"
POST_HOOK="$HOOK_DIR/post-receive.cjs"
if [[ -f "$POST_HOOK" ]]; then
  echo "→ installing stamp-mirror post-receive hook"
  install -m 0755 "$POST_HOOK" "$REPO_DIR/hooks/post-receive"
fi

USED_PLACEHOLDER_SEED=0
# Placeholder seed only when neither --from-tarball nor seed-dir was given.
if [[ -z "$SEED_DIR" && -z "$FROM_TARBALL" ]]; then
  USED_PLACEHOLDER_SEED=1
fi

# Final guard: the hook we just installed must be the one git runs. If any
# config source (repo, or an operator's global/system config) sets
# core.hooksPath, git would consult that directory instead and every push
# would skip stamp verification. Refuse to report the repo ready.
if HOOKS_PATH=$(git --git-dir="$REPO_DIR" config --get core.hooksPath 2>/dev/null) && [[ -n "$HOOKS_PATH" ]]; then
  rm -rf "$REPO_DIR"
  echo "error: core.hooksPath is set ('$HOOKS_PATH') for $REPO_DIR; git would ignore the stamp pre-receive hook" >&2
  echo "       find it with \`git config --show-origin --get core.hooksPath\`, unset it, and re-run (partial $REPO_DIR removed)" >&2
  exit 1
fi

echo "✓ repo ready"
# When STAMP_SETUP_QUIET_NEXT_STEPS=1, callers (e.g. server/new-stamp-repo)
# suppress the next-steps section because they want to print their own
# server-aware version with an ssh://... clone URL.
echo
echo "  bare repo:        $REPO_DIR"
echo "  pre-receive:      $REPO_DIR/hooks/pre-receive"
if [[ -f "$REPO_DIR/hooks/post-receive" ]]; then
  echo "  post-receive:     $REPO_DIR/hooks/post-receive (mirror-capable)"
fi
echo "  seeded branch:    main"
echo "  trusted key:      ${FP}.pub"
if [[ $USED_PLACEHOLDER_SEED -eq 1 ]]; then
  echo "  reviewer seed:    placeholder \`example\` (auto-approves)"
elif [[ -n "$FROM_TARBALL" ]]; then
  echo "  reviewer seed:    existing repo state from $FROM_TARBALL (brownfield migration)"
else
  echo "  reviewer seed:    $SEED_DIR"
fi
if [[ "${STAMP_SETUP_QUIET_NEXT_STEPS:-0}" != "1" ]]; then
  echo
  echo "Next steps:"
  echo "  1. Clone:        git clone $REPO_DIR"
  echo "  2. cd into the clone"
  if [[ $USED_PLACEHOLDER_SEED -eq 1 ]]; then
    echo "  3. Run:          stamp bootstrap"
    echo
    echo "     This installs real reviewers (security/standards/product) in one"
    echo "     command and replaces the placeholder. Run \`stamp bootstrap --help\`"
    echo "     for options including \`--from <dir>\` to use your own reviewer set."
    echo
    echo "     To skip the bootstrap dance entirely on future repos, re-run this"
    echo "     script with a seed-dir arg (4th positional) containing your real"
    echo "     .stamp/ config + reviewers/."
  else
    echo "  3. Customize .stamp/reviewers/ to fit your project, then start the"
    echo "     normal stamp review/merge cycle."
  fi
fi
