#!/usr/bin/env bash
#
# setup-repo.sh — operator bootstrap for a stamp-protected bare git repo.
#
# Run this on the server (or anywhere you're provisioning a bare repo).
# It:
#   1. Creates a bare repo
#   2. Installs the stamp-verify pre-receive hook
#   3. Seeds an initial commit with .stamp/config.yml + trusted key + example reviewer
#
# Because the seed commit is written by local git operations (not a push),
# it bypasses the hook — which is exactly what DESIGN.md "Bootstrap" requires.
# After this, every subsequent push is verified normally.
#
# Usage:
#   setup-repo.sh <repo-dir> <hook-script> <trusted-pub-key>
#
# Example:
#   setup-repo.sh /srv/git/myproject.git \
#                 /path/to/stamp-cli/dist/hooks/pre-receive.cjs \
#                 /home/matt/.stamp/keys/ed25519.pub
#
# Arguments:
#   <repo-dir>         Path where the bare repo will be created
#   <hook-script>      Path to the stamp-verify hook (dist/hooks/pre-receive.js)
#   <trusted-pub-key>  Path to an Ed25519 public key PEM file — the first
#                      trusted signer for this repo
#
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <repo-dir> <hook-script> <trusted-pub-key>" >&2
  exit 2
fi

REPO_DIR="$1"
HOOK_SCRIPT="$2"
PUB_KEY="$3"

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
# Example Reviewer

Placeholder reviewer prompt. Replace with the real reviewer instructions
for your project. Must end with a line of the form:

    VERDICT: approved

Options: approved | changes_requested | denied
EOF

cp "$PUB_KEY" ".stamp/trusted-keys/${FP}.pub"

git add .stamp
git commit --quiet -m "bootstrap: seed stamp config + first trusted key"

git push --quiet "$REPO_DIR" main

echo "→ installing stamp-verify hook (now active for all subsequent pushes)"
install -m 0755 "$HOOK_SCRIPT" "$REPO_DIR/hooks/pre-receive"

echo "✓ repo ready"
echo
echo "  bare repo:        $REPO_DIR"
echo "  hook installed:   $REPO_DIR/hooks/pre-receive"
echo "  seeded branch:    main"
echo "  trusted key:      ${FP}.pub"
echo
echo "Clone the repo and start pushing:"
echo "  git clone $REPO_DIR"
