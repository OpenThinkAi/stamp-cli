#!/bin/sh
#
# Container entrypoint: populate per-deployment config from env vars, then
# start sshd.
#
#   AUTHORIZED_KEYS   newline-delimited authorized public keys for the git user
#                     (who you SSH in as to push/pull/create repos)
#   OPERATOR_PUB_KEY  PEM-encoded public key of the operator; will be seeded
#                     into each new repo as the first trusted signer
#
set -e

# Platform volume mounts (Railway, Fly, etc.) come up root-owned, overriding
# any build-time chown. Fix at boot so the git user can write its own repos.
chown -R git:git /srv/git 2>/dev/null || true

# Sticky bit on /srv/git: prevents the git user from renaming or deleting
# root-owned subdirectories like .ssh-host-keys. Without sticky, write
# permission on the parent directory grants rename/delete on its children
# regardless of child ownership; the prior chmod 700 on .ssh-host-keys
# only protected the contents, not the directory entry. Sticky bit is the
# canonical fix (mirrors /tmp).
chmod +t /srv/git

# SSH host-key persistence — the load-bearing fix for the recurring
# "REMOTE HOST IDENTIFICATION HAS CHANGED" warning every operator hits
# after a container redeploy. The keys live on the persistent volume,
# not in the image, so the same project's stamp server keeps the same
# host identity across rebuilds.
HOST_KEY_DIR=/srv/git/.ssh-host-keys
mkdir -p "$HOST_KEY_DIR"
if [ ! -f "$HOST_KEY_DIR/ssh_host_ed25519_key" ]; then
  echo "Generating fresh SSH host keys into $HOST_KEY_DIR (first boot for this volume)" >&2
  ssh-keygen -t ed25519 -N "" -f "$HOST_KEY_DIR/ssh_host_ed25519_key" -q
  ssh-keygen -t rsa -b 4096 -N "" -f "$HOST_KEY_DIR/ssh_host_rsa_key" -q
  ssh-keygen -t ecdsa -b 521 -N "" -f "$HOST_KEY_DIR/ssh_host_ecdsa_key" -q
fi
# Pin the host-key directory to root:root every boot. The git user owns its
# parent /srv/git (so it can write bare repos), so without this the git user
# could in theory rename/delete .ssh-host-keys. The git user's surface is
# heavily constrained anyway (forced command via new-stamp-repo / git-shell),
# but belt-and-suspenders is cheap here.
chown root:root "$HOST_KEY_DIR"
chmod 700 "$HOST_KEY_DIR"
chown root:root "$HOST_KEY_DIR"/ssh_host_*
chmod 600 "$HOST_KEY_DIR"/ssh_host_*_key
chmod 644 "$HOST_KEY_DIR"/ssh_host_*_key.pub
# Point sshd at the persistent keys via /etc/ssh symlinks. We replace any
# build-time-generated keys (which we no longer create, but defensive) so
# there's exactly one set of keys in play.
for keytype in ed25519 rsa ecdsa; do
  rm -f "/etc/ssh/ssh_host_${keytype}_key" "/etc/ssh/ssh_host_${keytype}_key.pub"
  ln -s "$HOST_KEY_DIR/ssh_host_${keytype}_key" "/etc/ssh/ssh_host_${keytype}_key"
  ln -s "$HOST_KEY_DIR/ssh_host_${keytype}_key.pub" "/etc/ssh/ssh_host_${keytype}_key.pub"
done

# Print host-key fingerprints to logs at boot so operators can verify
# the key the SSH client is being asked to trust. Useful when adding the
# server to known_hosts for the first time, or when investigating a
# legitimate vs. suspicious key change.
echo "SSH host-key fingerprints (verify these match what your client sees):" >&2
for keytype in ed25519 rsa ecdsa; do
  ssh-keygen -lf "$HOST_KEY_DIR/ssh_host_${keytype}_key.pub" 2>&1 | sed 's/^/  /' >&2
done

if [ -n "$AUTHORIZED_KEYS" ]; then
  printf '%s\n' "$AUTHORIZED_KEYS" > /home/git/.ssh/authorized_keys
  chmod 600 /home/git/.ssh/authorized_keys
  chown git:git /home/git/.ssh/authorized_keys
  # AUTHORIZED_KEYS is deprecated as the ongoing membership source — its
  # entries get imported into the sqlite users table by stamp-seed-users
  # below, after which the CLI surface (stamp invites, stamp users) is
  # authoritative. The env-var path remains supported for first-boot
  # bootstrap so operators don't lose the existing way to seed an empty
  # server, but new operators should be onboarded via `stamp invites
  # mint`.
  echo "note: AUTHORIZED_KEYS is supported for bootstrap; ongoing user management goes through 'stamp invites mint' and 'stamp users …'. See server/README.md." >&2
fi

# Membership sqlite — back-end for the AuthorizedKeysCommand resolver
# (sshd consults this on every connection before falling back to
# AuthorizedKeysFile) AND the HTTP server's invite-accept endpoint
# (which writes new user rows). The DB lives on the persistent volume
# so it survives container redeploys.
#
# Directory mode: root:git 1770. The 0770 bits give the git user
# write+create access in the directory, which sqlite needs to write
# its `-journal` sidecar files on every transaction (without it,
# sqlite silently demotes to read-only and every UPDATE throws
# "attempt to write a readonly database"). The leading sticky bit (1)
# means git can rename/delete files it owns but NOT files owned by
# root — so any future root-owned state file in this dir is protected
# from a git-shell-escapee, even though the dir itself is git-writable.
# Phase 1 had 0750 here, which broke the write path; we found this
# the first time someone tried `stamp users promote` end-to-end.
#
# File mode: root:git 0660. The HTTP server runs as the git user and
# needs WRITE access for invite/accept (new user rows). The
# AuthorizedKeysCommand resolver also runs as git but opens the DB
# `readOnly: true` in code, so it can't mutate state even with the
# write bit set.
#
# stamp-seed-users walks AUTHORIZED_KEYS and INSERT-OR-NO-OPs each entry
# into the users table as role=admin source=env. This runs on EVERY boot
# (not just the first one) because operators may add or remove keys
# between deploys; the script is idempotent on the import side. Removal
# of an env-var line does NOT cascade to a DB delete here — that's a
# phase-3 operator action.
STAMP_STATE_DIR=/srv/git/.stamp-state
mkdir -p "$STAMP_STATE_DIR"
chown root:git "$STAMP_STATE_DIR"
chmod 1770 "$STAMP_STATE_DIR"
if /usr/local/sbin/stamp-seed-users; then
  if [ -f "$STAMP_STATE_DIR/users.db" ]; then
    chown root:git "$STAMP_STATE_DIR/users.db"
    chmod 0660 "$STAMP_STATE_DIR/users.db"
  fi
else
  # Don't abort the boot — sshd's AuthorizedKeysFile fallback still
  # services connections from AUTHORIZED_KEYS during transition.
  echo "WARNING: stamp-seed-users failed; AuthorizedKeysCommand path may be empty until next boot" >&2
fi

# Launch the HTTP server in the background as the git user, BEFORE
# sshd's exec replaces this shell. Once exec runs, sshd inherits PID 1
# and the HTTP server becomes its child via re-parenting. Stdout/stderr
# go to the container's log stream so operators see invite-accept
# traffic alongside ssh logs.
#
# `su -s /bin/sh -p git` is the runuser-equivalent that works against
# Alpine's busybox su (Alpine doesn't ship util-linux by default, and
# the git user's login shell is /usr/bin/git-shell which would reject
# `-c <cmd>`; -s overrides that). -p preserves the environment so
# STAMP_HTTP_PORT (and any STAMP_SERVER_DB_PATH test override) flow
# through.
#
# If the HTTP server dies mid-container-life, invite-accept stops
# working until the operator redeploys. Phase 5 may add a supervisor
# (s6/tini) for crash-restart; for now the simpler shape ships.
su -s /bin/sh -p git -c "/usr/local/sbin/stamp-http-server" &
echo "stamp-http-server: launched as git user (pid $!)" >&2

# SSH client setup for the post-receive mirror push.
#
# The post-receive hook can push to the GitHub mirror via either:
#   (a) HTTPS with $GITHUB_BOT_TOKEN as an Authorization: Basic header
#       (the legacy/default path; identity is the PAT's owning user), or
#   (b) SSH using a deploy key registered on the GitHub repo
#       (the locked-down path; identity is the deploy key, which lets
#        org-owned repos use DeployKey bypass on their Rulesets without
#        needing a machine-user account or a GitHub App install).
#
# The selection is made per-push by post-receive.cjs based on whether
# the deploy-key private file exists at SSH_CLIENT_KEY_PATH below. This
# entrypoint sets up the SSH client config unconditionally — pointing
# at the key path even before the key exists is harmless; ssh only
# touches the file when an SSH push is actually attempted.
#
# Permissions model:
#   - /srv/git/.ssh-client-keys/ — root-owned, mode 0750 root:git. The
#     git user can READ + traverse the directory but cannot CREATE,
#     RENAME, or DELETE entries within it. This is the load-bearing
#     invariant: a pusher who escapes git-shell cannot plant new files
#     here, so the set of legitimately-registered deploy keys is
#     constrained to what the entrypoint (legacy github_ed25519) and
#     the sudo-elevated stamp-ensure-repo-key helper (per-repo files)
#     have created. If the dir's perms or owner ever change, the
#     boot-time chown/chmod loop below becomes a symlink-following
#     hazard — re-evaluate together.
#   - The private key files — git-owned, mode 0600 (git:git 0600).
#     Standard SSH posture, owner-only readable. The git user runs
#     the post-receive hook and invokes ssh, so it has to BE the file
#     owner; OpenSSH 9.x's strict-perms check rejects any private key
#     with group or other read bits set, so the previous root:git
#     0640 posture broke the SSH transport. Trade-off: a git-shell
#     escapee can now substitute a key file's content, but still
#     needs GitHub repo-admin auth to register their pubkey as a
#     bypass actor — multi-step exploit chain rather than single-
#     step substitution. See server/stamp-ensure-repo-key for the
#     long-form discussion; see DESIGN.md "Key-file ownership
#     posture" for the spec-level note.
#   - /home/git/.ssh/config — git-owned, mode 0644. Standard SSH client
#     config location; sshd does not read this file for inbound auth,
#     it's strictly for outbound git push from the hook.
SSH_CLIENT_KEY_DIR=/srv/git/.ssh-client-keys
SSH_CLIENT_KEY_PATH="$SSH_CLIENT_KEY_DIR/github_ed25519"
mkdir -p "$SSH_CLIENT_KEY_DIR"
chown root:git "$SSH_CLIENT_KEY_DIR"
chmod 0750 "$SSH_CLIENT_KEY_DIR"

# Generate the mirror-push keypair on first boot if missing, mirroring
# the host-key generation block above. The keypair persists on the
# /srv/git volume across container redeploys, so the same server keeps
# the same GitHub-side identity once the operator registers the public
# key as a deploy key on each mirrored repo. Rotation is an explicit
# operator step: delete the file pair on the volume, redeploy, then
# re-register the new public key on each repo.
#
# Why ed25519 only (not also rsa/ecdsa like host keys): the client side
# offers ONE identity per connection (IdentitiesOnly + a single
# IdentityFile in ~/.ssh/config). Generating multiple algorithms would
# bloat the volume for keys ssh would never offer. ed25519 is supported
# by GitHub and produces 80-byte public keys — short enough to paste
# into a deploy-key form by hand.
#
# The public-key comment carries "stamp-mirror" + the container hostname
# at generation time. The comment is informational (GitHub ignores it
# on deploy-key POST) but lets an operator who SSHes in and runs
# `ssh-keygen -lf` recognize what they're looking at.
if [ ! -f "$SSH_CLIENT_KEY_PATH" ]; then
  echo "Generating fresh mirror-push keypair into $SSH_CLIENT_KEY_DIR (first boot for this volume)" >&2
  ssh-keygen -t ed25519 -N "" \
    -f "$SSH_CLIENT_KEY_PATH" \
    -C "stamp-mirror@$(hostname)" \
    -q
fi

# Enforce ownership/mode on EVERY key file in the keys dir on each
# boot — fixes drift if a file was created by an earlier helper
# version that used different perms, or restored from a backup that
# didn't preserve them. Covers both the legacy shared `github_ed25519`
# and per-repo `<owner>_<repo>_ed25519` files (lazily generated by
# `stamp-ensure-repo-key` via sudo from the unprivileged pubkey
# wrapper).
#
# Why git:git 0600 rather than the old root:git 0640: OpenSSH 9.x
# strict-perms check rejects any private key whose mode has group or
# other bits set, regardless of owner — emits "WARNING: UNPROTECTED
# PRIVATE KEY FILE!" and refuses to load the key. The standard SSH
# posture is owner-only readable, so the git user that runs
# post-receive needs to OWN the file at mode 0600.
#
# Trade-off note: under the previous root:git 0640 posture, a
# git-shell escape couldn't WRITE-overwrite key files (root owned,
# git only had read access via the group bit). With git:git 0600, an
# escapee with git's privileges can substitute the local file. They
# still need GitHub repo-admin auth to register the new public half
# as a deploy key, so the exploit chain is bounded — see
# stamp-ensure-repo-key for the long-form discussion.
for key_file in "$SSH_CLIENT_KEY_DIR"/*_ed25519; do
  # Glob expands to itself if no matches — guard with -f.
  [ -f "$key_file" ] || continue
  chown git:git "$key_file" "$key_file.pub"
  chmod 0600 "$key_file"
  chmod 0644 "$key_file.pub"
done

cat > /home/git/.ssh/config <<EOF
Host github.com
  Hostname github.com
  User git
  IdentityFile $SSH_CLIENT_KEY_PATH
  IdentitiesOnly yes
  StrictHostKeyChecking yes
  UserKnownHostsFile /etc/ssh/ssh_known_hosts
EOF
chown git:git /home/git/.ssh/config
chmod 0644 /home/git/.ssh/config

# Print the deploy-key public-key fingerprint at boot, mirroring the
# host-key fingerprint block above. Lets the operator eyeball-confirm
# that the in-container key matches what's registered as a deploy key
# on the GitHub repo without having to SSH in and read the .pub file.
# The key always exists at this point — the auto-generation block above
# regenerates it if it was missing or deleted.
echo "GitHub mirror-push key (deploy-key bypass mode):" >&2
ssh-keygen -lf "$SSH_CLIENT_KEY_PATH.pub" 2>&1 | sed 's/^/  /' >&2

if [ -n "$OPERATOR_PUB_KEY" ]; then
  printf '%s\n' "$OPERATOR_PUB_KEY" > /etc/stamp/operator.pub
  # Root-owned, world-readable. The git user (which runs new-stamp-repo
  # via git-shell) reads it via the world bit; nothing else needs to
  # write it after this entrypoint sets it up. Pre-A.2-cluster-B the
  # file was git-owned, which let an interactive-shell pusher REPLACE
  # the seed trusted-key for newly-provisioned repos.
  chown root:root /etc/stamp/operator.pub
  chmod 0444 /etc/stamp/operator.pub
fi

# sshd strips custom environment variables by default, so hooks invoked
# through SSH sessions don't see things like GITHUB_BOT_TOKEN. Persist
# them to a file the hooks can read directly. Owned by root, group git
# with mode 0640 so the hook process (running as git user) can read via
# group membership but cannot WRITE — and a pusher who somehow gets shell
# access despite git-shell still cannot edit it. Pre-cluster-B the file
# was git:git mode 0600, which made the mode-600 protection illusory
# (the shell-having user IS the file owner).
: > /etc/stamp/env
chown root:git /etc/stamp/env
chmod 0640 /etc/stamp/env

write_env_var() {
  local name="$1"
  local value
  value="$(eval "printf '%s' \"\$$name\"")"
  if [ -n "$value" ]; then
    printf '%s=%s\n' "$name" "$value" >> /etc/stamp/env
  fi
}

write_env_var GITHUB_BOT_TOKEN

# Refresh stamp hooks in every existing bare repo before accepting connections.
#
# When setup-repo.sh provisioned each repo, it COPIED /etc/stamp/*.cjs into
# that repo's hooks/ directory. Git runs the per-repo copy at push time, not
# /etc/stamp/ directly — so a container rebuild with new hook code doesn't
# reach existing repos on its own. Walk /srv/git/ on every boot and overwrite
# each repo's hooks with the fresh bundle from /etc/stamp/. Idempotent;
# no-ops if the volume is empty (first boot, no repos yet).
for repo in /srv/git/*.git; do
  [ -d "$repo" ] || continue
  for hook in pre-receive post-receive; do
    src="/etc/stamp/${hook}.cjs"
    if [ -f "$src" ]; then
      cp "$src" "$repo/hooks/$hook"
      # Root-owned, mode 0755: git can EXECUTE the hook (which is what git-
      # receive-pack does at push time) but cannot REPLACE it. Pre-cluster-B
      # the per-repo hook was git:git, so even with git-shell a sufficiently
      # creative pusher could overwrite the hook between container restarts.
      # entrypoint refreshes hooks on every boot, so attacker windows close
      # at the next restart — but routine redeploys don't happen on attacker
      # timing. Root-owned hooks close the window entirely.
      chown root:root "$repo/hooks/$hook"
      chmod 0755 "$repo/hooks/$hook"
    fi
  done
done

# -e: log to stderr (goes to container logs); -D: don't daemonize.
exec /usr/sbin/sshd -D -e
