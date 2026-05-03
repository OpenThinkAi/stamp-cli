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
fi

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
