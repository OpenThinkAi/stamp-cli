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

if [ -n "$AUTHORIZED_KEYS" ]; then
  printf '%s\n' "$AUTHORIZED_KEYS" > /home/git/.ssh/authorized_keys
  chmod 600 /home/git/.ssh/authorized_keys
  chown git:git /home/git/.ssh/authorized_keys
fi

if [ -n "$OPERATOR_PUB_KEY" ]; then
  printf '%s\n' "$OPERATOR_PUB_KEY" > /etc/stamp/operator.pub
  chmod 644 /etc/stamp/operator.pub
  chown git:git /etc/stamp/operator.pub
fi

# sshd strips custom environment variables by default, so hooks invoked
# through SSH sessions don't see things like GITHUB_BOT_TOKEN. Persist
# them to a file the hooks can read directly. Chown to the git user so
# only that user (which runs the hooks) can read the secret.
: > /etc/stamp/env
chmod 600 /etc/stamp/env
chown git:git /etc/stamp/env

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
      chmod +x "$repo/hooks/$hook"
      chown git:git "$repo/hooks/$hook"
    fi
  done
done

# -e: log to stderr (goes to container logs); -D: don't daemonize.
exec /usr/sbin/sshd -D -e
