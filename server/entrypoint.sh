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

if [ -n "$AUTHORIZED_KEYS" ]; then
  printf '%s\n' "$AUTHORIZED_KEYS" > /home/git/.ssh/authorized_keys
  chmod 600 /home/git/.ssh/authorized_keys
  chown git:git /home/git/.ssh/authorized_keys
fi

if [ -n "$OPERATOR_PUB_KEY" ]; then
  printf '%s\n' "$OPERATOR_PUB_KEY" > /etc/stamp/operator.pub
  chmod 644 /etc/stamp/operator.pub
fi

# -e: log to stderr (goes to container logs); -D: don't daemonize.
exec /usr/sbin/sshd -D -e
