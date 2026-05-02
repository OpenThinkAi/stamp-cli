# Build the stamp-verify hook in a first stage so runtime image stays small.
# Base images are pinned by digest (not just tag) so two builds 24h apart
# produce byte-identical userspace, and a re-push of the upstream tag by an
# attacker cannot silently change the runtime. Renovate / Dependabot's
# `docker` ecosystem keeps the digest current with annotated PRs.
FROM node:22-alpine3.21@sha256:af8023ec879993821f6d5b21382ed915622a1b0f1cc03dbeb6804afaf01f8885 AS builder
WORKDIR /build
COPY package.json package-lock.json tsconfig.json tsup.config.ts ./
RUN npm ci
COPY src ./src
RUN npm run build

# Runtime: bare git server + sshd + node (to run the hook) + the hook itself.
# Bumped from alpine:3.19 (EOL 2025-11-01 — no further security updates for
# git/openssh/musl/openssl) to alpine:3.21 (supported through 2027-04). The
# image runs sshd exposed to the internet on every stamp-server deploy, so
# being on a supported package set matters. Pinned by digest for the same
# reason as the builder.
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d

# sed step unlocks the git account (alpine's adduser -D leaves password as "!",
# which openssh treats as "locked"; "*" means no password but unlocked, which
# is what we want for pubkey-only auth).
RUN apk add --no-cache git openssh-server bash nodejs \
 && adduser -D -s /bin/bash -h /home/git git \
 && sed -i 's/^git:!/git:*/' /etc/shadow \
 && mkdir -p /srv/git /home/git/.ssh /etc/stamp \
 && chown -R git:git /srv/git /home/git \
 && chmod 700 /home/git/.ssh
# NOTE: ssh-keygen -A is intentionally NOT run at build time. Host keys
# baked into the image rotate on every container rebuild, breaking every
# operator's known_hosts on every redeploy. entrypoint.sh generates host
# keys on first boot into /srv/git/.ssh-host-keys/ (the persistent volume)
# and reuses them on subsequent boots, so the same image deployed multiple
# times keeps the same host identity.

# Harden sshd: no password auth, no root login.
RUN sed -i \
      -e 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' \
      -e 's/^#*PermitRootLogin.*/PermitRootLogin no/' \
      -e 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' \
      /etc/ssh/sshd_config

COPY --from=builder /build/dist/hooks/pre-receive.cjs /etc/stamp/pre-receive.cjs
COPY --from=builder /build/dist/hooks/post-receive.cjs /etc/stamp/post-receive.cjs
COPY scripts/setup-repo.sh /usr/local/bin/setup-repo.sh
COPY server/new-stamp-repo /usr/local/bin/new-stamp-repo
COPY server/delete-stamp-repo /usr/local/bin/delete-stamp-repo
COPY server/restore-stamp-repo /usr/local/bin/restore-stamp-repo
COPY server/list-trash /usr/local/bin/list-trash
COPY server/entrypoint.sh /entrypoint.sh

RUN chmod +x /etc/stamp/pre-receive.cjs \
             /etc/stamp/post-receive.cjs \
             /usr/local/bin/setup-repo.sh \
             /usr/local/bin/new-stamp-repo \
             /usr/local/bin/delete-stamp-repo \
             /usr/local/bin/restore-stamp-repo \
             /usr/local/bin/list-trash \
             /entrypoint.sh

EXPOSE 22
CMD ["/entrypoint.sh"]
