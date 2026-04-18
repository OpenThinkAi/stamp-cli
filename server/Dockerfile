# Build the stamp-verify hook in a first stage so runtime image stays small.
FROM node:22-alpine AS builder
WORKDIR /build
COPY package.json package-lock.json tsconfig.json tsup.config.ts ./
RUN npm ci
COPY src ./src
RUN npm run build

# Runtime: bare git server + sshd + node (to run the hook) + the hook itself.
FROM alpine:3.19

# sed step unlocks the git account (alpine's adduser -D leaves password as "!",
# which openssh treats as "locked"; "*" means no password but unlocked, which
# is what we want for pubkey-only auth).
RUN apk add --no-cache git openssh-server bash nodejs \
 && adduser -D -s /bin/bash -h /home/git git \
 && sed -i 's/^git:!/git:*/' /etc/shadow \
 && mkdir -p /srv/git /home/git/.ssh /etc/stamp \
 && chown -R git:git /srv/git /home/git \
 && chmod 700 /home/git/.ssh \
 && ssh-keygen -A

# Harden sshd: no password auth, no root login.
RUN sed -i \
      -e 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' \
      -e 's/^#*PermitRootLogin.*/PermitRootLogin no/' \
      -e 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' \
      /etc/ssh/sshd_config

COPY --from=builder /build/dist/hooks/pre-receive.cjs /etc/stamp/pre-receive
COPY scripts/setup-repo.sh /usr/local/bin/setup-repo.sh
COPY server/new-stamp-repo /usr/local/bin/new-stamp-repo
COPY server/entrypoint.sh /entrypoint.sh

RUN chmod +x /etc/stamp/pre-receive \
             /usr/local/bin/setup-repo.sh \
             /usr/local/bin/new-stamp-repo \
             /entrypoint.sh

EXPOSE 22
CMD ["/entrypoint.sh"]
