# Build the stamp-verify hook in a first stage so runtime image stays small.
# Base images are pinned by digest (not just tag) so the *base userspace*
# (the layers shipped inside the alpine and node-alpine images themselves)
# is fixed across builds, and a re-push of the upstream tag by an attacker
# cannot silently change those layers. Renovate / Dependabot's `docker`
# ecosystem keeps the digest current with annotated PRs.
#
# Caveat — what the digest pin does NOT cover: the `apk add --no-cache`
# step further down installs git, openssh-server, bash, nodejs,
# netcat-openbsd, and tar from Alpine 3.21's mutable package repositories.
# Those repos receive ongoing 3.21 patch updates, so two builds 24h apart
# can resolve different package versions even on an identical base digest.
# The image is therefore reproducible at the base-userspace layer but not
# bit-for-bit reproducible end-to-end. We accept this: pinning every apk
# package would add Renovate churn on a weekly cadence for marginal risk
# reduction (this is a LOW-tier audit finding — see oaudit-may-2-2026
# rerun-3 L5), and the digest pin still defeats the higher-impact attack
# of upstream-tag re-push.
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

# Restricted shell: git-shell prevents authenticated SSH users from getting
# an interactive bash. Pushers can still run git-receive-pack / git-upload-
# pack (built into git-shell) plus the wrapper scripts symlinked into
# /home/git/git-shell-commands/ below. Without this, every AUTHORIZED_KEYS
# pusher would have shell on the container and could `cat /etc/stamp/env`
# to exfiltrate the GitHub bot token, or replace the per-repo hooks with
# no-ops between container restarts.
#
# The sed step unlocks the git account (alpine's adduser -D leaves password
# as "!", which openssh treats as "locked"; "*" means no password but
# unlocked, which is what we want for pubkey-only auth).
#
# bash is intentionally still installed — entrypoint.sh and several wrapper
# scripts use bash-isms. The git USER doesn't get a bash login shell;
# system-level scripts run as root via the entrypoint.
# netcat-openbsd is installed for the HEALTHCHECK loopback probe at the
# bottom of this file. Alpine's busybox `nc` also supports `-z`, but its
# behavior has drifted between busybox versions; pinning to OpenBSD nc
# keeps the probe semantics stable across Alpine point releases.
# tar (GNU tar) is installed because setup-repo.sh extracts operator-
# supplied tarballs in the `--from-tarball` brownfield-migration path.
# Alpine's busybox tar applet has historically had weaker path-traversal
# protections than GNU tar (which has refused absolute paths and `..`
# segments by default since 1.30). Installing the `tar` package puts GNU
# tar at /usr/bin/tar ahead of busybox's applet, so plain `tar` invocations
# in setup-repo.sh resolve to GNU. Combined with the pre-extraction
# entry-name check in setup-repo.sh, this is defense in depth.
# sudo is installed so the git user can invoke a single root-owned helper
# (stamp-ensure-repo-key) for per-repo deploy-key generation, preserving
# the legacy root:git ownership posture on the key files while still
# allowing lazy on-demand generation. See server/sudoers.d-stamp for the
# tightly-scoped policy entry.
RUN apk add --no-cache git openssh-server openssh-client bash nodejs netcat-openbsd tar sudo \
 && adduser -D -s /usr/bin/git-shell -h /home/git git \
 && sed -i 's/^git:!/git:*/' /etc/shadow \
 && mkdir -p /srv/git /home/git/.ssh /home/git/git-shell-commands /etc/stamp \
 && chown -R git:git /srv/git /home/git \
 && chmod 700 /home/git/.ssh
# NOTE: ssh-keygen -A is intentionally NOT run at build time. Host keys
# baked into the image rotate on every container rebuild, breaking every
# operator's known_hosts on every redeploy. entrypoint.sh generates host
# keys on first boot into /srv/git/.ssh-host-keys/ (the persistent volume)
# and reuses them on subsequent boots, so the same image deployed multiple
# times keeps the same host identity.

# Harden sshd: no password auth, no root login, no forwarding of any kind,
# tightened connection-establishment limits.
#
# Forwarding: git-shell blocks the *interactive* command surface, but ssh
# port/agent/X11/StreamLocal forwarding is negotiated independently of the
# user's shell. Without these flags, any holder of a key in AUTHORIZED_KEYS
# can `ssh -L`, `ssh -R`, or `ssh -D` against the stamp container — turning
# the SSH endpoint into a SOCKS proxy into the host's private network and
# an outbound tunnel from it. Nothing in stamp's documented workflow uses
# forwarding (pushers do `git push` and `ssh git@<host> new-stamp-repo …`
# only), so disabling all five surfaces is a strict tightening.
#
# Connection limits: pubkey-only auth removes the brute-force concern, but
# pre-auth slot exhaustion is still cheap. MaxStartups 10:50:50 begins
# probabilistic 50% dropping at 10 concurrent unauthed handshakes and full
# dropping at 50, leaving headroom for parallel CI pushes while bounding
# the worst case; MaxAuthTries 3 + LoginGraceTime 30 close the half-open-
# handshake hold. MaxSessions 5 caps multiplexed channels per accepted
# connection — git push needs one channel, `ssh new-stamp-repo` needs one;
# 5 is a generous ceiling that prevents a single connection from opening
# hundreds of channels for resource consumption.
#
# Implementation note: we PREPEND these directives to sshd_config rather
# than sed-edit-in-place. OpenSSH uses "first obtained value wins" for
# these keys, so prepending guarantees the directive applies regardless
# of whether the stock Alpine sshd_config already mentions the key (an
# in-place sed s/^#*Foo.*/Foo no/ silently no-ops on absent keys, and
# Alpine's stock config does not include AllowStreamLocalForwarding,
# PermitTunnel, or MaxStartups in every version — exactly the keys
# whose compiled-in defaults are insecure for our threat model).
RUN { \
      printf '%s\n' \
        '# Stamp hardening — prepended; OpenSSH uses first-match for these.' \
        'PasswordAuthentication no' \
        'PermitRootLogin no' \
        'PubkeyAuthentication yes' \
        'AllowTcpForwarding no' \
        'AllowAgentForwarding no' \
        'AllowStreamLocalForwarding no' \
        'X11Forwarding no' \
        'GatewayPorts no' \
        'PermitTunnel no' \
        'MaxAuthTries 3' \
        'LoginGraceTime 30' \
        'MaxStartups 10:50:50' \
        'MaxSessions 5' \
        '# Membership resolver: consult the stamp users DB before falling' \
        '# back to AuthorizedKeysFile. sshd passes the offered key fingerprint' \
        '# as %f (SHA256:<base64>); the resolver prints the matching' \
        '# authorized_keys line on a hit, exits empty on a miss. The legacy' \
        '# /home/git/.ssh/authorized_keys path stays in play during the' \
        "# env-var → sqlite transition (phase 1 of the multi-user onboarding)" \
        "# so an operator who hasn't rolled phase-3 CLI tooling yet still has" \
        '# the env var as an escape hatch.' \
        'AuthorizedKeysCommand /usr/local/sbin/stamp-authorized-keys %u %f' \
        'AuthorizedKeysCommandUser git' \
        '# Expose successful auth info (pubkey wire blob) to user sessions' \
        '# via SSH_USER_AUTH. The phase-2 stamp-mint-invite wrapper reads' \
        '# this file to bind the connection to a user row in the membership' \
        '# DB by fingerprint — without it, the wrapper has no reliable way' \
        '# to know which sshd-authenticated key just connected.' \
        'ExposeAuthInfo yes' \
        ''; \
      cat /etc/ssh/sshd_config; \
    } > /etc/ssh/sshd_config.new \
 && mv /etc/ssh/sshd_config.new /etc/ssh/sshd_config \
 && chmod 0644 /etc/ssh/sshd_config

# Bake GitHub.com's SSH host keys into the system-wide known_hosts so the
# post-receive mirror-push leg can verify the destination without TOFU when
# pushing as a deploy-key (SSH transport). Without this, the first SSH push
# from a fresh container would either prompt (hangs the hook) or, with
# StrictHostKeyChecking=accept-new, accept whatever responds on github.com:22
# — turning a DNS or routing compromise into a key-disclosure path.
#
# Three key types pinned (ed25519, ecdsa-sha2-nistp256, rsa) covering every
# advertised GitHub host key. The ed25519 key has been stable since 2022;
# the RSA key was rotated in March 2023 after a key disclosure. A future
# rotation requires rebuilding this image with the new key value — that's
# a manual operator step, but rotation is rare (years between events) and
# the alternative (looser StrictHostKeyChecking) would silently accept an
# attacker-controlled host key during the rotation window.
COPY server/github-known-hosts /etc/ssh/ssh_known_hosts
RUN chmod 0644 /etc/ssh/ssh_known_hosts

COPY --from=builder /build/dist/hooks/pre-receive.cjs /etc/stamp/pre-receive.cjs
COPY --from=builder /build/dist/hooks/post-receive.cjs /etc/stamp/post-receive.cjs
# AuthorizedKeysCommand resolver — bundled CJS, ships at /usr/local/sbin/.
# sshd refuses to load the command if the file or any parent directory is
# group/other-writable, so the chmod at the end of this stage pins both
# the file (0755) and we rely on the image's stock /usr/local/sbin (root:root
# 0755) for the parent.
COPY --from=builder /build/dist/server/authorized-keys.cjs /usr/local/sbin/stamp-authorized-keys
# Boot-time seeder — synchronizes AUTHORIZED_KEYS env var into the
# membership sqlite. Invoked by entrypoint.sh as root on every container
# start, before sshd exec.
COPY --from=builder /build/dist/server/seed-users.cjs /usr/local/sbin/stamp-seed-users
# Invite-mint SSH command. Invoked as `git@server stamp-mint-invite <name>`
# via git-shell command dispatch (symlinked below). Binds to the
# authenticated SSH key via SSH_USER_AUTH (ExposeAuthInfo).
COPY --from=builder /build/dist/server/mint-invite.cjs /usr/local/bin/stamp-mint-invite
# HTTP listener for invite/accept. Started by entrypoint.sh as the git
# user, runs alongside sshd on STAMP_HTTP_PORT (default 8080). TLS is
# the hosting platform's job (Railway terminates at its edge proxy).
COPY --from=builder /build/dist/server/start-http-server.cjs /usr/local/sbin/stamp-http-server
COPY scripts/setup-repo.sh /usr/local/bin/setup-repo.sh
COPY server/new-stamp-repo /usr/local/bin/new-stamp-repo
COPY server/delete-stamp-repo /usr/local/bin/delete-stamp-repo
COPY server/restore-stamp-repo /usr/local/bin/restore-stamp-repo
COPY server/list-trash /usr/local/bin/list-trash
COPY server/stamp-server-pubkey /usr/local/bin/stamp-server-pubkey
COPY server/stamp-ensure-repo-key /usr/local/sbin/stamp-ensure-repo-key
COPY server/entrypoint.sh /entrypoint.sh

# Sudoers fragment that grants the unprivileged git user passwordless
# invocation of stamp-ensure-repo-key (and nothing else). 0440 root:root
# is required by sudo's own file-perm check — sudo refuses to load a
# fragment that's group- or world-writable. visudo -c at build time
# catches a malformed fragment before the image ships; without it, sudo
# silently ignores the fragment at runtime and the lazy-key-generation
# path appears to be allowed but actually fails with "git is not in the
# sudoers file" — surfacing the typo at build time avoids a confusing
# production debug session.
COPY server/sudoers.d-stamp /etc/sudoers.d/stamp-server
RUN chown root:root /etc/sudoers.d/stamp-server \
 && chmod 0440 /etc/sudoers.d/stamp-server \
 && visudo -c -f /etc/sudoers.d/stamp-server

RUN chmod +x /etc/stamp/pre-receive.cjs \
             /etc/stamp/post-receive.cjs \
             /usr/local/bin/setup-repo.sh \
             /usr/local/bin/new-stamp-repo \
             /usr/local/bin/delete-stamp-repo \
             /usr/local/bin/restore-stamp-repo \
             /usr/local/bin/list-trash \
             /usr/local/bin/stamp-server-pubkey \
             /usr/local/bin/stamp-mint-invite \
             /usr/local/sbin/stamp-ensure-repo-key \
             /usr/local/sbin/stamp-authorized-keys \
             /usr/local/sbin/stamp-seed-users \
             /usr/local/sbin/stamp-http-server \
             /entrypoint.sh \
 && chown root:root /usr/local/sbin/stamp-authorized-keys \
 && chmod 0755     /usr/local/sbin/stamp-authorized-keys
# Only stamp-authorized-keys needs the extra chown root:root + 0755:
# sshd's AuthorizedKeysCommand validation refuses to load the script if
# the file or any parent directory is group/other-writable. The other
# server-side scripts (stamp-seed-users, stamp-http-server,
# stamp-mint-invite) are invoked by entrypoint.sh as root, by sshd
# via git-shell-commands, or by the operator's CLI — none go through
# sshd's strict-perms check.

# Symlink the operator-facing wrapper scripts into the directory git-shell
# scans for allowed commands. With these in place, `ssh git@<host> new-
# stamp-repo <name>` continues to work exactly as before — the only thing
# pushers lose is interactive shell access, which they shouldn't have had.
# git-shell's built-in commands (git-receive-pack, git-upload-pack,
# git-upload-archive) cover normal git push/fetch operations without
# needing entries here.
RUN ln -s /usr/local/bin/new-stamp-repo /home/git/git-shell-commands/new-stamp-repo \
 && ln -s /usr/local/bin/delete-stamp-repo /home/git/git-shell-commands/delete-stamp-repo \
 && ln -s /usr/local/bin/restore-stamp-repo /home/git/git-shell-commands/restore-stamp-repo \
 && ln -s /usr/local/bin/list-trash /home/git/git-shell-commands/list-trash \
 && ln -s /usr/local/bin/stamp-server-pubkey /home/git/git-shell-commands/stamp-server-pubkey \
 && ln -s /usr/local/bin/stamp-mint-invite /home/git/git-shell-commands/stamp-mint-invite \
 && chown -R root:git /home/git/git-shell-commands \
 && chmod 0755 /home/git/git-shell-commands

EXPOSE 22
# HTTP listener for the invite-accept endpoint (POST /invite/accept).
# Plain HTTP inside the container; TLS termination is the hosting
# platform's job (Railway terminates at its edge proxy and forwards
# decrypted traffic to this port). Override via STAMP_HTTP_PORT at run
# time. Operators who want to expose this externally must point
# STAMP_PUBLIC_URL at the platform-facing URL so stamp-mint-invite can
# bake it into the share URLs it prints.
EXPOSE 8080

# HEALTHCHECK lets the orchestrator (Railway/Fly/Docker) distinguish a
# running container from one whose sshd has crashed or hung while PID 1
# (entrypoint.sh) is still alive. Without it, pushers see "connection
# refused" while the platform reports the service as healthy. nc against
# loopback:22 is the cheapest TCP-level probe; an actual ssh handshake
# would require a key and pollute auth logs.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD nc -z 127.0.0.1 22 || exit 1

CMD ["/entrypoint.sh"]
