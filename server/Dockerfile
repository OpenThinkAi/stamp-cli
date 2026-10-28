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
FROM node:24-alpine3.21@sha256:b8f7c9056af700568c1ce76173f1c93743fb64ca1343e18cdf3a6ded8985ad3d AS builder
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
FROM alpine:3.24@sha256:a2d49ea686c2adfe3c992e47dc3b5e7fa6e6b5055609400dc2acaeb241c829f4

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
# sudo is installed so the git user can invoke exactly two root-owned
# helpers: stamp-ensure-repo-key (per-repo deploy-key generation) and
# stamp-sign-approval (signs server review approvals with the root-only
# review-signing key, AGT-2263). See server/sudoers.d-stamp for the
# tightly-scoped policy entries.
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
        '# Membership resolver: the stamp users DB is the ONLY source of' \
        '# SSH access (AGT-2260). AuthorizedKeysFile none turns off the' \
        '# per-user authorized_keys files, so `stamp users remove` revokes' \
        '# a key for real. sshd passes the offered key fingerprint as %f' \
        '# (SHA256:<base64>); the resolver prints the matching line on a' \
        '# hit, exits empty on a miss. Every line it prints carries' \
        '# command="stamp-gate <id>",restrict (AGT-2265).' \
        'AuthorizedKeysFile none' \
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
 && chmod 0644 /etc/ssh/sshd_config \
 && first=$(grep -iE '^[[:space:]]*AuthorizedKeysFile([[:space:]]|$)' /etc/ssh/sshd_config | head -1 | tr -s ' \t' ' ') \
 && if [ "$first" != 'AuthorizedKeysFile none' ]; then \
      echo "error: first AuthorizedKeysFile directive is '$first', expected 'AuthorizedKeysFile none' (AGT-2260)" >&2; exit 1; \
    fi

# Strip every `Subsystem` directive (AGT-2271). Alpine's stock sshd_config
# ships `Subsystem sftp ...`, and a subsystem request is NOT routed through
# the user's login shell: sshd runs the subsystem directly (internal-sftp
# runs in-process), so git-shell never sees it. With the line present, any
# enrolled key — any role — opens an sftp session as the git user and can
# write straight into the bare repos (refs/objects, skipping pre-receive and
# the whole review gate) and into the membership DB (root:git 0660). Nothing
# in stamp's workflow uses sftp/scp-over-sftp; pushers only run git and the
# git-shell-commands verbs. The prepend trick above can't disable a
# subsystem (there is no "Subsystem none"), so we delete the lines instead —
# from the main config and any drop-in under sshd_config.d. Keywords are
# case-insensitive in sshd_config, hence grep -i. The final grep fails the
# build if a Subsystem line survives (e.g. a future base image moves it).
RUN for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*; do \
      [ -f "$f" ] || continue; \
      grep -viE '^[[:space:]]*Subsystem([[:space:]]|$)' "$f" > "$f.new" || true; \
      cat "$f.new" > "$f"; rm -f "$f.new"; \
    done \
 && if grep -rqiE '^[[:space:]]*Subsystem([[:space:]]|$)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null; then \
      echo 'error: a Subsystem directive survived the strip (AGT-2271)' >&2; exit 1; \
    fi

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
# Boot-time seeder — bootstraps an EMPTY membership sqlite from the
# AUTHORIZED_KEYS env var, once (AGT-2260). Invoked by entrypoint.sh as root
# on every container start, before sshd exec; after the first bootstrap it
# never re-imports, so a removed user stays removed.
COPY --from=builder /build/dist/server/seed-users.cjs /usr/local/sbin/stamp-seed-users
# Break-glass recovery CLI (AGT-2260). users.db is the only source of SSH
# access, so if every admin key is lost the operator opens a root shell in
# the container (railway ssh / docker exec) and runs
# `stamp-break-glass add --role owner <pubkey-file|->`. root:root 0700 (set
# below): the git user can neither read nor execute it, and it is NOT
# symlinked into git-shell-commands or on the stamp-gate verb allowlist, so
# it is unreachable over SSH. It also refuses any uid but 0.
COPY --from=builder /build/dist/server/break-glass.cjs /usr/local/sbin/stamp-break-glass
# Boot-time review-signing-key bootstrap. Invoked by entrypoint.sh as
# root after stamp-seed-users, before sshd exec. No-ops when
# ANTHROPIC_API_KEY is unset (review capability disabled). On first
# boot with the env var set, mints an Ed25519 keypair at
# $STAMP_STATE_DIR/review-signing-key.pem (mode 0600) and prints the
# fingerprint loudly to stdout (operator-instruction prose, not an
# error); subsequent boots reuse it.
COPY --from=builder /build/dist/server/bootstrap-review-key.cjs /usr/local/sbin/stamp-bootstrap-review-key
# Root signing helper (AGT-2263). The review-signing key is root:root 0600
# and never readable by git; stamp-review (git) signs each approval by
# piping its canonical bytes to `sudo -n /usr/local/sbin/stamp-sign-approval`
# (the one no-argument sudoers rule in server/sudoers.d-stamp). The helper
# validates the payload as a well-formed ApprovalV4 under its own key id
# with a fresh issued_at and prints only the signature. A helper, NOT a
# verb: not symlinked into git-shell-commands, not on stamp-gate's
# allowlist, so unreachable over SSH. root:root 0755 (set below).
COPY --from=builder /build/dist/server/sign-approval.cjs /usr/local/sbin/stamp-sign-approval
# Boot-time prompts-cache populator (AGT-375). Invoked by entrypoint.sh
# as root after stamp-bootstrap-review-key. No-ops when
# STAMP_PROMPTS_REPO_URL is unset (Phase A bundled-prompts path); when
# set, clones/fetches the external prompts repo into the cache root
# (default /srv/git/.prompts-cache) before sshd / the HTTP listener
# launch, so the cache is populated before any review request can land.
# Failures abort the boot — Phase B operators must fix the
# misconfiguration before traffic resumes.
COPY --from=builder /build/dist/server/prompts-cache-bootstrap.cjs /usr/local/sbin/stamp-prompts-cache-bootstrap
# Invite-mint SSH command. Invoked as `git@server stamp-mint-invite <name>`
# via git-shell command dispatch (symlinked below). Binds to the
# authenticated SSH key via SSH_USER_AUTH (ExposeAuthInfo).
COPY --from=builder /build/dist/server/mint-invite.cjs /usr/local/bin/stamp-mint-invite
# Server-attested review SSH command (AGT-328 scaffold). Invoked as
# `git@server stamp-review --reviewer X --org Y --repo Z --base-sha S
# --head-sha H --diff-sha256 D < diff` via git-shell command dispatch
# (symlinked below). Same SSH_USER_AUTH identity-binding pattern as
# stamp-mint-invite; rejects callers below role=member. AGT-330 fills
# in the Anthropic call; AGT-331 fills in the real signature.
COPY --from=builder /build/dist/server/stamp-review.cjs /usr/local/bin/stamp-review
# Trash-retention purge SSH command (AGT-423). `git@server purge-trash
# --older-than <N>d` removes soft-deleted bare repos older than the TTL.
# Wrapped by `stamp server-repos purge`; symlinked into git-shell-commands
# below. Role-gated to owner/admin (AGT-423).
COPY --from=builder /build/dist/server/purge-trash.cjs /usr/local/bin/purge-trash
# Role gate the shell repo verbs call before touching /srv/git (AGT-2259):
# new-stamp-repo, delete-stamp-repo (incl. --purge) and restore-stamp-repo
# run `stamp-require-role admin "<action>"`, which resolves the caller from
# SSH_USER_AUTH against users.db and refuses role=member (exit 3). A
# helper, not a verb — deliberately NOT symlinked into git-shell-commands.
COPY --from=builder /build/dist/server/require-role.cjs /usr/local/sbin/stamp-require-role
# SSH session gate (AGT-2265). The AuthorizedKeysCommand resolver (the only
# source of SSH access — AuthorizedKeysFile is none) emits every key as
# `command="stamp-gate <user-id>",restrict`, so every session runs the
# stamp-gate verb whatever the client asked for. stamp-gate (shell, in
# git-shell-commands so git-shell will run it as the forced command) calls
# stamp-gate-check, which resolves the caller, parses SSH_ORIGINAL_COMMAND,
# refuses any repo path that isn't a live /srv/git/<name>.git (so .trash,
# .prompts-cache and every other dot-dir are never served), applies the
# role/grant rule, and prints the re-quoted command; stamp-gate then execs
# git-shell -c with it. stamp-gate-check is a helper, NOT a verb.
COPY --from=builder /build/dist/server/gate-check.cjs /usr/local/sbin/stamp-gate-check
COPY server/stamp-gate /usr/local/bin/stamp-gate
# Peer-agentic review SSH verbs (AGT-427 / AGT-453). Only stamp-pr-opened
# remains — the six seat-protocol verbs were migrated to HTTP POST
# endpoints in AGT-453. The SQLite migration always runs at boot regardless
# of STAMP_PEER_REVIEWS_ENABLED (so an operator enabling the feature on a
# running deploy finds the tables already present).
COPY --from=builder /build/dist/server/pr-opened.cjs /usr/local/bin/stamp-pr-opened
# HTTP listener for invite/accept. Started by entrypoint.sh as the git
# user, runs alongside sshd on STAMP_HTTP_PORT (default 8080). TLS is
# the hosting platform's job (Railway terminates at its edge proxy).
COPY --from=builder /build/dist/server/start-http-server.cjs /usr/local/sbin/stamp-http-server
# User-management SSH command. One bundle dispatches list / promote /
# demote / remove via argv. Symlinked below so git-shell finds it.
COPY --from=builder /build/dist/server/users-cli.cjs /usr/local/bin/stamp-users
COPY scripts/setup-repo.sh /usr/local/bin/setup-repo.sh
COPY server/new-stamp-repo /usr/local/bin/new-stamp-repo
COPY server/delete-stamp-repo /usr/local/bin/delete-stamp-repo
COPY server/restore-stamp-repo /usr/local/bin/restore-stamp-repo
COPY server/list-trash /usr/local/bin/list-trash
COPY server/list-stamp-repos /usr/local/bin/list-stamp-repos
COPY server/stamp-server-pubkey /usr/local/bin/stamp-server-pubkey
COPY server/resync-mirror /usr/local/bin/resync-mirror
COPY server/stamp-ensure-repo-key /usr/local/sbin/stamp-ensure-repo-key
COPY server/entrypoint.sh /entrypoint.sh
# entrypoint.sh sources this guard via `. "$(dirname "$0")/lib/check-prompts-dir.sh"`
# (i.e. /lib/check-prompts-dir.sh). Must be copied into the image or the
# entrypoint aborts under `set -e` on boot (AGT-411 regression).
COPY server/lib/check-prompts-dir.sh /lib/check-prompts-dir.sh
# entrypoint.sh sources this helper via `. "$(dirname "$0")/lib/inject-sshd-setenv.sh"`
# (i.e. /lib/inject-sshd-setenv.sh). Must be copied into the image or the
# entrypoint aborts on first boot when STAMP_SSH_PASS_ENV injection runs (AGT-469).
COPY server/lib/inject-sshd-setenv.sh /lib/inject-sshd-setenv.sh

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

# Canonical reviewer prompts (security/standards/product). The SSH-invoked
# stamp-review command resolves these at review time from
# ${STAMP_PROMPTS_DIR:-/etc/stamp/reviewers}/<reviewer>.md and includes a
# content hash in the signed verdict — so substituting prompts at runtime
# would invalidate downstream verification. Bundling them in the image
# (rather than mounting from the host) is what gives the server its
# "operator controls the prompt bytes" trust property. See
# server/reviewers/README.md for the editing/rebuild workflow.
#
# Mode 0644 root:root: world-readable so the git-shell user that runs
# stamp-review can read without elevation. The chmod is explicit (rather
# than relying on --chmod= on COPY) because this Dockerfile has no
# `# syntax=docker/dockerfile:1.4+` directive enabling that COPY flag.
COPY server/reviewers/ /etc/stamp/reviewers/
RUN chown -R root:root /etc/stamp/reviewers \
 && chmod 0755 /etc/stamp/reviewers \
 && chmod 0644 /etc/stamp/reviewers/*.md

RUN chmod +x /etc/stamp/pre-receive.cjs \
             /etc/stamp/post-receive.cjs \
             /usr/local/bin/setup-repo.sh \
             /usr/local/bin/new-stamp-repo \
             /usr/local/bin/delete-stamp-repo \
             /usr/local/bin/restore-stamp-repo \
             /usr/local/bin/list-trash \
             /usr/local/bin/list-stamp-repos \
             /usr/local/bin/stamp-server-pubkey \
             /usr/local/bin/resync-mirror \
             /usr/local/bin/stamp-mint-invite \
             /usr/local/bin/stamp-review \
             /usr/local/bin/purge-trash \
             /usr/local/bin/stamp-users \
             /usr/local/bin/stamp-pr-opened \
             /usr/local/bin/stamp-gate \
             /usr/local/sbin/stamp-ensure-repo-key \
             /usr/local/sbin/stamp-require-role \
             /usr/local/sbin/stamp-gate-check \
             /usr/local/sbin/stamp-authorized-keys \
             /usr/local/sbin/stamp-seed-users \
             /usr/local/sbin/stamp-http-server \
             /usr/local/sbin/stamp-bootstrap-review-key \
             /usr/local/sbin/stamp-prompts-cache-bootstrap \
             /entrypoint.sh \
 && chown root:root /usr/local/sbin/stamp-sign-approval \
 && chmod 0755     /usr/local/sbin/stamp-sign-approval \
 && chown root:root /usr/local/sbin/stamp-authorized-keys \
 && chmod 0755     /usr/local/sbin/stamp-authorized-keys \
 && chown root:root /usr/local/sbin/stamp-break-glass \
 && chmod 0700     /usr/local/sbin/stamp-break-glass
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
 && ln -s /usr/local/bin/list-stamp-repos /home/git/git-shell-commands/list-stamp-repos \
 && ln -s /usr/local/bin/stamp-server-pubkey /home/git/git-shell-commands/stamp-server-pubkey \
 && ln -s /usr/local/bin/resync-mirror /home/git/git-shell-commands/resync-mirror \
 && ln -s /usr/local/bin/stamp-mint-invite /home/git/git-shell-commands/stamp-mint-invite \
 && ln -s /usr/local/bin/stamp-review /home/git/git-shell-commands/stamp-review \
 && ln -s /usr/local/bin/purge-trash /home/git/git-shell-commands/purge-trash \
 && ln -s /usr/local/bin/stamp-users /home/git/git-shell-commands/stamp-users \
 && ln -s /usr/local/bin/stamp-pr-opened /home/git/git-shell-commands/stamp-pr-opened \
 && ln -s /usr/local/bin/stamp-gate /home/git/git-shell-commands/stamp-gate \
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
