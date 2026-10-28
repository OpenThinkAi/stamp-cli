#!/bin/sh
#
# Container entrypoint: populate per-deployment config from env vars, then
# start sshd.
#
#   AUTHORIZED_KEYS   newline-delimited SSH public keys that bootstrap an EMPTY
#                     users table as admins, once (AGT-2260). After that,
#                     users.db is the only source of SSH access and is managed
#                     with `stamp invites` / `stamp users` (or, locked out,
#                     the root-only stamp-break-glass CLI).
#   OPERATOR_PUB_KEY  PEM-encoded public key of the operator; will be seeded
#                     into each new repo as the first trusted signer
#
set -e

# Reviewer-prompt inventory. The image bundles canonical prompts at
# /etc/stamp/reviewers/<name>.md (see server/reviewers/README.md). The
# defensive mkdir -p covers image variants that didn't bundle the dir —
# without it, the SSH-time resolver would hard-fail on opendir() rather
# than degrade to "no server-bundled prompt available." Log the file list
# at boot so operators can confirm what shipped without exec'ing into the
# container.
mkdir -p /etc/stamp/reviewers
echo "reviewer prompts available: $(ls /etc/stamp/reviewers/*.md 2>/dev/null | xargs -n1 basename 2>/dev/null | paste -sd ',' - || echo none)" >&2

# Platform volume mounts (Railway, Fly, etc.) come up root-owned, overriding
# any build-time chown. Fix at boot so the git user can create and write its
# own repos.
#
# Scoped, not `chown -R git:git /srv/git` (AGT-2263): the recursive form ran
# as root over the whole volume and so handed every root-owned file in the
# dot-dirs — notably the review-signing private key in .stamp-state — to the
# git user on each boot. Now: the volume root itself (non-recursive, -h so a
# symlink is never followed), then each bare repo /srv/git/<name>.git that
# is a real directory (a symlinked "repo" is skipped) with -R -h, so a
# symlink planted inside a repo is re-owned itself rather than root chowning
# whatever it points at. Dot-dirs (.stamp-state, .ssh-host-keys,
# .ssh-client-keys, .prompts-cache, .trash) are never swept: each is pinned
# explicitly below or created and owned by the git user itself.
chown -h git:git /srv/git 2>/dev/null || true
for r in /srv/git/*.git; do
  [ -d "$r" ] && [ ! -L "$r" ] || continue
  chown -R -h git:git "$r" 2>/dev/null || true
  # AGT-2264: no access for "other". The HTTP listener runs as stamp-http,
  # which is neither git nor in the git group; a bare repo created with the
  # default umask is world-readable, so without this a listener compromise
  # could read every repo. Only the top-level dir needs it (it blocks
  # traversal); setup-repo.sh / restore-stamp-repo apply it to new repos.
  chmod o-rwx "$r" 2>/dev/null || true
done
if [ -d /srv/git/.trash ] && [ ! -L /srv/git/.trash ]; then
  chmod o-rwx /srv/git/.trash
fi

# Sticky bit on /srv/git: prevents the git user from renaming or deleting
# root-owned subdirectories like .ssh-host-keys. Without sticky, write
# permission on the parent directory grants rename/delete on its children
# regardless of child ownership; the prior chmod 700 on .ssh-host-keys
# only protected the contents, not the directory entry. Sticky bit is the
# canonical fix (mirrors /tmp).
#
# Mode 1751 (AGT-2264): "other" — which now includes the stamp-http
# listener user — may traverse /srv/git (it must reach
# .stamp-state/users.db) but not list it. Every entry inside it is closed to
# "other" by its own mode (repos and .trash o-rwx above, the key dirs
# root-only / root:git, .stamp-state root:stamp-db).
chmod 1751 /srv/git

# Refresh stamp hooks in every existing bare repo.
#
# When setup-repo.sh provisioned each repo, it COPIED /etc/stamp/*.cjs into
# that repo's hooks/ directory. Git runs the per-repo copy at push time, not
# /etc/stamp/ directly — so a container rebuild with new hook code doesn't
# reach existing repos on its own. Walk /srv/git/ on every boot and replace
# each repo's hooks with the fresh bundle from /etc/stamp/ (root:root 0755).
# Idempotent; no-ops if the volume is empty (first boot, no repos yet).
#
# AGT-2261: hooks/ is git-writable, so the refresh never follows a symlink
# there — a planted hooks/ or hooks/<name> link is replaced, never written
# through, and each hook is staged root-only and rename(2)d into place. See
# lib/refresh-repo-hooks.sh. It MUST run here, after the scoped chown and
# before anything runs as git or stamp-http (the prompts-cache bootstrap,
# stamp-workers, the HTTP listener, sshd): its lstat-then-rename steps are only race-free while no
# git-user process exists. A hook refreshed at boot is not permanent — git
# owns the repo directory and can still swap hooks/ between boots; the next
# boot replaces it again.
. "$(dirname "$0")/lib/refresh-repo-hooks.sh"
_refresh_repo_hooks || exit 1

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

# No AuthorizedKeysFile (AGT-2260): sshd_config sets `AuthorizedKeysFile
# none`, so users.db (via the AuthorizedKeysCommand resolver) is the only
# source of SSH access and `stamp users remove` revokes a key for real.
# Earlier images wrote AUTHORIZED_KEYS to /home/git/.ssh/authorized_keys on
# every boot; sshd no longer reads it, but delete any copy a previous image
# left on disk so nothing suggests it still grants access.
rm -f /home/git/.ssh/authorized_keys /home/git/.ssh/authorized_keys2
if [ -n "$AUTHORIZED_KEYS" ]; then
  echo "note: AUTHORIZED_KEYS only bootstraps an empty server (first boot); ongoing user management goes through 'stamp invites mint' and 'stamp users …'. See server/README.md." >&2
fi

# Membership sqlite — back-end for the AuthorizedKeysCommand resolver
# (sshd consults this on every connection; it is the only source of SSH
# access) AND the HTTP server's invite-accept endpoint
# (which writes new user rows). The DB lives on the persistent volume
# so it survives container redeploys.
#
# Group (AGT-2264): stamp-db, not git. The git user AND the stamp-http
# listener user are both members; stamp-http is deliberately NOT in the git
# group (which reads /etc/stamp/env and the root:git key directory), so the
# DB is shared through a group that grants nothing else. The leading setgid
# bit (2) makes every file created in the dir — sqlite's -journal sidecar
# included — inherit group stamp-db, so a hot journal left by a crash of
# either writer stays readable by the other.
#
# Directory mode: root:stamp-db 3770. The 0770 bits give the git user
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
# File mode: root:stamp-db 0660. The HTTP server (stamp-http) needs WRITE
# access for invite/accept (new user rows) and the peer seat endpoints;
# the git-run SSH verbs write it too. The AuthorizedKeysCommand resolver
# runs as git but opens the DB `readOnly: true` in code, so it can't
# mutate state even with the write bit set.
#
# stamp-seed-users bootstraps the users table from AUTHORIZED_KEYS ONCE
# (AGT-2260): only when the table is empty and no bootstrap marker is
# recorded, it imports each key as role=admin source=env and records the
# marker. On a server upgraded with users already present it records the
# marker without importing. It runs every boot but never re-imports, so a
# user removed with `stamp users remove` is not resurrected on restart.
STAMP_STATE_DIR=/srv/git/.stamp-state
mkdir -p "$STAMP_STATE_DIR"
chown root:stamp-db "$STAMP_STATE_DIR"
chmod 3770 "$STAMP_STATE_DIR"
# Export so child processes (stamp-bootstrap-review-key below; future
# state-dir-aware helpers) can resolve the same location without
# re-hardcoding the path. The DB-write code paths above use the shell
# var directly, so no behavior change for them.
export STAMP_STATE_DIR
if /usr/local/sbin/stamp-seed-users; then
  if [ -f "$STAMP_STATE_DIR/users.db" ] && [ ! -L "$STAMP_STATE_DIR/users.db" ]; then
    chown root:stamp-db "$STAMP_STATE_DIR/users.db"
    chmod 0660 "$STAMP_STATE_DIR/users.db"
  fi
  # Upgrade (AGT-2264): sidecars an earlier image left behind carry group
  # git, which stamp-http can't open. Re-group them (never via a symlink).
  for _side in "$STAMP_STATE_DIR/users.db-journal" "$STAMP_STATE_DIR/users.db-wal" "$STAMP_STATE_DIR/users.db-shm"; do
    if [ -f "$_side" ] && [ ! -L "$_side" ]; then
      chgrp stamp-db "$_side" && chmod 0660 "$_side"
    fi
  done
  unset _side
else
  # Don't abort the boot: existing members in users.db keep working. There
  # is no file fallback (AuthorizedKeysFile none) — a server with an empty
  # or unreadable users.db admits nobody until an operator runs
  # stamp-break-glass from a root shell in the container.
  echo "WARNING: stamp-seed-users failed; only keys already in users.db can connect (recovery: stamp-break-glass, see server/README.md)" >&2
fi

# Review-signing key bootstrap (AGT-327). When ANTHROPIC_API_KEY is
# set, the server gains review-attestation capability; that capability
# requires an Ed25519 signing key under stamp-server's control so the
# operator cannot forge per-approval signatures. We mint on first boot
# and reuse on every subsequent boot.
#
# Failure of this step IS fatal — unlike stamp-seed-users (whose failure
# leaves existing members working), there's no fallback for a
# missing or wrong-mode review key. The capability either works
# correctly (with stable identity) or refuses to start. Reviews
# remain opt-in via ANTHROPIC_API_KEY: with it unset, the bootstrap
# logs "skipped" and exits 0 and the server continues to boot as it
# does today.
#
# Permissions (AGT-2263): the script runs as root (everything in
# entrypoint.sh does until the exec at the bottom). The private .pem
# is root:root 0600 and the bootstrap FAILS THE BOOT if it is anything
# else (wrong owner, wrong mode, a symlink). The git user cannot read
# it: stamp-review, which runs as git, signs each approval through the
# root helper /usr/local/sbin/stamp-sign-approval (one no-argument
# sudoers rule; the helper only signs a well-formed approval under its
# own key id). The .pub sibling is root:root 0644 and git-readable —
# stamp-review and the stamp-server-pubkey wrapper read it. Both live
# in $STAMP_STATE_DIR, 3770 root:stamp-db, so the git user (a stamp-db
# member) can traverse but not delete/rename the root-owned files within.
# The stamp-http listener is also a stamp-db member: it can read the .pub
# but not the 0600 private key, and has no sudo rule for the helper.
#
# Upgrade: earlier images' boot-time `chown -R git:git /srv/git` left
# the key git-owned. The bootstrap re-owns a key (and .pub) in exactly
# that state to root:root and logs it; any other foreign owner fails.
if /usr/local/sbin/stamp-bootstrap-review-key; then
  # Successful bootstrap. The script handles its own logging
  # (silent on disabled-capability skip, loud banner on first
  # generation, one-line reuse note on subsequent boots).
  #
  # AGT-2264: $STAMP_STATE_DIR is setgid stamp-db, so a key minted there
  # inherits group stamp-db. The 0600 / 0644 modes already keep the private
  # half from the group, but pin the group back to root so the key stays
  # exactly root:root (never via a symlink).
  _rk="${REVIEW_SIGNING_KEY_PATH:-$STAMP_STATE_DIR/review-signing-key.pem}"
  case "$_rk" in *.pem) _rp="${_rk%.pem}.pub" ;; *) _rp="$_rk.pub" ;; esac
  for _f in "$_rk" "$_rp"; do
    if [ -f "$_f" ] && [ ! -L "$_f" ] && [ "$(stat -c %u "$_f")" = 0 ]; then
      chgrp root "$_f"
    fi
  done
  unset _rk _rp _f
else
  # Lowercase `error: ` prefix to match the codebase convention; the
  # Node layer already uses it (process.stderr.write("error: ...")).
  # The pre-existing "WARNING: stamp-seed-users failed" line above is
  # a legacy convention break, not a reference for new code.
  echo "error: stamp-bootstrap-review-key failed; aborting startup" >&2
  exit 1
fi

# Env allowlists + _exec_allowlisted_env for every background / network
# process this script starts as an unprivileged user (AGT-2264).
. "$(dirname "$0")/lib/allowlisted-env.sh"

# External-prompt-storage-via-webhook (Phase B / AGT-375): populate the
# prompts cache from an external github repo on boot, BEFORE sshd or the
# HTTP listener accept any traffic. Three cases:
#
#   - STAMP_PROMPTS_REPO_URL unset → Phase A path stays in effect; the
#     bundled prompts at /etc/stamp/reviewers/ logged above remain the
#     only source. The bootstrap binary itself no-ops; we skip the
#     deploy-key gate too because there's nothing to clone.
#
#   - STAMP_PROMPTS_REPO_URL set + STAMP_PROMPTS_DEPLOY_KEY_PATH set but
#     the key file doesn't exist on the persistent volume → fail fast
#     with an error: line naming the missing path, exit non-zero. This
#     mirrors the stamp-ensure-repo-key UX (operators upload the
#     private half of the deploy key into the volume themselves; we
#     NEVER auto-generate). The prompts-cache module would also throw
#     on the same condition from buildGitEnv, but failing here gives a
#     cleaner one-line boot-log error before any git-network attempt.
#
#   - STAMP_PROMPTS_REPO_URL set + deploy key present (or HTTPS URL, no
#     key needed) → invoke the bootstrap binary, which clones/fetches
#     the cache and logs the SHA + file inventory. Failure aborts the
#     boot via the explicit `if !` below; we don't rely on `set -e`
#     interaction with subshells.
#
# GIT_SSH_KNOWN_HOSTS points at the bundled /etc/ssh/ssh_known_hosts
# (COPY'd from server/github-known-hosts in the Dockerfile) so the
# prompts-cache module's GIT_SSH_COMMAND wiring resolves to a real file
# inside the runtime image. Without this, the module's default-path
# resolution (relative to the .cjs bundle location) would look at
# /server/github-known-hosts which doesn't exist on this image layout.
# Operators can override via STAMP_PROMPTS_KNOWN_HOSTS_PATH if they
# want to pin a different known-hosts file (e.g. self-hosted github
# enterprise). Empty → fall back to the image default.
#
# AGT-2277: STAMP_PROMPTS_CACHE_ROOT must be a dot-dir directly under
# /srv/git (lib/prompts-cache-config.sh says why), checked whether or not
# Phase B is on, since it is persisted for stamp-review below. With
# STAMP_PROMPTS_DEPLOY_KEY_PATH unset, the deploy key is the default path
# when a key is there — the same fallback stamp-workers' runtime refresh and
# the bootstrap binary apply (src/server/promptsCachePaths.ts) — so the key
# is pinned git:git 0600 here in that case too.
. "$(dirname "$0")/lib/prompts-cache-config.sh"
check_prompts_cache_root || exit 1
if [ -n "$STAMP_PROMPTS_REPO_URL" ]; then
  if [ -n "$STAMP_PROMPTS_DEPLOY_KEY_PATH" ] && [ ! -f "$STAMP_PROMPTS_DEPLOY_KEY_PATH" ]; then
    echo "error: STAMP_PROMPTS_DEPLOY_KEY_PATH=$STAMP_PROMPTS_DEPLOY_KEY_PATH does not exist on the volume; provision the private SSH key (mirroring the stamp-ensure-repo-key flow) and redeploy. Never auto-generated." >&2
    exit 1
  fi
  export GIT_SSH_KNOWN_HOSTS="${STAMP_PROMPTS_KNOWN_HOSTS_PATH:-${GIT_SSH_KNOWN_HOSTS:-/etc/ssh/ssh_known_hosts}}"
  _pcroot="${STAMP_PROMPTS_CACHE_ROOT:-$DEFAULT_PROMPTS_CACHE_ROOT}"
  _pkey=$(resolve_prompts_deploy_key)
  # The git-run bootstrap below must be able to read the deploy key and
  # write the cache. Earlier images got that for free from the boot-time
  # `chown -R git:git /srv/git`; that sweep is now scoped to repo dirs
  # (AGT-2263), so hand exactly these paths to git explicitly — the key
  # only if it is a regular file (never follow a symlink), the cache with
  # -R -h (symlinks re-owned, not followed).
  if [ -n "$_pkey" ] && [ -f "$_pkey" ] && [ ! -L "$_pkey" ]; then
    chown git:git "$_pkey"
    chmod 0600 "$_pkey"
  fi
  if [ -d "$_pcroot" ] && [ ! -L "$_pcroot" ]; then
    chown -R -h git:git "$_pcroot" || true
  fi
  # Fix A (AGT-468): run bootstrap as the git user, not root. The deploy key
  # ($_pkey) is git-readable (mode 0600, git-owned via
  # the explicit chown just above), so the user-switch is clean.
  # It gets the same allowlisted env as stamp-workers (AGT-2264: the
  # STAMP_PROMPTS_* / GIT_SSH_KNOWN_HOSTS vars it reads, no bot token or API
  # key) and umask 027, so the cache it creates is closed to "other".
  # Running as git ensures the cache dir and its contents are created with
  # git:git ownership — the poll worker (startPromptsPollWorker, in the
  # stamp-workers process since AGT-2264) also runs as git and would
  # otherwise hit "fatal: dubious ownership" when fetching into a root-owned
  # repo (AGT-376 / git safe.directory semantics).
  if ! ( umask 027
         _exec_allowlisted_env /home/git "$STAMP_WORKERS_ENV" \
           su -s /bin/sh -p git -c 'exec /usr/local/sbin/stamp-prompts-cache-bootstrap' ); then
    echo "error: stamp-prompts-cache-bootstrap failed; aborting startup" >&2
    exit 1
  fi
  # Fix B (AGT-468, belt-and-braces): ensure the cache dir is git-owned before
  # the http-server's poll worker tries to fetch into it. Covers deployment
  # layouts where the cache was migrated from an older root-owned install or
  # where a manual operator chown went wrong. The || true keeps the boot alive
  # if, e.g., the dir doesn't exist yet (Phase B disabled mid-deploy).
  if [ -d "$_pcroot" ] && [ ! -L "$_pcroot" ]; then
    chown -R -h git:git "$_pcroot" || true
    # AGT-2264: closed to "other" (the stamp-http listener). stamp-workers
    # runs with umask 027, so a rebuilt cache stays closed too.
    chmod o-rwx "$_pcroot" || true
  fi
  # The .old dir is the atomic-swap staging area used by cloneOrFetchPromptsCache
  # during in-place refreshes. Chown it too: a previous root-owned bootstrap
  # could have left an orphaned .old dir that the poll worker's rename(2) call
  # would EACCES on (git user cannot rmdir a root-owned directory, even with
  # write perms on the parent).
  if [ -d "${_pcroot}.old" ] && [ ! -L "${_pcroot}.old" ]; then
    chown -R -h git:git "${_pcroot}.old" || true
    chmod o-rwx "${_pcroot}.old" || true
  fi
fi

# Launch the HTTP listener and the git-user workers in the background,
# BEFORE sshd's exec replaces this shell. Once exec runs, sshd inherits
# PID 1 and both become its children via re-parenting. Stdout/stderr go to
# the container's log stream so operators see invite-accept traffic
# alongside ssh logs.
#
# AGT-2264 — the listener is the most exposed process in the container
# (public :8080, unauthenticated invite-accept and webhook traffic), so it
# gets the least:
#
#   - It runs as stamp-http: not git (which owns every repo and the mirror
#     deploy keys) and not in the git group (which reads /etc/stamp/env and
#     the root:git key directory). It reaches users.db through the stamp-db
#     group and nothing else. It has no sudo rule.
#   - It starts from `env -i` with only the variables its code reads
#     ($STAMP_HTTP_SERVER_ENV in lib/allowlisted-env.sh). No GITHUB_BOT_TOKEN,
#     ANTHROPIC_API_KEY, AUTHORIZED_KEYS or platform variables; the one
#     secret it holds is STAMP_PROMPTS_WEBHOOK_SECRET, which it needs to
#     verify the webhook HMAC. It never sees STAMP_PROMPTS_REPO_URL.
#
# The workers that need git's file access — the prompts poll / refresh
# (deploy key + git-owned cache) and the trash sweep (git-owned trashed
# repos) — moved out of the listener into stamp-workers, which runs as git
# with its own allowlist ($STAMP_WORKERS_ENV) and opens no socket. A valid
# webhook reaches it through a trigger file the listener replaces in
# /run/stamp-http (stamp-http-owned, world-readable). See server/README.md
# "What the HTTP listener can reach".
#
# `su -s /bin/sh -p <user>` is the runuser-equivalent that works against
# Alpine's busybox su (Alpine doesn't ship util-linux by default; -s
# overrides the target's login shell). -p keeps the env exactly as
# _exec_allowlisted_env built it — busybox su then touches nothing.
#
# Each runs under a small restart loop (AGT-2270): before, a crash stopped
# invite accept, the webhook, the prompts poll and the trash/retention
# sweeps until the next redeploy while the healthcheck (sshd only) stayed
# green. `_supervise` reruns the launcher in a subshell (the launcher execs,
# so the loop itself survives) after a 5s back-off and logs each exit. The
# Dockerfile HEALTHCHECK now probes the HTTP port as well.
STAMP_HTTP_RUN_DIR=/run/stamp-http
rm -rf "$STAMP_HTTP_RUN_DIR"
mkdir -p "$STAMP_HTTP_RUN_DIR"
chown stamp-http:stamp-http "$STAMP_HTTP_RUN_DIR"
chmod 0755 "$STAMP_HTTP_RUN_DIR"
if [ -n "$STAMP_PROMPTS_REPO_URL" ]; then
  STAMP_PROMPTS_REFRESH_TRIGGER="$STAMP_HTTP_RUN_DIR/prompts-refresh"
  export STAMP_PROMPTS_REFRESH_TRIGGER
else
  unset STAMP_PROMPTS_REFRESH_TRIGGER
fi
_launch_workers() {
  umask 027
  _exec_allowlisted_env /home/git "$STAMP_WORKERS_ENV" \
    su -s /bin/sh -p git -c 'exec /usr/local/sbin/stamp-workers'
}
_launch_http_server() {
  _exec_allowlisted_env /var/empty "$STAMP_HTTP_SERVER_ENV" \
    su -s /bin/sh -p stamp-http -c 'exec /usr/local/sbin/stamp-http-server'
}
_supervise() {
  _sv_name=$1
  shift
  while :; do
    _sv_rc=0
    ( "$@" ) || _sv_rc=$?
    echo "$_sv_name: exited (status $_sv_rc); restarting in 5s" >&2
    sleep 5
  done
}
_supervise stamp-workers _launch_workers &
echo "stamp-workers: launched as git user under a restart loop (pid $!)" >&2
_supervise stamp-http-server _launch_http_server &
echo "stamp-http-server: launched as stamp-http user with an allowlisted env under a restart loop (pid $!)" >&2

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

# One KEY=value per line, no quoting (lib/serverEnvFile.ts reads it back).
# A value with a newline or carriage return would split into a second,
# operator-unintended line — e.g. a STAMP_PROMPTS_DIR smuggled in through
# another variable — so such a value is refused and the variable is NOT
# written (the verb then uses its default). Logged, but not fatal: a bad
# paste must not crash-loop the self-deploying server (AGT-420 rule).
write_env_var() {
  local name="$1"
  local value
  value="$(eval "printf '%s' \"\$$name\"")"
  [ -n "$value" ] || return 0
  case "$value" in
    *"$_wev_nl"*|*"$_wev_cr"*)
      echo "warning: $name contains a newline or carriage return; not persisting it to /etc/stamp/env (SSH verbs will use the default)" >&2
      return 0
      ;;
  esac
  printf '%s=%s\n' "$name" "$value" >> /etc/stamp/env
}
_wev_nl='
'
_wev_cr=$(printf '\r')

write_env_var GITHUB_BOT_TOKEN
write_env_var ANTHROPIC_API_KEY  # consumed by stamp-review.cjs via lib/serverEnvFile.loadServerEnvFile()
# AGT-2263: a REVIEW_SIGNING_KEY_PATH override must reach both
# stamp-review (git, SSH-stripped env) and the sudo-invoked
# stamp-sign-approval (env_reset) — both reload this root-written file —
# so they agree with the boot-time bootstrap on which key is "the" key.
write_env_var REVIEW_SIGNING_KEY_PATH

# Phase B (AGT-373) — STAMP_PROMPTS_REPO_URL and STAMP_PROMPTS_DIR are read
# by resolvePromptCacheRoot() at SSH-verb request time. stamp-review.cjs's
# loadServerEnvFile() call merges them back into process.env early in
# main(), so the resolver sees them. Without these write_env_var lines
# the URL toggle silently fails closed — the verb falls through to the
# Phase A bundled-prompts path and Phase B operators see the staging
# repo provisioned but never consulted. (The webhook + poll workers run
# inside the long-running stamp-http-server process, which inherits the
# container env normally, so the cache itself was populating correctly
# while the consumer side was reading the bundled fallback — a confusing
# half-broken state.) Since AGT-2264 those workers run in stamp-workers,
# which receives the STAMP_PROMPTS_* vars through its env allowlist; the
# listener never sees the repo URL.
write_env_var STAMP_PROMPTS_REPO_URL

# AGT-420 — per-caller rate-limit caps consumed by stamp-review.cjs /
# stamp-mint-invite.cjs via loadServerEnvFile(). sshd strips these from the
# SSH session env, so without persisting them here the verbs silently fall
# back to their built-in defaults (30 reviews/hr, 10 invites/hr). A bad
# value is tolerated (the TS resolvers fall back to the default — no boot
# guard, deliberately, so a typo can't crash-loop the self-deploying server).
write_env_var MAX_REVIEWS_PER_HOUR
write_env_var MAX_INVITES_PER_HOUR

# AGT-423 — trash retention. STAMP_TRASH_TTL_DAYS is consumed by the
# sweep worker (which receives it through the stamp-workers env allowlist,
# AGT-2264) AND by the `purge-trash` SSH verb's no-flag fallback
# (SSH strips env, so it must be persisted here). Default 30 days; a bad
# value falls back to the default (no boot guard — a typo must not
# crash-loop the self-deploying server).
write_env_var STAMP_TRASH_TTL_DAYS

# AGT-454 — peer-agentic reviews master toggle. Consumed by the peer-review
# SSH verbs (stamp-pr-opened / stamp-claim-seat / stamp-subscribe / etc.) via
# resolvePeerReviewsEnabled(), which reads process.env after the verb's
# loadServerEnvFile() merge. sshd strips env from the session, so without
# persisting it here every peer verb sees the flag as unset and reports
# "peer reviews disabled" — even when the container has STAMP_PEER_REVIEWS_ENABLED=1.
# (The long-running stamp-http-server receives it through its env allowlist,
# AGT-2264, so only the SSH verbs need this.) A bad value is harmless: the
# resolver only enables on an exact "1", anything else stays disabled.
write_env_var STAMP_PEER_REVIEWS_ENABLED

# AGT-1724 — AI-attribution commit-message policy toggle. Read by the
# pre-receive hook (via loadServerEnvFile) to reject pushes whose newly
# introduced commits carry Claude-Session / Co-Authored-By Claude /
# "Generated with Claude Code" attribution. Hooks run inside the SSH
# push session, which sshd strips of container env, so without this line
# setting the var on the container would silently do nothing. Off unless
# set to 1/true/yes/on; a per-repo commit_policy block can still override.
write_env_var STAMP_FORBID_AI_ATTRIBUTION

# AGT-411: production refusal guard for STAMP_PROMPTS_DIR override.
# Must run before write_env_var STAMP_PROMPTS_DIR so a misconfigured prod
# deployment is rejected before the var is persisted to /etc/stamp/env.
# Phase B carve-out is handled inside check_prompts_dir: when
# STAMP_PROMPTS_REPO_URL is set the resolver ignores STAMP_PROMPTS_DIR,
# so a stale Phase A var is harmless and the guard is a no-op.
. "$(dirname "$0")/lib/check-prompts-dir.sh"
check_prompts_dir

write_env_var STAMP_PROMPTS_DIR
# AGT-2277: the resolver reads STAMP_ENV and the insecure-test toggle too.
# Without them the verb saw a dev/test STAMP_PROMPTS_DIR (written above)
# with STAMP_ENV unset — production — and refused every review. Both were
# already validated by check_prompts_dir.
write_env_var STAMP_ENV
write_env_var STAMP_PROMPTS_DIR_INSECURE_TEST_ONLY

# AGT-2277 — stamp-review tuning and the cache location. All read by the
# stamp-review verb after its loadServerEnvFile() merge; sshd strips them
# from the session, so before this every one of them silently did nothing
# on the image. A bad value is tolerated: each resolver falls back to its
# default (STAMP_REVIEWER_MODEL with a warning:), no boot guard. The cache
# root was checked by check_prompts_cache_root above; the verb must read
# the same root stamp-workers and the bootstrap write.
# tests/serverEnvFileCoverage.test.ts fails if stamp-review reads a variable
# that is neither written here nor listed there as unsupported.
write_env_var STAMP_REVIEWER_MODEL
write_env_var STAMP_REVIEWER_THINKING
write_env_var MAX_DIFF_BYTES
write_env_var REVIEW_TIMEOUT_MS
write_env_var STAMP_PROMPTS_CACHE_ROOT

# SSH sessions strip env vars by default; sshd_config's SetEnv bypasses
# that for explicitly-listed vars. Inject a whitelist of operator-declared
# variables so SSH-invoked commands (stamp-mint-invite, stamp-review, etc.)
# see them via process.env without needing a /etc/stamp/env file fallback.
#
# STAMP_SSH_PASS_ENV — space-separated list of env var names to inject.
# Defaults to "STAMP_PUBLIC_URL" so mint-invite Just Works in v2.0.2+ with
# no additional operator config. Operators can extend this list if future
# SSH-invoked verbs need other NON-SECRET container vars:
#
#   STAMP_SSH_PASS_ENV="STAMP_PUBLIC_URL STAMP_PUBLIC_REGION"
#
# !!! SECURITY: NON-SECRET VALUES ONLY !!!
# sshd_config is mode 0644 (world-readable on the host). DO NOT add API
# tokens, credentials, or any other secret to STAMP_SSH_PASS_ENV — they
# would land in a world-readable file. Use the /etc/stamp/env pattern above
# (write_env_var, mode 0640 root:git) for anything sensitive — that's why
# GITHUB_BOT_TOKEN / ANTHROPIC_API_KEY take that path and STAMP_PUBLIC_URL
# (an externally-published URL, by definition not secret) takes this one.
#
# Security — values are validated before writing to sshd_config. `printf '%s'`
# does not sanitize, so an embedded newline in a value would be passed through
# and create a new sshd directive (PermitRootLogin yes, AuthorizedKeysFile
# override, etc.). The value is operator-supplied via the container env, which
# sits downstream of Railway/Helm/Terraform/CI secret stores — all realistic
# injection vectors.
#
# The accepted charset [A-Za-z0-9.:/_@=+-] is the conservative safe set for
# sshd SetEnv values: covers URLs, region codes, hostnames, and version
# strings while excluding whitespace, quotes, semicolons, dollar signs, and
# other characters that have special meaning in sshd_config or shell expansion.
# STAMP_PUBLIC_URL additionally requires an http(s):// prefix — a semantics
# check that catches operator fat-finger before it breaks mint-invite at
# runtime.
#
# Idempotent across container restarts AND value changes — for each var, filter
# any prior `SetEnv <NAME>=` line out before appending the current value.
# Without this, in-place restarts accumulate stale lines (OpenSSH takes first
# match for duplicate SetEnv, so correctness is preserved but the file grows),
# and changing a var between deploys would leave the OLD value in effect forever.

STAMP_SSH_PASS_ENV="${STAMP_SSH_PASS_ENV:-STAMP_PUBLIC_URL}"

. "$(dirname "$0")/lib/inject-sshd-setenv.sh"

for _ssh_env_var in $STAMP_SSH_PASS_ENV; do
  _inject_sshd_setenv "$_ssh_env_var" || exit 1
done
unset _ssh_env_var

# -e: log to stderr (goes to container logs); -D: don't daemonize.
exec /usr/sbin/sshd -D -e
