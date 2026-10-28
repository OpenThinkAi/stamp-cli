#!/bin/sh
# Sourceable library: _refresh_repo_hooks
#
# Re-installs the stamp pre-receive / post-receive hooks into every bare repo
# under $STAMP_GIT_ROOT from the image's bundle in $STAMP_HOOK_SRC_DIR.
# Called by entrypoint.sh on every boot (as root) so a rebuilt image's hook
# code reaches repos provisioned under an older image.
#
# Security (AGT-2261): each repo — including its hooks/ directory — is owned
# by the git user, so everything this function touches inside a repo may have
# been planted by a git-user foothold (a git-shell escape, a crafted migration
# tarball). Root must never follow a symlink there:
#
#   - A repo path that is itself a symlink is skipped (it points outside the
#     volume's real repo set).
#   - hooks/ that is a symlink (or any non-directory) is removed — the link
#     itself, never its target — and recreated as a real directory.
#   - Each hook is prepared in full (bytes, mode 0755, owner) in a root-only
#     0700 staging directory on the same filesystem, then rename(2)d into
#     hooks/<name>. A symlink at hooks/<name> is unlinked first (mv would
#     otherwise follow one that resolves to a directory); rename then
#     replaces the ENTRY, so a hard link there is never written through, and
#     chown/chmod are never applied to the final path at all. (The previous
#     `cp src hooks/<name>; chown; chmod` wrote through a planted symlink and
#     then chowned/chmodded its target — a root-level overwrite of an
#     arbitrary file.) A non-regular entry at hooks/<name> (a directory, a
#     fifo) is removed first so the rename lands.
#
# The check-then-rename sequence is race-free only because nothing running as
# git exists yet when entrypoint.sh calls this: it runs before sshd starts and
# before any `su git` (prompts-cache bootstrap, HTTP listener). Keep it there.
#
# hooks/ stays git-owned on purpose. A root-owned hooks/ would not stop a git
# foothold from substituting hooks — the repo directory itself is git-owned,
# so git can rename hooks/ aside and make a new one, or set core.hooksPath in
# the repo's git-writable config — and it would break the git-run paths that
# must write there: setup-repo.sh installs the first hooks as git, and
# `delete-stamp-repo --purge` (as git) must be able to `rm -rf` the repo.
# Hook substitution by a git foothold is closed at the next boot by this
# refresh; the fix here is that the refresh itself can no longer be turned
# against root.
#
# Config redirection (AGT-2249): replacing hooks/ is not enough on its own —
# a git foothold can set `core.hooksPath` in the repo's git-writable config
# (or an `include.path` / `includeIf.<cond>.path` that pulls one in), and git
# would then run hooks from wherever that points, skipping the stamp
# pre-receive entirely. So each boot also strips those keys from every
# repo's own config file and from the git user's global config
# (~git/.gitconfig, ~git/.config/git/config), logging each removal. The edit runs as the git
# user ($STAMP_REPO_CONFIG_USER), never as root: the config file is
# git-owned and may be a planted symlink, and `git config` writes through
# symlinks — as git, that can only touch what git could already write. A key
# that cannot be removed fails the refresh (and so the boot), the same as
# setup-repo.sh refusing to report a repo ready with core.hooksPath set
# (AGT-2266). A file git cannot parse at all only warns: receive-pack cannot
# parse it either, so it cannot redirect hooks.
#
# Env knobs exist solely for unit-test isolation (tests run unprivileged);
# production callers leave them unset:
#   STAMP_GIT_ROOT          default /srv/git
#   STAMP_HOOK_SRC_DIR      default /etc/stamp  (reads <hook>.cjs)
#   STAMP_HOOK_OWNER        default root:root   (owner of installed hooks)
#   STAMP_HOOKS_DIR_OWNER   default git:git     (owner of a recreated hooks/)
#   STAMP_REPO_CONFIG_USER  default git         (user that edits repo config;
#                                                empty = the current user)
#   STAMP_GIT_HOME          default /home/git   (git user's HOME: its global
#                                                config is cleaned too)

: "${STAMP_GIT_ROOT:=/srv/git}"
: "${STAMP_HOOK_SRC_DIR:=/etc/stamp}"
: "${STAMP_HOOK_OWNER:=root:root}"
: "${STAMP_HOOKS_DIR_OWNER:=git:git}"
: "${STAMP_REPO_CONFIG_USER=git}"
: "${STAMP_GIT_HOME:=/home/git}"

# Runs (as $STAMP_REPO_CONFIG_USER) against the config file named by
# $STAMP_RRH_CFG: prints each hook-redirecting key it removes, exits non-zero
# if the file cannot be read or edited or a key survives. --no-includes:
# only the file's own entries matter (its include keys are removed here).
_RRH_SANITIZE_CONFIG='
cfg=$STAMP_RRH_CFG
[ -e "$cfg" ] || [ -L "$cfg" ] || exit 0
_redirect_keys() {
  _all=$(git config --file "$cfg" --no-includes --name-only --list) || return 2
  printf "%s\n" "$_all" | grep -iE "^(core\.hookspath|include\.path|includeif\..*\.path)\$" | sort -u
}
found=$(_redirect_keys) || exit 2
[ -n "$found" ] || exit 0
printf "%s\n" "$found" | while IFS= read -r k; do
  printf "%s\n" "$k"
  git config --file "$cfg" --unset-all "$k" || exit 3
done || exit 3
left=$(_redirect_keys) || exit 2
[ -z "$left" ] || exit 3
'

# _rrh_sanitize_config_file FILE — strip hook-redirecting keys from FILE.
_rrh_sanitize_config_file() {
  if [ -n "$STAMP_REPO_CONFIG_USER" ]; then
    _rrh_removed=$(cd / && STAMP_RRH_CFG="$1" su -s /bin/sh -p "$STAMP_REPO_CONFIG_USER" -c "$_RRH_SANITIZE_CONFIG")
  else
    _rrh_removed=$(cd / && STAMP_RRH_CFG="$1" sh -c "$_RRH_SANITIZE_CONFIG")
  fi
  _rrh_cfg_rc=$?
  if [ -n "$_rrh_removed" ]; then
    printf '%s\n' "$_rrh_removed" | while IFS= read -r _rrh_key; do
      echo "warning: refresh-repo-hooks: removed '$_rrh_key' from $1 (it redirects hooks away from the stamp pre-receive)" >&2
    done
  fi
  case "$_rrh_cfg_rc" in
    0) return 0 ;;
    2)
      # git cannot read the file as config at all (malformed, or a dangling
      # symlink). git-receive-pack reads the same file, so a push to this
      # repo fails (or runs with defaults) — it cannot honour a hooksPath
      # from it. Warn rather than let a git foothold brick the boot.
      echo "warning: refresh-repo-hooks: $1 is not readable as git config; left as is (pushes that read it will fail until an operator repairs it)" >&2
      return 0
      ;;
    *)
      echo "error: refresh-repo-hooks: cannot remove hook-redirecting keys from $1 (exit $_rrh_cfg_rc); refusing to boot with hooks that may be redirected" >&2
      return 1
      ;;
  esac
}

_refresh_repo_hooks() {
  _rrh_stage="$STAMP_GIT_ROOT/.stamp-hook-staging"
  # Clear any leftover (a crashed earlier boot, or an entry git planted in
  # the volume root). rm -rf on a symlink removes the link, not its target.
  # mkdir then fails rather than following if anything reappeared.
  rm -rf "$_rrh_stage"
  if ! mkdir -m 0700 "$_rrh_stage"; then
    echo "error: refresh-repo-hooks: cannot create staging dir $_rrh_stage (check that $STAMP_GIT_ROOT is mounted, writable by root and not full)" >&2
    return 1
  fi

  _rrh_rc=0
  # The git user's own global config is read by receive-pack for every
  # repo, and git can write it: clean it too (AGT-2249). /etc/gitconfig
  # is root-owned and not a git-foothold surface.
  for _rrh_global in "$STAMP_GIT_HOME/.gitconfig" "$STAMP_GIT_HOME/.config/git/config"; do
    _rrh_sanitize_config_file "$_rrh_global" || _rrh_rc=1
  done
  for _rrh_repo in "$STAMP_GIT_ROOT"/*.git; do
    if [ -L "$_rrh_repo" ]; then
      echo "warning: refresh-repo-hooks: skipping symlinked repo path $_rrh_repo" >&2
      continue
    fi
    [ -d "$_rrh_repo" ] || continue

    _rrh_sanitize_config_file "$_rrh_repo/config" || _rrh_rc=1

    _rrh_hooks="$_rrh_repo/hooks"
    if [ -L "$_rrh_hooks" ] || { [ -e "$_rrh_hooks" ] && [ ! -d "$_rrh_hooks" ]; }; then
      echo "warning: refresh-repo-hooks: $_rrh_hooks is not a real directory; replacing it (target untouched)" >&2
      rm -f "$_rrh_hooks" || { _rrh_rc=1; continue; }
    fi
    if [ ! -d "$_rrh_hooks" ]; then
      if ! { mkdir -m 0755 "$_rrh_hooks" && chown -h "$STAMP_HOOKS_DIR_OWNER" "$_rrh_hooks"; }; then
        echo "error: refresh-repo-hooks: cannot create $_rrh_hooks" >&2
        _rrh_rc=1
        continue
      fi
    fi

    for _rrh_hook in pre-receive post-receive; do
      _rrh_src="$STAMP_HOOK_SRC_DIR/${_rrh_hook}.cjs"
      [ -f "$_rrh_src" ] || continue
      _rrh_tmp="$_rrh_stage/$_rrh_hook"
      _rrh_dest="$_rrh_hooks/$_rrh_hook"
      # Fully prepare the file where only root can reach it.
      if ! { cp "$_rrh_src" "$_rrh_tmp" \
          && chmod 0755 "$_rrh_tmp" \
          && chown -h "$STAMP_HOOK_OWNER" "$_rrh_tmp"; }; then
        echo "error: refresh-repo-hooks: cannot stage $_rrh_hook for $_rrh_repo" >&2
        _rrh_rc=1
        continue
      fi
      # A symlink must be unlinked first, not left for mv to replace: a
      # two-argument mv (BusyBox and BSD alike) stat()s DEST through the
      # link and, if it resolves to a directory, moves the file INTO that
      # directory — root writing wherever git pointed the link.
      if [ -L "$_rrh_dest" ]; then
        echo "warning: refresh-repo-hooks: $_rrh_dest was a symlink; replacing the link (target untouched)" >&2
        rm -f "$_rrh_dest" || { _rrh_rc=1; continue; }
      elif [ -e "$_rrh_dest" ] && [ ! -f "$_rrh_dest" ]; then
        echo "warning: refresh-repo-hooks: $_rrh_dest is not a regular file; replacing it" >&2
        rm -rf "$_rrh_dest" || { _rrh_rc=1; continue; }
      fi
      # DEST is now absent or a regular file, so mv is a plain rename(2): a
      # regular file (or hard link) there is replaced as an entry, never
      # opened or written.
      if ! mv -f "$_rrh_tmp" "$_rrh_dest"; then
        echo "error: refresh-repo-hooks: cannot install $_rrh_dest" >&2
        _rrh_rc=1
      fi
    done
  done

  rm -rf "$_rrh_stage"
  return "$_rrh_rc"
}
