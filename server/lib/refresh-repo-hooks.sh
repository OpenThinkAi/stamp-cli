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
# Env knobs exist solely for unit-test isolation (tests run unprivileged);
# production callers leave them unset:
#   STAMP_GIT_ROOT          default /srv/git
#   STAMP_HOOK_SRC_DIR      default /etc/stamp  (reads <hook>.cjs)
#   STAMP_HOOK_OWNER        default root:root   (owner of installed hooks)
#   STAMP_HOOKS_DIR_OWNER   default git:git     (owner of a recreated hooks/)

: "${STAMP_GIT_ROOT:=/srv/git}"
: "${STAMP_HOOK_SRC_DIR:=/etc/stamp}"
: "${STAMP_HOOK_OWNER:=root:root}"
: "${STAMP_HOOKS_DIR_OWNER:=git:git}"

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
  for _rrh_repo in "$STAMP_GIT_ROOT"/*.git; do
    if [ -L "$_rrh_repo" ]; then
      echo "warning: refresh-repo-hooks: skipping symlinked repo path $_rrh_repo" >&2
      continue
    fi
    [ -d "$_rrh_repo" ] || continue

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
